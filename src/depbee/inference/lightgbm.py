import math
from pathlib import Path

from ..contracts import (
    SCHEMA_VERSION,
    GuardError,
    OutOfScopeError,
    check_sha256,
    finite_number,
    read_json,
)

# Same limit as the Release model download in action.yml.
MAX_MODEL_BYTES = 100 * 1024 * 1024


def _name_list(manifest: dict, field: str, names: list[str]) -> frozenset[str]:
    value = manifest.get(field, [])
    if not isinstance(value, list) or not all(isinstance(n, str) and n in names for n in value):
        raise GuardError(f"{field} must list feature names of this model")
    return frozenset(value)


class LightGBMPredictor:
    """Load a trusted native LightGBM model and verify its feature contract.

    Optional manifest fields describe how analyzer values become model inputs, matching how
    the training data was read:
    - ``boolean_features``: true/false become 1/0.
    - ``categorical_features``: {name: [category, ...]}; a value's position is its code. A
      category the model never saw is out of training scope, not a missing value.
    - ``nullable_features``: null becomes NaN, LightGBM's missing value. Training left these
      empty when there was nothing to measure. Null anywhere else is rejected.

    manifest.json and model.txt are each read once, and what is parsed is what was hashed:
    LightGBM gets the model as text, never the file's name. ``sha256``, for the model shipped
    with depbee (bundled.SHA256), is {"manifest.json": ..., "model.txt": ...}: the SHA-256 each
    file's bytes must have before they are parsed. A folder the caller chose has none, and its
    model need only be the one its manifest names.
    """

    def __init__(self, directory: Path, sha256: dict | None = None):
        fixed = (None, None) if sha256 is None else (sha256["manifest.json"], sha256["model.txt"])
        manifest, manifest_hash = read_json(directory / "manifest.json", fixed[0])
        if manifest.get("schema_version") != SCHEMA_VERSION:
            raise GuardError("Unsupported model manifest schema_version")
        if manifest.get("positive_class") != "malicious" or manifest.get("objective") != "binary":
            raise GuardError("Model must use binary objective with positive_class=malicious")
        for field in ("model_id", "feature_schema"):
            if not isinstance(manifest.get(field), str) or not manifest[field]:
                raise GuardError(f"Model manifest requires {field}")
        names = manifest.get("feature_names")
        if (
            not isinstance(names, list)
            or not names
            or not all(isinstance(n, str) and n for n in names)
            or len(set(names)) != len(names)
        ):
            raise GuardError("feature_names must contain unique, ordered names")
        self.model_id = manifest["model_id"]
        self.feature_schema = manifest["feature_schema"]
        self.feature_names = names
        self.boolean_features = _name_list(manifest, "boolean_features", names)
        self.nullable_features = _name_list(manifest, "nullable_features", names)
        categorical = manifest.get("categorical_features", {})
        if not isinstance(categorical, dict) or not all(
            name in names
            and isinstance(values, list)
            and values
            and all(isinstance(v, str) for v in values)
            and len(set(values)) == len(values)
            for name, values in categorical.items()
        ):
            raise GuardError("categorical_features must map feature names to unique category lists")
        self.categories = {name: list(values) for name, values in categorical.items()}
        self.threshold = finite_number(manifest.get("threshold"), "threshold")
        if not 0 < self.threshold < 1:
            raise GuardError("threshold must be between 0 and 1")
        model_path = directory / "model.txt"
        too_large = f"LightGBM model exceeds {MAX_MODEL_BYTES} bytes: {model_path}"
        if model_path.stat().st_size > MAX_MODEL_BYTES:
            raise GuardError(too_large)
        with model_path.open("rb") as stream:
            raw = stream.read(MAX_MODEL_BYTES + 1)
        if len(raw) > MAX_MODEL_BYTES:
            raise GuardError(too_large)
        actual_hash = check_sha256(raw, fixed[1], model_path)
        if manifest.get("model_sha256") != actual_hash:
            raise GuardError("Model SHA-256 does not match the manifest")
        # The verified files; the feature cache keys on them (analysis.cache).
        self.identity = {"model_sha256": actual_hash, "manifest_sha256": manifest_hash}
        try:
            import lightgbm as lgb
        except ImportError as exc:
            raise GuardError(
                "depbee를 설치한 Python 환경에서 동일한 배포본과 기본 의존성 "
                "LightGBM, NumPy를 다시 설치하세요."
            ) from exc
        try:
            # The bytes hashed above, not the path: LightGBM's own reader would open the file a
            # second time, and on Windows it cannot open every path Python can (Korean, emoji).
            # It takes the text as a C string, which a NUL would end before the hashed bytes do.
            if b"\0" in raw:
                raise GuardError("Model file contains a NUL byte")
            self._booster = lgb.Booster(model_str=raw.decode("utf-8"))
            objective = self._booster.dump_model().get("objective", "").split()[0]
            if objective != "binary" or self._booster.num_model_per_iteration() != 1:
                raise GuardError("Native model is not a binary classifier")
            if self._booster.feature_name() != self.feature_names:
                raise GuardError("Model feature order/names differ from the manifest")
            # A model trained from a pandas DataFrame stores its category order; codes must match.
            stored = self._booster.pandas_categorical
            declared = [self.categories[n] for n in self.feature_names if n in self.categories]
            if stored is not None and [list(c) for c in stored] != declared:
                raise GuardError("Model categories differ from manifest categorical_features")
        except GuardError:
            raise
        except Exception as exc:
            raise GuardError("Unable to load the LightGBM model") from exc

    def encode(self, features: dict[str, object]) -> list[float]:
        """Model input for features. Raises OutOfScopeError for an unseen category and GuardError
        for anything else this model cannot take; the feature cache uses it to reject entries."""
        # The analyzer may extract more than this model uses; extras are dropped, never filled.
        missing = [name for name in self.feature_names if name not in features]
        if missing:
            raise GuardError(
                f"Analyzer output lacks model features {missing}; no auto-fill is allowed"
            )
        values = []
        for name in self.feature_names:
            value = features[name]
            if value is None:
                if name not in self.nullable_features:
                    raise GuardError(f"{name} must not be missing")
                values.append(math.nan)
            elif name in self.categories:
                if not isinstance(value, str) or value not in self.categories[name]:
                    raise OutOfScopeError(
                        f"{name}={value!r} is not a category the model was trained on"
                    )
                values.append(float(self.categories[name].index(value)))
            elif isinstance(value, bool):
                if name not in self.boolean_features:
                    raise GuardError(f"{name} must be a number")
                values.append(1.0 if value else 0.0)
            else:
                values.append(finite_number(value, name))
        return values

    def _run(self, values: list[float], **options):
        try:
            import numpy as np

            return self._booster.predict(np.array([values], dtype=float), num_threads=1, **options)
        except Exception as exc:
            raise GuardError("LightGBM prediction failed") from exc

    def predict(self, features: dict[str, object]) -> float:
        score = finite_number(float(self._run(self.encode(features))[0]), "model score")
        if not 0 <= score <= 1:
            raise GuardError("Model score is outside [0, 1]")
        return score

    def explain(self, features: dict[str, object], top: int = 3) -> dict:
        """Features that moved this score most, as LightGBM SHAP values in log-odds units.

        ``base_value`` plus every feature's contribution is the score's log-odds, so the
        features not listed are summed into ``others_sum`` to keep the explanation complete.
        """
        *contributions, base = self._run(self.encode(features), pred_contrib=True)[0]
        ranked = sorted(
            zip(self.feature_names, contributions, strict=True), key=lambda c: -abs(c[1])
        )
        shown = [(name, value) for name, value in ranked[:top] if value != 0]
        listed = {name for name, _ in shown}
        others = [value for name, value in ranked if name not in listed]
        return {
            "top": [
                {"feature": name, "value": features[name], "contribution": float(value)}
                for name, value in shown
            ],
            "others_sum": finite_number(float(sum(others)), "contribution sum"),
            "others_count": len(others),
            "base_value": finite_number(float(base), "base value"),
        }
