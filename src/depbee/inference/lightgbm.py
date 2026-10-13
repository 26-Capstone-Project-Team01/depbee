import hashlib
import math
from pathlib import Path

from ..contracts import SCHEMA_VERSION, GuardError, OutOfScopeError, finite_number, read_json


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
    """

    def __init__(self, directory: Path):
        manifest, _ = read_json(directory / "manifest.json")
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
        with model_path.open("rb") as stream:
            actual_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        if manifest.get("model_sha256") != actual_hash:
            raise GuardError("Model SHA-256 does not match the manifest")
        try:
            import lightgbm as lgb
        except ImportError as exc:
            raise GuardError('Install ML dependencies: python -m pip install -e ".[ml]"') from exc
        try:
            self._booster = lgb.Booster(model_file=str(model_path))
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

    def _encode(self, features: dict[str, object]) -> list[float]:
        if set(features) != set(self.feature_names):
            raise GuardError(
                "Feature names differ from the model contract; no auto-fill is allowed"
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
        score = finite_number(float(self._run(self._encode(features))[0]), "model score")
        if not 0 <= score <= 1:
            raise GuardError("Model score is outside [0, 1]")
        return score

    def explain(self, features: dict[str, object], top: int = 3) -> dict:
        """Features that moved this score most, as LightGBM SHAP values in log-odds units.

        ``base_value`` plus every feature's contribution is the score's log-odds, so the
        features not listed are summed into ``others_sum`` to keep the explanation complete.
        """
        *contributions, base = self._run(self._encode(features), pred_contrib=True)[0]
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
