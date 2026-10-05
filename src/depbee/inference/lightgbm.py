import hashlib
from pathlib import Path

from ..contracts import SCHEMA_VERSION, GuardError, finite_number, read_json


class LightGBMPredictor:
    """Load a trusted native LightGBM model and verify its feature contract."""

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
        except GuardError:
            raise
        except Exception as exc:
            raise GuardError("Unable to load the LightGBM model") from exc

    def predict(self, features: dict[str, float]) -> float:
        if set(features) != set(self.feature_names):
            raise GuardError("Feature names differ from the model contract; no auto-fill is allowed")
        values = [finite_number(features[n], n) for n in self.feature_names]
        try:
            import numpy as np

            result = self._booster.predict(np.array([values], dtype=float), num_threads=1)
            score = finite_number(float(result[0]), "model score")
        except GuardError:
            raise
        except Exception as exc:
            raise GuardError("LightGBM prediction failed") from exc
        if not 0 <= score <= 1:
            raise GuardError("Model score is outside [0, 1]")
        return score
