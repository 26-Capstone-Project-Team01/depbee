"""Write manifest.json next to a native LightGBM model trained on depbee-features-v1.

Feature names and category order are read from the model file itself; the feature types come
from the analyzer's schema. The threshold must come from the model owner's validation.

    python scripts/write_manifest.py models/d04-e00 --model-id D04-E00 --threshold 0.5 \
        --note "0.5 is the training default, not a validated threshold"
"""

import argparse
import hashlib
import json
from pathlib import Path

import lightgbm as lgb

from depbee.analysis.extractor import (
    BOOLEAN_FEATURES,
    CATEGORICAL_FEATURES,
    FEATURE_SCHEMA,
    NULLABLE_FEATURES,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("model_dir", type=Path, help="Directory containing model.txt")
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--threshold", required=True, type=float)
    parser.add_argument("--note", help="Free text kept in the manifest, e.g. data version")
    args = parser.parse_args()

    model_path = args.model_dir / "model.txt"
    booster = lgb.Booster(model_file=str(model_path))
    names = booster.feature_name()
    categorical = [n for n in names if n in CATEGORICAL_FEATURES]
    stored = booster.pandas_categorical or []
    if len(stored) != len(categorical):
        raise SystemExit(f"Model stores {len(stored)} category lists for {categorical}")
    manifest = {
        "schema_version": 1,
        "model_id": args.model_id,
        "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "objective": "binary",
        "positive_class": "malicious",
        "feature_schema": FEATURE_SCHEMA,
        "feature_names": names,
        "boolean_features": [n for n in names if n in BOOLEAN_FEATURES],
        "categorical_features": {n: list(c) for n, c in zip(categorical, stored, strict=True)},
        "nullable_features": [n for n in names if n in NULLABLE_FEATURES],
        "threshold": args.threshold,
    }
    if args.note:
        manifest["note"] = args.note
    with (args.model_dir / "manifest.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
