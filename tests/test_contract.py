"""Synthetic tests for the extended contract: result validation, typed model inputs, report fields."""

import hashlib
import importlib.util
import json
import math
import unittest

from test_workflow import FakePredictor, Fixture

from depbee.analysis.artifact import validate
from depbee.contracts import GuardError, OutOfScopeError
from depbee.pipeline import scan


class ValidationTests(Fixture):
    def test_feature_values_must_be_scalars(self):
        artifact = self.artifact({"signal": [1, 2]})
        with self.assertRaises(GuardError):
            validate(artifact, self.request())

    def test_unsupported_needs_reason(self):
        artifact = self.artifact()
        change_id = artifact["results"][0]["change_id"]
        artifact["results"][0] = {"change_id": change_id, "status": "unsupported", "error": "x"}
        with self.assertRaises(GuardError):
            validate(artifact, self.request())

    def test_unsupported_reports_incomplete_with_reason(self):
        artifact = self.artifact()
        change_id = artifact["results"][0]["change_id"]
        artifact["results"][0] = {
            "change_id": change_id,
            "status": "unsupported",
            "reason": "no_baseline",
            "error": "no earlier stable",
        }
        report = scan(self.request(), self.adapter(artifact), FakePredictor())
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(report["results"][0]["reason"], "no_baseline")


class ExplainingPredictor(FakePredictor):
    def predict(self, features):
        if features["signal"] == "unseen":
            raise OutOfScopeError("signal='unseen' is not a category the model was trained on")
        return features["signal"]

    def explain(self, features):
        return [{"feature": "signal", "value": features["signal"], "contribution": 1.5}]


class ReportTests(Fixture):
    def test_out_of_scope_category_is_incomplete(self):
        report = scan(
            self.request(), self.adapter(self.artifact({"signal": "unseen"})), ExplainingPredictor()
        )
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(report["results"][0]["reason"], "out_of_training_scope")
        self.assertIsNone(report["results"][0]["score"])

    def test_explanation_in_report(self):
        report = scan(self.request(), self.adapter(), ExplainingPredictor())
        self.assertEqual(report["results"][0]["explanation"][0]["feature"], "signal")
        self.assertEqual(report["results"][0]["features"], {"signal": 0.9})


@unittest.skipUnless(
    importlib.util.find_spec("lightgbm"), "Install .[ml] for native integration tests"
)
class TypedModelTests(Fixture):
    """A model with a boolean, a categorical and a nullable feature, like depbee-features-v1."""

    def setUp(self):
        super().setUp()
        import lightgbm as lgb
        import numpy as np

        x = np.array([[0, 0, 0.1], [0, 1, 0.2], [1, 2, 0.9], [1, 2, np.nan]] * 5, dtype=float)
        data = lgb.Dataset(
            x,
            label=[0, 0, 1, 1] * 5,
            feature_name=["flag", "kind", "ratio"],
            categorical_feature=[1],
        )
        booster = lgb.train(
            {
                "objective": "binary",
                "verbosity": -1,
                "num_threads": 1,
                "min_data_in_leaf": 1,
                "min_data_in_bin": 1,
            },
            data,
            num_boost_round=4,
        )
        self.model = self.root / "model.txt"
        booster.save_model(str(self.model))
        self.manifest = {
            "schema_version": 1,
            "model_id": "typed-test",
            "feature_schema": "test-v1",
            "feature_names": ["flag", "kind", "ratio"],
            "positive_class": "malicious",
            "objective": "binary",
            "threshold": 0.5,
            "boolean_features": ["flag"],
            "categorical_features": {"kind": ["a", "b", "c"]},
            "nullable_features": ["ratio"],
        }
        self.save_manifest()

    def save_manifest(self):
        self.manifest["model_sha256"] = hashlib.sha256(self.model.read_bytes()).hexdigest()
        self.write(self.root / "manifest.json", self.manifest)

    def predictor(self):
        from depbee.inference.lightgbm import LightGBMPredictor

        return LightGBMPredictor(self.root)

    def test_typed_values_are_encoded(self):
        predictor = self.predictor()
        high = predictor.predict({"flag": True, "kind": "c", "ratio": None})
        low = predictor.predict({"flag": False, "kind": "a", "ratio": 0.1})
        self.assertGreater(high, low)
        explanation = predictor.explain({"flag": True, "kind": "c", "ratio": None})
        self.assertTrue(all(math.isfinite(e["contribution"]) for e in explanation))

    def test_type_and_scope_errors(self):
        predictor = self.predictor()
        with self.assertRaises(OutOfScopeError):
            predictor.predict({"flag": True, "kind": "d", "ratio": 0.1})
        for bad in (
            {"flag": None, "kind": "a", "ratio": 0.1},
            {"flag": True, "kind": "a", "ratio": True},
            {"flag": 2.0, "kind": 0.0, "ratio": 0.1},
        ):
            with self.subTest(features=bad), self.assertRaises(GuardError):
                predictor.predict(bad)

    def test_stored_category_order_must_match(self):
        raw = self.model.read_bytes()
        self.assertIn(b"pandas_categorical:null", raw)
        stored = b"pandas_categorical:" + json.dumps([["b", "a", "c"]]).encode()
        self.model.write_bytes(raw.replace(b"pandas_categorical:null", stored))
        self.save_manifest()
        with self.assertRaises(GuardError):
            self.predictor()


if __name__ == "__main__":
    unittest.main()
