import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import shutil
import unittest
import uuid
from pathlib import Path
from unittest import mock

from depbee.analysis.artifact import ArtifactAnalyzer
from depbee.cli import main
from depbee.contracts import GuardError, finite_number, read_json
from depbee.inference.lightgbm import LightGBMPredictor
from depbee.inputs.npm import build_request
from depbee.pipeline import scan
from depbee.service import plan_project, scan_project


def package(version="1.0.0"):
    return {
        "version": version,
        "resolved": f"https://registry.npmjs.org/example/-/example-{version}.tgz",
        "integrity": "sha512-test-only-not-an-archive-digest",
    }


class Fixture(unittest.TestCase):
    def setUp(self):
        # Keep synthetic test outputs inside the workspace, with inherited directory ACLs.
        self.test_runs = Path(__file__).resolve().parents[1] / "artifacts" / "test-runs"
        self.root = self.test_runs / uuid.uuid4().hex
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup_run)
        self.project = self.root / "project"
        self.project.mkdir()
        self.base = self.root / "base.json"
        self.head = self.project / "package-lock.json"
        self.old = {"lockfileVersion": 3, "packages": {"node_modules/example": package()}}
        self.new = copy.deepcopy(self.old)
        self.new["packages"]["node_modules/example"] = package("1.1.0")
        self.save_locks()

    def cleanup_run(self):
        resolved = self.root.resolve()
        if resolved.parent != self.test_runs.resolve() or self.root.is_symlink():
            raise RuntimeError("Refusing to remove a test directory outside artifacts/test-runs")
        shutil.rmtree(resolved)

    def write(self, path, obj):
        path.write_text(json.dumps(obj), encoding="utf-8")

    def save_locks(self):
        self.write(self.base, self.old)
        self.write(self.head, self.new)

    def request(self):
        return build_request(self.project, self.base)

    def artifact(self, features=None):
        request = self.request()
        return {
            "schema_version": 1,
            "request_id": request["request_id"],
            "feature_schema": "test-v1",
            "analyzer_version": "test-only",
            "results": [{
                "change_id": c["change_id"], "status": "complete",
                "features": features or {"signal": 0.9}, "evidence": ["synthetic evidence"],
            } for c in request["changes"] if c["analyzable"]],
        }

    def adapter(self, artifact=None):
        path = self.root / "analysis.json"
        self.write(path, artifact if artifact is not None else self.artifact())
        return ArtifactAnalyzer(path)


class FakePredictor:
    """Only used to test orchestration, never shipped as a detection backend."""
    feature_schema = "test-v1"
    feature_names = ["signal"]
    threshold = 0.5
    model_id = "unit-test"

    def predict(self, features):
        return features["signal"]


class InputTests(Fixture):
    def test_updates_and_nested_dependencies(self):
        self.old["packages"]["node_modules/a/node_modules/@scope/pkg"] = package()
        self.new["packages"]["node_modules/a/node_modules/@scope/pkg"] = package("2.0.0")
        self.save_locks()
        changes = self.request()["changes"]
        self.assertEqual(len(changes), 2)
        self.assertTrue(all(c["analyzable"] for c in changes))
        self.assertEqual(changes[0]["after"]["name"], "@scope/pkg")

    def test_v1_rejected(self):
        self.new["lockfileVersion"] = 1
        self.save_locks()
        with self.assertRaises(GuardError):
            self.request()

    def test_source_and_integrity_changes_not_ignored(self):
        self.new = copy.deepcopy(self.old)
        self.new["packages"]["node_modules/example"]["integrity"] = "sha512-other"
        self.save_locks()
        self.assertEqual(self.request()["changes"][0]["reason"], "same_version_artifact_changed")

    def test_non_registry_is_incomplete(self):
        self.new["packages"]["node_modules/example"]["resolved"] = "https://evil.test/a.tgz"
        self.save_locks()
        self.assertEqual(scan(self.request(), None, None)["exit_code"], 2)

    def test_added_is_analyzed_not_silently_allowed(self):
        self.new["packages"]["node_modules/new"] = package()
        self.save_locks()
        added = [c for c in self.request()["changes"] if c["kind"] == "added"]
        self.assertTrue(added[0]["analyzable"])
        artifact = self.artifact()
        artifact["results"] = [r for r in artifact["results"] if r["change_id"] != added[0]["change_id"]]
        report = scan(self.request(), self.adapter(artifact), FakePredictor())
        self.assertEqual(report["exit_code"], 2)
        self.assertIn("analysis_missing", [r.get("reason") for r in report["results"]])

    def test_only_installed_version_source_is_checked(self):
        self.old["packages"]["node_modules/example"]["resolved"] = "https://evil.test/a.tgz"
        self.save_locks()
        self.assertTrue(self.request()["changes"][0]["analyzable"])

    def test_removed_and_unchanged_need_no_model(self):
        self.new = copy.deepcopy(self.old)
        self.save_locks()
        self.assertEqual(scan(self.request(), None, None)["exit_code"], 0)
        self.new["packages"] = {}
        self.save_locks()
        self.assertEqual(scan(self.request(), None, None)["results"][0]["status"], "removed")

    def test_duplicate_json_rejected(self):
        self.head.write_text('{"packages":{},"packages":{},"lockfileVersion":3}')
        with self.assertRaises(GuardError):
            self.request()


class PipelineTests(Fixture):
    def test_missing_analysis_is_incomplete(self):
        report = scan(self.request(), None, None)
        self.assertEqual(report["exit_code"], 2)
        self.assertIsNone(report["results"][0]["score"])

    def test_pass_flag_and_threshold_boundary(self):
        for score, expected in ((0.2, 0), (0.5, 1), (0.9, 1)):
            with self.subTest(score=score):
                analyzer = self.adapter(self.artifact({"signal": score}))
                self.assertEqual(scan(self.request(), analyzer, FakePredictor())["exit_code"], expected)

    def test_stale_artifact_rejected(self):
        artifact = self.artifact()
        artifact["request_id"] = "stale"
        with self.assertRaises(GuardError):
            scan(self.request(), self.adapter(artifact), FakePredictor())

    def test_feature_schema_mismatch(self):
        artifact = self.artifact()
        artifact["feature_schema"] = "another-version"
        with self.assertRaises(GuardError):
            scan(self.request(), self.adapter(artifact), FakePredictor())

    def test_duplicate_and_missing_results(self):
        artifact = self.artifact()
        artifact["results"] *= 2
        with self.assertRaises(GuardError):
            self.adapter(artifact).analyze(self.request())
        artifact["results"] = []
        self.assertEqual(scan(self.request(), self.adapter(artifact), FakePredictor())["exit_code"], 2)

    def test_failed_analysis_never_passes(self):
        artifact = self.artifact()
        artifact["results"][0] = {
            "change_id": artifact["results"][0]["change_id"],
            "status": "failed", "error": "parser unsupported",
        }
        self.assertEqual(scan(self.request(), self.adapter(artifact), FakePredictor())["exit_code"], 2)

    def test_invalid_scores_fail_closed(self):
        for score in (float("nan"), float("inf"), -0.1, 1.1, True):
            with self.subTest(score=score):
                artifact = self.artifact({"signal": score})
                self.assertEqual(scan(self.request(), self.adapter(artifact), FakePredictor())["exit_code"], 2)

    def test_cli_json_and_exit_status(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["scan", str(self.project), "--base-lock", str(self.base), "--format", "json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "incomplete")

    def test_cli_does_not_overwrite_input(self):
        original = self.base.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            code = main(["plan", str(self.project), "--base-lock", str(self.base), "--output", str(self.base)])
        self.assertEqual(code, 2)
        self.assertEqual(self.base.read_bytes(), original)

    def test_cli_export_request(self):
        output = self.root / "request.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["plan", str(self.project), "--base-lock", str(self.base), "--output", str(output)])
        self.assertEqual(code, 0)
        self.assertEqual(read_json(output)[0], self.request())


class ServiceTests(Fixture):
    def test_plan_project_is_the_request(self):
        self.assertEqual(plan_project(self.project, self.base), self.request())

    def test_scan_project_without_analysis_or_model(self):
        report = scan_project(self.project, self.base)
        self.assertEqual(report, scan(self.request(), None, None))
        self.assertEqual(report["results"][0]["reason"], "analysis_missing")
        self.adapter()
        report = scan_project(self.project, self.base, analysis=self.root / "analysis.json")
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(report["results"][0]["reason"], "model_missing")

    def test_scan_project_rejects_bad_source_options(self):
        with self.assertRaises(GuardError):
            scan_project(self.project, self.base, analysis=self.base, extract=True)
        with self.assertRaises(GuardError):
            scan_project(self.project, self.base, local_sources=[f"example@1.1.0={self.root}"])

    def test_scan_project_passes_sources_and_progress_to_extractor(self):
        (self.root / "src").mkdir()
        progress = mock.Mock()
        with mock.patch("depbee.analysis.extractor.ExtractorAnalyzer") as extractor:
            extractor.return_value.analyze.return_value = self.artifact()
            report = scan_project(
                self.project, self.base, extract=True, local_root=self.root,
                local_sources=["example@1.1.0=src"], progress=progress,
            )
        extractor.assert_called_once_with(
            {("example", "1.1.0"): (self.root / "src").resolve()}, progress=progress
        )
        self.assertEqual(report["results"][0]["reason"], "model_missing")


@unittest.skipUnless(importlib.util.find_spec("lightgbm"), "Install .[ml] for native integration tests")
class LightGBMTests(Fixture):
    def setUp(self):
        super().setUp()
        import lightgbm as lgb
        import numpy as np

        # Purely synthetic numbers verify serialization and integration, not detection quality.
        data = lgb.Dataset(np.array([[0.0], [0.1], [0.2], [0.8], [0.9], [1.0]]),
                           label=[0, 0, 0, 1, 1, 1], feature_name=["signal"])
        booster = lgb.train({"objective": "binary", "verbosity": -1, "num_threads": 1,
                             "min_data_in_leaf": 1, "min_data_in_bin": 1}, data, num_boost_round=4)
        booster.save_model(str(self.root / "model.txt"))
        self.manifest = {
            "schema_version": 1, "model_id": "synthetic-test-only", "feature_schema": "test-v1",
            "feature_names": ["signal"], "positive_class": "malicious", "objective": "binary",
            "threshold": 0.5,
            "model_sha256": hashlib.sha256((self.root / "model.txt").read_bytes()).hexdigest(),
        }
        self.write(self.root / "manifest.json", self.manifest)

    def test_native_prediction_and_cli(self):
        predictor = LightGBMPredictor(self.root)
        self.assertLess(predictor.predict({"signal": 0.1}), 0.5)
        self.assertGreater(predictor.predict({"signal": 0.9}), 0.5)
        self.adapter()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["scan", str(self.project), "--base-lock", str(self.base),
                         "--analysis", str(self.root / "analysis.json"),
                         "--model-dir", str(self.root), "--format", "json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())["results"][0]["status"], "flagged")

    def test_scan_project_matches_pipeline(self):
        self.adapter()
        analysis = self.root / "analysis.json"
        report = scan_project(self.project, self.base, analysis=analysis, model_dir=self.root)
        expected = scan(self.request(), ArtifactAnalyzer(analysis), LightGBMPredictor(self.root))
        self.assertEqual(report, expected)
        self.assertEqual(report["results"][0]["status"], "flagged")

    def test_hash_order_and_missing_features(self):
        predictor = LightGBMPredictor(self.root)
        with self.assertRaises(GuardError):
            predictor.predict({"wrong": 1})
        with self.assertRaises(GuardError):
            predictor.predict({"signal": float("nan")})
        self.manifest["feature_names"] = ["wrong"]
        self.write(self.root / "manifest.json", self.manifest)
        with self.assertRaises(GuardError):
            LightGBMPredictor(self.root)
        self.manifest["model_sha256"] = "wrong"
        self.write(self.root / "manifest.json", self.manifest)
        with self.assertRaises(GuardError):
            LightGBMPredictor(self.root)


class NumberTests(unittest.TestCase):
    def test_extreme_number(self):
        with self.assertRaises(GuardError):
            finite_number(10 ** 1000, "test")
