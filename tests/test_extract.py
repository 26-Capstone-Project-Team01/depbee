"""Synthetic tests for the extractor analyzer, baseline rule and Korean output.

No network access and no package code: feature-extractor is replaced by FakeBackend.
"""

import contextlib
import io
import unittest

from test_contract import ExplainingPredictor
from test_workflow import Fixture

from depbee.analysis.baseline import select_baseline
from depbee.analysis.extractor import ExtractorAnalyzer
from depbee.cli import _print_text, main
from depbee.contracts import GuardError
from depbee.pipeline import scan

INTEGRITY = "sha512-test-only-not-an-archive-digest"


def packument(times):
    return {
        "time": {"created": "2020-01-01T00:00:00Z", **times},
        "versions": {v: {"version": v, "dist": {"integrity": INTEGRITY}} for v in times},
    }


class BaselineTests(unittest.TestCase):
    def test_same_line_stable_predecessor(self):
        doc = packument(
            {
                "1.0.0": "2026-01-01T00:00:00Z",
                "1.0.1": "2026-01-02T00:00:00Z",
                "1.1.0-beta.1": "2026-01-03T00:00:00Z",
                "0.0.0-main.abc": "2026-01-04T00:00:00Z",
                "2.0.0": "2026-01-05T00:00:00Z",
                "1.1.0": "2026-01-06T00:00:00Z",
            }
        )
        baseline = select_baseline(doc, "1.1.0")
        self.assertEqual((baseline.version, baseline.level), ("1.0.1", "L1"))

    def test_earlier_line_when_new_starts_a_line(self):
        doc = packument({"1.4.0": "2026-01-01T00:00:00Z", "2.0.0": "2026-01-02T00:00:00Z"})
        baseline = select_baseline(doc, "2.0.0")
        self.assertEqual((baseline.version, baseline.level), ("1.4.0", "L2"))

    def test_zero_major_line_is_minor(self):
        doc = packument(
            {
                "0.2.9": "2026-01-01T00:00:00Z",
                "0.3.0": "2026-01-02T00:00:00Z",
                "0.3.1": "2026-01-03T00:00:00Z",
            }
        )
        self.assertEqual(select_baseline(doc, "0.3.1").version, "0.3.0")
        self.assertEqual(select_baseline(doc, "0.3.0").level, "L2")

    def test_excludes_later_published_and_unpublished_versions(self):
        doc = packument(
            {
                "1.0.0": "2026-01-01T00:00:00Z",
                "1.0.2": "2026-01-05T00:00:00Z",
                "1.0.3": "2026-01-03T00:00:00Z",
            }
        )
        doc["time"]["1.0.1"] = "2026-01-02T00:00:00Z"  # unpublished: no tarball
        # 1.0.2 was published after 1.0.3 (a backport), so it cannot be 1.0.3's predecessor.
        self.assertEqual(select_baseline(doc, "1.0.3").version, "1.0.0")

    def test_no_predecessor_and_prerelease(self):
        doc = packument({"1.0.0": "2026-01-01T00:00:00Z", "1.1.0-rc.1": "2026-01-02T00:00:00Z"})
        self.assertIsNone(select_baseline(doc, "1.0.0"))
        with self.assertRaises(GuardError):
            select_baseline(doc, "1.1.0-rc.1")


class FakeBackend:
    """Stands in for feature-extractor; returns fixed features."""

    errors = ()
    version = "fake-extractor"

    def __init__(self, doc, features=None, new_json=None):
        self.doc = doc
        self.features = features or {"signal": 0.9, "obfChangedFileCount": 2}
        self.new_json = new_json
        self.calls = []

    def fetch_packument(self, name):
        return self.doc

    def extract(self, name, old, new, doc, local):
        self.calls.append((name, old, new, local))
        return dict(self.features), self.new_json or doc["versions"][new]


class ExtractorAnalyzerTests(Fixture):
    def setUp(self):
        super().setUp()
        # Lockfile moves 1.0.0 -> 1.1.0; the model compares 1.1.0 with its predecessor 1.0.1.
        self.doc = packument(
            {
                "1.0.0": "2026-01-01T00:00:00Z",
                "1.0.1": "2026-01-02T00:00:00Z",
                "1.1.0": "2026-01-03T00:00:00Z",
            }
        )
        self.doc["versions"]["1.0.1"]["scripts"] = {"test": "x"}
        self.new_json = {
            "scripts": {"test": "x", "postinstall": "node setup.js"},
            "dependencies": {"left-pad": "^1.0.0"},
        }

    def run_analyzer(self, backend=None, local=None):
        backend = backend or FakeBackend(self.doc, new_json=self.new_json)
        return ExtractorAnalyzer(local, backend=backend).analyze(self.request()), backend

    def test_complete_result_compares_with_predecessor(self):
        artifact, backend = self.run_analyzer()
        row = artifact["results"][0]
        self.assertEqual(row["status"], "complete")
        self.assertEqual(row["baseline_version"], "1.0.1")
        self.assertEqual(backend.calls, [("example", "1.0.1", "1.1.0", None)])
        evidence = "\n".join(row["evidence"])
        self.assertIn("1.0.1 → 1.1.0", evidence)
        self.assertIn("lockfile의 이전 버전은 1.0.0", evidence)
        self.assertIn("postinstall = node setup.js", evidence)
        self.assertIn("새 의존성 1개: left-pad", evidence)

    def test_integrity_mismatch_fails(self):
        self.doc["versions"]["1.1.0"]["dist"]["integrity"] = "sha512-other"
        row = self.run_analyzer()[0]["results"][0]
        self.assertEqual(row["status"], "failed")
        self.assertIn("integrity", row["error"])

    def test_unpublished_version_fails_without_local_copy(self):
        del self.doc["versions"]["1.1.0"]
        self.assertEqual(self.run_analyzer()[0]["results"][0]["status"], "failed")

    def test_local_copy_skips_registry_and_says_so(self):
        del self.doc["versions"]["1.1.0"]
        local = {("example", "1.1.0"): self.root}
        row = self.run_analyzer(local=local)[0]["results"][0]
        self.assertEqual(row["status"], "complete")
        self.assertIn("로컬 사본", "\n".join(row["evidence"]))

    def test_unused_local_copy_is_an_error(self):
        with self.assertRaises(GuardError):
            self.run_analyzer(local={("example", "9.9.9"): self.root})

    def test_prerelease_is_out_of_scope(self):
        self.new["packages"]["node_modules/example"]["version"] = "1.2.0-beta.1"
        self.save_locks()
        row = self.run_analyzer()[0]["results"][0]
        self.assertEqual((row["status"], row["reason"]), ("unsupported", "out_of_training_scope"))

    def test_first_release_has_no_baseline(self):
        self.doc = packument({"1.1.0": "2026-01-03T00:00:00Z"})
        row = self.run_analyzer()[0]["results"][0]
        self.assertEqual((row["status"], row["reason"]), ("unsupported", "no_baseline"))
        report = scan(self.request(), ExtractorAnalyzer(backend=FakeBackend(self.doc)), None)
        self.assertEqual((report["exit_code"], report["results"][0]["reason"]), (2, "no_baseline"))


class CliTests(Fixture):
    def test_korean_text_escapes_control_characters(self):
        artifact = self.artifact()
        artifact["results"][0]["evidence"] = ["설치 스크립트 추가: postinstall = a\x1b[2Jb"]
        report = scan(self.request(), self.adapter(artifact), ExplainingPredictor())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            _print_text(report)
        text = out.getvalue()
        self.assertIn("depbee 검사 결과: 위험 판정 있음 (종료 코드 1)", text)
        self.assertIn("[위험] example@1.1.0", text)
        self.assertIn("+ signal = 0.9 (+1.50)", text)
        self.assertNotIn("\x1b", text)
        self.assertIn("\\u001b[2J", text)

    def test_korean_text_for_missing_model(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["scan", str(self.project), "--base-lock", str(self.base)])
        self.assertEqual(code, 2)
        self.assertIn("이유: 분석 결과 없음", out.getvalue())

    def run_cli(self, *extra):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["scan", str(self.project), "--base-lock", str(self.base), *extra])
        return code, err.getvalue()

    def test_local_source_needs_extract_and_root(self):
        code, err = self.run_cli("--local-source", f"example@1.1.0={self.root}")
        self.assertEqual(code, 2)
        self.assertIn("--local-root", err)

    def test_local_source_must_stay_under_root(self):
        code, err = self.run_cli(
            "--extract", "--local-root", str(self.project), "--local-source", "example@1.1.0=.."
        )
        self.assertEqual(code, 2)
        self.assertIn("under --local-root", err)


if __name__ == "__main__":
    unittest.main()
