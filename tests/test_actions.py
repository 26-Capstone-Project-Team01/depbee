import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from depbee import actions

EXAMPLES = Path(__file__).resolve().parents[1] / "docs" / "examples" / "result-contract"
LOCK = """{
  "name": "synthetic",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "synthetic", "version": "1.0.0"},
    "node_modules/b": {
      "version": "1.0.0"
    },
    "node_modules/@scope/name": {
      "version": "2.0.0"
    },
    "node_modules/a/node_modules/b": {
      "version": "3.0.0"
    }
  }
}
"""


def row(location="node_modules/b", package="b", status="not_flagged", known="not_hit",
        ml="not_hit", score=0.1, reason=None, matches=None):  # fmt: skip
    return {
        "change_id": "c1",
        "location": location,
        "package": package,
        "before_version": "1.0.0",
        "after_version": "1.0.1",
        "status": status,
        "score": score,
        "reason": reason,
        "known_malicious": {
            "status": known,
            "reason": None,
            "detail": None,
            "matches": matches or [],
        },
        "ml": {"status": ml},
    }


def report(*rows, exit_code=0):
    return {"schema_version": 1, "status": "passed", "exit_code": exit_code, "results": list(rows)}


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(contextlib.chdir(self.tmp))
        Path("package-lock.json").write_text(LOCK, encoding="utf-8")

    def run_gate(self, data, fail_on="", markdown=None, raw=None):
        path = self.tmp / "report.json"
        path.write_text(raw if raw is not None else json.dumps(data), encoding="utf-8")
        out, summary = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out):
            code = actions.gate(path, "package-lock.json", fail_on, markdown, summary)
        return code, out.getvalue().splitlines(), summary.getvalue()

    def example(self, name, fail_on=""):
        data = json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
        return self.run_gate(data, fail_on)

    def test_known_malicious_fails_by_default(self):
        code, lines, summary = self.example("03-known-malicious-low-ml.json")
        self.assertEqual(code, 1)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("::error file=package-lock.json::"))
        self.assertIn("EXAMPLE-ADVISORY-0001", lines[0])
        self.assertIn("판정: 실패", summary)

    def test_low_ml_score_does_not_cancel_known_malicious(self):
        for ml, status in (("not_hit", "flagged"), ("failed", "flagged"), ("not_run", "flagged")):
            data = report(row(status=status, known="hit", ml=ml, score=0.01))
            code, lines, _ = self.run_gate(data)
            self.assertEqual(code, 1, ml)
            self.assertTrue(lines[0].startswith("::error "), ml)

    def test_ml_hit_warns_by_default_and_fails_when_chosen(self):
        code, lines, summary = self.example("02-ml-only.json")
        self.assertEqual(code, 0)
        self.assertTrue(lines[0].startswith("::warning "))
        self.assertIn("판정: 경고", summary)
        code, lines, summary = self.example("02-ml-only.json", "ml-hit")
        self.assertEqual(code, 1)
        self.assertTrue(lines[0].startswith("::error "))
        self.assertIn("실패(fail-on ml-hit)", summary)

    def test_incomplete_warns_by_default_and_fails_when_chosen(self):
        code, lines, summary = self.example("04-analysis-failed.json")
        self.assertEqual(code, 0)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("::warning "))
        self.assertIn("통과가 아님", lines[0])
        # A warning, never a pass: the verdict says so and the item stays in the summary.
        self.assertIn("판정: 경고", summary)
        self.assertNotIn("판정: 통과", summary)
        self.assertIn("보류 1개", summary)
        for fail_on in ("incomplete", "ml-hit, incomplete", " incomplete ml-hit "):
            code, lines, _ = self.example("04-analysis-failed.json", fail_on)
            self.assertEqual(code, 1, fail_on)
            self.assertTrue(lines[0].startswith("::error "), fail_on)

    def test_ml_fail_on_does_not_fail_incomplete(self):
        code, lines, _ = self.example("04-analysis-failed.json", "ml-hit")
        self.assertEqual(code, 0)
        self.assertTrue(lines[0].startswith("::warning "))

    def test_passing_reports(self):
        for name in ("01-rule-only.json", "05-detectors-not-configured.json"):
            code, lines, summary = self.example(name, "ml-hit,incomplete")
            self.assertEqual((code, lines), (0, []), name)
            self.assertIn("판정: 통과", summary)
            self.assertIn(actions.SAFETY_NOTE, summary)

    def test_top_level_exit_code_is_not_used(self):
        # exit_code 2 (an unfinished item) must not hide the known malicious match.
        data = report(row(status="flagged", known="hit"),
                      row("node_modules/@scope/name", "@scope/name", "incomplete", ml="not_run",
                          score=None, reason="no_baseline"), exit_code=2)  # fmt: skip
        code, lines, _ = self.run_gate(data)
        self.assertEqual(code, 1)
        self.assertEqual([line.split(" ", 1)[0] for line in lines], ["::error", "::warning"])
        # exit_code 1 from an ML hit alone is a warning by default.
        code, _, _ = self.run_gate(report(row(status="flagged", ml="hit"), exit_code=1))
        self.assertEqual(code, 0)

    def test_unusable_reports_fail(self):
        missing = self.tmp / "missing.json"
        out, summary = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out):
            code = actions.gate(missing, "package-lock.json", "", None, summary)
        self.assertEqual(code, 1)
        self.assertTrue(out.getvalue().startswith("::error::"))
        self.assertIn("판정: 실패", summary.getvalue())
        bad_rows = [
            row() | {"ml": None},
            {k: v for k, v in row().items() if k != "known_malicious"},
            row(ml="maybe"),
            row(status="passed"),
            row() | {"package": 1},
            "not a row",
        ]
        cases = [None, "{", "[]", json.dumps({"results": {}})]
        cases += [json.dumps(report(bad)) for bad in bad_rows]
        for raw in cases:
            code, lines, summary = self.run_gate(None, raw=raw or "")
            self.assertEqual(code, 1, raw)
            self.assertTrue(lines[0].startswith("::error::"), raw)
            self.assertIn("판정: 실패", summary)

    def test_bad_fail_on_fails(self):
        for fail_on in ("known", "ml", "ml-hit,none", "incomplete;ml-hit"):
            code, lines, _ = self.example("01-rule-only.json", fail_on)
            self.assertEqual(code, 1, fail_on)
            self.assertIn("fail-on accepts", lines[0])

    def test_annotation_escapes_package_strings(self):
        hostile = "evil%0A::error::pwn\r\n::warning file=x,line=1::y\x1b[31m"
        data = report(row(package=hostile, location=hostile, status="incomplete", ml="not_run",
                          reason="no_baseline\n::error::z"))  # fmt: skip
        code, lines, _ = self.run_gate(data)
        self.assertEqual(code, 0)
        self.assertEqual(len(lines), 1)
        head, message = lines[0].split("::", 2)[1:]
        self.assertEqual(head, "warning file=package-lock.json")
        self.assertNotIn("\r", message)
        self.assertNotIn("\x1b", message)
        self.assertIn("evil%250A", message)
        self.assertIn("\\u000d\\u000a", message)

    def test_property_escaping(self):
        line = actions.command("warning", "m", "a,b:c%\n/package-lock.json", 3)
        self.assertEqual(line, "::warning file=a%2Cb%3Ac%25%0A/package-lock.json,line=3::m")

    def test_lockfile_lines(self):
        lines = LOCK.splitlines()
        self.assertEqual(actions.find_line(lines, "node_modules/b"), 6)
        self.assertEqual(actions.find_line(lines, "node_modules/@scope/name"), 9)
        self.assertEqual(actions.find_line(lines, "node_modules/a/node_modules/b"), 12)
        self.assertIsNone(actions.find_line(lines, "node_modules/missing"))
        self.assertIsNone(actions.find_line(lines, "registry.npmjs.org"))
        data = report(row("node_modules/a/node_modules/b", ml="hit", status="flagged"),
                      row("node_modules/@scope/name", "@scope/name", ml="hit", status="flagged"),
                      row("node_modules/gone", "gone", ml="hit", status="flagged"))  # fmt: skip
        _, lines, _ = self.run_gate(data)
        self.assertEqual(
            [line.split("::")[1] for line in lines],
            ["warning file=package-lock.json,line=12", "warning file=package-lock.json,line=9",
             "warning file=package-lock.json"],
        )  # fmt: skip

    def test_missing_lockfile_falls_back_to_file_annotation(self):
        Path("package-lock.json").unlink()
        code, lines, _ = self.run_gate(report(row(status="flagged", ml="hit")))
        self.assertEqual(code, 0)
        self.assertTrue(lines[0].startswith("::warning file=package-lock.json::"))

    def test_cli_markdown_goes_first_in_summary(self):
        markdown = self.tmp / "summary.md"
        markdown.write_text("## depbee 검사 결과: 통과 (종료 코드 0)\n", encoding="utf-8")
        _, _, summary = self.run_gate(report(row()), markdown=markdown)
        self.assertTrue(summary.startswith("## depbee 검사 결과"))
        self.assertIn("### depbee Actions 판정: 통과", summary)

    def test_main_writes_step_summary(self):
        path = self.tmp / "report.json"
        path.write_text(json.dumps(report(row(status="flagged", known="hit"))), encoding="utf-8")
        summary = self.tmp / "step-summary.md"
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}):
            with contextlib.redirect_stdout(out):
                code = actions.main(["report", str(path), "--lockfile", "package-lock.json"])
        self.assertEqual(code, 1)
        self.assertIn("판정: 실패", summary.read_text(encoding="utf-8"))


class InputsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.tmp / "app").mkdir()
        (self.tmp / "app" / "package-lock.json").write_text("{}", encoding="utf-8")
        (self.tmp / "report.json").write_text("{}", encoding="utf-8")
        self.env = {
            "LOCKFILE": "app/package-lock.json",
            "FAIL_ON": "",
            "MAX_CHANGES": "20",
            "MODEL_VERSION": "model-d04-e00",
            "MODEL_SHA256": "a" * 64,
            "MANIFEST_SHA256": "b" * 64,
            "REPORT": "",
            "BASE_SHA": "c" * 40,
        }

    def test_valid_inputs(self):
        actions.check_inputs(self.env, self.tmp)
        report_mode = {"LOCKFILE": "app/package-lock.json", "REPORT": "report.json"}
        actions.check_inputs(report_mode, self.tmp)

    def test_invalid_inputs(self):
        cases = {
            "LOCKFILE": ["", "app/yarn.lock", "missing/package-lock.json", "../package-lock.json",
                         "/app/package-lock.json", "C:/app/package-lock.json"],
            "FAIL_ON": ["all"],
            "MAX_CHANGES": ["", "0", "-1", "1.5", "２"],
            "MODEL_VERSION": ["", "../x", "a/b", "v1?x", "-x"],
            "MODEL_SHA256": ["", "A" * 64, "a" * 63, "g" * 64],
            "MANIFEST_SHA256": [""],
            "BASE_SHA": ["", "HEAD", "c" * 39],
            "REPORT": ["missing.json"],
        }  # fmt: skip
        for name, values in cases.items():
            for value in values:
                with self.subTest(name=name, value=value):
                    with self.assertRaises(actions.ActionError):
                        actions.check_inputs(self.env | {name: value}, self.tmp)

    def test_verify(self):
        model = self.tmp / "model.txt"
        model.write_bytes(b"synthetic model")
        digest = hashlib.sha256(b"synthetic model").hexdigest()
        actions.verify([(model, digest)])
        for expected in ("0" * 64, digest.upper(), digest[:-1]):
            with self.assertRaises(actions.ActionError):
                actions.verify([(model, expected)])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(actions.main(["verify", str(model), "0" * 64]), 1)
            self.assertEqual(actions.main(["verify", str(self.tmp / "none"), digest]), 1)
            self.assertEqual(actions.main(["verify", str(model)]), 1)
            self.assertEqual(actions.main(["verify", str(model), digest]), 0)
        self.assertIn("::error::depbee action: SHA-256 mismatch for model.txt", out.getvalue())

    def test_count_changes(self):
        plan = self.tmp / "plan.json"
        plan.write_text(json.dumps({"changes": [{}, {}, {}]}), encoding="utf-8")
        self.assertEqual(actions.count_changes(plan, 3), 3)
        with self.assertRaises(actions.ActionError):
            actions.count_changes(plan, 2)
        plan.write_text("{}", encoding="utf-8")
        with self.assertRaises(actions.ActionError):
            actions.count_changes(plan, 3)


if __name__ == "__main__":
    unittest.main()
