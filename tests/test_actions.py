import contextlib
import hashlib
import io
import itertools
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from depbee import actions

EXAMPLES = Path(__file__).resolve().parents[1] / "docs" / "examples" / "result-contract"
MODEL_ID = "synthetic-model-001"
LIST_AS_OF = "2026-11-01T00:00:00Z"
MODEL_LINE = "- 모델 ID(`model_id`): "
LIST_LINE = "- 기지 악성 색인 기준 시점(`detectors.known_malicious.list_as_of`): "
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


def report(*rows, exit_code=0, named=True):
    """A scan's report. named=False: the fields this gate read before it asked for the names of
    the model and the known malicious list (older and hand-made reports)."""
    data = {"schema_version": 1, "status": "passed", "exit_code": exit_code, "results": list(rows)}
    if named:
        known = {"source": "SYNTHETIC-LIST", "list_as_of": LIST_AS_OF, "list_sha256": "e" * 64}
        data |= {"model_id": MODEL_ID, "detectors": {"known_malicious": known, "rules": None}}
    return data


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(contextlib.chdir(self.tmp))
        Path("package-lock.json").write_text(LOCK, encoding="utf-8")

    def run_gate(self, data, fail_on="", markdown=None, raw=None, self_test=False):
        path = self.tmp / "report.json"
        path.write_text(raw if raw is not None else json.dumps(data), encoding="utf-8")
        out, summary = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out):
            code = actions.gate(path, "package-lock.json", fail_on, markdown, summary, self_test)
        return code, out.getvalue().splitlines(), summary.getvalue()

    def example(self, name, fail_on="", self_test=False):
        data = json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
        return self.run_gate(data, fail_on, self_test=self_test)

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
        # 05 names no known malicious list: only the self-test may judge it (below).
        for name, self_test in (("01-rule-only.json", False),
                                ("05-detectors-not-configured.json", True)):  # fmt: skip
            code, lines, summary = self.example(name, "ml-hit,incomplete", self_test)
            self.assertEqual((code, lines), (0, []), name)
            self.assertIn("판정: 통과", summary)
            self.assertIn(actions.SAFETY_NOTE, summary)

    def test_scan_report_must_name_the_model_and_the_list(self):
        # A scan that ran without a model or without the index would otherwise only warn
        # (model_missing) or never fail on a known malicious match.
        named = report(row())
        list_as_of = "detectors.known_malicious.list_as_of"
        cases = {
            "no model_id": ({k: v for k, v in named.items() if k != "model_id"}, ["model_id"]),
            "null model_id": (named | {"model_id": None}, ["model_id"]),
            "blank model_id": (named | {"model_id": " "}, ["model_id"]),
            "model_id not text": (named | {"model_id": 7}, ["model_id"]),
            "no detectors": ({k: v for k, v in named.items() if k != "detectors"}, [list_as_of]),
            "detectors not an object": (named | {"detectors": "x"}, [list_as_of]),
            "list not connected": (named | {"detectors": {"known_malicious": None}}, [list_as_of]),
            "list not an object": (named | {"detectors": {"known_malicious": ["x"]}}, [list_as_of]),
            "no list_as_of": (named | {"detectors": {"known_malicious": {"source": "S"}}},
                              [list_as_of]),
            "null list_as_of": (named | {"detectors": {"known_malicious": {"list_as_of": None}}},
                                [list_as_of]),
            "neither": (report(row(), named=False), ["model_id", list_as_of]),
        }  # fmt: skip
        for name, (data, unnamed) in cases.items():
            with self.subTest(name):
                code, lines, summary = self.run_gate(data)
                self.assertEqual(code, 1)
                self.assertEqual(len(lines), 1)
                self.assertTrue(
                    lines[0].startswith(f"::error::depbee: 보고서에 {', '.join(unnamed)} 값이"),
                    lines[0],
                )
                self.assertIn("판정: 실패", summary)
                self.assertEqual(summary.count("보고서에 없음: 실패"), len(unnamed))
                # The self-test still judges such a report: older and hand-made ones.
                code, lines, summary = self.run_gate(data, self_test=True)
                self.assertEqual((code, lines), (0, []))
                self.assertIn("판정: 통과", summary)
                self.assertEqual(summary.count("보고서에 없음"), len(unnamed))
                self.assertNotIn("보고서에 없음: 실패", summary)
        code, lines, _ = self.example("05-detectors-not-configured.json")
        self.assertEqual(code, 1)
        self.assertIn(list_as_of, lines[0])

    def test_unnamed_scan_report_fails_whatever_the_results_say(self):
        # Warnings stay warnings and a known malicious match keeps its own error.
        for rows, levels in (
            ([], ["::error"]),
            ([row(status="flagged", ml="hit")], ["::error", "::warning"]),
            ([row(status="incomplete", ml="not_run", reason="model_missing")],
             ["::error", "::warning"]),
            ([row(status="flagged", known="hit")], ["::error", "::error"]),
        ):  # fmt: skip
            with self.subTest(levels=levels):
                code, lines, summary = self.run_gate(report(*rows, named=False))
                self.assertEqual(code, 1)
                self.assertEqual([line.split("::")[1].split(" ")[0] for line in lines],
                                 [level[2:] for level in levels])  # fmt: skip
                self.assertIn("판정: 실패", summary)

    def test_summary_names_the_model_and_the_list(self):
        for data in (report(), report(row(status="flagged", known="hit"))):
            _, _, summary = self.run_gate(data)
            self.assertIn(f"{MODEL_LINE}` {MODEL_ID} `\n", summary)
            self.assertIn(f"{LIST_LINE}` {LIST_AS_OF} `\n", summary)
            self.assertNotIn("자기 검사", summary)
        # The values are the report's own, also below the CLI Markdown of a scan.
        markdown = self.tmp / "summary.md"
        markdown.write_text("## depbee 검사 결과: 통과 (종료 코드 0)\n", encoding="utf-8")
        _, _, summary = self.run_gate(report(row()), markdown=markdown)
        self.assertIn(f"{MODEL_LINE}` {MODEL_ID} `\n", summary)
        _, _, summary = self.example("01-rule-only.json")
        self.assertIn(f"{MODEL_LINE}` example-model-001 `\n", summary)
        self.assertIn(f"{LIST_LINE}` 2026-11-01T00:00:00Z `\n", summary)

    def test_summary_shows_the_names_as_code_spans(self):
        hostile = "x`</code><img src=x onerror=1>\n## 판정: 통과 ``` [a](http://b) | <!--"
        data = report(row()) | {"model_id": hostile}
        data["detectors"]["known_malicious"]["list_as_of"] = hostile
        expected = "x`</code><img src=x onerror=1>\\u000a## 판정: 통과 ``` [a](http://b) | <!--"
        for self_test in (False, True):
            with self.subTest(self_test=self_test):
                code, lines, summary = self.run_gate(data, self_test=self_test)
                self.assertEqual((code, lines), (0, []))
                # A fence longer than the longest backtick run inside, on one line.
                self.assertIn(f"{MODEL_LINE}```` {expected} ````\n", summary)
                self.assertIn(f"{LIST_LINE}```` {expected} ````\n", summary)
                self.assertNotIn("\n## 판정: 통과", summary)
                self.assertEqual(summary.count("### depbee Actions 판정"), 1)

    def test_self_test_says_it_is_not_a_scan(self):
        code, lines, summary = self.run_gate(report(row(), named=False), self_test=True)
        self.assertEqual((code, lines), (0, []))
        self.assertIn("자기 검사(`report` 입력)입니다.", summary)
        self.assertIn("실제 검사 결과가 아닙니다.", summary)
        self.assertIn(f"{MODEL_LINE}보고서에 없음\n", summary)
        self.assertIn(f"{LIST_LINE}보고서에 없음\n", summary)
        # The verdict rules are the same there: a known malicious match fails.
        data = report(row(status="flagged", known="hit"), named=False)
        code, lines, _ = self.run_gate(data, self_test=True)
        self.assertEqual(code, 1)
        self.assertEqual(len(lines), 1)

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

    def test_main_asks_for_the_names_unless_self_test(self):
        path = self.tmp / "report.json"
        path.write_text(json.dumps(report(row(), named=False)), encoding="utf-8")
        summary = self.tmp / "step-summary.md"
        arguments = ["report", str(path), "--lockfile", "package-lock.json"]
        with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(actions.main(arguments), 1)
                self.assertEqual(actions.main([*arguments, "--self-test"]), 0)
        verdicts = re.findall("판정: (..)", summary.read_text(encoding="utf-8"))
        self.assertEqual(verdicts, ["실패", "통과"])


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
            "KNOWN_MALICIOUS_VERSION": "known-malicious-2026-10-06",
            "KNOWN_MALICIOUS_SHA256": "d" * 64,
            "REPORT": "",
            "BASE_SHA": "c" * 40,
        }

    def bundled(self) -> dict:
        """The inputs of a workflow that sets none of the five Release inputs."""
        return {k: v for k, v in self.env.items() if k not in actions.RELEASE_INPUTS}

    def test_valid_inputs(self):
        self.assertEqual(actions.check_inputs(self.env, self.tmp), "release")
        report_mode = {"LOCKFILE": "app/package-lock.json", "REPORT": "report.json"}
        self.assertIsNone(actions.check_inputs(report_mode, self.tmp))

    def test_no_release_input_means_the_installed_assets(self):
        self.assertEqual(len(actions.RELEASE_INPUTS), 5)
        self.assertEqual(actions.check_inputs(self.bundled(), self.tmp), "bundled")
        # GitHub passes an input that was not set as an empty string.
        empty = self.env | dict.fromkeys(actions.RELEASE_INPUTS, "")
        self.assertEqual(actions.check_inputs(empty, self.tmp), "bundled")

    def test_release_inputs_are_all_or_none(self):
        names = actions.RELEASE_INPUTS
        for size in range(1, len(names)):
            for given in itertools.combinations(names, size):
                missing = ", ".join(n.lower().replace("_", "-") for n in names if n not in given)
                for unset in ({}, dict.fromkeys(set(names) - set(given), "")):
                    env = self.bundled() | {name: self.env[name] for name in given} | unset
                    with (
                        self.subTest(given=given, unset=unset),
                        self.assertRaises(actions.ActionError) as caught,
                    ):
                        actions.check_inputs(env, self.tmp)
                    message = str(caught.exception)
                    self.assertIn("all five or not at all", message)
                    self.assertTrue(message.endswith(f"missing: {missing}"), message)

    def test_release_input_errors_name_the_input(self):
        cases = [
            ("MODEL_VERSION", "a/b", "model-version must be a Release tag name: 'a/b'"),
            ("MODEL_SHA256", "A" * 64, "model-sha256 must be 64 lowercase hex digits"),
            ("MANIFEST_SHA256", "b" * 63, "manifest-sha256 must be 64 lowercase hex digits"),
            ("KNOWN_MALICIOUS_VERSION", " ", "known-malicious-version must be a Release tag name"),
            ("KNOWN_MALICIOUS_SHA256", "d" * 65, "known-malicious-sha256 must be 64 lowercase"),
        ]
        for name, value, message in cases:
            with self.subTest(name=name), self.assertRaises(actions.ActionError) as caught:
                actions.check_inputs(self.env | {name: value}, self.tmp)
            self.assertIn(message, str(caught.exception))
        # Blank values are values: never read as "no Release inputs".
        blank = self.env | dict.fromkeys(actions.RELEASE_INPUTS, " ")
        with self.assertRaisesRegex(actions.ActionError, "model-version must be"):
            actions.check_inputs(blank, self.tmp)

    def test_base_commit_and_limits_are_checked_in_both_modes(self):
        for env in (self.env, self.bundled()):
            for sha in ("c" * 40, "0123456789abcdef" * 4):
                actions.check_inputs(env | {"BASE_SHA": sha}, self.tmp)
            cases = [("BASE_SHA", ""), ("BASE_SHA", "main"), ("BASE_SHA", "c" * 39),
                     ("BASE_SHA", "C" * 40), ("BASE_SHA", "c" * 40 + "\n"), ("MAX_CHANGES", "0"),
                     ("LOCKFILE", "app/yarn.lock"), ("FAIL_ON", "all")]  # fmt: skip
            for name, value in cases:
                with self.subTest(name=name, value=value), self.assertRaises(actions.ActionError):
                    actions.check_inputs(env | {name: value}, self.tmp)
            missing = {k: v for k, v in env.items() if k != "BASE_SHA"}
            with self.assertRaisesRegex(actions.ActionError, "pull_request"):
                actions.check_inputs(missing, self.tmp)

    def run_inputs(self, env):
        """main(["inputs"]) with only these variables: (exit status, GITHUB_OUTPUT lines, stdout)."""
        output = self.tmp / "github-output.txt"
        output.unlink(missing_ok=True)
        out = io.StringIO()
        with (
            mock.patch.dict(os.environ, env | {"GITHUB_OUTPUT": str(output)}, clear=True),
            mock.patch.object(actions, "tree_digest", return_value="f" * 64) as digest,
            contextlib.chdir(self.tmp),
            contextlib.redirect_stdout(out),
        ):
            code = actions.main(["inputs"])
        self.digested = digest.call_args_list
        written = output.read_text(encoding="utf-8").splitlines() if output.exists() else []
        return code, written, out.getvalue()

    def test_inputs_command_writes_the_asset_source_and_cache_identity(self):
        code, written, _ = self.run_inputs(self.env)
        self.assertEqual((code, written), (0, ["assets=release", f"identity={'a' * 64}"]))
        self.assertEqual(self.digested, [])
        # Without a Release hash the cache is kept apart by this depbee package's own files.
        code, written, _ = self.run_inputs(self.bundled())
        self.assertEqual((code, written), (0, ["assets=bundled", f"identity=bundled-{'f' * 64}"]))
        self.assertEqual(self.digested, [mock.call(Path(actions.__file__).resolve().parent)])
        # Self-test: nothing is scanned, so no asset source. A rejected input writes nothing.
        report_mode = {"LOCKFILE": "app/package-lock.json", "REPORT": "report.json"}
        self.assertEqual(self.run_inputs(report_mode)[:2], (0, []))
        code, written, out = self.run_inputs(self.bundled() | {"MODEL_SHA256": "a" * 64})
        self.assertEqual((code, written), (1, []))
        self.assertIn("::error::depbee action: Release inputs must be given all five", out)
        self.assertIn("missing: model-version, manifest-sha256, known-malicious-version", out)

    def test_tree_digest(self):
        def digest(files):
            root = Path(tempfile.mkdtemp(dir=self.tmp))
            for name, data in files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(data)
            return actions.tree_digest(root)

        base = {"cli.py": b"code", "assets/model/model.txt": b"model", "assets/index.json": b"[]"}
        self.assertRegex(digest(base), "^[0-9a-f]{64}$")
        self.assertEqual(digest(base), digest(dict(reversed(base.items()))))
        cache = {"__pycache__/cli.cpython-313.pyc": b"1", "assets/__pycache__/x.pyc": b"2"}
        self.assertEqual(digest(base | cache), digest(base))
        others = [
            base | {"assets/model/model.txt": b"other model"},
            base | {"assets/index.json": b"[1]"},
            base | {"cli.py": b"code "},
            base | {"new.py": b""},
            {"cli.py": b"code", "assets/model.txt": b"model", "assets/index.json": b"[]"},
            # The same bytes split between a name and its content otherwise.
            {"cli.py": b"code", "assets/model/model.tx": b"tmodel", "assets/index.json": b"[]"},
        ]
        self.assertEqual(len({digest(files) for files in [base, *others]}), len(others) + 1)

    def test_invalid_inputs(self):
        cases = {
            "LOCKFILE": ["", "app/yarn.lock", "missing/package-lock.json", "../package-lock.json",
                         "/app/package-lock.json", "C:/app/package-lock.json"],
            "FAIL_ON": ["all"],
            "MAX_CHANGES": ["", "0", "-1", "1.5", "２"],
            "MODEL_VERSION": ["", "../x", "a/b", "v1?x", "-x"],
            "MODEL_SHA256": ["", "A" * 64, "a" * 63, "g" * 64],
            "MANIFEST_SHA256": [""],
            "KNOWN_MALICIOUS_VERSION": ["", "../x", "a/b", "v1?x", "-x"],
            "KNOWN_MALICIOUS_SHA256": ["", "A" * 64, "a" * 63, "g" * 64],
            "BASE_SHA": ["", "HEAD", "c" * 39],
            "REPORT": ["missing.json"],
        }  # fmt: skip
        for name, values in cases.items():
            for value in values:
                with self.subTest(name=name, value=value):
                    with self.assertRaises(actions.ActionError):
                        actions.check_inputs(self.env | {name: value}, self.tmp)
        for name in ("KNOWN_MALICIOUS_VERSION", "KNOWN_MALICIOUS_SHA256"):
            missing = {key: value for key, value in self.env.items() if key != name}
            with self.subTest(missing=name), self.assertRaisesRegex(actions.ActionError, "known"):
                actions.check_inputs(missing, self.tmp)

    def test_report_mode_does_not_check_the_index_inputs(self):
        # The self-test (ci.yml, uses: ./) gives only lockfile and report. One written for an
        # earlier version may still give Release inputs, all, some or malformed: none is read.
        report_mode = {"LOCKFILE": "app/package-lock.json", "REPORT": "report.json",
                       "KNOWN_MALICIOUS_VERSION": "../x", "KNOWN_MALICIOUS_SHA256": "x"}  # fmt: skip
        self.assertIsNone(actions.check_inputs(report_mode, self.tmp))
        self.assertIsNone(actions.check_inputs(self.env | {"REPORT": "report.json"}, self.tmp))

    def test_paths_are_checked_as_the_shell_reads_them(self):
        # Review F1: Linux dirname keeps "\" in a name and reads "-..." as an option, so such
        # paths would make plan and scan check the repository root instead of this lockfile.
        (self.tmp / "package-lock.json").write_text("{}", encoding="utf-8")
        (self.tmp / "-app").mkdir()
        (self.tmp / "-app" / "package-lock.json").write_text("{}", encoding="utf-8")
        (self.tmp / "-app" / "report.json").write_text("{}", encoding="utf-8")
        for value in ("package-lock.json", "app/package-lock.json"):
            actions.check_inputs(self.env | {"LOCKFILE": value}, self.tmp)
        cases = [
            ("LOCKFILE", "app\\package-lock.json", "separator"),
            ("LOCKFILE", ".\\package-lock.json", "separator"),
            ("LOCKFILE", "-app/package-lock.json", "start with -"),
            ("LOCKFILE", "app/-x/../package-lock.json", "start with -"),
            ("REPORT", "-app/report.json", "start with -"),
        ]
        for name, value, message in cases:
            with self.subTest(value=value), self.assertRaisesRegex(actions.ActionError, message):
                actions.check_inputs(self.env | {name: value}, self.tmp)

    def test_paths_with_control_characters_are_rejected(self):
        # Review F2: $(dirname -- "app<LF>/package-lock.json") drops the trailing LF and gives
        # "app", so plan and scan would check another folder. Rejected before the file lookup.
        cases = [
            ("LOCKFILE", "app\n/package-lock.json"),
            ("LOCKFILE", "app\r/package-lock.json"),
            ("LOCKFILE", "app\t/package-lock.json"),
            ("LOCKFILE", "app\x7f/package-lock.json"),
            ("REPORT", "report.json\n"),
            ("REPORT", "report\r.json"),
        ]
        for name, value in cases:
            with self.subTest(value=value), self.assertRaisesRegex(actions.ActionError, "control"):
                actions.check_inputs(self.env | {name: value}, self.tmp)
        actions.check_inputs(self.env | {"LOCKFILE": "app/package-lock.json"}, self.tmp)

    @unittest.skipIf(os.name == "nt", "Windows file names cannot contain LF")
    def test_folder_ending_in_lf_next_to_its_trimmed_twin(self):
        # Both app/ (from setUp) and "app<LF>" exist, the case where the shell would silently
        # scan app/ instead of the requested lockfile.
        (self.tmp / "app\n").mkdir()
        (self.tmp / "app\n" / "package-lock.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(actions.ActionError, "control"):
            actions.check_inputs(self.env | {"LOCKFILE": "app\n/package-lock.json"}, self.tmp)

    def _workspace_and_outside(self) -> tuple[Path, Path]:
        # ws2 starts with the text of ws: a string prefix comparison would let it through.
        ws, outside = self.tmp / "ws", self.tmp / "ws2"
        for root in (ws, outside):
            (root / "app").mkdir(parents=True)
            (root / "app" / "package-lock.json").write_text("{}", encoding="utf-8")
            (root / "report.json").write_text('{"results": []}', encoding="utf-8")
        return ws, outside

    def _link(self, link: Path, target: Path) -> None:
        try:
            link.symlink_to(target, target_is_directory=target.is_dir())
        except OSError as exc:  # Windows without Developer Mode or the symlink privilege
            self.skipTest(f"no symbolic link privilege here, runs on CI ubuntu: {exc.strerror}")

    def test_links_must_stay_inside_the_workspace(self):
        # Review F3: is_file() follows links, so a link in the workspace reached files outside it.
        ws, outside = self._workspace_and_outside()
        self._link(ws / "package-lock.json", outside / "app" / "package-lock.json")
        self._link(ws / "linked", outside / "app")
        self._link(ws / "outside.json", outside / "report.json")
        self._link(ws / "inner", ws / "app")
        self._link(ws / "inside.json", ws / "report.json")
        self._link(self.tmp / "ws-link", ws)
        for name, value in [("LOCKFILE", "package-lock.json"),
                            ("LOCKFILE", "linked/package-lock.json"),
                            ("REPORT", "outside.json")]:  # fmt: skip
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(actions.ActionError, "links must not point outside"),
            ):
                actions.check_inputs(self.env | {name: value}, ws)
        for name, value in [("LOCKFILE", "inner/package-lock.json"), ("REPORT", "inside.json")]:
            with self.subTest(value=value):
                actions.check_inputs(self.env | {name: value}, ws)
        # A workspace reached through a link is resolved too.
        actions.check_inputs(self.env | {"REPORT": "report.json"}, self.tmp / "ws-link")

    def test_paths_without_links_still_pass(self):
        ws, _ = self._workspace_and_outside()
        folder = ws / "한글 폴더"
        folder.mkdir()
        (folder / "package-lock.json").write_text("{}", encoding="utf-8")
        for name, value in [("LOCKFILE", "app/package-lock.json"),
                            ("LOCKFILE", "한글 폴더/package-lock.json"),
                            ("REPORT", "report.json")]:  # fmt: skip
            with self.subTest(value=value):
                actions.check_inputs(self.env | {name: value}, ws)

    @unittest.skipUnless(os.name == "nt", "Windows junctions")
    def test_junction_to_a_folder_outside_the_workspace(self):
        import _winapi  # CreateJunction needs no privilege, unlike symbolic links

        ws, outside = self._workspace_and_outside()
        try:
            _winapi.CreateJunction(str(outside / "app"), str(ws / "linked"))
            _winapi.CreateJunction(str(ws / "app"), str(ws / "inner"))
        except (AttributeError, OSError) as exc:
            self.skipTest(f"cannot create junctions here: {exc}")
        with self.assertRaisesRegex(actions.ActionError, "links must not point outside"):
            actions.check_inputs(self.env | {"LOCKFILE": "linked/package-lock.json"}, ws)
        actions.check_inputs(self.env | {"LOCKFILE": "inner/package-lock.json"}, ws)

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

    def test_verify_several_pairs(self):
        files = {}
        for name in ("model.txt", "manifest.json", "index.json"):
            path = self.tmp / name
            path.write_bytes(name.encode())
            files[path] = hashlib.sha256(name.encode()).hexdigest()
        actions.verify(list(files.items()))
        index = self.tmp / "index.json"
        with self.assertRaisesRegex(actions.ActionError, "index.json"):
            actions.verify([*files.items(), (index, "0" * 64)][1:])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            args = [str(part) for pair in files.items() for part in pair]
            self.assertEqual(actions.main(["verify", *args]), 0)
            self.assertEqual(actions.main(["verify", *args[:-1], "0" * 64]), 1)
        self.assertIn("SHA-256 mismatch for index.json", out.getvalue())

    def test_count_changes(self):
        plan = self.tmp / "plan.json"
        plan.write_text(json.dumps({"changes": [{}, {}, {}]}), encoding="utf-8")
        self.assertEqual(actions.count_changes(plan, 3), 3)
        with self.assertRaises(actions.ActionError):
            actions.count_changes(plan, 2)
        plan.write_text("{}", encoding="utf-8")
        with self.assertRaises(actions.ActionError):
            actions.count_changes(plan, 3)


class ActionFileTest(unittest.TestCase):
    """action.yml read as text (no YAML parser in the dev extra): the index steps and arguments."""

    def setUp(self):
        path = Path(__file__).resolve().parents[1] / "action.yml"
        self.text = path.read_text(encoding="utf-8")

    def step(self, name):
        """The text of the step with this name, up to the next step."""
        start = self.text.rindex("\n    - ", 0, self.text.index(f"name: {name}\n")) + 1
        end = self.text.find("\n    - ", start)
        return self.text[start : end if end != -1 else None]

    def test_release_inputs_are_optional_and_downloads_need_all_of_them(self):
        # No Release input has a default or is called required: a workflow gives none of them.
        for name in actions.RELEASE_INPUTS:
            name = name.lower().replace("_", "-")
            # The input's own lines: those indented deeper than its key.
            block = re.search(rf"^  {name}:\n((?:    .*\n)+)", self.text, re.MULTILINE).group(1)
            with self.subTest(name):
                self.assertIn("Optional, all five Release inputs or none.", block)
                self.assertNotIn("default:", block)
                self.assertNotIn("equired", block)
        setup = self.step("Check depbee inputs")
        for name in actions.RELEASE_INPUTS:
            self.assertIn(f"{name}: ${{{{ inputs.{name.lower().replace('_', '-')} }}}}", setup)
        # Only the release source (all five inputs, written by the input check) downloads.
        for name in ("Download and verify the model",
                     "Download and verify the known malicious index"):  # fmt: skip
            self.assertTrue(
                self.step(name).startswith("    - if: steps.setup.outputs.assets == 'release'\n"),
                name,
            )
        self.assertEqual(self.text.count("releases/download/"), 2)
        self.assertEqual(self.text.count("curl "), 2)

    def test_scan_uses_only_trusted_assets_and_settings(self):
        scan = self.step("Scan with depbee")
        self.assertIn("ASSETS: ${{ steps.setup.outputs.assets }}", scan)
        self.assertIn("DEPBEE_CONFIG_DIR: ${{ steps.setup.outputs.out }}/config", scan)
        self.assertIn('mkdir "$out/config"', self.step("Check depbee inputs"))
        unset = scan.index("unset DEPBEE_MODEL_DIR DEPBEE_KNOWN_MALICIOUS_DIR\n")
        run = scan.index("python -I -m depbee scan ")
        self.assertLess(unset, run)
        # The Release folders only for the release source; any other source but bundled stops.
        chosen = scan[unset:run]
        self.assertIn(
            'assets=()\n        if [ "$ASSETS" = release ]; then\n'
            '          assets=(--model-dir "$OUT/model" --known-malicious-dir "$OUT/known-malicious")\n'
            '        else\n          test "$ASSETS" = bundled\n        fi\n',
            chosen,
        )
        self.assertIn('--base-ref "$BASE_SHA" --extract "${assets[@]}"', scan)
        self.assertEqual(self.text.count("--model-dir"), 1)
        self.assertEqual(self.text.count("--known-malicious-dir"), 1)
        # The report of a scan is written by depbee into the run's own folder; only the
        # self-test copies a given one, and only that one is judged without the names.
        self.assertIn('--output "$OUT/report.json"', scan)
        self.assertEqual(self.text.count("cp -- "), 1)
        self.assertIn(
            'if [ -n "$REPORT" ]; then\n          cp -- "$REPORT" "$OUT/report.json"', scan
        )
        decide = self.step("Decide from the report")
        self.assertIn("REPORT: ${{ inputs.report }}", decide)
        self.assertIn('report "$OUT/report.json"\n        ${REPORT:+--self-test}\n', decide)
        self.assertEqual(self.text.count("--self-test"), 2)  # that line and its comment

    def test_depbee_runs_installed_and_isolated_from_the_pull_request(self):
        install = self.step("Install depbee")
        self.assertIn('cd "$OUT"\n', install)
        self.assertIn(
            'python -I -m pip install --disable-pip-version-check --no-input "$GITHUB_ACTION_PATH[',
            install,
        )
        self.assertEqual(self.text.count("pip install"), 1)
        # Every Python start is isolated (-I) and depbee is the installed module, not a script
        # found on PATH or a folder of the pull request.
        starts = re.findall(r"^ *[^# ].*\bpython .*$|^ *python .*$", self.text, re.MULTILINE)
        self.assertEqual(len(starts), 8)
        for line in starts:
            self.assertRegex(
                line, r'python -I (-m (pip|depbee) |"\$GITHUB_ACTION_PATH/src/depbee/)'
            )
        self.assertNotRegex(self.text, r"(?m)^\s*(if )?depbee (plan|scan)\b")
        # No step builds or installs the project being checked.
        self.assertNotRegex(self.text, r"(?m)^\s*(if )?(npm|npx|node|yarn|pnpm|make)\b")
        # The base is the pull request's base commit, in the check, the plan and the scan.
        base = "BASE_SHA: ${{ github.event.pull_request.base.sha }}"
        for name in ("Check depbee inputs", "Count changed lockfile entries", "Scan with depbee"):
            self.assertIn(base, self.step(name), name)
        self.assertEqual(self.text.count('--base-ref "$BASE_SHA"'), 2)
        # Third-party actions are pinned to full commit ids.
        uses = re.findall(r"uses: (\S+)", self.text)
        self.assertEqual(len(uses), 4)
        for action in uses:
            self.assertRegex(action, r"^actions/[a-z/-]+@[0-9a-f]{40}$")
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("GITHUB_TOKEN", self.text)

    def test_index_inputs_and_steps(self):
        names = ["Check depbee inputs", "Install depbee", "Download and verify the model",
                 "Download and verify the known malicious index", "Count changed lockfile entries",
                 "Scan with depbee", "Decide from the report"]  # fmt: skip
        positions = [self.text.index(f"name: {name}\n") for name in names]
        self.assertEqual(positions, sorted(positions))
        model = self.step("Download and verify the model")
        index = self.step("Download and verify the known malicious index")
        curl = (
            "curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https'"
        )
        self.assertIn(curl, model)
        self.assertIn(curl, index)
        self.assertIn("--max-time 300", index)
        self.assertIn(
            'base="https://github.com/26-Capstone-Project-Team01/depbee/releases/download/'
            '$KNOWN_MALICIOUS_VERSION"',
            index,
        )
        self.assertIn("for name in index manifest; do", index)
        self.assertIn('--output "$OUT/known-malicious/$name.json"', index)
        self.assertIn('"$base/known-malicious-$name.json"', index)
        verify = 'verify \\\n          "$OUT/known-malicious/index.json" "$KNOWN_MALICIOUS_SHA256"'
        self.assertIn(verify, index)
        scan = self.step("Scan with depbee")
        self.assertIn('--model-dir "$OUT/model" --known-malicious-dir "$OUT/known-malicious"', scan)
        # The feature cache holds no detector results: its keys stay without the index. They
        # have the trusted model's identity from the input check, never an empty hash input.
        keys = [line for line in self.text.splitlines() if "key:" in line or "keys:" in line]
        self.assertEqual(len(keys), 3)
        prefix = (
            "depbee-${{ runner.os }}-${{ steps.setup.outputs.identity }}-"
            "${{ steps.setup.outputs.extractor }}-"
        )
        for line in keys:
            self.assertNotIn("known-malicious", line)
            self.assertNotIn("inputs.", line)
            self.assertIn(f"key: {prefix}", line.replace("restore-keys", "key"))


if __name__ == "__main__":
    unittest.main()
