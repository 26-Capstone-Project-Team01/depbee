"""Markdown output (DEV-02f): escaping of package data, layout, and the same data as JSON.

Synthetic strings only; nothing is rendered or executed. A GitHub job summary is not checked.
"""

import contextlib
import copy
import io
import json
import re
import unittest
from unittest import mock

from test_contract import ExplainingPredictor
from test_extract import FakeBackend, PackagePredictor, packument
from test_workflow import FakePredictor, Fixture, package

from depbee.cli import _cell, _md, _print_markdown, main
from depbee.pipeline import scan

HOSTILE = [
    "a|b",
    "back\\slash\\",
    "line\nbreak\r\n",
    "`tick` ``two`` ```three```",
    "`",
    "<img src=x onerror=alert(1)>",
    "<!-- hidden",
    "[link](https://evil.test)",
    "![image](https://evil.test/x.png)",
    "**bold** _em_ ~~strike~~",
    "https://evil.test/a www.evil.test mail@evil.test",
    "&amp; &#60;b&#62;",
    "# heading",
    "\x1b[2J‮",
]


def render(report):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        _print_markdown(report)
    return out.getvalue()


def unescaped_pipes(line):
    return len(re.findall(r"(?<!\\)\|", line))


def outside_code_spans(text):
    """Text left after removing code spans, per CommonMark: a backtick run opens a span that the
    next run of the same length closes; a run without one stays literal (and is kept here)."""
    lines = []
    for line in text.split("\n"):
        runs = [m.span() for m in re.finditer("`+", line)]
        kept, position, k = [], 0, 0
        while k < len(runs):
            start, end = runs[k]
            close = next((j for j in range(k + 1, len(runs))
                          if runs[j][1] - runs[j][0] == end - start), None)  # fmt: skip
            if close is None:
                k += 1
                continue
            kept.append(line[position:start])
            position, k = runs[close][1], close + 1
        lines.append("".join(kept) + line[position:])
    return "\n".join(lines)


class MarkdownEscapeTests(Fixture):
    def report(self, text):
        """A flagged report whose every external string is text."""
        artifact = self.artifact({"signal": 0.9, text: text})
        artifact["results"][0]["evidence"] = [text]
        report = scan(self.request(), self.adapter(artifact), ExplainingPredictor())
        row = report["results"][0]
        row.update(package=text, location=text, after_version=text, compared_version=text,
                   detail=text, reason=text)  # fmt: skip
        row["explanation"] = [{"feature": text, "value": text, "contribution": 0.5}]
        report["model_id"] = text
        return report

    def test_every_external_string_is_one_inert_code_span(self):
        plain = outside_code_spans(render(self.report("plain")))
        self.assertNotIn("plain", plain)
        for text in HOSTILE:
            with self.subTest(text=text):
                output = render(self.report(text))
                # Outside code spans the output is the same whatever the data: package text can
                # never become HTML, a link, an image, emphasis, an autolink or a new line.
                self.assertEqual(outside_code_spans(output), plain)
                table = [line for line in output.split("\n") if line.startswith("|")]
                self.assertEqual(len(table), 3)  # header, separator, one result
                self.assertEqual({unescaped_pipes(line) for line in table}, {8})  # 7 columns
                self.assertNotIn("\x1b", output)
                self.assertNotIn("\r", output)

    def test_code_span_survives_backticks_and_control_characters(self):
        self.assertEqual(_md("a"), "` a `")
        self.assertEqual(_md("x`y"), "`` x`y ``")
        self.assertEqual(_md("``a```"), "```` ``a``` ````")
        self.assertEqual(_md("a\nb\x1b"), "` a\\u000ab\\u001b `")
        self.assertEqual(_cell(_md("a|b")), "` a\\|b `")


class MarkdownLayoutTests(Fixture):
    def test_statuses_order_scores_and_note(self):
        self.old["packages"]["node_modules/gone"] = package()
        self.old["packages"]["node_modules/zeta"] = package()
        self.new["packages"]["node_modules/zeta"] = package("1.1.0")
        self.new["packages"]["node_modules/local"] = {**package(), "resolved": "file:x.tgz"}
        self.save_locks()
        artifact = self.artifact()
        artifact["results"][0]["features"] = {"signal": 0.0}  # example: score 0, passed
        report = scan(self.request(), self.adapter(artifact), FakePredictor())
        output = render(report)
        rows = [line for line in output.split("\n") if line.startswith("| ")][2:]  # no header
        self.assertEqual([r.split(" | ")[0] for r in rows], ["| 위험", "| 보류", "| 통과", "| 삭제"])
        self.assertIn("| 통과 | ` example ` | ` 1.1.0 ` | - | 0.000 | - |", output)  # score 0
        self.assertIn("| 보류 | ` local ` | ` 1.0.0 ` | - | - | npm 공식 registry가 아닌 출처 |",
                      output)  # fmt: skip
        self.assertIn("| 삭제 | ` gone ` | - | - | - | 현재 lockfile에서 삭제됨 |", output)
        self.assertIn("- 바뀐 의존성 4개: 위험 1, 통과 1, 보류 1, 삭제 1\n", output)
        self.assertIn("- 범위: lockfile에서 바뀐 의존성만 검사했습니다.", output)
        self.assertNotIn("분석 시간", output)  # no times in an --analysis report
        self.assertNotIn("소요 시간", output)
        self.assertTrue(output.endswith("\n> '통과'는 모델의 판정일 뿐 패키지가 안전하다는 보증이 아닙니다.\n"))

    def test_empty_report_and_times(self):
        self.new = copy.deepcopy(self.old)
        self.save_locks()
        output = render(scan(self.request(), None, None))
        self.assertIn("- 바뀐 의존성 0개: 위험 0, 통과 0, 보류 0\n", output)
        self.assertNotIn("|", output)
        report = scan(self.request(), None, None)
        report.update(elapsed_seconds=1.5, results=[{
            "change_id": "x", "location": "node_modules/a", "package": "a",
            "before_version": None, "after_version": "1.0.0", "status": "not_flagged",
            "score": 0.1, "evidence": [], "elapsed_seconds": 0.25, "cache_hit": True}])  # fmt: skip
        output = render(report)
        self.assertIn("- 소요 시간: 1.500초\n", output)
        self.assertIn("| 분석 시간 |", output)
        self.assertIn(" | 0.250초, 캐시 사용 |", output)
        self.assertNotIn("### ", output)  # nothing to detail


class MarkdownCliTests(Fixture):
    def setUp(self):
        super().setUp()
        self.doc = packument({"1.0.1": "2026-01-02T00:00:00Z", "1.1.0": "2026-01-03T00:00:00Z"})
        backend = mock.patch("depbee.analysis.extractor.FeatureExtractorBackend",
                             return_value=FakeBackend(self.doc))  # fmt: skip
        model = mock.patch("depbee.service.LightGBMPredictor", return_value=PackagePredictor())
        for patcher in (backend, model):
            patcher.start()
            self.addCleanup(patcher.stop)

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_same_data_and_exit_code_as_json_without_progress(self):
        scan_args = ["scan", str(self.project), "--base-lock", str(self.base), "--extract",
                     "--model-dir", "m", "--no-cache"]  # fmt: skip
        for args in (scan_args, ["check", "example@1.1.0", "--model-dir", "m", "--no-cache"]):
            with self.subTest(args[0]):
                output = self.root / f"{args[0]}.json"
                with mock.patch("time.monotonic", return_value=7.0):
                    code, out, err = self.cli(*args, "--format", "markdown", "--output",
                                              str(output))  # fmt: skip
                    json_code, json_out, _ = self.cli(*args, "--format", "json")
                self.assertEqual((code, err), (json_code, ""))  # no progress in markdown
                self.assertEqual(output.read_bytes(), json_out.encode())  # --output stays JSON
                self.assertTrue(out.startswith("## depbee 검사 결과: 위험 판정 있음 (종료 코드 1)\n"))
                self.assertIn("| ` example ` | ` 1.1.0 ` | ` 1.0.1 ` | 0.900 |", out)
                self.assertIn("- 소요 시간: 0.000초\n", out)
                original = output.read_bytes()
                code, out, err = self.cli(*args, "--format", "markdown", "--output", str(output))
                self.assertEqual((code, out), (2, ""))
                self.assertEqual(json.loads(err)["status"], "error")
                self.assertEqual(output.read_bytes(), original)
        code, out, _ = self.cli("check", "example@1.1.0", "--no-cache", "--format", "markdown",
                                "--model-dir", "m")  # fmt: skip
        self.assertIn("- 범위: lockfile 없이 registry 정보로 이 버전 하나만 검사했습니다.", out)
        self.assertIn("  - ` lockfile 없이 registry 정보로 검사 `", out)
        self.assertNotIn("lockfile에서 바뀐", out)


if __name__ == "__main__":
    unittest.main()
