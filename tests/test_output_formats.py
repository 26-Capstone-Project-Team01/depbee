"""Text, Markdown and JSON of the same report (SVC-04, D-13): same verdicts, reasons, detector
states and exit code; package strings stay inert; results keep their order.

Synthetic only: fake detectors and predictor from test_detectors; nothing is rendered or executed.
"""

import argparse
import contextlib
import copy
import io
import json
import unittest
from unittest import mock

from test_detectors import ADVISORY, DetectorFixture, KnownList, Rules, rule
from test_markdown import HOSTILE, outside_code_spans, unescaped_pipes
from test_workflow import FakePredictor, package

from depbee.cli import (
    DETECTOR_REASON_LABELS,
    KNOWN_STATUS_LABELS,
    OVERALL_LABELS,
    REASON_LABELS,
    RULE_STATUS_LABELS,
    STATUS_LABELS,
    _emit,
    _print_markdown,
    _print_text,
    main,
)
from depbee.pipeline import scan

FORMATS = ("text", "markdown", "json")


def capture(function, *args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        function(*args)
    return out.getvalue()


def as_json(report):
    return capture(_emit, report, argparse.Namespace(output=None, command="scan", format="json"))


def slot_text(slot, labels):
    text = labels[slot["status"]]
    return text + (f" ({DETECTOR_REASON_LABELS[slot['reason']]})" if slot["reason"] else "")


class FormatFixture(DetectorFixture):
    def mixed(self):
        """One report with known malicious hits, a D-7 failure, an input_failed slot, a removed
        and an unanalyzable change; scores chosen so that the order is not the lockfile's."""
        for name, version in (("zeta", "1.1.0"), ("high", "1.1.0"), ("low", "1.1.0"),
                              ("lower", "1.1.0"), ("broken", "1.1.0"), ("gone", None)):  # fmt: skip
            self.old["packages"][f"node_modules/{name}"] = package()
            if version:
                self.new["packages"][f"node_modules/{name}"] = package(version)
        self.old["packages"]["node_modules/x"] = {**package(), "name": "x"}
        self.new["packages"]["node_modules/x"] = {**package(), "name": "y",
                                                  "resolved": "https://[::1"}  # fmt: skip
        self.save_locks()
        scores = {"example": 0.1, "zeta": 0.9, "high": 0.95, "low": 0.3, "lower": 0.2,
                  "broken": 0.4}  # fmt: skip
        request = self.request()
        names = {c["change_id"]: c["location"].rsplit("/", 1)[-1] for c in request["changes"]}
        artifact = self.artifact()
        for row in artifact["results"]:
            row["features"] = {"signal": scores[names[row["change_id"]]]}

        class Listed(KnownList):
            def match(self, name, version):
                return list(self.result) if name in ("example", "zeta") else []

        class BrokenFor(Rules):
            def check(self, change, analysis):
                if change["location"].endswith("broken"):
                    raise RuntimeError("synthetic rule engine crash")
                return [rule("hit")] if change["location"].endswith("lower") else [rule()]

        return scan(request, self.adapter(artifact), FakePredictor(),
                    known_malicious=Listed((ADVISORY,)), rules=BrokenFor())  # fmt: skip

    def cases(self):
        hit_and_failed = Rules((rule("hit"), rule("failed", "R2", detail="timeout")))
        unsupported = {"status": "unsupported", "reason": "no_baseline", "error": "none"}
        undated = type("Undated", (KnownList,), {"list_as_of": "2026-11-01"})
        return {
            "known hit, low ML": self.scan_with(0.1, known_malicious=KnownList((ADVISORY,)),
                                               rules=Rules()),
            "D-7 rule failed": self.scan_with(0.9, known_malicious=KnownList(),
                                              rules=Rules(error=RuntimeError("crashed"))),
            "known hit over D-7": self.scan_with(0.1, known_malicious=KnownList((ADVISORY,)),
                                                 rules=Rules(error=RuntimeError("crashed"))),
            "rule hit and failed": self.scan_with(0.1, rules=hit_and_failed),
            "rules not_run": self.scan_with(analyzer=False, known_malicious=KnownList(),
                                            rules=Rules()),
            "analysis failed": self.scan_with(row={"status": "failed", "error": "mismatch"},
                                              known_malicious=KnownList(), rules=Rules()),
            "no baseline": self.scan_with(row=unsupported, known_malicious=KnownList(),
                                          rules=Rules()),
            "undated list": self.scan_with(0.1, known_malicious=undated()),
            "not configured": self.scan_with(0.9),
            "mixed": self.mixed(),
        }  # fmt: skip


class EquivalenceTests(FormatFixture):
    def test_each_item_shows_its_report_values_in_every_format(self):
        for label, report in self.cases().items():
            with self.subTest(label):
                kept = copy.deepcopy(report)
                text, markdown = capture(_print_text, report), capture(_print_markdown, report)
                self.assertEqual(report, kept)  # rendering reads only
                self.assertEqual(json.loads(as_json(report)), report)
                overall = f"{OVERALL_LABELS[report['status']]} (종료 코드 {report['exit_code']})"
                self.assertTrue(text.startswith(f"depbee 검사 결과: {overall}\n"))
                self.assertTrue(markdown.startswith(f"## depbee 검사 결과: {overall}\n"))
                blocks = text.split("\n\n")
                table = [line for line in markdown.split("\n") if line.startswith("| ")]
                sections = markdown.split("\n### ")
                for item in report["results"]:
                    self.check_text(item, blocks)
                    self.check_markdown(item, table, sections, report["detectors"])
                for output in (text, markdown):
                    self.assertNotIn("확률", output)  # an ML risk score, never a probability
                    self.assertIn("패키지가 안전하다는 보증이 아닙니다.", output)

    def check_text(self, item, blocks):
        version = item["after_version"] or item["before_version"]
        head = (
            f"[{STATUS_LABELS[item['status']]}] {item['package']}@{version}  ({item['location']})"
        )
        (block,) = [b for b in blocks if b.startswith(head)]
        lines = block.strip("\n").split("\n")
        if item.get("reason"):
            self.assertIn(f"  이유: {REASON_LABELS[item['reason']]}", lines)
        km, rules = item["known_malicious"], item["rules"]
        if km["reason"] == "detector_not_configured":
            self.assertFalse([line for line in lines if line.startswith("  기지 악성")])
        else:
            self.assertTrue(any(line.startswith(f"  기지 악성: {slot_text(km, KNOWN_STATUS_LABELS)}")
                                for line in lines), lines)  # fmt: skip
        if rules["reason"] == "detector_not_configured":
            self.assertFalse([line for line in lines if line.startswith("  규칙")])
        else:
            self.assertTrue(any(line.startswith(f"  규칙: {slot_text(rules, RULE_STATUS_LABELS)}")
                                for line in lines), lines)  # fmt: skip
            self.assertEqual(sum(line.startswith("    - ") and "0.0.0-example" in line for line in lines),
                             len(rules["checks"]))  # fmt: skip
        ml = item["ml"]["status"]
        if item["score"] is not None:
            self.assertIn(f"  ML 위험 점수: {item['score']:.3f} "
                          f"({'기준 이상' if ml == 'hit' else '기준 미만'})", lines)  # fmt: skip
        elif item["status"] != "removed":
            self.assertIn(f"  ML 위험 점수: 없음({'실패' if ml == 'failed' else '미실행'})", lines)

    def check_markdown(self, item, table, sections, detectors):
        (row,) = [r for r in table if f"| ` {item['location']} ` |" in r]
        cells = row.strip("| ").split(" | ")
        self.assertEqual(cells[0], STATUS_LABELS[item["status"]])
        column = 4
        for key, labels in (
            ("known_malicious", KNOWN_STATUS_LABELS),
            ("rules", RULE_STATUS_LABELS),
        ):
            if detectors[key] is not None:
                expected = labels[item[key]["status"]]
                hit = key == "known_malicious" and item[key]["status"] == "hit"
                self.assertEqual(cells[column], f"**{expected}**" if hit else expected)
                column += 1
        self.assertEqual(cells[column + 1], REASON_LABELS[item["reason"]] if item.get("reason")
                         else "-")  # fmt: skip
        if detectors["known_malicious"] or detectors["rules"]:
            version = item["after_version"] or item["before_version"]
            (section,) = [s for s in sections
                          if s.startswith(f"{STATUS_LABELS[item['status']]}: ` {item['package']}@{version} `")]  # fmt: skip
            for key, name, labels in (("known_malicious", "기지 악성", KNOWN_STATUS_LABELS),
                                      ("rules", "규칙", RULE_STATUS_LABELS)):  # fmt: skip
                if detectors[key] is not None:
                    self.assertIn(f"\n- {name}: {slot_text(item[key], labels)}", section)

    def test_known_malicious_warning_and_unfinished_items_are_emphasized(self):
        report = self.cases()["mixed"]
        text, markdown = capture(_print_text, report), capture(_print_markdown, report)
        warning = "기지 악성 기록 일치 2개."
        self.assertIn(f"경고: {warning} 낮은 ML 위험 점수는 이 경고를 취소하지 않습니다.", text)
        self.assertIn(f"- **경고: {warning}** 낮은 ML 위험 점수는", markdown)
        self.assertIn("보류 2개. 검사를 끝내지 못한 항목이며 통과가 아닙니다.", text)
        self.assertIn("- **보류 2개.** 검사를 끝내지 못한 항목이며 통과가 아닙니다.", markdown)
        self.assertIn("기지 악성 목록: EXAMPLE-KNOWN-MALICIOUS-LIST, 기준 시점 2026-11-01T00:00:00Z",
                      text)  # fmt: skip
        self.assertIn("- 규칙: ` example-ruleset-0.0.0 `", markdown)
        self.assertIn("| 위험 | ` example ` | ` 1.1.0 ` | - | **일치** | 미적중 | 0.100 (기준 미만) | - |",
                      markdown)  # fmt: skip
        self.assertIn("  기지 악성: 일치\n    - EXAMPLE-ADVISORY-0001 (버전 목록에 있음, 영향 버전 1.1.0)",
                      text)  # fmt: skip
        self.assertIn("  규칙: 실패 (탐지기 실패), 상세: synthetic rule engine crash\n", text)
        self.assertIn("  기지 악성: 실패 (탐지기 입력을 얻지 못함), 상세: ", text)
        self.assertIn("  규칙/ML: 규칙만 적중(불일치). 판정에 쓰지 않는 표시입니다.", text)
        self.assertIn("    - 적중 EXAMPLE-RULE-0001 0.0.0-example, 근거: synthetic evidence, "
                      "위치: package/index.js:3", text)  # fmt: skip

    def test_not_run_and_failed_have_different_words(self):
        cases = self.cases()
        text = capture(_print_text, cases["rules not_run"])
        self.assertIn("  규칙: 미실행 (분석기 연결 안 됨)\n", text)
        self.assertIn("  ML 위험 점수: 없음(미실행)\n", text)
        text = capture(_print_text, cases["analysis failed"])
        self.assertIn("  규칙: 실패 (탐지기 입력을 얻지 못함)\n", text)
        self.assertIn("  ML 위험 점수: 없음(실패)\n", text)
        text = capture(_print_text, cases["rule hit and failed"])
        self.assertIn("    - 실패 R2 0.0.0-example, 상세: timeout\n", text)
        self.assertIn("규칙/ML: 규칙만 적중(불일치). 판정에 쓰지 않는 표시입니다.", text)
        text = capture(_print_text, cases["not configured"])
        self.assertIn("기지 악성 목록: 연결 안 됨(미실행)\n규칙: 연결 안 됨(미실행)\n", text)

    def test_cli_exit_code_and_json_do_not_depend_on_the_format(self):
        for label, report in self.cases().items():
            for fmt in FORMATS:
                with (
                    self.subTest(label, format=fmt),
                    mock.patch("depbee.cli.scan_project", return_value=copy.deepcopy(report)),
                ):
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        code = main(["scan", str(self.project), "--format", fmt])
                    self.assertEqual(code, report["exit_code"])
                    if fmt == "json":
                        self.assertEqual(json.loads(out.getvalue()), report)


class OrderTests(FormatFixture):
    def test_risky_unfinished_passed_removed_then_score(self):
        report = self.mixed()
        expected = ["high", "zeta", "example", "broken", "x", "low", "lower", "gone"]
        text, markdown = capture(_print_text, report), capture(_print_markdown, report)
        text_order = [line.split("(node_modules/")[1].rstrip(")") for line in text.split("\n")
                      if line.startswith("[")]  # fmt: skip
        table_order = [line.split("` node_modules/")[1].split(" `")[0]
                       for line in markdown.split("\n") if line.startswith("| ") and "node_modules/" in line]  # fmt: skip
        self.assertEqual(text_order, expected)
        self.assertEqual(table_order, expected)
        self.assertEqual([r["location"].rsplit("/", 1)[-1] for r in json.loads(as_json(report))
                          ["results"]], [r["location"].rsplit("/", 1)[-1] for r in report["results"]])  # fmt: skip


class EscapeTests(FormatFixture):
    def report(self, text):
        """A report with connected detectors whose every external string is text."""
        report = self.scan_with(0.1, known_malicious=KnownList((ADVISORY,)),
                                rules=Rules((rule("hit"), rule("failed", "R2", detail="t"))))  # fmt: skip
        report["detectors"]["known_malicious"].update(source=text, list_as_of=text)
        report["detectors"]["rules"]["ruleset_version"] = text
        report["model_id"] = text
        item = report["results"][0]
        item.update(package=text, location=text, after_version=text, detail=text,
                    rule_ml_agreement=text)  # fmt: skip
        item["known_malicious"].update(reason=text, detail=text)
        item["known_malicious"]["matches"] = [{"advisory_id": text, "match_kind": text,
                                               "affected": text}]  # fmt: skip
        item["rules"].update(reason=text, detail=text)
        for check in item["rules"]["checks"]:
            check.update(rule_id=text, rule_version=text, evidence=[text, text], detail=text,
                         status=text, locations=[{"file": text, "line": 3}])  # fmt: skip
        return report

    def test_detector_strings_stay_inert(self):
        plain_md = capture(_print_markdown, self.report("plain"))
        plain_text = capture(_print_text, self.report("plain"))
        self.assertNotIn("plain", outside_code_spans(plain_md))
        for text in HOSTILE:
            with self.subTest(text=text):
                markdown = capture(_print_markdown, self.report(text))
                self.assertEqual(outside_code_spans(markdown), outside_code_spans(plain_md))
                table = [line for line in markdown.split("\n") if line.startswith("|")]
                self.assertEqual(len(table), 3)
                self.assertEqual({unescaped_pipes(line) for line in table}, {10})  # 9 columns
                output = capture(_print_text, self.report(text))
                self.assertEqual(output.count("\n"), plain_text.count("\n"))
                for rendered in (markdown, output):
                    self.assertTrue(all(c.isprintable() or c == "\n" for c in rendered))


if __name__ == "__main__":
    unittest.main()
