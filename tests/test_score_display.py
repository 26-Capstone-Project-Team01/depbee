"""How an ML risk score is shown to people: one rule (actions.score_text) on the text and Markdown
output, the update gate lines, the Actions gate and the dashboard.

Synthetic only: reports of pipeline.scan() with the fake predictor, whose score and threshold are
set here. Nothing is rendered in a browser or executed, and the stored values never change.
"""

import contextlib
import copy
import io
import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock

import test_actions  # the modules: their test classes, imported by name, would run again here
import test_dashboard
from test_detectors import ADVISORY, KnownList
from test_markdown import outside_code_spans
from test_output_formats import FormatFixture, as_json, capture, older
from test_workflow import FakePredictor

from depbee import actions, history, service
from depbee.actions import plain_number, score_raw, score_text
from depbee.cli import _apply_item, _clean, _print_markdown, _print_text, _text_label

TINY = 3.950535635136895e-07  # the stored score of an ordinary lodash pair
FULL = "0.0000003950535635136895"  # the same digits without the exponent


class ScoreTextTests(unittest.TestCase):
    def test_short_form_unless_it_would_misstate_the_side_of_the_threshold(self):
        for score, threshold, text, raw in (
            (0.0, 0.5, "0", None),
            (-0.0, 0.5, "0", None),
            (0, None, "0", None),
            (TINY, 0.5, "<0.001", repr(TINY)),
            (TINY, None, "<0.001", repr(TINY)),  # a report without a threshold
            (0.000999, 0.001, "<0.001", "0.000999"),
            (0.9, 0.5, "0.900", None),
            (0.1234567, 0.5, "0.123", "0.1234567"),
            # 0.500 would read as the threshold itself.
            (0.4996, 0.5, "0.4996", None),
            (0.5004, 0.5, "0.5004", None),
            (0.5000001, 0.5, "0.5000001", None),
            (0.5, 0.5, "0.500", None),  # equal, and shown as equal
            # Custom thresholds: 0.500 would be on the other side, in both directions.
            (0.50041, 0.5004, "0.50041", None),
            (0.49955, 0.4996, "0.49955", None),
            (0.12345, 0.12345, "0.12345", None),
            # A threshold below 0.001: <0.001 would say neither side.
            (0.0007, 0.0005, "0.0007", None),
            (0.0003, 0.0005, "0.0003", None),
            (0.0005, 0.0005, "0.0005", None),
            (TINY, 1e-06, FULL, None),
            (1e-07, 1e-07, "0.0000001", None),
        ):
            with self.subTest(score=score, threshold=threshold):
                self.assertEqual(score_text(score, threshold), text)
                self.assertEqual(score_raw(score, threshold), raw)

    def test_a_shown_number_reads_against_the_threshold_as_the_stored_score_does(self):
        values = (0.0, 1e-07, TINY, 0.0004, 0.0005, 0.0006, 0.000999, 0.001, 0.0010004, 0.4994,
                  0.49955, 0.4996, 0.49996, 0.5, 0.5000001, 0.5004, 0.50041, 0.9, 0.9996, 1.0)  # fmt: skip
        for threshold in values[1:-1]:
            for score in values:
                with self.subTest(score=score, threshold=threshold):
                    text = score_text(score, threshold)
                    if text == "<0.001":  # says only that the score is under 0.001
                        self.assertTrue(0 < score < 0.001 <= threshold)
                        continue
                    shown, limit = Decimal(text), Decimal(repr(threshold))
                    self.assertEqual((shown > limit) - (shown < limit),
                                     (score > threshold) - (score < threshold))  # fmt: skip
                    self.assertEqual(shown == 0, score == 0)

    def test_threshold_in_full_and_values_that_are_no_finite_number(self):
        for value, text in ((0.5, "0.5"), (0.999, "0.999"), (1e-06, "0.000001"),
                            (0.0005, "0.0005"), (1, "1"), (None, "기록 없음")):  # fmt: skip
            self.assertEqual(plain_number(value), text)
        # Nothing is compared with a threshold that is no finite number.
        for threshold in (None, "0.5", True, float("nan")):
            self.assertEqual(score_text(0.4996, threshold), "0.500")
        self.assertEqual(score_text(float("nan"), 0.5), "nan")


class RenderedTests(FormatFixture):
    def scored(self, score, threshold=0.5, **detectors):
        """A report of one item with this stored score, decided by pipeline.scan() against
        threshold."""
        with mock.patch.object(FakePredictor, "threshold", threshold):
            return self.scan_with(score, **detectors)

    def both(self, report):
        return capture(_print_text, report), capture(_print_markdown, report)

    def test_tiny_score_is_not_zero_and_its_stored_value_is_in_the_details(self):
        report = self.scored(TINY)
        kept = copy.deepcopy(report)
        text, markdown = self.both(report)
        self.assertIn(f"  ML 위험 점수: <0.001 (기준 미만)\n  점수 원값: {TINY!r}\n", text)
        self.assertIn(" | <0.001 (기준 미만) | ", markdown)
        self.assertIn(f"\n- 점수 원값: {TINY!r}\n", markdown)
        for output in (text, markdown):
            self.assertNotIn("0.000", output)
            self.assertIn("판정 기준 점수 0.5\n", output)
        # The report itself is as it was: the same JSON, verdict and exit code.
        self.assertEqual(report, kept)
        self.assertEqual(json.loads(as_json(report)), kept)
        self.assertEqual((report["results"][0]["score"], report["exit_code"]), (TINY, 0))

    def test_markdown_stored_value_says_which_lockfile_location_it_belongs_to(self):
        # The same package and version at two locations: the two details have one heading.
        report = self.scored(2e-07)
        (row,) = report["results"]
        hostile = "node_modules/`x`/[link](https://evil.test)/node_modules/example"
        report["results"] = [row, {**row, "location": hostile, "score": 4e-07}]
        markdown = capture(_print_markdown, report)
        self.assertEqual(markdown.count("\n### 통과: ` example@1.1.0 `\n"), 2)
        self.assertIn("\n- 점수 원값: 2e-07\n- 위치: ` node_modules/example `\n", markdown)
        self.assertIn(f"\n- 점수 원값: 4e-07\n- 위치: `` {hostile} ``\n", markdown)
        # The location is one code span: its backticks and link never reach the rendered text.
        plain = outside_code_spans(markdown)
        for inert in ("`", "[link]", "evil.test"):
            self.assertNotIn(inert, plain)

    def test_markdown_location_spells_a_newline_and_its_typed_escape_apart(self):
        # Escaped for the output, a real newline is the six characters the other location holds.
        report = self.scored(2e-07)
        (row,) = report["results"]
        real, typed = "node_modules/a\nb", "node_modules/a\\u000ab"
        report["results"] = [{**row, "location": real},
                             {**row, "location": typed, "score": 4e-07}]  # fmt: skip
        kept = copy.deepcopy(report)
        markdown = capture(_print_markdown, report)
        shown = {real: "` node_modules/a\\u000ab `", typed: "` node_modules/a\\\\u000ab `"}
        for location, score in ((real, "2e-07"), (typed, "4e-07")):
            # Each spelling is in one table row and under its own row's stored value.
            self.assertEqual(markdown.count(f" | {shown[location]} |\n"), 1)
            self.assertIn(f"\n- 점수 원값: {score}\n- 위치: {shown[location]}\n", markdown)
        self.assertEqual(report, kept)  # only the Markdown spelling differs, never the report

    def test_exact_zero_and_exact_scores_have_no_separate_stored_value(self):
        for score, shown in ((0.0, "0"), (-0.0, "0"), (0.9, "0.900")):
            with self.subTest(score=score):
                text, markdown = self.both(self.scored(score))
                label = "기준 이상" if score >= 0.5 else "기준 미만"
                self.assertIn(f"  ML 위험 점수: {shown} ({label})\n", text)
                self.assertIn(f" | {shown} ({label}) | ", markdown)
                self.assertNotIn("점수 원값", text + markdown)

    def test_score_next_to_the_threshold_keeps_its_side_and_equality(self):
        for score, threshold, shown, label in (
            (0.4996, 0.5, "0.4996", "기준 미만"),
            (0.5, 0.5, "0.500", "기준 이상"),
            (0.5004, 0.5, "0.5004", "기준 이상"),
            (0.49955, 0.4996, "0.49955", "기준 미만"),
            (0.50041, 0.5004, "0.50041", "기준 이상"),
            (0.0003, 0.0005, "0.0003", "기준 미만"),
            (0.0005, 0.0005, "0.0005", "기준 이상"),
            (0.0007, 0.0005, "0.0007", "기준 이상"),
            (TINY, 1e-06, FULL, "기준 미만"),
            (1e-06, 1e-06, "0.000001", "기준 이상"),
        ):
            with self.subTest(score=score, threshold=threshold):
                report = self.scored(score, threshold)
                # The status is the scan's own (pipeline.scan); the output only words it.
                hit = report["results"][0]["ml"]["status"] == "hit"
                self.assertEqual(hit, label == "기준 이상")
                text, markdown = self.both(report)
                self.assertIn(f"  ML 위험 점수: {shown} ({label})\n", text)
                self.assertIn(f" | {shown} ({label}) | ", markdown)
                for output in (text, markdown):
                    self.assertIn(f"판정 기준 점수 {plain_number(threshold)}\n", output)

    def test_explanation_ending_and_update_gate_lines_word_the_same_score(self):
        report = self.scored(TINY)
        report["results"][0]["explanation_rest"] = {
            "others_count": 2, "others_sum": -0.25, "base_value": -1.0}  # fmt: skip
        for output in self.both(report):
            self.assertIn("모델 기준값 -1.00 (합계 -1.25 → 점수 <0.001)\n", output)
        # No list was connected, so the gate asks to confirm the item and shows its score.
        (item,) = service.update_gate(report)[1]
        line = _apply_item(item, _clean, _text_label, report["threshold"])
        self.assertTrue(line.endswith("기지 악성 목록 미확인; ML 위험 점수 <0.001"), line)
        near = self.scored(0.4996)
        (item,) = service.update_gate(near)[1]
        line = _apply_item(item, _clean, _text_label, near["threshold"])
        self.assertTrue(line.endswith("; ML 위험 점수 0.4996"), line)

    def test_known_malicious_match_and_older_reports_keep_their_own_words(self):
        report = self.scored(TINY, known_malicious=KnownList((ADVISORY,)))
        self.assertEqual((report["status"], report["exit_code"]), ("flagged", 1))
        text, markdown = self.both(report)
        # The match decides the item; the ML path's own words stay beside it.
        self.assertIn("[위험] example@1.1.0  (node_modules/example)\n"
                      "  ML 위험 점수: <0.001 (기준 미만)\n", text)  # fmt: skip
        self.assertIn("  기지 악성: 일치\n", text)
        self.assertIn("규칙: 연결 안 됨(미실행)\n", text)
        self.assertIn(" | **일치** | <0.001 (기준 미만) | ", markdown)
        old = older(self.scored(TINY))
        self.assertIn("  ML 위험 점수: <0.001 (기준 미만, 참고값)\n", capture(_print_text, old))
        # A report that names no model and no threshold: nothing to compare the score with.
        bare = {**old, "model_id": None, "threshold": None}
        text, markdown = self.both(bare)
        self.assertIn("  ML 위험 점수: <0.001 (기준 미만, 참고값)\n", text)
        self.assertIn(" | <0.001 (기준 미만, 참고값) | ", markdown)
        self.assertNotIn("판정 기준 점수", text + markdown)
        del bare["threshold"]
        self.assertIn("  ML 위험 점수: <0.001 (기준 미만, 참고값)\n", capture(_print_text, bare))
        # No score at all: said as before, never as a number.
        text, markdown = self.both(self.scan_with(analyzer=False))
        self.assertIn("  ML 위험 점수: 없음(미실행)\n", text)
        self.assertNotIn("점수 원값", text + markdown)


class GateTests(unittest.TestCase):
    def annotation(self, score, threshold):
        data = test_actions.report(test_actions.row(status="flagged", ml="hit", score=score))
        if threshold is not None:
            data["threshold"] = threshold
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = actions.gate(path, "package-lock.json", "", None, io.StringIO())
        self.assertEqual(code, 0)  # an ML hit alone is a warning, however its score is worded
        (line,) = out.getvalue().splitlines()
        return line

    def test_ml_hit_annotation_words_the_score_against_the_report_threshold(self):
        for score, threshold, shown in (
            (0.9, 0.5, "0.900"),
            (0.5, 0.5, "0.500"),
            (0.5004, 0.5, "0.5004"),
            (0.50041, 0.5004, "0.50041"),
            (TINY, 1e-07, FULL),
            (TINY, None, "<0.001"),  # a report without a threshold
        ):
            with self.subTest(score=score, threshold=threshold):
                line = self.annotation(score, threshold)
                self.assertTrue(line.startswith("::warning file=package-lock.json::"), line)
                self.assertTrue(line.endswith(f": ML 위험 점수 기준 이상({shown})"), line)


class DashboardTests(test_dashboard.DashboardFixture):
    made_now = test_dashboard.CandidateTests.made_now
    check = test_dashboard.CandidateTests.check
    scored = RenderedTests.scored

    def test_saved_report_without_score_or_threshold_preserves_its_other_facts(self):
        report = self.scored(TINY)
        del report["threshold"], report["results"][0]["score"]
        run = self.record(report)
        for output in (
            self.page(f"/runs/{run}"),
            capture(_print_text, report),
            capture(_print_markdown, report),
        ):
            self.assertIn("판정 기준 점수 기록 없음", output)
            self.assertIn("기준 미만", output)
            self.assertNotIn("점수 원값", output)
        self.assertEqual(history.get_run(run)["report"], report)

    def test_run_page_shows_the_short_score_and_the_stored_value_as_text(self):
        report = self.scored(TINY)
        row = self.app._result(report["results"][0], report)
        self.assertEqual((row["score"], row["score_raw"]), ("<0.001 (기준 미만)", repr(TINY)))
        run = self.record(report)
        text = self.page(f"/runs/{run}")
        self.assertIn("<dt>ML 위험 점수</dt><dd>&lt;0.001 (기준 미만)</dd>", text)
        # Text on the page itself, not a tooltip: it can be read, selected and copied.
        self.assertIn(f"<dt>점수 원값</dt><dd>{TINY!r}</dd>", text)
        self.assertIn("판정 기준 점수 0.5</li>", text)
        self.assertNotIn("<dd>0.000", text)
        self.assertEqual(history.get_run(run)["report"], report)  # stored as it was scanned

    def test_threshold_and_history_peak_are_worded_from_each_stored_report(self):
        usual = self.record(self.scored(TINY))
        custom = self.record(self.scored(TINY, 1e-06))
        self.assertIn("판정 기준 점수 0.000001</li>", self.page(f"/runs/{custom}"))
        self.assertIn("<dd>0.000001</dd>", self.page("/model"))
        rows = history.list_run_scores(1)
        self.assertEqual([(r["id"], r["peak_score"], r["threshold"]) for r in rows],
                         [(custom, TINY, 1e-06), (usual, TINY, 0.5)])  # fmt: skip
        page = self.page("/projects/1/history")
        # against its own threshold of 0.000001
        self.assertIn(f'<span class="score">{FULL}</span>', page)
        self.assertIn('<span class="score">&lt;0.001</span>', page)
        self.assertIn(f'<meter min="0" max="1" value="{TINY!r}"', page)

    def test_update_candidate_and_its_inspector_show_the_same_score(self):
        self.manifest = self.project / "package.json"
        root = test_dashboard.lock()["packages"][""]
        self.manifest.write_text(json.dumps(root), encoding="utf-8")
        self.old, self.new = test_dashboard.lock(), test_dashboard.lock("1.2.0")
        self.save_locks()
        self.report = self.scored(TINY, 0.0005)  # both under 0.001
        self.write(self.head, self.old)  # the project as it is now
        project = history.register_project(self.project)
        self.check(targets=None)
        html = self.page(f"/projects/{project}/updates")
        self.assertIn(f"<td>{FULL} (기준 미만)</td>", html)
        self.assertIn(f"<dt>ML 위험 점수</dt><dd>{FULL} (기준 미만)</dd>", html)
        self.assertIn(f"<dt>점수 원값</dt><dd>{TINY!r}</dd>", html)
        self.assertIn("<dt>판정 기준 점수</dt><dd>0.0005</dd>", html)


if __name__ == "__main__":
    unittest.main()
