"""The assets a report was made with, as every output shows them: the saved model ID and, in the
same summary, the known malicious list (its source and its time, list_as_of) and the ruleset.

cli._detector_setup words those two lines for the text and Markdown outputs and for the dashboard,
from each stored field alone and only ever as the report stores it.

Synthetic only, as test_dashboard: the example reports of docs/examples, printed in-process or
stored with the history API in the test run's folder and read through the in-process TestClient;
no server, npm or registry.
"""

import json
import re
import unittest

from test_dashboard import DashboardFixture
from test_output_formats import EXAMPLES, as_json, capture, older

from depbee.cli import NOT_CHECKED, NOT_CONFIGURED, _md, _print_markdown, _print_text

DATE = re.compile(r"\d{4}-\d\d-\d\d")
UNKNOWN = "확인할 수 없음"
# The ML example of the result contract: a model, a dated known malicious list and a ruleset.
REPORT = json.loads((EXAMPLES / "02-ml-only.json").read_text("utf-8"))
KNOWN, RULES = REPORT["detectors"]["known_malicious"], REPORT["detectors"]["rules"]
# What the report stores, under the names the expected lines use.
STORED = {
    "source": KNOWN["source"],
    "time": KNOWN["list_as_of"],
    "version": RULES["ruleset_version"],
}
DATED, UNDATED, VERSION = (
    "{source}, 기준 시점 {time}",
    f"{{source}}, 기준 시점 {UNKNOWN}",
    "{version}",
)


def stored(**detectors):
    """The example with exactly these detectors entries."""
    return {**REPORT, "detectors": detectors}


def known_without(field, **added):
    return {**{key: value for key, value in KNOWN.items() if key != field}, **added}


# label: (stored report, the known malicious list's line, the rules' line)
CASES = {
    "as stored": (REPORT, DATED, VERSION),
    "older report, no detectors (contract 6)": (older(REPORT), NOT_CHECKED, NOT_CHECKED),
    "detectors null": ({**REPORT, "detectors": None}, NOT_CHECKED, NOT_CHECKED),
    "known_malicious null, no list connected": (
        stored(known_malicious=None, rules=RULES),
        NOT_CONFIGURED,
        VERSION,
    ),
    "known_malicious absent": (stored(rules=RULES), NOT_CHECKED, VERSION),
    "known_malicious not an object": (
        stored(known_malicious="x", rules=RULES),
        NOT_CHECKED,
        VERSION,
    ),
    "rules null, no ruleset connected": (
        stored(known_malicious=KNOWN, rules=None),
        DATED,
        NOT_CONFIGURED,
    ),
    "rules absent, the list keeps its time": (stored(known_malicious=KNOWN), DATED, NOT_CHECKED),
    "list_as_of absent, the rules keep their version": (
        stored(known_malicious=known_without("list_as_of"), rules=RULES),
        UNDATED,
        VERSION,
    ),
    "list_as_of null": (
        stored(known_malicious={**KNOWN, "list_as_of": None}, rules=RULES),
        UNDATED,
        VERSION,
    ),
    "list_as_of absent, an unknown field holds a date": (
        stored(
            known_malicious=known_without("list_as_of", fetched_at="2026-11-20T00:00:00Z"),
            rules=RULES,
        ),
        UNDATED,
        VERSION,
    ),
    "source absent, the time is still the stored one": (
        stored(known_malicious=known_without("source"), rules=RULES),
        f"{UNKNOWN}, 기준 시점 {{time}}",
        VERSION,
    ),
    "ruleset_version absent": (stored(known_malicious=KNOWN, rules={}), DATED, UNKNOWN),
}


def text_lines(report):
    """The summary lines of the text output: everything before the first result."""
    return capture(_print_text, report).split("\n\n", 1)[0].splitlines()


def markdown_lines(report):
    """The summary list of the Markdown output, without its bullets."""
    summary = capture(_print_markdown, report).split("\n\n")[1]
    return [line.removeprefix("- ") for line in summary.splitlines()]


def page_lines(html):
    """The text of each line of the report's summary list on a dashboard page."""
    summary = html.split('<ul class="meta">', 1)[1].split("</ul>", 1)[0]
    return [text.strip() for text in re.findall(r"<li[^>]*>(.*?)</li>", summary, re.S)]


class SetupLines:
    def assert_setup(self, lines, known, rules, esc=str):
        """The two lines as expected, the stored values through esc, and no other date."""
        values = {name: esc(value) for name, value in STORED.items()}
        known, rules = known.format(**values), rules.format(**values)
        self.assertIn(f"기지 악성 목록: {known}", lines)
        self.assertIn(f"규칙: {rules}", lines)
        shown = "\n".join(lines)
        self.assertEqual(DATE.findall(shown), DATE.findall(known))  # only where the report has one
        self.assertNotIn("None", shown)


class CliSetupLineTests(SetupLines, unittest.TestCase):
    def test_every_format_reads_each_stored_field_alone(self):
        for label, (report, known, rules) in CASES.items():
            with self.subTest(label, output="text"):
                self.assert_setup(text_lines(report), known, rules)
            with self.subTest(label, output="markdown"):
                self.assert_setup(markdown_lines(report), known, rules, _md)
            with self.subTest(label, output="json"):  # the stored report itself: nothing filled in
                self.assertEqual(json.loads(as_json(report)), report)


class ReportAssetTests(SetupLines, DashboardFixture):
    def summary(self, report):
        """The summary lines of the report on its stored run's page."""
        return page_lines(self.page(f"/runs/{self.record(report)}"))

    def test_the_stored_list_time_is_shown_with_the_model_id(self):
        lines = self.summary(REPORT)
        self.assert_setup(lines, DATED, VERSION)
        self.assertTrue(any(line.startswith(f"모델: {REPORT['model_id']}") for line in lines))
        # scanned.html and preview.html include this template with this same context.
        shared = self.app.ENV.get_template("report.html").render(**self.app._report(REPORT))
        self.assertEqual(page_lines(shared), lines)

    def test_the_dashboard_reads_each_stored_field_alone(self):
        for label, (report, known, rules) in CASES.items():
            with self.subTest(label):
                self.assert_setup(self.summary(report), known, rules)

    def test_a_hostile_stored_list_time_stays_inert(self):
        hostile = "<script>alert(1)</script>" + chr(0x202E)  # ends with a right-to-left override
        report = stored(known_malicious={**KNOWN, "list_as_of": hostile}, rules=RULES)
        lines = self.summary(report)
        escaped = "&lt;script&gt;alert(1)&lt;/script&gt;\\u202e"
        self.assertIn(f"기지 악성 목록: {KNOWN['source']}, 기준 시점 {escaped}", lines)
        self.assertNotIn("<script", " ".join(lines))
