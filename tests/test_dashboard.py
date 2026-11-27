"""Local history dashboard (SVC-07): pages, security, escaping and registration.

Synthetic only, inside each test run's folder (Fixture sets DEPBEE_HISTORY_DB there): reports
come from pipeline.scan() with fake detectors and predictor or from docs/examples, and are stored
with the history API. The Starlette TestClient talks to the app in-process; no server, browser,
npm or registry.
"""

import base64
import contextlib
import errno
import importlib.machinery
import importlib.metadata
import importlib.util
import io
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tomllib
import types
import unittest
import venv
from collections import Counter
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlsplit

import test_mcp
from test_apply import ApplyFixture, sha
from test_detectors import ADVISORY, KnownList, Rules, rule
from test_extract import FAKE_PIP
from test_markdown import HOSTILE
from test_output_formats import EXAMPLES, FormatFixture, older
from test_workflow import Fixture, package

from depbee import dashboard, history, service
from depbee.analysis.extractor import _with_this_python
from depbee.cli import SAFETY_NOTE, _clean, main
from depbee.contracts import GuardError
from depbee.dashboard import picker

WEB = all(importlib.util.find_spec(name) for name in ("starlette", "jinja2", "uvicorn", "httpx2"))
NO_WEB = "web extra ([web] and httpx2) not installed; the dashboard is not tested here"
PORT = 48213
BASE = f"http://127.0.0.1:{PORT}"
CSRF = "synthetic-csrf-value-for-tests-only-0123456789"  # the hidden field of every form
# The one script element a page has: the one file, never a script of the page's own.
SCRIPT = '<script src="/static/app.js" defer></script>'
WEB_MODULES = ("starlette", "jinja2", "uvicorn", "markupsafe")
PREVIEW = {
    "targets": ["example"], "npm_version": "11.6.1", "package_json_sha256": "0" * 64,
    "package_lock_sha256": "1" * 64, "new_package_lock_sha256": "2" * 64,
    "package_json_changed": False, "changed_count": 1, "project_npmrc_ignored": False,
    "notices": ["미리보기만 했고 프로젝트 파일은 아무것도 바꾸지 않았습니다."],
}  # fmt: skip


class Elements(HTMLParser):
    """The elements of a page as (tag, {attribute: value}), in the page's order."""

    def __init__(self, html):
        super().__init__()
        self.found = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.found.append((tag, dict(attrs)))


# A row of the packages table: the name, then its kind (and the name it is declared under) and
# its location under it, the version (with the candidate's after an arrow), and the cell that
# says what a check found for it. The row's own elements carry no attribute.
PACKAGE_ROW = re.compile(
    r'<tr><th scope="row">([^<]*)<span class="row-tags"> ([^<]*)</span>'
    r'(?:<span class="where">선언 이름 ([^<]*)</span>)?<span class="where">([^<]*)</span></th>'
    r"<td>(.*?)</td>\n<td>(.*?)</td>\n</tr>",
    re.S,
)


def package_rows(html):
    """(name, kind, declared as, location, version cell, candidate cell) of each packages row."""
    return [(*row[:5], row[5].strip()) for row in PACKAGE_ROW.findall(html)]


class Head(HTMLParser):
    """A project view's head (header.project-head), parsed: the name (h1), the path as shown and
    the whole path (its title), with character references decoded."""

    def __init__(self, html):
        super().__init__()
        self.depth, self.into, self.name, self.shown, self.whole = 0, None, "", "", None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "header" and attrs.get("class") == "project-head":
            self.depth = 1
        elif self.depth:
            self.depth += tag == "header"
            if tag == "h1":
                self.into = "name"
            elif tag == "p" and attrs.get("class") == "path":
                self.into, self.whole = "shown", attrs.get("title")

    def handle_endtag(self, tag):
        if self.depth and tag == "header":
            self.depth -= 1
        if tag in ("h1", "p"):
            self.into = None

    def handle_data(self, data):
        if self.depth and self.into:
            setattr(self, self.into, getattr(self, self.into) + data)


def project_head(html):
    """(name, the path as shown, the whole path) of a project view's head."""
    head = Head(html)
    return head.name, head.shown, head.whole


def assert_one_script(case, html):
    """A page of the dashboard runs the one script file and nothing else: no second script
    element, none that a package string wrote, and no handler in an attribute."""
    case.assertEqual((html.count("<script"), html.count(SCRIPT)), (1, 1))
    elements = Elements(html).found
    case.assertEqual([attrs for tag, attrs in elements if tag == "script"],
                     [{"src": "/static/app.js", "defer": None}])  # fmt: skip
    case.assertEqual([name for _, attrs in elements for name in attrs if name.startswith("on")],
                     [])  # fmt: skip


@unittest.skipUnless(WEB, NO_WEB)
class DashboardFixture(FormatFixture):
    def setUp(self):
        super().setUp()
        from starlette.testclient import TestClient

        from depbee.dashboard import app

        self.app = app
        self.client = TestClient(app.build_app(PORT, CSRF), base_url=BASE)
        self.addCleanup(self.client.close)
        self.db = Path(os.environ["DEPBEE_HISTORY_DB"])

    def get(self, url, **kwargs):
        return self.client.get(url, **kwargs)

    def page(self, url):
        response = self.get(url)
        self.assertEqual(response.status_code, 200, url)
        self.assertNotIn("set-cookie", response.headers)
        # Every link, form and file of the dashboard is a path of this address: one slash,
        # so never another host ("//host", or "/\\host" as a browser reads it), and never with
        # the form's value in it. A link to a place of the page it is on (the skip link, the
        # apply form) stays there.
        for target in re.findall(r'(?:href|action|src)="([^"]*)"', response.text):
            if not re.fullmatch(r"#[a-z]+", target) and not target.startswith(
                "https://www.npmjs.com/package/"
            ):
                self.assertRegex(target, r"\A/(?![/\\])")
                self.assertNotIn(CSRF, target)
        assert_one_script(self, response.text)
        return response.text

    def record(self, report, kind="scan", preview=None):
        history.register_project(self.project)
        return history.record(kind, self.project, report, preview)

    def form_csrf(self):
        return re.search(r'name="csrf" value="([^"]+)"', self.page("/?manage=1")).group(1)

    def dialog(self, folder):
        """picker.choose replaced for the rest of the test: the dialog answers this folder. No
        test opens the desktop's dialog."""
        patcher = mock.patch.object(picker, "choose", return_value=("chosen", folder))
        self.addCleanup(patcher.stop)
        return patcher.start()

    def send_pick(self, csrf=CSRF, origin=BASE, **fields):
        """The folder dialog's form, the one request that registers a project. csrf None:
        the form without its csrf field."""
        data = {**fields, **({"other": "1"} if csrf is None else {"csrf": csrf})}
        headers = {} if origin is None else {"origin": origin}
        return self.client.post("/projects/pick", data=data, headers=headers,
                                follow_redirects=False)  # fmt: skip


class PageTests(DashboardFixture):
    def test_every_page_of_the_example_reports(self):
        for path in sorted(EXAMPLES.glob("*.json")):
            with self.subTest(path.name):
                report = json.loads(path.read_text("utf-8"))
                run = self.record(report)
                text = self.page(f"/runs/{run}")
                self.assertIn(f"종료 코드 {report['exit_code']}", text)
                for row in report["results"]:
                    self.assertIn(row["package"], text)
                self.assertNotIn("확률", text)
        projects, project, model = (
            self.page("/?manage=1"),
            self.page("/projects/1"),
            self.page("/model"),
        )
        for text in (projects, project, model):
            self.assertIn(SAFETY_NOTE.replace("'", "&#39;"), text)  # autoescaped
        self.assertIn(str(self.project.resolve()), projects)
        self.assertIn("최근 6개 실행", projects)
        self.assertIn("example-model-001", model)
        self.assertIn("학습 데이터 버전과 공격 유형별 탐지율은", model)
        self.assertIn("0123456789abcdef" * 4, model)  # provenance model_sha256, as stored
        self.assertIn("text/css", self.get("/static/style.css").headers["content-type"])

    def test_a_report_opens_with_its_result_and_counts_in_a_band(self):
        report = json.loads((EXAMPLES / "03-known-malicious-low-ml.json").read_text("utf-8"))
        run = self.record(report)
        text = self.page(f"/runs/{run}")
        band = text.split('<div class="band">', 1)[1].split("</div>", 1)[0]
        self.assertIn('<h2 class="band-title">검사 결과: <span class="verdict risk"><span class="cell risk" '
                      'aria-hidden="true"></span>위험 판정 있음</span></h2>', band)  # fmt: skip
        found = Counter(row["status"] for row in report["results"])
        package_input = report.get("input_kind") == "package"
        total = "검사한 패키지" if package_input else "바뀐 의존성"
        expected = [("all", total, len(report["results"])), ("risk", "위험", found["flagged"]),
                    ("hold", "보류", found["incomplete"]), ("pass", "통과", found["not_flagged"])]  # fmt: skip
        if not package_input:
            expected.append(("removed", "삭제", found["removed"]))
        self.assertEqual(re.findall(r'<li class="n-(\w+)">([^<]+) <b>(\d+)</b></li>', band),
                         [(key, label, str(count)) for key, label, count in expected])  # fmt: skip
        # One line of what the result was made with, then the warnings, then the items.
        meta = text.split('<ul class="meta">', 1)[1].split("</ul>", 1)[0]
        for part in ("모델: ", "기지 악성 목록: ", "규칙: ", f"종료 코드 {report['exit_code']}"):
            self.assertIn(part, meta)
        warning = text.index(
            '<p class="warning risk"><strong>경고: 기지 악성 기록 일치 1개.</strong>'
        )
        self.assertLess(text.index('<ul class="meta">'), warning)
        self.assertLess(warning, text.index('<section class="result'))
        # An item: its verdict, the package and the versions on its title line; the two sides
        # and its anchor as before.
        hit = next(
            row
            for row in report["results"]
            if (row.get("known_malicious") or {}).get("status") == "hit"
        )
        position = report["results"].index(hit)
        # One version checked alone has no change to show; a lockfile's change has two.
        move = (hit["after_version"] or hit["before_version"] if package_input else
                f'{hit["before_version"]} <span aria-hidden="true">→</span>'
                f'<span class="visually-hidden">에서</span> {hit["after_version"]}')  # fmt: skip
        self.assertIn(f'<section class="result flagged known" id="r{position}">\n<h3 class="result-title">'
                      '<span class="verdict risk"><span class="cell risk" aria-hidden="true"></span>위험</span> '
                      f'<span class="ident">{hit["package"]}</span> <span class="move">{move}</span></h3>',
                      text)  # fmt: skip
        for side in ('<p class="side">확인된 사실</p>', '<p class="side">모델 점수</p>'):
            self.assertIn(side, text)

    def test_a_report_title_says_only_the_versions_it_has(self):
        row = self.scan_with(0.9)["results"][0]

        def title(**changes):
            report = {**self.scan_with(0.9), "model_id": None}
            report["results"] = [{**row, **changes}]
            html = self.page(f"/runs/{self.record(report)}")
            found = re.search(
                r'<span class="ident">[^<]*</span> <span class="move">(.*?)</span></h3>', html
            )
            return re.sub(r"<[^>]+>", "", found.group(1)), html

        # A removal is the stored status, never a missing version.
        before, after = row["before_version"], row["after_version"]
        self.assertEqual(
            title(after_version=None, status="removed", score=None)[0], f"{before} →에서 삭제"
        )
        self.assertEqual(title(after_version=None, status="incomplete", score=None)[0], before)
        self.assertEqual(title(before_version=None)[0], after)  # not said to be new
        moved, html = title(
            before_version=None, after_version=None, status="incomplete", score=None
        )
        self.assertEqual(moved, "버전 기록 없음")
        self.assertNotIn("None", moved)
        # The band says every count of a lockfile's report, 0 included, and a missing model.
        self.assertIn('<li class="n-removed">삭제 <b>0</b></li>', html)
        self.assertIn("<li>모델: 기록 없음</li>", html)

    def test_the_score_chart_draws_each_run_against_its_threshold(self):
        from depbee.actions import score_text

        chart = self.app._score_chart
        scores = [0.001, 0.87, 0.012, 0.42, 0.61, 0.05]  # oldest first
        entries = [{"id": n + 1, "created_at": "2026-11-21T00:00:00.000Z", "model_id": "m",
                    "scored_count": 1, "peak_score": score, "threshold": 0.5}
                   for n, score in enumerate(scores)][::-1]  # newest first, as the history gives  # fmt: skip
        found = chart(entries)
        self.assertEqual((found["width"], found["height"]), (440, 160))
        self.assertEqual([p["x"] for p in found["points"]], [44, 119.2, 194.4, 269.6, 344.8, 420])
        self.assertEqual(
            [p["y"] for p in found["points"]], [124.89, 29.3, 123.68, 78.8, 57.9, 119.5]
        )
        self.assertEqual([p["id"] for p in found["points"]], [1, 2, 3, 4, 5, 6])
        self.assertEqual(found["threshold"], 70)  # one line: every run has the same threshold
        self.assertEqual(found["ticks"], [])
        self.assertEqual([p["id"] for p in found["points"] if p["over"]], [2, 5])
        self.assertEqual(
            [p["label"] for p in found["points"]], [score_text(s, 0.5) for s in scores]
        )
        self.assertEqual(
            found["segments"], [" ".join(f"{p['x']},{p['y']}" for p in found["points"])]
        )
        self.assertIn("6회", found["summary"])
        # Thresholds that differ: a short mark on each run instead of one line.
        mixed = [
            {**e, "threshold": t}
            for e, t in zip(entries, (0.5, 0.6, 0.5, 0.7, 0.5, 0.4), strict=True)
        ]
        found = chart(mixed)
        self.assertIsNone(found["threshold"])
        self.assertEqual(len(found["ticks"]), 6)
        # A run without a score is a gap in the line, its point empty.
        gap = [dict(e) for e in entries]
        gap[2]["peak_score"] = None  # the fourth from the oldest
        found = chart(gap)
        self.assertIsNone(found["points"][3]["y"])
        self.assertEqual([len(s.split()) for s in found["segments"]], [3, 2])
        # One run, or none: no chart.
        self.assertIsNone(chart(entries[:1]))
        self.assertIsNone(chart([]))
        # The highest run is the stored score's, not the drawn spot's.
        close = [
            {**entries[0], "id": 2, "peak_score": 0.5000001},
            {**entries[0], "id": 1, "peak_score": 0.4999999},
        ]
        found = chart(close)
        self.assertIn("가장 높은 값은 실행 #2의", found["summary"])
        self.assertIn("판정 기준 이상 1회", found["summary"])
        # Runs whose threshold cannot be compared are said to be so, not counted as under it.
        blind = [
            {**entries[0], "id": 2, "threshold": None},
            {**entries[0], "id": 1, "threshold": -0.1},
        ]
        found = chart(blind)
        self.assertIn("기준을 비교할 수 없는 실행 2회", found["summary"])
        self.assertNotIn("판정 기준 이상", found["summary"])
        # Values that fit beside their points are drawn there; else they are listed under it.
        self.assertTrue(chart(entries)["inline"])
        tiny = [{**entries[0], "id": n, "peak_score": 3.950535635136895e-07, "threshold": 1e-07}
                for n in range(10, 0, -1)]  # fmt: skip
        found = chart(tiny)
        self.assertFalse(found["inline"])
        self.assertEqual(len([p for p in found["points"] if p["over"]]), 10)
        # Two runs leave room: a value runs from its point at the value axis's side and ends at
        # its point at the box's other end, inside both.
        found = chart(tiny[:2])
        self.assertTrue(found["inline"])
        self.assertEqual(
            [(p["anchor"], p["lx"]) for p in found["points"]], [("start", 41), ("end", 423)]
        )
        found = chart(
            [
                {**entries[0], "id": 2, "peak_score": 0.87},
                {**entries[0], "id": 1, "peak_score": 0.87},
            ]
        )
        self.assertTrue(found["inline"])
        self.assertEqual(found["points"][0]["anchor"], "start")  # clear of the axis's "1"
        # A value at 1 has its room above the box (style.css gives the box its padding).
        self.assertTrue(
            chart(
                [
                    {**entries[0], "id": n, "peak_score": s}
                    for n, s in ((3, 1.0), (2, 0.999), (1, 1.0))
                ]
            )["inline"]
        )
        # A value that a connecting line would cross is listed under the chart instead: the
        # line from a long value's point rises through its digits to the next run's.
        crossed = [
            {**entries[0], "id": 2, "peak_score": 0.37},
            {**entries[0], "id": 1, "peak_score": 3.950535635136895e-07, "threshold": 1e-07},
        ]
        self.assertFalse(chart(crossed)["inline"])
        # A shallow line under the digits still meets the box a browser gives the text.
        for shallow in (crossed, crossed[::-1]):
            low = (
                [{**shallow[0], "peak_score": 0.097}, shallow[1]]
                if shallow[0]["id"] == 2
                else [shallow[0], {**shallow[1], "peak_score": 0.097}]
            )
            self.assertFalse(chart(low)["inline"], low)
        # A line that stays under the value leaves it over its point.
        flat = [
            {**entries[0], "id": 2, "peak_score": 0.87},
            {**entries[0], "id": 1, "peak_score": 0.9},
        ]
        self.assertTrue(chart(flat)["inline"])
        # A value that would run over another run's point is listed under the chart instead.
        mixed = [{**entries[0], "id": n, "peak_score": 0.13} for n in range(10, 1, -1)]
        mixed.append(
            {**entries[0], "id": 1, "peak_score": 3.950535635136895e-07, "threshold": 1e-07}
        )
        self.assertFalse(chart(mixed)["inline"])
        # Run numbers that do not fit between the points: every few, the newest always.
        ids = [{**entries[0], "id": 100000 + n} for n in range(9, -1, -1)]
        ticks = [p["tick"] for p in chart(ids)["points"]]
        self.assertTrue(ticks[-1])
        self.assertLess(sum(ticks), 10)
        self.assertNotIn([True, True], [ticks[n : n + 2] for n in range(9)])
        # The numbers at the two ends lean inwards; no two shown numbers meet.
        points = chart(ids)["points"]
        self.assertEqual((points[-1]["tick_anchor"], points[-1]["tx"]), ("end", 420))
        spans = []
        for p in (p for p in points if p["tick"]):
            width = len(f"#{p['id']}") * 7.3
            left = {"start": p["tx"], "end": p["tx"] - width}.get(
                p["tick_anchor"], p["tx"] - width / 2
            )
            spans.append((left, left + width))
        self.assertTrue(all(0 <= left and right <= 440 for left, right in spans))
        self.assertTrue(all(b[0] - a[1] >= 6 for a, b in zip(spans, spans[1:], strict=False)))
        self.assertTrue(all(p["tick"] for p in chart(entries)["points"]))

    def test_a_line_crosses_a_box_only_through_it(self):
        crosses, box = self.app._crosses, (10, 10, 20, 20)
        self.assertTrue(crosses((0, 0), (30, 30), box))  # through, corner to corner
        self.assertTrue(crosses((12, 12), (18, 14), box))  # all inside
        self.assertTrue(crosses((15, 0), (15, 30), box))  # straight down through it
        self.assertFalse(crosses((0, 25), (30, 25), box))  # level, under it
        self.assertFalse(crosses((0, 0), (30, 5), box))  # rising, above it
        self.assertFalse(crosses((21, 0), (21, 30), box))  # beside it
        self.assertFalse(crosses((0, 30), (9, 0), box))  # ends before it

    def test_the_history_view_draws_the_chart_above_the_table(self):
        history.register_project(self.project)
        history.record("scan", self.project, self.scan_with(0.9))
        one = self.page("/projects/1/history")
        self.assertNotIn('class="score-chart"', one)  # one run: the table alone
        self.assertIn('class="score-history"', one)
        history.record("scan", self.project, self.scan_with(0.1))
        html = self.page("/projects/1/history")
        self.assertRegex(
            html, r'<svg class="score-chart" viewBox="0 0 440 160" role="img" aria-label="[^"]+">'
        )
        self.assertLess(
            html.index('class="score-chart"'),
            html.index('<table class="stack">', html.index("score-history")),
        )
        self.assertNotIn("<meter", html)
        # Never drawn smaller than its own size: a narrow page scrolls it inside its box.
        self.assertIn(
            '<div class="scroll chart-scroll" role="region" aria-label="점수 그래프" tabindex="0">',
            html,
        )
        svg = html.split('<svg class="score-chart"', 1)[1].split("</svg>", 1)[0]
        # Values come after every point, so no point is drawn over one.
        self.assertIn('class="value"', svg)
        self.assertLess(svg.rindex("<circle"), svg.index('class="value"'))
        # The threshold is drawn over the line, so a line on it does not hide it.
        self.assertLess(svg.index('class="line"'), svg.index('class="threshold"'))

    def test_values_are_the_stored_ones_and_known_malicious_is_emphasized(self):
        report = json.loads((EXAMPLES / "03-known-malicious-low-ml.json").read_text("utf-8"))
        text = self.page(f"/runs/{self.record(report)}")
        self.assertIn("<strong>경고: 기지 악성 기록 일치 1개.</strong>", text)
        self.assertIn('class="result flagged known"', text)
        self.assertIn("<dd>0.040 (기준 미만)</dd>", text)  # a low score stays as stored
        # cli._alternative; the version in the identifiers' face, the words around it not.
        self.assertIn('<dd><span class="ident">2.0.0</span> (비교 기준 버전)</dd>', text)
        self.assertIn("<h4>추출된 사실</h4>", text)
        self.assertIn("<h4>모델 설명:", text)
        self.assertIn('<rect class="normal" width="100" height="8"/>', text)

    def test_order_null_scores_and_unfinished_items(self):
        report = self.cases()["mixed"]
        text = self.page(f"/runs/{self.record(report)}")
        heads = re.findall(r'<h3 class="result-title"><span class="verdict \w+">(?:<span class="cell \w+" '
                           r'aria-hidden="true"></span>)?([^<]+)</span> <span class="ident">([^<]+)</span>', text)  # fmt: skip
        labels = {"flagged": "위험", "incomplete": "보류", "not_flagged": "통과", "removed": "삭제"}
        order = {key: index for index, key in enumerate(labels)}
        expected = sorted(report["results"],
                          key=lambda r: (order[r["status"]], -(r["score"] or 0.0)))  # fmt: skip
        self.assertEqual(heads, [(labels[r["status"]], r["package"]) for r in expected])
        self.assertIn("<strong>보류 ", text)
        self.assertIn("<dd>없음(미실행)</dd>", text)  # a null score is never 0 or passed

    def test_update_preview_run(self):
        run = self.record(self.scan_with(0.1), "update_preview", PREVIEW)
        text = self.page(f"/runs/{run}")
        self.assertIn("<h2>업데이트 미리보기</h2>", text)
        self.assertIn("<li>대상: example</li>", text)
        self.assertIn("npm 11.6.1, package.json 변경 없음, lockfile에서 바뀐 항목 1개", text)
        self.assertIn("미리보기만 했고 프로젝트 파일은 아무것도 바꾸지 않았습니다.", text)
        self.assertIn("업데이트 미리보기", self.page("/"))

    def test_older_report_and_rule_failures(self):
        text = self.page(f"/runs/{self.record(older(self.scan_with(0.9)))}")
        for line in ("기지 악성 목록: 확인 안 됨", "규칙: 확인 안 됨", "<li>기지 악성: 확인 안 됨</li>",
                     "<dd>0.900 (기준 이상, 참고값)</dd>"):  # fmt: skip
            self.assertIn(line, text)
        self.assertNotIn("미적중", text)
        self.assertIn("이 보고서에는 provenance가 없어", self.page("/model"))
        rules = Rules((rule("hit"), rule("failed", "R2", detail="t")))
        text = self.page(f"/runs/{self.record(self.scan_with(0.1, rules=rules))}")
        self.assertIn("<dd>연결된 탐지기 실패</dd>", text)
        self.assertIn("<li>규칙: 적중, 실패 1개<ul>", text)

    def test_project_without_folder_or_lockfile(self):
        history.register_project(self.project)
        self.head.unlink()
        self.assertIn("package-lock.json이 없습니다.", self.page("/projects/1"))
        self.head.write_text("{broken", encoding="utf-8")
        self.assertIn("package-lock.json을 읽을 수 없습니다", self.page("/projects/1"))
        self.head.unlink()
        self.project.rmdir()
        self.assertIn("찾을 수 없음", self.page("/"))
        self.assertIn("프로젝트 폴더를 찾을 수 없습니다.", self.page("/projects/1"))

    def test_dependencies_and_unknown_ids(self):
        self.new["packages"][""] = {"dependencies": {"example": "^1.0.0"}}
        self.new["packages"]["node_modules/example/node_modules/inner"] = package("2.0.0")
        self.save_locks()
        history.register_project(self.project)
        text = self.page("/projects/1")
        self.assertIn("직접 1개, 중첩 1개.", text)
        self.assertIn(("inner", "중첩", "", "node_modules/example/node_modules/inner", "2.0.0"),
                      [row[:5] for row in package_rows(text)])  # fmt: skip
        for url in ("/projects/2", "/projects/2/updates", "/projects/2/history", "/runs/1",
                    f"/runs/{2**70}", f"/projects/{2**70}/history"):  # fmt: skip
            self.assertEqual(self.get(url).status_code, 404, url)

    def test_explorer_filters_and_preview_targets(self):
        root = {"dependencies": {"example": "^1.0.0"}, "peerDependencies": {"peer": "*"}}
        self.new["packages"][""] = root
        self.new["packages"]["node_modules/peer"] = package()
        self.new["packages"]["node_modules/example/node_modules/inner"] = package("2.0.0")
        self.save_locks()
        (self.project / "package.json").write_text(json.dumps(root), encoding="utf-8")
        history.register_project(self.project)

        html = self.page("/projects/1?q=EXa&scope=direct")
        self.assertIn('form="preview-project" name="packages" value="example"', html)
        form = re.search(r'<form [^>]*id="preview-project"[^>]*>(.*?)</form>', html, re.S)
        self.assertIsNotNone(form)
        self.assertIn('action="/projects/1/previews"', form[0])
        self.assertIn(f'<input type="hidden" name="csrf" value="{CSRF}">', form[1])
        self.assertIn('<a href="/projects/1">필터 초기화</a>', html)
        self.assertNotIn('<th scope="row">inner<span class="row-tags">', html)
        nested = self.page("/projects/1?scope=nested")
        self.assertIn('<th scope="row">inner<span class="row-tags">', nested)
        self.assertNotIn('form="preview-project" name="packages"', nested)
        self.assertNotIn('form="preview-project" name="packages"', self.page("/projects/1?q=peer"))
        self.assertIn("조건에 맞는 패키지가 없습니다", self.page("/projects/1?q=missing"))
        self.assertEqual(self.get("/projects/1?scope=invalid").status_code, 400)
        for invalid in ("scope=direct&scope=nested", "q=x&q=y", "q=%01x%01", "q=" + "x" * 215):
            self.assertEqual(self.get(f"/projects/1?{invalid}").status_code, 400)
        self.assertEqual(history.list_runs(1), [])

    def test_kind_says_how_the_root_declares_each_direct_dependency(self):
        root = {"dependencies": {"example": "^1.0.0", "alias": "npm:real-name@5"},
                "devDependencies": {"both": "1"}, "optionalDependencies": {"opt": "1"},
                "peerDependencies": {"both": "*", "peer": "*"}}  # fmt: skip
        self.new["packages"][""] = root
        self.new["packages"]["node_modules/alias"] = {**package("5.0.0"), "name": "real-name"}
        for location in ("both", "opt", "peer", "hoisted", "example/node_modules/both"):
            self.new["packages"][f"node_modules/{location}"] = package()
        self.save_locks()
        history.register_project(self.project)
        html = self.page("/projects/1")
        # Each row's kind beside its name, with the name it is declared under.
        kinds = {location: (kind, alias) for _, kind, alias, location, _, _ in package_rows(html)}
        self.assertEqual(kinds, {
            "node_modules/example": ("직접 일반", ""),
            # Declared under another name than the package's own; the spec is not read.
            "node_modules/alias": ("직접 일반", "alias"),
            "node_modules/both": ("직접 개발, 피어", ""),  # declared twice
            "node_modules/opt": ("직접 선택", ""),
            "node_modules/peer": ("직접 피어", ""),
            "node_modules/example/node_modules/both": ("중첩", ""),  # another copy of a name
            "node_modules/hoisted": ("중첩", ""),  # at the top, but no root declaration
        })  # fmt: skip
        self.assertIn(("real-name", "직접 일반", "alias", "node_modules/alias", "5.0.0"),
                      [row[:5] for row in package_rows(html)])  # fmt: skip
        self.assertIn("dependencies·devDependencies·optionalDependencies·peerDependencies", html)
        self.assertNotIn("npm:real-name@5", html)
        nested = self.page("/projects/1?scope=nested")
        self.assertEqual({row[1] for row in package_rows(nested)}, {"중첩"})

    def test_missing_dependency_name_keeps_project_accessible(self):
        history.register_project(self.project)
        entry = "node_modules/missing"
        self.new["packages"][entry] = {**package(), "name": None}
        self.save_locks()
        html = self.page("/projects/1")
        self.assertIn('<th scope="row">이름 없음<span class="row-tags">', html)
        self.assertIn(entry, html)
        self.assertNotIn(entry, self.page("/projects/1?q=example"))
        self.assertNotIn('name="packages" value="None"', html)
        self.new["packages"][entry]["name"] = []
        self.save_locks()
        self.assertIn("package-lock.json을 읽을 수 없습니다", self.page("/projects/1"))

    def test_resources_have_no_external_urls(self):
        package_dir = Path(self.app.__file__).parent
        static = package_dir / "static"
        self.assertEqual(sorted(p.relative_to(static).as_posix() for p in static.rglob("*") if p.is_file()), [
            "app.js", "fonts/JetBrainsMono-depbee.woff2", "fonts/NotoSansKR-depbee.woff2",
            "fonts/OFL-JetBrainsMono.txt", "fonts/OFL-NotoSansKR.txt", "fonts/coverage.txt",
            "overview.css", "style.css"])  # fmt: skip
        files = [*package_dir.glob("templates/*.html"),
                 *(p for p in static.glob("*") if p.is_file())]  # fmt: skip
        self.assertEqual(sorted(p.name for p in files), [
            "app.js", "applied.html", "apply_lines.html", "base.html", "counts.html",
            "error.html", "history.html", "inspector.html", "model.html",
            "overview.css", "overview.html", "preview.html", "project.html",
            "project_head.html", "projects.html", "report.html", "run.html", "scanned.html",
            "score_history.html", "start.html", "style.css", "trail.html", "updates.html"])  # fmt: skip
        for path in files:
            self.assertIsNone(re.search(r"https?:|//", path.read_text("utf-8")), path.name)
        # The bundled fonts, their licences and the list of what they cover; nothing else.
        self.assertEqual(sorted(p.name for p in (package_dir / "static" / "fonts").iterdir()), [
            "JetBrainsMono-depbee.woff2", "NotoSansKR-depbee.woff2", "OFL-JetBrainsMono.txt",
            "OFL-NotoSansKR.txt", "coverage.txt"])  # fmt: skip
        # The stylesheet's two font faces name the bundled files, beside it under fonts/.
        css = (package_dir / "static" / "style.css").read_text("utf-8")
        self.assertEqual(css.count("@font-face"), 2)
        self.assertEqual(re.findall(r"url\(([^)]*)\)", css),
                         [f"fonts/{name}" for name in self.app.FONTS])  # fmt: skip
        text = "".join(p.read_text("utf-8") for p in files if p.name != "style.css")
        text += re.sub(r"@font-face \{[^}]*\}", "", css)
        # CSP: style-src 'self' refuses a style attribute or element.
        for refused in ("<style", " style=", "url(", "@import", "@font-face"):
            self.assertNotIn(refused, text)
        # script-src 'self': the two documents (the console and the start page) name the one
        # script file, and no template holds a script or a handler of its own.
        self.assertEqual(re.findall(r"<script[^>]*>[^<]*", text),
                         ['<script src="/static/app.js" defer>'] * 2)  # fmt: skip
        # By name: a folder lists its files in an order of its own (not by name on Linux).
        self.assertEqual(sorted(p.name for p in files if "<script" in p.read_text("utf-8")),
                         ["base.html", "start.html"])  # fmt: skip
        self.assertIsNone(re.search(r"\son[a-z]+=|javascript:", text))
        # The script sends no request, reads no answer and writes no markup: a form is still
        # the browser's own, so every check of a request holds with the script as without it.
        script = (package_dir / "static" / self.app.SCRIPT).read_text("utf-8")
        for refused in ("fetch", "XMLHttpRequest", "sendBeacon", "WebSocket", "EventSource",
                        "eval", "Function(", "innerHTML", "outerHTML", "insertAdjacent",
                        "document.write", "import", "cookie", "localStorage", "sessionStorage",
                        ".submit(", ".click("):  # fmt: skip
            self.assertNotIn(refused, script)


class ConsoleTests(DashboardFixture):
    """The console around every page: the registered projects as tabs, a project's three views
    and the way back from the pages under them."""

    def folder(self, *parts):
        path = self.root.joinpath(*parts)
        path.mkdir(parents=True)
        self.write(path / "package-lock.json", self.new)
        return path

    def tab(self, html, project_id):
        """(the rest of the link's opening tag after its title, cell, name, state) of a
        project's tab. The state is said for a screen reader; the counts follow it."""
        found = re.search(
            rf'<a class="tab" href="/projects/{project_id}" title="[^"]*"([^>]*)>'
            r'<span class="cell (\w+)" aria-hidden="true"></span>'
            r'<span class="tab-name">([^<]*)</span>'
            r'<span class="visually-hidden">, ([^<]*)</span>',
            html,
        )
        self.assertIsNotNone(found, project_id)
        return found.groups()

    def test_the_rail_lists_its_menu_first_and_the_projects_that_need_a_look_first(self):
        passed = history.register_project(self.folder("passed"))
        flagged = history.register_project(self.project)
        fresh = history.register_project(self.folder("fresh"))
        held = history.register_project(self.folder("held"))
        gone = history.register_project(self.folder("gone"))
        history.record("scan", self.root / "passed", self.scan_with(0.1))
        history.record("scan", self.project, self.scan_with(0.9))
        history.record("scan", self.root / "held", self.scan_with(analyzer=False))
        history.record("scan", self.root / "gone", self.scan_with(0.9))  # hidden by the folder
        (self.root / "gone" / "package-lock.json").unlink()
        (self.root / "gone").rmdir()
        html = self.page("/model")
        self.assertLess(html.index('<nav class="aux" aria-label="관리와 정보">'),
                        html.index('<nav class="tabs" aria-label="프로젝트">'))  # fmt: skip
        self.assertIn('<p class="rail-title">프로젝트 5개 · 조치 필요 3</p>', html)
        order = [
            int(i)
            for i in re.findall(r'<a class="tab" href="/projects/(\d+)"', html)
        ]
        self.assertEqual(order, [gone, flagged, held, fresh, passed])
        # Each line: the full path on hover, and the risk and hold counts of the newest run.
        self.assertIn(f'href="/projects/{flagged}" title="{self.project.resolve()}"', html)
        counts = dict(re.findall(r'/projects/(\d+)" title="[^"]*"[^>]*><span class="cell \w+" '
                                 r'aria-hidden="true"></span><span class="tab-name">[^<]*</span>'
                                 r'<span class="visually-hidden">[^<]*</span>'
                                 r'<span class="tab-count">((?:<span class="n-\w+"[^>]*>[^<]*</span> ?)*)'
                                 r"</span></a>", html))  # fmt: skip
        # Each state in words beside its mark, where its counts do not say it already (for a
        # screen reader the hidden state says it, so these words are not said twice); a folder
        # that is gone keeps what its last run found.
        word = '<span class="n-{}" aria-hidden="true">{}</span>'
        self.assertEqual(counts, {str(flagged): '<span class="n-risk">위험 1</span>',
                                  str(held): '<span class="n-hold">보류 1</span>',
                                  str(passed): word.format("pass", "통과"),
                                  str(fresh): word.format("none", "미검사"),
                                  str(gone): word.format("gone", "폴더 없음")
                                  + ' <span class="n-risk">위험 1</span>'})  # fmt: skip

    def test_the_bar_keeps_each_name_in_view(self):
        css = (Path(self.app.__file__).parent / "static" / "style.css").read_text("utf-8")
        # The project row is never narrower than one whole project with its ring: below 46rem
        # the open one has its name, between 46rem and 80rem the row scrolls.
        self.assertRegex(css, r"(?m)^\.tabs \{ flex: 1 1 15rem;")
        # Without the script (app.js brings a focused project into the row) the row wraps.
        found = re.search(r"@media \(scripting: none\) and \(min-width: 46rem\) and "
                          r"\(max-width: 79\.99rem\) \{\n  \.tabs ul \{([^}]*)\}", css)  # fmt: skip
        self.assertIn("flex-wrap: wrap", found.group(1))
        # Between 46rem and 80rem the projects take a line of their own under the menu: a
        # focused project with long counts fits the row whole, and a wrapped list leaves the
        # menu at the top. Without the script the page leaves room for a focused ring too.
        medium = re.search(
            r"@media \(min-width: 46rem\) and \(max-width: 79\.99rem\) \{\n(.*?)\n\}", css, re.S
        )
        self.assertIn("  .tabs { flex-basis: 100%; }", medium.group(1))
        self.assertRegex(css, r"@media \(scripting: none\) and \(min-width: 46rem\) and "
                              r"\(max-width: 79\.99rem\) \{\n  \.tabs ul \{[^}]*\}\n  html \{ scroll-padding-block: 1\.5rem; \}")  # fmt: skip
        # A project that takes the focus is scrolled to with room for its ring, in the bar, in
        # the wide rail and on the page.
        self.assertRegex(css, r"(?m)^\.tab \{[^}]*scroll-margin: \.5rem;")
        # The lines wrap their counts under the name rather than cut the name to a letter.
        self.assertRegex(css, r"(?m)^\.tab-name \{ flex: 1 1 5rem;")
        # The views' links wrap rather than push a narrow page sideways.
        self.assertRegex(css, r"(?m)^\.views \{ display: flex; flex-wrap: wrap;")

    def test_the_rail_says_0_when_nothing_needs_a_look(self):
        history.register_project(self.project)
        history.record("scan", self.project, self.scan_with(0.1))
        self.assertIn('<p class="rail-title">프로젝트 1개 · 조치 필요 0</p>', self.page("/model"))

    def test_a_run_whose_result_is_unknown_comes_before_no_run(self):
        from test_history import sql

        fresh = history.register_project(self.folder("fresh"))
        odd = history.register_project(self.project)
        history.record("scan", self.project, self.scan_with(0.1))
        for status in (None, "odd"):
            with self.subTest(status=status):
                sql(self.db, "UPDATE runs SET status = ?", status)
                html = self.page("/model")
                order = re.findall(r'<a class="tab" href="/projects/(\d+)"', html)
                self.assertEqual(order, [str(odd), str(fresh)])
                self.assertEqual(
                    self.tab(html, odd)[1:], ("none", "project", "최근 실행 알 수 없음")
                )
                self.assertEqual(self.tab(html, fresh)[1:], ("none", "fresh", "실행 기록 없음"))
                # The same mark, told apart in view by a word.
                line = html.split(f'href="/projects/{odd}"', 1)[1].split("</a>", 1)[0]
                self.assertIn('<span class="tab-count"><span class="n-unknown" aria-hidden="true">'
                              "알 수 없음</span></span>", line)  # fmt: skip
                line = html.split(f'href="/projects/{fresh}"', 1)[1].split("</a>", 1)[0]
                self.assertIn('<span class="tab-count"><span class="n-none" aria-hidden="true">'
                              "미검사</span></span>", line)  # fmt: skip

    def test_without_a_project_the_first_page_is_one_button_that_adds_it(self):
        for url in ("/", "/?manage=1"):  # nothing to manage yet: the same page
            html = self.page(url)
            elements = Elements(html).found
            body = elements[[tag for tag, _ in elements].index("body") :]
            # One form with one button, and nothing of the console around it: no bar, no
            # heading, no count, no chart, no footer, no link.
            self.assertEqual([tag for tag, _ in body],
                             ["body", "main", "form", "input", "button", "p", "p"], url)  # fmt: skip
            self.assertEqual(body[0][1], {"class": "start"})
            self.assertEqual(body[2][1], {"method": "post", "action": "/projects/pick"})
            self.assertEqual(body[3][1], {"type": "hidden", "name": "csrf", "value": CSRF})
            self.assertEqual(body[4][1]["type"], "submit")
            self.assertEqual(body[4][1]["data-busy-label"], "폴더 선택 창을 확인하세요…")
            self.assertIn(">프로젝트 추가</button>", html)
            # What else the page says is for a screen reader only: what the button opens, and
            # the line the script speaks through.
            self.assertEqual([attrs["class"] for tag, attrs in body if tag == "p"],
                             ["visually-hidden"] * 2)  # fmt: skip
            self.assertEqual(body[4][1]["aria-describedby"], body[5][1]["id"])
            self.assertIn("npm 프로젝트 폴더를 이 PC에서 고릅니다.", html)
            for absent in ("등록한 프로젝트", "프로젝트 0개", SAFETY_NOTE.replace("'", "&#39;")):
                self.assertNotIn(absent, html)
            self.assertIn("<title>프로젝트 추가 - depbee</title>", html)
        self.assertFalse(self.db.exists())  # looking creates no history
        # Every page names the tab icon: a browser then never asks for /favicon.ico.
        self.assertIn('<link rel="icon" type="image/svg+xml" href="/static/icon.svg">', html)
        icon = self.get("/static/icon.svg")
        self.assertEqual((icon.status_code, icon.headers["content-type"]), (200, "image/svg+xml"))
        self.assertTrue(icon.text.startswith("<svg "))
        # The pages outside a project keep the console.
        model = self.page("/model")
        self.assertIn("이 화면은 이 PC의 127.0.0.1에서만 열립니다.", model)
        self.assertIn('<a class="skip" href="#main">본문으로 건너뛰기</a>', model)
        self.assertIn('<main id="main">', model)
        self.assertNotIn('<a class="tab" ', model)
        self.assertIn('<a href="/model" aria-current="page">모델 정보</a>', model)
        self.assertNotIn(' aria-current="page">프로젝트 관리', model)
        # With a project the first page is the overview, and project management the place
        # where the next one is added, by the dialog alone.
        history.register_project(self.project)
        self.assertIn("<title>프로젝트 현황판 - depbee</title>", self.page("/"))
        manage = self.page("/?manage=1")
        self.assertIn('<a class="tab manage" href="/?manage=1" aria-current="page">프로젝트 관리</a>',
                      manage)  # fmt: skip
        self.assertIn('<form method="post" action="/projects/pick">', manage)
        self.assertNotIn('action="/projects"', manage)
        self.assertNotIn('name="path"', manage)

    def test_tabs_show_each_project_its_state_and_the_open_one(self):
        flagged = history.register_project(self.project)
        passed = history.register_project(self.folder("passed"))
        held = history.register_project(self.folder("held"))
        fresh = history.register_project(self.folder("fresh"))
        gone = history.register_project(self.folder("gone"))
        run = history.record("scan", self.project, self.scan_with(0.9))
        history.record("scan", self.root / "passed", self.scan_with(0.1))
        history.record("scan", self.root / "held", self.scan_with(analyzer=False))
        history.record("scan", self.root / "gone", self.scan_with(0.9))  # hidden by the folder
        (self.root / "gone" / "package-lock.json").unlink()
        (self.root / "gone").rmdir()
        html = self.page("/")
        states = {project: self.tab(html, project) for project in (flagged, passed, held, fresh,
                                                                   gone)}  # fmt: skip
        self.assertEqual(states, {
            flagged: ("", "risk", "project", "최근 실행 위험"),
            passed: ("", "pass", "passed", "최근 실행 통과"),
            held: ("", "hold", "held", "최근 실행 보류"),
            fresh: ("", "none", "fresh", "실행 기록 없음"),
            gone: ("", "gone", "gone", "폴더를 찾을 수 없음"),
        })  # fmt: skip
        # The open project is marked on its own views and on the pages under it, and only it.
        marks = {"": ' aria-current="page"', "/updates": ' aria-current="true"',
                 "/history": ' aria-current="true"'}  # fmt: skip
        for view, mark in marks.items():
            html = self.page(f"/projects/{flagged}{view}")
            self.assertEqual(self.tab(html, flagged)[0], mark, view)
            # The rail tab and the view link; the packages view also marks its list tab.
            self.assertEqual(html.count("aria-current="), 3 if view == "" else 2, view)
            self.assertEqual(self.tab(html, passed)[0], "", view)
        html = self.page(f"/runs/{run}")
        self.assertEqual(self.tab(html, flagged)[0], ' aria-current="true"')
        self.assertIn(f'<li><a href="/projects/{flagged}">project</a></li>\n'
                      f'<li><a href="/projects/{flagged}/history">기록</a></li>\n'
                      f'<li aria-current="page">실행 #{run}</li>', html)  # fmt: skip

    def test_same_folder_names_are_told_apart_by_their_parents(self):
        paths = [self.project, self.folder("a", "app"), self.folder("b", "app"),
                 self.folder("c", "x", "app"), self.folder("d", "x", "app")]  # fmt: skip
        ids = [history.register_project(path) for path in paths]
        names = ["project", "a/app", "b/app", "c/x/app", "d/x/app"]
        html = self.page("/")
        self.assertEqual([self.tab(html, project)[2] for project in ids], names)
        for project, name, path in zip(ids, names, paths, strict=True):
            html = self.page(f"/projects/{project}")
            full = str(path.resolve())
            self.assertEqual(project_head(html), (name, self.app._short_path(full), full))
            self.assertIn(f"<title>{name} 패키지 - depbee</title>", html)
        self.assertEqual(self.app._names([]), [])
        self.assertEqual(self.app._names([str(self.root)]), [self.root.name])
        # The whole path at most: one folder inside another one of the same name.
        outer, inner = str(Path("app")), str(Path("app", "app"))
        self.assertEqual(self.app._names([outer, inner]), [outer, inner])

    def test_each_view_heads_with_the_two_actions_and_how_many_each_view_holds(self):
        project = history.register_project(self.project)
        history.record("scan", self.project, self.scan_with(0.9))
        entries = len(self.app._dependencies(str(self.project.resolve()))[0])
        self.assertGreater(entries, 0)
        for view in ("", "/updates", "/history"):
            html = self.page(f"/projects/{project}{view}")
            head = html[
                html.index('<header class="project-head">') : html.index(
                    "</header>", html.index('<header class="project-head">')
                )
            ]
            self.assertIn(
                '<span class="verdict risk"><span class="cell risk" aria-hidden="true"></span>최근 실행 위험</span>',
                head,
            )
            check = re.search(
                rf'<form method="post" action="/projects/{project}/previews" id="preview-project">(.*?)</form>',
                head,
                re.S,
            )
            self.assertIsNotNone(check, view)
            self.assertIn('name="packages" value="">전체 업데이트 미리보기(update)</button>', check[1])
            # Only a check sent from the packages view comes back to its list (app._back).
            self.assertEqual('name="back"' in check[1], view == "", view)
            self.assertIn(f'<form method="post" action="/projects/{project}/scans">', head)
            self.assertIn('data-busy-label="lockfile 변경 검사 중…">lockfile 변경 검사(scan)</button>', head)
            for label, count in (("패키지", entries), ("업데이트", 0), ("기록", 1)):
                self.assertIn(f'{label}<span class="view-count">{count}</span></a>', head, view)
            # The packages view holds no second check button of its own.
            self.assertEqual(html.count('id="preview-project"'), 1, view)
        # A folder that is gone: no action, and no count of packages it cannot read.
        self.head.unlink()
        self.project.rmdir()
        html = self.page(f"/projects/{project}")
        self.assertNotIn("/previews", html)
        self.assertIn("패키지</a>", html)

    def test_a_path_is_cut_to_its_last_three_folders(self):
        short = self.app._short_path
        self.assertEqual(short(r"C:\Users\dev\work\clients\acme\repos\storefront-web"),
                         "…\\acme\\repos\\storefront-web")  # fmt: skip
        self.assertEqual(short("/projects/web/app/x/y"), "…/app/x/y")
        self.assertEqual(short("\\\\server\\share\\a\\b\\c\\d"), "…\\b\\c\\d")
        # A POSIX folder may have a backslash in its name; a Windows path written with "/"
        # keeps it.
        self.assertEqual(short("/projects/group/my\\team/repo"), "…/group/my\\team/repo")
        self.assertEqual(short("C:/work/client/app/src"), "…/client/app/src")
        for whole in (r"C:\a\b", r"C:\a\b\c", "D:\\", "/", "/projects/app-a", "/a/b/c", "relative"):
            self.assertEqual(short(whole), whole)
        # Shown cut, whole on hover; project management keeps the whole path.
        folder = self.folder("one", "two", "three", "four")
        project = history.register_project(folder)
        full = str(folder.resolve())
        self.assertEqual(project_head(self.page(f"/projects/{project}")),
                         ("four", short(full), full))  # fmt: skip
        self.assertTrue(
            short(full).startswith("…")
            and short(full).endswith("two" + os.sep + "three" + os.sep + "four")
        )
        self.assertIn(f'<span class="ov-path" title="{full}">{short(full)}</span>', self.page("/"))
        self.assertIn(f'<p class="path">{full}</p>', self.page("/?manage=1"))

    def test_each_view_of_a_project_names_it_and_links_the_others(self):
        project = history.register_project(self.project)
        path = str(self.project.resolve())
        views = {"": "패키지", "/updates": "업데이트", "/history": "기록"}
        for view, label in views.items():
            html = self.page(f"/projects/{project}{view}")
            self.assertIn(f"<title>project {label} - depbee</title>", html)
            self.assertEqual(project_head(html), ("project", self.app._short_path(path), path))
            self.assertIn('<nav class="views" aria-label="project 화면">', html)
            for other, text in views.items():
                current = ' aria-current="page"' if other == view else ""
                self.assertIn(
                    f'<a href="/projects/{project}{other}"{current}>{text}<span class="view-count',
                    html,
                )
            if view:  # the views take GET only
                response = self.client.post(f"/projects/{project}{view}",
                                            data={"csrf": CSRF}, headers={"origin": BASE})  # fmt: skip
                self.assertEqual(response.status_code, 405)
        history_page = self.page(f"/projects/{project}/history")
        self.assertIn("기록된 반영이 없습니다.", history_page)
        self.assertIn("기록된 실행이 없습니다.", history_page)
        self.assertIn(f'<a href="/projects/{project}/updates">업데이트</a>', history_page)

    def test_a_missing_folder_keeps_its_history_and_says_where_to_go(self):
        project = history.register_project(self.project)
        run = history.record("scan", self.project, self.scan_with(0.9))
        self.head.unlink()
        self.project.rmdir()
        for view in ("", "/updates", "/history"):
            html = self.page(f"/projects/{project}{view}")
            self.assertIn('<p class="error">프로젝트 폴더를 찾을 수 없습니다.', html)
            self.assertIn('<a href="/?manage=1">프로젝트 관리</a>에서 새로 등록하세요.', html)
            self.assertIn(f'<a href="/projects/{project}/history">기록</a>에 그대로', html)
            for form in ("/previews", "/scans"):
                self.assertNotIn(form, html)
            # No button but the rail's theme one and the question marks of the explanations.
            self.assertEqual(
                html.count("<button"),
                html.count('<button type="submit" name="theme"') + html.count('class="help"'),
            )
        self.assertIn(f'<a href="/runs/{run}">#{run}</a>', html)  # the history view
        self.assertIn("찾을 수 없음. 폴더를 원래 위치로", self.page("/?manage=1"))


def lock(example="1.1.0"):
    """A synthetic lockfile: example and other are direct, inner is under example."""
    return {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"example": "^1.0.0", "other": "^1.0.0"}},
        "node_modules/example": package(example),
        "node_modules/example/node_modules/inner": package("2.0.0"),
        "node_modules/other": package(),
    }}  # fmt: skip


class CandidateTests(DashboardFixture):
    """Update candidates on the project's views: only stored update previews of this project
    made from package.json and package-lock.json as they are now. The project installs example
    1.1.0; the synthetic preview report would update it to 1.2.0."""

    def setUp(self):
        super().setUp()
        self.manifest = self.project / "package.json"
        self.manifest.write_text(json.dumps(lock()["packages"][""]), encoding="utf-8")
        self.old, self.new = lock(), lock("1.2.0")
        self.save_locks()
        self.report = self.scan_with(0.9)  # example 1.1.0 -> 1.2.0, flagged
        self.write(self.head, self.old)  # the project as it is now
        self.project_id = history.register_project(self.project)
        self.packages = f"/projects/{self.project_id}"
        self.updates = f"/projects/{self.project_id}/updates"

    def made_now(self, **changes):
        """An update preview document made from the project's two files as they are now."""
        return {**PREVIEW, "package_json_sha256": sha(self.manifest.read_bytes()),
                "package_lock_sha256": sha(self.head.read_bytes()), **changes}  # fmt: skip

    def check(self, report=None, project=None, **changes):
        return history.record("update_preview", project or self.project, report or self.report,
                              self.made_now(**changes))  # fmt: skip

    def nothing(self):
        return {**self.report, "results": []}

    def test_explanations_wait_behind_a_question_mark_and_safety_sentences_stay_in_view(self):
        unchecked = self.page(self.packages)
        self.check()  # a current candidate: the inspector beside the list
        pages = {"unchecked": unchecked, "packages": self.page(self.packages),
                 "updates": self.page(self.updates), "history": self.page(f"{self.packages}/history")}  # fmt: skip
        always = (SAFETY_NOTE, "이 PC의 다른 계정과 프로그램도 이 주소를 열 수 있습니다.")
        shown = {
            "unchecked": always + ("미리보기 전은 후보 0개와 다릅니다",),
            "packages": always + ("이 화면에서는 반영하지 않습니다.",),
            "updates": always, "history": always,
        }  # fmt: skip
        for name, html in pages.items():
            popovers = re.findall(
                r'<div class="help-pop" id="([\w-]+)" popover>(.*?)</div>', html, re.S
            )
            self.assertTrue(popovers, name)
            ids = re.findall(r'\sid="([^"]+)"', html)
            self.assertEqual(len(ids), len(set(ids)), name)
            targets = re.findall(r'<button type="button" class="help" popovertarget="([\w-]+)" '
                                 r'aria-label="[^"]+">', html)  # fmt: skip
            self.assertEqual(sorted(targets), sorted(pop for pop, _ in popovers), name)
            self.assertEqual(html.count("popovertarget="), len(targets), name)
            outside = re.sub(
                r'<div class="help-pop" id="[\w-]+" popover>.*?</div>', "", html, flags=re.S
            )
            # Below 64rem the picked candidate's evidence is folded until it is opened.
            outside = re.sub(r'(<aside class="inspector" [^>]*>.*?)<div class="inspect-body">.*?</aside>',
                             r"\1</aside>", outside, flags=re.S)  # fmt: skip
            visible = " ".join(unescape(re.sub(r"<[^>]+>", " ", outside)).split())
            for sentence in shown[name]:
                self.assertIn(" ".join(sentence.split()), visible, name)
            # Every safety sentence a page holds at all is in view, never behind a question mark.
            for sentence in ("실행하지 않은 것은 통과가 아닙니다.", "점수가 없는 것은 0점이 아닙니다.",
                             "이 화면에서는 반영하지 않습니다.", "미리보기 전은 후보 0개와 다릅니다"):  # fmt: skip
                if sentence in unescape(html):
                    self.assertIn(sentence, visible, name)
        self.assertIn("실행하지 않은 것은 통과가 아닙니다.", unescape(pages["packages"]))
        # The stylesheet never hides a popover itself: a browser without them shows it in place.
        css = (Path(self.app.__file__).parent / "static" / "style.css").read_text("utf-8")
        self.assertEqual(re.findall(r"\[popover\](?!:popover-open)[^{,]*[{,]", css), [])
        # A question mark takes its whole 44px: nothing next to it lies over its lower part.
        rule = re.search(r"^\.help \{([^}]*)\}", css, re.M).group(1)
        self.assertNotRegex(rule, r"margin[^;]*-")
        # The footer's sentence is as wide as the footer.
        self.assertRegex(css, r"(?m)^footer \.note \{[^}]*max-width: none")

    def test_how_long_a_check_takes_is_behind_a_question_mark(self):
        unchecked = self.page(self.packages)
        self.assertNotIn('후보 옆의 "근거"', unchecked)
        self.assertIn("보고서에서 전체 근거 보기", unchecked)
        self.assertIn("미리보기 전은 후보 0개와 다릅니다.", unchecked)
        self.assertRegex(unchecked, r'(?s)<div class="help-pop" id="[\w-]+" popover>'
                                    r"(?:(?!</div>).)*미리보기는 몇 초에서 수십 초 걸리고")  # fmt: skip
        # The buttons each page names are the ones its head has.
        self.assertNotIn("업데이트 후보 확인", self.page(f"{self.packages}/history"))

    def test_a_gone_folder_without_a_run_names_no_button(self):
        moved = self.project.with_name(self.project.name + "-moved")
        self.project.rename(moved)
        try:
            history_html = self.page(f"{self.packages}/history")
        finally:
            moved.rename(self.project)
        self.assertIn("기록된 실행이 없습니다.", history_html)
        self.assertNotIn('위의 "전체 업데이트 미리보기', history_html)
        self.assertNotIn("미리보기에서 반영하면", history_html)
        self.assertIn("기록된 반영이 없습니다.", history_html)
        self.assertNotIn('id="preview-project"', history_html)

    def test_the_updates_tab_counts_the_current_candidates_and_stands_out(self):
        self.check()
        for view in (self.packages, self.updates, f"{self.packages}/history"):
            self.assertIn('업데이트<span class="view-count hot">1</span></a>', self.page(view))

    def cells(self, html=None):
        """{location: the candidate cell} of the packages table."""
        html = self.page(self.packages) if html is None else html
        rows = package_rows(html)
        self.assertEqual(len(rows), 3, html)
        return {row[3]: row[5] for row in rows}

    def assert_unchecked(self, cells):
        for name in ("example", "other"):
            self.assertIn(f'form="preview-project" name="packages" value="{name}" '
                          f'aria-label="이 패키지 미리보기: {name} 업데이트(update)">'
                          "이 패키지 미리보기</button>",
                          cells[f"node_modules/{name}"])  # fmt: skip
        self.assertIn("</span>미리보기 전</span>", cells["node_modules/example/node_modules/inner"])
        self.assertNotIn("후보 없음", "".join(cells.values()))
        self.assertNotIn("1.2.0", "".join(cells.values()))

    def test_a_first_look_says_nothing_was_checked_and_runs_nothing(self):
        services = [mock.patch.object(service, name) for name in
                    ("preview_files", "scan_project", "apply_preview", "check_package")]  # fmt: skip
        mocks = [patcher.start() for patcher in services]
        for patcher in services:
            self.addCleanup(patcher.stop)
        html = self.page(self.packages)
        self.assertIn("아직 업데이트 미리보기를 실행하지 않았습니다.", html)
        self.assert_unchecked(self.cells(html))
        updates = self.page(self.updates)
        self.assertIn("아직 업데이트 미리보기를 실행하지 않았습니다.", updates)
        self.assertNotIn('class="stack candidates"', updates)
        self.assertNotIn("검토·반영할 미리보기", updates)
        for view in ("/history", "?q=example&scope=direct"):
            self.page(self.packages + view)
        self.page("/")
        self.page("/model")
        self.assertEqual([called.call_count for called in mocks], [0, 0, 0, 0])
        self.assertEqual(history.list_runs(self.project_id), [])  # looking records nothing

    def test_a_check_of_everything_shows_its_candidates_and_covers_the_rest(self):
        run = self.check(targets=None)
        html = self.page(self.packages)
        self.assertIn("전체 업데이트 미리보기에서 후보 1개를 찾았습니다.", html)
        cells = self.cells(html)
        candidate = cells["node_modules/example"]
        self.assertIn('<span class="visually-hidden">: example, node_modules/example, 후보 버전 1.2.0, '
                      "검사 근거 열기</span>", candidate)  # fmt: skip
        # Whether the candidate could be applied, as the update gate decides it: an ML hit that
        # no known malicious list was checked against needs the user's confirmation.
        self.assertIn('<span class="verdict hold"><span class="cell hold" aria-hidden="true">'
                      "</span>확인 필요</span>", candidate)  # fmt: skip
        self.assertIn(f'?item={run}.0#candidate-evidence"', candidate)
        # The report's own row is reached from the inspector, not from each row of the list.
        self.assertNotIn(f'href="/runs/{run}#r0"', html.split('<aside class="inspector"')[0])
        for location in ("node_modules/other", "node_modules/example/node_modules/inner"):
            self.assertEqual(cells[location], '<span class="quiet">후보 없음</span>')
        self.assertNotIn("이 패키지 미리보기</button>", html)
        updates = self.page(self.updates)
        self.assertIn("지금의 package.json과 package-lock.json으로 만든 전체 업데이트 미리보기의 결과입니다. "
                      "바뀐 의존성 1개: 위험 1, 통과 0, 보류 0.", updates)  # fmt: skip
        self.assertRegex(updates, rf'미리보기한 실행: <a href="/runs/{run}">#{run}</a> '
                                  r"\(\d{4}-\d\d-\d\d \d\d:\d\d UTC, 전체\)</p>")  # fmt: skip
        for text in (
            '<th scope="row">example<span class="where">node_modules/example</span></th>',
            '<td>1.1.0 <span aria-hidden="true">→</span><span class="visually-hidden">에서</span>'
            " 1.2.0</td>",
            "<td>0.900 (기준 이상)</td>",
            "<li>synthetic evidence</li>",  # in the inspector, open on the first candidate
            f'href="/runs/{run}#r0">보고서에서 전체 근거 보기',
            'href="https://www.npmjs.com/package/example" rel="noreferrer noopener">',
            "릴리스 노트와 변경 내역 원문은 depbee가 수집하지 않으므로",
        ):  # fmt: skip
            self.assertIn(text, updates)
        self.assertIn('<section class="result flagged" id="r0">', self.page(f"/runs/{run}"))
        for view in (self.packages, self.updates):
            html = self.page(f"{view}?item={run}.0")
            self.assertIn(f'href="{view}?item={run}.0#candidate-evidence"', html)
            self.assertEqual(html.count('id="candidate-evidence" tabindex="-1"'), 1)
            panel = html.split('<aside class="inspector"', 1)[1].split("</aside>", 1)[0]
            self.assertIn("node_modules/example", panel)
            self.assertIn("synthetic evidence", panel)

    def test_a_check_of_named_packages_covers_only_them(self):
        first = self.check(targets=["example"])
        cells = self.cells()
        self.assertIn("후보 버전 1.2.0,", cells["node_modules/example"])
        self.assertIn("이 패키지 미리보기</button>", cells["node_modules/other"])  # no preview yet
        self.assertIn("미리보기 전", cells["node_modules/example/node_modules/inner"])
        second = self.check(self.nothing(), targets=["other"], changed_count=0)
        cells = self.cells()
        self.assertIn("후보 버전 1.2.0,", cells["node_modules/example"])  # the older check stands
        self.assertEqual(cells["node_modules/other"], '<span class="quiet">후보 없음</span>')
        self.assertIn("미리보기 전", cells["node_modules/example/node_modules/inner"])
        updates = self.page(self.updates)
        self.assertRegex(updates, rf'#{second}</a> \([^)]*, other\), <a href="/runs/{first}">'
                                  rf"#{first}</a> \([^)]*, example\)</p>")  # fmt: skip
        self.assertIn("바뀐 의존성 1개: 위험 1, 통과 0, 보류 0.", updates)

    def test_the_newest_check_of_a_location_wins(self):
        self.check(targets=["example"])
        self.check(self.nothing(), targets=None, changed_count=0)  # later: nothing would change
        html = self.page(self.packages)
        self.assertEqual(set(self.cells(html).values()), {'<span class="quiet">후보 없음</span>'})
        self.assertRegex(html, r"\d\d:\d\d UTC의 전체 업데이트 미리보기에서 바뀌는 항목이 없었습니다.")
        updates = self.page(self.updates)
        self.assertIn("전체 업데이트 미리보기의 결과입니다. 바뀌는 항목이 없었습니다.", updates)
        self.assertNotIn('class="stack candidates"', updates)

    def test_results_of_changed_files_are_not_current_candidates(self):
        run = self.check(targets=None)
        current = self.head.read_bytes()
        for changed in (self.head, self.manifest):
            with self.subTest(changed=changed.name):
                before = changed.read_bytes()
                changed.write_bytes(before + b"\n")
                html = self.page(self.packages)
                self.assertIn("마지막 업데이트 미리보기 뒤에 package.json이나 package-lock.json이 "
                              "바뀌었습니다. 업데이트 미리보기를 다시 실행하세요.", html)  # fmt: skip
                self.assert_unchecked(self.cells(html))
                updates = self.page(self.updates)
                self.assertRegex(updates, rf'마지막 미리보기\(실행 <a href="/runs/{run}">'
                                          rf"#{run}</a>, [^)]*\) 뒤에")  # fmt: skip
                self.assertIn("그 결과는 현재 후보로 보지 않습니다.", updates)
                self.assertNotIn('class="stack candidates"', updates)
                changed.write_bytes(before)
        # The same bytes again are the files the check was made from.
        self.assertEqual(self.head.read_bytes(), current)
        self.assertIn("후보 버전 1.2.0,", self.cells()["node_modules/example"])

    def test_another_projects_results_are_not_candidates(self):
        other = self.root / "other"
        other.mkdir()
        self.write(other / "package-lock.json", lock("1.0.0"))
        (other / "package.json").write_bytes(self.manifest.read_bytes())
        other_id = history.register_project(other)
        # A run of the other project that names this project's files.
        run = self.check(project=other, targets=None)
        self.assert_unchecked(self.cells())
        self.assertIn("아직 업데이트 미리보기를 실행하지 않았습니다.", self.page(self.updates))
        updates = self.page(f"/projects/{other_id}/updates")
        self.assertIn(f'<a href="/runs/{run}">#{run}</a>', updates)
        self.assertIn("그 결과는 현재 후보로 보지 않습니다.", updates)
        self.assertNotIn("1.2.0", updates)

    def test_unreadable_files_have_no_candidates(self):
        self.check(targets=None)
        self.manifest.unlink()
        html = self.page(self.packages)
        cells = "".join(self.cells(html).values())
        self.assertNotIn("1.2.0", cells)
        self.assertNotIn("<button", cells)  # package.json names what can be checked alone
        for page in (html, self.page(self.updates)):
            self.assertIn("package.json이나 package-lock.json을 읽을 수 없어", page)
            self.assertNotIn("바뀌었습니다", page)
        self.assertIsNone(self.app._sha256(str(self.project), "package.json"))
        self.assertIsNone(self.app._sha256(str(self.root), "project"))  # a folder
        self.assertIsNone(self.app._sha256("\\\\server\\share", "package.json"))
        with mock.patch.object(self.app, "MAX_JSON_BYTES", 4):
            self.assertIsNone(self.app._sha256(str(self.project), "package-lock.json"))

    def test_an_applied_check_is_said_to_be_applied(self):
        run = history.record("update_preview", self.project, self.report, self.made_now(),
                             apply=applied_document())  # fmt: skip
        self.write(self.head, self.new)  # what the apply wrote
        updates = self.page(self.updates)
        self.assertRegex(updates, rf'실행 <a href="/runs/{run}">#{run}</a>의 업데이트를 '
                                  r"[^<]* UTC에 반영했습니다. 반영한 뒤의 파일로는 아직")  # fmt: skip
        self.assertNotIn("그 결과는 현재 후보로 보지 않습니다.", updates)
        refused = history.record("update_preview", self.project, self.report, self.made_now(
            package_lock_sha256="3" * 64), apply=applied_document("refused", "project_changed"))  # fmt: skip
        updates = self.page(self.updates)
        self.assertIn(f'<a href="/runs/{refused}">#{refused}</a>', updates)
        self.assertIn("그 결과는 현재 후보로 보지 않습니다.", updates)

    def test_added_and_removed_entries_and_a_later_check_of_one_of_them(self):
        row = self.report["results"][0]
        added = {**row, "location": "node_modules/new", "package": "new",
                 "before_version": None, "after_version": "3.0.0"}  # fmt: skip
        removed = {**row, "location": "node_modules/other", "package": "other",
                   "before_version": "1.0.0", "after_version": None, "status": "removed",
                   "score": None}  # fmt: skip
        run = self.check({**self.report, "results": [added, removed]}, targets=None)
        cells = self.cells()
        self.assertIn('<span class="verdict pass"><span class="cell pass" aria-hidden="true"></span>'
                      '반영 가능</span><span class="visually-hidden">: other, node_modules/other, '
                      "후보 버전 삭제, 검사 근거 열기</span>", cells["node_modules/other"])  # fmt: skip
        panel = self.page(f"{self.packages}?item={run}.1").split('<aside class="inspector"', 1)[1]
        self.assertIn("<dt>ML 점수</dt><dd><b>해당 없음(삭제)</b></dd>", panel)
        self.assertNotIn("0점이 아닙니다", panel)
        updates = self.page(self.updates)
        self.assertIn('<td><span class="quiet">새로 추가</span> <span aria-hidden="true">→</span>'
                      '<span class="visually-hidden">에서</span> 3.0.0</td>', updates)  # fmt: skip
        self.assertIn('에서</span> <span class="quiet">삭제</span></td>', updates)
        self.assertIn(f'/updates?item={run}.1#candidate-evidence"', updates)
        self.assertIn("바뀐 의존성 2개: 위험 1, 통과 0, 보류 0, 삭제 1.", updates)
        # A later check of other alone would not remove it: that row goes, the added entry of
        # the check of everything stays.
        later = self.check(self.nothing(), targets=["other"], changed_count=0)
        self.assertEqual(self.cells()["node_modules/other"], '<span class="quiet">후보 없음</span>')
        updates = self.page(self.updates)
        self.assertIn('<span class="quiet">새로 추가</span>', updates)
        self.assertNotIn('<span class="quiet">삭제</span>', updates)
        self.assertIn("전체 업데이트 미리보기의 결과입니다. 바뀐 의존성 1개: 위험 1, 통과 0, 보류 0.", updates)
        self.assertRegex(updates, rf'#{later}</a> \([^)]*, other\), <a href="/runs/{run}">'
                                  rf"#{run}</a> \([^)]*, 전체\)</p>")  # fmt: skip

    def test_a_check_of_everything_stands_after_many_checks_of_other_packages(self):
        everything = self.check(targets=None)
        for _ in range(12):  # more than any window of recent previews
            newest = self.check(self.nothing(), targets=["other"], changed_count=0)
        html = self.page(self.packages)
        self.assertIn("전체 업데이트 미리보기에서 후보 1개를 찾았습니다.", html)
        cells = self.cells(html)
        self.assertIn("후보 버전 1.2.0,", cells["node_modules/example"])
        self.assertIn(f'?item={everything}.0#candidate-evidence"', cells["node_modules/example"])
        for location in ("node_modules/other", "node_modules/example/node_modules/inner"):
            self.assertEqual(cells[location], '<span class="quiet">후보 없음</span>')
        updates = self.page(self.updates)
        self.assertIn("전체 업데이트 미리보기의 결과입니다. 바뀐 의존성 1개: 위험 1, 통과 0, 보류 0.", updates)
        self.assertIn('class="stack candidates"', updates)
        # Listed are the checks whose result is shown: the newest of other and the one of
        # everything, not the eleven checks of other that the newest one replaced.
        self.assertRegex(updates, rf'미리보기한 실행: <a href="/runs/{newest}">#{newest}</a> '
                                  rf'\([^)]*, other\), <a href="/runs/{everything}">'
                                  rf"#{everything}</a> \([^)]*, 전체\)</p>")  # fmt: skip

    def test_restored_files_have_their_candidates_again(self):
        self.check(targets=None)
        original = self.head.read_bytes()
        self.write(self.head, lock("1.0.0"))  # other files for a while, e.g. another branch
        for _ in range(12):  # checked there: nothing would change
            self.check(self.nothing(), targets=None, changed_count=0)
        html = self.page(self.packages)
        self.assertRegex(html, r"\d\d:\d\d UTC의 전체 업데이트 미리보기에서 바뀌는 항목이 없었습니다.")
        self.assertNotIn("1.2.0", "".join(self.cells(html).values()))
        self.head.write_bytes(original)  # the same bytes as when the first check ran
        self.assertIn("후보 버전 1.2.0,", self.cells()["node_modules/example"])
        updates = self.page(self.updates)
        self.assertIn("전체 업데이트 미리보기의 결과입니다. 바뀐 의존성 1개: 위험 1, 통과 0, 보류 0.", updates)
        self.assertNotIn("그 결과는 현재 후보로 보지 않습니다.", updates)

    def test_checks_of_named_packages_never_say_that_nothing_changes(self):
        self.check(self.nothing(), targets=["other"], changed_count=0)
        html, updates = self.page(self.packages), self.page(self.updates)
        self.assertIn("지정한 패키지만 미리보기했고 그 패키지에는 업데이트 후보가 없었습니다. 나머지 "
                      "패키지는 미리보기 전입니다.", html)  # fmt: skip
        cells = self.cells(html)
        self.assertEqual(cells["node_modules/other"], '<span class="quiet">후보 없음</span>')
        self.assertIn("이 패키지 미리보기</button>", cells["node_modules/example"])
        self.assertIn("미리보기 전", cells["node_modules/example/node_modules/inner"])
        self.assertIn("지정한 패키지만 미리보기한 결과입니다. 그 패키지에는 업데이트 후보가 "
                      "없었습니다. 나머지 패키지는 미리보기 전이며", updates)  # fmt: skip
        self.assertNotIn('class="stack candidates"', updates)
        for page in (html, updates):  # only a check of everything is evidence of that
            self.assertNotIn("바뀌는 항목이 없었습니다", page)
        self.check(targets=["example"])  # a candidate, still not a check of everything
        self.assertIn("지정한 패키지만 미리보기했고 업데이트 후보 1개를 찾았습니다. 나머지 패키지는 "
                      "미리보기 전입니다.", self.page(self.packages))  # fmt: skip
        self.assertIn("지정한 패키지만 미리보기한 결과입니다. 바뀐 의존성 1개: 위험 1, 통과 0, 보류 0. "
                      "나머지 패키지는 미리보기 전이며", self.page(self.updates))  # fmt: skip

    def test_projects_with_the_same_files_keep_their_own_candidates(self):
        twin = self.root / "twin"
        twin.mkdir()
        for name in ("package.json", "package-lock.json"):
            (twin / name).write_bytes((self.project / name).read_bytes())
        twin_id = history.register_project(twin)
        mine = self.check(targets=None)
        # The same two hashes, but the check was made in the other project.
        self.assertIn(
            "아직 업데이트 미리보기를 실행하지 않았습니다.", self.page(f"/projects/{twin_id}")
        )
        theirs = self.check(self.nothing(), project=twin, targets=None, changed_count=0)
        self.assertIn("미리보기에서 바뀌는 항목이 없었습니다.", self.page(f"/projects/{twin_id}"))
        self.assertNotIn(f"/runs/{mine}", self.page(f"/projects/{twin_id}/updates"))
        self.assertIn(f'?item={mine}.0#candidate-evidence"', self.cells()["node_modules/example"])
        self.assertNotIn(f"/runs/{theirs}", self.page(self.updates))

    def test_a_location_the_history_stores_as_escaped_text_is_the_same_location(self):
        # The history stores a lone surrogate in a result row's location as the text \udc80. The
        # lockfile row, the stored row and a later check's target must still be one location.
        odd = "node_modules/\udc80x"
        self.old["packages"][odd] = package()
        self.write(self.head, self.old)

        def cell():
            rows = package_rows(self.page(self.packages))
            self.assertEqual(len(rows), 4)
            return {row[3]: row[5] for row in rows}["node_modules/\\udc80x"]

        row = {**self.report["results"][0], "location": odd, "package": "\udc80x"}
        run = self.check({**self.report, "results": [row]}, targets=None)
        self.assertIn(f'?item={run}.0#candidate-evidence"', cell())
        # Later that package alone is checked and would not change: its candidate goes.
        self.check(self.nothing(), targets=["\udc80x"], changed_count=0)
        self.assertEqual(cell(), '<span class="quiet">후보 없음</span>')

    def test_a_lone_surrogate_and_its_escape_text_are_two_locations(self):
        # The history stores both locations as the same text; the stored reports tell them
        # apart. Each keeps its own candidate, from its own run and its own row.
        lone, text = "node_modules/\udc80x", "node_modules/\\udc80x"
        self.old["packages"][lone] = package("7.0.0")
        self.old["packages"][text] = package("8.0.0")
        self.write(self.head, self.old)

        def cells():
            """The candidate cells of the two rows (told apart by the installed version: their
            location is shown with the same characters)."""
            rows = package_rows(self.page(self.packages))
            shown = {version.split("<")[0]: cell for _, _, _, location, version, cell in rows
                     if location == "node_modules/\\udc80x"}  # fmt: skip
            self.assertEqual(sorted(shown), ["7.0.0", "8.0.0"])
            return shown["7.0.0"], shown["8.0.0"]

        def row(location, package_name, before, after):
            return {**self.report["results"][0], "location": location, "package": package_name,
                    "before_version": before, "after_version": after}  # fmt: skip

        both = [row(lone, "\udc80x", "7.0.0", "7.1.0"), row(text, "\\udc80x", "8.0.0", "8.1.0")]
        first = self.check({**self.report, "results": both}, targets=None)
        of_lone, of_text = cells()
        self.assertIn("후보 버전 7.1.0,", of_lone)
        self.assertIn(f'?item={first}.0#candidate-evidence"', of_lone)
        self.assertIn("후보 버전 8.1.0,", of_text)
        self.assertIn(f'?item={first}.1#candidate-evidence"', of_text)
        updates = self.page(self.updates)
        self.assertIn("바뀐 의존성 2개: 위험 2, 통과 0, 보류 0.", updates)
        for position in (0, 1):
            self.assertIn(f'/updates?item={first}.{position}#candidate-evidence"', updates)
        # A later check of the package named with the escape text alone: only that location
        # takes the new run's row.
        second = self.check({**self.report, "results": [row(text, "\\udc80x", "8.0.0", "8.2.0")]},
                            targets=["\\udc80x"])  # fmt: skip
        of_lone, of_text = cells()
        self.assertIn(f'?item={first}.0#candidate-evidence"', of_lone)
        self.assertIn("후보 버전 8.2.0,", of_text)
        self.assertIn(f'?item={second}.0#candidate-evidence"', of_text)
        updates = self.page(self.updates)
        self.assertIn(f'/updates?item={first}.0#candidate-evidence"', updates)
        self.assertIn(f'/updates?item={second}.0#candidate-evidence"', updates)
        self.assertNotIn(f'/updates?item={first}.1#candidate-evidence"', updates)
        # A later check of the package named with the lone surrogate alone finds nothing: only
        # that location loses its candidate.
        self.check(self.nothing(), targets=["\udc80x"], changed_count=0)
        of_lone, of_text = cells()
        self.assertEqual(of_lone, '<span class="quiet">후보 없음</span>')
        self.assertIn(f'?item={second}.0#candidate-evidence"', of_text)

    def test_a_look_reads_only_the_reports_whose_candidates_it_shows(self):
        self.check(targets=None)
        for _ in range(12):
            self.check(self.nothing(), targets=["other"], changed_count=0)
            self.check(package_lock_sha256="4" * 64)  # a preview of other files
            history.record("scan", self.project, self.report)
        for view in (self.packages, self.updates):
            with (
                mock.patch.object(history, "get_run", wraps=history.get_run) as read,
                mock.patch.object(history, "list_runs", wraps=history.list_runs) as listed,
            ):
                self.assertIn("1.2.0", self.page(view))
            # One stored report, of the check of everything whose row is shown, out of 37 runs;
            # and no list of all the project's runs.
            self.assertEqual(read.call_count, 1, view)
            for call in listed.call_args_list:
                self.assertEqual(call.args[1:2], (1,), call)

    def test_a_history_file_of_the_previous_format_shows_the_same_candidates(self):
        self.check(targets=None)
        self.check(self.nothing(), targets=["other"], changed_count=0)
        expected = self.cells()
        self.assertIn("후보 버전 1.2.0,", expected["node_modules/example"])
        with contextlib.closing(sqlite3.connect(self.db)) as connection:
            connection.execute("DROP TABLE previews")  # as the version 2 code left the file
            connection.execute("DROP INDEX runs_by_kind")
            connection.execute("PRAGMA user_version = 2")
            connection.commit()
        before = self.db.read_bytes()
        self.assertEqual(self.cells(), expected)
        self.assertIn('class="stack candidates"', self.page(self.updates))
        self.assertEqual(self.db.read_bytes(), before)  # looking does not upgrade the file

    def test_the_tabs_count_what_the_search_leaves_and_keep_it(self):
        url = f"{self.packages}"

        def listed(html):
            return [row[0] for row in package_rows(html)]

        def tabs(html):
            nav = re.search(r'<nav class="filter-tabs" aria-label="패키지 목록 거르기">(.*?)</nav>',
                            html, re.S)[1]  # fmt: skip
            return re.findall(r'<(a href="[^"]*"(?: aria-current="true")?|span class="filter-off"'
                              r'(?: aria-current="true")?)>'
                              r'([^<]*) <span class="filter-count">(\d+)</span>', nav)  # fmt: skip

        # Nothing checked: everything is unchecked, which is not 0 candidates.
        html = self.page(self.packages)
        self.assertEqual(tabs(html), [
            (f'a href="{url}" aria-current="true"', "전체", "3"),
            ('span class="filter-off"', "후보", "0"),
            (f'a href="{url}?show=unchecked"', "미리보기 전", "3"),
            ('span class="filter-off"', "후보 없음", "0")])  # fmt: skip
        self.assertIn("미리보기 전은 후보 0개와 다릅니다.", html)
        # A tab the address names that holds nothing, and the old filter, list everything.
        for address in ("?show=candidates", "?only=1", "?only=0"):
            self.assertEqual(
                listed(self.page(self.packages + address)), ["example", "inner", "other"]
            )
        run = self.check(targets=None)  # a check of everything: example has a candidate
        # The counts are of what the search and the kind leave, and each tab keeps both and
        # the open candidate.
        html = self.page(f"{self.packages}?q=e&scope=direct")
        item = f"&amp;item={run}.0"
        self.assertEqual(tabs(html), [
            (f'a href="{url}?q=e&amp;scope=direct{item}" aria-current="true"', "전체", "2"),
            (f'a href="{url}?q=e&amp;scope=direct&amp;show=candidates{item}"', "후보", "1"),
            ('span class="filter-off"', "미리보기 전", "0"),
            (f'a href="{url}?q=e&amp;scope=direct&amp;show=none{item}"', "후보 없음", "1")])  # fmt: skip
        self.assertEqual(listed(html), ["example", "other"])
        self.assertNotIn('name="show"', html)
        self.assertIn(f'검색 결과 <strong>2개</strong>. <a href="{url}">필터 초기화</a>', html)
        # A tab narrows the list; a new search keeps the tab, and a pick keeps all three.
        on = self.page(f"{self.packages}?q=e&scope=direct&show=candidates")
        self.assertIn(
            f'<a href="{url}?q=e&amp;scope=direct&amp;show=candidates{item}" aria-current="true">후보',
            on,
        )
        self.assertIn('<input type="hidden" name="show" value="candidates">', on)
        self.assertIn('name="q" maxlength="214" value="e"', on)
        self.assertIn('<option value="direct" selected>직접</option>', on)
        self.assertIn(f'검색 결과 <strong>1개</strong>. <a href="{url}">필터 초기화</a>', on)
        self.assertEqual(listed(on), ["example"])
        self.assertIn(f'href="{url}?q=e&amp;scope=direct&amp;show=candidates&amp;item={run}.0'
                      '#candidate-evidence"', on)  # fmt: skip
        self.assertEqual(listed(self.page(f"{self.packages}?show=none")), ["inner", "other"])
        self.assertEqual(
            listed(self.page(f"{self.packages}?show=all")), ["example", "inner", "other"]
        )
        self.assertIn("조건에 맞는 패키지가 없습니다.", self.page(f"{self.packages}?q=missing"))
        # A check of everything that found nothing: 0 is known, and the list is whole.
        self.check(self.nothing(), targets=None, changed_count=0)
        html = self.page(f"{self.packages}?show=candidates")
        self.assertIn("바뀌는 항목이 없었습니다. 후보 0개입니다.", html)
        self.assertNotIn("미리보기 전은 후보 0개와 다릅니다.", html)
        self.assertEqual(listed(html), ["example", "inner", "other"])
        for address in ("?show=evil", "?show=", "?show=none&show=none", "?show=none&show=all"):
            self.assertEqual(self.get(self.packages + address).status_code, 400, address)

    def test_candidate_strings_stay_inert(self):
        from markupsafe import escape

        for text in EscapeTests.STRINGS:
            with self.subTest(text=text):
                row = self.report["results"][0]
                for key in ("package", "before_version", "after_version", "detail"):
                    row[key] = text
                row["evidence"] = [text]
                self.check(targets=[text])
                packages, updates = self.page(self.packages), self.page(self.updates)
                for html in (packages, updates):
                    EscapeTests.check(self, html)
                shown = escape(_clean(text))
                self.assertIn(
                    f"후보 버전 {shown}, 검사 근거 열기</span>", packages
                )  # the candidate
                self.assertIn(f'<th scope="row">{shown}<span class="where">', updates)
                self.assertIn(f"<li>{shown}</li>", updates)
                self.assertIn(f", {shown})", updates)  # the check's target


class SecurityTests(DashboardFixture):
    URLS = ("/", "/?manage=1", "/model", "/static/style.css", "/static/overview.css",
            "/static/app.js", "/static/icon.svg", "/projects/1", "/projects/1/updates",
            "/projects/1/history", "/runs/1")  # fmt: skip

    def assert_headers(self, response):
        headers = response.headers
        self.assertEqual(headers["content-security-policy"], self.app.CSP)
        # Each source list is 'self' or 'none' alone: no inline script or style, no eval, no
        # other host. script-src 'self' is the one file of static/, font-src 'self' the two
        # bundled fonts.
        self.assertEqual(sorted(headers["content-security-policy"].split("; ")), [
            "base-uri 'none'", "default-src 'none'", "font-src 'self'", "form-action 'self'",
            "frame-ancestors 'none'", "img-src 'self'", "script-src 'self'",
            "style-src 'self'"])  # fmt: skip
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(headers["referrer-policy"], "same-origin")
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertNotIn("server", headers)

    def test_host_must_be_this_address_and_port(self):
        for host in (f"127.0.0.1:{PORT + 1}", "127.0.0.1", f"localhost:{PORT}",
                     f"evil.test:{PORT}", ""):  # fmt: skip
            for url in ("/", "/static/style.css", "/"):
                with self.subTest(host=host, url=url):
                    response = self.client.get(url, headers={"host": host},
                                               follow_redirects=False)  # fmt: skip
                    self.assertEqual(response.status_code, 400)
                    self.assert_headers(response)
                    self.assertNotIn("set-cookie", response.headers)

    def test_every_page_opens_at_the_root_of_the_address_without_a_secret_or_a_cookie(self):
        self.record(self.scan_with(0.1))
        for url in self.URLS:
            response = self.get(url)
            self.assertEqual(response.status_code, 200, url)
            self.assert_headers(response)
            self.assertNotIn("set-cookie", response.headers)
            self.assertEqual(len(self.client.cookies), 0)
        html = self.page("/")
        self.assertIn('<link rel="stylesheet" href="/static/style.css">', html)
        self.assertIn('href="/projects/1"', html)
        self.assertIn('href="/static/overview.css"', html)
        manage = self.page("/?manage=1")
        self.assertIn('<form method="post" action="/projects/pick">', manage)
        # The form's value is in the hidden field of each form and nowhere else on a page.
        field = f'<input type="hidden" name="csrf" value="{CSRF}">'
        for page in (html, manage, self.page("/projects/1")):
            self.assertEqual(page.count(CSRF), page.count(field))
            self.assertEqual(page.count(field), len(re.findall(r'<form [^>]*method="post"', page)))
        # A cookie is neither needed nor read.
        self.assertEqual(self.client.get("/", headers={"cookie": "x=1"}).status_code, 200)

    def test_no_login_and_no_address_of_an_earlier_kind_is_served(self):
        # Nothing answers under a prefix: the address of a dashboard before this one (a session
        # in its path) is not found like any other, and nothing redirects.
        for url in ("/login", f"/login?token={CSRF}", f"/s/{CSRF}/", f"/s/{CSRF}/model",
                    f"/s/{CSRF}/static/style.css", f"/{CSRF}/", "/s/", "/s", "/favicon.ico",
                    "/model/", "/projects/1/", "/static/", f"/static/{CSRF}/style.css",
                    "/control"):  # fmt: skip
            with self.subTest(url=url):
                response = self.client.get(url, follow_redirects=False)
                self.assertEqual((response.status_code, response.text), (404, "Not Found"))
                self.assert_headers(response)
                self.assertNotIn("location", response.headers)
                self.assertNotIn("set-cookie", response.headers)

    def test_another_site_can_link_to_a_page_and_can_load_or_probe_nothing(self):
        self.record(self.scan_with(0.1))
        link = {"sec-fetch-mode": "navigate", "sec-fetch-dest": "document"}
        # What a page of another site makes a browser ask for: a script, a frame, a fetch, an
        # image, and a request that says no more than its site.
        loads = ({"sec-fetch-mode": "no-cors", "sec-fetch-dest": "script"},
                 {"sec-fetch-mode": "navigate", "sec-fetch-dest": "iframe"},
                 {"sec-fetch-mode": "cors", "sec-fetch-dest": "empty"},
                 {"sec-fetch-mode": "no-cors", "sec-fetch-dest": "image"},
                 {"sec-fetch-mode": "navigate"}, {"sec-fetch-dest": "document"}, {})  # fmt: skip
        # Another port of 127.0.0.1 is the same site and another origin.
        for site in ("cross-site", "same-site", "Cross-Site", "other", ""):
            # A page that is there and one that is not get the same answer: nothing to probe.
            for url in (*self.URLS, "/runs/999", "/nothing"):
                for load in loads:
                    with self.subTest(site=site, url=url, load=load):
                        response = self.client.get(url, headers={"sec-fetch-site": site, **load})
                        self.assertEqual((response.status_code, response.text),
                                         (403, self.app.OTHER_SITE))  # fmt: skip
                        self.assert_headers(response)
            headers = {"sec-fetch-site": site, **link}
            self.assertEqual(self.client.head("/", headers=headers).status_code, 403)
            # One header that is not the dashboard's own is enough, whatever a second one says.
            both = [("sec-fetch-site", "same-origin"), ("sec-fetch-site", site)]
            self.assertEqual(self.client.get("/", headers=both).status_code, 403)
            # A link on that site to a page here opens it: the address is one to keep.
            for url in ("/", "/model", "/projects/1"):
                self.assertEqual(self.client.get(url, headers=headers).status_code, 200, url)
        # The dashboard's own pages and files, the address bar or a reload, and a client that is
        # no browser (it says nothing).
        own = ({"sec-fetch-site": "same-origin", "sec-fetch-mode": "no-cors",
                "sec-fetch-dest": "style"}, {"sec-fetch-site": "SAME-ORIGIN"},
               {"sec-fetch-site": "none", **link}, link, {})  # fmt: skip
        for headers in own:
            for url in self.URLS:
                with self.subTest(headers=headers, url=url):
                    self.assertEqual(self.client.get(url, headers=headers).status_code, 200)

    def test_port_80_is_also_taken_as_a_browser_writes_it(self):
        from starlette.testclient import TestClient

        # No port is bound: the app is asked in this process.
        client = TestClient(self.app.build_app(80, CSRF), base_url="http://127.0.0.1")
        self.addCleanup(client.close)
        self.dialog(str(self.project))

        def post(host, origin):
            return client.post("/projects/pick", data={"csrf": CSRF},
                               headers={"host": host, "origin": origin},
                               follow_redirects=False)  # fmt: skip

        for host in ("127.0.0.1", "127.0.0.1:80"):
            with self.subTest(host=host):
                self.assertEqual(client.get("/", headers={"host": host}).status_code, 200)
                self.assertEqual(post(host, f"http://{host}").status_code, 303)
        for host in ("127.0.0.1:8080", "127.0.0.1:", "localhost", "localhost:80", "evil.test"):
            with self.subTest(host=host):
                self.assertEqual(client.get("/", headers={"host": host}).status_code, 400)
                self.assertEqual(post("127.0.0.1", f"http://{host}").status_code, 403)
        self.assertEqual(post("127.0.0.1", "https://127.0.0.1").status_code, 403)
        # Any other port is written in full (test_host_must_be_this_address_and_port).
        self.assertEqual(self.client.get("/", headers={"host": "127.0.0.1"}).status_code, 400)
        refused = self.send_pick(origin="http://127.0.0.1")
        self.assertEqual(refused.status_code, 403)

    def test_a_form_of_a_page_opened_before_a_restart_is_refused_until_it_is_loaded_again(self):
        from starlette.testclient import TestClient

        kept = self.form_csrf()  # a tab left open
        self.dialog(str(self.project))
        # The next start: the same address, and a value of its own (serve() makes one).
        restarted = TestClient(self.app.build_app(PORT, "the-value-of-the-next-start"),
                               base_url=BASE)  # fmt: skip
        self.addCleanup(restarted.close)

        def post(value):
            return restarted.post("/projects/pick", data={"csrf": value},
                                  headers={"origin": BASE, "sec-fetch-site": "same-origin"},
                                  follow_redirects=False)  # fmt: skip

        refused = post(kept)
        self.assertEqual((refused.status_code, refused.text), (403, self.app.FORM_REFUSED))
        self.assert_headers(refused)
        self.assertEqual(history.list_projects(), [])
        # The same address, loaded again, has the form that is taken.
        fresh = re.search(r'name="csrf" value="([^"]+)"', restarted.get("/").text)[1]
        self.assertNotEqual(fresh, kept)
        self.assertEqual(post(fresh).status_code, 303)
        self.assertEqual(len(history.list_projects()), 1)

    def test_npm_links_send_no_referrer(self):
        # A link out says nothing of the page it is on.
        run = self.record(self.scan_with(0.9))
        html = self.page(f"/runs/{run}")
        links = re.findall(r"<a [^>]*>", html)
        npm = [link for link in links if "https://www.npmjs.com/package/" in link]
        self.assertTrue(npm)
        for link in npm:
            self.assertIn('rel="noreferrer noopener"', link)

    def test_post_needs_the_form_csrf_and_origin(self):
        form, choose = self.form_csrf(), self.dialog(str(self.project))
        self.assertEqual(form, CSRF)
        refused = {
            "no form csrf": self.send_pick(None),
            "wrong form csrf": self.send_pick(form[:-1] + ("A" if form[-1] != "A" else "B")),
            "empty form csrf": self.send_pick(""),
            "no origin": self.send_pick(form, origin=None),
            "other port": self.send_pick(form, origin=f"http://127.0.0.1:{PORT + 1}"),
            "other host": self.send_pick(form, origin=f"http://localhost:{PORT}"),
            "null origin": self.send_pick(form, origin="null"),
            "https origin": self.send_pick(form, origin=f"https://127.0.0.1:{PORT}"),
        }
        for label, response in refused.items():
            with self.subTest(label):
                self.assertEqual(response.status_code, 403)
                self.assert_headers(response)
                self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(refused["wrong form csrf"].text, self.app.FORM_REFUSED)
        self.assertEqual(history.list_projects(), [])
        # GET never changes state: the form's route takes POST only.
        self.assertEqual(self.get("/projects/pick").status_code, 405)
        self.assertEqual(choose.call_count, 0)  # no refused request opens the dialog

    def test_a_post_that_the_browser_says_comes_from_elsewhere_is_refused(self):
        form = self.form_csrf()
        self.dialog(str(self.project))

        def post(*sites):
            """The registration form, sent with these Sec-Fetch-Site headers and its Origin."""
            headers = [("origin", BASE), *(("sec-fetch-site", site) for site in sites)]
            return self.client.post("/projects/pick", data={"csrf": form},
                                    headers=headers, follow_redirects=False)  # fmt: skip

        # Another port of 127.0.0.1 is the same site and another origin. One header that is
        # not the dashboard's own is enough, whatever a second one says.
        for sites in (("cross-site",), ("same-site",), ("Cross-Site",), ("",), ("other",),
                      ("same-origin", "cross-site"), ("cross-site", "none")):  # fmt: skip
            with self.subTest(sites=sites):
                response = post(*sites)
                self.assertEqual(response.status_code, 403)
                self.assert_headers(response)
                self.assertEqual(history.list_projects(), [])
        # The dashboard's own page, the user (a reload), and a browser that says nothing, which
        # is left to the Origin check.
        for number, sites in enumerate((("same-origin",), ("none",), ("SAME-ORIGIN",), ())):
            with self.subTest(sites=sites):
                response = post(*sites)
                # The first of these registers the project; the others find it registered.
                self.assertEqual((response.status_code, response.headers["location"]),
                                 (303, ("/projects/1" if number else "/")))  # fmt: skip
        # The header does not stand in for the Origin.
        refused = self.client.post("/projects/pick", data={"csrf": form},
                                   headers={"sec-fetch-site": "same-origin"})  # fmt: skip
        self.assertEqual(refused.status_code, 403)
        # What links here from another site is a GET, never a form.
        linked = self.client.post("/projects/pick", data={"csrf": form},
                                  headers={"origin": BASE, "sec-fetch-site": "cross-site",
                                           "sec-fetch-mode": "navigate",
                                           "sec-fetch-dest": "document"})  # fmt: skip
        self.assertEqual(linked.status_code, 403)

    def test_large_or_odd_bodies_are_refused(self):
        form, choose = self.form_csrf(), self.dialog(str(self.project))
        big = self.send_pick(form, other="a" * (self.app.MAX_BODY + 1))
        self.assertEqual(big.status_code, 413)
        self.assert_headers(big)
        fields = "&".join(f"f{i}=1" for i in range(self.app.MAX_FIELDS + 1))
        response = self.client.post("/projects/pick", content=f"csrf={form}&{fields}",
                                    headers={"origin": BASE, "content-type":
                                             "application/x-www-form-urlencoded"})  # fmt: skip
        self.assertEqual(response.status_code, 400)
        response = self.client.post("/projects/pick", content=json.dumps({"csrf": form}),
                                    headers={"origin": BASE, "content-type": "application/json"})  # fmt: skip
        self.assertEqual(response.status_code, 415)
        self.assertEqual((history.list_projects(), choose.call_count), ([], 0))

    def test_server_settings_and_the_address_line(self):
        from depbee.dashboard import app

        started = {}

        class Server:
            def __init__(self, config):
                started["config"] = config

            def run(self, sockets):
                (sock,) = sockets
                started["bound"] = sock.getsockname()

        out = io.StringIO()
        with (
            mock.patch.object(app.uvicorn, "Server", Server),
            mock.patch.object(app, "build_app", wraps=app.build_app) as built,
            contextlib.redirect_stdout(out),
        ):
            app.serve(0)
            app.serve(0)  # the next start
        config, (host, port) = started["config"], started["bound"]
        self.assertEqual((host, config.host, config.port), ("127.0.0.1", "127.0.0.1", port))
        self.assertNotEqual(port, 0)
        self.assertEqual((config.access_log, config.server_header, config.proxy_headers,
                          config.log_level, config.lifespan, config.ws),
                         (False, False, False, "warning", "off", "none"))  # fmt: skip
        # The address is the port's and nothing else: the same at every start on that port.
        lines = out.getvalue().splitlines()
        self.assertRegex(lines[0], r"\Ahttp://127\.0\.0\.1:[1-9]\d*/\Z")
        self.assertEqual(lines[1:], [app.STARTED, f"http://127.0.0.1:{port}/", app.STARTED])
        # Each start has its own value for its forms, which no line holds.
        first, second = (call.args[1] for call in built.call_args_list)
        self.assertNotEqual(first, second)
        for value in (first, second):
            self.assertRegex(value, r"\A[A-Za-z0-9_-]{43}\Z")
            self.assertNotIn(value, out.getvalue())
        code, err = None, io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["dashboard", "--port", "70000"])
        self.assertEqual(code, 2)
        self.assertIn("--port must be between 0 and 65535", err.getvalue())

    def test_a_port_that_cannot_be_bound_says_what_to_do_and_nothing_else_is_tried(self):
        from depbee.dashboard import app

        def advised(error, port):
            self.assertIn(f"127.0.0.1:{port} could not be opened for the dashboard (", error)
            self.assertIn("no other port was tried", error)
            self.assertIn("depbee dashboard --status", error)
            self.assertTrue(error.endswith("depbee dashboard --port PORT"), error)
            self.assertTrue(error.isascii() and "\n" not in error, error)

        Server = self.fake_server(AssertionError("served although the port was not bound"))
        with socket.create_server(("127.0.0.1", 0)) as taken:  # another program's port
            port = taken.getsockname()[1]
            out, err = io.StringIO(), io.StringIO()
            with (
                mock.patch.object(app.uvicorn, "Server", Server),
                contextlib.redirect_stdout(out),
                contextlib.redirect_stderr(err),
            ):
                code = main(["dashboard", "--port", str(port)])
            self.assertEqual((code, out.getvalue()), (2, ""))  # no address was printed
            self.assertNotIn("Traceback", err.getvalue())
            advised(json.loads(err.getvalue())["error"], port)
            self.assertEqual(Server.bound, [])
            # What holds the port was left as it was: it still takes a connection.
            socket.create_connection(("127.0.0.1", port), timeout=5).close()
            taken.accept()[0].close()
        # A port the system keeps reserved has no owner to see, and Windows names either case
        # either way (10013 WSAEACCES, 10048 WSAEADDRINUSE): one answer for every refusal.
        for number in (errno.EADDRINUSE, errno.EACCES, 10013, 10048, None):
            with self.subTest(errno=number):
                refusal = OSError(number, "synthetic refusal with C:\\private text")
                with (
                    mock.patch.object(app.socket, "create_server", side_effect=refusal) as bind,
                    self.assertRaises(GuardError) as caught,
                ):
                    app.serve(18765)
                advised(str(caught.exception), 18765)
                self.assertNotIn("private", str(caught.exception))
                bind.assert_called_once_with(("127.0.0.1", 18765))  # no other port

    def fake_server(self, error):
        """A uvicorn.Server whose run() raises error; the sockets it got are kept in .bound."""

        class Server:
            bound = []

            def __init__(self, config):
                pass

            def run(self, sockets):
                Server.bound.extend(sockets)
                raise error

        return Server

    def test_start_address_opens_the_overview_and_keeps_management_available(self):
        from depbee.dashboard import app

        project_id = history.register_project(self.project)
        second = self.root / "second"
        second.mkdir()
        for only_one in (True, False):
            if not only_one:
                history.register_project(second)
            out = io.StringIO()
            with (
                mock.patch.object(app.uvicorn, "Server", self.fake_server(KeyboardInterrupt())),
                contextlib.redirect_stdout(out),
            ):
                app.serve(0)
            url = out.getvalue().splitlines()[0]
            self.assertTrue(url.endswith("/"))
        self.assertIn("프로젝트 등록", self.page("/?manage=1"))
        self.assertIn('<a class="tab manage" href="/?manage=1">프로젝트 관리</a>',
                      self.page(f"/projects/{project_id}"))  # fmt: skip

    def test_start_address_falls_back_to_project_list_on_unreadable_history(self):
        from depbee.dashboard import app

        self.db.write_bytes(b"not a database")
        out = io.StringIO()
        with (
            mock.patch.object(app.uvicorn, "Server", self.fake_server(KeyboardInterrupt())),
            contextlib.redirect_stdout(out),
        ):
            app.serve(0)
        self.assertTrue(out.getvalue().splitlines()[0].endswith("/"))

    def test_ctrl_c_ends_the_dashboard_with_one_line_and_exit_code_0(self):
        from depbee.dashboard import app

        # uvicorn's run() ends with KeyboardInterrupt after a graceful Ctrl+C shutdown.
        Server = self.fake_server(KeyboardInterrupt())
        out = io.StringIO()
        with mock.patch.object(app.uvicorn, "Server", Server), contextlib.redirect_stdout(out):
            try:  # without the catch, KeyboardInterrupt would stop unittest itself
                app.serve(0)
                code = main(["dashboard", "--port", "0"])
            except KeyboardInterrupt:
                self.fail("Ctrl+C reached the caller of the dashboard")
        self.assertEqual(code, 0)
        lines = out.getvalue().splitlines()
        stopped = "대시보드를 종료했습니다. 위 주소는 더 이상 열리지 않습니다."
        self.assertEqual((len(lines), lines[2], lines[5]), (6, stopped, stopped))
        self.assertEqual(len(Server.bound), 2)
        self.assertTrue(all(sock.fileno() == -1 for sock in Server.bound))  # closed

    def test_other_server_errors_still_raise(self):
        from depbee.dashboard import app

        Server = self.fake_server(OSError("synthetic server error"))
        out = io.StringIO()
        with mock.patch.object(app.uvicorn, "Server", Server), contextlib.redirect_stdout(out):
            with self.assertRaisesRegex(OSError, "synthetic server error"):
                app.serve(0)
        self.assertEqual(len(out.getvalue().splitlines()), 2)  # the start lines only
        (sock,) = Server.bound
        self.assertEqual(sock.fileno(), -1)

    def test_an_unexpected_error_is_a_fixed_500_with_the_headers(self):
        from starlette.testclient import TestClient

        client = TestClient(self.app.build_app(PORT, CSRF), base_url=BASE,
                            raise_server_exceptions=False)  # fmt: skip
        self.addCleanup(client.close)
        marker = "C:\\private\\folder\\history.sqlite3 synthetic-secret-0123456789"
        with mock.patch.object(history, "list_projects", side_effect=RuntimeError(marker)):
            response = client.get("/")
        self.assertEqual(response.status_code, 500)
        self.assert_headers(response)
        self.assertEqual(
            response.text, "요청을 처리하지 못했습니다(이력 데이터베이스나 파일을 읽지 못함)."
        )
        exposed = response.text + "".join(f"{k}: {v}" for k, v in response.headers.items())
        for secret in (marker, "private", "synthetic-secret", "RuntimeError", CSRF):
            self.assertNotIn(secret, exposed)


class EscapeTests(DashboardFixture):
    STRINGS = [*HOSTILE, '"><script>alert(1)</script>', "' onmouseover='x", "javascript:alert(1)",
               "\u202eexe.js", "zero\u200cwidth", "\x1b[31mred", "lone\udc80surrogate"]  # fmt: skip

    def test_lockfile_strings_in_the_dependency_table_stay_inert(self):
        # The project keeps its real path, so /projects/1 really reads and renders the lockfile.
        from markupsafe import escape

        history.register_project(self.project)
        shown = []
        for index, text in enumerate(self.STRINGS):
            named, nested = f"node_modules/h{index}", f"node_modules/h{index}/node_modules/{text}"
            self.new["packages"][named] = {**package(), "name": text}
            self.new["packages"][nested] = package("2.0.0")  # name inferred from the location
            shown += [(text, named), (text, nested)]
        self.save_locks()
        html = self.page("/projects/1")
        self.assertIn(f"직접 0개, 중첩 {len(shown) + 1}개.", html)
        for name, location in shown:
            with self.subTest(name=name):
                # Present, as _clean then HTML escaping made it: the row was really rendered.
                self.assertIn(
                    f'<th scope="row">{escape(_clean(name))}<span class="row-tags">', html
                )
                self.assertIn(f'<span class="where">{escape(_clean(location))}</span></th>', html)
        self.check(html)

    def test_report_and_path_strings_stay_inert(self):
        report = self.scan_with(
            0.9, known_malicious=KnownList((ADVISORY,)), rules=Rules((rule("hit"),))
        )
        item = report["results"][0]
        item["evidence"] = list(self.STRINGS)
        item["rules"]["checks"][0]["locations"] = [{"file": s, "line": None} for s in self.STRINGS]
        for text in self.STRINGS:
            with self.subTest(text=text):
                for key in ("package", "location", "detail"):
                    item[key] = text
                run = self.record(report)
                sql = "UPDATE projects SET path = ?"
                with contextlib.closing(sqlite3.connect(self.db)) as connection, connection:
                    connection.execute(sql, (history._text(text),))
                for url in ("/", "/projects/1", f"/runs/{run}"):
                    self.check(self.page(url))

    def check(self, html):
        assert_one_script(self, html)
        self.assertNotIn("<img", html)
        self.assertNotIn("onmouseover='x", html)
        self.assertNotRegex(html, r'href="(?!/|#main"|#apply"|https://www\.npmjs\.com/package/)')
        # A hostile string is text wherever it lands (a title, an aria-label), never an address.
        held = [(tag, name) for tag, attrs in Elements(html).found for name, value in attrs.items()
                if name in ("href", "src", "action", "formaction") and "javascript:" in value]  # fmt: skip
        self.assertEqual(held, [])
        for character in "\u202e\u200c\x1b\r":
            self.assertNotIn(character, html)
        self.assertTrue(all(c.isprintable() or c in "\n" for c in html))

    def test_hostile_strings_are_shown_as_visible_escapes(self):
        report = self.scan_with(0.9)
        report["results"][0]["package"] = "\u202eexe.js\udc80"
        html = self.page(f"/runs/{self.record(report)}")
        self.assertIn("\\u202eexe.js\\udc80", html)

    def test_npm_links_use_the_fixed_prefix_and_the_encoded_name(self):
        link = self.app.npm_link
        self.assertEqual(link("lodash"), "https://www.npmjs.com/package/lodash")
        self.assertEqual(link("@scope/name"), "https://www.npmjs.com/package/@scope/name")
        self.assertEqual(
            link("@scope/na(me)!"), "https://www.npmjs.com/package/@scope/na%28me%29%21"
        )
        for name in ("javascript:alert(1)", "../x", "a/b", "", "a b", "x" * 215, None, "\u202ea"):
            self.assertIsNone(link(name), name)


class RegistrationTests(DashboardFixture):
    """A project is registered by the folder the desktop's dialog answers, checked first, and by
    nothing a request carries (what each answer of the dialog does: test_dashboard_picker)."""

    def test_no_request_carries_a_path_to_register(self):
        other = self.root / "other"
        other.mkdir()
        self.write(other / "package-lock.json", self.new)
        choose = self.dialog(str(self.project))
        # The address a typed path was sent to is no address any more, with a path or without.
        for fields in ({"csrf": CSRF, "path": str(other)}, {"csrf": CSRF}):
            response = self.client.post("/projects", data=fields, headers={"origin": BASE},
                                        follow_redirects=False)  # fmt: skip
            self.assertEqual(response.status_code, 404)
        self.assertEqual(self.get("/projects").status_code, 404)
        self.assertEqual((choose.call_count, self.db.exists()), (0, False))
        # The dialog's form registers the folder the dialog answers, whatever path a request
        # holds beside its csrf value.
        response = self.send_pick(path=str(other), folder=str(other))
        self.assertEqual((response.status_code, response.headers["location"]), (303, "/"))
        choose.assert_called_once_with()
        self.assertEqual([project["path"] for project in history.list_projects()],
                         [str(self.project.resolve())])  # fmt: skip
        # No page has a field for a path, a file or a folder, or names a path to type.
        pages = [self.page(url) for url in ("/", "/?manage=1", "/projects/1",
                                            "/projects/1/updates", "/projects/1/history")]  # fmt: skip
        for html in pages:
            for absent in ('name="path"', 'type="file"', "webkitdirectory", "multipart",
                           'action="/projects"', "직접 입력", "절대 경로"):  # fmt: skip
                self.assertNotIn(absent, html)
        # Project management names the two things a project's pages run, and their CLI commands.
        projects = pages[1]
        self.assertIn('등록한 뒤 프로젝트 화면에서 "전체 업데이트 미리보기(update)"나 "lockfile 변경 '
                      '검사(scan)"를 실행합니다.', projects)  # fmt: skip
        self.assertIn('기록된 실행이 없습니다. 프로젝트 화면에서 "전체 업데이트 미리보기(update)"나',
                      projects)  # fmt: skip
        self.assertIn("CLI로 실행한 depbee update·depbee scan도 기록됩니다.", projects)

    def test_refused_folders(self):
        problem = self.app._registration_problem
        cases = [
            ("project", "absolute"),
            (os.path.join("..", "project"), "absolute"),
            (str(self.root / "missing"), "folder"),
            (str(self.head), "folder"),
            (str(self.root), "lockfile"),
            ("", "local"),
            ("\\\\server\\share\\project", "local"),
            ("//server/share/project", "local"),
            ("\\\\.\\pipe\\x", "local"),
            ("\\\\?\\C:\\project", "local"),
            ("/dev/stdin", "local"),
            ("C:/" + "a" * self.app.MAX_PATH, "long"),
        ]
        if os.name == "nt":
            cases += [(str(self.root / "CON"), "local"),
                      (str(self.project / "nul.txt"), "local"),
                      ("\\project", "absolute"),
                      ("C:project", "absolute")]  # fmt: skip
        (self.root / "lock-dir" / "package-lock.json").mkdir(parents=True)
        cases.append((str(self.root / "lock-dir"), "lockfile"))
        for path, key in cases:
            with self.subTest(path=path[:40]):
                self.assertEqual(problem(path), key)
        self.assertIsNone(problem(str(self.project)))
        # Each refusal has its own words, about the folder that was chosen: nothing to type.
        self.assertEqual(set(self.app.REGISTER_ERRORS),
                         {key for _, key in cases} | {"link", "unreadable"})  # fmt: skip
        for message in (*self.app.REGISTER_ERRORS.values(), *self.app.PICK_ERRORS.values()):
            self.assertNotIn("입력", message)
        self.assertFalse(self.db.exists())

    def test_links_to_shares_or_devices_are_refused(self):
        # The MCP boundary's link walk (mcp._unlinked); a real link to a share needs rights.
        link = self.root / "share-link"
        for target in ("\\\\server\\share\\project", "//server/share/project", "/dev/stdin"):
            lstat, readlink, follow = test_mcp.ResponseTests.links(self, {link: target})
            with self.subTest(target=target), mock.patch("os.lstat", lstat), \
                    mock.patch("os.readlink", readlink), \
                    mock.patch("pathlib.Path.stat", autospec=True, side_effect=follow):  # fmt: skip
                problem = self.app._registration_problem(str(link))
            self.assertEqual(problem, "link")
        self.dialog(str(self.project))
        with mock.patch.object(self.app, "_registration_problem", return_value="link"):
            response = self.send_pick()
        self.assertEqual(response.status_code, 400)
        self.assertIn(self.app.REGISTER_ERRORS["link"], response.text)
        self.assertEqual(history.list_projects(), [])


def applied_document(outcome="applied", reason=None, mode="lockfile", **extra):
    """A synthetic apply document in the shape service.apply_preview returns."""
    files = [{"path": "package-lock.json", "sha256": "1" * 64, "new_sha256": "2" * 64}]
    document = {
        "mode": mode, "outcome": outcome, "reason": reason, "error": None, "blocked": [],
        "confirmation_required": [], "confirmed": True,
        "files": files if outcome in ("applied", "failed") else [],
        "backup": BACKUP if outcome in ("applied", "failed") else None,
        "npm_version": None, "npm_ci_exit_code": None, "notices": [],
    }  # fmt: skip
    return {**document, **extra}


BACKUP = "C:/synthetic/backups/20261117T000000Z-0123abcd"
FIXED_500 = "요청을 처리하지 못했습니다(이력 데이터베이스나 파일을 읽지 못함)."
NO_HISTORY = b"synthetic bytes that are no history database"  # in place of the history file


def main_of(html):
    """The main element of a page: everything but the rail and the footer."""
    return re.search(r'<main id="main">.*</main>', html, re.S).group()


class ScreenFixture(DashboardFixture):
    """Update check and apply screens with service.preview_files and apply_preview replaced."""

    def setUp(self):
        super().setUp()
        self.project_id = history.register_project(self.project)
        self.report = self.scan_with(0.1)  # not flagged; known malicious list not connected
        self.npmrc, self.targets = False, None
        self.previewed, self.applied = [], []
        self.document = applied_document()
        self.preview_files = self.patch_service("preview_files", self.fake_preview)
        self.apply_preview = self.patch_service("apply_preview", self.fake_apply)

    def patch_service(self, name, function):
        patcher = mock.patch.object(service, name, side_effect=function)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def fake_preview(self, project, names, **options):
        self.previewed.append((project, names, options))
        preview = {**PREVIEW, "targets": self.targets or names or None,
                   "changed_count": len(self.report["results"]),
                   "project_npmrc_ignored": self.npmrc}  # fmt: skip
        return {"preview": preview, "report": self.report}, b"new package.json", b"new lockfile"

    def fake_apply(self, project, result, new_package, new_lock, *, mode, confirm=False):
        self.applied.append({"project": project, "result": result, "new_package": new_package,
                             "new_lock": new_lock, "mode": mode, "confirm": confirm})  # fmt: skip
        _, required = service.update_gate(result["report"])
        return {**self.document, "mode": mode, "confirmed": confirm,
                "confirmation_required": required}  # fmt: skip

    def check(self, packages="", csrf=CSRF, origin=BASE, project_id=None):
        url = f"/projects/{project_id or self.project_id}/previews"
        headers = {} if origin is None else {"origin": origin}
        return self.client.post(url, data={"csrf": csrf, "packages": packages},
                                headers=headers, follow_redirects=False)  # fmt: skip

    def preview_id(self, packages=""):
        response = self.check(packages)
        self.assertEqual(response.status_code, 303, response.text)
        location = response.headers["location"]
        self.assertTrue(location.startswith("/previews/"), location)
        return location.rsplit("/", 1)[1]

    def apply(self, preview_id, mode="lockfile", confirm=True, csrf=CSRF, origin=BASE):
        data = {"csrf": csrf, "mode": mode, **({"confirm": "yes"} if confirm else {})}
        headers = {} if origin is None else {"origin": origin}
        return self.client.post(f"/previews/{preview_id}/apply", data=data, headers=headers,
                                follow_redirects=False)  # fmt: skip

    def assert_form(self, html, present):
        (self.assertIn if present else self.assertNotIn)(
            '<button type="submit" data-busy-label="반영 중…">고른 방식으로 프로젝트에 반영</button>', html
        )

    def assert_stopped(self, response, status, message):
        """A request that ran nothing: the fixed message on a page that still has the tabs, so
        there is a way on; it is not said to be a failed run."""
        self.assertEqual(response.status_code, status)
        self.assertIn(f'<p class="error">{message}</p>', response.text)
        self.assertIn(f'<a class="tab" href="/projects/{self.project_id}"', response.text)
        self.assertNotIn("이력에 기록하지 않았습니다.", response.text)

    def answer_errors(self):
        """Requests go through a client that answers with the app's own 500 instead of raising
        the exception in the test."""
        from starlette.testclient import TestClient

        self.client = TestClient(self.app.build_app(PORT, CSRF), base_url=BASE,
                                 raise_server_exceptions=False)  # fmt: skip
        self.addCleanup(self.client.close)

    def breaking(self, fake):
        """fake as a service function during whose run the history file stops being a history
        (damaged or replaced while the work runs): from then on no write and no read of the
        history succeeds."""

        def service_call(*args, **kwargs):
            self.db.write_bytes(NO_HISTORY)
            return fake(*args, **kwargs)

        return service_call

    def assert_fixed_500(self, response):
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.text, FIXED_500)

    def assert_recovered(self, response, status=200):
        """A page that says what a scan or an apply did, drawn without the history, and its
        main element without the line that says so. That line is a paragraph of the content,
        in view at every width and read like the rest of it, not the rail's title, which only
        the wide layout shows. The rail has the tab of the page's project alone, whose newest
        run is unknown in view and to a screen reader (never "not inspected", never a count of
        projects); the trail leads to that project, and nothing links a stored run."""
        html = response.text
        self.assertEqual(response.status_code, status, html)
        assert_one_script(self, html)
        said = f'<p class="warning">{self.app.RAIL_UNREAD}</p>\n'
        main = main_of(html)
        self.assertEqual((html.count(self.app.RAIL_UNREAD), main.count(said)), (1, 1))
        self.assertNotIn("rail-title", html)
        project = f"/projects/{self.project_id}"
        links = [attrs.get("href") for tag, attrs in Elements(main).found if tag == "a"]
        self.assertEqual(links[:2], [project, f"{project}/updates"])  # the trail
        # The rail's links: project management, then the projects, here the current one only.
        tabs = re.findall(r'<a class="tab[^>]*>.*?</a>', html, re.S)
        self.assertEqual(len(tabs), 2)
        _, current = Elements(tabs[1]).found[0]
        self.assertEqual((current["href"], current.get("aria-current")), (project, "true"))
        words = unescape(re.sub(r"<[^>]+>", "", tabs[1]))
        self.assertIn(self.project.name, words)
        self.assertIn(self.app.RAIL_UNREAD_STATE, words)  # the state a screen reader is told
        self.assertIn("알 수 없음", words)  # and the word in view
        for absent in ("조치 필요", "미검사", "실행 기록 없음", "/runs/"):
            self.assertNotIn(absent, html)
        return main.replace(said, "")


class UpdateCheckTests(ScreenFixture):
    def test_a_check_is_recorded_kept_in_memory_and_shown(self):
        from starlette.testclient import TestClient

        client = TestClient(self.app.build_app(PORT, CSRF, model_dir=Path("m"),
                                               cache_dir=Path("c")), base_url=BASE)  # fmt: skip
        self.addCleanup(client.close)
        self.client = client
        project_page = self.page(f"/projects/{self.project_id}")
        self.assertIn(f'action="/projects/{self.project_id}/previews"', project_page)
        preview_id = self.preview_id("example  other\tthird")
        ((project, names, options),) = self.previewed
        self.assertEqual(project, Path(str(self.project.resolve())))  # the registered path
        self.assertEqual(names, ["example", "other", "third"])
        self.assertEqual(options, {"model_dir": Path("m"), "cache_dir": Path("c"),
                                   "no_cache": False})  # fmt: skip
        (run,) = history.list_runs(self.project_id)
        stored = history.get_run(run["id"])
        self.assertEqual((stored["kind"], stored["report"]), ("update_preview", self.report))
        self.assertEqual(stored["preview"]["targets"], ["example", "other", "third"])
        html = self.page(f"/previews/{preview_id}")
        self.assertIn("<li>대상: example, other, third</li>", html)
        self.assertIn(f'<a href="/runs/{run["id"]}">실행 #{run["id"]}</a>', html)
        self.assertIn("검사 결과: ", html)  # the report, rendered as on the run page
        self.assertIn("반영은 한 미리보기에 한 번만 시도할 수 있습니다.", html)
        # How long the preview is kept is behind a question mark.
        self.assertRegex(html, r'<div class="help-pop" id="[\w-]+" popover><p>[^<]*'
                               r"대시보드 프로세스 메모리에만 있습니다")  # fmt: skip
        self.assertNotIn(self.app.PREVIEW_NOT_RECORDED, html)
        self.preview_id()
        self.assertEqual(self.previewed[1][1], [])  # an empty field previews everything
        self.assertEqual(self.apply_preview.call_count, 0)

    def test_dashboard_options_reach_the_app(self):
        class Server:
            def __init__(self, config):
                pass

            def run(self, sockets):
                pass

        with mock.patch.object(self.app.uvicorn, "Server", Server),                 mock.patch.object(self.app, "build_app", wraps=self.app.build_app) as built,                 contextlib.redirect_stdout(io.StringIO()):  # fmt: skip
            # --port 0: whatever holds the default port does not matter here.
            self.assertEqual(main(["dashboard", "--port", "0", "--model-dir", "m", "--no-cache"]), 0)
            self.assertEqual(main(["dashboard", "--port", "0", "--cache-dir", "c"]), 0)
        self.assertEqual([call.kwargs for call in built.call_args_list], [
            {"model_dir": Path("m"), "cache_dir": None, "no_cache": True},
            {"model_dir": None, "cache_dir": Path("c"), "no_cache": False}])  # fmt: skip
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["dashboard", "--cache-dir", "c", "--no-cache"])

    def test_errors_show_a_page_and_record_nothing(self):
        extract = 'Install analyzer dependencies: python -m pip install -e ".[extract]"'
        node = "node.exe not found on PATH (the current directory is not used)"
        hostile = '<script>alert(1)</script> "quoted" \u202e'
        secret = "C:\\private\\folder synthetic-secret-0123456789"
        cases = [
            (GuardError(extract), 400, extract.replace('"', "&#34;")),
            (GuardError(node), 400, node),
            (GuardError(hostile), 400, "&lt;script&gt;alert(1)&lt;/script&gt; &#34;quoted&#34; \\u202e"),
            (ValueError(secret), 400, self.app.PREVIEW_FAILED),
            (OSError(secret), 400, self.app.PREVIEW_FAILED),
            (RecursionError(secret), 400, self.app.PREVIEW_FAILED),
        ]  # fmt: skip
        for error, status, shown in cases:
            with self.subTest(error=type(error).__name__, text=str(error)[:20]):
                self.preview_files.side_effect = error
                response = self.check("example")
                self.assertEqual(response.status_code, status)
                self.assertIn(shown, response.text)
                self.assertIn("이력에 기록하지 않았습니다.", response.text)
                for hidden in ("private", "synthetic-secret", "<script>", "\u202e"):
                    self.assertNotIn(hidden, response.text)
        self.assertEqual(history.list_runs(self.project_id), [])

    def test_missing_or_unknown_projects_run_nothing(self):
        self.assertEqual(self.check(project_id=99).status_code, 404)
        self.assertEqual(self.check(project_id=2**70).status_code, 404)
        self.head.unlink()
        self.project.rmdir()
        response = self.check()
        self.assertEqual(response.status_code, 400)
        self.assertIn(self.app.PROJECT_MISSING, response.text)
        updates = self.page(f"/projects/{self.project_id}/updates")
        self.assertIn("업데이트를 미리보기할 수 없습니다", updates)
        self.assertNotIn("/previews", updates + self.page(f"/projects/{self.project_id}"))
        self.assertEqual(self.preview_files.call_count, 0)

    def test_blank_names_are_no_names_and_never_a_preview_of_everything(self):
        for blank in (" ", "   ", "\t", " \r\n "):
            with self.subTest(blank=repr(blank)):
                response = self.check(blank)
                self.assertEqual(response.status_code, 400)
                self.assertIn(f'<p class="error">{self.app.TARGETS_BLANK}</p>', response.text)
        # Nothing ran for them: no npm, no run, no preview to apply.
        self.assertEqual(self.preview_files.call_count, 0)
        self.assertEqual(history.list_runs(self.project_id), [])
        self.assertNotIn("/previews/", self.page(f"/projects/{self.project_id}/updates"))
        # The empty field of the button that previews everything is everything, and blanks
        # around names are only what separates them.
        self.assertEqual(self.check("").status_code, 303)
        self.assertEqual(self.check("  example\t").status_code, 303)
        self.assertEqual([names for _, names, _ in self.previewed], [[], ["example"]])
        # The field for names asks for one.
        self.assertIn('<input id="packages" name="packages" type="text" maxlength="1024" required>',
                      self.page(f"/projects/{self.project_id}/updates"))  # fmt: skip

    def test_form_csrf_origin_and_limits(self):
        for response in (self.check(csrf="wrong"), self.check(origin=None),
                         self.check(origin=f"http://127.0.0.1:{PORT + 1}")):  # fmt: skip
            self.assertEqual(response.status_code, 403)
        too_long = self.check("a" * (self.app.MAX_TARGETS + 1))
        self.assertEqual(too_long.status_code, 400)
        self.assertIn(self.app.TARGETS_TOO_LONG, too_long.text)
        url = f"/projects/{self.project_id}/previews"
        two = self.client.post(url, content=f"csrf={CSRF}&packages=a&packages=b",
                               headers={"origin": BASE, "content-type":
                                        "application/x-www-form-urlencoded"})  # fmt: skip
        self.assertEqual(two.status_code, 400)
        self.assertEqual(self.get(f"/projects/{self.project_id}/previews").status_code, 405)
        self.assertEqual(self.preview_files.call_count, 0)

    def test_one_change_at_a_time_while_pages_stay_open(self):
        seen = {}

        def during(project, names, **options):
            # Another request arrives while this preview runs in its worker thread. Switch the
            # fake first so a missing refusal fails at the assertions instead of recursing.
            self.preview_files.side_effect = self.fake_preview
            seen["check"] = self.check("example")
            seen["page"] = self.get(f"/projects/{self.project_id}")
            return self.fake_preview(project, names, **options)

        self.preview_files.side_effect = during
        preview_id = self.preview_id()
        self.assert_stopped(seen["check"], 409, self.app.BUSY)
        self.assertIn(self.app.BUSY_NOTE, seen["check"].text)
        self.assertEqual(seen["page"].status_code, 200)
        self.assertEqual(len(self.previewed), 1)
        self.apply_preview.side_effect = lambda *a, **k: (
            seen.setdefault("apply", self.check("example")),
            self.fake_apply(*a, **k),
        )[1]
        self.assertEqual(self.apply(preview_id).status_code, 200)
        self.assertEqual(seen["apply"].status_code, 409)
        self.assertEqual(self.check().status_code, 303)  # free again

    def test_only_the_newest_previews_are_kept(self):
        ids = [self.preview_id() for _ in range(self.app.KEPT_PREVIEWS + 1)]
        self.assert_stopped(self.get(f"/previews/{ids[0]}"), 404, self.app.PREVIEW_GONE)
        for preview_id in ids[1:]:
            self.page(f"/previews/{preview_id}")
        self.assertEqual(self.apply(ids[0]).status_code, 404)
        self.assertEqual(self.get("/previews/unknown").status_code, 404)

    def test_a_failed_record_keeps_the_preview(self):
        with mock.patch.object(history, "record", side_effect=sqlite3.OperationalError("x")):
            preview_id = self.preview_id()
        html = self.page(f"/previews/{preview_id}")
        self.assertIn(self.app.PREVIEW_NOT_RECORDED, html)
        self.assertNotIn("/runs/", html)
        response = self.apply(preview_id)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.app.PREVIEW_NOT_RECORDED, response.text)
        self.assertEqual(history.list_applies(self.project_id), [])


class HeldPreviewTests(ScreenFixture):
    """The previews this process holds, on the project's updates view. Here the faked preview
    names the project's two files as they are, as a real one does."""

    def setUp(self):
        super().setUp()
        self.manifest = self.project / "package.json"
        self.manifest.write_text('{"dependencies": {"example": "^1.0.0"}}', encoding="utf-8")
        self.updates = f"/projects/{self.project_id}/updates"

    def fake_preview(self, project, names, **options):
        result, new_package, new_lock = super().fake_preview(project, names, **options)
        result["preview"].update(package_json_sha256=sha(self.manifest.read_bytes()),
                                 package_lock_sha256=sha(self.head.read_bytes()))  # fmt: skip
        return result, new_package, new_lock

    def test_a_held_preview_is_listed_until_it_is_applied(self):
        other = self.root / "other"
        other.mkdir()
        self.write(other / "package-lock.json", self.new)
        other_id = history.register_project(other)
        self.assertNotIn("검토·반영할 미리보기", self.page(self.updates))
        preview_id = self.preview_id("example")
        (run,) = history.list_runs(self.project_id)
        html = self.page(self.updates)
        self.assertRegex(html, rf'<li><a href="/previews/{preview_id}">[^<]* UTC 미리보기 검토·반영'
                               rf'</a> \(실행 #{run["id"]}\)')  # fmt: skip
        self.assertIn("<li>대상: example</li>", html)
        self.assertNotIn("반영을 시도하면 거부됩니다", html)
        # The recorded check is the current candidate, linked to its report.
        self.assertIn(f'href="/runs/{run["id"]}#r0"', html)
        self.assertIn(f'href="/runs/{run["id"]}#r0"', self.page(f"/projects/{self.project_id}"))
        self.assertNotIn(preview_id, self.page(f"/projects/{other_id}/updates"))
        # Files changed after the preview: it stays listed, said to be refused if applied.
        before = self.head.read_bytes()
        self.head.write_bytes(before + b"\n")
        html = self.page(self.updates)
        self.assertIn(f'href="/previews/{preview_id}"', html)
        self.assertIn("반영을 시도하면 거부됩니다. 업데이트 미리보기를 다시 실행하세요.", html)
        self.assertNotIn(f"/runs/{run['id']}#r0", html)
        self.head.write_bytes(before)
        self.assertEqual(self.apply(preview_id).status_code, 200)
        self.assertNotIn("검토·반영할 미리보기", self.page(self.updates))

    def test_an_unrecorded_preview_is_listed_without_a_run(self):
        with mock.patch.object(history, "record", return_value=None):
            preview_id = self.preview_id()
        html = self.page(self.updates)
        self.assertRegex(
            html, rf'<a href="/previews/{preview_id}">[^<]* UTC 미리보기 검토·반영</a>\n'
        )
        self.assertIn("<li>대상: package.json 범위 안의 전체 의존성</li>", html)
        self.assertNotIn("/runs/", html)
        self.assertIn("아직 업데이트 미리보기를 실행하지 않았습니다.", html)  # nothing stored to show


class PreviewOpensTests(ScreenFixture):
    """An update preview opens its own page, whatever view sent it: the one place where it is
    reviewed and applied. The project installs example and other (direct) and inner (under
    example); the faked preview names the project's two files as they are, and returns a
    candidate for each name given to returns()."""

    LOCATIONS = {"example": "node_modules/example", "other": "node_modules/other",
                 "inner": "node_modules/example/node_modules/inner"}  # fmt: skip
    # What each button that starts a request is called, on the pages that have it: the Korean
    # words of what it runs, with the CLI command it stands for where it runs one.
    ACTING = {
        "전체 업데이트 미리보기(update)": "업데이트 미리보기 중…",
        "전체 업데이트 다시 미리보기(update)": "업데이트 미리보기 중…",
        "이 패키지 미리보기": "업데이트 미리보기 중…",
        "이 패키지 업데이트 미리보기(update)": "업데이트 미리보기 중…",
        "지정한 패키지 업데이트 미리보기(update)": "업데이트 미리보기 중…",
        "lockfile 변경 검사(scan)": "lockfile 변경 검사 중…",
        "고른 방식으로 프로젝트에 반영": "반영 중…",
        "프로젝트 폴더 선택": "폴더 선택 창을 확인하세요…",
    }

    def setUp(self):
        super().setUp()
        self.manifest = self.project / "package.json"
        self.manifest.write_text(json.dumps(lock()["packages"][""]), encoding="utf-8")
        self.write(self.head, lock())
        self.packages = f"/projects/{self.project_id}"
        (self.row,) = self.report["results"]

    def returns(self, *names):
        self.report = {**self.report, "results": [
            {**self.row, "package": name, "location": self.LOCATIONS[name]} for name in names]}  # fmt: skip

    def fake_preview(self, project, names, **options):
        result, new_package, new_lock = super().fake_preview(project, names, **options)
        result["preview"].update(package_json_sha256=sha(self.manifest.read_bytes()),
                                 package_lock_sha256=sha(self.head.read_bytes()))  # fmt: skip
        return result, new_package, new_lock

    def top(self, html):
        """The part of the inspector that is in view at every width."""
        return html.split('<div class="inspect-top">', 1)[1].split('<div class="inspect-body">')[0]

    def another_run(self):
        """A client of another run of the dashboard on the same history: it holds no preview."""
        from starlette.testclient import TestClient

        client = TestClient(self.app.build_app(PORT, CSRF), base_url=BASE)
        self.addCleanup(client.close)
        return client

    def test_every_view_sends_the_same_form_and_ends_on_the_preview(self):
        self.returns("other", "example")
        files = {name: (self.project / name).read_bytes()
                 for name in ("package.json", "package-lock.json")}  # fmt: skip
        for view in ("", "/updates", "/history"):
            html = self.page(self.packages + view)
            form = re.search(r'<form [^>]*id="preview-project"[^>]*>(.*?)</form>', html, re.S)[1]
            # The csrf value and the button's own field; the packages view also says what it
            # shows, for the way back from the preview's page (three fields, within MAX_FIELDS).
            self.assertEqual(re.findall(r'<input [^>]*name="(\w+)"', form),
                             ["csrf"] if view else ["csrf", "back"], view)  # fmt: skip
            self.assertIn('<button class="primary" type="submit" data-busy-label="업데이트 미리보기 '
                          '중…" name="packages" value="">전체 업데이트 미리보기(update)</button>',
                          form)  # fmt: skip
        # A direct dependency's own button on the packages view belongs to the same form.
        self.assertIn('<button type="submit" data-busy-label="업데이트 미리보기 중…" '
                      'form="preview-project" name="packages" value="example" aria-label="이 패키지 '
                      '미리보기: example 업데이트(update)">이 패키지 미리보기</button>',
                      self.page(self.packages))  # fmt: skip
        # Everything, one named package, and the same from the packages view: each ends on the
        # page of its preview.
        for fields in ({}, {"packages": "example"}, {"back": ""}, {"back": "q=ex&item=1.0"}):
            with self.subTest(fields=fields):
                response = self.client.post(
                    f"{self.packages}/previews",
                    data={"csrf": CSRF, "packages": "", **fields},
                    headers={"origin": BASE}, follow_redirects=False)  # fmt: skip
                self.assertEqual(response.status_code, 303, response.text)
                self.assertRegex(response.headers["location"],
                                 r"\A/previews/[A-Za-z0-9_-]+(\?back=[^&#]*)?\Z")  # fmt: skip
                self.assertEqual("back" in fields, "?back=" in response.headers["location"])
        # Four previews are held and recorded; none of them wrote a file or applied anything.
        self.assertEqual((len(self.previewed), len(history.list_runs(self.project_id))), (4, 4))
        self.assertEqual(self.apply_preview.call_count, 0)
        self.assertEqual(history.list_applies(self.project_id), [])
        for name, content in files.items():
            self.assertEqual((self.project / name).read_bytes(), content, name)
        # After a preview of everything the head's button says that it previews again.
        self.assertIn('value="">전체 업데이트 다시 미리보기(update)</button>',
                      self.page(self.packages))  # fmt: skip
        # A run named in the address once (checked) is no query of the view: nothing is said
        # or moved for it.
        run = history.list_runs(self.project_id, 1)[0]["id"]
        html = self.page(f"{self.packages}?checked={run}")
        self.assertNotIn("data-landing", html)
        self.assertNotIn(f"실행 #{run}에서", html)

    def test_the_preview_page_leads_to_the_apply_form_and_back_without_applying(self):
        self.returns("example")
        preview_id = self.preview_id()
        html = self.page(f"/previews/{preview_id}")
        # What is still untouched, and the way down to where it is applied.
        self.assertIn('<p>프로젝트 파일은 아직 그대로입니다. 아래 검사 결과와 <a href="#apply">'
                      "업데이트 반영</a> 가능 여부를 확인하세요.</p>", html)  # fmt: skip
        self.assertIn('<section class="gate" id="apply" aria-labelledby="gate-title">\n'
                      '<h2 id="gate-title">업데이트 반영(update --apply)</h2>', html)  # fmt: skip
        self.assertLess(html.index('<div class="summary">'), html.index('id="apply"'))
        # The two ways are the CLI's own.
        self.assertIn('<label for="mode-lockfile">lockfile 반영 <code>--apply lockfile</code></label>',
                      html)  # fmt: skip
        self.assertIn('<label for="mode-install">설치까지(npm ci --ignore-scripts) <code>--apply '
                      "install</code></label>", html)  # fmt: skip
        # The button says that it changes the project, and the line above it what it changes.
        gate = html.split('id="apply"', 1)[1]
        self.assertLess(gate.index("아래 버튼을 누르면 프로젝트의 package-lock.json을(npm이 바꿨으면 "
                                   "package.json도) 실제로 바꿉니다. 누르기 전에는 아무것도 바꾸지 "
                                   "않습니다."),
                        gate.index(">고른 방식으로 프로젝트에 반영</button>"))  # fmt: skip
        self.assert_form(html, True)
        # Leaving is a link: nothing is applied, and the preview waits where the views list it.
        self.assertIn(f'<p><a class="action" href="{self.packages}/updates">반영하지 않고 업데이트 '
                      "화면으로</a></p>", gate)  # fmt: skip
        updates = self.page(f"{self.packages}/updates")
        self.assertIn('<h2 id="previews-title">검토·반영할 미리보기</h2>', updates)
        self.assertRegex(updates, rf'<li><a href="/previews/{preview_id}">[^<]* UTC 미리보기 '
                                  r"검토·반영</a>")  # fmt: skip
        self.assertIn("열기만 해서는 아무것도 바꾸지 않습니다.", updates)
        self.page(f"/previews/{preview_id}")  # still held
        self.assertEqual(self.apply_preview.call_count, 0)
        self.assertEqual(history.list_applies(self.project_id), [])

    def send(self, back, packages=""):
        """The packages view's preview form: back is the view it was sent from (a list is the
        field given more than once). The address it ends on."""
        fields = [("csrf", CSRF), ("packages", packages),
                  *(("back", value) for value in ([back] if isinstance(back, str) else back))]  # fmt: skip
        response = self.client.post(f"{self.packages}/previews", content=urlencode(fields),
                                    headers={"origin": BASE, "content-type":
                                             "application/x-www-form-urlencoded"},
                                    follow_redirects=False)  # fmt: skip
        self.assertEqual(response.status_code, 303, response.text)
        return response.headers["location"]

    def way_out(self, html):
        """(the words, the address) of the preview page's link that leaves without applying."""
        found = re.search(r'<p><a class="action" href="([^"]*)">(반영하지 않고 [^<]*)</a></p>', html)
        return found[2], unescape(found[1])

    def test_a_preview_sent_from_the_packages_view_leads_back_to_what_that_view_showed(self):
        self.returns("example")
        # The search, the kind, the tab and the open candidate, as the view reads them.
        for back, query in (
            ("", ""),
            ("q=ex&scope=direct&show=candidates&item=3.0", "q=ex&scope=direct&show=candidates&item=3.0"),
            ("show=unchecked&q=ex", "q=ex&show=unchecked"),
            ("scope=all&q=+", ""),  # nothing that narrows the list
            ("q=%ED%95%9C%EA%B8%80+x&", "q=%ED%95%9C%EA%B8%80+x"),
        ):  # fmt: skip
            with self.subTest(back=back):
                url = self.send(back)
                self.assertEqual(url.partition("?")[2], urlencode({"back": query}))
                html = self.page(url)
                self.assertEqual(self.way_out(html), (
                    "반영하지 않고 패키지 목록으로", self.packages + (f"?{query}" if query else "")))  # fmt: skip
                # The apply form keeps it: a refused apply shows the page with the same way out.
                action = unescape(re.search(r'<form method="post" action="([^"]+/apply[^"]*)">',
                                            html)[1])  # fmt: skip
                self.assertEqual(action, url.replace("?", "/apply?"))
        # The address is always this project's packages view, built from what that view reads
        # of the value and never from its text: what the view would refuse, a value that is no
        # query of it, or a value given twice is the view without a filter.
        hostile = ("scope=evil&q=x", "q=" + "x" * 215, "show=evil&q=x", "q=a&q=b", "//evil.test/x",
                   "https://evil.test/?q=x", f"../../{CSRF}/model", "item=" + "9" * 41,
                   "item=1.0&item=2.0", 'item=1.0"><script>alert(1)</script>', "item=-1.0",
                   "item=1", ["q=ex", "only=1"])  # fmt: skip
        for back in hostile:
            with self.subTest(back=str(back)[:30]):
                url = self.send(back)
                self.assertEqual(url.partition("?")[2], "back=")
                self.assertEqual(self.way_out(self.page(url))[1], self.packages)
        # The preview page reads its own address the same way, whoever wrote it.
        preview = url.partition("?")[0]
        for back in hostile[:-1]:
            html = self.page(f"{preview}?{urlencode({'back': back})}")
            self.assertEqual(self.way_out(html)[1], self.packages, back)
            self.assertNotIn("alert(1)", html)
        self.assertEqual(self.way_out(self.page(f"{preview}?back=q%3Dex&back=q%3Dother"))[1],
                         self.packages)  # fmt: skip
        # Without the value the preview was not sent from that view: the updates view.
        self.assertEqual(self.way_out(self.page(preview)),
                         ("반영하지 않고 업데이트 화면으로", f"{self.packages}/updates"))  # fmt: skip
        # A refused apply (no way chosen) shows the page again with the same way out.
        refused = self.client.post(f"{preview}/apply?back=q%3Dex", data={"csrf": CSRF},
                                   headers={"origin": BASE})  # fmt: skip
        self.assertEqual(refused.status_code, 400)
        self.assertEqual(self.way_out(refused.text)[1], f"{self.packages}?q=ex")
        # The way out is a link to a view: the list as it was, the search filled in and the
        # candidate open, and nothing applied.
        run = history.list_runs(self.project_id, 1)[0]["id"]
        html = self.page(self.way_out(self.page(self.send(f"q=ex&scope=direct&item={run}.0")))[1])
        self.assertIn('value="ex" placeholder="패키지 검색">', html)
        self.assertIn('<option value="direct" selected>', html)
        self.assertIn('<a class="pick" id="picked" aria-current="true"', html)
        self.assertEqual(self.apply_preview.call_count, 0)
        self.assertEqual(history.list_applies(self.project_id), [])

    def test_a_candidate_reviewed_from_a_filtered_list_comes_back_to_that_list(self):
        self.returns("example", "other")
        self.preview_id()
        run = history.list_runs(self.project_id, 1)[0]["id"]
        # From the packages view the candidate's link says what the view shows.
        html = self.page(f"{self.packages}?q=oth&scope=direct")
        link = unescape(re.search(r'<p class="inspect-apply"><a class="action" href="([^"]+)">',
                                  html)[1])  # fmt: skip
        self.assertEqual(parse_qs(urlsplit(link).query),
                         {"back": [f"q=oth&scope=direct&item={run}.1"]})  # fmt: skip
        review = self.page(link)
        self.assertEqual(self.way_out(review), (
            "반영하지 않고 패키지 목록으로", f"{self.packages}?q=oth&scope=direct&item={run}.1"))  # fmt: skip
        back = self.page(self.way_out(review)[1])
        self.assertIn("<strong>other</strong>", self.top(back))
        self.assertIn('value="oth" placeholder="패키지 검색">', back)
        # From the updates view it carries nothing, and the way out is that view.
        link = re.search(r'<p class="inspect-apply"><a class="action" href="([^"]+)">',
                         self.page(f"{self.packages}/updates"))[1]  # fmt: skip
        self.assertNotIn("?", link)
        self.assertEqual(self.way_out(self.page(link))[1],
                         f"{self.packages}/updates")  # fmt: skip
        self.assertEqual(self.apply_preview.call_count, 0)

    def test_a_candidate_links_the_preview_it_came_from_while_it_is_held(self):
        self.returns("example", "other")
        preview_id = self.preview_id()
        link = f'<p class="inspect-apply"><a class="action" href="/previews/{preview_id}'
        again = "반영하려면 업데이트 미리보기를 다시 실행합니다."
        missing = "이 후보를 반영하려면 위에서 업데이트 미리보기를 다시 실행합니다."
        for view in ("", "/updates"):
            html = self.page(self.packages + view)
            top = self.top(html)
            # In view without opening the evidence: that nothing is applied here, and where.
            self.assertIn("이 화면에서는 반영하지 않습니다.", top)
            self.assertIn(link, top)
            self.assertIn(">이 후보의 미리보기 검토·반영</a></p>", top)
            self.assertNotIn(again, top)
            self.assertEqual(html.count(f'href="/previews/{preview_id}'),
                             2 if view else 1, view)  # fmt: skip
            self.assertNotIn(missing, html)
        self.assertIn("후보를 고르면 반영 여부와 검사 근거를 이 화면에서 보고, 그 후보의 미리보기에서 "
                      "반영합니다.", self.page(self.packages))  # fmt: skip
        # Another run of the dashboard has the candidates (the history) and no preview: the
        # views say that a preview is run again, and the packages view has its button.
        client = self.another_run()
        packages = client.get(self.packages).text
        self.assertIn(">example</strong>", packages)
        self.assertNotIn("/previews/" + preview_id, packages)
        self.assertNotIn("inspect-apply", packages)
        self.assertIn(again, self.top(packages))
        self.assertIn('name="packages" value="example">이 패키지 업데이트 미리보기(update)</button>',
                      packages)  # fmt: skip
        updates = client.get(f"{self.packages}/updates").text
        self.assertIn(missing, updates)
        self.assertNotIn("검토·반영할 미리보기", updates)
        # A preview made after the files changed is listed as one that would be refused, and is
        # no candidate's.
        self.head.write_bytes(self.head.read_bytes() + b"\n")
        html = self.page(f"{self.packages}/updates")
        self.assertIn("반영을 시도하면 거부됩니다. 업데이트 미리보기를 다시 실행하세요.", html)
        self.assertNotIn("inspect-apply", html)

    def test_the_check_of_one_version_is_a_cli_line_and_never_run(self):
        checked = self.patch_service("check_package", mock.Mock())
        # Before any preview, a newly registered project: both views say in view (outside the
        # question marks) what they run and that the check is the CLI's, with a package of this
        # project as the example: the first lockfile entry that has a line a shell takes.
        entries = lock()["packages"]
        self.write(self.head, {"lockfileVersion": 3, "packages": {
            "": entries[""], "node_modules/it's": package("9.9.9"),
            **{place: entry for place, entry in entries.items() if place}}})  # fmt: skip
        for view in ("", "/updates"):
            html = self.page(self.packages + view)
            idle = re.search(r'<aside class="inspector idle".*?</aside>', html, re.S)[0]
            self.assertNotIn("help-pop", idle)
            self.assertIn("<strong>패키지 한 버전 검사(check)</strong>: 대시보드에서는 실행하지 않고 "
                          "CLI에서만 실행합니다.", idle)  # fmt: skip
            self.assertEqual(re.findall(r"<code>([^<]*)</code>", idle), [
                "depbee update", "depbee update 이름", "depbee scan . --extract",
                "depbee check example@1.1.0"])  # fmt: skip
            self.assertIn('직접 의존성 하나는 패키지 목록 그 행의 "이 패키지 미리보기"', unescape(idle))
        self.assertIsNone(self.app._check_example([]))
        self.write(self.head, {"lockfileVersion": 3, "packages": {"": {}}})
        self.assertIn("예: <code>depbee check 이름@버전</code></li>", self.page(self.packages))
        self.write(self.head, lock())
        # A candidate's own line is in the part of the inspector that is always in view.
        self.returns("example")
        self.preview_id()
        for view in ("", "/updates"):
            html = self.page(self.packages + view)
            self.assertIn('<p class="note">이 버전만 검사(check)는 CLI에서만 실행합니다: '
                          "<code>depbee check example@1.1.0</code></p>", self.top(html))  # fmt: skip
        # What each thing the pages run is in the CLI, and the one they do not run.
        popover = re.search(r'<div class="help-pop" id="help-run" popover>(.*?)</div>', html, re.S)[1]
        self.assertEqual(re.findall(r"<code>([^<]*)</code>", popover), [
            "depbee update", "depbee update 이름", "depbee update --apply lockfile",
            "depbee update --apply install", "depbee scan . --extract", "depbee check 이름@버전",
            "depbee check lodash@4.17.21"])  # fmt: skip
        self.assertIn("check는 대시보드에서 실행하지 않습니다.", popover)
        self.assertEqual(checked.call_count, 0)
        # The line is shown only when it is one that depbee check takes and a shell reads as
        # the two words it shows.
        command = self.app.check_command
        self.assertEqual(command("lodash", "4.17.21"), "depbee check lodash@4.17.21")
        self.assertEqual(command("@scope/na.me_x", "1.0.0-rc.1"),
                         "depbee check @scope/na.me_x@1.0.0-rc.1")  # fmt: skip
        for name, version in (("lodash", None), ("lodash", "1.0.0+build"), ("lodash", "^1.0.0"),
                              ("lodash", "1.0.0 && calc"), ("lodash", "01.0.0"), (None, "1.0.0"),
                              ("a b", "1.0.0"), ("$(calc)", "1.0.0"), ("it's", "1.0.0"),
                              ("a;b", "1.0.0"), ("-x", "1.0.0"), ("~x", "1.0.0"), ("a*", "1.0.0"),
                              ("(a)", "1.0.0"), ("a!", "1.0.0"), ("x" * 215, "1.0.0"),
                              ("../x", "1.0.0"), ("", "1.0.0")):  # fmt: skip
            with self.subTest(name=name, version=version):
                self.assertIsNone(command(name, version))
        # A removal has no version to check, and a name a shell would read gets no line.
        self.report = {**self.report, "results": [
            {**self.row, "status": "removed", "after_version": None, "score": None},
            {**self.row, "package": "it's", "location": "node_modules/other"}]}  # fmt: skip
        self.preview_id()
        for item in (0, 1):
            run = history.list_runs(self.project_id, 1)[0]["id"]
            html = self.page(f"{self.packages}/updates?item={run}.{item}")
            self.assertNotIn("depbee check", self.top(html))
            self.assertNotIn("<code>depbee check it", html)

    def test_buttons_say_what_they_run_and_no_page_calls_an_update_a_check(self):
        self.returns("example")
        preview_id = self.preview_id("example")  # a named one: other stays without a preview
        scan = history.record("scan", self.project, self.report)
        packages = self.page(self.packages)
        pages = {
            "packages": packages, "updates": self.page(f"{self.packages}/updates"),
            "history": self.page(f"{self.packages}/history"),
            "preview": self.page(f"/previews/{preview_id}"), "manage": self.page("/?manage=1"),
            "overview": self.page("/"), "model": self.page("/model"),
            "run": self.page(f"/runs/{scan}"),
            "restarted": self.another_run().get(self.packages).text,
        }  # fmt: skip
        found = {}
        for name, html in pages.items():
            for busy, label in re.findall(
                    r'<button [^>]*data-busy-label="([^"]+)"[^>]*>([^<]*)</button>', html):  # fmt: skip
                self.assertEqual(self.ACTING.get(label), busy, (name, label))
                found.setdefault(label, set()).add(name)
            # Every other button is at once: the search, the theme and the question marks.
            for button in re.findall(r"<button (?![^>]*data-busy-label)[^>]*>.*?</button>", html):
                self.assertRegex(button, r'>검색</button>|name="theme"|class="help"', name)
            visible = unescape(re.sub(r"<[^>]+>", " ", html))
            for word in ("검사만", "후보 확인", "업데이트 확인", "패키지 확인", "후보 다시 확인",
                         "확인했습니다", "확인한 실행", "직접 입력", "미리보기 열기"):  # fmt: skip
                self.assertNotIn(word, visible, name)
        self.assertEqual(set(found), set(self.ACTING) - {"전체 업데이트 다시 미리보기(update)"})
        self.assertEqual(found["이 패키지 업데이트 미리보기(update)"], {"restarted"})
        self.assertEqual(found["고른 방식으로 프로젝트에 반영"], {"preview"})
        # The packages view words a row that no preview covers as that, never as unchecked.
        tabs = packages.split('<nav class="filter-tabs"', 1)[1].split("</nav>", 1)[0]
        self.assertEqual(re.findall(r">(전체|후보|미리보기 전|후보 없음|미확인) <", tabs),
                         ["전체", "후보", "미리보기 전", "후보 없음"])  # fmt: skip
        self.assertIn("</span>미리보기 전</span>", packages)
        # A stored run is named by what ran, with its CLI command.
        self.assertIn("lockfile 변경 검사(scan)", pages["history"])
        self.assertIn("업데이트 미리보기(update)", pages["history"])
        # With the button's own field the head's form is within what a form may send.
        self.assertLess(2, self.app.MAX_FIELDS)


class ScanScreenTests(ScreenFixture):
    """The project page's scan-only button with service.scan_project replaced."""

    def setUp(self):
        super().setUp()
        self.scanned = []
        self.scan_project = self.patch_service("scan_project", self.fake_scan)

    def fake_scan(self, project, base_lock=None, **options):
        self.scanned.append((project, base_lock, options))
        return self.report

    def scan(self, csrf=CSRF, origin=BASE, project_id=None):
        headers = {} if origin is None else {"origin": origin}
        return self.client.post(f"/projects/{project_id or self.project_id}/scans",
                                data={"csrf": csrf}, headers=headers,
                                follow_redirects=False)  # fmt: skip

    def test_a_scan_against_head_with_extraction_is_recorded_and_shown(self):
        from starlette.testclient import TestClient

        self.client = TestClient(self.app.build_app(
            PORT, CSRF, model_dir=Path("m"), cache_dir=Path("c"),
            known_malicious_dir=Path("k")), base_url=BASE)  # fmt: skip
        self.addCleanup(self.client.close)
        project_page = self.page(f"/projects/{self.project_id}/updates")
        self.assertIn(f'action="/projects/{self.project_id}/scans"', project_page)
        self.assertIn("Git HEAD", project_page)
        with mock.patch.object(history, "record", wraps=history.record) as record:
            response = self.scan()
        self.assertEqual(response.status_code, 303, response.text)
        ((project, base_lock, options),) = self.scanned
        self.assertEqual(project, Path(str(self.project.resolve())))  # the registered path
        self.assertIsNone(base_lock)
        self.assertEqual(options, {"base_ref": None, "extract": True, "model_dir": Path("m"),
                                   "cache_dir": Path("c"), "no_cache": False,
                                   "known_malicious_dir": Path("k")})  # fmt: skip
        record.assert_called_once_with("scan", project, self.report, None, base_ref=None,
                                       base_lock=False)  # fmt: skip
        (run,) = history.list_runs(self.project_id)
        self.assertEqual(response.headers["location"], f"/runs/{run['id']}")
        stored = history.get_run(run["id"])
        self.assertEqual((stored["kind"], stored["base_ref"], stored["base_lock"]),
                         ("scan", None, False))  # fmt: skip
        self.assertEqual((stored["report"], stored["preview"]), (self.report, None))
        html = self.page(f"/runs/{run['id']}")
        self.assertIn("검사(scan)", html)
        self.assertIn("검사 결과: ", html)
        self.assertEqual((self.preview_files.call_count, self.apply_preview.call_count), (0, 0))

    def test_an_unrecorded_scan_still_shows_its_report(self):
        for patched in ({"side_effect": sqlite3.OperationalError("x")}, {"return_value": None}):
            with self.subTest(patched=patched), mock.patch.object(history, "record", **patched):
                response = self.scan()
                self.assertEqual(response.status_code, 200)
                self.assertIn(self.app.SCAN_NOT_RECORDED, response.text)
                self.assertIn("검사 결과: ", response.text)
                self.assertNotIn("/runs/", response.text)
                self.assertIn(f'href="/projects/{self.project_id}"', response.text)
        self.assertEqual(history.list_runs(self.project_id), [])

    def test_a_scan_is_shown_when_the_history_breaks_while_it_runs(self):
        """Neither the record nor the rail's read succeeds once the scan has run: the report is
        shown as when only the record fails, the scan is not run again, and every other
        request still ends as the fixed 500 until the history can be read."""
        self.answer_errors()
        with mock.patch.object(history, "record", side_effect=sqlite3.OperationalError("x")):
            unrecorded = self.scan()
        self.assertEqual(unrecorded.status_code, 200)
        self.assertIn('<p class="rail-title">프로젝트 1개 · 조치 필요 0</p>', unrecorded.text)
        history_file = self.db.read_bytes()
        self.scan_project.side_effect = self.breaking(self.fake_scan)
        response = self.scan()
        self.assertEqual(self.assert_recovered(response), main_of(unrecorded.text))
        self.assertIn(self.app.SCAN_NOT_RECORDED, response.text)
        self.assertIn("검사 결과: ", response.text)
        self.assertIn("example", main_of(response.text))
        self.assertEqual(len(self.scanned), 2)  # one scan a request
        # Outside that page nothing changed: a page, and a scan that cannot find its project.
        self.assert_fixed_500(self.get(f"/projects/{self.project_id}"))
        self.assert_fixed_500(self.get("/"))
        self.assert_fixed_500(self.scan())
        self.assertEqual(len(self.scanned), 2)
        self.db.write_bytes(history_file)
        self.assertEqual(history.list_runs(self.project_id), [])
        self.assertIn('<p class="rail-title">프로젝트 1개 · 조치 필요 0</p>',
                      self.page(f"/projects/{self.project_id}"))  # fmt: skip

    def test_a_recorded_scan_keeps_its_stored_address_when_the_history_is_unread_later(self):
        """A scan that was recorded goes to the address of its stored run, as ever. While the
        history cannot be read that address is the fixed 500 like every stored page, and the
        report is not lost: the same address shows it once the history is read again."""
        self.answer_errors()
        response = self.scan()
        (run,) = history.list_runs(self.project_id)
        self.assertEqual((response.status_code, response.headers["location"]),
                         (303, f"/runs/{run['id']}"))  # fmt: skip
        history_file = self.db.read_bytes()
        self.db.write_bytes(NO_HISTORY)
        self.assert_fixed_500(self.get(f"/runs/{run['id']}"))
        self.db.write_bytes(history_file)
        self.assertIn("검사 결과: ", self.page(f"/runs/{run['id']}"))
        self.assertEqual(len(self.scanned), 1)

    def test_a_failed_scan_with_the_history_unread_is_still_the_fixed_500(self):
        self.answer_errors()
        self.scan_project.side_effect = self.breaking(mock.Mock(side_effect=GuardError("x")))
        self.assert_fixed_500(self.scan())

    def test_errors_show_a_page_and_record_nothing(self):
        extract = 'Install analyzer dependencies: python -m pip install -e ".[extract]"'
        hostile = '<script>alert(1)</script> "quoted" \u202e'
        secret = "C:\\private\\folder synthetic-secret-0123456789"
        cases = [
            (GuardError(extract), extract.replace('"', "&#34;")),
            (GuardError(hostile), "&lt;script&gt;alert(1)&lt;/script&gt; &#34;quoted&#34; \\u202e"),
            (ValueError(secret), self.app.SCAN_FAILED),
            (OSError(secret), self.app.SCAN_FAILED),
            (RecursionError(secret), self.app.SCAN_FAILED),
        ]  # fmt: skip
        for error, shown in cases:
            with self.subTest(error=type(error).__name__, text=str(error)[:20]):
                self.scan_project.side_effect = error
                response = self.scan()
                self.assertEqual(response.status_code, 400)
                self.assertIn(shown, response.text)
                self.assertIn(f"<h1>{self.app.SCAN_TITLE}</h1>", response.text)
                self.assertIn("이력에 기록하지 않았습니다.", response.text)
                for hidden in ("private", "synthetic-secret", "<script>", "\u202e"):
                    self.assertNotIn(hidden, response.text)
        self.assertEqual(history.list_runs(self.project_id), [])

    def test_missing_or_unknown_projects_run_nothing(self):
        self.assertEqual(self.scan(project_id=99).status_code, 404)
        self.assertEqual(self.scan(project_id=2**70).status_code, 404)
        self.head.unlink()
        self.project.rmdir()
        response = self.scan()
        self.assertEqual(response.status_code, 400)
        self.assertIn(self.app.PROJECT_MISSING, response.text)
        project_page = self.page(f"/projects/{self.project_id}/updates")
        self.assertIn("검사할 수 없습니다", project_page)
        self.assertNotIn("/scans", project_page)
        self.assertEqual(self.scan_project.call_count, 0)

    def test_form_csrf_and_origin(self):
        for response in (self.scan(csrf="wrong"), self.scan(origin=None),
                         self.scan(origin=f"http://127.0.0.1:{PORT + 1}")):  # fmt: skip
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.get(f"/projects/{self.project_id}/scans").status_code, 405)
        self.assertEqual(self.scan_project.call_count, 0)

    def test_one_scan_or_update_at_a_time_while_pages_stay_open(self):
        seen = {}

        def during_scan(project, base_lock=None, **options):
            # Switch the fakes first so a missing refusal fails at the assertions instead of
            # recursing.
            self.scan_project.side_effect = self.fake_scan
            seen["scan"], seen["check"] = self.scan(), self.check("example")
            seen["page"] = self.get(f"/projects/{self.project_id}")
            return self.fake_scan(project, base_lock, **options)

        self.scan_project.side_effect = during_scan
        self.assertEqual(self.scan().status_code, 303)
        for name in ("scan", "check"):
            self.assert_stopped(seen[name], 409, self.app.BUSY)
        self.assertEqual(seen["page"].status_code, 200)
        self.assertEqual((len(self.scanned), len(self.previewed)), (1, 0))

        def during_check(project, names, **options):
            self.preview_files.side_effect = self.fake_preview
            seen["scan during check"] = self.scan()
            return self.fake_preview(project, names, **options)

        self.preview_files.side_effect = during_check
        preview_id = self.preview_id()
        self.assertEqual(seen["scan during check"].status_code, 409)
        self.apply_preview.side_effect = lambda *a, **k: (
            seen.setdefault("scan during apply", self.scan()),
            self.fake_apply(*a, **k),
        )[1]
        self.assertEqual(self.apply(preview_id).status_code, 200)
        self.assertEqual(seen["scan during apply"].status_code, 409)
        self.assertEqual(len(self.scanned), 1)
        self.assertEqual(self.scan().status_code, 303)  # free again


class GateDisplayTests(ScreenFixture):
    def test_a_known_malicious_match_has_no_apply_form(self):
        self.report = self.scan_with(0.1, known_malicious=KnownList((ADVISORY,)))
        html = self.page(f"/previews/{self.preview_id()}")
        self.assert_form(html, False)
        self.assertIn("반영할 수 없습니다: 기지 악성 기록 일치(예외 없이 거부)", html)
        self.assertIn("기지 악성 기록 일치로 거부한 항목 1개:", html)
        # The line that leads to the gate asks for no choice that this preview does not have.
        self.assertIn('<a href="#apply">업데이트 반영</a> 가능 여부를 확인하세요.', html)
        self.assertNotIn("반영 방식", html)
        self.assertIn("<li>[위험] example@1.1.0 (node_modules/example): 기지 악성 기록 일치", html)

    def test_items_to_confirm_with_their_causes(self):
        self.report = self.scan_with(0.9)
        html = self.page(f"/previews/{self.preview_id()}")
        self.assert_form(html, True)
        self.assertIn("<strong>확인이 필요한 항목 1개:</strong>", html)
        self.assertIn("<li>[위험] example@1.1.0 (node_modules/example): ML 위험 점수 기준 이상; "
                      "기지 악성 목록 미확인; ML 위험 점수 0.900</li>", html)  # fmt: skip
        self.assertIn('name="confirm" value="yes" required> <label for="confirm">위 1개 항목을 '
                      "검토했고 진행합니다.</label>", html)  # fmt: skip
        self.assertIn('value="lockfile" checked>', html)
        self.assertIn('value="install">', html)
        self.assertNotIn(self.app.NPMRC_NO_INSTALL, html)

    def test_passing_items_need_no_confirmation(self):
        self.report = self.scan_with(0.1, known_malicious=KnownList())
        html = self.page(f"/previews/{self.preview_id()}")
        self.assert_form(html, True)
        self.assertNotIn('name="confirm"', html)
        self.assertNotIn("확인이 필요한 항목", html)

    def test_no_change_has_no_apply_form(self):
        self.report = {**self.scan_with(0.1), "results": []}
        html = self.page(f"/previews/{self.preview_id()}")
        self.assert_form(html, False)
        self.assertIn("lockfile에서 바뀐 항목이 없어 반영할 것이 없습니다.", html)
        self.assertIn('<a href="#apply">업데이트 반영</a> 가능 여부를 확인하세요.', html)
        self.assertNotIn("반영 방식", html)

    def test_a_project_npmrc_disables_install(self):
        self.npmrc = True
        html = self.page(f"/previews/{self.preview_id()}")
        self.assert_form(html, True)
        self.assertIn('value="install" disabled>', html)
        self.assertIn(self.app.NPMRC_NO_INSTALL, html)


class ApplyScreenTests(ScreenFixture):
    def test_without_the_confirmation_nothing_runs_and_the_preview_stays(self):
        preview_id = self.preview_id()
        response = self.apply(preview_id, confirm=False)
        self.assertEqual(response.status_code, 400)
        self.assertIn(self.app.CONFIRM_NEEDED, response.text)
        self.assert_form(response.text, True)
        for mode in ("", "both", "LOCKFILE"):
            with self.subTest(mode=mode):
                response = self.apply(preview_id, mode=mode)
                self.assertEqual(response.status_code, 400)
                self.assertIn(self.app.CHOOSE_MODE, response.text)
        self.assertEqual(self.apply(preview_id, csrf="wrong").status_code, 403)
        self.assertEqual(self.apply(preview_id, origin=None).status_code, 403)
        self.assertEqual(self.apply_preview.call_count, 0)
        self.page(f"/previews/{preview_id}")  # still there
        self.assertEqual(self.apply(preview_id).status_code, 200)
        self.assertEqual(self.apply_preview.call_count, 1)

    def test_install_after_a_project_npmrc_is_refused_before_the_service(self):
        self.npmrc = True
        preview_id = self.preview_id()
        response = self.apply(preview_id, mode="install")
        self.assertEqual(response.status_code, 400)
        self.assertIn(self.app.NPMRC_NO_INSTALL, response.text)
        self.assertEqual(self.apply_preview.call_count, 0)
        self.assertEqual(self.apply(preview_id, mode="lockfile").status_code, 200)

    def test_an_apply_uses_the_registered_path_once_and_is_recorded(self):
        preview_id = self.preview_id("example")
        (run,) = history.list_runs(self.project_id)
        self.document = applied_document(mode="install", npm_version="11.6.1", npm_ci_exit_code=0,
                                          notices=[service.SCRIPTS_NOTICE,
                                                   service.RESTORE_NOTICE])  # fmt: skip
        response = self.apply(preview_id, mode="install")
        self.assertEqual(response.status_code, 200)
        (call,) = self.applied
        self.assertEqual(call["project"], Path(str(self.project.resolve())))
        self.assertEqual((call["mode"], call["confirm"]), ("install", True))
        self.assertEqual((call["new_package"], call["new_lock"]),
                         (b"new package.json", b"new lockfile"))  # fmt: skip
        self.assertEqual(call["result"]["report"], self.report)
        html = response.text
        self.assertIn("<h1>업데이트 반영: 반영함</h1>", html)
        self.assertIn(f"원본 백업: {BACKUP}", html)
        self.assertIn("npm 11.6.1, npm ci 종료 코드 0", html)
        self.assertIn(service.SCRIPTS_NOTICE, html)
        self.assertIn(service.RESTORE_NOTICE, html)
        self.assertIn("확인이 필요한 항목 1개(대시보드에서 확인함):", html)
        self.assertNotIn("--confirm-warnings", html)
        self.assertIn(f'<a href="/runs/{run["id"]}">실행 #{run["id"]}</a>에 반영 기록', html)
        # The preview is gone: a reload or a resent form applies nothing again.
        self.assertEqual(self.get(f"/previews/{preview_id}").status_code, 404)
        self.assert_stopped(self.apply(preview_id, mode="install"), 404, self.app.PREVIEW_GONE)
        self.assertEqual(self.apply_preview.call_count, 1)
        (stored,) = history.list_applies(self.project_id)
        self.assertEqual((stored["run_id"], stored["outcome"], stored["backup"]),
                         (run["id"], "applied", BACKUP))  # fmt: skip
        self.assertEqual(stored["apply"]["confirmation_required"][0]["causes"],
                         ["known_malicious_unchecked"])  # fmt: skip
        run_page = self.page(f"/runs/{run['id']}")
        self.assertIn("<h2>업데이트 반영: 반영함</h2>", run_page)
        self.assertIn("확인이 필요한 항목 1개(확인함):", run_page)
        project_page = self.page(f"/projects/{self.project_id}/history")
        self.assertIn("<td>설치까지(npm ci --ignore-scripts)</td>\n<td>반영함</td>\n<td>-</td>\n"
                      f"<td>예</td>\n<td>{BACKUP}</td>\n<td>0</td>", project_page)  # fmt: skip
        self.assertIn(f'<a href="/runs/{run["id"]}">#{run["id"]}</a>', project_page)

    def test_a_failed_apply_record_still_shows_the_result_and_backup(self):
        preview_id = self.preview_id()
        with mock.patch.object(history, "record_apply", side_effect=sqlite3.OperationalError("x")):
            response = self.apply(preview_id)
        self.assertEqual(response.status_code, 200)
        self.assertIn("업데이트 반영: 반영함", response.text)
        self.assertIn(f"원본 백업: {BACKUP}", response.text)
        self.assertIn(self.app.APPLY_NOT_RECORDED, response.text)
        self.assertEqual(history.list_applies(self.project_id), [])

    def test_an_apply_is_shown_when_the_history_breaks_while_it_runs(self):
        """Neither the apply record nor the rail's read succeeds once the files are replaced:
        the result and the backup are shown as when only the record fails, and the preview is
        used up, so nothing is applied again."""
        self.answer_errors()
        first = self.preview_id()
        with mock.patch.object(history, "record_apply", side_effect=sqlite3.OperationalError("x")):
            unrecorded = self.apply(first)
        self.assertEqual(unrecorded.status_code, 200)
        preview_id = self.preview_id()
        history_file = self.db.read_bytes()
        self.apply_preview.side_effect = self.breaking(self.fake_apply)
        response = self.apply(preview_id)
        self.assertEqual(self.assert_recovered(response), main_of(unrecorded.text))
        self.assertIn("<h1>업데이트 반영: 반영함</h1>", response.text)
        self.assertIn(f"원본 백업: {BACKUP}", response.text)
        self.assertIn(self.app.APPLY_NOT_RECORDED, response.text)
        self.assertEqual(self.apply_preview.call_count, 2)  # one apply a preview
        self.assert_fixed_500(self.apply(preview_id))  # the page of a preview that is gone
        self.assert_fixed_500(self.get(f"/projects/{self.project_id}/updates"))
        self.db.write_bytes(history_file)
        self.assert_stopped(self.apply(preview_id), 404, self.app.PREVIEW_GONE)
        self.assertEqual(self.apply_preview.call_count, 2)
        self.assertEqual(history.list_applies(self.project_id), [])

    def test_an_apply_that_was_recorded_is_shown_when_the_rail_cannot_be_read(self):
        self.answer_errors()
        preview_id = self.preview_id()
        (run,) = history.list_runs(self.project_id)
        with mock.patch.object(self.app, "_tabs", side_effect=sqlite3.OperationalError("x")):
            response = self.apply(preview_id)
        self.assertEqual(response.status_code, 200)
        self.assertIn(f'<p class="warning">{self.app.RAIL_UNREAD}</p>', main_of(response.text))
        self.assertIn(f"원본 백업: {BACKUP}", response.text)
        self.assertNotIn(self.app.APPLY_NOT_RECORDED, response.text)
        # The run is stored, so its link is a true one.
        self.assertIn(f'<a href="/runs/{run["id"]}">실행 #{run["id"]}</a>에 반영 기록',
                      response.text)  # fmt: skip
        (stored,) = history.list_applies(self.project_id)
        self.assertEqual((stored["run_id"], stored["backup"]), (run["id"], BACKUP))

    def test_an_apply_the_service_failed_says_so_when_the_history_breaks_too(self):
        """The preview is used up and the files may have changed: the page that says to look at
        them is not replaced by the fixed text."""
        self.answer_errors()
        preview_id = self.preview_id()
        history_file = self.db.read_bytes()
        failing = mock.Mock(side_effect=OSError("C:/private synthetic-secret-0123456789"))
        self.apply_preview.side_effect = self.breaking(failing)
        response = self.apply(preview_id)
        self.assert_recovered(response, 500)
        self.assertIn(f'<p class="error">{self.app.APPLY_FAILED}</p>', response.text)
        self.assertNotIn("synthetic-secret", response.text)
        self.db.write_bytes(history_file)
        self.assertEqual(self.get(f"/previews/{preview_id}").status_code, 404)

    def test_an_apply_with_the_history_unread_runs_nothing_and_keeps_the_preview(self):
        self.answer_errors()
        preview_id = self.preview_id()
        history_file = self.db.read_bytes()
        self.db.write_bytes(NO_HISTORY)
        self.assert_fixed_500(self.apply(preview_id))
        self.assertEqual(self.apply_preview.call_count, 0)
        self.db.write_bytes(history_file)
        self.page(f"/previews/{preview_id}")  # still there
        self.assertEqual(self.apply(preview_id).status_code, 200)
        self.assertEqual(self.apply_preview.call_count, 1)

    def test_refused_and_failed_results_are_shown_and_need_a_new_check(self):
        cases = [
            (applied_document("refused", "project_changed", notices=[service.UNCHANGED_NOTICE]),
             ["업데이트 반영: 반영하지 않음", "이유: 미리보기 뒤 package.json 또는 package-lock.json이 바뀜",
              service.UNCHANGED_NOTICE]),
            (applied_document("refused", "confirmation_required"),
             ["이유: 확인이 필요한 항목이 있는데 확인하지 않음", self.app.RETRY_HERE]),
            (applied_document("failed", "install_failed", mode="install",
                              error="npm ci failed with exit code 1", npm_version="11.6.1",
                              npm_ci_exit_code=1),
             ["업데이트 반영: 실패", "이유: npm ci 실패", "오류: npm ci failed with exit code 1",
              f"원본 백업: {BACKUP}", "npm 11.6.1, npm ci 종료 코드 1"]),
        ]  # fmt: skip
        for document, lines in cases:
            with self.subTest(reason=document["reason"]):
                self.document = document
                preview_id = self.preview_id()
                response = self.apply(preview_id, mode=document["mode"])
                self.assertEqual(response.status_code, 200)
                for line in lines:
                    self.assertIn(line, response.text)
                self.assertNotIn("--confirm-warnings", response.text)
                self.assertEqual(self.apply(preview_id).status_code, 404)
        reasons = [a["reason"] for a in history.list_applies(self.project_id)]
        self.assertEqual(reasons, ["install_failed", "confirmation_required", "project_changed"])

    def test_an_unexpected_service_error_is_a_fixed_page(self):
        preview_id = self.preview_id()
        self.apply_preview.side_effect = OSError("C:\\private synthetic-secret-0123456789")
        response = self.apply(preview_id)
        self.assertEqual(response.status_code, 500)
        self.assertIn(self.app.APPLY_FAILED, response.text)
        self.assertNotIn("synthetic-secret", response.text)
        self.assertEqual(self.get(f"/previews/{preview_id}").status_code, 404)

    def test_a_missing_project_folder_runs_nothing_and_keeps_the_preview(self):
        preview_id = self.preview_id()
        self.head.unlink()
        self.project.rmdir()
        response = self.apply(preview_id)
        self.assertEqual(response.status_code, 400)
        self.assertIn(self.app.PROJECT_MISSING, response.text)
        self.assertEqual(self.apply_preview.call_count, 0)
        self.page(f"/previews/{preview_id}")

    def test_cli_applies_are_shown_with_neutral_wording(self):
        document = applied_document(confirmation_required=[
            {"location": "node_modules/example", "package": "example", "before_version": "1.0.0",
             "after_version": "1.1.0", "status": "not_flagged", "reason": None, "score": 0.1,
             "known_malicious_status": "not_run", "ml_status": "not_hit",
             "causes": ["known_malicious_unchecked"]}])  # fmt: skip
        run_id = history.record("update_preview", self.project, self.report, PREVIEW,
                                apply=document)  # fmt: skip
        run_page = self.page(f"/runs/{run_id}")
        self.assertIn("<h2>업데이트 반영: 반영함</h2>", run_page)
        self.assertIn("확인이 필요한 항목 1개(확인함):", run_page)
        self.assertNotIn("--confirm-warnings", run_page)
        self.assertIn(f"<td>{BACKUP}</td>", self.page(f"/projects/{self.project_id}/history"))
        scan_page = self.page(f"/runs/{history.record('scan', self.project, self.report)}")
        self.assertNotIn("업데이트 반영", scan_page)


class UpdateEscapeTests(ScreenFixture):
    STRINGS = EscapeTests.STRINGS
    check_html = EscapeTests.check

    def test_gate_lists_errors_backups_and_targets_stay_inert(self):
        from markupsafe import escape

        for text in self.STRINGS:
            with self.subTest(text=text):
                self.report = self.scan_with(0.9)
                for key in ("package", "location"):
                    self.report["results"][0][key] = text
                self.targets = [text]
                self.document = applied_document("failed", "write_failed", error=text,
                                                 backup=text)  # fmt: skip
                preview_id = self.preview_id()
                self.check_html(self.page(f"/previews/{preview_id}"))
                response = self.apply(preview_id)
                self.assertEqual(response.status_code, 200)
                self.check_html(response.text)
                self.assertIn(f"원본 백업: {escape(_clean(text))}", response.text)
                for view in ("", "/updates", "/history"):
                    self.check_html(self.page(f"/projects/{self.project_id}{view}"))
                self.preview_files.side_effect = GuardError(f"{text} is not a dependency")
                response = self.check()  # the name is in the service's message
                self.assertEqual(response.status_code, 400)
                self.check_html(response.text)
                self.assertIn(escape(_clean(f"{text} is not a dependency")), response.text)
                self.preview_files.side_effect = self.fake_preview
        known = self.scan_with(0.1, known_malicious=KnownList((ADVISORY,)))
        known["results"][0]["package"] = self.STRINGS[-1]
        self.report = known
        self.check_html(self.page(f"/previews/{self.preview_id()}"))


@unittest.skipUnless(WEB, NO_WEB)
class EndToEndTests(ApplyFixture):
    """An update through the dashboard with the real service and the fake npm of test_apply, as a
    browser goes: every request is a link or a form of the page before it, starting from a view
    of the project. FakePredictor flags the one update, so it waits for a confirmation."""

    def setUp(self):
        super().setUp()
        from starlette.testclient import TestClient

        from depbee.dashboard import app

        self.app = app
        self.client = TestClient(app.build_app(PORT, CSRF, model_dir=self.root), base_url=BASE)
        self.addCleanup(self.client.close)
        self.project_id = history.register_project(self.upd)
        self.views = f"/projects/{self.project_id}"

    def look(self, url):
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, url)
        return response.text

    def form(self, html, pattern):
        """(the address, the hidden fields) of the form of a page whose opening tag matches."""
        found = re.search(rf"<form {pattern}[^>]*>(.*?)</form>", html, re.S)
        self.assertIsNotNone(found, pattern)
        action = re.search(r'action="([^"]+)"', found[0])[1]
        hidden = dict(re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)">', found[1]))
        return unescape(action), {name: unescape(value) for name, value in hidden.items()}

    def preview(self, view="", **fields):
        """Press the head's preview button on a view of the project (fields: another button of
        that form). The page the browser ends on, after the redirect."""
        action, hidden = self.form(self.look(self.views + view), 'method="post" [^>]*id="preview-project"')
        response = self.client.post(action, data={**hidden, "packages": "", **fields},
                                    headers={"origin": BASE})  # fmt: skip
        self.assertEqual(response.status_code, 200, response.text)
        self.assertRegex(response.url.path, r"\A/previews/[A-Za-z0-9_-]+\Z")
        return response.text

    def send_apply(self, html, **fields):
        """Send the preview page's apply form with these choices."""
        action, hidden = self.form(html, 'method="post" action="[^"]+/apply')
        return self.client.post(action, data={**hidden, **fields}, headers={"origin": BASE})

    def test_looking_writes_nothing(self):
        run = history.record("update_preview", self.upd, {
            "status": "not_flagged", "exit_code": 0, "results": []}, PREVIEW)  # fmt: skip
        with mock.patch.object(service, "preview_files") as preview, \
                mock.patch.object(service, "apply_preview") as apply, \
                mock.patch.object(service, "scan_project") as scan:  # fmt: skip
            for url in ("/", "/?manage=1", "/model", self.views,
                        f"{self.views}/updates",
                        f"{self.views}/history", f"/runs/{run}"):  # fmt: skip
                self.look(url)
            # The addresses that change something answer a GET with nothing done.
            for url in (f"{self.views}/previews", f"{self.views}/scans", "/previews/x/apply",
                        "/projects/pick"):  # fmt: skip
                self.assertEqual(self.client.get(url).status_code, 405, url)
            self.assertEqual((preview.call_count, apply.call_count, scan.call_count), (0, 0, 0))
        self.assert_unchanged()
        self.assertEqual(history.list_applies(self.project_id), [])

    def test_from_the_packages_view_to_an_applied_lockfile(self):
        page = self.preview()  # the head's button for everything, on the packages view
        self.assert_unchanged()  # the preview changed nothing
        self.assertIn("프로젝트 파일은 아직 그대로입니다.", page)
        self.assertIn("확인이 필요한 항목 1개", page)  # FakePredictor flags it
        self.look(self.views)  # the views list the candidate: still nothing written
        self.look(f"{self.views}/updates")
        self.assert_unchanged()
        applied = self.send_apply(page, mode="lockfile", confirm="yes")
        self.assertEqual(applied.status_code, 200)
        self.assertIn("업데이트 반영: 반영함", applied.text)
        backup = self.assert_applied({"outcome": "applied",
                                      "backup": str(next(self.backups.iterdir()))})  # fmt: skip
        self.assertEqual((backup / "package-lock.json").read_bytes(),
                         self.original["package-lock.json"])  # fmt: skip
        self.assertIn(f"원본 백업: {backup}", applied.text)
        (run,) = history.list_runs(self.project_id)
        (stored,) = history.list_applies(self.project_id)
        self.assertEqual((stored["run_id"], stored["outcome"], stored["confirmed"],
                          stored["backup"]), (run["id"], "applied", True, str(backup)))  # fmt: skip
        self.assertEqual(stored["new_package_lock_sha256"], sha(self.head.read_bytes()))
        self.assertEqual(self.ci_calls, [])  # lockfile only: no npm ci
        # One use: the same form again finds no preview, and nothing is backed up twice.
        again = self.send_apply(page, mode="lockfile", confirm="yes")
        self.assertEqual(again.status_code, 404)
        self.assertEqual(len(list(self.backups.iterdir())), 1)
        # The views say that it was applied.
        self.assertIn("의 업데이트를", self.look(f"{self.views}/updates"))
        self.assertIn("<td>lockfile 반영</td>\n<td>반영함</td>", self.look(f"{self.views}/history"))

    def test_a_named_preview_from_the_updates_view_to_an_install_without_scripts(self):
        # The names typed on the updates view: the same address, the form of that view.
        action, hidden = self.form(self.look(f"{self.views}/updates"),
                                   rf'method="post" action="{re.escape(self.views)}/previews"(?! id=)')  # fmt: skip
        response = self.client.post(action, data={**hidden, "packages": "example"},
                                    headers={"origin": BASE})  # fmt: skip
        self.assertEqual(response.status_code, 200, response.text)
        page = response.text
        self.assertIn("<li>대상: example</li>", page)
        self.assert_unchanged()
        self.assertEqual(self.ci_calls, [])
        applied = self.send_apply(page, mode="install", confirm="yes")
        self.assertEqual(applied.status_code, 200)
        self.assertIn("업데이트 반영: 반영함", applied.text)
        self.assert_applied({"outcome": "applied", "backup": str(next(self.backups.iterdir()))})
        # npm ci ran once, in the project, with the lifecycle scripts off.
        (call,) = self.ci_calls
        self.assertEqual(call["cwd"], self.upd.resolve())
        self.assertIn("--ignore-scripts", call["argv"])
        self.assertIn("npm ci 종료 코드 0", applied.text)
        (stored,) = history.list_applies(self.project_id)
        self.assertEqual((stored["mode"], stored["outcome"], stored["npm_ci_exit_code"]),
                         ("install", "applied", 0))  # fmt: skip

    def test_leaving_the_preview_or_not_confirming_changes_nothing(self):
        page = self.preview(back="q=ex")  # sent from the packages view while it was searched
        # The way out is a link back to that list; following it applies nothing.
        out = unescape(re.search(r'<a class="action" href="([^"]+)">반영하지 않고 패키지 목록으로</a>',
                                 page)[1])  # fmt: skip
        self.assertEqual(out, f"{self.views}?q=ex")
        self.assertIn('value="ex" placeholder="패키지 검색">', self.look(out))
        self.assert_unchanged()
        # The form sent without its confirmation, or without a way, is refused before the
        # service, and the preview stays to be decided.
        for fields, message in (({"mode": "lockfile"}, self.app.CONFIRM_NEEDED),
                                ({"confirm": "yes"}, self.app.CHOOSE_MODE),
                                ({"mode": "install"}, self.app.CONFIRM_NEEDED)):  # fmt: skip
            with self.subTest(fields=fields):
                refused = self.send_apply(page, **fields)
                self.assertEqual(refused.status_code, 400)
                self.assertIn(message, refused.text)
                self.assert_unchanged()
        self.assertEqual((self.ci_calls, history.list_applies(self.project_id)), ([], []))
        # It is still there, and applies once it is confirmed.
        self.assertEqual(self.send_apply(page, mode="lockfile", confirm="yes").status_code, 200)
        self.assertEqual(len(list(self.backups.iterdir())), 1)

    def test_a_known_malicious_match_is_refused_whatever_is_sent(self):
        self.verdict([{"status": "flagged", "reason": None, "ml": "not_hit", "known": "hit"}], 1)
        page = self.preview()
        self.assertIn("반영할 수 없습니다: 기지 악성 기록 일치(예외 없이 거부)", page)
        self.assertNotRegex(page, r'<form method="post" action="[^"]+/apply')
        self.assertIn("반영하지 않고 패키지 목록으로", page)  # the way out is still there
        # A request made by hand, confirmation and all, is refused by the service's gate.
        preview_id = re.search(r'href="/previews/([A-Za-z0-9_-]+)"',
                               self.look(f"{self.views}/updates"))[1]  # fmt: skip
        forced = self.client.post(f"/previews/{preview_id}/apply",
                                  data={"csrf": CSRF, "mode": "lockfile", "confirm": "yes"},
                                  headers={"origin": BASE})  # fmt: skip
        self.assertEqual(forced.status_code, 200)
        self.assertIn("업데이트 반영: 반영하지 않음", forced.text)
        self.assertIn("기지 악성 기록 일치(예외 없이 거부)", forced.text)
        self.assert_unchanged()
        self.assertEqual(self.ci_calls, [])
        (stored,) = history.list_applies(self.project_id)
        self.assertEqual((stored["outcome"], stored["reason"]), ("refused", "known_malicious_hit"))

    def test_a_preview_of_files_that_changed_since_is_refused_and_overwrites_nothing(self):
        page = self.preview()
        edited = self.original["package-lock.json"] + b"\n"  # the user's own edit, meanwhile
        (self.upd / "package-lock.json").write_bytes(edited)
        # The views say so before anything is sent.
        self.assertIn("반영을 시도하면 거부됩니다. 업데이트 미리보기를 다시 실행하세요.",
                      self.look(f"{self.views}/updates"))  # fmt: skip
        refused = self.send_apply(page, mode="install", confirm="yes")
        self.assertEqual(refused.status_code, 200)
        self.assertIn("업데이트 반영: 반영하지 않음", refused.text)
        self.assertIn("미리보기 뒤 package.json 또는 package-lock.json이 바뀜", refused.text)
        self.assertEqual((self.upd / "package-lock.json").read_bytes(), edited)
        self.assertFalse(self.backups.exists())
        self.assertEqual(self.ci_calls, [])
        # The refusal used the preview up: a new preview is what applies.
        self.assertEqual(self.send_apply(page, mode="lockfile", confirm="yes").status_code, 404)
        self.assertEqual((self.upd / "package-lock.json").read_bytes(), edited)


class WithoutWebTests(Fixture):
    """depbee dashboard where importing its web libraries fails, typed in the folder of an npm
    project as the depbee of an installed wheel is: no Python project is there for pip."""

    def refusal(self, absent=(), gone=(), modules=None, anew=(), path=None):
        """The error of depbee dashboard: the one JSON object on stderr, with exit code 2 and
        nothing on stdout. absent: packages that are not installed, with neither a module nor
        an install record. gone: packages whose module is not found although their install
        record is there. modules: what sys.modules holds besides. anew: packages that are
        imported again. path: a folder that comes first on sys.path."""
        modules = modules or {}
        found = importlib.metadata.distribution
        find = importlib.machinery.PathFinder.find_spec

        def distribution(name):
            if name in absent:
                raise importlib.metadata.PackageNotFoundError(name)
            return found(name)

        # The finder of sys.path, which the import system and importlib.util.find_spec both
        # ask: each then says of these packages what it says where they are not installed.
        def find_spec(name, path=None, target=None):
            return None if name.split(".")[0] in (*absent, *gone) else find(name, path, target)

        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.dict(sys.modules),  # as it was once this ends
            mock.patch.object(sys, "path", [str(path), *sys.path] if path else sys.path),
            mock.patch("importlib.metadata.distribution", distribution),
            mock.patch.object(importlib.machinery.PathFinder, "find_spec", find_spec),
            contextlib.chdir(self.project),
        ):
            # Nothing that an earlier import left answers for them: a real import decides.
            again = {name.split(".")[0] for name in (*absent, *gone, *modules, *anew)}
            for name in [name for name in sys.modules if name.split(".")[0] in again]:
                del sys.modules[name]
            sys.modules.pop("depbee.dashboard.app", None)
            sys.modules.update(modules)
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["dashboard"])
        self.assertEqual((code, out.getvalue()), (2, ""))
        self.assertNotIn("Traceback", err.getvalue())
        error = json.loads(err.getvalue())
        self.assertEqual((error["status"], error["exit_code"]), ("error", 2))
        self.assertNotIn(chr(0x2014), error["error"])
        return error["error"]

    def assert_no_command(self, error, cause, why):
        self.assertIn(f"({sys.executable}): ", error)
        self.assertIn(cause, error)
        self.assertTrue(error.endswith(f"No install command is suggested: {why}."), error)
        self.assertNotIn("pip install", error)
        self.assertNotIn("Not installed", error)

    def test_the_requirements_named_are_the_web_extra(self):
        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        project = tomllib.loads(pyproject.read_text("utf-8"))["project"]
        self.assertEqual(list(dashboard.WEB.values()), project["optional-dependencies"]["web"])
        self.assertEqual([re.match("[a-z0-9]+", text)[0] for text in dashboard.WEB.values()],
                         list(dashboard.WEB))  # fmt: skip

    def test_absent_libraries_get_one_command_for_them_that_ends_the_error(self):
        cases = [tuple(dashboard.WEB)]
        if WEB:  # the others are installed here
            cases += [("starlette",), ("jinja2",), ("uvicorn",), ("starlette", "uvicorn")]
        # The Python that runs this, and one whose path each shell has to write in its own way.
        for python in (sys.executable, str(self.root / "O'Brien [dev] env" / "python")):
            for absent in cases:
                with self.subTest(python=python, absent=absent):
                    with mock.patch.object(sys, "executable", python):
                        error = self.refusal(absent)
                        shown = _with_this_python(*(dashboard.WEB[name] for name in absent))
                    lead = error.removesuffix(shown)
                    self.assertNotEqual(lead, error)  # nothing follows the command
                    self.assertRegex(lead, r": No module named '\w+'\. ")  # the cause, before it
                    self.assertIn(f"Not installed: {', '.join(absent)}. ", lead)
                    self.assertNotIn("pip install", lead)
                    self.assertNotIn(".[web]", error)  # no project is here to take an extra from
        plan = io.StringIO()
        gone = {name: None for name in (*sys.modules, *WEB_MODULES)
                if name.split(".")[0] in WEB_MODULES}  # fmt: skip
        with mock.patch.dict(sys.modules, gone), contextlib.redirect_stdout(plan):
            # Other commands do not need the libraries.
            planned = main(["plan", str(self.project), "--base-lock", str(self.base)])
        self.assertEqual(planned, 0)
        self.assertEqual(len(json.loads(plan.getvalue())["changes"]), 1)

    def test_what_follows_the_lead_runs_as_typed_in_the_npm_folder(self):
        """All that the error says after its lead, typed in the npm project's folder in each
        shell found here, runs the pip of the Python that ran depbee with those requirements
        and nothing else. That Python is a stand-in whose pip only reports how it was run."""
        shells = [shell for shell in ("powershell", "pwsh") if shutil.which(shell)]
        if os.name != "nt":
            shells = ["sh"]
        elif not shells:
            self.skipTest("no PowerShell here")
        for folder in ("O'Brien env", "O'Brien [dev] env"):  # PowerShell: one form for each
            home = self.root / folder
            venv.create(home, with_pip=False)
            (python,) = [file for file in (home / "Scripts" / "python.exe", home / "bin" / "python")
                         if file.exists()]  # fmt: skip
            (site,) = [*home.glob("Lib/site-packages"), *home.glob("lib/python*/site-packages")]
            (site / "pip").mkdir()
            (site / "pip" / "__main__.py").write_text(FAKE_PIP, "utf-8")
            with mock.patch.object(sys, "executable", str(python)):
                error = self.refusal(tuple(dashboard.WEB))
            lead = ", in PowerShell: " if os.name == "nt" else " the Python that runs depbee: "
            typed = error.partition(lead)[2]
            self.assertTrue(typed, error)
            for shell in shells:
                with self.subTest(folder=folder, shell=shell):
                    command = [shell, "-c", typed]
                    if os.name == "nt":
                        command = [shell, "-NoProfile", "-NonInteractive", "-EncodedCommand",
                                   base64.b64encode(typed.encode("utf-16-le")).decode()]  # fmt: skip
                    # Without PowerShell 7's module path Windows PowerShell loads its own modules.
                    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
                    done = subprocess.run(command, cwd=self.project, env=env, timeout=120,
                                          stdin=subprocess.DEVNULL, capture_output=True,
                                          text=True, errors="replace")  # fmt: skip
                    self.assertEqual(done.returncode, 0, done.stderr)
                    ((ran, arguments, where),) = [json.loads(line[4:])
                                                  for line in done.stdout.splitlines()
                                                  if line.startswith("PIP ")]  # fmt: skip
                    self.assertTrue(Path(ran).samefile(python), ran)
                    self.assertEqual(arguments, ["install", *dashboard.WEB.values()])
                    self.assertTrue(Path(where).samefile(self.project), where)

    def test_a_library_left_without_its_module_gets_no_command(self):
        # What is left of a library whose package folder is gone: its install record, which is
        # what pip goes by. What an install would do then is not depbee's to promise.
        site = self.root / "site"
        for name in dashboard.WEB:
            (site / f"{name}-0.dist-info").mkdir(parents=True)
            (site / f"{name}-0.dist-info" / "METADATA").write_text(
                f"Metadata-Version: 2.1\nName: {name}\nVersion: 0\n", "utf-8")  # fmt: skip
        why = "jinja2 is recorded as installed there"
        # Alone, and with others that are absent: their command would not bring jinja2 back.
        for absent in ((), ("starlette", "uvicorn")):
            with self.subTest(absent=absent):
                gone = [name for name in dashboard.WEB if name not in absent]
                error = self.refusal(absent, gone, path=site)
                self.assert_no_command(error, "No module named 'jinja2'", why)
        # An absent library that is what failed keeps its command, for the absent ones alone.
        error = self.refusal(("jinja2", "uvicorn"), ("starlette",), path=site)
        self.assertIn("Not installed: jinja2, uvicorn. ", error)
        self.assertTrue(error.endswith(_with_this_python(dashboard.WEB["jinja2"],
                                                         dashboard.WEB["uvicorn"])), error)  # fmt: skip

    @unittest.skipUnless(WEB, NO_WEB)
    def test_installed_libraries_that_fail_to_import_get_the_cause_and_no_command(self):
        shadow = self.root / "shadow"
        shadow.mkdir()
        (shadow / "starlette.py").write_text("", "utf-8")
        cases = {
            # Not the Starlette the dashboard was written for: the name it imports is not there.
            "broken": ("cannot import name 'Starlette'", {
                "modules": {"starlette.applications": types.ModuleType("starlette.applications")},
            }),
            # Jinja2 is there and what it imports itself is not.
            "transitive": ("No module named 'markupsafe'", {
                "gone": ("markupsafe",), "anew": ("jinja2",),
            }),
            # An absent library is not what failed: installing it would leave this cause.
            "transitive, another absent": ("No module named 'markupsafe'", {
                "absent": ("uvicorn",), "gone": ("markupsafe",), "anew": ("jinja2",),
            }),
            # A file of that name comes before the library on sys.path.
            "shadowed": ("'starlette' is not a package", {"anew": ("starlette",), "path": shadow}),
        }  # fmt: skip
        for label, (cause, state) in cases.items():
            with self.subTest(label):
                self.assert_no_command(self.refusal(**state), cause,
                                       "what failed is not a web library missing from that Python")
