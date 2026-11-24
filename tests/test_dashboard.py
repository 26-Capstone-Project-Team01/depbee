"""Local history dashboard (SVC-07): pages, security, escaping and registration.

Synthetic only, inside each test run's folder (Fixture sets DEPBEE_HISTORY_DB there): reports
come from pipeline.scan() with fake detectors and predictor or from docs/examples, and are stored
with the history API. The Starlette TestClient talks to the app in-process; no server, browser,
npm or registry.
"""

import contextlib
import importlib.util
import io
import json
import os
import re
import sqlite3
import sys
import unittest
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

import test_mcp
from test_apply import ApplyFixture, sha
from test_detectors import ADVISORY, KnownList, Rules, rule
from test_markdown import HOSTILE
from test_output_formats import EXAMPLES, FormatFixture, older
from test_workflow import Fixture, package

from depbee import history, service
from depbee.cli import SAFETY_NOTE, _clean, main
from depbee.contracts import GuardError

WEB = all(importlib.util.find_spec(name) for name in ("starlette", "jinja2", "uvicorn", "httpx2"))
NO_WEB = "web extra ([web] and httpx2) not installed; the dashboard is not tested here"
PORT = 48213
BASE = f"http://127.0.0.1:{PORT}"
SESSION = "synthetic-session-value-for-tests-only-0123456789"
S = f"/s/{SESSION}"  # every page, form and link is under this prefix
# The one script element a page has: the file under the session, never a script of the page's own.
SCRIPT = f'<script src="{S}/static/app.js" defer></script>'
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
                     [{"src": f"{S}/static/app.js", "defer": None}])  # fmt: skip
    case.assertEqual([name for _, attrs in elements for name in attrs if name.startswith("on")],
                     [])  # fmt: skip


@unittest.skipUnless(WEB, NO_WEB)
class DashboardFixture(FormatFixture):
    def setUp(self):
        super().setUp()
        from starlette.testclient import TestClient

        from depbee.dashboard import app

        self.app = app
        self.client = TestClient(app.build_app(PORT, SESSION), base_url=BASE)
        self.addCleanup(self.client.close)
        self.db = Path(os.environ["DEPBEE_HISTORY_DB"])

    def get(self, url, **kwargs):
        return self.client.get(S + url, **kwargs)

    def page(self, url):
        response = self.get(url)
        self.assertEqual(response.status_code, 200, url)
        self.assertNotIn("set-cookie", response.headers)
        # Every link, form and file of the dashboard keeps the session prefix; the skip link
        # stays on the page it is on.
        for target in re.findall(r'(?:href|action|src)="([^"]*)"', response.text):
            if target != "#main" and not target.startswith("https://www.npmjs.com/package/"):
                self.assertTrue(target.startswith(S + "/"), target)
        assert_one_script(self, response.text)
        return response.text

    def record(self, report, kind="scan", preview=None):
        history.register_project(self.project)
        return history.record(kind, self.project, report, preview)

    def form_session(self):
        return re.search(r'name="session" value="([^"]+)"', self.page("/?manage=1")).group(1)

    def post(self, path, session=None, origin=BASE, **extra):
        fields = {"path": path} if session is None else {"path": path, "session": session}
        headers = {} if origin is None else {"origin": origin}
        return self.client.post(S + "/projects", data=fields, headers=headers,
                                follow_redirects=False, **extra)  # fmt: skip


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
        heads = re.findall(r"<h3>\[([^\]]+)\] ([^@<]+)@", text)
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
        self.assertIn(f'action="{S}/projects/1/previews"', form[0])
        self.assertIn(f'<input type="hidden" name="session" value="{SESSION}">', form[1])
        self.assertIn(f'<a href="{S}/projects/1">필터 초기화</a>', html)
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
            "error.html", "history.html", "inspector.html", "model.html", "mounted.html",
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
                         ['<script src="{{ base }}/static/app.js" defer>'] * 2)  # fmt: skip
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
            rf'<a class="tab" href="{re.escape(S)}/projects/{project_id}" title="[^"]*"([^>]*)>'
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
            for i in re.findall(rf'<a class="tab" href="{re.escape(S)}/projects/(\d+)"', html)
        ]
        self.assertEqual(order, [gone, flagged, held, fresh, passed])
        # Each line: the full path on hover, and the risk and hold counts of the newest run.
        self.assertIn(f'href="{S}/projects/{flagged}" title="{self.project.resolve()}"', html)
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
        medium = re.search(r"@media \(min-width: 46rem\) and \(max-width: 79\.99rem\) \{\n(.*?)\n\}", css, re.S)
        self.assertIn("  .tabs { flex-basis: 100%; }", medium.group(1))
        self.assertRegex(css, r"@media \(scripting: none\) and \(min-width: 46rem\) and "
                              r"\(max-width: 79\.99rem\) \{\n  \.tabs ul \{[^}]*\}\n  html \{ scroll-padding-block: 1rem; \}")  # fmt: skip
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
                order = re.findall(rf'<a class="tab" href="{re.escape(S)}/projects/(\d+)"', html)
                self.assertEqual(order, [str(odd), str(fresh)])
                self.assertEqual(self.tab(html, odd)[1:], ("none", "project", "최근 실행 알 수 없음"))
                self.assertEqual(self.tab(html, fresh)[1:], ("none", "fresh", "실행 기록 없음"))
                # The same mark, told apart in view by a word.
                line = html.split(f'href="{S}/projects/{odd}"', 1)[1].split("</a>", 1)[0]
                self.assertIn('<span class="tab-count"><span class="n-unknown" aria-hidden="true">'
                              "알 수 없음</span></span>", line)  # fmt: skip
                line = html.split(f'href="{S}/projects/{fresh}"', 1)[1].split("</a>", 1)[0]
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
            self.assertEqual(body[2][1], {"method": "post", "action": f"{S}/projects/pick"})
            self.assertEqual(body[3][1], {"type": "hidden", "name": "session", "value": SESSION})
            self.assertEqual(body[4][1]["type"], "submit")
            self.assertIn(">프로젝트 추가</button>", html)
            # What else the page says is for a screen reader only: what the button opens, and
            # the line the script speaks through.
            self.assertEqual([attrs["class"] for tag, attrs in body if tag == "p"],
                             ["visually-hidden"] * 2)  # fmt: skip
            self.assertEqual(body[4][1]["aria-describedby"], body[5][1]["id"])
            for absent in ("등록한 프로젝트", "프로젝트 0개", SAFETY_NOTE.replace("'", "&#39;")):
                self.assertNotIn(absent, html)
            self.assertIn("<title>프로젝트 추가 - depbee</title>", html)
        self.assertFalse(self.db.exists())  # looking creates no history
        # The tab icon comes from under the session: a browser then never asks for /favicon.ico.
        self.assertIn(f'<link rel="icon" type="image/svg+xml" href="{S}/static/icon.svg">', html)
        icon = self.get("/static/icon.svg")
        self.assertEqual((icon.status_code, icon.headers["content-type"]), (200, "image/svg+xml"))
        self.assertTrue(icon.text.startswith("<svg "))
        # The pages outside a project keep the console.
        model = self.page("/model")
        self.assertIn('<a class="skip" href="#main">본문으로 건너뛰기</a>', model)
        self.assertIn('<main id="main">', model)
        self.assertNotIn('<a class="tab" ', model)
        self.assertIn(f'<a href="{S}/model" aria-current="page">모델 정보</a>', model)
        self.assertNotIn(' aria-current="page">프로젝트 관리', model)
        # With a project the first page is the overview, and project management the place
        # where the next one is added by the dialog or by a typed path.
        history.register_project(self.project)
        self.assertIn("<title>프로젝트 현황판 - depbee</title>", self.page("/"))
        manage = self.page("/?manage=1")
        self.assertIn(f'<a class="tab manage" href="{S}/?manage=1" aria-current="page">프로젝트 관리</a>',
                      manage)  # fmt: skip
        self.assertIn(f'<form method="post" action="{S}/projects/pick">', manage)
        self.assertIn(f'<form method="post" action="{S}/projects">', manage)

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
        self.assertIn(f'<li><a href="{S}/projects/{flagged}">project</a></li>\n'
                      f'<li><a href="{S}/projects/{flagged}/history">기록</a></li>\n'
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
                rf'<form method="post" action="{S}/projects/{project}/previews" id="preview-project">(.*?)</form>',
                head,
                re.S,
            )
            self.assertIsNotNone(check, view)
            self.assertIn('name="packages" value="">업데이트 후보 확인</button>', check[1])
            # Only a check sent from the packages view comes back to its list (app._back).
            self.assertEqual('name="back"' in check[1], view == "", view)
            self.assertIn(f'<form method="post" action="{S}/projects/{project}/scans">', head)
            self.assertIn('data-busy-label="검사 중…">검사만</button>', head)
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
                    f'<a href="{S}/projects/{project}{other}"{current}>{text}<span class="view-count',
                    html,
                )
            if view:  # the views take GET only
                response = self.client.post(f"{S}/projects/{project}{view}",
                                            data={"session": SESSION}, headers={"origin": BASE})  # fmt: skip
                self.assertEqual(response.status_code, 405)
        history_page = self.page(f"/projects/{project}/history")
        self.assertIn("기록된 반영이 없습니다.", history_page)
        self.assertIn("기록된 실행이 없습니다.", history_page)
        self.assertIn(f'<a href="{S}/projects/{project}/updates">업데이트</a>', history_page)

    def test_a_missing_folder_keeps_its_history_and_says_where_to_go(self):
        project = history.register_project(self.project)
        run = history.record("scan", self.project, self.scan_with(0.9))
        self.head.unlink()
        self.project.rmdir()
        for view in ("", "/updates", "/history"):
            html = self.page(f"/projects/{project}{view}")
            self.assertIn('<p class="error">프로젝트 폴더를 찾을 수 없습니다.', html)
            self.assertIn(f'<a href="{S}/?manage=1">프로젝트 관리</a>에서 새로 등록하세요.', html)
            self.assertIn(f'<a href="{S}/projects/{project}/history">기록</a>에 그대로', html)
            for form in ("/previews", "/scans"):
                self.assertNotIn(form, html)
            # No button but the rail's theme one and the question marks of the explanations.
            self.assertEqual(
                html.count("<button"),
                html.count('<button type="submit" name="theme"') + html.count('class="help"'),
            )
        self.assertIn(f'<a href="{S}/runs/{run}">#{run}</a>', html)  # the history view
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
        session = "주소에 이번 실행의 세션 값이 들어 있으니 다른 사람에게 보이지 않게 합니다."
        always = (SAFETY_NOTE, session)
        shown = {
            "unchecked": always + ("미확인은 확인된 후보 0개와 다릅니다",),
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
                             "이 화면에서는 반영하지 않습니다.", "미확인은 확인된 후보 0개와 다릅니다"):  # fmt: skip
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
        self.assertIn("미확인은 확인된 후보 0개와 다릅니다.", unchecked)
        self.assertRegex(unchecked, r'(?s)<div class="help-pop" id="[\w-]+" popover>'
                                    r"(?:(?!</div>).)*확인은 몇 초에서 수십 초 걸립니다")  # fmt: skip
        # The buttons each page names are the ones its head has.
        self.assertNotIn("전체 업데이트 확인", self.page(f"{self.packages}/history"))

    def test_a_gone_folder_without_a_run_names_no_button(self):
        moved = self.project.with_name(self.project.name + "-moved")
        self.project.rename(moved)
        try:
            history_html = self.page(f"{self.packages}/history")
        finally:
            moved.rename(self.project)
        self.assertIn("기록된 실행이 없습니다.", history_html)
        self.assertNotIn('위의 "업데이트 후보 확인"', history_html)
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
                          f'aria-label="{name} 업데이트 후보 확인">후보 확인</button>',
                          cells[f"node_modules/{name}"])  # fmt: skip
        self.assertIn("</span>미확인</span>", cells["node_modules/example/node_modules/inner"])
        self.assertNotIn("후보 없음", "".join(cells.values()))
        self.assertNotIn("1.2.0", "".join(cells.values()))

    def test_a_first_look_says_nothing_was_checked_and_runs_nothing(self):
        services = [mock.patch.object(service, name) for name in
                    ("preview_files", "scan_project", "apply_preview", "check_package")]  # fmt: skip
        mocks = [patcher.start() for patcher in services]
        for patcher in services:
            self.addCleanup(patcher.stop)
        html = self.page(self.packages)
        self.assertIn("업데이트 후보는 아직 확인하지 않았습니다.", html)
        self.assert_unchecked(self.cells(html))
        updates = self.page(self.updates)
        self.assertIn("아직 업데이트를 확인하지 않았습니다.", updates)
        self.assertNotIn('class="stack candidates"', updates)
        self.assertNotIn("열려 있는 미리보기", updates)
        for view in ("/history", "?q=example&scope=direct"):
            self.page(self.packages + view)
        self.page("/")
        self.page("/model")
        self.assertEqual([called.call_count for called in mocks], [0, 0, 0, 0])
        self.assertEqual(history.list_runs(self.project_id), [])  # looking records nothing

    def test_a_check_of_everything_shows_its_candidates_and_covers_the_rest(self):
        run = self.check(targets=None)
        html = self.page(self.packages)
        self.assertIn("업데이트 후보 1개를 확인했습니다.", html)
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
        self.assertNotIn(f'href="{S}/runs/{run}#r0"', html.split('<aside class="inspector"')[0])
        for location in ("node_modules/other", "node_modules/example/node_modules/inner"):
            self.assertEqual(cells[location], '<span class="quiet">후보 없음</span>')
        self.assertNotIn("후보 확인</button>", html)
        updates = self.page(self.updates)
        self.assertIn("지금의 package.json과 package-lock.json으로 확인한 결과입니다. "
                      "바뀐 의존성 1개: 위험 1, 통과 0, 보류 0.", updates)  # fmt: skip
        self.assertRegex(updates, rf'확인한 실행: <a href="{S}/runs/{run}">#{run}</a> '
                                  r"\(\d{4}-\d\d-\d\d \d\d:\d\d UTC, 전체\)</p>")  # fmt: skip
        for text in (
            '<th scope="row">example<span class="where">node_modules/example</span></th>',
            '<td>1.1.0 <span aria-hidden="true">→</span><span class="visually-hidden">에서</span>'
            " 1.2.0</td>",
            "<td>0.900 (기준 이상)</td>",
            "<li>synthetic evidence</li>",
            f'<a href="{S}/runs/{run}#r0">실행 #{run}<span class="visually-hidden">의 example '
            "근거 전체</span></a>",
            '<a href="https://www.npmjs.com/package/example" rel="noreferrer noopener">',
            "릴리스 노트와 변경 내역 원문은 depbee가 수집하지 않으므로",
        ):  # fmt: skip
            self.assertIn(text, updates)
        self.assertIn('<section class="result flagged" id="r0">', self.page(f"/runs/{run}"))
        for view in (self.packages, self.updates):
            html = self.page(f"{view}?item={run}.0")
            self.assertIn(f'href="{S}{view}?item={run}.0#candidate-evidence"', html)
            self.assertEqual(html.count('id="candidate-evidence" tabindex="-1"'), 1)
            panel = html.split('<aside class="inspector"', 1)[1].split("</aside>", 1)[0]
            self.assertIn("node_modules/example", panel)
            self.assertIn("synthetic evidence", panel)

    def test_a_check_of_named_packages_covers_only_them(self):
        first = self.check(targets=["example"])
        cells = self.cells()
        self.assertIn("후보 버전 1.2.0,", cells["node_modules/example"])
        self.assertIn("후보 확인</button>", cells["node_modules/other"])  # not checked yet
        self.assertIn("미확인", cells["node_modules/example/node_modules/inner"])
        second = self.check(self.nothing(), targets=["other"], changed_count=0)
        cells = self.cells()
        self.assertIn("후보 버전 1.2.0,", cells["node_modules/example"])  # the older check stands
        self.assertEqual(cells["node_modules/other"], '<span class="quiet">후보 없음</span>')
        self.assertIn("미확인", cells["node_modules/example/node_modules/inner"])
        updates = self.page(self.updates)
        self.assertRegex(updates, rf'#{second}</a> \([^)]*, other\), <a href="{S}/runs/{first}">'
                                  rf"#{first}</a> \([^)]*, example\)</p>")  # fmt: skip
        self.assertIn("바뀐 의존성 1개: 위험 1, 통과 0, 보류 0.", updates)

    def test_the_newest_check_of_a_location_wins(self):
        self.check(targets=["example"])
        self.check(self.nothing(), targets=None, changed_count=0)  # later: nothing would change
        html = self.page(self.packages)
        self.assertEqual(set(self.cells(html).values()), {'<span class="quiet">후보 없음</span>'})
        self.assertRegex(html, r"\d\d:\d\d UTC에 확인했고 바뀌는 항목이 없었습니다.")
        updates = self.page(self.updates)
        self.assertIn("확인한 결과입니다. 바뀌는 항목이 없었습니다.", updates)
        self.assertNotIn('class="stack candidates"', updates)

    def test_results_of_changed_files_are_not_current_candidates(self):
        run = self.check(targets=None)
        current = self.head.read_bytes()
        for changed in (self.head, self.manifest):
            with self.subTest(changed=changed.name):
                before = changed.read_bytes()
                changed.write_bytes(before + b"\n")
                html = self.page(self.packages)
                self.assertIn("마지막 업데이트 확인 뒤에 package.json이나 package-lock.json이 "
                              "바뀌었습니다. 후보를 다시 확인하세요.", html)  # fmt: skip
                self.assert_unchecked(self.cells(html))
                updates = self.page(self.updates)
                self.assertRegex(updates, rf'마지막 업데이트 확인\(실행 <a href="{S}/runs/{run}">'
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
        self.assertIn("아직 업데이트를 확인하지 않았습니다.", self.page(self.updates))
        updates = self.page(f"/projects/{other_id}/updates")
        self.assertIn(f'<a href="{S}/runs/{run}">#{run}</a>', updates)
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
        self.assertRegex(updates, rf'실행 <a href="{S}/runs/{run}">#{run}</a>의 업데이트를 '
                                  r"[^<]* UTC에 반영했습니다. 반영한 뒤의 파일로는 아직")  # fmt: skip
        self.assertNotIn("그 결과는 현재 후보로 보지 않습니다.", updates)
        refused = history.record("update_preview", self.project, self.report, self.made_now(
            package_lock_sha256="3" * 64), apply=applied_document("refused", "project_changed"))  # fmt: skip
        updates = self.page(self.updates)
        self.assertIn(f'<a href="{S}/runs/{refused}">#{refused}</a>', updates)
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
        self.assertIn(f'href="{S}/runs/{run}#r1"', updates)
        self.assertIn("바뀐 의존성 2개: 위험 1, 통과 0, 보류 0, 삭제 1.", updates)
        # A later check of other alone would not remove it: that row goes, the added entry of
        # the check of everything stays.
        later = self.check(self.nothing(), targets=["other"], changed_count=0)
        self.assertEqual(self.cells()["node_modules/other"], '<span class="quiet">후보 없음</span>')
        updates = self.page(self.updates)
        self.assertIn('<span class="quiet">새로 추가</span>', updates)
        self.assertNotIn('<span class="quiet">삭제</span>', updates)
        self.assertIn("확인한 결과입니다. 바뀐 의존성 1개: 위험 1, 통과 0, 보류 0.", updates)
        self.assertRegex(updates, rf'#{later}</a> \([^)]*, other\), <a href="{S}/runs/{run}">'
                                  rf"#{run}</a> \([^)]*, 전체\)</p>")  # fmt: skip

    def test_a_check_of_everything_stands_after_many_checks_of_other_packages(self):
        everything = self.check(targets=None)
        for _ in range(12):  # more than any window of recent previews
            newest = self.check(self.nothing(), targets=["other"], changed_count=0)
        html = self.page(self.packages)
        self.assertIn("업데이트 후보 1개를 확인했습니다.", html)
        cells = self.cells(html)
        self.assertIn("후보 버전 1.2.0,", cells["node_modules/example"])
        self.assertIn(f'?item={everything}.0#candidate-evidence"', cells["node_modules/example"])
        for location in ("node_modules/other", "node_modules/example/node_modules/inner"):
            self.assertEqual(cells[location], '<span class="quiet">후보 없음</span>')
        updates = self.page(self.updates)
        self.assertIn("확인한 결과입니다. 바뀐 의존성 1개: 위험 1, 통과 0, 보류 0.", updates)
        self.assertIn('class="stack candidates"', updates)
        # Listed are the checks whose result is shown: the newest of other and the one of
        # everything, not the eleven checks of other that the newest one replaced.
        self.assertRegex(updates, rf'확인한 실행: <a href="{S}/runs/{newest}">#{newest}</a> '
                                  rf'\([^)]*, other\), <a href="{S}/runs/{everything}">'
                                  rf"#{everything}</a> \([^)]*, 전체\)</p>")  # fmt: skip

    def test_restored_files_have_their_candidates_again(self):
        self.check(targets=None)
        original = self.head.read_bytes()
        self.write(self.head, lock("1.0.0"))  # other files for a while, e.g. another branch
        for _ in range(12):  # checked there: nothing would change
            self.check(self.nothing(), targets=None, changed_count=0)
        html = self.page(self.packages)
        self.assertRegex(html, r"\d\d:\d\d UTC에 확인했고 바뀌는 항목이 없었습니다.")
        self.assertNotIn("1.2.0", "".join(self.cells(html).values()))
        self.head.write_bytes(original)  # the same bytes as when the first check ran
        self.assertIn("후보 버전 1.2.0,", self.cells()["node_modules/example"])
        updates = self.page(self.updates)
        self.assertIn("확인한 결과입니다. 바뀐 의존성 1개: 위험 1, 통과 0, 보류 0.", updates)
        self.assertNotIn("그 결과는 현재 후보로 보지 않습니다.", updates)

    def test_checks_of_named_packages_never_say_that_nothing_changes(self):
        self.check(self.nothing(), targets=["other"], changed_count=0)
        html, updates = self.page(self.packages), self.page(self.updates)
        self.assertIn("일부 패키지만 확인했고 그 패키지에는 업데이트 후보가 없었습니다. 나머지 "
                      "패키지는 미확인입니다.", html)  # fmt: skip
        cells = self.cells(html)
        self.assertEqual(cells["node_modules/other"], '<span class="quiet">후보 없음</span>')
        self.assertIn("후보 확인</button>", cells["node_modules/example"])
        self.assertIn("미확인", cells["node_modules/example/node_modules/inner"])
        self.assertIn("일부 패키지만 확인한 결과입니다. 확인한 패키지에는 업데이트 후보가 "
                      "없었습니다. 나머지 패키지는 미확인이며", updates)  # fmt: skip
        self.assertNotIn('class="stack candidates"', updates)
        for page in (html, updates):  # only a check of everything is evidence of that
            self.assertNotIn("바뀌는 항목이 없었습니다", page)
        self.check(targets=["example"])  # a candidate, still not a check of everything
        self.assertIn("일부 패키지만 확인했고 업데이트 후보 1개를 찾았습니다. 나머지 패키지는 "
                      "미확인입니다.", self.page(self.packages))  # fmt: skip
        self.assertIn("일부 패키지만 확인한 결과입니다. 바뀐 의존성 1개: 위험 1, 통과 0, 보류 0. "
                      "나머지 패키지는 미확인이며", self.page(self.updates))  # fmt: skip

    def test_projects_with_the_same_files_keep_their_own_candidates(self):
        twin = self.root / "twin"
        twin.mkdir()
        for name in ("package.json", "package-lock.json"):
            (twin / name).write_bytes((self.project / name).read_bytes())
        twin_id = history.register_project(twin)
        mine = self.check(targets=None)
        # The same two hashes, but the check was made in the other project.
        self.assertIn(
            "업데이트 후보는 아직 확인하지 않았습니다.", self.page(f"/projects/{twin_id}")
        )
        theirs = self.check(self.nothing(), project=twin, targets=None, changed_count=0)
        self.assertIn("확인했고 바뀌는 항목이 없었습니다.", self.page(f"/projects/{twin_id}"))
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
            self.assertIn(f'href="{S}/runs/{first}#r{position}"', updates)
        # A later check of the package named with the escape text alone: only that location
        # takes the new run's row.
        second = self.check({**self.report, "results": [row(text, "\\udc80x", "8.0.0", "8.2.0")]},
                            targets=["\\udc80x"])  # fmt: skip
        of_lone, of_text = cells()
        self.assertIn(f'?item={first}.0#candidate-evidence"', of_lone)
        self.assertIn("후보 버전 8.2.0,", of_text)
        self.assertIn(f'?item={second}.0#candidate-evidence"', of_text)
        updates = self.page(self.updates)
        self.assertIn(f'href="{S}/runs/{first}#r0"', updates)
        self.assertIn(f'href="{S}/runs/{second}#r0"', updates)
        self.assertNotIn(f'href="{S}/runs/{first}#r1"', updates)
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
        url = f"{S}{self.packages}"

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
            (f'a href="{url}?show=unchecked"', "미확인", "3"),
            ('span class="filter-off"', "후보 없음", "0")])  # fmt: skip
        self.assertIn("미확인은 확인된 후보 0개와 다릅니다.", html)
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
            ('span class="filter-off"', "미확인", "0"),
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
        self.assertIn("바뀌는 항목이 없었습니다. 확인된 후보 0개입니다.", html)
        self.assertNotIn("미확인은 확인된 후보 0개와 다릅니다.", html)
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
                self.assertIn(f"후보 버전 {shown}, 검사 근거 열기</span>", packages)  # the candidate
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
            for url in (S + "/", S + "/static/style.css", "/"):
                with self.subTest(host=host, url=url):
                    response = self.client.get(url, headers={"host": host},
                                               follow_redirects=False)  # fmt: skip
                    self.assertEqual(response.status_code, 400)
                    self.assert_headers(response)
                    self.assertNotIn("set-cookie", response.headers)

    def test_every_request_needs_the_session_prefix(self):
        wrong = SESSION[:-1] + ("A" if SESSION[-1] != "A" else "B")
        urls = [*self.URLS, f"/login?token={SESSION}", f"/s/{wrong}/", f"/s/{SESSION}",
                f"/s/{SESSION[:-1]}/", f"/s/{SESSION}x/", f"/s//{SESSION}/", f"/x/{SESSION}/",
                f"/S/{SESSION}/", "/s/", "/s", f"/s/{wrong}/static/style.css",
                f"/static/{SESSION}/style.css", f"/{SESSION}/", "/s/%C3%A9/"]  # fmt: skip
        for url in urls:
            with self.subTest(url=url):
                response = self.client.get(url, follow_redirects=False)
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.text, self.app.SESSION_REFUSED)  # fixed, no path
                self.assert_headers(response)
                self.assertNotIn("set-cookie", response.headers)
        # A cookie, even holding the session, is not a credential: the address is.
        self.client.cookies.set(f"depbee_session_{PORT}", SESSION)
        self.client.cookies.set("session", SESSION)
        for url in ("/", "/model"):
            self.assertEqual(self.client.get(url).status_code, 403, url)
        self.client.cookies.clear()
        self.assertEqual(self.client.get(S + "/", headers={"cookie": "x=1"}).status_code, 200)

    def test_the_session_prefix_opens_every_page_without_cookies(self):
        self.record(self.scan_with(0.1))
        for url in self.URLS:
            response = self.get(url)
            self.assertEqual(response.status_code, 200, url)
            self.assert_headers(response)
            self.assertNotIn("set-cookie", response.headers)
            self.assertEqual(len(self.client.cookies), 0)
        html = self.page("/")
        self.assertIn(f'<link rel="stylesheet" href="{S}/static/style.css">', html)
        self.assertIn(f'href="{S}/projects/1"', html)
        self.assertIn(f'href="{S}/static/overview.css"', html)
        manage = self.page("/?manage=1")
        self.assertIn(f'<form method="post" action="{S}/projects">', manage)
        self.assertIn(f'<input type="hidden" name="session" value="{SESSION}">', manage)
        self.assertEqual(self.get("/login").status_code, 404)  # no login step any more

    def test_npm_links_send_no_referrer(self):
        # The session is in the address; a link out must not carry it as a Referer.
        run = self.record(self.scan_with(0.9))
        html = self.page(f"/runs/{run}")
        links = re.findall(r"<a [^>]*>", html)
        npm = [link for link in links if "https://www.npmjs.com/package/" in link]
        self.assertTrue(npm)
        for link in npm:
            self.assertIn('rel="noreferrer noopener"', link)

    def test_post_needs_the_form_session_and_origin(self):
        form, path = self.form_session(), str(self.project)
        self.assertEqual(form, SESSION)
        refused = {
            "no form session": self.post(path),
            "wrong form session": self.post(path, form[:-1] + ("A" if form[-1] != "A" else "B")),
            "empty form session": self.post(path, ""),
            "no origin": self.post(path, form, origin=None),
            "other port": self.post(path, form, origin=f"http://127.0.0.1:{PORT + 1}"),
            "other host": self.post(path, form, origin=f"http://localhost:{PORT}"),
            "null origin": self.post(path, form, origin="null"),
            "https origin": self.post(path, form, origin=f"https://127.0.0.1:{PORT}"),
        }
        for label, response in refused.items():
            with self.subTest(label):
                self.assertEqual(response.status_code, 403)
                self.assert_headers(response)
                self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(refused["wrong form session"].text, self.app.FORM_REFUSED)
        self.assertEqual(history.list_projects(), [])
        # Without the prefix the request never reaches the form.
        response = self.client.post("/projects", data={"path": path, "session": form},
                                    headers={"origin": BASE})  # fmt: skip
        self.assertEqual(response.status_code, 403)
        self.assertEqual(history.list_projects(), [])
        # GET never changes state: the form's route takes POST only.
        self.assertEqual(self.get("/projects").status_code, 405)

    def test_a_post_that_the_browser_says_comes_from_elsewhere_is_refused(self):
        form, path = self.form_session(), str(self.project)

        def post(*sites):
            """The registration form, sent with these Sec-Fetch-Site headers and its Origin."""
            headers = [("origin", BASE), *(("sec-fetch-site", site) for site in sites)]
            return self.client.post(S + "/projects", data={"path": path, "session": form},
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
                                 (303, S + ("/projects/1" if number else "/")))  # fmt: skip
        # The header does not stand in for the Origin, and a page is opened from anywhere: its
        # address holds the session.
        refused = self.client.post(S + "/projects", data={"path": path, "session": form},
                                   headers={"sec-fetch-site": "same-origin"})  # fmt: skip
        self.assertEqual(refused.status_code, 403)
        for url in ("/", "/static/app.js", "/projects/1"):
            opened = self.client.get(S + url, headers={"sec-fetch-site": "cross-site"})
            self.assertEqual(opened.status_code, 200, url)

    def test_large_or_odd_bodies_are_refused(self):
        form = self.form_session()
        big = self.post("C:/" + "a" * (self.app.MAX_BODY + 1), form)
        self.assertEqual(big.status_code, 413)
        self.assert_headers(big)
        fields = "&".join(f"f{i}=1" for i in range(self.app.MAX_FIELDS + 1))
        response = self.client.post(S + "/projects", content=f"session={form}&{fields}",
                                    headers={"origin": BASE, "content-type":
                                             "application/x-www-form-urlencoded"})  # fmt: skip
        self.assertEqual(response.status_code, 400)
        response = self.client.post(S + "/projects", content=json.dumps({"session": form}),
                                    headers={"origin": BASE, "content-type": "application/json"})  # fmt: skip
        self.assertEqual(response.status_code, 415)
        self.assertEqual(history.list_projects(), [])

    def test_server_settings_and_the_one_line_with_the_session(self):
        from depbee.dashboard import app

        started = {}

        class Server:
            def __init__(self, config):
                started["config"] = config

            def run(self, sockets):
                (sock,) = sockets
                started["bound"] = sock.getsockname()

        out = io.StringIO()
        with mock.patch.object(app.uvicorn, "Server", Server), contextlib.redirect_stdout(out):
            app.serve(0)
        config, (host, port) = started["config"], started["bound"]
        self.assertEqual((host, config.host, config.port), ("127.0.0.1", "127.0.0.1", port))
        self.assertNotEqual(port, 0)
        self.assertEqual((config.access_log, config.server_header, config.proxy_headers,
                          config.log_level, config.lifespan, config.ws),
                         (False, False, False, "warning", "off", "none"))  # fmt: skip
        first, second = out.getvalue().splitlines()
        self.assertRegex(first, rf"\Ahttp://127\.0\.0\.1:{port}/s/[A-Za-z0-9_-]{{43}}/\Z")
        session = first.split("/")[4]
        self.assertNotIn(session, second)
        code, err = None, io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["dashboard", "--port", "70000"])
        self.assertEqual(code, 2)
        self.assertIn("--port must be between 0 and 65535", err.getvalue())

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
        self.assertIn(f'<a class="tab manage" href="{S}/?manage=1">프로젝트 관리</a>',
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

        client = TestClient(self.app.build_app(PORT, SESSION), base_url=BASE,
                            raise_server_exceptions=False)  # fmt: skip
        self.addCleanup(client.close)
        marker = "C:\\private\\folder\\history.sqlite3 synthetic-secret-0123456789"
        with mock.patch.object(history, "list_projects", side_effect=RuntimeError(marker)):
            response = client.get(S + "/")
        self.assertEqual(response.status_code, 500)
        self.assert_headers(response)
        self.assertEqual(
            response.text, "요청을 처리하지 못했습니다(이력 데이터베이스나 파일을 읽지 못함)."
        )
        exposed = response.text + "".join(f"{k}: {v}" for k, v in response.headers.items())
        for secret in (marker, "private", "synthetic-secret", "RuntimeError", SESSION):
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
        self.assertNotRegex(html, r'href="(?!/|#main"|https://www\.npmjs\.com/package/)')
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
    def register(self, path):
        return self.post(path, self.form_session())

    def assert_refused(self, path, message):
        response = self.register(path)
        self.assertEqual(response.status_code, 400, path)
        self.assertIn(message, response.text)
        if len(path) > 10:  # short ones such as "project" are words of the page itself
            self.assertNotIn(path, response.text)  # the input is not echoed
        self.assertEqual(history.list_projects(), [])

    def test_register_and_register_again(self):
        response = self.register(str(self.project))
        # The first project of all opens the overview; the same folder again, its own project.
        self.assertEqual((response.status_code, response.headers["location"]), (303, S + "/"))
        again = self.post(str(self.project) + os.sep, self.form_session())
        self.assertEqual(again.headers["location"], S + "/projects/1")
        (project,) = history.list_projects()
        self.assertEqual(project["path"], str(self.project.resolve()))
        projects = self.page("/?manage=1")
        self.assertIn(str(self.project.resolve()), projects)
        # Both lines name the dashboard's buttons as well as the CLI.
        self.assertIn('등록한 뒤 프로젝트 화면의 "검사만"이나 "업데이트 확인"으로', projects)
        self.assertIn('기록된 실행이 없습니다. 프로젝트 화면의 "검사만"이나 "업데이트', projects)
        self.assertIn("CLI로 실행한 depbee scan·depbee update 검사도 기록됩니다.", projects)

    def test_refused_paths(self):
        cases = [
            ("project", "절대 경로를 입력하세요."),
            (os.path.join("..", "project"), "절대 경로를 입력하세요."),
            (str(self.root / "missing"), "폴더를 찾을 수 없습니다."),
            (str(self.head), "폴더를 찾을 수 없습니다."),
            (str(self.root), "폴더에 package-lock.json 파일이 없습니다."),
            ("", "로컬 폴더 경로가 아닙니다"),
            ("\\\\server\\share\\project", "로컬 폴더 경로가 아닙니다"),
            ("//server/share/project", "로컬 폴더 경로가 아닙니다"),
            ("\\\\.\\pipe\\x", "로컬 폴더 경로가 아닙니다"),
            ("\\\\?\\C:\\project", "로컬 폴더 경로가 아닙니다"),
            ("/dev/stdin", "로컬 폴더 경로가 아닙니다"),
            ("C:/" + "a" * self.app.MAX_PATH, "경로가 너무 깁니다"),
        ]
        if os.name == "nt":
            cases += [(str(self.root / "CON"), "로컬 폴더 경로가 아닙니다"),
                      (str(self.project / "nul.txt"), "로컬 폴더 경로가 아닙니다"),
                      ("\\project", "절대 경로를 입력하세요."),
                      ("C:project", "절대 경로를 입력하세요.")]  # fmt: skip
        (self.root / "lock-dir" / "package-lock.json").mkdir(parents=True)
        cases.append((str(self.root / "lock-dir"), "폴더에 package-lock.json 파일이 없습니다."))
        for path, message in cases:
            with self.subTest(path=path[:40]):
                self.assert_refused(path, message)

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
        with mock.patch.object(self.app, "_registration_problem", return_value="link"):
            response = self.register(str(self.project))
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

    def check(self, packages="", session=SESSION, origin=BASE, project_id=None):
        url = f"{S}/projects/{project_id or self.project_id}/previews"
        headers = {} if origin is None else {"origin": origin}
        return self.client.post(url, data={"session": session, "packages": packages},
                                headers=headers, follow_redirects=False)  # fmt: skip

    def preview_id(self, packages=""):
        response = self.check(packages)
        self.assertEqual(response.status_code, 303, response.text)
        location = response.headers["location"]
        self.assertTrue(location.startswith(f"{S}/previews/"), location)
        return location.rsplit("/", 1)[1]

    def apply(self, preview_id, mode="lockfile", confirm=True, session=SESSION, origin=BASE):
        data = {"session": session, "mode": mode, **({"confirm": "yes"} if confirm else {})}
        headers = {} if origin is None else {"origin": origin}
        return self.client.post(f"{S}/previews/{preview_id}/apply", data=data, headers=headers,
                                follow_redirects=False)  # fmt: skip

    def assert_form(self, html, present):
        (self.assertIn if present else self.assertNotIn)(
            '<button type="submit" data-busy-label="반영 중…">반영</button>', html
        )

    def assert_stopped(self, response, status, message):
        """A request that ran nothing: the fixed message on a page that still has the tabs, so
        there is a way on; it is not said to be a failed run."""
        self.assertEqual(response.status_code, status)
        self.assertIn(f'<p class="error">{message}</p>', response.text)
        self.assertIn(f'<a class="tab" href="{S}/projects/{self.project_id}"', response.text)
        self.assertNotIn("이력에 기록하지 않았습니다.", response.text)


class UpdateCheckTests(ScreenFixture):
    def test_a_check_is_recorded_kept_in_memory_and_shown(self):
        from starlette.testclient import TestClient

        client = TestClient(self.app.build_app(PORT, SESSION, model_dir=Path("m"),
                                               cache_dir=Path("c")), base_url=BASE)  # fmt: skip
        self.addCleanup(client.close)
        self.client = client
        project_page = self.page(f"/projects/{self.project_id}")
        self.assertIn(f'action="{S}/projects/{self.project_id}/previews"', project_page)
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
        self.assertIn(f'<a href="{S}/runs/{run["id"]}">실행 #{run["id"]}</a>', html)
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
            self.assertEqual(main(["dashboard", "--model-dir", "m", "--no-cache"]), 0)
            self.assertEqual(main(["dashboard", "--cache-dir", "c"]), 0)
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
        self.assertIn("업데이트를 확인할 수 없습니다", updates)
        self.assertNotIn("/previews", updates + self.page(f"/projects/{self.project_id}"))
        self.assertEqual(self.preview_files.call_count, 0)

    def test_form_session_origin_and_limits(self):
        for response in (self.check(session="wrong"), self.check(origin=None),
                         self.check(origin=f"http://127.0.0.1:{PORT + 1}")):  # fmt: skip
            self.assertEqual(response.status_code, 403)
        too_long = self.check("a" * (self.app.MAX_TARGETS + 1))
        self.assertEqual(too_long.status_code, 400)
        self.assertIn(self.app.TARGETS_TOO_LONG, too_long.text)
        url = f"{S}/projects/{self.project_id}/previews"
        two = self.client.post(url, content=f"session={SESSION}&packages=a&packages=b",
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
        self.assertNotIn(f"{S}/runs/", html)
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
        self.assertNotIn("열려 있는 미리보기", self.page(self.updates))
        preview_id = self.preview_id("example")
        (run,) = history.list_runs(self.project_id)
        html = self.page(self.updates)
        self.assertRegex(html, rf'<li><a href="{S}/previews/{preview_id}">[^<]* UTC 미리보기 열기'
                               rf'</a> \(실행 #{run["id"]}\)')  # fmt: skip
        self.assertIn("<li>대상: example</li>", html)
        self.assertNotIn("반영을 시도하면 거부됩니다", html)
        # The recorded check is the current candidate, linked to its report.
        self.assertIn(f'href="{S}/runs/{run["id"]}#r0"', html)
        self.assertIn(f'href="{S}/runs/{run["id"]}#r0"', self.page(f"/projects/{self.project_id}"))
        self.assertNotIn(preview_id, self.page(f"/projects/{other_id}/updates"))
        # Files changed after the preview: it stays listed, said to be refused if applied.
        before = self.head.read_bytes()
        self.head.write_bytes(before + b"\n")
        html = self.page(self.updates)
        self.assertIn(f'href="{S}/previews/{preview_id}"', html)
        self.assertIn("반영을 시도하면 거부됩니다. 업데이트 확인을 다시 실행하세요.", html)
        self.assertNotIn(f"/runs/{run['id']}#r0", html)
        self.head.write_bytes(before)
        self.assertEqual(self.apply(preview_id).status_code, 200)
        self.assertNotIn("열려 있는 미리보기", self.page(self.updates))

    def test_an_unrecorded_preview_is_listed_without_a_run(self):
        with mock.patch.object(history, "record", return_value=None):
            preview_id = self.preview_id()
        html = self.page(self.updates)
        self.assertRegex(
            html, rf'<a href="{S}/previews/{preview_id}">[^<]* UTC 미리보기 열기</a>\n'
        )
        self.assertIn("<li>대상: package.json 범위 안의 전체 의존성</li>", html)
        self.assertNotIn(f"{S}/runs/", html)
        self.assertIn("아직 업데이트를 확인하지 않았습니다.", html)  # nothing stored to show


class CheckReturnTests(ScreenFixture):
    """A check sent from the packages view comes back to that list, at the first candidate it
    returned among the rows the view's search and filter leave. The project installs example
    and other (direct) and inner (under example); the faked preview names the project's two
    files as they are, and returns a candidate for each name given to returns()."""

    LOCATIONS = {"example": "node_modules/example", "other": "node_modules/other",
                 "inner": "node_modules/example/node_modules/inner"}  # fmt: skip

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

    def send(self, back, packages=""):
        """The packages view's check form: back is the view it was sent from (a list is the
        field given more than once)."""
        fields = [("session", SESSION), ("packages", packages),
                  *(("back", value) for value in ([back] if isinstance(back, str) else back))]  # fmt: skip
        return self.client.post(f"{S}{self.packages}/previews", content=urlencode(fields),
                                headers={"origin": BASE, "content-type":
                                         "application/x-www-form-urlencoded"},
                                follow_redirects=False)  # fmt: skip

    def landed(self, back, packages=""):
        """(run, the address the check came back to without the session prefix): this project's
        packages view, with the run, at the candidate it opens or at the line that says there
        is none to open."""
        response = self.send(back, packages)
        self.assertEqual(response.status_code, 303, response.text)
        run = history.list_runs(self.project_id, 1)[0]["id"]
        location = response.headers["location"]
        self.assertTrue(location.startswith(f"{S}{self.packages}?"), location)
        self.assertRegex(location, rf"[?&]checked={run}#(picked|check-status)$")
        return run, location.removeprefix(S)

    def context(self, url):
        template = mock.Mock(**{"render.return_value": "<html></html>"})
        with mock.patch.object(self.app.ENV, "get_template", return_value=template):
            self.assertEqual(self.get(url).status_code, 200, url)
        # The theme form's way back is the address itself, whatever the address holds.
        return {k: v for k, v in template.render.call_args.kwargs.items() if k != "theme_back"}

    def inspector(self, url):
        """The inspector of the page at an address, as it is shown: the candidate that is open."""
        return re.search(r'<aside class="inspector" .*?</aside>', self.page(url), re.S)[0]

    def test_a_check_comes_back_to_the_view_it_was_sent_from(self):
        self.returns("other", "example")
        # Without the field (any other form): the preview's own page, as before.
        self.assertTrue(self.check().headers["location"].startswith(f"{S}/previews/"))
        # The search, the kind and the filter are kept. The item is the candidate the view
        # opens: example's (the report's second row) is the first that the list shows, whatever
        # was open before, and the address goes to it.
        for back, query in (
            ("", ""),
            # The check opened a candidate: the tab is dropped, as a tab of unchecked rows
            # would no longer list the row just checked.
            ("q=ex&scope=direct&show=candidates&item=3.0", "q=ex&scope=direct&"),
            ("show=unchecked&q=ex", "q=ex&"),
            ("scope=all&q=+", ""),  # nothing that narrows the list
        ):
            with self.subTest(back=back):
                run, url = self.landed(back)
                self.assertEqual(url, f"{self.packages}?{query}item={run}.1&checked={run}#picked")
        # A search that lists none of the candidates: the address goes to the line that says so.
        run, url = self.landed("q=%ED%95%9C%EA%B8%80+x&")
        self.assertEqual(url, f"{self.packages}?q=%ED%95%9C%EA%B8%80+x&checked={run}#check-status")
        # It opened none: the tab it was sent from stays (the view shows all when that is empty).
        run, url = self.landed("q=%ED%95%9C%EA%B8%80+x&show=none")
        self.assertEqual(
            url, f"{self.packages}?q=%ED%95%9C%EA%B8%80+x&show=none&checked={run}#check-status"
        )
        # The address is always this project's packages view, built from what that view reads
        # of the field and never from the field's text: what the view would refuse, a value
        # that is no query of it, or a field given twice is the view without a filter.
        for back in ("scope=evil&q=x", "q=" + "x" * 215, "show=evil&q=x", "q=a&q=b",
                     "//evil.test/x", "https://evil.test/?q=x", f"../../{SESSION}/model",
                     "item=" + "9" * 41, "item=1.0&item=2.0", ["q=ex", "only=1"]):  # fmt: skip
            with self.subTest(back=str(back)[:30]):
                run, url = self.landed(back)
                self.assertEqual(url, f"{self.packages}?item={run}.1&checked={run}#picked")
        # Every one of these checks is held and recorded, and none of them applied anything.
        self.assertEqual(len(history.list_runs(self.project_id)), len(self.previewed))
        self.assertEqual(self.apply_preview.call_count, 0)
        self.assertEqual(history.list_applies(self.project_id), [])

    def test_a_check_that_was_not_recorded_or_failed_ends_where_it_did_before(self):
        self.returns("example")
        with mock.patch.object(history, "record", return_value=None):
            unrecorded = self.send("q=ex")
        # No run to come back to: the preview's page is the only place its result is.
        self.assertEqual(unrecorded.status_code, 303)
        self.assertTrue(unrecorded.headers["location"].startswith(f"{S}/previews/"))
        self.preview_files.side_effect = GuardError("synthetic failure")
        failed = self.send("q=ex")
        self.assertEqual(failed.status_code, 400)
        self.assertIn('<p class="error">synthetic failure</p>', failed.text)
        self.assertEqual(self.send("q=ex", "a" * (self.app.MAX_TARGETS + 1)).status_code, 400)
        self.assertEqual(history.list_runs(self.project_id), [])

    def test_the_list_opens_the_first_candidate_the_check_returned_among_its_rows(self):
        self.returns("other", "example")  # the report's order; the list is by location
        run, url = self.landed("")
        context = self.context(url)
        returned = context["returned"]
        self.assertEqual({key: returned[key] for key in ("id", "full", "count")},
                         {"id": run, "full": True, "count": 2})  # fmt: skip
        self.assertEqual((returned["first"]["package"], returned["first"] is context["selected"]),
                         ("example", True))  # fmt: skip
        html = self.page(url)
        self.assertIn('<p class="state" id="check-status" tabindex="-1" data-landing="picked">',
                      html)  # fmt: skip
        self.assertIn(f"실행 #{run}에서 후보 2개를 확인했습니다. 목록에서 그 첫 후보를 열었습니다: "
                      "example. 자동으로 반영하지 않습니다.", html)  # fmt: skip
        self.assertRegex(html, rf'<a class="pick" id="picked" aria-current="true" href="{S}'
                               rf'{self.packages}\?item={run}\.1#candidate-evidence">')  # fmt: skip
        # The check's preview is still held, one link away: it is where an apply is decided.
        (preview_id,) = set(re.findall(rf'href="{S}/previews/([^"]+)"', html))
        self.assertIn(f'<a class="action" href="{S}/previews/{preview_id}">이 확인의 미리보기 열기'
                      "</a>", html)  # fmt: skip
        self.assertIn("이 화면에서는 반영하지 않습니다.", html)
        self.assertEqual(self.apply_preview.call_count, 0)
        # The search the check was sent with decides which returned candidate is the first.
        run, url = self.landed("q=oth")
        self.assertEqual((url, self.context(url)["selected"]["package"]),
                         (f"{self.packages}?q=oth&item={run}.0&checked={run}#picked", "other"))  # fmt: skip
        # No returned candidate among the rows: the line says so, and is where the focus goes.
        run, url = self.landed("q=inner")
        self.assertEqual(url, f"{self.packages}?q=inner&checked={run}#check-status")
        context = self.context(url)
        self.assertEqual((context["returned"]["count"], context["returned"]["first"],
                          context["selected"]), (2, None, None))  # fmt: skip
        html = self.page(url)
        self.assertIn('id="check-status" tabindex="-1" data-landing="status">', html)
        self.assertIn(f"실행 #{run}에서 후보 2개를 확인했지만 지금 검색과 필터로는 목록에 보이지 "
                      f'않습니다. <a href="{S}{self.packages}">필터 초기화</a>', html)  # fmt: skip
        self.assertNotIn('id="picked"', html)

    def test_a_check_that_returned_nothing_keeps_the_candidate_that_was_open(self):
        self.returns("other")
        first, url = self.landed("", "other")
        key = f"{first}.0"
        self.assertEqual((url, self.context(url)["selected"]["package"]),
                         (f"{self.packages}?item={key}&checked={first}#picked", "other"))  # fmt: skip
        # A check of example alone, sent while other is open: its candidate is opened instead,
        # and it is the one the address names.
        self.returns("example")
        second, url = self.landed(f"item={key}", "example")
        context = self.context(url)
        self.assertEqual((url, context["selected"]["package"], context["returned"]["full"]),
                         (f"{self.packages}?item={second}.0&checked={second}#picked", "example",
                          False))  # fmt: skip
        # A check of inner alone finds nothing: the open candidate stays open, and the line
        # says that this check has none. Nothing says that nothing would change at all.
        self.returns()
        third, url = self.landed(f"item={key}", "inner")
        context = self.context(url)
        self.assertEqual((url, context["selected"]["package"], context["returned"]),
                         (f"{self.packages}?item={key}&checked={third}#check-status", "other",
                          {"id": third, "full": False, "count": 0, "first": None}))  # fmt: skip
        html = self.page(url)
        self.assertIn('data-landing="status">', html)
        self.assertIn(f"실행 #{third}에서 확인한 패키지에는 업데이트 후보가 없었습니다.", html)
        self.assertNotIn("바뀌는 항목이 없었습니다", html)
        # A check of everything that finds nothing says so, and that it is 0, not unknown.
        fourth, url = self.landed("")
        self.assertEqual(url, f"{self.packages}?checked={fourth}#check-status")
        html = self.page(url)
        self.assertIn(f"실행 #{fourth}에서 확인했고 바뀌는 항목이 없었습니다. 확인된 후보 "
                      "0개입니다.", html)  # fmt: skip
        self.assertIn(
            '<span class="filter-off">후보 <span class="filter-count">0</span></span>', html
        )

    def test_a_check_with_nothing_to_open_goes_to_its_line_not_to_the_candidate_left_open(self):
        """The browser follows the fragment of the address a check comes back to, with the
        script or without it. The candidate an earlier check left open keeps its link on the
        page, so that link must not be where the address of a check with nothing to open goes."""
        self.returns("other")
        first, _ = self.landed("", "other")
        item = f"item={first}.0"
        for returned, back, said in (
            # example alone, and nothing would change for it.
            ((), item, "확인한 패키지에는 업데이트 후보가 없었습니다."),
            # example alone has a candidate now, which the search of the view it was sent from
            # leaves out.
            (("example",), f"q=oth&{item}", "후보 1개를 확인했지만 지금 검색과 필터로는 목록에 "
                                           "보이지 않습니다."),
        ):  # fmt: skip
            with self.subTest(back=back):
                self.returns(*returned)
                run, url = self.landed(back, "example")
                self.assertEqual(url, f"{self.packages}?{back}&checked={run}#check-status")
                html = self.page(url)
                # The line is the landing, and it can take the focus the fragment gives it.
                self.assertIn('<p class="state" id="check-status" tabindex="-1" '
                              'data-landing="status">', html)  # fmt: skip
                self.assertIn(f"실행 #{run}에서 {said}", html)
                # other's candidate is still the open one, in the one link with that id.
                self.assertEqual(html.count('id="picked"'), 1)
                self.assertIn("<strong>other</strong>", self.inspector(url))

        # The lockfile changes while a check runs: that check is one of other files, and so is
        # every check before it. The address goes to the line, which says to check again.
        def changed_meanwhile(project, names, **options):
            result = self.fake_preview(project, names, **options)
            self.head.write_bytes(self.head.read_bytes() + b"\n")
            return result

        self.preview_files.side_effect = changed_meanwhile
        run, url = self.landed(item, "example")
        self.assertEqual(url, f"{self.packages}?{item}&checked={run}#check-status")
        html = self.page(url)
        self.assertIn("바뀌었습니다. 후보를 다시 확인하세요.", html)
        self.assertNotIn("data-landing", html)
        self.assertNotIn('id="picked"', html)

    def test_the_address_a_check_comes_back_to_opens_the_same_candidate_when_asked_again(self):
        """A reload, a way back or a way forward asks for the address again: as the check came
        back to it (without the script), or without the run and the fragment, which app.js
        takes off once the focus is there. Both show the candidate the check returned, under
        the same search and kind, and not the one that was open when the check was sent."""
        self.returns("other")
        first, _ = self.landed("", "other")
        self.returns("example")
        self.report["results"][0]["after_version"] = "1.9.0"  # not the version other would get
        run, url = self.landed(f"q=e&scope=direct&item={first}.0", "example")
        later = f"{self.packages}?q=e&scope=direct&item={run}.0"
        self.assertEqual(url, f"{later}&checked={run}#picked")
        shown = self.inspector(url)
        self.assertIn('<p class="subject"><strong>example</strong> <span class="where">'
                      "node_modules/example</span></p>", shown)  # fmt: skip
        self.assertIn("<div><dt>사용 버전</dt><dd>1.0.0</dd></div>\n"
                      "<div><dt>후보 버전</dt><dd>1.9.0</dd></div>", shown)  # fmt: skip
        # The package, the location, the versions and every line of evidence are the same.
        self.assertEqual(self.inspector(later), shown)
        html = self.page(later)
        self.assertIn('value="e" placeholder="패키지 검색">', html)
        self.assertIn('<option value="direct" selected>', html)
        # Without the run nothing is said of a check: nothing to announce or to focus again.
        self.assertNotIn("data-landing", html)
        # The view shows the candidate its address names and no other. With the one that was
        # open when the check was sent as the item, that one is shown, and nothing is said of
        # a check whose first candidate is not the one on the screen.
        before = f"{self.packages}?q=e&scope=direct&item={first}.0&checked={run}"
        self.assertIn("<strong>other</strong>", self.inspector(before))
        self.assertNotIn("data-landing", self.page(before))

    def test_a_run_that_is_no_current_check_of_the_project_is_as_no_run_at_all(self):
        self.returns("example", "other")
        run, _ = self.landed("")
        twin = self.root / "twin"
        twin.mkdir()
        for name in ("package.json", "package-lock.json"):
            (twin / name).write_bytes((self.project / name).read_bytes())
        twin_id = history.register_project(twin)
        foreign = history.record("update_preview", twin, self.report, {
            **PREVIEW, "targets": None, "package_json_sha256": sha(self.manifest.read_bytes()),
            "package_lock_sha256": sha(self.head.read_bytes())})  # fmt: skip
        plain = self.context(self.packages)
        self.assertIsNone(plain["returned"])
        for query in (f"checked={foreign}", "checked=999", "checked=", "checked=x",
                      f"checked={run}&checked={run}", f"checked=0{run}", f"checked={run}.0",
                      f"checked=+{run}", "checked=" + "9" * 5000):  # fmt: skip
            with self.subTest(query=query[:30]):
                self.assertEqual(self.context(f"{self.packages}?{query}"), plain)
        self.assertNotIn("data-landing", self.page(f"{self.packages}?checked=999"))
        self.assertIsNone(self.context(f"/projects/{twin_id}?checked={run}")["returned"])
        # Once the files change, the check is one of other files: nothing is said of it.
        self.head.write_bytes(self.head.read_bytes() + b"\n")
        context = self.context(f"{self.packages}?checked={run}")
        self.assertEqual((context["returned"], context["selected"]), (None, None))
        self.assertNotIn("data-landing", self.page(f"{self.packages}?checked={run}"))

    def test_the_form_says_which_view_it_is_sent_from_and_what_its_buttons_do_meanwhile(self):
        self.returns("example")
        run, _ = self.landed("")
        html = self.page(f"{self.packages}?q=ex&scope=direct&show=candidates")
        form = re.search(r'<form [^>]*id="preview-project"[^>]*>(.*?)</form>', html, re.S)[1]
        self.assertIn(f'<input type="hidden" name="session" value="{SESSION}">', form)
        self.assertIn('<input type="hidden" name="back" value="q=ex&amp;scope=direct&amp;show=candidates'
                      f'&amp;item={run}.0">', form)  # fmt: skip
        self.assertIn('<button class="primary" type="submit" data-busy-label="후보 확인 중…" '
                      'name="packages" value="">업데이트 후보 다시 확인</button>', form)  # fmt: skip
        # With the button's own field: three, within what a form may send (MAX_FIELDS).
        self.assertEqual(form.count("<input "), 2)
        self.assertLess(form.count("<input "), self.app.MAX_FIELDS)
        # Before the first check the button says so, and the view without a filter is empty.
        self.head.write_bytes(self.head.read_bytes() + b"\n")
        html = self.page(self.packages)
        self.assertIn('<input type="hidden" name="back" value="">', html)
        self.assertIn('name="packages" value="">업데이트 후보 확인</button>', html)
        # Every button that starts a request that takes time says what it turns into while
        # that request runs (app.js); a search and a typed path are at once and say nothing.
        pages = (html, self.page(f"{self.packages}/updates"),
                 self.page(f"/previews/{self.preview_id()}"), self.page("/?manage=1"))  # fmt: skip
        labels = {label for page in pages for label in re.findall(
            r'<button [^>]*data-busy-label="([^"]+)"[^>]*>', page)}  # fmt: skip
        self.assertEqual(labels, {"후보 확인 중…", "검사 중…", "반영 중…",
                                  "폴더 선택 창을 확인하세요…"})  # fmt: skip
        for page in pages:
            for button in re.findall(r"<button [^>]*>[^<]*</button>", page):
                timed = "data-busy-label" in button
                self.assertEqual(timed, not re.search(r">(검색|등록)</button>", button), button)


class ScanScreenTests(ScreenFixture):
    """The project page's scan-only button with service.scan_project replaced."""

    def setUp(self):
        super().setUp()
        self.scanned = []
        self.scan_project = self.patch_service("scan_project", self.fake_scan)

    def fake_scan(self, project, base_lock=None, **options):
        self.scanned.append((project, base_lock, options))
        return self.report

    def scan(self, session=SESSION, origin=BASE, project_id=None):
        headers = {} if origin is None else {"origin": origin}
        return self.client.post(f"{S}/projects/{project_id or self.project_id}/scans",
                                data={"session": session}, headers=headers,
                                follow_redirects=False)  # fmt: skip

    def test_a_scan_against_head_with_extraction_is_recorded_and_shown(self):
        from starlette.testclient import TestClient

        self.client = TestClient(self.app.build_app(
            PORT, SESSION, model_dir=Path("m"), cache_dir=Path("c"),
            known_malicious_dir=Path("k")), base_url=BASE)  # fmt: skip
        self.addCleanup(self.client.close)
        project_page = self.page(f"/projects/{self.project_id}/updates")
        self.assertIn(f'action="{S}/projects/{self.project_id}/scans"', project_page)
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
        self.assertEqual(response.headers["location"], f"{S}/runs/{run['id']}")
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
                self.assertNotIn(f"{S}/runs/", response.text)
                self.assertIn(f'href="{S}/projects/{self.project_id}"', response.text)
        self.assertEqual(history.list_runs(self.project_id), [])

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

    def test_form_session_and_origin(self):
        for response in (self.scan(session="wrong"), self.scan(origin=None),
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
        self.assertEqual(self.apply(preview_id, session="wrong").status_code, 403)
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
        self.assertIn(f'<a href="{S}/runs/{run["id"]}">실행 #{run["id"]}</a>에 반영 기록', html)
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
        self.assertIn(f'<a href="{S}/runs/{run["id"]}">#{run["id"]}</a>', project_page)

    def test_a_failed_apply_record_still_shows_the_result_and_backup(self):
        preview_id = self.preview_id()
        with mock.patch.object(history, "record_apply", side_effect=sqlite3.OperationalError("x")):
            response = self.apply(preview_id)
        self.assertEqual(response.status_code, 200)
        self.assertIn("업데이트 반영: 반영함", response.text)
        self.assertIn(f"원본 백업: {BACKUP}", response.text)
        self.assertIn(self.app.APPLY_NOT_RECORDED, response.text)
        self.assertEqual(history.list_applies(self.project_id), [])

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
    """The real service with the fake npm of test_apply: check, confirm and apply a lockfile."""

    def test_check_and_apply_through_the_dashboard(self):
        from starlette.testclient import TestClient

        from depbee.dashboard import app

        client = TestClient(app.build_app(PORT, SESSION, model_dir=self.root), base_url=BASE)
        self.addCleanup(client.close)
        project_id = history.register_project(self.upd)
        response = client.post(f"{S}/projects/{project_id}/previews",
                               data={"session": SESSION, "packages": "example"},
                               headers={"origin": BASE}, follow_redirects=False)  # fmt: skip
        self.assertEqual(response.status_code, 303, response.text)
        self.assert_unchanged()  # the preview changed nothing
        page = client.get(response.headers["location"])
        self.assertIn("확인이 필요한 항목 1개", page.text)  # FakePredictor flags it
        action = re.search(r'<form method="post" action="([^"]+/apply)">', page.text).group(1)
        applied = client.post(action, data={"session": SESSION, "mode": "lockfile",
                                            "confirm": "yes"}, headers={"origin": BASE})  # fmt: skip
        self.assertEqual(applied.status_code, 200)
        self.assertIn("업데이트 반영: 반영함", applied.text)
        backup = self.assert_applied({"outcome": "applied",
                                      "backup": str(next(self.backups.iterdir()))})  # fmt: skip
        self.assertEqual((backup / "package-lock.json").read_bytes(),
                         self.original["package-lock.json"])  # fmt: skip
        self.assertIn(f"원본 백업: {backup}", applied.text)
        (run,) = history.list_runs(project_id)
        (stored,) = history.list_applies(project_id)
        self.assertEqual((stored["run_id"], stored["outcome"], stored["confirmed"],
                          stored["backup"]), (run["id"], "applied", True, str(backup)))  # fmt: skip
        self.assertEqual(stored["new_package_lock_sha256"], sha(self.head.read_bytes()))
        self.assertEqual(self.ci_calls, [])  # lockfile only: no npm ci
        again = client.post(action, data={"session": SESSION, "mode": "lockfile",
                                          "confirm": "yes"}, headers={"origin": BASE})  # fmt: skip
        self.assertEqual(again.status_code, 404)
        self.assertEqual(len(list(self.backups.iterdir())), 1)


class WithoutWebTests(Fixture):
    def test_dashboard_without_the_extra_says_how_to_install_it(self):
        out, err, plan = io.StringIO(), io.StringIO(), io.StringIO()
        # Every web module, also those other tests imported: none of them can be imported now.
        hidden = {name: None for name in sys.modules if name.split(".")[0] in WEB_MODULES}
        with mock.patch.dict(sys.modules, {**hidden, **dict.fromkeys(WEB_MODULES)}):
            sys.modules.pop("depbee.dashboard.app", None)  # restored when the patch ends
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["dashboard"])
            with contextlib.redirect_stdout(plan):  # other commands do not need the extra
                planned = main(["plan", str(self.project), "--base-lock", str(self.base)])
        self.assertEqual((code, out.getvalue()), (2, ""))
        error = json.loads(err.getvalue())
        self.assertEqual(error["status"], "error")
        self.assertIn('pip install -e ".[web]"', error["error"])
        self.assertNotIn("Traceback", err.getvalue())
        self.assertEqual(planned, 0)
        self.assertEqual(len(json.loads(plan.getvalue())["changes"]), 1)
