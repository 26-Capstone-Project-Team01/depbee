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
from pathlib import Path
from unittest import mock

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
WEB_MODULES = ("starlette", "jinja2", "uvicorn", "markupsafe")
PREVIEW = {
    "targets": ["example"], "npm_version": "11.6.1", "package_json_sha256": "0" * 64,
    "package_lock_sha256": "1" * 64, "new_package_lock_sha256": "2" * 64,
    "package_json_changed": False, "changed_count": 1, "project_npmrc_ignored": False,
    "notices": ["미리보기만 했고 프로젝트 파일은 아무것도 바꾸지 않았습니다."],
}  # fmt: skip


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
        # Every link and form of the dashboard keeps the session prefix.
        for target in re.findall(r'(?:href|action)="([^"]*)"', response.text):
            if not target.startswith("https://www.npmjs.com/package/"):
                self.assertTrue(target.startswith(S + "/"), target)
        return response.text

    def record(self, report, kind="scan", preview=None):
        history.register_project(self.project)
        return history.record(kind, self.project, report, preview)

    def form_session(self):
        return re.search(r'name="session" value="([^"]+)"', self.page("/")).group(1)

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
        projects, project, model = self.page("/"), self.page("/projects/1"), self.page("/model")
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
        self.assertIn("<dd>2.0.0 (비교 기준 버전)</dd>", text)  # cli._alternative
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
        self.assertIn("<td>inner</td><td>2.0.0</td><td>node_modules/example/node_modules/inner</td>",
                      text)  # fmt: skip
        for url in ("/projects/2", "/runs/1", f"/runs/{2**70}"):
            self.assertEqual(self.get(url).status_code, 404, url)

    def test_resources_have_no_external_urls(self):
        package_dir = Path(self.app.__file__).parent
        files = [*package_dir.glob("templates/*.html"), *package_dir.glob("static/*")]
        self.assertEqual(sorted(p.name for p in files), [
            "applied.html", "apply_lines.html", "base.html", "counts.html", "error.html",
            "model.html", "preview.html", "project.html", "projects.html", "report.html",
            "run.html", "style.css"])  # fmt: skip
        for path in files:
            self.assertIsNone(re.search(r"https?:|//", path.read_text("utf-8")), path.name)
        self.assertNotIn("<script", "".join(p.read_text("utf-8") for p in files))


class SecurityTests(DashboardFixture):
    URLS = ("/", "/model", "/static/style.css", "/projects/1", "/runs/1")

    def assert_headers(self, response):
        headers = response.headers
        self.assertEqual(headers["content-security-policy"], self.app.CSP)
        for directive in ("default-src 'none'", "style-src 'self'", "form-action 'self'",
                          "frame-ancestors 'none'", "base-uri 'none'"):  # fmt: skip
            self.assertIn(directive, headers["content-security-policy"])
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
        self.assertIn(f'<a href="{S}/projects/1">', html)
        self.assertIn(f'<form method="post" action="{S}/projects">', html)
        self.assertIn(f'<input type="hidden" name="session" value="{SESSION}">', html)
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
                self.assertIn(f"<td>{escape(_clean(name))}</td>", html)
                self.assertIn(f"<td>{escape(_clean(location))}</td>", html)
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
        self.assertNotIn("<script", html)
        self.assertNotIn("<img", html)
        self.assertNotIn("onmouseover='x", html)
        self.assertNotRegex(html, r'href="(?!/|https://www\.npmjs\.com/package/)')
        self.assertNotIn('javascript:alert(1)"', html)
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
        self.assertEqual(
            (response.status_code, response.headers["location"]), (303, S + "/projects/1")
        )
        again = self.post(str(self.project) + os.sep, self.form_session())
        self.assertEqual(again.headers["location"], S + "/projects/1")
        (project,) = history.list_projects()
        self.assertEqual(project["path"], str(self.project.resolve()))
        self.assertIn(str(self.project.resolve()), self.page("/"))

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
            '<button type="submit">반영</button>', html
        )


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
        self.assertIn("대시보드 프로세스 메모리에만 있습니다", html)
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
        self.assertIn("업데이트를 확인할 수 없습니다", self.page(f"/projects/{self.project_id}"))
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
        self.assertEqual(seen["check"].status_code, 409)
        self.assertEqual(seen["check"].text, self.app.BUSY)
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
        gone = self.get(f"/previews/{ids[0]}")
        self.assertEqual((gone.status_code, gone.text), (404, self.app.PREVIEW_GONE))
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
        again = self.apply(preview_id, mode="install")
        self.assertEqual((again.status_code, again.text), (404, self.app.PREVIEW_GONE))
        self.assertEqual(self.apply_preview.call_count, 1)
        (stored,) = history.list_applies(self.project_id)
        self.assertEqual((stored["run_id"], stored["outcome"], stored["backup"]),
                         (run["id"], "applied", BACKUP))  # fmt: skip
        self.assertEqual(stored["apply"]["confirmation_required"][0]["causes"],
                         ["known_malicious_unchecked"])  # fmt: skip
        run_page = self.page(f"/runs/{run['id']}")
        self.assertIn("<h2>업데이트 반영: 반영함</h2>", run_page)
        self.assertIn("확인이 필요한 항목 1개(확인함):", run_page)
        project_page = self.page(f"/projects/{self.project_id}")
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
        self.assertIn(f"<td>{BACKUP}</td>", self.page(f"/projects/{self.project_id}"))
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
                self.check_html(self.page(f"/projects/{self.project_id}"))
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
