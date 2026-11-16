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
from test_detectors import ADVISORY, KnownList, Rules, rule
from test_markdown import HOSTILE
from test_output_formats import EXAMPLES, FormatFixture, older
from test_workflow import Fixture, package

from depbee import history
from depbee.cli import SAFETY_NOTE, main

WEB = all(importlib.util.find_spec(name) for name in ("starlette", "jinja2", "uvicorn", "httpx2"))
NO_WEB = "web extra ([web] and httpx2) not installed; the dashboard is not tested here"
PORT = 48213
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = "synthetic-login-token-for-tests-only-0123456789"
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
        self.client = TestClient(app.build_app(PORT, TOKEN), base_url=BASE)
        self.addCleanup(self.client.close)
        self.db = Path(os.environ["DEPBEE_HISTORY_DB"])

    def login(self):
        response = self.client.get(f"/login?token={TOKEN}", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        return response

    def page(self, url):
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, url)
        self.assertNotIn(TOKEN, response.text)
        return response.text

    def record(self, report, kind="scan", preview=None):
        history.register_project(self.project)
        return history.record(kind, self.project, report, preview)

    def csrf(self):
        return re.search(r'name="csrf" value="([^"]+)"', self.page("/")).group(1)

    def post(self, path, csrf=None, origin=BASE, **extra):
        fields = {"path": path} if csrf is None else {"path": path, "csrf": csrf}
        headers = {} if origin is None else {"origin": origin}
        return self.client.post("/projects", data=fields, headers=headers,
                                follow_redirects=False, **extra)  # fmt: skip


class PageTests(DashboardFixture):
    def test_every_page_of_the_example_reports(self):
        self.login()
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
        self.assertIn("text/css", self.client.get("/static/style.css").headers["content-type"])

    def test_values_are_the_stored_ones_and_known_malicious_is_emphasized(self):
        self.login()
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
        self.login()
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
        self.login()
        run = self.record(self.scan_with(0.1), "update_preview", PREVIEW)
        text = self.page(f"/runs/{run}")
        self.assertIn("<h2>업데이트 미리보기</h2>", text)
        self.assertIn("<li>대상: example</li>", text)
        self.assertIn("npm 11.6.1, package.json 변경 없음, lockfile에서 바뀐 항목 1개", text)
        self.assertIn("미리보기만 했고 프로젝트 파일은 아무것도 바꾸지 않았습니다.", text)
        self.assertIn("업데이트 미리보기", self.page("/"))

    def test_older_report_and_rule_failures(self):
        self.login()
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
        self.login()
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
        self.login()
        self.new["packages"][""] = {"dependencies": {"example": "^1.0.0"}}
        self.new["packages"]["node_modules/example/node_modules/inner"] = package("2.0.0")
        self.save_locks()
        history.register_project(self.project)
        text = self.page("/projects/1")
        self.assertIn("직접 1개, 중첩 1개.", text)
        self.assertIn("<td>inner</td><td>2.0.0</td><td>node_modules/example/node_modules/inner</td>",
                      text)  # fmt: skip
        for url in ("/projects/2", "/runs/1", f"/runs/{2**70}"):
            self.assertEqual(self.client.get(url).status_code, 404, url)

    def test_resources_have_no_external_urls(self):
        package_dir = Path(self.app.__file__).parent
        files = [*package_dir.glob("templates/*.html"), *package_dir.glob("static/*")]
        self.assertEqual(sorted(p.name for p in files), [
            "base.html", "counts.html", "model.html", "project.html", "projects.html", "run.html",
            "style.css"])  # fmt: skip
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
        self.login()
        for host in (f"127.0.0.1:{PORT + 1}", "127.0.0.1", f"localhost:{PORT}",
                     f"evil.test:{PORT}", ""):  # fmt: skip
            for url in ("/", f"/login?token={TOKEN}"):
                with self.subTest(host=host, url=url):
                    response = self.client.get(url, headers={"host": host},
                                               follow_redirects=False)  # fmt: skip
                    self.assertEqual(response.status_code, 400)
                    self.assert_headers(response)
                    self.assertNotIn("set-cookie", response.headers)

    def test_every_request_needs_a_session(self):
        for url in self.URLS:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 403, url)
            self.assert_headers(response)
        wrong = self.client.get("/login?token=" + TOKEN[:-1] + "X", follow_redirects=False)
        self.assertEqual(wrong.status_code, 403)
        self.assertNotIn("set-cookie", wrong.headers)
        self.assertEqual(self.client.get("/login", follow_redirects=False).status_code, 403)
        self.client.cookies.set(self.app.cookie_name(PORT), TOKEN)  # the token is not a session
        self.assertEqual(self.client.get("/").status_code, 403)

    def test_login_sets_a_strict_http_only_session_and_drops_the_token(self):
        response = self.login()
        self.assert_headers(response)
        self.assertEqual(response.headers["location"], "/")
        cookie = response.headers["set-cookie"]
        name, value = cookie.split(";")[0].split("=", 1)
        self.assertEqual(name, f"depbee_session_{PORT}")
        self.assertNotIn(TOKEN, cookie)
        self.assertGreaterEqual(len(value), 40)
        attributes = {part.strip().lower() for part in cookie.split(";")[1:]}
        self.assertTrue({"httponly", "path=/", "samesite=strict"} <= attributes, attributes)
        for url in self.URLS[:3]:
            page = self.client.get(url)
            self.assertEqual(page.status_code, 200, url)
            self.assert_headers(page)
            self.assertNotIn(TOKEN, page.text)

    def test_post_needs_session_csrf_and_origin(self):
        self.login()
        csrf, path = self.csrf(), str(self.project)
        self.assertNotIn(TOKEN, csrf)
        refused = {
            "no csrf": self.post(path),
            "wrong csrf": self.post(path, csrf[:-1] + ("A" if csrf[-1] != "A" else "B")),
            "no origin": self.post(path, csrf, origin=None),
            "other port": self.post(path, csrf, origin=f"http://127.0.0.1:{PORT + 1}"),
            "other host": self.post(path, csrf, origin=f"http://localhost:{PORT}"),
            "null origin": self.post(path, csrf, origin="null"),
            "https origin": self.post(path, csrf, origin=f"https://127.0.0.1:{PORT}"),
        }
        for label, response in refused.items():
            with self.subTest(label):
                self.assertEqual(response.status_code, 403)
                self.assert_headers(response)
        self.assertEqual(history.list_projects(), [])
        self.client.cookies.clear()
        self.assertEqual(self.post(path, csrf).status_code, 403)  # no session
        self.assertEqual(history.list_projects(), [])
        # GET never changes state: the form's route takes POST only.
        self.login()
        self.assertEqual(self.client.get("/projects").status_code, 405)

    def test_large_or_odd_bodies_are_refused(self):
        self.login()
        csrf = self.csrf()
        big = self.post("C:/" + "a" * (self.app.MAX_BODY + 1), csrf)
        self.assertEqual(big.status_code, 413)
        self.assert_headers(big)
        fields = "&".join(f"f{i}=1" for i in range(self.app.MAX_FIELDS + 1))
        response = self.client.post("/projects", content=f"csrf={csrf}&{fields}",
                                    headers={"origin": BASE, "content-type":
                                             "application/x-www-form-urlencoded"})  # fmt: skip
        self.assertEqual(response.status_code, 400)
        response = self.client.post("/projects", content=json.dumps({"csrf": csrf}),
                                    headers={"origin": BASE, "content-type": "application/json"})  # fmt: skip
        self.assertEqual(response.status_code, 415)
        self.assertEqual(history.list_projects(), [])

    def test_server_settings_and_the_one_line_with_the_token(self):
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
        self.assertRegex(first, rf"\Ahttp://127\.0\.0\.1:{port}/login\?token=[A-Za-z0-9_-]{{43}}\Z")
        self.assertNotIn("token", second)
        code, err = None, io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["dashboard", "--port", "70000"])
        self.assertEqual(code, 2)
        self.assertIn("--port must be between 0 and 65535", err.getvalue())


class EscapeTests(DashboardFixture):
    STRINGS = [*HOSTILE, '"><script>alert(1)</script>', "' onmouseover='x", "javascript:alert(1)",
               "\u202eexe.js", "zero\u200cwidth", "\x1b[31mred", "lone\udc80surrogate"]  # fmt: skip

    def test_report_lockfile_and_path_strings_stay_inert(self):
        self.login()
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
        self.new["packages"][f"node_modules/{self.STRINGS[0]}"] = package()
        self.new["packages"]["node_modules/b"] = {**package(), "name": '"><script>x</script>'}
        self.save_locks()
        self.check(self.page("/projects/1"))

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
        self.login()
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
        self.login()
        return self.post(path, self.csrf())

    def assert_refused(self, path, message):
        response = self.register(path)
        self.assertEqual(response.status_code, 400, path)
        self.assertIn(message, response.text)
        if len(path) > 10:  # short ones such as "project" are words of the page itself
            self.assertNotIn(path, response.text)  # the input is not echoed
        self.assertEqual(history.list_projects(), [])

    def test_register_and_register_again(self):
        response = self.register(str(self.project))
        self.assertEqual((response.status_code, response.headers["location"]), (303, "/projects/1"))
        again = self.post(str(self.project) + os.sep, self.csrf())
        self.assertEqual(again.headers["location"], "/projects/1")
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
