"""The console's shell and the way a project leaves it (docs/dashboard-design.md): the rail's way
home, its foot with the theme button and the question mark's bubble, and taking one registered
project off the list (unregister), which may touch nothing but that project's row in the history.

Synthetic only, inside each test run's folder: no npm, registry, package code or folder dialog.
"""

import re
import sqlite3
import unittest
from html import unescape
from pathlib import Path
from unittest import mock

from test_dashboard import (
    BASE,
    CSRF,
    NO_WEB,
    PORT,
    PREVIEW,
    WEB,
    ScreenFixture,
    applied_document,
)
from test_history import make_older, sql, tree

from depbee import history
from depbee.cli import SAFETY_NOTE

STATIC = Path(__file__).resolve().parents[1] / "src" / "depbee" / "dashboard" / "static"
ACCESS = (
    "이 화면은 이 PC의 127.0.0.1에서만 열립니다. 이 PC의 다른 계정과 프로그램도 이 주소를 열 수 "
    "있습니다."
)
NOT_REGISTERED = "등록된 프로젝트가 아닙니다."
ROWS = ("projects", "runs", "results", "applies", "previews")


@unittest.skipUnless(WEB, NO_WEB)
class ShellFixture(ScreenFixture):
    """Two registered projects (ScreenFixture registers the first, self.project): the second is
    self.other. The first has a scan and an applied update preview stored, the second a scan,
    and a backup of an apply lies beside the history file."""

    def setUp(self):
        super().setUp()
        self.other = self.root / "other"
        self.other.mkdir()
        (self.other / "package-lock.json").write_bytes(
            (self.project / "package-lock.json").read_bytes()
        )
        self.other_id = history.register_project(self.other)
        self.scan = history.record("scan", self.project, self.report)
        self.applied_run = history.record("update_preview", self.project, self.report, PREVIEW,
                                      apply=applied_document())  # fmt: skip
        self.kept = history.record("scan", self.other, self.report)
        (self.project / "index.js").write_text("module.exports = 1;\n", "utf-8")
        backup = self.db.parent / "backups" / "20261128T000000Z-synthetic"
        backup.mkdir(parents=True)
        (backup / "package-lock.json").write_text("{}\n", "utf-8")

    def stored(self):
        return {name: sql(self.db, f"SELECT count(*) FROM {name}")[0][0] for name in ROWS}

    def outside(self):
        """Every file and folder of the test run but the history file itself and the lock
        files depbee keeps beside it (locks/)."""
        return tree(self.root, self.db, self.db.with_name(self.db.name + "-journal"),
                    self.db.parent / "locks")  # fmt: skip

    def listed(self):
        return [project["id"] for project in history.list_projects()]

    def unregister(self, project_id=None, csrf=CSRF, origin=BASE, **sent):
        """The question's form. csrf None: without its field; origin None: without the
        header a browser sends with it; sent: other headers."""
        data = {"other": "1"} if csrf is None else {"csrf": csrf}
        headers = {**({} if origin is None else {"origin": origin}), **sent}
        return self.client.post(f"/projects/{project_id or self.project_id}/unregister",
                                data=data, headers=headers, follow_redirects=False)  # fmt: skip


class RailTests(ShellFixture):
    def test_home_is_an_icon_named_in_words_and_the_overview_is_its_page(self):
        overview, model = self.page("/"), self.page("/model")
        home = ('<a class="home" href="/" aria-label="홈: 프로젝트 현황판" '
                'title="홈: 프로젝트 현황판"%s><svg viewBox="0 0 24 24" aria-hidden="true">')  # fmt: skip
        self.assertIn(home % ' aria-current="page"', overview)
        self.assertIn(home % "", model)
        self.assertIn("<title>프로젝트 현황판 - depbee</title>", overview)
        self.assertIn('<h1 class="ov-title" id="overview-title">프로젝트 현황판</h1>', overview)
        for html in (overview, model, self.page("/?manage=1"), self.page("/projects/1")):
            rail = html.split('<header class="masthead">', 1)[1].split("</header>", 1)[0]
            # The overview has no menu entry in words any more: the icon is the way to it.
            self.assertNotIn("현황판</a>", rail)
            menu = rail.split('<nav class="aux" aria-label="관리와 정보">', 1)[1].split("</nav>")[0]
            self.assertEqual(re.findall(r'<a (?:class="[^"]+" )?href="([^"]+)"', menu),
                             ["/", "/?manage=1", "/model"])  # fmt: skip
            # Every drawing of the rail is hidden from a screen reader; its control has a name.
            self.assertEqual(rail.count("<svg"), rail.count('<svg viewBox="0 0 24 24" aria-hidden="true">'))
            self.assertEqual(rail.count("<svg"), 3)
            self.assertNotIn("<footer", html)
        self.assertIn(' aria-current="page">프로젝트 관리</a>', self.page("/?manage=1"))

    def test_the_question_mark_says_what_a_verdict_does_not_promise_on_every_page(self):
        pages = ("/", "/?manage=1", "/model", "/projects/1", "/projects/1/updates",
                 "/projects/1/history", f"/runs/{self.scan}", "/projects/1/unregister")  # fmt: skip
        for url in pages:
            html = self.page(url)
            bubble = re.search(
                r'<div class="rail-help">\n<button type="button" class="help" '
                r'aria-label="판정과 접속 안내" aria-describedby="rail-caveat">'
                r'<span aria-hidden="true">\?</span></button>\n'
                r'<div class="bubble" id="rail-caveat" role="tooltip">\n'
                r"<p>(.*?)</p>\n<p>(.*?)</p>\n</div>\n</div>", html,
            )  # fmt: skip
            self.assertIsNotNone(bubble, url)
            # The CLI's own sentence, word for word, then who can open the address.
            self.assertEqual([unescape(text) for text in bubble.groups()], [SAFETY_NOTE, ACCESS])
            self.assertEqual(html.count(SAFETY_NOTE.replace("'", "&#39;")), 1, url)
            self.assertEqual(html.count('id="rail-caveat"'), 1, url)
            # At the rail's foot, after the theme, before the projects.
            foot = html.index('<div class="rail-foot">')
            self.assertLess(foot, html.index('<div class="rail-help">'))
            self.assertLess(html.index('<div class="rail-help">'), html.index('<nav class="tabs"'))
        # The page before the first project has no rail: the same foot is its bottom left.
        for project_id in self.listed():
            history.unregister_project(project_id)
        start = self.page("/")
        self.assertNotIn("masthead", start)
        foot = start.split("</main>", 1)[1].strip()
        self.assertTrue(foot.startswith('<div class="rail-foot">'), foot[:40])
        self.assertIn('<form class="theme" method="post" action="/theme">', foot)
        caveat = SAFETY_NOTE.replace("'", "&#39;")
        self.assertRegex(foot, rf"<p>{re.escape(caveat)}</p>\s*<p>{re.escape(ACCESS)}</p>")

    def test_the_bubble_shows_under_the_pointer_and_the_focus_and_escape_puts_it_away(self):
        css = re.sub(r"/\*.*?\*/", "", (STATIC / "style.css").read_text("utf-8"), flags=re.S)
        self.assertRegex(css, r"(?m)^\.bubble \{ display: none; ")
        # Shown by the pointer or the focus on the button or on the bubble (inside the same
        # element, and touching the button); the class Escape sets wins over both.
        shown = ".rail-help:hover .bubble, .rail-help:focus-within .bubble { display: block; }"
        shut = ".rail-help.shut .bubble { display: none; }"
        self.assertIn(f"{shown}\n{shut}\n", css)
        self.assertRegex(css, r"(?m)^\.bubble \{[^}]*position: absolute; top: 100%;")
        # On the rail the foot stays at the bottom left and the bubble is not cut by the rail.
        wide = css[css.index("@media (min-width: 80rem)") :]
        self.assertRegex(wide, r"\.rail-foot \{ position: sticky; bottom: 0; order: 1; ")
        self.assertRegex(wide, r"\.bubble \{ position: fixed; [^}]*bottom: 3\.5rem; \}")
        # The icons are targets of 44px.
        self.assertRegex(css, r"(?m)^\.theme button, \.rail-help \.help \{ width: 2\.75rem; "
                              r"height: 2\.75rem; ")  # fmt: skip
        self.assertRegex(css, r"(?m)^\.aux \.home \{[^}]*width: 2\.75rem; ")
        script = (STATIC / "app.js").read_text("utf-8")
        self.assertIn("if (event.key === 'Escape' && help.matches(':hover, :focus-within')) {\n"
                      "        help.classList.add('shut');", script)  # fmt: skip
        for event in ("pointerenter", "focusin"):
            self.assertIn(f"help.addEventListener('{event}', open);", script)


class UnregisterTests(ShellFixture):
    def test_each_project_has_its_own_question_and_asking_changes_nothing(self):
        before, files = self.db.read_bytes(), self.outside()
        manage = self.page("/?manage=1")
        for project_id, name in ((self.project_id, "project"), (self.other_id, "other")):
            self.assertIn(f'<a class="unregister" href="/projects/{project_id}/unregister">'
                          f'<span class="visually-hidden">{name} </span>등록 해제</a>', manage)  # fmt: skip
        # Only project management offers it, and no page unregisters by a link or a form of
        # its own: the one form is the question's.
        for url in ("/", "/model", "/projects/1", "/projects/1/updates", "/projects/1/history"):
            self.assertNotIn("/unregister", self.page(url), url)
        self.assertNotIn('method="post" action="/projects/1/unregister"', manage)
        html = self.page(f"/projects/{self.project_id}/unregister")
        self.assertIn("<title>프로젝트 등록 해제 - depbee</title>", html)
        self.assertIn(' aria-current="page">프로젝트 관리</a>', html)
        main = html.split('<main id="main">', 1)[1].split("</main>", 1)[0]
        # Which project: its name and its whole path, and not the other one.
        self.assertIn("project 등록을 해제할까요?</h2>", main)
        self.assertIn(f'<p class="path">{self.project.resolve()}</p>', main)
        self.assertNotIn(str(self.other.resolve()), main)
        for said in ("프로젝트 하나만 뺍니다", "package.json, package-lock.json, 소스 코드",
                     "이 폴더를 읽지도 쓰지도 않습니다", "백업 폴더", "저장된 실행 기록 2개와 반영 기록",
                     "같은 폴더를 다시 등록하면 그대로 다시 보입니다", "기록되지 않습니다"):  # fmt: skip
            self.assertIn(said, main)
        self.assertEqual(re.findall(r'<form method="post" action="([^"]+)">', main),
                         [f"/projects/{self.project_id}/unregister"])  # fmt: skip
        self.assertIn(f'<input type="hidden" name="csrf" value="{CSRF}">', main)
        self.assertIn('<button type="submit">project 등록 해제</button> '
                      '<a class="action" href="/?manage=1">취소</a>', main)  # fmt: skip
        # The theme button comes back to the question.
        self.assertIn('name="back" value="/projects/1/unregister"', html)
        self.assertEqual(self.app._way_back("/projects/1/unregister"), "/projects/1/unregister")
        self.assertEqual((self.db.read_bytes(), self.outside(), self.listed()),
                         (before, files, [self.project_id, self.other_id]))  # fmt: skip

    def test_only_this_runs_form_unregisters_a_registered_project(self):
        before = self.db.read_bytes()
        refused = (
            (self.unregister(csrf=None), 403), (self.unregister(csrf="wrong"), 403),
            (self.unregister(origin="http://evil.example"), 403),
            (self.unregister(origin=None), 403),
            (self.unregister(**{"sec-fetch-site": "cross-site"}), 403),
            (self.client.post("/projects/1/unregister", json={"csrf": CSRF},
                              headers={"origin": BASE}), 415),
            (self.client.put("/projects/1/unregister", data={"csrf": CSRF},
                             headers={"origin": BASE}), 405),
            (self.unregister(99), 404), (self.get("/projects/99/unregister"), 404),
            (self.get(f"/projects/1/unregister?csrf={CSRF}&confirm=yes"), 200),
        )  # fmt: skip
        for at, (response, status) in enumerate(refused):
            self.assertEqual(response.status_code, status, at)
        self.assertEqual((self.db.read_bytes(), self.listed()),
                         (before, [self.project_id, self.other_id]))  # fmt: skip
        self.assertEqual(self.unregister(99).text, NOT_REGISTERED)

    def test_one_project_leaves_and_every_file_and_record_stays(self):
        rows, files = self.stored(), self.outside()
        response = self.unregister()
        self.assertEqual(response.status_code, 200)
        html = response.text
        # The answer is project management, which says what was done and what was kept.
        self.assertIn("<title>프로젝트 관리 - depbee</title>", html)
        self.assertIn('<p class="done" role="status">project 프로젝트의 등록을 해제했습니다. 프로젝트 폴더와 '
                      "그 안의 파일, 저장된 검사 기록은 그대로입니다.</p>", html)  # fmt: skip
        self.assertIn("등록한 프로젝트 1개", html)
        self.assertNotIn('href="/projects/1"', html)
        self.assertIn(f'href="/projects/{self.other_id}"', html)
        # Nothing of any folder was written, moved or removed: the project, its two manifests
        # and its source, the other project, the backup beside the history.
        self.assertEqual(self.outside(), files)
        self.assertEqual(self.stored(), rows)  # and no row of the history
        self.assertEqual(self.listed(), [self.other_id])
        for url in ("/", "/?manage=1", "/model", f"/projects/{self.other_id}"):
            html = self.page(url)
            self.assertNotIn('href="/projects/1"', html, url)
            self.assertIn('<p class="rail-title">프로젝트 1개 · 조치 필요 0</p>', html, url)
        # Its pages and its reports are not found; the other project's are as before.
        for url in ("/projects/1", "/projects/1/updates", "/projects/1/history",
                    "/projects/1/unregister", f"/runs/{self.scan}", f"/runs/{self.applied_run}"):  # fmt: skip
            self.assertEqual(self.get(url).status_code, 404, url)
        self.page(f"/runs/{self.kept}")
        self.page(f"/projects/{self.other_id}/history")
        # A form sent twice, and a check, a scan or a question for it, find no project.
        again = self.unregister()
        self.assertEqual((again.status_code, again.text), (404, NOT_REGISTERED))
        self.assertEqual(self.check().status_code, 404)
        self.assertEqual(self.client.post("/projects/1/scans", data={"csrf": CSRF},
                                          headers={"origin": BASE}).status_code, 404)  # fmt: skip
        self.assertEqual(self.previewed, [])
        self.assertEqual(self.stored(), rows)

    def test_the_last_project_leaves_the_page_that_adds_the_first(self):
        self.assertEqual(self.unregister(self.other_id).status_code, 200)
        files = self.outside()
        response = self.unregister()
        self.assertEqual(response.status_code, 200)
        self.assertIn('<p class="done" role="status">project 프로젝트의 등록을', response.text)
        self.assertIn("등록한 프로젝트가 없습니다.", response.text)
        self.assertIn('<form method="post" action="/projects/pick">', response.text)
        self.assertNotIn("/unregister", response.text)
        for url in ("/", "/?manage=1"):  # the start page again: one button
            html = self.page(url)
            self.assertIn("<title>프로젝트 추가 - depbee</title>", html)
            self.assertEqual(html.split("</main>")[0].count("<button"), 1)
        self.assertEqual(self.outside(), files)
        self.assertEqual(self.stored()["runs"], 3)

    def test_a_project_whose_folder_is_gone_is_unregistered_too(self):
        (self.other / "package-lock.json").unlink()
        self.other.rmdir()
        self.assertIn('더 쓰지 않는 프로젝트는 아래 "등록 해제"로', unescape(self.page("/?manage=1")))
        html = self.page(f"/projects/{self.other_id}/unregister")
        self.assertIn('<span class="cell gone" aria-hidden="true"></span>other 등록을', html)
        files = self.outside()
        self.assertEqual(self.unregister(self.other_id).status_code, 200)
        self.assertEqual((self.listed(), self.outside()), ([self.project_id], files))
        self.assertFalse(self.other.exists())

    def test_nothing_is_unregistered_while_a_check_a_scan_or_an_apply_runs(self):
        seen = {}

        def during(name, fake):
            def running(*args, **kwargs):
                seen[name] = (self.unregister(), self.unregister(self.other_id), self.listed())
                return fake(*args, **kwargs)

            return running

        self.preview_files.side_effect = during("check", self.fake_preview)
        preview_id = self.preview_id()
        self.patch_service("scan_project", during("scan", lambda *a, **k: self.report))
        self.assertEqual(self.client.post("/projects/1/scans", data={"csrf": CSRF},
                                          headers={"origin": BASE}).status_code, 200)  # fmt: skip
        self.apply_preview.side_effect = during("apply", self.fake_apply)
        self.assertEqual(self.apply(preview_id).status_code, 200)
        self.assertEqual(sorted(seen), ["apply", "check", "scan"])
        for name, (own, other, listed) in seen.items():
            # Neither the project the work runs on nor another one: one thing at a time.
            for response in (own, other):
                self.assertEqual(response.status_code, 409, name)
                self.assertIn(f'<p class="error">{self.app.UNREGISTER_BUSY}</p>', response.text)
                self.assertIn(self.app.UNREGISTER_BUSY_NOTE, response.text)
                self.assertIn(f'<a href="/?manage=1">{self.app.PICK_REOPEN}</a>', response.text)
            self.assertEqual(listed, [self.project_id, self.other_id], name)
        # What ran was recorded for the project, which was registered all along.
        self.assertEqual(len(self.applied_documents()), 2)
        self.assertEqual(self.unregister().status_code, 200)  # free again
        self.assertEqual(self.listed(), [self.other_id])

    def applied_documents(self):
        return history.list_applies(self.project_id)

    def test_an_update_check_held_for_the_project_is_gone_for_good(self):
        mine, others = self.preview_id(), None
        others = self.started(project_id=self.other_id)
        self.ended(others)
        self.page(f"/previews/{mine}")
        self.assertEqual(self.unregister().status_code, 200)
        for when in ("unregistered", "registered again"):
            response = self.get(f"/previews/{mine}")
            self.assertEqual(response.status_code, 404, when)
            self.assertIn(self.app.PREVIEW_GONE, response.text)
            self.assertEqual(self.apply(mine).status_code, 404, when)
            # The same folder registered again is the same project, with its stored runs, and
            # still without the check that was held for it: that one is checked again.
            self.assertEqual(history.register_project(self.project), self.project_id)
        self.assertEqual(self.applied, [])
        self.assertNotIn(f"/previews/{mine}", self.page("/projects/1/updates"))
        # The other project's check is as it was.
        self.page(f"/previews/{others}")
        self.assertEqual(self.apply(others).status_code, 200)
        self.assertEqual(len(self.applied), 1)

    def started(self, packages="", project_id=None, **fields):
        response = self.check(packages, project_id=project_id, **fields)
        self.assertEqual(response.status_code, 303, response.text)
        return response.headers["location"].rsplit("/", 1)[1].split("?")[0]

    def test_no_run_of_the_folder_is_recorded_and_none_brings_the_project_back(self):
        self.assertEqual(self.unregister().status_code, 200)
        rows = self.stored()
        self.assertIsNone(history.record("scan", self.project, self.report))
        self.assertIsNone(history.record("update_preview", self.project, self.report, PREVIEW,
                                         apply=applied_document()))  # fmt: skip
        self.assertEqual((self.stored(), self.listed()), (rows, [self.other_id]))
        self.assertNotIn('href="/projects/1"', self.page("/"))

    def test_the_folder_registered_again_has_its_history_and_its_report_links(self):
        self.assertEqual(self.unregister().status_code, 200)
        self.dialog(str(self.project))
        response = self.send_pick()
        self.assertEqual((response.status_code, response.headers["location"]),
                         (303, f"/projects/{self.project_id}"))  # fmt: skip
        self.assertEqual(self.listed(), [self.project_id, self.other_id])  # its old place
        for run_id in (self.scan, self.applied_run):
            self.assertIn(f'<a href="/runs/{run_id}">#{run_id}</a>',
                          self.page("/projects/1/history"))  # fmt: skip
            self.page(f"/runs/{run_id}")
        self.assertIsNotNone(history.record("scan", self.project, self.report))

    def test_a_history_file_of_the_previous_version_is_upgraded_by_the_unregistration(self):
        make_older(self.db, 3)  # as the previous depbee left it
        before, rows = self.db.read_bytes(), self.stored()
        self.page("/?manage=1")
        self.page("/projects/1/unregister")
        self.assertEqual(self.db.read_bytes(), before)  # looking and asking do not upgrade
        self.assertEqual(self.unregister().status_code, 200)
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(4,)])
        self.assertEqual((self.stored(), self.listed()), (rows, [self.other_id]))
        self.assertEqual(self.get(f"/runs/{self.scan}").status_code, 404)
        self.assertEqual(history.register_project(self.project), self.project_id)
        self.page(f"/runs/{self.scan}")

    def test_a_history_that_cannot_be_written_keeps_the_project(self):
        self.answer_errors()
        files = self.outside()
        for error in (sqlite3.OperationalError("database is locked"),
                      history.HistoryError("synthetic"), OSError("synthetic")):  # fmt: skip
            with mock.patch.object(history, "unregister_project", side_effect=error):
                response = self.unregister()
            self.assertEqual(response.status_code, 500)
            self.assertNotIn("synthetic", response.text)
        self.assertEqual((self.listed(), self.outside()),
                         ([self.project_id, self.other_id], files))  # fmt: skip
        # The lock of the work is free again after a failure.
        self.assertEqual(self.unregister().status_code, 200)


class TwoDashboardsTests(ShellFixture):
    """Two dashboards on one history file, as two `depbee dashboard --port` processes are: each
    its own app, with its own update checks in memory and its own lock of the work it runs.
    What they share is the history file and the hold of a project (history.hold_project), a
    lock of the operating system that two open files of one process contend for just as two
    processes do (test_history has it across two real processes, one of them killed)."""

    OTHER_PORT = PORT + 1
    OTHER_BASE = f"http://127.0.0.1:{OTHER_PORT}"
    OTHER_CSRF = "another-dashboards-csrf-value-0123456789"

    def setUp(self):
        super().setUp()
        from starlette.testclient import TestClient

        self.second = TestClient(self.app.build_app(self.OTHER_PORT, self.OTHER_CSRF),
                                 base_url=self.OTHER_BASE)  # fmt: skip
        self.addCleanup(self.second.close)

    def unregister_there(self, project_id=None):
        """The question's form sent to the second dashboard."""
        return self.second.post(f"/projects/{project_id or self.project_id}/unregister",
                                data={"csrf": self.OTHER_CSRF},
                                headers={"origin": self.OTHER_BASE})  # fmt: skip

    def test_a_check_one_dashboard_holds_is_gone_once_the_other_unregistered_the_project(self):
        mine = self.preview_id()
        self.page(f"/previews/{mine}")
        self.assertEqual(self.unregister_there().status_code, 200)
        self.assertEqual(self.listed(), [self.other_id])
        for when in ("unregistered", "registered again"):
            response = self.get(f"/previews/{mine}")
            self.assertEqual(response.status_code, 404, when)
            self.assertIn(self.app.PREVIEW_GONE, response.text)
            self.assertEqual(self.apply(mine).status_code, 404, when)
            # Registered again it is the same project, at another generation: what the first
            # dashboard kept from before is not shown or applied to it.
            self.assertEqual(history.register_project(self.project), self.project_id)
        self.assertEqual(self.applied, [])
        self.assertEqual(history.list_applies(self.project_id)[0]["run_id"], self.applied_run)
        self.assertNotIn(f"/previews/{mine}", self.page("/projects/1/updates"))
        # A check made now, of the registration of now, is reviewed and applied as ever.
        fresh = self.preview_id()
        self.assertEqual(self.apply(fresh).status_code, 200)
        self.assertEqual(len(self.applied), 1)

    def test_the_other_dashboard_cannot_unregister_under_a_check_a_scan_or_an_apply(self):
        seen = {}

        def during(name, fake):
            def running(*args, **kwargs):
                seen[name] = (self.unregister_there(), self.listed())
                return fake(*args, **kwargs)

            return running

        self.preview_files.side_effect = during("check", self.fake_preview)
        preview_id = self.preview_id()
        self.patch_service("scan_project", during("scan", lambda *a, **k: self.report))
        self.assertEqual(self.client.post("/projects/1/scans", data={"csrf": CSRF},
                                          headers={"origin": BASE}).status_code, 200)  # fmt: skip
        self.apply_preview.side_effect = during("apply", self.fake_apply)
        self.assertEqual(self.apply(preview_id).status_code, 200)
        self.assertEqual(sorted(seen), ["apply", "check", "scan"])
        for name, (response, listed) in seen.items():
            self.assertEqual(response.status_code, 409, name)
            self.assertIn(f'<p class="error">{self.app.UNREGISTER_BUSY}</p>', response.text)
            self.assertEqual(listed, [self.project_id, self.other_id], name)
        # The apply that ran was recorded for the project, which never left the list.
        self.assertEqual(len(history.list_applies(self.project_id)), 2)
        # The other project was free all along, and this one is free once the work has ended.
        self.assertEqual(self.unregister_there(self.other_id).status_code, 200)
        self.assertEqual(self.unregister_there().status_code, 200)
        self.assertEqual(self.listed(), [])

    def test_no_work_starts_on_a_project_that_another_process_holds_or_unregisters(self):
        preview_id = self.preview_id()
        with history.hold_project(self.project_id, 0):  # as work of another process would
            self.assertEqual(self.check().status_code, 409)
            self.assertEqual(self.client.post("/projects/1/scans", data={"csrf": CSRF},
                                              headers={"origin": BASE}).status_code, 409)  # fmt: skip
            self.assertEqual(self.apply(preview_id).status_code, 409)
            self.assertEqual(self.unregister().status_code, 409)
        self.assertEqual((len(self.previewed), self.applied), (1, []))
        # The check it held is still there to apply once the project is free.
        self.assertEqual(self.apply(preview_id).status_code, 200)
        self.assertEqual(len(self.applied), 1)


if __name__ == "__main__":
    unittest.main()
