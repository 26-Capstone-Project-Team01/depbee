"""A dashboard in a container (dashboard.mounted): where it listens, the folder picker behind
the folder button, and what may be registered or used as a project.

Synthetic folders in each test run's folder stand for the mounted ones (DEPBEE_CONTAINER_PROJECTS
names one of them); no container, no desktop dialog, no server (a stand-in for uvicorn.Server),
no npm and no registry. Real links are made where the system lets a test make them, which an
ordinary Windows account does not; the registration checks also run on links that os.lstat and
os.readlink are made to report (test_mcp.ResponseTests.links).
"""

import contextlib
import html
import io
import json
import os
import re
import shutil
from pathlib import Path
from unittest import mock
from urllib.parse import quote

import test_mcp
from test_dashboard import BASE, PORT, SESSION, DashboardFixture, S, ScreenFixture

from depbee import history, service
from depbee.cli import main
from depbee.contracts import GuardError
from depbee.dashboard import lifecycle, mounted, picker

VARIABLE = "DEPBEE_CONTAINER_PROJECTS"


class ContainerFixture(DashboardFixture):
    """The dashboard as a container's: self.mount stands for the folder the projects are mounted
    under, and self.project (Fixture) is a real project outside it."""

    def setUp(self):
        super().setUp()
        self.mount = self.root / "projects"
        self.mount.mkdir()
        os.environ[VARIABLE] = str(self.mount)  # restored with the Fixture's environment

    def add(self, *names, lock=True):
        """A folder below the mounted one, with the example lockfile unless lock is False."""
        folder = self.mount.joinpath(*names)
        folder.mkdir(parents=True)
        if lock:
            shutil.copyfile(self.head, folder / "package-lock.json")
        return folder

    def link(self, link, target):
        """A real symbolic link, or a skipped test where this account cannot make one."""
        try:
            os.symlink(target, link, target_is_directory=Path(target).is_dir())
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"no symbolic links for this account ({type(exc).__name__})")

    def listed(self, at=None):
        return self.page("/projects/mounted" + ("" if at is None else "?at=" + quote(at, safe="")))

    def register(self, path):
        return self.post(path, SESSION)

    def forms(self, page):
        """The folder paths that the page's registration forms send."""
        values = re.findall(r'<input type="hidden" name="path" value="([^"]*)">', page)
        return [html.unescape(value) for value in values]

    def assert_outside(self, path):
        response = self.register(str(path))
        self.assertEqual(response.status_code, 400, path)
        self.assertIn(self.app.REGISTER_ERRORS["outside"], response.text)
        self.assertNotIn(str(path), response.text)  # the input is not echoed


class ServeTests(ContainerFixture):
    def serve(self, port=0):
        """app.serve() with stand-ins for the listening socket and the server: (the address
        asked of socket.create_server, the uvicorn config, the port build_app was given, the
        lines printed)."""
        app, asked, started = self.app, [], {}
        real = app.socket.create_server

        def create_server(address):
            asked.append(address)
            return real(("127.0.0.1", 0))  # never the container's address on this machine

        class Server:
            should_exit = False

            def __init__(self, config):
                started["config"] = config

            def run(self, sockets):
                pass

        out = io.StringIO()
        with mock.patch.object(app.socket, "create_server", create_server), \
                mock.patch.object(app.uvicorn, "Server", Server), \
                mock.patch.object(app, "build_app", wraps=app.build_app) as built, \
                contextlib.redirect_stdout(out):  # fmt: skip
            app.serve(port)
        (address,) = asked
        return address, started["config"], built.call_args.args[0], out.getvalue().splitlines()

    def test_a_container_listens_on_every_interface_at_a_port_known_before_it_is_published(self):
        address, config, _, _ = self.serve()
        self.assertEqual((address, config.host), (("0.0.0.0", mounted.PORT), "0.0.0.0"))
        self.assertEqual(self.serve(6001)[0], ("0.0.0.0", 6001))
        # Outside a container nothing changes: 127.0.0.1 alone, and a free port.
        del os.environ[VARIABLE]
        address, config, _, lines = self.serve()
        self.assertEqual((address, config.host), (("127.0.0.1", 0), "127.0.0.1"))
        self.assertEqual(lines[1], self.app.STARTED)

    def test_the_address_printed_is_the_hosts_with_this_runs_session(self):
        _, config, guarded, (first, second) = self.serve()
        port = config.port
        self.assertRegex(first, rf"\Ahttp://127\.0\.0\.1:{port}/s/[A-Za-z0-9_-]{{43}}/\Z")
        self.assertEqual(guarded, port)  # the Host and Origin the app takes: 127.0.0.1 at it
        self.assertEqual(second, self.app.CONTAINER_STARTED.format(port=port))
        self.assertIn(f"docker run -p 127.0.0.1:{port}:{port}", second)
        self.assertNotIn(first.split("/")[4], second)  # the session is in the address only
        self.assertNotIn("0.0.0.0", first + second)
        self.assertNotEqual(first.split("/")[4], self.serve()[3][0].split("/")[4])  # per run

    def test_only_the_hosts_loopback_address_is_a_host_or_an_origin(self):
        project = str(self.add("app"))
        hosts = (f"0.0.0.0:{PORT}", f"172.17.0.2:{PORT}", f"localhost:{PORT}",
                 f"host.docker.internal:{PORT}", f"127.0.0.1:{PORT + 1}", "127.0.0.1", "*")  # fmt: skip
        for host in hosts:
            with self.subTest(host=host):
                response = self.client.get(S + "/", headers={"host": host})
                self.assertEqual(response.status_code, 400)
        origins = (f"http://0.0.0.0:{PORT}", f"http://172.17.0.2:{PORT}",
                   f"http://localhost:{PORT}", f"https://127.0.0.1:{PORT}", "null", "*", None)  # fmt: skip
        for origin in origins:
            with self.subTest(origin=origin):
                self.assertEqual(self.post(project, SESSION, origin=origin).status_code, 403)
        self.assertEqual(self.post(project, "not-this-session").status_code, 403)
        self.assertEqual(history.list_projects(), [])
        self.assertEqual(self.get("/").status_code, 200)
        self.assertEqual(self.register(project).status_code, 303)

    def test_a_container_has_no_background_instance(self):
        for option in ("--background", "--status", "--stop"):
            with self.subTest(option=option), \
                    mock.patch.object(lifecycle, "start") as start, \
                    mock.patch.object(lifecycle, "status") as status, \
                    mock.patch.object(lifecycle, "stop") as stop:  # fmt: skip
                err = io.StringIO()
                with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                    code = main(["dashboard", option])
                self.assertEqual(code, 2)
                self.assertIn("foreground only", json.loads(err.getvalue())["error"])
                for call in (start, status, stop):
                    call.assert_not_called()

    def test_the_mounted_folder_is_an_absolute_path_or_none(self):
        os.environ[VARIABLE] = "projects"
        with self.assertRaisesRegex(GuardError, VARIABLE):
            mounted.root()
        err = io.StringIO()
        with mock.patch.object(self.app.socket, "create_server") as bound, \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):  # fmt: skip
            code = main(["dashboard"])
        self.assertEqual(code, 2)
        self.assertIn(VARIABLE, json.loads(err.getvalue())["error"])
        bound.assert_not_called()  # refused before anything listens
        os.environ[VARIABLE] = ""
        self.assertIsNone(mounted.root())
        self.assertTrue(mounted.holds(self.project))


class PickerTests(ContainerFixture):
    """The folder button's request and the list it leads to."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(picker, "choose", side_effect=AssertionError("a dialog"))
        self.choose = patcher.start()
        self.addCleanup(patcher.stop)

    def pick(self, session=SESSION, origin=BASE):
        headers = {} if origin is None else {"origin": origin}
        return self.client.post(S + "/projects/pick", data={"session": session},
                                headers=headers, follow_redirects=False)  # fmt: skip

    def test_the_folder_button_leads_to_the_mounted_folders_and_opens_no_dialog(self):
        response = self.pick()
        self.assertEqual((response.status_code, response.headers["location"]),
                         (303, S + "/projects/mounted"))  # fmt: skip
        self.assertEqual(self.choose.call_count, 0)
        # It is still a form of this session, sent from this dashboard's own page.
        for refused in (self.pick(session="not-this-session"), self.pick(origin=None),
                        self.pick(origin=f"http://0.0.0.0:{PORT}")):  # fmt: skip
            self.assertEqual(refused.status_code, 403)
            self.assertNotIn("location", refused.headers)
        self.assertEqual(history.list_projects(), [])

    def test_the_start_pages_button_reaches_the_mounted_folders_and_their_way_back(self):
        project = self.add("app-a")
        start = self.page("/")
        self.assertIn('<body class="start">', start)
        # The start page's one form is the folder button's: in a container it leads to the list.
        self.assertEqual(re.findall(r'<form method="post" action="([^"]*)">', start),
                         [S + "/projects/pick"])  # fmt: skip
        self.assertEqual(self.pick().headers["location"], S + "/projects/mounted")
        page = self.listed()
        # Nothing is registered yet: the way back is the start page, as it was, and the typed
        # path has its place here, since project management opens only once a project is there.
        self.assertIn(f'<a href="{S}/">처음 화면으로 돌아가기</a>', page)
        self.assertNotIn("프로젝트 관리로 돌아가기", page)
        self.assertIn(f'<form method="post" action="{S}/projects">\n<input type="hidden" '
                      f'name="session" value="{SESSION}">\n<label for="path">', page)  # fmt: skip
        self.assertIn('<input id="path" name="path" type="text" maxlength="1024" required>', page)
        self.assertEqual(self.page("/"), start)
        self.assertEqual(self.page("/?manage=1"), start)
        # That typed path is checked as every other: outside is refused, inside is registered.
        # A refusal registers nothing, so what follows is still the first project of all: it
        # ends on the overview, where it stands with nothing inspected.
        self.assert_outside(self.project)
        self.assertEqual(history.list_projects(), [])
        self.assertEqual(self.register(str(project)).headers["location"], S + "/")
        overview = self.page("/")
        self.assertIn(f'<a class="ov-name" href="{S}/projects/1">app-a</a>', overview)
        self.assertIn('<span class="ov-label">미검사</span> <b class="ov-count">1</b>', overview)
        # With a project the way back is project management, whose folder button leads here too.
        page = self.listed()
        self.assertIn(f'<a href="{S}/?manage=1">프로젝트 관리로 돌아가기</a>', page)
        self.assertNotIn("처음 화면으로 돌아가기", page)
        self.assertIn(f'<form method="post" action="{S}/projects/pick">', self.page("/?manage=1"))
        self.assertEqual(self.pick().headers["location"], S + "/projects/mounted")
        self.assertEqual(self.choose.call_count, 0)

    def test_on_a_desktop_the_start_pages_button_opens_the_dialog_and_closing_it_comes_back(self):
        del os.environ[VARIABLE]
        start = self.page("/")
        self.choose.side_effect = None
        self.choose.return_value = ("cancelled", None)
        closed = self.pick()
        self.assertEqual((closed.status_code, closed.headers["location"]),
                         (303, S + "/?manage=1"))  # fmt: skip
        self.assertEqual(self.choose.call_count, 1)
        # Nothing registered: that address is the start page again, and no list of folders.
        self.assertEqual(self.page("/?manage=1"), start)
        self.assertEqual(history.list_projects(), [])
        self.assertEqual(self.get("/projects/mounted").status_code, 404)

    def test_the_first_page_and_the_management_page_are_the_ones_a_desktop_shows(self):
        first = self.page("/")
        self.assertIn(f'<form method="post" action="{S}/projects/pick">', first)
        self.assertEqual(self.register(str(self.add("app-a"))).status_code, 303)
        manage = self.page("/?manage=1")
        del os.environ[VARIABLE]
        self.assertEqual(manage, self.page("/?manage=1"))
        history.db_path().unlink()
        self.assertEqual(first, self.page("/"))

    def test_the_list_names_the_mounted_folders_and_marks_the_projects(self):
        project = self.add("app-a")
        self.add("notes", lock=False)
        self.add(".hidden")
        self.add("node_modules", "kept-out")
        (self.mount / "README.md").write_text("synthetic", encoding="utf-8")
        page = self.listed()
        self.assertIn("하위 폴더 2개", page)
        self.assertEqual(self.forms(page), [str(project)])
        marks = {"app-a": "npm 프로젝트", "notes": "package-lock.json 없음"}
        for name, mark in marks.items():
            self.assertIn(f'<a href="{S}/projects/mounted?at={name}">{name}</a> '
                          f'<span class="project-state">{mark}</span>', page)  # fmt: skip
        for kept_out in ("at=.hidden", "at=node_modules", "kept-out", "README.md"):
            self.assertNotIn(kept_out, page)
        # A folder is never uploaded, and looking registers and writes nothing.
        for upload in ('type="file"', "webkitdirectory", "multipart", "enctype"):
            self.assertNotIn(upload, page)
        self.assertEqual(history.list_projects(), [])
        self.assertFalse(self.db.exists())

    def test_a_folder_opens_its_subfolders_down_to_a_project(self):
        project = self.add("workspace", "web")
        odd = "한글 폴더 & x=1"
        self.add("workspace", odd, lock=False)
        page = self.listed("workspace")
        self.assertIn(f'<a href="{S}/projects/mounted">', page)  # the way back up
        self.assertIn('<li aria-current="page">workspace</li>', page)
        self.assertEqual(self.forms(page), [str(project)])
        link = f"{S}/projects/mounted?at={quote('workspace/' + odd, safe='/')}"
        self.assertIn(f'<a href="{link}">{html.escape(odd)}</a>', page)
        opened = self.client.get(link)
        self.assertEqual(opened.status_code, 200)
        self.assertIn(f'<li aria-current="page">{html.escape(odd)}</li>', opened.text)
        self.assertIn(f'<a href="{S}/projects/mounted?at=workspace">workspace</a>', opened.text)
        # A folder that is a project itself is offered where it is opened.
        page = self.listed("workspace/web")
        self.assertEqual(self.forms(page), [str(project)])
        self.assertIn('<button class="primary" type="submit">이 폴더 등록</button>', page)
        self.assertIn("하위 폴더 0개", page)
        self.assertIn("하위 폴더가 없습니다.", page)

    def test_the_first_listed_project_opens_the_overview_and_later_ones_their_project(self):
        for name in ("app-a", "app-b"):
            self.add(name)
        paths = self.forms(self.listed())
        self.assertEqual(paths, [str(self.mount / "app-a"), str(self.mount / "app-b")])
        # The first project of all ends on the overview, as on a desktop; the next one, which
        # project management's folder button leads to, on its own project.
        for path, location in zip(paths, (f"{S}/", f"{S}/projects/2"), strict=True):
            response = self.register(path)
            self.assertEqual((response.status_code, response.headers["location"]),
                             (303, location))  # fmt: skip
        self.assertEqual([project["path"] for project in history.list_projects()], paths)
        overview = self.page("/")
        self.assertIn("<title>프로젝트 현황판 - depbee</title>", overview)
        for number, name in enumerate(("app-a", "app-b"), 1):
            self.assertIn(f'<a class="ov-name" href="{S}/projects/{number}">{name}</a>', overview)
        self.assertIn(f'<p class="path">{paths[0]}</p>', self.page("/projects/1"))
        self.assertEqual(self.register(paths[0]).headers["location"], S + "/projects/1")
        self.assertEqual(self.choose.call_count, 0)

    def test_one_project_mounted_as_the_folder_itself_is_offered(self):
        shutil.copyfile(self.head, self.mount / "package-lock.json")
        page = self.listed()
        self.assertEqual(self.forms(page), [str(self.mount)])
        self.assertIn('<button class="primary" type="submit">이 폴더 등록</button>', page)
        self.assertEqual(self.register(str(self.mount)).headers["location"], S + "/")
        self.assertEqual(self.register(str(self.mount)).headers["location"], S + "/projects/1")

    def test_nothing_mounted_says_how_to_mount(self):
        page = self.listed()
        self.assertIn("연결한 프로젝트 폴더가 없습니다.", page)
        self.assertIn(f"target={self.mount}/&lt;이름&gt;", page)
        self.assertEqual(self.forms(page), [])
        os.environ[VARIABLE] = str(self.root / "not-there")
        page = self.listed()
        self.assertIn('role="alert">컨테이너에 연결한 폴더를 찾을 수 없습니다.</p>', page)
        self.assertEqual(self.forms(page), [])
        self.assertEqual(self.get("/projects/mounted?at=project").status_code, 404)

    def test_more_folders_than_the_list_shows_are_counted(self):
        for name in ("a", "b", "c"):
            self.add(name, lock=False)
        with mock.patch.object(mounted, "MAX_FOLDERS", 2):
            page = self.listed()
        self.assertIn("하위 폴더 3개", page)
        self.assertIn("이름순으로 2개만 표시했습니다. 나머지 1개는", page)
        self.assertNotIn("at=c", page)

    def test_outside_a_container_there_is_no_list_and_the_button_opens_the_dialog(self):
        self.add("app-a")
        del os.environ[VARIABLE]
        response = self.get("/projects/mounted")
        self.assertEqual((response.status_code, response.text), (404, self.app.MOUNTED_MISSING))
        self.choose.side_effect = None
        self.choose.return_value = ("cancelled", None)
        self.assertEqual(self.pick().headers["location"], S + "/?manage=1")
        self.assertEqual(self.choose.call_count, 1)


class ConfinementTests(ContainerFixture):
    """Nothing outside the mounted folder is listed, registered or used."""

    def test_the_list_never_leaves_the_mounted_folder(self):
        self.add("app-a")
        outside = str(self.project)
        odd = ["..", "../project", "app-a/..", "app-a/../..", "app-a/../../project", "/", "/etc",
               outside, outside.replace("\\", "/"), ".", "app-a/.", "app-a//", "/app-a",
               "app-a/", "app-a\\..", "..\\project", "app-a\x00", "%2e%2e", "~", "missing",
               "a" * (mounted.MAX_AT + 1)]  # fmt: skip
        for at in odd:
            with self.subTest(at=at[:30]):
                response = self.get("/projects/mounted?at=" + quote(at, safe=""))
                self.assertEqual((response.status_code, response.text),
                                 (404, self.app.MOUNTED_MISSING))  # fmt: skip
                self.assertIsNone(mounted.listing(at))
        self.assertEqual(self.get("/projects/mounted?at=app-a&at=app-a").status_code, 404)
        self.assertEqual(self.get("/projects/mounted?at=app-a").status_code, 200)

    def test_a_name_the_page_cannot_show_as_spelled_is_neither_listed_nor_opened(self):
        # Its registration form would send the escaped spelling, which is another path.
        hidden = "app‮a"  # a right-to-left override in the name
        self.add(hidden)
        self.add(hidden, "below")
        page = self.listed()
        self.assertEqual(self.forms(page), [])
        self.assertIn("하위 폴더 0개", page)
        for at in (hidden, hidden + "/below"):
            self.assertIsNone(mounted.listing(at))
            response = self.get("/projects/mounted?at=" + quote(at, safe=""))
            self.assertEqual(response.status_code, 404)

    def test_a_path_sent_to_the_registration_form_stays_inside(self):
        self.add("app-a")
        outside = [
            self.project,  # a real project
            self.root,  # a folder without a lockfile: nothing is said of what it holds
            self.mount / ".." / "project",
            self.mount / "app-a" / ".." / ".." / "project",
        ]
        for path in outside:
            with self.subTest(path=str(path)[-30:]):
                self.assert_outside(path)
        self.assertEqual(history.list_projects(), [])
        self.assertFalse(self.db.exists())
        # Nor is anything inside a folder that is not there.
        os.environ[VARIABLE] = str(self.root / "not-there")
        self.assert_outside(self.mount / "app-a")
        # A desktop registers the same folder as before.
        del os.environ[VARIABLE]
        self.assertEqual(self.register(str(self.project)).status_code, 303)

    def test_a_link_is_never_a_way_out(self):
        inside = self.add("app-a")
        swapped = self.add("swapped", lock=False)
        (self.project / "below").mkdir()  # a folder that is there, behind the link out
        self.link(self.mount / "escape", self.project)  # to a real project outside
        self.link(self.mount / "inner", inside)
        self.link(swapped / "package-lock.json", self.head)  # to a lockfile outside
        page = self.listed()
        self.assertEqual(self.forms(page), [str(inside)])
        self.assertIn('swapped</a> <span class="project-state">package-lock.json 없음</span>', page)
        for at in ("escape", "inner", "escape/below", "inner/.."):
            with self.subTest(at=at):
                self.assertNotIn(f"at={at}", page)
                self.assertEqual(self.get(f"/projects/mounted?at={at}").status_code, 404)
        for path in (self.mount / "escape", swapped, self.mount / "inner" / ".." / "escape"):
            with self.subTest(path=path.name):
                self.assert_outside(path)
        self.assertEqual(history.list_projects(), [])
        # A link that stays inside is the folder it leads to.
        self.assertEqual(self.register(str(self.mount / "inner")).status_code, 303)
        self.assertEqual([project["path"] for project in history.list_projects()], [str(inside)])

    def test_reported_links_are_resolved_before_the_folder_is_placed(self):
        inside = self.add("app-a")
        cases = {
            "a folder link out": ({self.mount / "escape": str(self.project)},
                                  self.mount / "escape", "outside"),
            "a lockfile link out": ({inside / "package-lock.json": str(self.head)},
                                    inside, "outside"),
            "a folder link that stays inside": ({self.mount / "inner": str(inside)},
                                                self.mount / "inner", None),
        }  # fmt: skip
        for label, (links, path, problem) in cases.items():
            lstat, readlink, follow = test_mcp.ResponseTests.links(self, links)
            with self.subTest(label), mock.patch("os.lstat", lstat), \
                    mock.patch("os.readlink", readlink), \
                    mock.patch("pathlib.Path.stat", autospec=True, side_effect=follow):  # fmt: skip
                self.assertEqual(self.app._registration_problem(str(path)), problem)
                # Nor does the list open a link or a folder behind one (the stand-in for
                # os.lstat fails the test if anything behind a link is looked at).
                for at in ("escape", "escape/below", "inner", "inner/below"):
                    self.assertIsNone(mounted.listing(at), at)


class StoredOutsideTests(ScreenFixture):
    """A project the history holds from outside the mounted folder (self.project, registered by
    the fixture): its records stay, and nothing runs on its folder."""

    def setUp(self):
        super().setUp()
        self.scan_project = self.patch_service("scan_project", lambda *a, **k: self.report)
        self.mount = self.root / "projects"
        self.mount.mkdir()

    def scan(self):
        return self.client.post(f"{S}/projects/{self.project_id}/scans",
                                data={"session": SESSION}, headers={"origin": BASE},
                                follow_redirects=False)  # fmt: skip

    def test_nothing_is_checked_scanned_or_applied_there(self):
        held = self.preview_id()  # made while the folder was still a project's
        os.environ[VARIABLE] = str(self.mount)
        path = str(self.project)
        self.assertFalse(self.app._found(path))
        self.assertIsNone(self.app._sha256(path, "package-lock.json"))
        self.assertIn("폴더를 찾을 수 없음", self.page("/?manage=1"))
        self.assertIn(
            "프로젝트 폴더를 찾을 수 없습니다.", self.page(f"/projects/{self.project_id}")
        )
        for response in (self.check(), self.scan(), self.apply(held)):
            self.assertEqual(response.status_code, 400)
            self.assertIn(self.app.PROJECT_MISSING, response.text)
        self.assertEqual((self.preview_files.call_count, self.scan_project.call_count,
                          self.apply_preview.call_count), (1, 0, 0))  # fmt: skip
        self.assertEqual(len(history.list_runs(self.project_id)), 1)  # still there to read
        # On a desktop the same folder is used as before.
        del os.environ[VARIABLE]
        self.assertTrue(self.app._found(path))
        self.assertEqual(self.scan().status_code, 303)
        self.assertEqual(self.apply(held).status_code, 200)
        self.assertEqual(service.apply_preview.call_count, 1)
