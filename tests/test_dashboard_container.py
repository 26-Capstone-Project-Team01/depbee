"""A dashboard in a container (dashboard.mounted): where it listens, the folder picker behind
the folder button, and what may be registered or used as a project.

Synthetic folders in each test run's folder stand for the mounted ones (DEPBEE_CONTAINER_PROJECTS
names one of them); no container, no desktop dialog, no server (a stand-in for uvicorn.Server),
no npm, no Git and no registry. Real links are made where the system lets a test make them,
which an ordinary Windows account does not, and only to synthetic files of the test run. What a
link does to a check is tested on entries that os.lstat is made to report as links
(test_apply.reported): nothing is linked there, and fenced() fails a test that looks behind one.
"""

import builtins
import contextlib
import html
import io
import json
import os
import re
import shutil
import stat
from pathlib import Path
from unittest import mock
from urllib.parse import quote

from test_dashboard import BASE, PORT, SESSION, DashboardFixture, S, ScreenFixture, project_head
from test_workflow import LINKS, reported

from depbee import history, service
from depbee.cli import main
from depbee.contracts import GuardError
from depbee.dashboard import lifecycle, mounted, picker

VARIABLE = "DEPBEE_CONTAINER_PROJECTS"
LINK = LINKS["symlink"]


@contextlib.contextmanager
def fenced(*roots, look=False):
    """No file-system call may name one of roots or anything below it: os.stat, os.readlink,
    os.scandir, os.listdir and every open fail the test there, and os.lstat too unless look
    (lstat reads the entry itself, never what a link names). Yields the calls that tried,
    which stay empty: a handler that swallowed the failure is still found out."""
    roots = [Path(root) for root in roots]
    tried = []

    def guard(real, name):
        def call(target, *args, **kwargs):
            if isinstance(target, (str, os.PathLike)):
                path = Path(target)
                if any(path == root or root in path.parents for root in roots):
                    tried.append((name, str(path)))
                    raise AssertionError(f"{name} looked at {path}")
            return real(target, *args, **kwargs)

        return call

    names = [(os, "stat"), (os, "readlink"), (os, "scandir"), (os, "listdir"), (os, "open"),
             (io, "open"), (builtins, "open"), *([] if look else [(os, "lstat")])]  # fmt: skip
    with contextlib.ExitStack() as stack:
        for owner, name in names:
            stack.enter_context(mock.patch.object(owner, name, guard(getattr(owner, name), name)))
        yield tried


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

    def unhinted(self, page):
        """The page without what says where the folder button leads: its note paragraphs (the
        hints of the folder button and of the typed path are among them), the start page's hint
        for a screen reader, the folder button's words while its request runs, and the footer's
        explanation of where the page opens (its help popover). They alone differ between a
        container's page and a desktop's."""
        page = re.sub(r'<p class="note"[^>]*>[^<]*</p>\n', "", page)
        page = re.sub(
            r'<div class="help-pop" id="help-where" popover>.*?</div>', "", page, flags=re.S
        )
        page = re.sub(r'<p class="visually-hidden" id="start-hint">[^<]*</p>\n', "", page)
        folder_button = r">프로젝트 (?:추가|폴더 선택)</button>"
        return re.sub(rf' data-busy-label="[^"]*"(?={folder_button})', "", page)

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
        self.assertTrue(self.app._found(str(self.project)))  # a desktop's folder, as before


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
        self.assertIn(f'<a class="ov-name" href="{S}/projects/1" title="app-a">app-a</a>', overview)
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
        # Word for word, but for what says where the folder button leads: the hints of that
        # button and of the typed path, and the button's words while its request runs (the next
        # two tests).
        del os.environ[VARIABLE]
        self.assertEqual(self.unhinted(manage), self.unhinted(self.page("/?manage=1")))
        history.db_path().unlink()
        self.assertEqual(self.unhinted(first), self.unhinted(self.page("/")))

    def test_the_start_pages_one_button_says_what_it_opens_in_a_container(self):
        hint = '<p class="visually-hidden" id="start-hint">package-lock.json이 있는 npm 프로젝트 폴더를 '
        button = '<button type="submit" aria-describedby="start-hint" data-busy-label="{}">'
        page = self.page("/")
        # Still the one button with the same words on it, and nothing else to see. What it
        # opens is said to a screen reader, and by the button itself while its request runs:
        # the list of the mounted folders, not a folder dialog on this PC.
        self.assertEqual(re.findall(r"<button [^>]*>([^<]*)</button>", page), ["프로젝트 추가"])
        self.assertEqual(re.findall(r'<p class="([^"]*)"', page), ["visually-hidden"] * 2)
        self.assertIn(button.format("연결한 폴더 목록을 여는 중…") + "프로젝트 추가</button>", page)
        self.assertIn(hint + "컨테이너에 연결한 폴더 목록에서 고릅니다.</p>", page)
        for words in ("이 PC", "폴더 선택 창"):
            self.assertNotIn(words, page)
        # A desktop keeps its own words and is told nothing of a container.
        del os.environ[VARIABLE]
        desktop = self.page("/")
        self.assertIn(
            button.format("폴더 선택 창을 확인하세요…") + "프로젝트 추가</button>", desktop
        )
        self.assertIn(hint + "이 PC에서 고릅니다.</p>", desktop)
        for words in ("컨테이너", "연결한 폴더"):
            self.assertNotIn(words, desktop)

    def test_the_management_page_says_what_the_folder_button_does_in_a_container(self):
        # What only a desktop's page says: this PC, and the folder dialog's limit and keys.
        desktop_only = ("이 PC에서 폴더를 열어", "폴더 선택 창을 열 수 없거나",
                        f"{picker.PICK_SECONDS}초 뒤 닫히며", self.app.SWITCH_KEYS,
                        'data-busy-label="폴더 선택 창을 확인하세요…">프로젝트 폴더 선택</button>')  # fmt: skip
        self.assertEqual(self.register(str(self.add("app-a"))).status_code, 303)
        page = self.page("/?manage=1")
        self.assertIn(f'<form method="post" action="{S}/projects/pick">', page)
        self.assertIn('id="pick-hint">컨테이너에 연결한 폴더의 목록을 엽니다.', page)
        self.assertIn('id="path-hint">컨테이너 안의 경로를 적습니다.', page)
        # While its request runs the button names that list too, not a dialog to look for.
        self.assertIn(
            'data-busy-label="연결한 폴더 목록을 여는 중…">프로젝트 폴더 선택</button>', page
        )
        # The button and the typed path are still described by one hint each.
        self.assertEqual((page.count('id="pick-hint"'), page.count('id="path-hint"')), (1, 1))
        for words in desktop_only:
            self.assertNotIn(words, page)
        # A desktop keeps its own words and is told nothing of a container.
        del os.environ[VARIABLE]
        desktop = self.page("/?manage=1")
        for words in desktop_only:
            self.assertIn(words, desktop)
        for words in ("컨테이너", "연결한 폴더"):
            self.assertNotIn(words, desktop)

    def test_the_footer_and_a_missing_folder_are_worded_for_a_container(self):
        published = ("이 화면은 docker run의 -p로 컨테이너의 포트를 호스트의 127.0.0.1에만 "
                     "게시했을 때 이 PC에서만 열립니다.")  # fmt: skip
        local = "이 화면은 이 PC의 127.0.0.1에서만 열립니다."
        remount = (
            "대시보드 컨테이너를 종료한 뒤 이 폴더를 같은 별칭으로(위의 컨테이너 경로) 다시 연결해"
        )
        restore = "폴더를 원래 위치로 되돌리"
        project = self.add("app-a")
        self.assertEqual(self.register(str(project)).status_code, 303)
        shutil.rmtree(project)  # as when the container is started again without that mount
        views = ("/?manage=1", "/projects/1", "/projects/1/updates", "/projects/1/history")
        for url in ("/", *views):
            page = self.page(url)
            # Who can open the page is decided by how Docker published the port, so nothing
            # is promised of this PC's 127.0.0.1 without saying so.
            self.assertIn(published, page, url)
            self.assertNotIn(local, page, url)
            # The folder comes back by mounting it again at its path, under the same name.
            self.assertEqual(remount in page, url in views, url)
            for words in (restore, "새로 등록하세요"):
                self.assertNotIn(words, page, url)
        # A desktop keeps its own words and is told nothing of a container.
        del os.environ[VARIABLE]
        for url in ("/", *views):
            page = self.page(url)
            self.assertIn(local, page, url)
            self.assertEqual(restore in page, url in views, url)
            # "docker run", the footer's own words: these pages show the project's path, and a
            # checkout can be in a folder named after Docker.
            for words in ("컨테이너", "별칭", "docker run"):
                self.assertNotIn(words, page, url)

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
            self.assertIn(f'<a class="ov-name" href="{S}/projects/{number}" title="{name}">{name}</a>', overview)
        self.assertEqual(
            project_head(self.page("/projects/1"))[1:], (self.app._short_path(paths[0]), paths[0])
        )
        self.assertEqual(self.register(paths[0]).headers["location"], S + "/projects/1")
        self.assertEqual(self.choose.call_count, 0)

    def test_one_project_mounted_as_the_folder_itself_is_offered(self):
        shutil.copyfile(self.head, self.mount / "package-lock.json")
        page = self.listed()
        self.assertEqual(self.forms(page), [str(self.mount)])
        self.assertIn('<button class="primary" type="submit">이 폴더 등록</button>', page)
        self.assertEqual(self.register(str(self.mount)).headers["location"], S + "/")
        self.assertEqual(self.register(str(self.mount)).headers["location"], S + "/projects/1")

    def test_how_to_mount_a_folder_is_said_once_and_read_only(self):
        def option(page):
            """The docker run option a page shows: one, whatever the page lists."""
            (shown,) = re.findall(r'<p class="path">(--mount [^<]*)</p>', page)
            return html.unescape(shown)

        def expected(top):
            source = "source=<호스트의 프로젝트 폴더>"
            return f'--mount "type=bind,{source},target={top}/<별칭>,readonly"'

        page = self.listed()
        self.assertIn("연결한 프로젝트 폴더가 없습니다.", page)
        self.assertEqual(option(page), expected(self.mount))
        self.assertEqual(self.forms(page), [])
        # Below a list of folders and in an opened folder it is the same read-only option.
        self.add("app-a")
        for at in (None, "app-a"):
            self.assertEqual(option(self.listed(at)), expected(self.mount))
        missing = self.root / "not-there"
        os.environ[VARIABLE] = str(missing)
        page = self.listed()
        self.assertIn('role="alert">컨테이너에 연결한 폴더를 찾을 수 없습니다.</p>', page)
        self.assertEqual(option(page), expected(missing))
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
        # A link is refused wherever it leads: the folder it names is registered by its own
        # path, as the list offers it.
        links = (self.mount / "escape", swapped, self.mount / "inner" / ".." / "escape",
                 self.mount / "inner", self.mount / "inner" / ".." / "app-a")  # fmt: skip
        for path in links:
            with self.subTest(path=path.name):
                self.assert_outside(path)
        self.assertEqual(history.list_projects(), [])
        self.assertEqual(self.register(str(inside)).status_code, 303)

    def test_an_entry_reported_as_a_link_is_refused_and_never_read(self):
        inside = self.add("app-a")
        entry = self.mount / "entry"
        entry.mkdir()
        for kind, mode in LINKS.items():
            with self.subTest("a linked folder", kind=kind), reported(entry, mode), \
                    fenced(entry, look=True) as tried:  # fmt: skip
                for path in (entry, entry / "app"):
                    self.assertEqual(self.app._registration_problem(str(path)), "outside")
                    self.assertFalse(self.app._found(str(path)))
                for at in ("entry", "entry/app"):
                    self.assertIsNone(mounted.listing(at))
                self.assertEqual(tried, [])
            lock = inside / "package-lock.json"
            with self.subTest("a linked lockfile", kind=kind), reported(lock, mode), \
                    fenced(lock, look=True) as tried:  # fmt: skip
                self.assertEqual(self.app._registration_problem(str(inside)), "outside")
                self.assertIsNone(self.app._sha256(str(inside), "package-lock.json"))
                (row,) = [row for row in mounted.listing("")["folders"] if row["name"] == "app-a"]
                self.assertFalse(row["project"])
                self.assertEqual(tried, [])
        self.assertIsNone(self.app._registration_problem(str(inside)))


class ProblemTests(ContainerFixture):
    """mounted.problem(): what a container's dashboard may use as it is spelled."""

    def test_a_path_outside_the_mounted_folder_is_told_from_its_spelling_alone(self):
        self.add("app")
        outside = [self.project, self.project / "package-lock.json", self.root, self.root.parent,
                   Path(str(self.mount) + "-2"), self.mount / ".." / "project",
                   self.mount / "app" / ".." / ".." / "project", self.mount / "app" / "..",
                   Path("app"), Path("projects") / "app", Path(self.mount.anchor)]  # fmt: skip
        top = mounted._top()  # the mounted folder itself is looked at, not the path asked about
        looked = AssertionError("the file system was looked at")
        with mock.patch.object(mounted, "_top", return_value=top), \
                mock.patch("os.lstat", side_effect=looked), \
                mock.patch("os.stat", side_effect=looked), \
                mock.patch("os.readlink", side_effect=looked):  # fmt: skip
            for path in outside:
                with self.subTest(path=str(path)[-40:]):
                    self.assertEqual(mounted.problem(path), "outside")
                    self.assertEqual(mounted.problem(path, stat.S_ISREG), "outside")
        # Without a mounted folder that is there, every path is outside it.
        os.environ[VARIABLE] = str(self.root / "not-there")
        self.assertEqual(mounted.problem(self.mount / "app"), "outside")

    def test_what_is_in_the_mounted_folder_is_looked_at_and_never_followed(self):
        app = self.add("app")
        lock = app / "package-lock.json"
        with mock.patch("os.readlink", side_effect=AssertionError("a link was read")):
            self.assertIsNone(mounted.problem(self.mount))
            self.assertIsNone(mounted.problem(app))
            self.assertIsNone(mounted.problem(lock, stat.S_ISREG))
            self.assertEqual(mounted.problem(app, stat.S_ISREG), "kind")
            self.assertEqual(mounted.problem(lock), "kind")
            self.assertEqual(mounted.problem(self.mount, stat.S_ISREG), "kind")
            for missing in (app / "none", self.mount / "none" / "app", lock / "below"):
                self.assertEqual(mounted.problem(missing), "missing")
                self.assertEqual(mounted.problem(missing, stat.S_ISREG), "missing")
            for kind, mode in LINKS.items():
                with self.subTest(kind=kind), reported(app, mode), fenced(app, look=True) as tried:
                    self.assertEqual(mounted.problem(app), "link")
                    self.assertEqual(mounted.problem(lock, stat.S_ISREG), "link")
                    self.assertEqual(tried, [])
                with self.subTest(kind=kind, entry="the file"), reported(lock, mode):
                    self.assertEqual(mounted.problem(lock, stat.S_ISREG), "link")
                    self.assertIsNone(mounted.problem(app))

    def test_an_entry_that_cannot_be_looked_at_is_not_taken_for_a_missing_one(self):
        app = self.add("app")
        lock = app / "package-lock.json"
        for failure in (PermissionError(13, "synthetic"), OSError(5, "synthetic")):
            with self.subTest(type(failure).__name__, entry="the file"), reported(lock, failure):
                self.assertEqual(mounted.problem(lock, stat.S_ISREG), "unreadable")
                self.assertTrue(self.app._refused(str(app), "package-lock.json"))
                self.assertIsNone(self.app._sha256(str(app), "package-lock.json"))
                self.assertEqual(self.app._registration_problem(str(app)), "unreadable")
            with self.subTest(type(failure).__name__, entry="the folder"), reported(app, failure):
                self.assertEqual(mounted.problem(app), "unreadable")
                self.assertFalse(self.app._found(str(app)))
                self.assertTrue(self.app._refused(str(app), "package-lock.json"))
                self.assertEqual(self.app._registration_problem(str(app)), "unreadable")
        # What is really not there stays missing: the reader of the file says so itself.
        lock.unlink()
        self.assertEqual(mounted.problem(lock, stat.S_ISREG), "missing")
        self.assertFalse(self.app._refused(str(app), "package-lock.json"))
        self.assertEqual(self.app._registration_problem(str(app)), "lockfile")


class InstallChoiceTests(ScreenFixture):
    """The apply form of a preview: a container says by the install choice itself what its
    install does to the mounted folder. A desktop's form says nothing of it."""

    def test_a_container_says_by_the_install_choice_what_it_installs(self):
        preview = f"/previews/{self.preview_id()}"
        desktop = self.page(preview)
        os.environ[VARIABLE] = str(self.root)  # the registered project is a mounted folder now
        page = self.page(preview)
        choices = page.partition("<legend>반영 방식</legend>")[2].partition("</fieldset>")[0]
        radio = '<input type="radio" id="mode-install" name="mode" value="install"'
        self.assertIn(f'{radio} aria-describedby="install-note">', choices)
        note = re.search(r'<p class="note" id="install-note">([^<]+)</p>', choices)
        self.assertLess(choices.index(radio), note.start())  # right below the choice it is about
        for words in ("컨테이너의 Linux용 npm", "node_modules", "lockfile 반영을 고르고",
                      "호스트에서 npm ci --ignore-scripts", "readonly"):  # fmt: skip
            self.assertIn(words, note[1])
        self.assertEqual(page.count("install-note"), 2)  # the note, and the one choice it is for
        # A desktop installs for itself and is told nothing of it.
        self.assertIn(f"{radio}>", desktop)
        for words in ("install-note", "Linux", "컨테이너"):
            self.assertNotIn(words, desktop)


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
        # Its path is outside by its spelling: the folder and its files are not even looked at.
        with fenced(self.project) as tried:
            self.assertFalse(self.app._found(path))
            self.assertIsNone(self.app._sha256(path, "package-lock.json"))
            self.assertEqual(self.app._preview_targets(path), set())
            self.assertIn("폴더를 찾을 수 없음", self.page("/?manage=1"))
            self.assertIn("폴더를 찾을 수 없습니다.", self.page("/"))
            for view in ("", "/updates", "/history"):
                self.assertIn("프로젝트 폴더를 찾을 수 없습니다.",
                              self.page(f"/projects/{self.project_id}{view}"))  # fmt: skip
            for response in (self.check(), self.scan(), self.apply(held)):
                self.assertEqual(response.status_code, 400)
                self.assertIn(self.app.PROJECT_MISSING, response.text)
            self.assertEqual(tried, [])
        self.assertEqual((self.preview_files.call_count, self.scan_project.call_count,
                          self.apply_preview.call_count), (1, 0, 0))  # fmt: skip
        self.assertEqual(len(history.list_runs(self.project_id)), 1)  # still there to read
        # On a desktop the same folder is used as before.
        del os.environ[VARIABLE]
        self.assertTrue(self.app._found(path))
        self.assertEqual(self.scan().status_code, 303)
        self.assertEqual(self.apply(held).status_code, 200)
        self.assertEqual(service.apply_preview.call_count, 1)


class LiveInputTests(ScreenFixture):
    """A project registered in the mounted folder (self.inside): each time it is used, its
    folder, its two files and its Git folder must still be the project's own. The services
    are replaced (ScreenFixture), so a test sees whether one was handed the project at all."""

    FILES = ("package-lock.json", "package.json")

    def setUp(self):
        super().setUp()
        self.scan_project = self.patch_service("scan_project", lambda *a, **k: self.report)
        self.mount = self.root / "projects"
        self.inside = self.mount / "app"
        self.git_dir = self.inside / ".git"
        (self.git_dir / "objects").mkdir(parents=True)
        lock = {**self.new, "packages": {"": {"dependencies": {"example": "^1.0.0"}},
                                         **self.new["packages"]}}  # fmt: skip
        self.write(self.inside / "package-lock.json", lock)
        self.write(self.inside / "package.json", {"name": "app", "dependencies": {"example": "^1"}})
        os.environ[VARIABLE] = str(self.mount)
        self.project_id = history.register_project(self.inside)
        self.url = f"/projects/{self.project_id}"
        self.target = 'name="packages" value="example"'  # the row's update check button

    def scan(self):
        return self.client.post(f"{S}{self.url}/scans", data={"session": SESSION},
                                headers={"origin": BASE}, follow_redirects=False)  # fmt: skip

    def handed(self):
        """How often each service was given the project."""
        return (self.preview_files.call_count, self.scan_project.call_count,
                self.apply_preview.call_count)  # fmt: skip

    def test_a_project_of_its_own_files_is_read_checked_scanned_and_applied(self):
        page = self.page(self.url)
        self.assertIn("직접 1개, 중첩 0개", page)
        self.assertIn(self.target, page)
        for name in self.FILES:
            self.assertEqual(len(self.app._sha256(str(self.inside), name)), 64)
        held = self.preview_id()
        self.assertEqual(self.scan().status_code, 303)
        self.assertEqual(self.apply(held).status_code, 200)
        self.assertEqual(self.handed(), (1, 1, 1))
        project = Path(str(self.inside))
        self.assertEqual(self.previewed[0][0], project)
        self.assertEqual(self.applied[0]["project"], project)
        # Git is told which folder to read: the project's own, inside the mounted folder.
        scanned = self.scan_project.call_args
        self.assertEqual(scanned.args, (project, None))
        self.assertEqual((scanned.kwargs["git_dir"], scanned.kwargs["base_ref"]),
                         (self.git_dir, None))  # fmt: skip
        # A desktop leaves the repository to Git, as before.
        del os.environ[VARIABLE]
        self.assertEqual(self.scan().status_code, 303)
        self.assertNotIn("git_dir", self.scan_project.call_args.kwargs)

    def test_a_file_that_is_no_longer_the_projects_own_is_not_read_or_handed_on(self):
        held = self.preview_id()
        a_folder = os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        for name in self.FILES:
            file = self.inside / name
            for kind, mode in {**LINKS, "a folder": a_folder}.items():
                with self.subTest(name, kind=kind), reported(file, mode), \
                        fenced(file, look=True) as tried, \
                        mock.patch.object(service, "list_dependencies",
                                          wraps=service.list_dependencies) as listed:  # fmt: skip
                    page = self.page(self.url)
                    lockfile = name == "package-lock.json"
                    self.assertEqual("package-lock.json이 일반 파일이 아닙니다." in page, lockfile)
                    self.assertEqual(listed.call_count, 0 if lockfile else 1)
                    self.assertNotIn(self.target, page)
                    self.assertIsNone(self.app._sha256(str(self.inside), name))
                    self.page(self.url + "/updates")
                    refused = [self.check(), self.apply(held), *([self.scan()] if lockfile else [])]
                    for response in refused:
                        self.assertEqual(response.status_code, 400)
                        self.assertIn(self.app.INPUT_REFUSED, response.text)
                    self.assertEqual(self.handed(), (1, 0, 0))
                    self.assertEqual(tried, [])
        # The preview was not used up: once the files are the project's own again, it applies.
        self.assertEqual(self.apply(held).status_code, 200)
        self.assertEqual(self.handed(), (1, 0, 1))

    def test_git_is_given_only_a_git_folder_of_its_own_in_the_mounted_folder(self):
        def refused(case, why="is not a Git folder with its own objects"):
            response = self.scan()
            self.assertEqual(response.status_code, 400, case)
            self.assertIn(why, response.text, case)
            self.assertEqual(self.scan_project.call_count, 0, case)

        objects = self.git_dir / "objects"
        # Entries that would send Git to another folder: pointer files, and links.
        pointers = {"commondir": self.git_dir / "commondir",
                    "alternates": objects / "info" / "alternates"}  # fmt: skip
        for case, pointer in pointers.items():
            pointer.parent.mkdir(exist_ok=True)
            pointer.write_text("../../elsewhere\n", encoding="utf-8")
            refused(case)
            pointer.unlink()
        for kind, mode in LINKS.items():
            for entry in (self.git_dir, objects, pointers["commondir"], pointers["alternates"]):
                with reported(entry, mode), fenced(entry, look=True) as tried:
                    refused(f"{entry.name} as a {kind}")
                    self.assertEqual(tried, [])
        shutil.rmtree(objects)
        refused("no objects folder")
        # A .git file names a Git folder somewhere else (a worktree, a submodule).
        shutil.rmtree(self.git_dir)
        self.git_dir.write_text("gitdir: ../elsewhere/.git/worktrees/app\n", encoding="utf-8")
        with fenced(self.git_dir, look=True) as tried:
            refused("a .git file")
            self.assertEqual(tried, [])
        self.git_dir.unlink()
        # No Git folder in the mounted folder: one above it is not looked for.
        above = self.root / ".git"
        (above / "objects").mkdir(parents=True)
        with fenced(above) as tried:
            refused("a Git folder above the mounted folder",
                    "no .git folder at or above it in the mounted folder")  # fmt: skip
            self.assertEqual(tried, [])
        nearest = self.mount / ".git"
        (nearest / "objects").mkdir(parents=True)
        # A .git that cannot be looked at is not passed over for the one above it.
        for failure in (PermissionError(13, "synthetic"), OSError(5, "synthetic")):
            with reported(self.git_dir, failure):
                refused(f"a .git that cannot be looked at ({type(failure).__name__})")
        # The nearest one at or above the project, up to the mounted folder itself, is used.
        self.assertEqual(self.scan().status_code, 303)
        self.assertEqual(self.scan_project.call_args.kwargs["git_dir"], nearest)
