"""The dashboard's folder dialog (dashboard.picker) and the route that registers its answer.

No desktop dialog is opened here. The route tests replace picker.choose; the child's own code
runs in this process with a stand-in for tkinter; and choose() runs real child processes, but of
small synthetic scripts written into the test run's folder instead of the dialog's.
"""

import ast
import contextlib
import io
import json
import os
import subprocess
import sys
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from test_dashboard import (
    BASE,
    PORT,
    SESSION,
    DashboardFixture,
    S,
    assert_one_script,
    project_head,
)
from test_workflow import Fixture

from depbee import history
from depbee.dashboard import picker

PICK_FORM = f'<form method="post" action="{S}/projects/pick">'
PATH_FORM = f'<form method="post" action="{S}/projects">'
CLOSED = "<details>\n<summary>폴더 경로 직접 입력</summary>"
OPEN = "<details open>\n<summary>폴더 경로 직접 입력</summary>"


def stand_in(root: Path, source: str) -> str:
    """A synthetic script for choose() to run in place of the dialog's."""
    script = root / "stand_in_dialog.py"
    script.write_text(source, encoding="utf-8")
    return str(script)


def answering(folder: object) -> str:
    """The source of a child that answers as the dialog's does: one line of ASCII JSON."""
    return f"import sys\nsys.stdout.write({json.dumps({'folder': folder})!r})\n"


class PickRouteTests(DashboardFixture):
    """POST /projects/pick with picker.choose replaced: what each answer of the dialog does."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(picker, "choose", return_value=("cancelled", None))
        self.choose = patcher.start()
        self.addCleanup(patcher.stop)

    def pick(self, session=SESSION, origin=BASE, client=None):
        headers = {} if origin is None else {"origin": origin}
        return (client or self.client).post(S + "/projects/pick", data={"session": session},
                                            headers=headers, follow_redirects=False)  # fmt: skip

    def files(self):
        """Everything in the test run's folder: the history file and the settings folder would
        be created there."""
        return sorted(str(path) for path in self.root.rglob("*"))

    def assert_nothing_registered(self, before):
        self.assertEqual(history.list_projects(), [])
        self.assertFalse(self.db.exists())
        self.assertEqual(self.files(), before)

    def test_the_dialog_comes_first_and_the_typed_path_is_folded_under_it(self):
        # Before the first project the dialog's form is all there is (the start page): the same
        # address and the same field as project management's, and no typed path beside it.
        html = self.page("/")
        self.assertIn(f'{PICK_FORM}\n<input type="hidden" name="session" value="{SESSION}">\n'
                      '<button type="submit" ', html)  # fmt: skip
        self.assertEqual((html.count("<form "), html.count("<button ")), (1, 1))
        self.assertNotIn(PATH_FORM, html)
        self.assertNotIn("<details", html)
        for upload in ('type="file"', "webkitdirectory", "multipart", "enctype"):
            self.assertNotIn(upload, html)
        self.assertEqual(self.choose.call_count, 0)  # looking opens no dialog
        # With a project, project management has the dialog first and the typed path under it.
        history.register_project(self.project)
        html = self.page("/?manage=1")
        self.assertNotIn("등록한 프로젝트가 없습니다.", html)
        button = ('<button class="primary" type="submit" aria-describedby="pick-hint" '
                  'data-busy-label="폴더 선택 창을 확인하세요…">프로젝트 폴더 선택</button>')  # fmt: skip
        self.assertIn(f'{PICK_FORM}\n<input type="hidden" name="session" value="{SESSION}">\n'
                      f"{button}\n</form>", html)  # fmt: skip
        self.assertIn(
            '<p class="note" id="pick-hint">이 PC에서 폴더를 열어 파일을 읽습니다.</p>', html
        )
        # The dialog's time limit and the way back to its window are folded with the typed path.
        folded = html.partition(CLOSED)[2]
        self.assertIn(f"창은 {picker.PICK_SECONDS}초 뒤 닫히며", folded)
        self.assertIn(f"{self.app.SWITCH_KEYS}으로 전환하세요.</p>", folded)
        # The typed path is still there, closed, after the dialog's button; it is not primary.
        self.assertIn(CLOSED, html)
        self.assertLess(html.index(PICK_FORM), html.index(CLOSED))
        self.assertLess(html.index(CLOSED), html.index(PATH_FORM))
        self.assertLess(html.index(PATH_FORM), html.index("</details>"))
        self.assertIn('<button type="submit">등록</button>', html)
        self.assertEqual(html.count('class="primary"'), 1)
        self.assertNotIn('role="alert"', html)
        # A folder is never uploaded: no file input, no multipart form.
        for upload in ('type="file"', "webkitdirectory", "multipart", "enctype"):
            self.assertNotIn(upload, html)
        # The section comes before the list of the registered projects.
        self.assertLess(html.index(PICK_FORM), html.index("등록한 프로젝트 1개"))
        self.assertEqual(self.choose.call_count, 0)  # looking opens no dialog

    def test_the_first_chosen_folder_opens_the_overview_and_later_ones_their_project(self):
        self.choose.return_value = ("chosen", str(self.project))
        response = self.pick()
        # The first project of all: registered, and the overview is where the button ends.
        self.assertEqual((response.status_code, response.headers["location"]),
                         (303, S + "/"))  # fmt: skip
        self.choose.assert_called_once_with()
        (project,) = history.list_projects()
        self.assertEqual(project["path"], str(self.project.resolve()))
        overview = self.page("/")
        self.assertIn("<title>프로젝트 현황판 - depbee</title>", overview)
        self.assertIn(f'<a class="ov-name" href="{S}/projects/1" title="project">project</a>', overview)
        self.assertEqual(project_head(self.page("/projects/1"))[::2],
                         ("project", str(self.project.resolve())))  # fmt: skip
        # The same folder again opens the first registration, as the typed path does.
        self.choose.return_value = ("chosen", str(self.project) + os.sep)
        self.assertEqual(self.pick().headers["location"], S + "/projects/1")
        self.assertEqual(self.post(str(self.project), SESSION).headers["location"],
                         S + "/projects/1")  # fmt: skip
        self.assertEqual(len(history.list_projects()), 1)
        # A folder chosen from project management once a project is there opens its own project.
        second = self.root / "second"
        second.mkdir()
        (second / "package-lock.json").write_bytes(self.head.read_bytes())
        self.choose.return_value = ("chosen", str(second))
        self.assertEqual(self.pick().headers["location"], S + "/projects/2")
        self.assertEqual(len(history.list_projects()), 2)

    def test_closing_the_dialog_registers_and_writes_nothing(self):
        before = self.files()
        response = self.pick()
        self.assertEqual(
            (response.status_code, response.headers["location"]), (303, S + "/?manage=1")
        )
        self.assert_nothing_registered(before)
        # With nothing registered that address is the start page again: the button, no message.
        html = self.page("/?manage=1")
        self.assertIn('<body class="start">', html)
        self.assertIn(PICK_FORM, html)
        self.assertNotIn('role="alert"', html)
        # With a project it is project management, the typed path folded as before.
        history.register_project(self.project)
        self.assertEqual(self.pick().headers["location"], S + "/?manage=1")
        html = self.page("/?manage=1")
        self.assertIn(CLOSED, html)
        self.assertNotIn('role="alert"', html)
        self.assertEqual(len(history.list_projects()), 1)

    def test_a_dialog_that_cannot_open_or_runs_out_of_time_opens_the_typed_path(self):
        before = self.files()
        for outcome in ("unavailable", "timeout"):
            with self.subTest(outcome=outcome):
                self.choose.return_value = (outcome, None)
                response = self.pick()
                self.assertEqual(response.status_code, 503)
                html = response.text
                alert = f'<p class="error" role="alert">{self.app.PICK_ERRORS[outcome]}</p>'
                self.assertIn(alert, html)
                self.assertIn("아래에 폴더 경로를 직접 입력하세요.", html)
                self.assertIn(OPEN, html)
                self.assertNotIn(CLOSED, html)
                # The message is the dialog's, above its button: the path field is not invalid.
                self.assertLess(html.index(alert), html.index(PICK_FORM))
                self.assertNotIn("aria-invalid", html)
                self.assertNotIn("path-error", html)
                self.assertIn(PATH_FORM, html)
                self.assert_nothing_registered(before)
        self.assertIn(f"{picker.PICK_SECONDS}초 안에", self.app.PICK_ERRORS["timeout"])
        # The typed path then registers the project: the first of all, so the overview opens.
        self.assertEqual(self.post(str(self.project), SESSION).headers["location"], S + "/")
        self.assertEqual(len(history.list_projects()), 1)

    def test_a_chosen_folder_is_checked_as_a_typed_path_is(self):
        (self.root / "lock-dir" / "package-lock.json").mkdir(parents=True)
        cases = [
            (str(self.root), "폴더에 package-lock.json 파일이 없습니다."),
            (str(self.root / "lock-dir"), "폴더에 package-lock.json 파일이 없습니다."),
            (str(self.root / "missing"), "폴더를 찾을 수 없습니다."),
            (str(self.head), "폴더를 찾을 수 없습니다."),
            ("project", "절대 경로를 입력하세요."),
            ("", "로컬 폴더 경로가 아닙니다"),
            ("\\\\server\\share\\project", "로컬 폴더 경로가 아닙니다"),
            ("//server/share/project", "로컬 폴더 경로가 아닙니다"),
            ("\\\\?\\C:\\project", "로컬 폴더 경로가 아닙니다"),
            ("C:/" + "a" * self.app.MAX_PATH, "경로가 너무 깁니다"),
            # Refused for a reason that depends on the platform; here it must stay inert.
            ('C:/"><script>alert(1)</script>', ""),
        ]
        before = self.files()
        for path, message in cases:
            with self.subTest(path=path[:40]):
                self.choose.return_value = ("chosen", path)
                response = self.pick()
                self.assertEqual(response.status_code, 400)
                html = response.text
                self.assertIn('<p class="error" role="alert">' + message, html)
                if len(path) > 10:
                    self.assertNotIn(path, html)  # the answer is not echoed
                assert_one_script(self, html)
                self.assertNotIn("alert(1)", html)
                # The dialog's button is what to use again: the typed path stays folded.
                self.assertIn(CLOSED, html)
                self.assertNotIn("aria-invalid", html)
                self.assert_nothing_registered(before)
        # The same refusal of a typed path is shown at its field, with the form open.
        typed = self.post(str(self.root), SESSION)
        self.assertEqual(typed.status_code, 400)
        self.assertIn(OPEN + '\n<p class="error" id="path-error" role="alert">폴더에 '
                      "package-lock.json 파일이 없습니다.</p>", typed.text)  # fmt: skip
        self.assertIn('aria-describedby="path-hint path-error" aria-invalid="true"', typed.text)
        self.assert_nothing_registered(before)

    def test_one_dialog_at_a_time_while_pages_and_the_typed_path_stay_open(self):
        seen = {}

        def open_dialog():
            # More requests arrive while the dialog is open in its worker thread. Switch the
            # fake first so a missing refusal fails at the assertions instead of recursing.
            self.choose.side_effect = None
            seen["again"] = self.pick()
            seen["page"] = self.get("/")
            seen["files"] = (history.list_projects(), self.db.exists())
            seen["typed"] = self.post(str(self.project), SESSION)
            return "cancelled", None

        self.choose.side_effect = open_dialog
        self.assertEqual(self.pick().headers["location"], S + "/?manage=1")
        self.assertEqual(self.choose.call_count, 1)  # the second request opened no dialog
        again = seen["again"]
        self.assertEqual(again.status_code, 409)
        self.assertIn(f"<h1>{self.app.PICK_OPEN_TITLE}</h1>", again.text)
        self.assertIn(f'<p class="error">{self.app.PICK_OPEN}</p>', again.text)
        self.assertIn(f"<p>{self.app.PICK_OPEN_NOTE}</p>", again.text)
        self.assertIn(f'<a class="tab manage" href="{S}/?manage=1" aria-current="page">프로젝트 관리</a>',
                      again.text)  # fmt: skip
        self.assertNotIn("이력에 기록하지 않았습니다.", again.text)
        self.assertEqual(seen["page"].status_code, 200)
        self.assertEqual(seen["files"], ([], False))  # an open dialog has written nothing
        self.assertEqual(seen["typed"].headers["location"], S + "/")  # the first project of all
        self.assertEqual(self.pick().status_code, 303)  # free again
        self.assertEqual(self.choose.call_count, 2)

    def test_a_failed_dialog_leaves_the_next_one_free(self):
        from starlette.testclient import TestClient

        client = TestClient(self.app.build_app(PORT, SESSION), base_url=BASE,
                            raise_server_exceptions=False)  # fmt: skip
        self.addCleanup(client.close)
        self.choose.side_effect = RuntimeError("C:\\private synthetic-secret-0123456789")
        failed = self.pick(client=client)
        self.assertEqual(failed.status_code, 500)
        self.assertNotIn("synthetic-secret", failed.text)
        self.choose.side_effect = None
        self.assertEqual(self.pick(client=client).status_code, 303)
        self.assertEqual(history.list_projects(), [])

    def test_the_dialog_needs_the_form_session_and_origin(self):
        url = S + "/projects/pick"
        form = {"content-type": "application/x-www-form-urlencoded"}
        refused = {
            "wrong form session": (self.pick(session="wrong"), 403),
            "empty form session": (self.pick(session=""), 403),
            "no form session": (self.client.post(url, content="x=1",
                                                 headers={"origin": BASE, **form}), 403),
            "no origin": (self.pick(origin=None), 403),
            "other port": (self.pick(origin=f"http://127.0.0.1:{PORT + 1}"), 403),
            "other host": (self.pick(origin=f"http://localhost:{PORT}"), 403),
            "null origin": (self.pick(origin="null"), 403),
            "no session prefix": (self.client.post("/projects/pick", data={"session": SESSION},
                                                   headers={"origin": BASE}), 403),
            "other host header": (self.client.post(url, data={"session": SESSION},
                                                   headers={"origin": BASE,
                                                            "host": f"localhost:{PORT}"}), 400),
            "json": (self.client.post(url, content=json.dumps({"session": SESSION}),
                                      headers={"origin": BASE,
                                               "content-type": "application/json"}), 415),
            "get": (self.get("/projects/pick"), 405),
        }  # fmt: skip
        for label, (response, status) in refused.items():
            with self.subTest(label):
                self.assertEqual(response.status_code, status)
                self.assertEqual(response.headers["content-security-policy"], self.app.CSP)
                self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(self.choose.call_count, 0)  # no refused request opens a dialog
        self.assertEqual(history.list_projects(), [])


class PickedFolderTests(DashboardFixture):
    """The whole way with nothing replaced but the child's script: choose() runs a real child
    process, and its answer goes through the registration checks into the history."""

    def pick(self, source):
        with mock.patch.object(picker, "_SCRIPT", stand_in(self.root, source)):
            return self.client.post(S + "/projects/pick", data={"session": SESSION},
                                    headers={"origin": BASE}, follow_redirects=False)  # fmt: skip

    def test_the_answer_of_a_child_process_is_registered(self):
        folder = self.root / "한글 프로젝트"
        folder.mkdir()
        self.write(folder / "package-lock.json", self.new)
        response = self.pick(answering(str(folder)))
        self.assertEqual((response.status_code, response.headers["location"]),
                         (303, S + "/"))  # fmt: skip
        (project,) = history.list_projects()
        self.assertEqual(project["path"], str(folder.resolve()))
        html = self.page("/projects/1")
        self.assertEqual(project_head(html)[::2], ("한글 프로젝트", str(folder.resolve())))
        self.assertIn('<th scope="row">example<span class="row-tags">', html)  # read in place

    def test_a_child_that_answers_nothing_registers_and_writes_nothing(self):
        (self.root / "no-lockfile").mkdir()
        cases = [
            (answering(None), 303),  # the dialog was closed
            (answering(str(self.root / "no-lockfile")), 400),
            ("raise SystemExit(1)\n", 503),  # no dialog could be shown
        ]
        for source, status in cases:
            with self.subTest(status=status):
                response = self.pick(source)
                self.assertEqual(response.status_code, status)
                self.assertEqual(history.list_projects(), [])
                self.assertFalse(self.db.exists())


class ChooseTests(Fixture):
    """picker.choose() with real child processes of synthetic scripts."""

    def choose(self, source, seconds=60):
        with mock.patch.object(picker, "_SCRIPT", stand_in(self.root, source)), \
                mock.patch.object(picker, "PICK_SECONDS", seconds):  # fmt: skip
            return picker.choose()

    def test_each_answer_of_the_child(self):
        korean = str(self.root / "한글 폴더")
        huge = "x" * (picker.MAX_ANSWER + 1)
        cases = [
            (answering(korean), ("chosen", korean)),
            (answering(None), ("cancelled", None)),
            # A dialog that could not be shown, or a child that broke: never a folder.
            ("raise SystemExit(1)\n", ("unavailable", None)),
            ("import tkinter_that_is_not_there\n", ("unavailable", None)),
            ("", ("unavailable", None)),
            ("print('not json')\n", ("unavailable", None)),
            ("print('[]')\n", ("unavailable", None)),
            ("print('{}')\n", ("unavailable", None)),
            (answering(7), ("unavailable", None)),
            (answering([korean]), ("unavailable", None)),
            (answering(huge), ("unavailable", None)),
            # An answer is the answer only if the child ended well.
            (answering(korean) + "raise SystemExit(3)\n", ("unavailable", None)),
            # What the child writes to stderr goes nowhere.
            ("import sys\nsys.stderr.write('noise')\n" + answering(korean), ("chosen", korean)),
        ]
        for source, expected in cases:
            with self.subTest(source=source[:40]):
                self.assertEqual(self.choose(source), expected)

    def test_the_child_gets_nothing_from_the_server(self):
        # What the child sees, sent back as its answer.
        source = (
            "import json, os, sys\n"
            "seen = {'argv': sys.argv[1:], 'isolated': sys.flags.isolated,\n"
            "        'no_bytecode': sys.flags.dont_write_bytecode, 'cwd': os.getcwd(),\n"
            "        'input': sys.stdin.read(), 'script_folder_on_path': sys.path[0]}\n"
            "sys.stdout.write(json.dumps({'folder': json.dumps(seen)}))\n"
        )
        script = stand_in(self.root, source)
        with mock.patch.object(picker.subprocess, "Popen", wraps=subprocess.Popen) as popen:
            outcome, answer = self.choose(source)
        self.assertEqual(outcome, "chosen")
        seen = json.loads(answer)
        self.assertEqual((seen["argv"], seen["isolated"], seen["no_bytecode"], seen["input"]),
                         ([], 1, 1, ""))  # fmt: skip
        self.assertTrue(os.path.samefile(seen["cwd"], os.path.expanduser("~")))
        self.assertNotEqual(os.path.normcase(seen["script_folder_on_path"]),
                            os.path.normcase(str(self.root)))  # fmt: skip
        # This Python by its own path, the arguments as a list: no shell, no PATH search.
        (command,), options = popen.call_args
        self.assertEqual(command, [sys.executable, "-I", "-B", script])
        self.assertTrue(os.path.isabs(sys.executable))
        self.assertNotIn("shell", options)
        self.assertEqual((options["stdin"], options["stdout"], options["stderr"]),
                         (subprocess.DEVNULL, subprocess.PIPE, subprocess.DEVNULL))  # fmt: skip
        self.assertNotIn("env", options)  # nothing is added to what the server itself has

    def test_a_dialog_left_open_is_closed_at_the_time_limit(self):
        started, real = [], subprocess.Popen

        def spawn(*args, **options):
            started.append(real(*args, **options))
            return started[-1]

        began = time.monotonic()
        with mock.patch.object(picker.subprocess, "Popen", side_effect=spawn):
            answer = self.choose("import time\ntime.sleep(120)\n", seconds=1)
        self.assertEqual(answer, ("timeout", None))
        self.assertLess(time.monotonic() - began, 60)
        (process,) = started
        self.assertIsNotNone(process.poll())  # killed and waited for
        self.assertTrue(process.stdout.closed)

    def test_a_child_that_cannot_be_started_is_no_dialog(self):
        with mock.patch.object(picker.subprocess, "Popen", side_effect=OSError("synthetic")):
            self.assertEqual(picker.choose(), ("unavailable", None))


class ChildTests(unittest.TestCase):
    """picker._child(), the code of the child process, here with a stand-in for tkinter."""

    def child(self, answer, unseen=False, tk=None):
        calls = []

        class Root:
            def withdraw(self):
                calls.append("withdraw")

            def attributes(self, *args):
                calls.append(("attributes", *args))

            def update(self):
                calls.append("update")

            def destroy(self):
                calls.append("destroy")

        def askdirectory(**options):
            calls.append(("askdirectory", options))
            return answer

        tkinter = types.ModuleType("tkinter")
        tkinter.Tk = tk or Root
        tkinter.filedialog = types.ModuleType("tkinter.filedialog")
        tkinter.filedialog.askdirectory = askdirectory
        modules = {"tkinter": tkinter, "tkinter.filedialog": tkinter.filedialog}
        out = io.StringIO()
        with mock.patch.dict(sys.modules, modules), contextlib.redirect_stdout(out), \
                mock.patch.object(picker, "_unseen", return_value=unseen):  # fmt: skip
            try:
                picker._child()
            except BaseException as exc:  # SystemExit too: how the child ends without an answer
                return exc, out.getvalue(), calls
        return None, out.getvalue(), calls

    def test_the_chosen_folder_is_answered_as_an_absolute_path_in_ascii(self):
        for chosen in ("C:/Users/someone/한글 폴더", "relative/프로젝트"):
            with self.subTest(chosen=chosen):
                error, out, calls = self.child(chosen)
                self.assertIsNone(error)
                self.assertTrue(out.isascii())
                self.assertEqual(json.loads(out), {"folder": os.path.abspath(chosen)})
                self.assertTrue(os.path.isabs(json.loads(out)["folder"]))
        # Only the dialog is shown, in front of the other windows, and asked for one folder.
        (asked,) = (call[1] for call in calls if call[0] == "askdirectory")
        self.assertEqual({"title": asked["title"], "mustexist": asked["mustexist"]},
                         {"title": picker.TITLE, "mustexist": True})  # fmt: skip
        self.assertEqual([call for call in calls if call[0] != "askdirectory"],
                         ["withdraw", ("attributes", "-topmost", True), "update", "destroy"])  # fmt: skip
        self.assertEqual(calls[3][0], "askdirectory")

    def test_a_closed_dialog_is_answered_as_no_folder(self):
        for closed in ("", ()):  # what Tk returns, depending on the platform
            with self.subTest(closed=closed):
                error, out, _ = self.child(closed)
                self.assertIsNone(error)
                self.assertEqual(json.loads(out), {"folder": None})

    def test_without_a_desktop_or_tkinter_the_child_ends_without_an_answer(self):
        error, out, calls = self.child("C:/never/asked", unseen=True)
        self.assertIsInstance(error, SystemExit)
        self.assertEqual((error.code, out, calls), (1, "", []))

        def no_display():
            raise RuntimeError("no display name and no $DISPLAY environment variable")

        error, out, calls = self.child("C:/never/asked", tk=no_display)
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual((out, calls), ("", []))
        with mock.patch.dict(sys.modules, {"tkinter": None}), \
                mock.patch.object(picker, "_unseen", return_value=False):  # fmt: skip
            with self.assertRaises(ImportError):
                picker._child()

    def test_the_desktop_check_answers_without_a_window(self):
        self.assertIsInstance(picker._unseen(), bool)
        with mock.patch.object(picker.os, "name", "posix"):
            self.assertIs(picker._unseen(), False)  # elsewhere Tk itself says so

    def test_the_file_runs_alone_with_the_standard_library_only(self):
        # choose() runs this file as a script under -I: it can import nothing of depbee.
        tree = ast.parse(Path(picker.__file__).read_text("utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, "a relative import")
                imported.add(node.module.split(".")[0])
        self.assertLessEqual(imported, sys.stdlib_module_names)
        self.assertIn("tkinter", imported)
        self.assertEqual(picker._SCRIPT, os.path.abspath(picker.__file__))


if __name__ == "__main__":
    unittest.main()
