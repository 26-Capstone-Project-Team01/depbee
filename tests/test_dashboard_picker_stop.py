"""Ending the dashboard while its folder dialog is open, and what a second dialog request is told.

A server that has been asked to end (the stop request of `depbee dashboard --stop`, or Ctrl+C)
closes the open dialog, waits for the dialog's child process and registers nothing, so it ends
within the stop command's time limit instead of after the dialog's.

No desktop dialog is opened here. picker.choose() runs real child processes, but of small
synthetic scripts written into the test run's folder, and the server tests run the real
app.serve() with uvicorn in a thread of this process, which is asked to end as a real one is.
"""

import contextlib
import http.client
import io
import json
import os
import re
import signal
import subprocess
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from test_dashboard import BASE, CSRF, PORT, DashboardFixture
from test_workflow import Fixture

from depbee import cli, history
from depbee.cli import main
from depbee.dashboard import lifecycle, picker

TOKEN = "synthetic-control-token-for-tests-only"
ADDRESS = re.compile(r"http://127\.0\.0\.1:(\d+)/$", re.M)


def wait_for(condition, seconds=30):
    """Ask condition() until it holds or seconds have passed: its last answer."""
    deadline = time.monotonic() + seconds
    while not (met := condition()) and time.monotonic() < deadline:
        time.sleep(0.02)
    return met


def stand_in(test, source: str) -> None:
    """For the rest of test, picker.choose() runs a synthetic script in place of the dialog's."""
    script = test.root / "stand_in_dialog.py"
    script.write_text(source, encoding="utf-8")
    patcher = mock.patch.object(picker, "_SCRIPT", str(script))
    patcher.start()
    test.addCleanup(patcher.stop)


def waiting(marker: Path) -> str:
    """The source of a child that creates marker once it runs and then stays, as an open dialog
    that nobody answers does."""
    return f"import pathlib, time\npathlib.Path({str(marker)!r}).touch()\ntime.sleep(120)\n"


def answering(folder: Path) -> str:
    """The source of a child that answers at once, as a dialog in which folder was chosen."""
    return f"import sys\nsys.stdout.write({json.dumps({'folder': str(folder)})!r})\n"


def children(test) -> list:
    """The child processes picker.choose() starts in the rest of test, as their Popen objects.
    choose() leaves none running; one left by a failed test is ended."""
    started, real = [], subprocess.Popen

    def spawn(*args, **options):
        started.append(real(*args, **options))
        return started[-1]

    def end():
        for child in started:
            if child.poll() is None:
                child.kill()
                child.communicate()

    patcher = mock.patch.object(picker.subprocess, "Popen", side_effect=spawn)
    patcher.start()
    test.addCleanup(patcher.stop)
    test.addCleanup(end)
    return started


class ChooseStopTests(Fixture):
    """picker.choose(stopping) with real child processes of synthetic scripts."""

    def test_a_stop_closes_the_open_dialog_and_waits_for_its_child(self):
        started, marker = children(self), self.root / "dialog-open"
        stand_in(self, waiting(marker))
        began = time.monotonic()
        # The stop comes once the child's own code runs: while "the dialog is open".
        self.assertEqual(picker.choose(marker.exists), ("stopped", None))
        # Not left to the dialog's time limit, which the stop command does not wait for.
        self.assertLess(time.monotonic() - began, lifecycle.STOP_SECONDS)
        self.assertLess(lifecycle.STOP_SECONDS, picker.PICK_SECONDS)
        (child,) = started
        self.assertIsNotNone(child.returncode)  # killed and waited for by choose() itself
        self.assertTrue(child.stdout.closed)  # at its end: nothing holds the pipe any more

    def test_a_stop_before_the_dialog_starts_no_child(self):
        started = children(self)
        stand_in(self, answering(self.project))
        self.assertEqual(picker.choose(lambda: True), ("stopped", None))
        self.assertEqual(started, [])
        # Without a stop the same call is the dialog's answer, as it is without the argument.
        self.assertEqual(picker.choose(lambda: False), ("chosen", str(self.project)))
        self.assertEqual(picker.choose(), ("chosen", str(self.project)))
        self.assertEqual(len(started), 2)


class StopRouteTests(DashboardFixture):
    """POST /projects/pick of an app whose server can be asked to end; picker.choose is
    replaced."""

    def setUp(self):
        super().setUp()
        from starlette.testclient import TestClient

        self.asked = []  # filled: the server has been asked to end
        app = self.app.build_app(PORT, CSRF, lambda: bool(self.asked))
        self.client = TestClient(app, base_url=BASE)
        self.addCleanup(self.client.close)
        patcher = mock.patch.object(picker, "choose", return_value=("chosen", str(self.project)))
        self.choose = patcher.start()
        self.addCleanup(patcher.stop)
        self.before = sorted(self.root.rglob("*"))

    def pick(self, csrf=CSRF):
        return self.client.post("/projects/pick", data={"csrf": csrf},
                                headers={"origin": BASE}, follow_redirects=False)  # fmt: skip

    def assert_stopped(self, response):
        """The fixed text of a server that is ending; no project, history file or other file."""
        self.assertEqual((response.status_code, response.text), (503, self.app.PICK_STOPPED))
        self.assertEqual(response.headers["content-type"], "text/plain; charset=utf-8")
        self.assertEqual(response.headers["content-security-policy"], self.app.CSP)
        self.assertEqual(history.list_projects(), [])
        self.assertFalse(self.db.exists())
        self.assertEqual(sorted(self.root.rglob("*")), self.before)

    def test_until_the_server_is_asked_to_end_the_dialog_registers_as_before(self):
        response = self.pick()
        # The first project of all: registered, and the overview is where it is shown.
        self.assertEqual((response.status_code, response.headers["location"]),
                         (303, "/"))  # fmt: skip
        self.assertEqual([project["id"] for project in history.list_projects()], [1])
        ((watched,), options) = self.choose.call_args
        self.assertEqual((watched(), options), (False, {}))
        self.asked.append(True)  # what the dialog watches is the server's own answer
        self.assertIs(watched(), True)

    def test_a_server_asked_to_end_opens_no_dialog(self):
        self.asked.append(True)
        self.assert_stopped(self.pick())
        self.assertEqual(self.choose.call_count, 0)
        # The form is still checked first: a request without its value learns nothing.
        self.assertEqual(self.pick(csrf="wrong").status_code, 403)

    def test_whatever_the_dialog_answers_after_the_stop_nothing_is_registered(self):
        answers = [("chosen", str(self.project)), ("cancelled", None), ("unavailable", None),
                   ("timeout", None), ("stopped", None)]  # fmt: skip
        for answer in answers:
            with self.subTest(answer=answer[0]):
                self.asked.clear()

                def answered(stopping, answer=answer):
                    self.asked.append(True)  # the stop request is taken while the dialog is open
                    return answer

                self.choose.side_effect = answered
                self.assert_stopped(self.pick())
        self.assertEqual(self.choose.call_count, len(answers))  # each left the next one free
        # A dialog that was closed for a stop registers nothing, whatever is asked afterwards.
        self.asked.clear()
        self.choose.side_effect = None
        self.choose.return_value = ("stopped", None)
        self.assert_stopped(self.pick())


class SecondRequestTests(DashboardFixture):
    """A second dialog request while the first dialog is open (409): how its page leads on."""

    def pick(self):
        return self.client.post("/projects/pick", data={"csrf": CSRF},
                                headers={"origin": BASE}, follow_redirects=False)  # fmt: skip

    def test_the_page_links_to_project_management_instead_of_a_second_post(self):
        seen = {}

        def open_dialog():
            choose.side_effect = None  # the request of "another tab" finds the dialog open
            seen["again"] = self.pick()
            return "chosen", str(self.project)

        with mock.patch.object(picker, "choose", side_effect=open_dialog) as choose:
            first = self.pick()
        self.assertEqual(first.headers["location"], "/")  # the first one registers
        self.assertEqual(choose.call_count, 1)
        again = seen["again"]
        self.assertEqual(again.status_code, 409)
        html = again.text
        # The page was made before the folder was chosen and stays as it is: the project is not
        # on it, and its words promise neither a tab nor ask to send the request again.
        self.assertNotIn('href="/projects/1"', html)
        self.assertIn("이 화면은 저절로 바뀌지 않으니", html)
        self.assertIn("새로 고치면 폴더 선택 요청을 다시 보내게 됩니다", html)
        for promise in ("탭이 생", "다시 시도"):
            self.assertNotIn(promise, html)
        # The way on is a link, which is a GET: the page has no form that could post again.
        self.assertEqual(self.app.PICK_REOPEN, "프로젝트 관리 다시 열기")
        self.assertIn(f'<p><a href="/?manage=1">{self.app.PICK_REOPEN}</a></p>', html)
        self.assertNotIn("<form", html)
        # Where the link leads, the registration of the first request is there to see.
        self.assertIn('href="/projects/1"', self.page("/"))
        self.assertEqual(len(history.list_projects()), 1)


class ServerStopTests(DashboardFixture):
    """The real server (app.serve() and uvicorn, in a thread of this process) is asked to end
    while a request of it waits for the folder dialog."""

    def setUp(self):
        super().setUp()
        self.folder = Path(os.environ["DEPBEE_CONFIG_DIR"])
        self.children = children(self)
        self.servers = servers = []

        class Server(self.app.uvicorn.Server):
            def __init__(self, config):
                super().__init__(config)
                servers.append(self)

        patcher = mock.patch.object(self.app.uvicorn, "Server", Server)
        patcher.start()
        self.addCleanup(patcher.stop)

    def start(self, run, address):
        """run() in a thread: the thread, and the port of the address that address() gives
        once it is there."""
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(self.end, thread)
        return thread, int(ADDRESS.match(wait_for(address) or "")[1])

    def end(self, thread):
        for server in self.servers:  # only after a failure: each test ends its server itself
            server.should_exit = server.force_exit = True
        thread.join(30)

    def background(self):
        """Serve as the background instance, as lifecycle._child does: the instance's lock is
        held until the server has ended, which is what the stop command waits for."""
        self.folder.mkdir()
        instance, lock = lifecycle.Instance(self.folder, TOKEN), lifecycle._acquire(self.folder)

        def run():
            try:
                self.app.serve(0, background=instance)
            finally:
                instance.close()
                os.close(lock)

        return self.start(run, lambda: (lifecycle._read(self.folder) or {}).get("url"))

    def post_pick(self, port):
        """Send the dialog's form as the first page has it (its hidden value is read from that
        page, as a browser has it), in a thread: the thread, and a dict that gets the answer's
        status and text."""
        answer = {}
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
        try:
            connection.request("GET", "/")
            page = connection.getresponse().read().decode("utf-8")
        finally:
            connection.close()
        self.assertIn('<form method="post" action="/projects/pick">', page)
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]{43})"', page)[1]

        def post():
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
            try:
                connection.request(
                    "POST", "/projects/pick", f"csrf={csrf}",
                    {"origin": f"http://127.0.0.1:{port}",
                     "content-type": "application/x-www-form-urlencoded"},
                )  # fmt: skip
                response = connection.getresponse()
                answer.update(status=response.status, text=response.read().decode("utf-8"))
            finally:
                connection.close()

        thread = threading.Thread(target=post, daemon=True)
        thread.start()
        return thread, answer

    def assert_ended(self, server, request, answer):
        """The server ended within the stop command's time limit, the dialog's request was told
        why, and there is no project and no history file."""
        server.join(lifecycle.STOP_SECONDS)
        self.assertFalse(server.is_alive(), "the server waited for the folder dialog")
        request.join(10)
        self.assertEqual(answer, {"status": 503, "text": self.app.PICK_STOPPED})
        self.assertEqual(history.list_projects(), [])
        self.assertFalse(self.db.exists())

    def test_the_stop_command_ends_a_server_whose_dialog_is_open(self):
        marker = self.root / "dialog-open"
        stand_in(self, waiting(marker))
        server, port = self.background()
        request, answer = self.post_pick(port)
        self.assertTrue(wait_for(marker.exists), "the dialog's child did not start")
        # The command itself: it has the request taken and then waits, STOP_SECONDS at most,
        # for the instance's lock. A server that waited for the dialog made it fail (exit 2).
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["dashboard", "--stop"])
        self.assertEqual((code, out.getvalue()), (0, cli.BACKGROUND_STOPPED + "\n"))
        (child,) = self.children
        self.assertIsNotNone(child.returncode)  # waited for before the command returned
        self.assertTrue(child.stdout.closed)
        self.assert_ended(server, request, answer)
        self.assertFalse((self.folder / lifecycle.STATE).exists())

    def test_a_stop_taken_before_the_dialog_starts_leaves_no_child(self):
        stand_in(self, answering(self.project))
        server, port = self.background()
        state, choose, taken = lifecycle._read(self.folder), picker.choose, []

        def stop_first(stopping):
            # In the worker thread: the request is accepted, the child not started yet.
            taken.append(lifecycle._control(state, "stop"))
            taken.append(wait_for(stopping))  # the server has taken it
            return choose(stopping)

        with mock.patch.object(picker, "choose", stop_first):
            request, answer = self.post_pick(port)
            self.assert_ended(server, request, answer)
        self.assertEqual((taken, self.children), ([True, True], []))

    def test_an_answer_that_comes_back_after_the_stop_is_not_registered(self):
        stand_in(self, answering(self.project))  # a folder that would be registered
        server, port = self.background()
        state, choose, seen = lifecycle._read(self.folder), picker.choose, []

        def answer_then_stop(stopping):
            # In the worker thread: the dialog has answered, the answer is not registered yet.
            seen.append(choose(stopping))
            seen.append(lifecycle._control(state, "stop"))
            return seen[0]

        with mock.patch.object(picker, "choose", answer_then_stop):
            request, answer = self.post_pick(port)
            self.assert_ended(server, request, answer)
        self.assertEqual(seen, [("chosen", str(self.project)), True])
        (child,) = self.children
        self.assertEqual(child.returncode, 0)  # it ended by itself, with its answer

    def test_ctrl_c_closes_the_open_dialog_too(self):
        """In the foreground the server is asked to end by uvicorn's own handler of Ctrl+C,
        which sets the flag the dialog watches. The handler is called as the signal calls it:
        a real Ctrl+C would end the test run."""
        marker, out = self.root / "dialog-open", io.StringIO()
        stand_in(self, waiting(marker))
        with contextlib.redirect_stdout(out):  # the two lines of a foreground start
            server, port = self.start(
                lambda: self.app.serve(0),
                lambda: out.getvalue().count("\n") == 2 and out.getvalue(),
            )
        request, answer = self.post_pick(port)
        self.assertTrue(wait_for(marker.exists), "the dialog's child did not start")
        (running,) = self.servers
        running.handle_exit(signal.SIGINT, None)
        self.assert_ended(server, request, answer)
        (child,) = self.children
        self.assertIsNotNone(child.returncode)


if __name__ == "__main__":
    unittest.main()
