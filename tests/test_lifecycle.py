"""Background dashboard (depbee.dashboard.lifecycle): the lock, the state file, the control
endpoint, and `depbee dashboard --background`, `--status` and `--stop` with real processes.

Everything stays in each test run's folder: Fixture sets DEPBEE_CONFIG_DIR, the user's settings
folder and so the folder of the instance, to a folder there. The process tests start the real
CLI as a user does and always stop what they started; they need the [web] extra. No npm,
registry or package code.

No test serves on dashboard.DEFAULT_PORT, where a dashboard of this PC's user may be running:
a process test takes a port that is free when it starts and names it with --port, and what the
default is and where it goes is checked without a server (PortTests).
"""

import asyncio
import contextlib
import errno
import hmac
import http.client
import http.server
import importlib.util
import inspect
import io
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

from test_workflow import Fixture

from depbee import cli, dashboard
from depbee.cli import main
from depbee.contracts import GuardError
from depbee.dashboard import lifecycle

WEB = all(importlib.util.find_spec(name) for name in ("starlette", "jinja2", "uvicorn"))
NO_WEB = "web extra ([web]) not installed; the background dashboard is not started here"
SRC = str(Path(__file__).resolve().parents[1] / "src")
URL = re.compile(r"http://127\.0\.0\.1:(\d+)/")  # the whole address: the root of a port
SESSION = "/s/" + "s" * 43 + "/"  # after the port, in an address of the version before
TOKEN = "synthetic-control-token-for-tests-only"


def free_port():
    """A port nothing listens on at this moment, for a test that serves on the same one twice."""
    with socket.create_server(("127.0.0.1", 0)) as unused:
        return unused.getsockname()[1]


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def wait_until_free(folder, seconds=15):
    """Wait for a process this test has just ended to be gone (its lock is given back)."""
    deadline = time.monotonic() + seconds
    while lifecycle._alive(folder) and time.monotonic() < deadline:
        time.sleep(0.1)


class Folder(Fixture):
    """self.folder: the instance's folder, the user's settings folder of this run (Fixture's
    DEPBEE_CONFIG_DIR). It does not exist until something creates it."""

    def setUp(self):
        super().setUp()
        self.folder = Path(os.environ["DEPBEE_CONFIG_DIR"])


class LockAndStateTests(Folder):
    def setUp(self):
        super().setUp()
        self.folder.mkdir()

    def test_the_lock_is_held_by_one_descriptor_and_given_back_when_it_closes(self):
        self.assertFalse(lifecycle._alive(self.folder))
        self.assertFalse((self.folder / lifecycle.LOCK).exists())  # asking creates nothing
        first = lifecycle._acquire(self.folder)
        self.assertIsInstance(first, int)
        self.assertIsNone(lifecycle._acquire(self.folder))
        self.assertTrue(lifecycle._alive(self.folder))
        os.close(first)
        self.assertFalse(lifecycle._alive(self.folder))
        again = lifecycle._acquire(self.folder)
        self.assertIsInstance(again, int)
        os.close(again)

    def test_a_file_system_without_locks_is_an_error_not_a_running_instance(self):
        (self.folder / lifecycle.LOCK).touch()
        lock_call = "msvcrt.locking" if os.name == "nt" else "fcntl.flock"
        with mock.patch(lock_call, side_effect=OSError(errno.ENOLCK, "No locks available")):
            with self.assertRaises(OSError):
                lifecycle._alive(self.folder)
            code, out, err = run_cli("dashboard", "--status")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("No locks available", json.loads(err)["error"])

    def test_another_process_sees_the_lock_and_its_end_frees_it(self):
        code = ("import sys, time; from depbee.dashboard import lifecycle; from pathlib import Path\n"
                "print(lifecycle._acquire(Path(sys.argv[1])) is not None, flush=True)\n"
                "time.sleep(60)")  # fmt: skip
        holder = subprocess.Popen([sys.executable, "-c", code, str(self.folder)], text=True,
                                  stdout=subprocess.PIPE, env={**os.environ, "PYTHONPATH": SRC})  # fmt: skip
        try:
            self.assertEqual(holder.stdout.readline().strip(), "True")
            self.assertTrue(lifecycle._alive(self.folder))
            self.assertEqual(lifecycle.status(), ("unresponsive", None))
        finally:
            holder.kill()  # no cleanup runs in it: the system frees the lock
            holder.wait()
            holder.stdout.close()
        wait_until_free(self.folder)  # a venv's python.exe is a launcher: its interpreter ends next
        self.assertFalse(lifecycle._alive(self.folder))
        self.assertEqual(lifecycle.status(), ("stopped", None))

    def publish(self, **changes):
        instance = lifecycle.Instance(self.folder, TOKEN)
        instance.publish("http://127.0.0.1:8123/", 8123)
        if changes:
            state = json.loads((self.folder / lifecycle.STATE).read_text("utf-8"))
            (self.folder / lifecycle.STATE).write_text(json.dumps({**state, **changes}), "utf-8")
        return instance

    def test_the_state_file_is_only_what_an_instance_publishes(self):
        self.assertIsNone(lifecycle._read(self.folder))
        instance = self.publish()
        state = lifecycle._read(self.folder)
        self.assertEqual((state["port"], state["token"], state["pid"]), (8123, TOKEN, os.getpid()))
        self.assertRegex(state["started_at"], r"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")
        if os.name != "nt":  # the control token is the user's alone
            self.assertEqual((self.folder / lifecycle.STATE).stat().st_mode & 0o777, 0o600)
        # What the version before published is still a state file: its instance may be running.
        for label, url in {
            "a session's first page": f"http://127.0.0.1:8123{SESSION}",
            "a page of a session": f"http://127.0.0.1:8123{SESSION}projects/1",
        }.items():
            with self.subTest(label):
                self.publish(url=url)
                self.assertEqual(lifecycle._read(self.folder)["url"], url)
        for label, changes in {
            "another host": {"url": "http://192.0.2.1:8123/"},
            "a name for the host": {"url": "http://localhost:8123/"},
            "https": {"url": "https://127.0.0.1:8123/"},
            "a port that is not the address's": {"port": 8124},
            "a port that is no number": {"port": "8123"},
            "a port out of range": {"port": 0, "url": "http://127.0.0.1:0/"},
            "text after the address": {"url": "http://127.0.0.1:8123/\n\x1b[31m"},
            "no path": {"url": "http://127.0.0.1:8123"},
            "a page under the root": {"url": "http://127.0.0.1:8123/projects/1"},
            "a query": {"url": "http://127.0.0.1:8123/?manage=1"},
            "a session without a value": {"url": "http://127.0.0.1:8123/s//"},
            "a session with other text": {"url": "http://127.0.0.1:8123/s/a%20b/"},
            "another host with a session": {"url": f"http://localhost:8123{SESSION}"},
            "an empty token": {"token": ""},
            "a process ID that is no number": {"pid": "1"},
            "a time in another form": {"started_at": "yesterday"},
        }.items():
            with self.subTest(label):
                self.publish(**changes)
                self.assertIsNone(lifecycle._read(self.folder))
        (self.folder / lifecycle.STATE).write_bytes(b"x" * (lifecycle.MAX_STATE + 1))
        self.assertIsNone(lifecycle._read(self.folder))
        self.publish()
        instance.close()  # its own state file
        self.assertFalse((self.folder / lifecycle.STATE).exists())

    def test_an_instance_removes_only_its_own_state_file(self):
        old = lifecycle.Instance(self.folder, "an-older-instance-token")
        self.publish()
        old.close()
        self.assertEqual(lifecycle._read(self.folder)["token"], TOKEN)

    def test_a_left_state_file_is_removed_only_by_a_caller_that_holds_the_lock(self):
        self.publish()
        held = lifecycle._acquire(self.folder)  # as a new instance that is about to publish
        lifecycle._sweep(self.folder)
        self.assertEqual(lifecycle._read(self.folder)["token"], TOKEN)  # it may be the holder's
        os.close(held)
        lifecycle._sweep(self.folder)
        self.assertFalse((self.folder / lifecycle.STATE).exists())
        self.assertFalse(lifecycle._alive(self.folder))  # and the lock is given back

    def test_a_state_file_nobody_answers_for_is_stale_and_removed(self):
        port = free_port()
        for path in ("/", SESSION):  # this version's, and one the version before left
            with self.subTest(path):
                lifecycle.Instance(self.folder, TOKEN).publish(
                    f"http://127.0.0.1:{port}{path}", port
                )
                self.assertEqual(lifecycle.status(), ("stopped", None))
                self.assertFalse((self.folder / lifecycle.STATE).exists())
        self.assertFalse(lifecycle.stop())  # already stopped: nothing to do, no error
        self.assertEqual(run_cli("dashboard", "--stop"), (0, cli.BACKGROUND_NONE + "\n", ""))
        self.assertEqual(run_cli("dashboard", "--status"), (0, cli.BACKGROUND_NONE + "\n", ""))

    def test_a_server_without_the_token_does_not_pass_for_the_instance(self):
        """Another program on the port of a dead instance: its answers prove nothing."""

        class Handler(http.server.BaseHTTPRequestHandler):
            seen = []

            def do_POST(self):
                Handler.seen.append(dict(self.headers))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        lifecycle.Instance(self.folder, TOKEN).publish(f"http://127.0.0.1:{port}/", port)
        self.assertEqual(lifecycle.status(), ("stopped", None))
        self.assertFalse(lifecycle.stop())
        # A start does not take it for the instance either: it goes on to create its own (here
        # no process: the one it would create is replaced by a failure).
        lifecycle.Instance(self.folder, TOKEN).publish(f"http://127.0.0.1:{port}/", port)
        asked = len(Handler.seen)
        with mock.patch.object(lifecycle.subprocess, "Popen", side_effect=OSError("no child")):
            with self.assertRaisesRegex(OSError, "no child"):
                lifecycle.start(port)
        self.assertGreater(len(Handler.seen), asked)
        self.assertTrue(Handler.seen)
        for headers in Handler.seen:  # the token itself never goes over the wire
            self.assertNotIn(TOKEN, json.dumps(headers))

    def test_status_and_stop_take_no_other_option_and_modes_exclude_each_other(self):
        for argv in (["--stop", "--port", "8123"], ["--status", "--no-cache"],
                     ["--stop", "--model-dir", "m"], ["--status", "--port", "0"],
                     ["--stop", "--port", str(dashboard.DEFAULT_PORT)]):  # fmt: skip
            with self.subTest(argv):
                code, out, err = run_cli("dashboard", *argv)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("take no other option", json.loads(err)["error"])
        with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
            main(["dashboard", "--background", "--stop"])
        self.assertIn("not allowed with argument", err.getvalue())

    def test_without_a_home_folder_the_commands_say_what_to_set(self):
        os.environ.pop("DEPBEE_CONFIG_DIR")
        with mock.patch.object(Path, "home", side_effect=RuntimeError("no home")):
            for argv in (["--status"], ["--stop"], ["--background"]):
                code, out, err = run_cli("dashboard", *argv)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("DEPBEE_CONFIG_DIR", json.loads(err)["error"])


class PortTests(Folder):
    """Which port a command asks for. Nothing is bound: serve() and start() are replaced."""

    def test_no_port_is_the_default_one_and_a_given_port_is_kept(self):
        self.assertEqual(dashboard.DEFAULT_PORT, 18765)
        for function in (dashboard.serve, lifecycle.start):  # called from Python without a port
            default = inspect.signature(function).parameters["port"].default
            self.assertEqual(default, dashboard.DEFAULT_PORT)
        state = {"url": "http://127.0.0.1:18765/"}
        for argv, port in (([], 18765), (["--port", "0"], 0), (["--port", "8765"], 8765)):
            with self.subTest(argv), mock.patch.object(dashboard, "serve") as serve, \
                    mock.patch.object(lifecycle, "start", return_value=(state, True)) as start:  # fmt: skip
                self.assertEqual(run_cli("dashboard", "--no-cache", *argv), (0, "", ""))
                started = (0, f"{state['url']}\n{cli.BACKGROUND_STARTED}\n", "")
                self.assertEqual(run_cli("dashboard", "--background", *argv), started)
                self.assertEqual(serve.call_args.args, (port,))
                self.assertEqual(start.call_args.args, (port,))
                self.assertTrue(serve.call_args.kwargs["no_cache"])  # the options still go along


class PreviousVersionTests(Folder):
    """After an upgrade, the instance the version before started is still running: its state file
    names a session address and its server speaks the control protocol of its time. That server
    is written out here from the protocol and not taken from lifecycle, so that a change to what
    this version sends or accepts fails here. As that instance's process would, it holds the
    lock, and on a stop it removes its state file and gives the lock back."""

    def setUp(self):
        super().setUp()
        self.folder.mkdir()
        self.actions = actions = []
        state_file, held = self.folder / lifecycle.STATE, [lifecycle._acquire(self.folder)]

        def end():
            if held:
                state_file.unlink()
                os.close(held.pop())

        self.addCleanup(end)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                action, nonce = self.headers["x-depbee-action"], self.headers["x-depbee-nonce"]
                key, sent = TOKEN.encode(), self.headers["x-depbee-auth"] or ""
                wanted = hmac.new(key, f"{action}\n{nonce}".encode(), "sha256").hexdigest()
                if self.path != "/control" or not hmac.compare_digest(sent, wanted):
                    self.send_error(403)
                    return
                actions.append(action)
                proof = hmac.new(key, f"ok\n{action}\n{nonce}".encode(), "sha256").hexdigest()
                self.send_response(200)
                self.send_header("Content-Length", str(len(proof)))
                self.end_headers()
                self.wfile.write(proof.encode())
                if action == "stop":
                    end()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        # Its state file, byte for byte as that version's Instance.publish() wrote one.
        self.state = {"url": f"http://127.0.0.1:{port}{SESSION}", "port": port, "pid": 4242,
                      "token": TOKEN, "started_at": "2026-11-27T01:02:03Z"}  # fmt: skip
        state_file.write_text(json.dumps(self.state, ensure_ascii=True) + "\n", "utf-8")

    def test_it_is_shown_reused_and_stopped_at_the_address_it_serves(self):
        url = self.state["url"]
        self.assertEqual(lifecycle.status(), ("running", self.state))
        shown = cli.BACKGROUND_STATUS.format(pid=4242, started_at="2026-11-27T01:02:03Z")
        self.assertEqual(run_cli("dashboard", "--status"), (0, f"{url}\n{shown}\n", ""))
        # A start shows it and creates nothing, whatever port is asked for, the default included.
        with mock.patch.object(lifecycle.subprocess, "Popen") as created:
            for argv in ([], ["--port", "0"], ["--port", "8765", "--no-cache"]):
                with self.subTest(argv):
                    self.assertEqual(run_cli("dashboard", "--background", *argv),
                                     (0, f"{url}\n{cli.BACKGROUND_RUNNING}\n", ""))  # fmt: skip
        created.assert_not_called()
        self.assertEqual(run_cli("dashboard", "--stop"), (0, cli.BACKGROUND_STOPPED + "\n", ""))
        self.assertEqual(self.actions, ["status"] * 5 + ["stop"])
        self.assertFalse(lifecycle._alive(self.folder))
        self.assertEqual(run_cli("dashboard", "--status"), (0, cli.BACKGROUND_NONE + "\n", ""))
        self.assertEqual(run_cli("dashboard", "--stop"), (0, cli.BACKGROUND_NONE + "\n", ""))

    def test_a_request_under_another_token_is_not_its_answer(self):
        """The file names its port but another token (a file put there, or a port that became
        another instance's): nothing it answers counts, and it is not stopped."""
        file = self.folder / lifecycle.STATE
        file.write_text(json.dumps({**self.state, "token": "another-token"}), "utf-8")
        self.assertEqual(lifecycle.status(), ("unresponsive", None))  # the lock is still held
        with self.assertRaisesRegex(GuardError, "did not take the stop request"):
            lifecycle.stop()
        self.assertEqual(self.actions, [])
        self.assertTrue(file.exists())


class OtherFolderTests(Folder):
    """Control files that are not in the user's settings folder are nobody's instance: in the
    current folder, in a project, beside the history file. They are not read, nothing is sent
    to the port they name, and they are left as they are."""

    def setUp(self):
        super().setUp()
        self.requests = []
        requests = self.requests

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.port = server.server_address[1]
        self.elsewhere = self.root / "elsewhere"
        self.elsewhere.mkdir()
        self.planted = {}
        for folder in (self.project, self.elsewhere):
            # By every sign an instance: a state file naming a port that answers, and a held lock.
            lifecycle.Instance(folder, TOKEN).publish(f"http://127.0.0.1:{self.port}/", self.port)
            self.addCleanup(os.close, lifecycle._acquire(folder))
            self.planted[folder] = (folder / lifecycle.STATE).read_bytes()

    def history_files(self):
        return ("history.sqlite3", str(self.project / "history.sqlite3"),
                str(self.elsewhere / "history.sqlite3"))  # fmt: skip

    def test_status_and_stop_use_only_the_users_folder(self):
        for history_db in self.history_files():
            with self.subTest(history_db), contextlib.chdir(self.project):
                os.environ["DEPBEE_HISTORY_DB"] = history_db
                self.assertEqual(lifecycle.status(), ("stopped", None))
                self.assertFalse(lifecycle.stop())
                none = (0, cli.BACKGROUND_NONE + "\n", "")
                self.assertEqual(run_cli("dashboard", "--status"), none)
                self.assertEqual(run_cli("dashboard", "--stop"), none)
                self.assertEqual(lifecycle._folder(), self.folder)
        self.assertEqual(self.requests, [])  # no stop or status went to the planted port
        for folder, state in self.planted.items():
            self.assertEqual((folder / lifecycle.STATE).read_bytes(), state)
        self.assertFalse(self.folder.exists())  # and asking created nothing

    def test_a_relative_settings_folder_is_refused_before_any_file_is_touched(self):
        for value in (".", "user"):
            with self.subTest(value), contextlib.chdir(self.project):
                os.environ["DEPBEE_CONFIG_DIR"] = value
                for argv in (["--status"], ["--stop"], ["--background"]):
                    code, out, err = run_cli("dashboard", *argv)
                    self.assertEqual((code, out), (2, ""))
                    self.assertIn("DEPBEE_CONFIG_DIR must be the absolute path",
                                  json.loads(err)["error"])  # fmt: skip
        self.assertEqual(self.requests, [])
        self.assertEqual((self.project / lifecycle.STATE).read_bytes(), self.planted[self.project])
        self.assertFalse((self.project / "user").exists())

    @unittest.skipUnless(WEB, NO_WEB)
    def test_a_start_from_a_project_runs_in_the_users_folder_and_leaves_the_projects_files(self):
        """The real CLI, started inside the project with a relative history file."""
        environment = {**os.environ, "PYTHONPATH": SRC, "PYTHONIOENCODING": "utf-8",
                       "DEPBEE_HISTORY_DB": "history.sqlite3"}  # fmt: skip

        def depbee(*argv):
            done = subprocess.run([sys.executable, "-m", "depbee", "dashboard", *argv],
                                  env=environment, cwd=self.project, text=True, encoding="utf-8",
                                  capture_output=True, timeout=90)  # fmt: skip
            return done.returncode, done.stdout.splitlines(), done.stderr

        self.addCleanup(depbee, "--stop")
        code, (url, line), err = depbee("--background", "--port", "0")  # a free port, when asked
        self.assertEqual((code, line, err), (0, cli.BACKGROUND_STARTED, ""))
        state = json.loads((self.folder / lifecycle.STATE).read_text("utf-8"))
        self.assertEqual(state["url"], url)
        self.assertEqual(url, f"http://127.0.0.1:{state['port']}/")
        self.assertNotIn(state["port"], (0, self.port, dashboard.DEFAULT_PORT))
        self.assertEqual(depbee("--stop"), (0, [cli.BACKGROUND_STOPPED], ""))
        self.assertEqual(self.requests, [])
        for folder, planted in self.planted.items():
            self.assertEqual((folder / lifecycle.STATE).read_bytes(), planted)
            self.assertFalse((folder / lifecycle.LOG).exists())


class ControlEndpointTests(unittest.TestCase):
    """Instance.control() as an ASGI app, without a server."""

    def setUp(self):
        self.stops, self.passed = [], []
        instance = lifecycle.Instance(Path("unused"), TOKEN)

        async def app(scope, receive, send):
            self.passed.append(scope["path"])

        self.app = instance.control(app, lambda: self.stops.append(True))

    def request(self, action="status", token=TOKEN, method="POST", path=lifecycle.CONTROL_PATH,
                **headers):  # fmt: skip
        nonce = "0123abcd"
        sent = {"x-depbee-action": action, "x-depbee-nonce": nonce,
                "x-depbee-auth": lifecycle._mac(token, action, nonce), **headers}  # fmt: skip
        scope = {"type": "http", "method": method, "path": path,
                 "headers": [(k.encode(), v.encode()) for k, v in sent.items() if v is not None]}  # fmt: skip
        messages = []

        async def send(message):
            messages.append(message)

        asyncio.run(self.app(scope, None, send))
        return messages, lifecycle._mac(TOKEN, "ok", action, nonce).encode()

    def test_a_request_with_the_token_gets_the_proof_and_stop_ends_the_server(self):
        (start, body), proof = self.request("status")
        self.assertEqual((start["status"], body["body"]), (200, proof))
        self.assertIn((b"cache-control", b"no-store"), start["headers"])
        self.assertEqual((self.stops, self.passed), ([], []))
        (start, body), proof = self.request("stop")
        self.assertEqual((start["status"], body["body"], self.stops), (200, proof, [True]))

    def test_anything_else_goes_to_the_app_as_if_there_were_no_endpoint(self):
        refused = (
            {"token": "another-token"},
            {"action": "restart"},
            {"method": "GET"},
            {"path": "/control/"},
            {"path": "/s/session/control"},
            {"x-depbee-auth": None},
            {"x-depbee-auth": "\u00e9"},
            {"x-depbee-nonce": "another-nonce"},
        )
        for changes in refused:
            with self.subTest(changes):
                messages, _ = self.request(**changes)
                self.assertEqual(messages, [])
        self.assertEqual((len(self.passed), self.stops), (len(refused), []))


@unittest.skipUnless(WEB, NO_WEB)
class ServeTests(Folder):
    def test_a_background_serve_publishes_instead_of_printing_and_can_be_stopped(self):
        from depbee.dashboard import app

        started = {}

        class Server:
            should_exit = False

            def __init__(self, config):
                started["config"], started["server"] = config, self

            def run(self, sockets):
                started["state"] = lifecycle._read(started["folder"])

        started["folder"] = self.folder
        instance = lifecycle.Instance(self.folder, TOKEN)
        out = io.StringIO()
        with mock.patch.object(app.uvicorn, "Server", Server), contextlib.redirect_stdout(out):
            app.serve(0, background=instance)
        state = started["state"]  # published before the server runs, with the bound port
        self.assertEqual(out.getvalue(), "")  # the address is in the state file, not printed
        self.assertEqual(state["url"], f"http://127.0.0.1:{state['port']}/")
        self.assertEqual((state["port"], state["token"]), (started["config"].port, TOKEN))
        # The control endpoint is in front of the guarded app and ends this server.
        scope = {"type": "http", "method": "POST", "path": lifecycle.CONTROL_PATH, "headers": [
            (b"x-depbee-action", b"stop"), (b"x-depbee-nonce", b"n"),
            (b"x-depbee-auth", lifecycle._mac(TOKEN, "stop", "n").encode())]}  # fmt: skip
        messages = []

        async def send(message):
            messages.append(message)

        asyncio.run(started["config"].app(scope, None, send))
        self.assertEqual(messages[0]["status"], 200)
        self.assertTrue(started["server"].should_exit)


@unittest.skipUnless(WEB, NO_WEB)
class ProcessTests(Folder):
    """The real CLI in real processes, as typed in a terminal. self.port: free when the test
    started and the one its dashboards serve on (start()), so that a restart has the address of
    the start before it, as with the default port, which no test serves on."""

    def setUp(self):
        super().setUp()
        self.environment = {**os.environ, "PYTHONPATH": SRC, "PYTHONIOENCODING": "utf-8"}
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}/"
        self.addCleanup(self.depbee, "--stop")  # whatever a failed test left running

    def start(self, *argv, wait=True):
        return self.depbee("--background", "--port", str(self.port), *argv, wait=wait)

    def depbee(self, *argv, wait=True):
        """depbee dashboard ARGV with captured output: (exit code, stdout lines, stderr), or
        the running process. A start that kept the pipes open would never return here."""
        command = [sys.executable, "-m", "depbee", "dashboard", *argv]
        options = {"env": self.environment, "cwd": self.root, "text": True, "encoding": "utf-8",
                   "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}  # fmt: skip
        if not wait:
            return subprocess.Popen(command, **options)
        done = subprocess.run(command, timeout=90, **options)
        return done.returncode, done.stdout.splitlines(), done.stderr

    def request(self, url, method="GET", path="/", body=None, headers=None):
        """(status, body) of a request to the dashboard at url, a root address."""
        connection = http.client.HTTPConnection("127.0.0.1", int(URL.fullmatch(url)[1]), timeout=10)
        try:
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            return response.status, response.read().decode("utf-8")
        finally:
            connection.close()

    def get(self, url):
        return self.request(url)[0]

    def page(self, url):
        return self.request(url)[1]

    def choose_theme(self, url, value):
        """The rail's theme form of the background dashboard, sent as a browser sends it: from
        the dashboard's own origin, with the hidden CSRF token of the page the form is on."""
        token = re.search(r'name="csrf" value="([^"]+)"', self.page(url))[1]
        body = urllib.parse.urlencode({"csrf": token, "theme": value, "back": "/"})
        headers = {"Origin": url.rstrip("/"), "Content-Type": "application/x-www-form-urlencoded"}
        return self.request(url, "POST", "/theme", body, headers)[0]

    def test_a_theme_chosen_in_the_background_keeps_status_and_stop_and_outlives_it(self):
        from depbee.dashboard import theme

        theme.save("light")
        code, (url, _), _ = self.start()
        self.assertIn('<html lang="ko" data-theme="light">', self.page(url))
        self.assertEqual(self.choose_theme(url, "dark"), 303)
        code, lines, _ = self.depbee("--status")
        self.assertEqual((code, lines[0]), (0, url))
        self.assertEqual(self.depbee("--stop"), (0, [cli.BACKGROUND_STOPPED], ""))
        code, (url, _), _ = self.start()
        self.assertIn('<html lang="ko" data-theme="dark">', self.page(url))
        self.assertEqual(self.depbee("--stop"), (0, [cli.BACKGROUND_STOPPED], ""))

    def test_start_status_duplicate_start_stop_and_stop_again(self):
        self.assertEqual(self.depbee("--status"), (0, [cli.BACKGROUND_NONE], ""))
        self.assertEqual(self.depbee("--stop"), (0, [cli.BACKGROUND_NONE], ""))
        self.assertFalse(self.folder.exists())  # asking created nothing, not even the folder

        code, (url, line), err = self.start()
        self.assertEqual((code, url, line, err), (0, self.url, cli.BACKGROUND_STARTED, ""))
        self.assertEqual(self.get(url), 200)  # ready when the command returned
        state = json.loads((self.folder / lifecycle.STATE).read_text("utf-8"))
        self.assertEqual((state["url"], state["port"]), (url, self.port))
        self.assertNotIn(state["token"], (self.folder / lifecycle.LOG).read_text("utf-8"))

        code, lines, _ = self.depbee("--status")
        self.assertEqual((code, lines[0]), (0, url))
        self.assertIn(f"PID {state['pid']}, 시작 {state['started_at']}", lines[1])
        # A second start starts nothing and shows the running one at the address it has, with
        # other options, with another port and with none (the default port, which stays unused).
        for argv in (["--port", "0", "--no-cache"], []):
            with self.subTest(argv):
                self.assertEqual(self.depbee("--background", *argv),
                                 (0, [url, cli.BACKGROUND_RUNNING], ""))  # fmt: skip
        self.assertEqual(json.loads((self.folder / lifecycle.STATE).read_text("utf-8")), state)

        self.assertEqual(self.depbee("--stop"), (0, [cli.BACKGROUND_STOPPED], ""))
        with self.assertRaises(OSError):
            self.get(url)
        self.assertFalse((self.folder / lifecycle.STATE).exists())
        self.assertFalse(lifecycle._alive(self.folder))  # its process has ended
        self.assertEqual(self.depbee("--stop"), (0, [cli.BACKGROUND_NONE], ""))
        self.assertEqual(self.depbee("--status"), (0, [cli.BACKGROUND_NONE], ""))

        # A restart is another process at the same address: a bookmark of it opens again.
        code, (again, line), _ = self.start()
        self.assertEqual((code, again, line), (0, url, cli.BACKGROUND_STARTED))
        self.assertEqual(self.get(url), 200)
        restarted = json.loads((self.folder / lifecycle.STATE).read_text("utf-8"))
        self.assertNotEqual((restarted["pid"], restarted["token"]), (state["pid"], state["token"]))
        self.assertEqual(self.depbee("--stop"), (0, [cli.BACKGROUND_STOPPED], ""))

    def test_starts_at_the_same_time_end_with_one_instance(self):
        starts = [self.start(wait=False) for _ in range(3)]
        results = []
        for process in starts:
            out, err = process.communicate(timeout=90)
            results.append((process.returncode, out.splitlines(), err))
        self.assertEqual([(code, err) for code, _, err in results], [(0, "")] * 3)
        self.assertEqual(len({lines[0] for _, lines, _ in results}), 1)  # one address
        said = sorted(lines[1] for _, lines, _ in results)
        self.assertEqual(said, sorted([cli.BACKGROUND_STARTED] + [cli.BACKGROUND_RUNNING] * 2))
        self.assertEqual(self.depbee("--stop"), (0, [cli.BACKGROUND_STOPPED], ""))
        # The starts that lost left no child waiting for the lock: none takes it now that it is
        # free and becomes an instance nobody asked for.
        time.sleep(lifecycle.LOCK_SECONDS + 0.5)
        self.assertFalse(lifecycle._alive(self.folder))
        self.assertFalse((self.folder / lifecycle.STATE).exists())

    def test_an_instance_that_died_is_seen_as_gone_and_a_new_start_replaces_it(self):
        _, (url, _), _ = self.start()
        state = json.loads((self.folder / lifecycle.STATE).read_text("utf-8"))
        # A crash, as from the task manager. Only this test ends a process by its ID.
        os.kill(state["pid"], signal.SIGTERM if os.name == "nt" else signal.SIGKILL)
        wait_until_free(self.folder)
        self.assertTrue((self.folder / lifecycle.STATE).exists())  # left behind by the crash
        self.assertEqual(self.depbee("--status"), (0, [cli.BACKGROUND_NONE], ""))
        self.assertFalse((self.folder / lifecycle.STATE).exists())  # recognized and removed
        (self.folder / lifecycle.STATE).write_text(json.dumps(state), "utf-8")  # put back
        code, (again, line), _ = self.start()  # on the port the crash gave back
        self.assertEqual((code, again, line), (0, url, cli.BACKGROUND_STARTED))
        self.assertNotEqual(lifecycle._read(self.folder)["token"], state["token"])
        self.assertEqual(self.get(again), 200)
        self.assertEqual(self.depbee("--stop"), (0, [cli.BACKGROUND_STOPPED], ""))

    def test_a_start_during_the_cleanup_of_an_old_state_file_keeps_its_own(self):
        """A check has found the state file of an instance that is gone and is at the point of
        removing it when a new start runs. Removing whatever is there by then took the new
        instance's file: the server ran, and --status and --stop no longer found it. The
        removal now holds the lock the new instance needs before it writes its file."""
        asked = []  # control requests to the port of the instance that is gone

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                asked.append(self.path)
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args):
                pass

        gone = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(gone.server_close)
        threading.Thread(target=gone.serve_forever, daemon=True).start()
        self.addCleanup(gone.shutdown)
        port = gone.server_address[1]
        self.folder.mkdir(mode=0o700)
        lifecycle.Instance(self.folder, TOKEN).publish(f"http://127.0.0.1:{port}/", port)
        state_file, log = self.folder / lifecycle.STATE, self.folder / lifecycle.LOG
        unlink, starts, published = os.unlink, [], []

        def is_new():
            state = lifecycle._read(self.folder)
            return state is not None and state["token"] != TOKEN

        def wait(condition, seconds):
            deadline = time.monotonic() + seconds
            while not condition() and time.monotonic() < deadline:
                time.sleep(0.02)
            return condition()

        def start_meanwhile(path, *args, **kwargs):
            if not starts and Path(path) == state_file:
                starts.append(self.start(wait=False))
                # Its own check has read the old file and asked the old port (the second
                # request, after this test's). Its child takes the lock within a moment if
                # nothing holds it, and then writes its file; a child that has to wait for this
                # removal gets the lock afterwards (the wait here is shorter than its patience).
                self.assertTrue(wait(lambda: len(asked) >= 2, 60))
                if wait(log.exists, lifecycle.LOCK_SECONDS / 2) and wait(is_new, 30):
                    published.append(state_file.read_bytes())
            return unlink(path, *args, **kwargs)

        def restore():  # after a failure: a server without its file could not be stopped
            if published and not state_file.exists():
                state_file.write_bytes(published[0])

        self.addCleanup(restore)
        with mock.patch.object(lifecycle.os, "unlink", side_effect=start_meanwhile):
            self.assertEqual(lifecycle.status(), ("stopped", None))
        (start,) = starts
        out, err = start.communicate(timeout=90)
        self.assertEqual(published, [], "an instance wrote its state file during the removal")
        self.assertEqual((start.returncode, err), (0, ""))
        url, line = out.splitlines()
        self.assertEqual(line, cli.BACKGROUND_STARTED)
        state = lifecycle._read(self.folder)
        self.assertIsNotNone(state, "the new instance's state file went with the old one")
        self.assertEqual(state["url"], url)
        code, lines, _ = self.depbee("--status")
        self.assertEqual((code, lines[0]), (0, url))
        self.assertEqual(self.get(url), 200)
        self.assertEqual(self.depbee("--stop"), (0, [cli.BACKGROUND_STOPPED], ""))

    def test_a_stop_is_done_when_its_instance_ended_whatever_started_after_it(self):
        """The stopped instance ends and a new one starts before the stop looks again. The lock
        is held again, by the new instance: waiting for the lock waited for the wrong server
        and failed after the time limit, although the old one had ended."""
        _, (old, _), _ = self.start()
        stopped = lifecycle._read(self.folder)["token"]
        control, restarts = lifecycle._control, []

        def restart_once_stopped(state, action):
            accepted = control(state, action)
            if action == "stop" and accepted:
                wait_until_free(self.folder)  # the instance that took the request has ended
                restarts.append(self.start())  # at the address the stopped one had
            return accepted

        with mock.patch.object(lifecycle, "_control", side_effect=restart_once_stopped), \
                mock.patch.object(lifecycle, "STOP_SECONDS", 2):  # fmt: skip
            self.assertEqual(run_cli("dashboard", "--stop"),
                             (0, cli.BACKGROUND_STOPPED + "\n", ""))  # fmt: skip
        ((code, (new, line), err),) = restarts
        self.assertEqual((code, new, line, err), (0, old, cli.BACKGROUND_STARTED, ""))
        self.assertNotEqual(lifecycle._read(self.folder)["token"], stopped)
        # The new instance was neither waited for nor touched: its file and server are there.
        code, lines, _ = self.depbee("--status")
        self.assertEqual((code, lines[0]), (0, new))
        self.assertEqual(self.get(new), 200)
        self.assertEqual(self.depbee("--stop"), (0, [cli.BACKGROUND_STOPPED], ""))

    def test_a_start_that_fails_says_why_and_leaves_nothing_running(self):
        with socket.create_server(("127.0.0.1", 0)) as taken:
            port = taken.getsockname()[1]
            code, out, err = self.depbee("--background", "--port", str(port))
            # In the terminal too: an error and no address, and no other port instead.
            here = self.depbee("--port", str(port))
            taken.settimeout(0)
            with self.assertRaises(BlockingIOError):  # nobody connected to what listens there
                taken.accept()
        self.assertEqual((code, out), (2, []))  # no address before it was ready
        error = json.loads(err)["error"]
        self.assertTrue(error.startswith("The background dashboard did not start: "), error)
        self.assertNotIn("exit code", error)  # the child's own error, here the bind failure
        self.assertEqual((here[0], here[1]), (2, []))
        self.assertNotIn("Traceback", here[2])
        self.assertIn(json.loads(here[2])["error"], error)  # the same reason, said by serve()
        self.assertFalse((self.folder / lifecycle.STATE).exists())
        self.assertFalse(lifecycle._alive(self.folder))
        code, out, err = self.depbee("--background", "--port", "70000")
        self.assertEqual((code, out), (2, []))
        self.assertIn("--port must be between 0 and 65535", json.loads(err)["error"])
        self.assertEqual(self.depbee("--status"), (0, [cli.BACKGROUND_NONE], ""))

    def test_the_port_of_a_running_dashboard_is_not_taken_and_that_one_is_left_alone(self):
        """Two settings folders (two accounts, or DEPBEE_CONFIG_DIR) and one port. The second
        start fails with the reason instead of serving somewhere else, and its folder has no
        token of the first dashboard: it cannot stop it, and says that none of its own runs."""
        _, (url, _), _ = self.start()
        other, own = self.root / "another-user", self.environment
        self.environment = {**own, "DEPBEE_CONFIG_DIR": str(other)}
        try:
            code, out, err = self.start()
            self.assertEqual((code, out), (2, []))
            error = json.loads(err)["error"]
            self.assertTrue(error.startswith("The background dashboard did not start: "), error)
            self.assertNotIn("exit code", error)
            self.assertEqual(self.depbee("--status"), (0, [cli.BACKGROUND_NONE], ""))
            self.assertEqual(self.depbee("--stop"), (0, [cli.BACKGROUND_NONE], ""))
        finally:
            self.environment = own
        self.assertFalse((other / lifecycle.STATE).exists())
        self.assertFalse(lifecycle._alive(other))
        code, lines, _ = self.depbee("--status")
        self.assertEqual((code, lines[0]), (0, url))
        self.assertEqual(self.get(url), 200)
        self.assertEqual(self.depbee("--stop"), (0, [cli.BACKGROUND_STOPPED], ""))

    def test_a_child_that_is_not_ready_in_time_is_ended_and_reported(self):
        created = []
        real = subprocess.Popen

        def popen(*args, **kwargs):
            created.append(real(*args, **kwargs))
            return created[-1]

        slow = "import sys, time; sys.stdin.read(); time.sleep(60)"
        with mock.patch.object(lifecycle, "_BOOTSTRAP", slow), \
                mock.patch.object(lifecycle, "START_SECONDS", 1), \
                mock.patch.object(lifecycle.subprocess, "Popen", side_effect=popen):  # fmt: skip
            with self.assertRaisesRegex(GuardError, "was not ready within 1 s"):
                lifecycle.start(self.port)
        (child,) = created
        self.assertIsNotNone(child.returncode)  # ended through the handle start() held
        self.assertFalse((self.folder / lifecycle.STATE).exists())

    def test_a_lock_holder_that_never_answers_is_reported_not_killed(self):
        self.folder.mkdir()
        held = lifecycle._acquire(self.folder)
        self.addCleanup(os.close, held)
        self.assertEqual(self.depbee("--status"), (2, [cli.BACKGROUND_UNRESPONSIVE], ""))
        code, out, err = self.depbee("--stop")
        self.assertEqual((code, out), (2, []))
        self.assertIn("never ends it by process ID", json.loads(err)["error"])
        with mock.patch.object(lifecycle, "START_SECONDS", 4):
            with self.assertRaisesRegex(GuardError, "Another background dashboard keeps the lock"):
                lifecycle.start(self.port)
        self.assertTrue(lifecycle._alive(self.folder))  # still ours


if __name__ == "__main__":
    unittest.main()
