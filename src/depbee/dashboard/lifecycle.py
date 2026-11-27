"""Background dashboard: `depbee dashboard --background`, `--status` and `--stop`.

One background instance per user settings folder (config.user_dir(): of the user's home, or the
absolute DEPBEE_CONFIG_DIR, never the current folder or a project). Three files there belong to
it: dashboard.lock, which the serving process keeps locked for its whole life, so whether one
runs is the operating system's answer and never a guess from a process ID; dashboard.json, its
address and control token, written once its port is bound and removed when it ends; and
dashboard.log, what it writes to stderr.

No process is ever killed by its ID. `--stop` sends a stop request authenticated with the token
to 127.0.0.1 and the server ends itself as after Ctrl+C. Every answer carries a proof of the same
token, so a state file whose port is now someone else's is seen as stale, and is removed. The one
process killed here is the child start() has just created and still holds, when it does not
become ready.

The lock also orders who may touch the state file. Only the process that holds it writes the
file, and a file left behind is removed only by a caller that holds it (_sweep), so a check that
found an old file never removes the one a new instance has written meanwhile. A stop waits for
the instance that took its request: once the lock belongs to a newer instance, it is done.

The address is the root of the port, http://127.0.0.1:<port>/, and the port is DEFAULT_PORT
unless another is asked for. A port that cannot be bound is the child's error, which start()
reports: no other port is tried, and whatever listens there is left alone. The token proves which
process a stop or status request reaches. It keeps nobody on this PC out of the dashboard.

Standard library only: the child imports the web libraries through dashboard.serve().
"""

import contextlib
import errno
import hmac
import http.client
import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from .. import config
from ..contracts import GuardError, parse_json
from . import DEFAULT_PORT

HOST = "127.0.0.1"  # the only address ever contacted, whatever a state file says
STATE, LOCK, LOG = "dashboard.json", "dashboard.lock", "dashboard.log"
CONTROL_PATH = "/control"
ACTIONS = ("status", "stop")
START_SECONDS = 30  # from creating the child to its proven answer
STOP_SECONDS = 15  # from an accepted stop request to the end of the process
CONTROL_SECONDS = 3  # one control request
LOCK_SECONDS = 2  # the child's wait for the lock, which a status check holds for an instant
ALREADY = 3  # the child's exit code when another instance keeps the lock
MAX_STATE = 4096  # bytes of a state file
# The address in a state file: the root of the port on HOST, which app.serve() publishes, or
# what the version before published (a session of URL-safe text and a path). An instance that
# version started still serves at that address and takes the same control requests, so its file
# is read until it ends, to show, reuse and stop it.
_URL = re.compile(r"http://127\.0\.0\.1:(\d+)/(?:s/[A-Za-z0-9_-]+/[A-Za-z0-9_/-]*)?")
_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
# These may be relative; the child, which runs in the settings folder, gets them as the
# absolute paths they mean where the user started it.
_PATH_VARIABLES = ("DEPBEE_HISTORY_DB", "DEPBEE_MODEL_DIR", "DEPBEE_KNOWN_MALICIOUS_DIR")
# -I as analysis.bounded: no PYTHON* variables and no current folder; the parent's sys.path.
_BOOTSTRAP = (
    "import json, sys; job = json.load(sys.stdin); sys.path[:] = job['sys_path']; "
    "from depbee.dashboard.lifecycle import _child; _child(job)"
)


def _folder() -> Path:
    """The instance's folder: the user's settings folder (config.user_dir()), which is absolute
    and never the current folder, a project or the history file's folder, so no state file
    from such a place is ever read or acted on."""
    try:
        return config.user_dir()
    except RuntimeError as exc:
        raise GuardError(
            "No home folder for the depbee settings folder; set DEPBEE_CONFIG_DIR to the "
            "absolute path of a folder of yours"
        ) from exc


def _acquire(folder: Path) -> int | None:
    """Take the instance lock: its open descriptor, which holds the lock until it is closed or
    the process ends, or None while another descriptor (of any process) holds it. Any other
    failure (a folder that cannot be written, a file system without locks) is its OSError."""
    descriptor = os.open(folder / LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(descriptor)
        if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):  # held
            return None
        raise
    return descriptor


def _alive(folder: Path) -> bool:
    """A background instance lives here: its lock is held. Creates nothing."""
    if not (folder / LOCK).exists():
        return False
    descriptor = _acquire(folder)
    if descriptor is None:
        return True
    os.close(descriptor)
    return False


def _read(folder: Path) -> dict | None:
    """The state file as publish() writes it, or None if there is none or it is not one
    (unreadable, another shape, an address that is not this dashboard's on HOST)."""
    try:
        with open(folder / STATE, "rb") as stream:
            state, _ = parse_json(stream.read(MAX_STATE + 1), STATE)
    except (OSError, GuardError):
        return None
    url, port, token = state.get("url"), state.get("port"), state.get("token")
    address = _URL.fullmatch(url) if isinstance(url, str) else None
    valid = (
        address is not None
        and type(port) is int
        and address[1] == str(port)
        and 0 < port < 65536
        and isinstance(token, str)
        and bool(token)
        and type(state.get("pid")) is int
        and isinstance(state.get("started_at"), str)
        and _TIME.fullmatch(state["started_at"]) is not None
    )
    return state if valid else None


def _forget(folder: Path, token: str) -> None:
    """An instance's removal of its own state file, as it ends: the file goes if it is still the
    one with this token. Only for the instance itself, which holds the lock: for anyone else the
    file could become a newer instance's between the look and the removal (_sweep)."""
    state = _read(folder)
    if state is not None and state["token"] == token:
        with contextlib.suppress(OSError):
            os.unlink(folder / STATE)


def _sweep(folder: Path) -> None:
    """Remove the state file a gone instance left behind. The lock is taken first and kept until
    the file is removed: an instance writes its file only while it holds the lock, so what is
    removed here is never the file of an instance that started meanwhile. While an instance (or
    another check, for an instant) holds the lock, nothing is removed."""
    descriptor = _acquire(folder)
    if descriptor is None:
        return
    try:
        with contextlib.suppress(OSError):
            os.unlink(folder / STATE)
    finally:
        os.close(descriptor)


def _mac(token: str, *parts: str) -> str:
    return hmac.new(token.encode(), "\n".join(parts).encode(), "sha256").hexdigest()


def _control(state: dict, action: str) -> bool:
    """Send action to the instance of state and check its answer: True only if the server on
    state's port proved that it holds state's token (and so took the action)."""
    nonce = secrets.token_hex(16)
    headers = {
        "x-depbee-action": action,
        "x-depbee-nonce": nonce,
        "x-depbee-auth": _mac(state["token"], action, nonce),
    }
    try:
        connection = http.client.HTTPConnection(HOST, state["port"], timeout=CONTROL_SECONDS)
        try:
            connection.request("POST", CONTROL_PATH, headers=headers)
            response = connection.getresponse()
            answer = response.read(128)
        finally:
            connection.close()
    except (OSError, http.client.HTTPException):
        return False
    proof = _mac(state["token"], "ok", action, nonce).encode()
    return response.status == 200 and hmac.compare_digest(answer, proof)


class Instance:
    """The serving side: what dashboard.app.serve() needs to run as the background instance."""

    def __init__(self, folder: Path, token: str) -> None:
        self.folder, self.token = folder, token

    def control(self, app, stop):
        """app behind the control endpoint. A POST to CONTROL_PATH whose headers carry an
        action, a nonce and their HMAC under this instance's token is answered with the HMAC of
        the answer, and "stop" then calls stop() (the server ends as after Ctrl+C). Any other
        request, a wrong HMAC included, goes to app as if there were no such endpoint."""

        async def controlled(scope, receive, send):
            answer = self._answer(scope) if scope["type"] == "http" else None
            if answer is None:
                await app(scope, receive, send)
                return
            action, proof = answer
            headers = [(b"content-type", b"text/plain"), (b"cache-control", b"no-store")]
            await send({"type": "http.response.start", "status": 200, "headers": headers})
            await send({"type": "http.response.body", "body": proof})
            if action == "stop":
                stop()

        return controlled

    def _answer(self, scope) -> tuple[str, bytes] | None:
        """(action, proof) for a control request with this instance's token, else None."""
        if scope["path"] != CONTROL_PATH or scope["method"] != "POST":
            return None
        headers = dict(scope["headers"])  # ASGI header names are lowercase bytes
        action = headers.get(b"x-depbee-action", b"").decode("latin-1")
        nonce = headers.get(b"x-depbee-nonce", b"").decode("latin-1")
        expected = _mac(self.token, action, nonce).encode()
        if action not in ACTIONS or not hmac.compare_digest(
            headers.get(b"x-depbee-auth", b""), expected
        ):
            return None
        return action, _mac(self.token, "ok", action, nonce).encode()

    def publish(self, url: str, port: int) -> None:
        """Write the state file: called once the port is bound, before the first request."""
        now = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        state = {
            "url": url, "port": port, "pid": os.getpid(), "token": self.token, "started_at": now,
        }  # fmt: skip
        config.write_atomic(self.folder / STATE, json.dumps(state, ensure_ascii=True) + "\n")

    def close(self) -> None:
        _forget(self.folder, self.token)


def _child(job: dict) -> None:
    """The background process, created by start() through _BOOTSTRAP: take the lock, send
    stdout and stderr to the log, serve until stopped, remove the state file."""
    folder = Path(job["folder"])
    deadline = time.monotonic() + LOCK_SECONDS
    # Never closed: the end of this process is what gives the lock back.
    while _acquire(folder) is None:
        if time.monotonic() > deadline:
            raise SystemExit(ALREADY)
        time.sleep(0.1)
    log = os.open(folder / LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.dup2(log, 1)
    os.dup2(log, 2)
    os.close(log)
    sys.stdout.reconfigure(errors="backslashreplace")  # the log's encoding is the locale's
    instance = Instance(folder, job["token"])
    try:
        from . import serve

        serve(job["port"], background=instance, no_cache=job["no_cache"],
              **{key: job[key] and Path(job[key])
                 for key in ("model_dir", "cache_dir", "known_malicious_dir")})  # fmt: skip
    except (GuardError, OSError, ValueError) as exc:
        # The last line of the log, as the CLI's stderr: start() reports it (_failure).
        error = {"status": "error", "exit_code": 2, "error": str(exc)}
        print(json.dumps(error, ensure_ascii=True), file=sys.stderr, flush=True)
        raise SystemExit(2) from None
    finally:
        instance.close()


def _failure(folder: Path, code: int, since: float) -> str:
    """Why the child ended: the error it wrote last to its log, else its exit code. since: when
    the child was created (time.time()); a log older than that is an earlier start's."""
    try:
        if os.stat(folder / LOG).st_mtime < since - 2:  # 2: coarse file times
            raise LookupError("the log of an earlier start")
        with open(folder / LOG, "rb") as stream:
            last = stream.read().decode("utf-8", "replace").strip().splitlines()[-1]
        return str(json.loads(last)["error"])
    except (OSError, ValueError, LookupError, TypeError):
        return f"its process ended with exit code {code} (log: {folder / LOG})"


def start(
    port: int = DEFAULT_PORT, *, model_dir: Path | None = None, cache_dir: Path | None = None,
    no_cache: bool = False, known_malicious_dir: Path | None = None,
) -> tuple[dict, bool]:  # fmt: skip
    """Make sure a background instance runs: (its state, whether this call started it).

    If one already answers, nothing is started and its options stay as they are, the port
    included: the state returned is that instance's, with its own address. Otherwise a
    detached child is created (no console window on Windows, its own session elsewhere, so it
    outlives this terminal) and this waits until a state file is there and the server behind it
    has proved its token. Only then is the address returned. It is the child's if the token is
    the one created here, else that of an instance started at the same time, and then the child
    is ended. A child that ends first is a GuardError with its error, and one not ready after
    START_SECONDS is ended too.
    """
    kind, state = status()
    if kind == "running":
        return state, False
    folder = _folder()
    try:
        config.make_dir(folder)
    except OSError as exc:
        raise GuardError(f"The depbee settings folder cannot be created: {folder}") from exc
    token = secrets.token_urlsafe(32)

    def absolute(value: Path | None) -> str | None:
        return None if value is None else os.path.abspath(value)

    job = {
        "sys_path": [os.path.abspath(entry) for entry in sys.path], "folder": str(folder),
        "token": token, "port": port, "no_cache": no_cache, "model_dir": absolute(model_dir),
        "cache_dir": absolute(cache_dir), "known_malicious_dir": absolute(known_malicious_dir),
    }  # fmt: skip
    environment = dict(os.environ)
    for name in _PATH_VARIABLES:
        if environment.get(name):
            environment[name] = os.path.abspath(environment[name])
    # CREATE_NO_WINDOW: a console of its own without a window, which the programs it runs (git,
    # node) share, so none of them opens one, and closing this terminal does not reach it.
    detached = (
        {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt"
        else {"start_new_session": True}
    )  # fmt: skip
    created = time.time()
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", _BOOTSTRAP], stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=folder, env=environment,
        **detached,
    )  # fmt: skip
    started = False
    try:
        with contextlib.suppress(OSError):  # a child that has ended is reported below
            process.stdin.write(json.dumps(job).encode())
            process.stdin.close()
        deadline = time.monotonic() + START_SECONDS
        while time.monotonic() < deadline:
            state = _read(folder)
            if state is not None and _control(state, "status"):
                started = state["token"] == token
                return state, started
            code = process.poll()
            if code not in (None, ALREADY):  # ALREADY: wait for the instance that has the lock
                raise GuardError(
                    f"The background dashboard did not start: {_failure(folder, code, created)}"
                )
            time.sleep(0.1)
        if process.poll() == ALREADY:
            raise GuardError(
                "Another background dashboard keeps the lock but has not answered within "
                f"{START_SECONDS} s (it is starting, or finishing work before it ends); check "
                "depbee dashboard --status"
            )
        raise GuardError(
            f"The background dashboard was not ready within {START_SECONDS} s and was not "
            f"left running (log: {folder / LOG})"
        )
    finally:
        # Unless the child is the instance returned, it must not stay: one still waiting for the
        # lock would become an instance nobody asked for once the other one stops. It is the
        # child created above, ended through the handle this call still holds.
        if not started and process.poll() is None:
            process.kill()
            process.wait()
            # What it may have published. If its lock is not free yet, or is another instance's,
            # nothing is removed here and the next status() does it.
            with contextlib.suppress(OSError):
                _sweep(folder)


def status() -> tuple[str, dict | None]:
    """("running", state) for an instance that proves its token; ("unresponsive", None) while
    one keeps the lock without answering (it is starting, or finishing work before it ends);
    else ("stopped", None), after removing a state file left by an instance that is gone."""
    folder = _folder()
    state = _read(folder)
    if state is not None and _control(state, "status"):
        return "running", state
    if _alive(folder):
        return "unresponsive", None
    if state is not None:
        _sweep(folder)
    return "stopped", None


def stop() -> bool:
    """Stop the background instance: True once its process has ended, False if none was
    running. GuardError if one is alive but does not take the request, or has not ended
    STOP_SECONDS after taking it (it finishes a running check or apply first).

    The wait is for the instance that took the request. Its lock is also the next instance's,
    so a lock that is held again does not mean it is still there: once the state file is another
    instance's, the one stopped has ended, and the new one is neither waited for nor touched."""
    folder = _folder()
    state = _read(folder)
    if state is None or not _control(state, "stop"):
        if status()[0] == "stopped":
            return False
        raise GuardError(
            "A background dashboard is alive but did not take the stop request (it is starting, "
            "or finishing work before it ends); try again shortly. depbee never ends it by "
            "process ID"
        )
    deadline = time.monotonic() + STOP_SECONDS
    while _alive(folder):
        current = _read(folder)
        if current is not None and current["token"] != state["token"]:
            return True  # the lock is a newer instance's now
        if time.monotonic() > deadline:
            raise GuardError(
                f"The background dashboard took the stop request but has not ended within "
                f"{STOP_SECONDS} s: it finishes a running check or apply first. Its address no "
                "longer opens; check again with depbee dashboard --status"
            )
        time.sleep(0.1)
    _sweep(folder)
    return True
