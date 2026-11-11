"""Run the slow steps of an analysis in a child process that is killed when time is up.

A Python thread cannot be stopped, so a registry download, unpacking or feature extraction that
ran past its limit would keep its connection, files and CPU after the caller gave up. run()
gives the function and its arguments to a child Python process instead (pickled by this, the
parent, process) and kills the child when the time is up (TerminateProcess on Windows, SIGKILL
elsewhere). That stops its work and closes its sockets and files; run() waits until it has
exited and only then raises TimeLimitError. The child sends its result back as JSON (or raw
bytes), never as a pickle, because it has handled package data.

budget() gives one analyzed change ANALYSIS_SECONDS from the moment it starts, whether or not it
starts a child: registry metadata, both tarball downloads, unpacking and feature extraction in
children, and the parent's own work (parsing metadata, the cache, evidence). The parent's own
synchronous work cannot be interrupted; run() and check() refuse its result once the deadline
passed, so such work can overrun the deadline by its own length but never turns into a success.
Deadlines use time.perf_counter, a monotonic clock kept apart from time.monotonic, which reports
the elapsed times in reports (and which tests and the fixed-clock evidence runner replace).
"""

import contextlib
import contextvars
import json
import pickle
import subprocess
import sys
import time
from collections.abc import Callable

from ..contracts import GuardError

ANALYSIS_SECONDS = 300
_clock = time.perf_counter  # enforcement only; elapsed_seconds use time.monotonic
_MAX_STDERR = 500
# -I: the child ignores PYTHON* variables and the current folder; it gets the parent's sys.path.
_BOOTSTRAP = (
    "import pickle, sys; sys.path[:] = pickle.load(sys.stdin.buffer); "
    "from depbee.analysis.bounded import _child; _child()"
)
_scope: contextvars.ContextVar[dict | None] = contextvars.ContextVar("budget", default=None)


class TimeLimitError(GuardError):
    """The steps of one change did not finish within ANALYSIS_SECONDS; the work was stopped."""


class StepError(GuardError):
    """A step failed in the child process; the message is the child's error message."""


@contextlib.contextmanager
def budget():
    """One change's ANALYSIS_SECONDS, from now, for the run() and check() calls inside.

    A budget() inside another one adds nothing: check opens one around its metadata read and
    the analysis, so both belong to its single change.
    """
    outer = _scope.get() is not None
    token = None if outer else _scope.set({"deadline": _clock() + ANALYSIS_SECONDS})
    try:
        yield
    finally:
        if token is not None:
            _scope.reset(token)


def _deadline() -> float:
    """The current budget's deadline; a run() outside any budget() gets its own, fixed when it
    starts."""
    scope = _scope.get()
    return scope["deadline"] if scope is not None else _clock() + ANALYSIS_SECONDS


def _remaining() -> float:
    return _deadline() - _clock()


def check() -> None:
    """Raise TimeLimitError if the current budget has run out (nothing outside a budget()).
    Callers use it before accepting work the parent did itself (parsing, cache, evidence)."""
    scope = _scope.get()
    if scope is not None and _clock() > scope["deadline"]:
        raise TimeLimitError(_limit_message())


def run(function: Callable, args: tuple):
    """function(*args) in a child process, within what is left of the current budget.

    function and args must be picklable (module-level functions, bound methods of picklable
    objects); the result must be bytes or JSON. A failure in the child raises StepError with its
    message; running out of time kills the child and raises TimeLimitError.

    The parent's own steps here (pickling, starting the process, decoding the result) cannot be
    interrupted, so the deadline is checked again after each: no child starts once it has
    passed, a started child is killed, and a result that arrives or is decoded later is refused.
    """
    deadline = _deadline()

    def left() -> float:
        seconds = deadline - _clock()
        if seconds <= 0:
            raise TimeLimitError(_limit_message())
        return seconds

    left()
    payload = pickle.dumps(sys.path) + pickle.dumps((function, args))
    left()
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", _BOOTSTRAP],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        out, err = process.communicate(payload, timeout=left())
    except subprocess.TimeoutExpired:
        raise TimeLimitError(_limit_message()) from None
    finally:
        if process.poll() is None:  # out of time or interrupted: stop the work and its I/O
            process.kill()
            process.communicate()  # returns once the child has exited and its pipes are closed
    tag, body = out[:1], out[1:]
    if tag not in (b"B", b"J", b"E"):
        tail = err.decode("utf-8", "replace")[-_MAX_STDERR:]
        raise StepError(f"Analysis process ended without a result (exit {process.returncode}): {tail}")
    try:
        value = body if tag == b"B" else json.loads(body)
    except ValueError as exc:
        raise StepError("Analysis process sent an unreadable result") from exc
    left()  # the result is used only if it arrived and was decoded in time
    if tag == b"E":
        raise StepError(value)
    return value


def _limit_message() -> str:
    return (
        f"Analysis did not finish within {ANALYSIS_SECONDS} s (registry metadata, tarball "
        "downloads, unpacking and feature extraction of one change share this limit)"
    )


def _child() -> None:
    """The child's side of run(): read the call, write a tagged result to stdout."""
    out, sys.stdout = sys.stdout.buffer, sys.stderr  # nothing else may write the result stream
    try:
        function, args = pickle.load(sys.stdin.buffer)
        result = function(*args)
        data = b"B" + result if isinstance(result, bytes) else b"J" + json.dumps(result).encode()
    except Exception as exc:
        data = b"E" + json.dumps(str(exc) or type(exc).__name__).encode()
    out.write(data)
    out.flush()
