"""Run the slow steps of an analysis in a child process that is killed when time is up.

A Python thread cannot be stopped, so a registry download, unpacking or feature extraction that
ran past its limit would keep its connection, files and CPU after the caller gave up. run()
gives the function and its arguments to a child Python process instead (pickled by this, the
parent, process) and kills the child when the time is up (TerminateProcess on Windows, SIGKILL
elsewhere). That stops its work and closes its sockets and files; run() waits until it has
exited and only then raises TimeLimitError. The child sends its result back as JSON (or raw
bytes), never as a pickle, because it has handled package data.

budget() makes the steps of one analyzed change share ANALYSIS_SECONDS, counted from the first
step: registry metadata, both tarball downloads, unpacking and feature extraction.
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
    """Share one ANALYSIS_SECONDS among the run() calls inside, counted from the first call.

    A budget() inside another one adds nothing: check opens one around its metadata read and
    the analysis, so both belong to its single change.
    """
    token = None if _scope.get() is not None else _scope.set({})
    try:
        yield
    finally:
        if token is not None:
            _scope.reset(token)


def _remaining() -> float:
    scope, now = _scope.get(), time.monotonic()
    if scope is None:
        return ANALYSIS_SECONDS
    return scope.setdefault("deadline", now + ANALYSIS_SECONDS) - now


def run(function: Callable, args: tuple):
    """function(*args) in a child process, within what is left of the current budget.

    function and args must be picklable (module-level functions, bound methods of picklable
    objects); the result must be bytes or JSON. A failure in the child raises StepError with its
    message; running out of time kills the child and raises TimeLimitError.
    """
    seconds = _remaining()
    if seconds <= 0:
        raise TimeLimitError(_limit_message())
    payload = pickle.dumps(sys.path) + pickle.dumps((function, args))
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", _BOOTSTRAP],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        out, err = process.communicate(payload, timeout=seconds)
    except subprocess.TimeoutExpired:
        raise TimeLimitError(_limit_message()) from None
    finally:
        if process.poll() is None:  # timed out or interrupted: stop the work and its I/O
            process.kill()
            process.communicate()  # returns once the child has exited and its pipes are closed
    tag, body = out[:1], out[1:]
    if tag == b"B":
        return body
    if tag == b"J":
        return json.loads(body)
    if tag == b"E":
        raise StepError(json.loads(body))
    tail = err.decode("utf-8", "replace")[-_MAX_STDERR:]
    raise StepError(f"Analysis process ended without a result (exit {process.returncode}): {tail}")


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
