"""Read the base package-lock.json from a Git commit with fixed, read-only plumbing commands.

Nothing is fetched, and the working tree, index and branches are left untouched.
"""

import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

from ..contracts import MAX_JSON_BYTES, GuardError

TIMEOUT_SECONDS = 30
_LINE_LIMIT = 4096  # rev-parse prints one commit id
_STDERR_LIMIT = 4096
_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def _run(argv: list[str], cwd: Path, limit: int) -> tuple[int, bytes, bytes]:
    """Run argv without a shell and return (returncode, stdout, stderr).

    The child is killed at TIMEOUT_SECONDS, or as soon as stdout passes limit bytes or stderr
    passes _STDERR_LIMIT bytes, so neither time nor memory depends on what it prints.
    """
    caps = {"stdout": limit, "stderr": _STDERR_LIMIT}
    captured: dict[str, bytes] = {}
    with subprocess.Popen(
        argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as proc:

        def drain(name: str) -> None:
            captured[name] = getattr(proc, name).read(caps[name] + 1)
            if len(captured[name]) > caps[name]:
                proc.kill()

        # One reader per pipe, so a child filling one pipe cannot block the other.
        readers = [threading.Thread(target=drain, args=(name,), daemon=True) for name in caps]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + TIMEOUT_SECONDS
        try:
            for reader in readers:
                reader.join(max(0.0, deadline - time.monotonic()))
            if any(reader.is_alive() for reader in readers):
                raise subprocess.TimeoutExpired(argv, TIMEOUT_SECONDS)
            proc.wait(max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise GuardError(f"Git did not finish within {TIMEOUT_SECONDS} seconds") from exc
        finally:
            # Popen's exit then closes the pipes and reaps the child.
            if proc.poll() is None:
                proc.kill()
    if any(len(captured[name]) > cap for name, cap in caps.items()):
        raise GuardError(f"Git output exceeds {limit} bytes (stderr {_STDERR_LIMIT})")
    return proc.returncode, captured["stdout"], captured["stderr"]


def _git(project: Path, *args: str, limit: int = _LINE_LIMIT) -> tuple[int, bytes, bytes]:
    git = shutil.which("git")
    # Windows also searches the current directory; never run a git.exe planted there.
    if git is None or not os.path.isabs(git):
        raise GuardError("Git executable not found on PATH")
    try:
        return _run([git, *args], project, limit)
    except OSError as exc:
        raise GuardError(f"Unable to run Git: {exc}") from exc


def _detail(stderr: bytes) -> str:
    text = stderr.decode("utf-8", "replace").strip()
    return f": {text[:300]}" if text else ""


def read_base_lock(project: Path, ref: str) -> bytes:
    """Raw bytes of project/package-lock.json as committed in ref (any commit-ish)."""
    if not ref or ref.startswith("-"):
        raise GuardError(f"Invalid Git ref: {ref!r}")
    code, out, err = _git(
        project, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}"
    )
    commit = out.decode("ascii", "replace").strip()
    if code or not _COMMIT.fullmatch(commit):
        raise GuardError(f"Git cannot resolve {ref} to a commit in {project}{_detail(err)}")
    # Git resolves ./ against cwd (the project) into the path from the repository root.
    code, out, err = _git(
        project, "cat-file", "blob", f"{commit}:./package-lock.json", limit=MAX_JSON_BYTES
    )
    if code:
        raise GuardError(f"No package-lock.json for {project} in Git ref {ref}{_detail(err)}")
    return out
