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
# Inherited, these would make Git read another repository than the one holding the project.
_REPOSITORY_VARIABLES = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
)


def _run(
    argv: list[str], cwd: Path, limit: int, env: dict[str, str] | None = None
) -> tuple[int, bytes, bytes]:
    """Run argv without a shell and return (returncode, stdout, stderr).

    The child is killed at TIMEOUT_SECONDS, or as soon as stdout passes limit bytes or stderr
    passes _STDERR_LIMIT bytes, so memory does not depend on what it prints. Only the direct
    child is killed: processes it started keep running, and closing the pipes waits for them.
    On Windows the default Git\\cmd\\git.exe is such a wrapper, so a timeout can take until the
    real Git ends.
    """
    caps = {"stdout": limit, "stderr": _STDERR_LIMIT}
    captured: dict[str, bytes] = {}
    with subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
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
    windows = os.name == "nt"
    # On Windows a git.cmd or git.bat would pass the arguments through cmd.exe; run git.exe only.
    git = shutil.which("git.exe" if windows else "git")
    # Windows also searches the current directory; never run a git.exe planted there.
    if git is None or not os.path.isabs(git) or (windows and not git.lower().endswith(".exe")):
        raise GuardError(
            "git.exe not found on PATH (git.cmd, git.bat and the current directory are not used)"
            if windows
            else "Git executable not found on PATH"
        )
    # A partial clone would fetch a missing blob from its promisor remote; never go online.
    # The option makes a Git too old to know it exit with an error instead of fetching, and the
    # forced variable overrides an inherited GIT_NO_LAZY_FETCH=0.
    env = {k: v for k, v in os.environ.items() if k not in _REPOSITORY_VARIABLES}
    env["GIT_NO_LAZY_FETCH"] = "1"
    # Grafts rewrite parents (HEAD~1) and --no-replace-objects does not turn them off. An empty
    # graft file replaces the default <git dir>/info/grafts path, so that file is ignored too.
    env["GIT_GRAFT_FILE"] = os.devnull
    # Untranslated messages: the version check below matches Git's "unknown option" text.
    env["LC_ALL"] = "C"
    # --no-replace-objects: read the committed objects, not refs/replace substitutes.
    argv = [git, "--no-lazy-fetch", "--no-replace-objects", *args]
    try:
        code, out, err = _run(argv, project, limit, env)
    except OSError as exc:
        raise GuardError(f"Unable to run Git: {exc}") from exc
    # Git before 2.45 rejects --no-lazy-fetch as an unknown option before running anything.
    # 129 alone is any usage failure, so without the marker the caller's Git error is kept.
    if code == 129 and b"unknown option" in err:
        raise GuardError(f"Git 2.45 or later is required (--no-lazy-fetch){_detail(err)}")
    return code, out, err


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
