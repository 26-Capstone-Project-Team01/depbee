"""Read the base package-lock.json from a Git commit with fixed, read-only plumbing commands.

Nothing is fetched, and the working tree, index and branches are left untouched.
"""

import os
import re
import shutil
import signal
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


STOP_SECONDS = 10  # how long _ProcessTree.close() waits for killed processes to end
_CREATE_SUSPENDED = 0x00000004  # Windows process creation flag
_KILL_ON_JOB_CLOSE = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
_EXTENDED_LIMITS = 9  # JobObjectExtendedLimitInformation

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    # winnt.h layouts; ctypes aligns the fields as the C compiler does, so sizeof() is 144 on
    # 64-bit and 112 on 32-bit Windows (tests check it; only 64-bit has been run).
    class _BasicLimits(ctypes.Structure):  # JOBOBJECT_BASIC_LIMIT_INFORMATION
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),  # LARGE_INTEGER
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),  # ULONG_PTR
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _ExtendedLimits(ctypes.Structure):  # JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        _fields_ = [
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", ctypes.c_uint64 * 6),  # IO_COUNTERS: six ULONGLONG counters
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]


class _ProcessTree:
    """A child and every process it starts, killed together.

    Windows: the child starts suspended (CREATE_SUSPENDED), joins a Job Object and only then
    runs, so every process it starts is in the job too; a fast native wrapper such as a venv
    python.exe would otherwise start its child first. The job kills them all when its last
    handle closes (KILL_ON_JOB_CLOSE), so also when depbee itself is killed. POSIX: the child
    leads a new session (start_new_session) and its process group is killed; a process that
    starts its own session leaves the group.
    """

    def __init__(self, proc: subprocess.Popen) -> None:
        self.proc = proc
        self.job = None
        self.lock = threading.Lock()  # a reader thread may kill while close() frees the job
        if os.name != "nt":
            return
        self.kernel32 = k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateJobObjectW.restype = wintypes.HANDLE
        k.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        k.OpenProcess.restype = wintypes.HANDLE
        k.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        k.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        k.SetInformationJobObject.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        )  # fmt: skip
        k.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        k.QueryInformationJobObject.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
        )  # fmt: skip
        k.CloseHandle.argtypes = (wintypes.HANDLE,)
        # NtResumeProcess resumes every thread of a process. It is an undocumented ntdll export;
        # psutil's Process.resume() calls it too (psutil/arch/windows/proc.c). Popen does not
        # return the thread handle that the documented ResumeThread would need. Checked on
        # 64-bit Windows 11 only.
        resume = ctypes.WinDLL("ntdll").NtResumeProcess
        resume.argtypes = (wintypes.HANDLE,)
        resume.restype = ctypes.c_long
        job = k.CreateJobObjectW(None, None)
        if not job:
            raise GuardError("Unable to create a Windows job for the child processes")
        self.job = job
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = _KILL_ON_JOB_CLOSE
        size = ctypes.sizeof(limits)
        if not k.SetInformationJobObject(job, _EXTENDED_LIMITS, ctypes.byref(limits), size):
            k.CloseHandle(job)
            self.job = None
            raise GuardError("Unable to set up a Windows job for the child processes")
        # PROCESS_TERMINATE | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME.
        handle = k.OpenProcess(0x0001 | 0x0100 | 0x0800, False, proc.pid)
        started = bool(handle) and k.AssignProcessToJobObject(job, handle) and resume(handle) == 0
        if handle:
            k.CloseHandle(handle)
        if not started:
            k.CloseHandle(job)
            self.job = None
            raise GuardError("Unable to start the child process in a Windows job")

    def kill(self) -> None:
        with self.lock:
            if self.job:
                self.kernel32.TerminateJobObject(self.job, 1)
                return
        if os.name == "nt":
            self.proc.kill()
        else:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def alive(self) -> bool:
        if self.job:
            # JOBOBJECT_BASIC_ACCOUNTING_INFORMATION (class 1): four 8-byte times, then four
            # 4-byte counts; ActiveProcesses is the third count, bytes 40 to 43.
            info = (ctypes.c_uint8 * 48)()
            if not self.kernel32.QueryInformationJobObject(self.job, 1, info, 48, None):
                return True
            return int.from_bytes(bytes(info[40:44]), "little") > 0
        if os.name == "nt":
            return self.proc.poll() is None
        try:
            os.killpg(self.proc.pid, 0)
        except ProcessLookupError:
            return False
        return True

    def close(self, name: str) -> None:
        """Kill every process left, wait until none runs, or raise GuardError."""
        try:
            self.kill()
            deadline = time.monotonic() + STOP_SECONDS
            try:
                self.proc.wait(STOP_SECONDS)
            except subprocess.TimeoutExpired:
                pass
            while self.alive():
                if time.monotonic() > deadline:
                    self.proc.kill()
                    raise GuardError(f"{name} processes did not stop after being killed")
                time.sleep(0.05)
        finally:
            with self.lock:
                if self.job:
                    self.kernel32.CloseHandle(self.job)
                    self.job = None


def _run(
    argv: list[str],
    cwd: Path,
    limit: int,
    env: dict[str, str] | None = None,
    *,
    timeout: float | None = None,
    stderr_limit: int = _STDERR_LIMIT,
    name: str = "Git",
    tree: bool = False,
) -> tuple[int, bytes, bytes]:
    """Run argv without a shell and return (returncode, stdout, stderr).

    The child is killed at timeout seconds (default TIMEOUT_SECONDS), or as soon as stdout passes
    limit bytes or stderr passes stderr_limit bytes, so memory does not depend on what it prints.
    name labels the program in errors. Without tree only the direct child is killed: processes
    it started keep running, and closing the pipes waits for them. On Windows the default
    Git\\cmd\\git.exe is such a wrapper, so a timeout can take until the real Git ends. With tree
    every process the child started is killed too, also after a normal exit, and _run returns
    only once none of them runs (GuardError if they do not stop).
    """
    if timeout is None:
        timeout = TIMEOUT_SECONDS
    caps = {"stdout": limit, "stderr": stderr_limit}
    captured: dict[str, bytes] = {}
    with subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=tree and os.name != "nt",
        creationflags=_CREATE_SUSPENDED if tree and os.name == "nt" else 0,
    ) as proc:
        try:
            group = _ProcessTree(proc) if tree else None
        except BaseException:
            proc.kill()
            raise
        kill = group.kill if group else proc.kill

        def drain(name: str) -> None:
            captured[name] = getattr(proc, name).read(caps[name] + 1)
            if len(captured[name]) > caps[name]:
                kill()

        # One reader per pipe, so a child filling one pipe cannot block the other.
        readers = [threading.Thread(target=drain, args=(name,), daemon=True) for name in caps]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + timeout
        try:
            for reader in readers:
                reader.join(max(0.0, deadline - time.monotonic()))
            if any(reader.is_alive() for reader in readers):
                raise subprocess.TimeoutExpired(argv, timeout)
            proc.wait(max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise GuardError(f"{name} did not finish within {timeout} seconds") from exc
        finally:
            # Popen's exit then closes the pipes and reaps the child.
            if group is not None:
                group.close(name)
            elif proc.poll() is None:
                proc.kill()
    if any(len(captured[name]) > cap for name, cap in caps.items()):
        raise GuardError(f"{name} output exceeds {limit} bytes (stderr {stderr_limit})")
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
