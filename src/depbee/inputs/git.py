"""Read the base package-lock.json from a Git commit with fixed, read-only plumbing commands.

Nothing is fetched, and the working tree, index and branches are left untouched.

Left to itself, Git finds the repository as in a terminal and reads what that repository's
files tell it to: its config and the files that includes, its refs, its object store and any
other store it points to. A caller that may use one folder only (a dashboard in a container,
dashboard.mounted) names the Git folder instead, and Git is kept from all of that
(_own_folder). It then runs in a folder depbee makes, on depbee's config, a HEAD and at most a
copy of packed-refs that depbee read from files of the chosen folder itself, and on the chosen
folder's object files, each of which was first seen to be a file of that folder.
"""

import contextlib
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from ..contracts import MAX_JSON_BYTES, GuardError

TIMEOUT_SECONDS = 30
_LINE_LIMIT = 4096  # rev-parse prints one commit id
_STDERR_LIMIT = 4096
_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# A chosen Git folder (_own_folder). Past a limit nothing is read: the scan is refused, with
# the limit as its reason.
MAX_OBJECT_ENTRIES = 200_000  # files and folders in its objects folder; git gc leaves a few
MAX_REF_BYTES = 4096  # HEAD or a loose ref: a commit id, or "ref: " and a ref's name
MAX_PACKED_REFS_BYTES = 64 * 1024 * 1024  # packed-refs, copied whole when HEAD's ref is in it
SYMREF_DEPTH = 5  # symbolic refs followed from HEAD, as Git follows them (SYMREF_MAXDEPTH)
# All the configuration Git gets in place of the chosen folder's own: SHA-1, refs in files. The
# commit-graph and the multi-pack-index are left unread: each is a file among the objects that
# lists the names of further files to open, and Git finds every object without them.
_OWN_CONFIG = (
    b"[core]\n\trepositoryformatversion = 0\n\tbare = true\n"
    b"\tcommitGraph = false\n\tmultiPackIndex = false\n"
)
_OWN_OID = re.compile(rb"([0-9a-fA-F]{40})\s*")
# Characters no part of a ref name has (git check-ref-format), the path separators among them.
_REF_FORBIDDEN = re.compile(r"[\x00-\x20\x7f~^:?*\[\\]")
# Windows reparse tag bit of tags that name another path (IsReparseTagNameSurrogate).
NAME_SURROGATE = 0x20000000
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


def is_link(mode: os.stat_result) -> bool:
    """An os.lstat result of a symlink, or on Windows of a name-surrogate reparse point (symlink,
    junction): an entry that names another path. Other reparse points (such as Cloud Files
    placeholders) are plain files and folders here."""
    return stat.S_ISLNK(mode.st_mode) or bool(
        (getattr(mode, "st_reparse_tag", 0) or 0) & NAME_SURROGATE
    )


def _git(
    folder: Path, *args: str, limit: int = _LINE_LIMIT, objects: Path | None = None
) -> tuple[int, bytes, bytes]:
    """Run Git in folder with the fixed options. objects: folder is a Git folder depbee made
    (_own_folder), and Git is to read it alone, with the objects of this other folder."""
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
    if objects is not None:
        # Set, these end Git's own search (parent folders, a .git file, commondir): its config,
        # HEAD and refs are the ones in folder, and only the objects come from elsewhere.
        env["GIT_DIR"] = env["GIT_COMMON_DIR"] = str(folder)
        env["GIT_OBJECT_DIRECTORY"] = str(objects)
        # The config in folder is then the only config file: not the machine's or the user's.
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_NO_LAZY_FETCH"] = "1"
    # Grafts rewrite parents (HEAD~1) and --no-replace-objects does not turn them off. An empty
    # graft file replaces the default <git dir>/info/grafts path, so that file is ignored too.
    env["GIT_GRAFT_FILE"] = os.devnull
    # Untranslated messages: the version check below matches Git's "unknown option" text.
    env["LC_ALL"] = "C"
    # --no-replace-objects: read the committed objects, not refs/replace substitutes.
    argv = [git, "--no-lazy-fetch", "--no-replace-objects", *args]
    try:
        code, out, err = _run(argv, folder, limit, env)
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


def _refusal(git_dir: Path, why: str) -> GuardError:
    """The error of a chosen Git folder that Git is not run on (_own_folder), with the way on."""
    return GuardError(
        f"The Git history of {git_dir.parent} is not read: {why}. Git is given only HEAD and "
        "the object files that this Git folder holds itself; scan with depbee scan --base-lock "
        "instead"
    )


def _own_file(git_dir: Path, name: str, limit: int) -> bytes | None:
    """The bytes of the file name (parts joined with "/") of git_dir, or None when it, or a
    folder on the way to it, is not there. Each part is looked at with lstat and must be a
    folder, and the last a regular file, of git_dir itself: a link or anything else that is
    there is a GuardError, as is a file of more than limit bytes. Any other failure to look or
    to read is its OSError: only what is really not there counts as not there."""
    current, parts = git_dir, name.split("/")
    for index, part in enumerate(parts):
        current = current / part
        try:
            mode = os.lstat(current)
        except (FileNotFoundError, NotADirectoryError):
            return None
        kind = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
        if is_link(mode) or not kind(mode.st_mode):
            raise _refusal(git_dir, f"{name} is a link or is no file of this Git folder")
    if mode.st_size > limit:
        raise _refusal(git_dir, f"{name} is larger than {limit} bytes")
    with open(current, "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise _refusal(git_dir, f"{name} is larger than {limit} bytes")
    return data


def _ref_name(text: str) -> bool:
    """text is a ref below refs/ as git check-ref-format takes one, so each part is a plain
    name: never "..", an empty part or a separator, and never the .invalid stub of a reftable
    repository."""
    parts = text.split("/")
    return parts[0] == "refs" and len(parts) > 1 and "@{" not in text and all(
        part and not part.startswith(".") and not part.endswith((".", ".lock"))
        and ".." not in part and not _REF_FORBIDDEN.search(part)
        for part in parts
    )  # fmt: skip


def _own_head(git_dir: Path) -> tuple[bytes, bool]:
    """What a HEAD file is to say for git_dir, read from files of git_dir itself, and whether
    packed-refs goes with it: the commit id that HEAD, or the loose ref it names, holds; else
    the name of the ref that no loose file holds, which Git then finds in packed-refs or not
    at all (an unborn branch)."""
    name = "HEAD"
    for _ in range(SYMREF_DEPTH + 1):
        content = _own_file(git_dir, name, MAX_REF_BYTES)
        if content is None:
            if name == "HEAD":
                raise _refusal(git_dir, "it has no HEAD")
            return f"ref: {name}\n".encode(), True
        commit = _OWN_OID.fullmatch(content)
        if commit:
            return commit[1].lower() + b"\n", False
        try:
            target = content[4:].strip().decode() if content.startswith(b"ref:") else ""
        except UnicodeDecodeError:
            target = ""
        if not _ref_name(target):
            raise _refusal(
                git_dir, f"{name} holds neither a SHA-1 commit id nor the name of a ref below refs/"
            )
        name = target
    raise _refusal(git_dir, f"HEAD leads through more than {SYMREF_DEPTH} symbolic refs")


def _own_objects(git_dir: Path) -> Path:
    """The objects folder of git_dir, once everything in it is seen to be a folder or a regular
    file of its own. Git opens these by name (a loose object, a pack, the pack folder itself),
    so a link among them would be another store's, and info/alternates names other stores
    outright: either is a GuardError, as is a FIFO or a device, and as are more than
    MAX_OBJECT_ENTRIES entries.

    The kind of an entry is the directory's own answer (os.scandir), not an lstat of each one:
    through a Docker Desktop bind mount 20,000 entries took 0.6 s this way and 17 s with
    lstat."""
    objects = git_dir / "objects"
    try:
        mode = os.lstat(objects)
    except (FileNotFoundError, NotADirectoryError):
        raise _refusal(git_dir, "it has no objects folder") from None
    if is_link(mode) or not stat.S_ISDIR(mode.st_mode):
        raise _refusal(git_dir, "objects is a link or is no folder of this Git folder")
    # Asked of the file system by the name Git uses, not looked for in a listing: a folder that
    # takes Info/Alternates for the same name (a Windows or macOS disk) then answers as to Git.
    try:
        os.lstat(objects / "info" / "alternates")
    except (FileNotFoundError, NotADirectoryError):
        pass
    else:
        raise _refusal(git_dir, "objects/info/alternates names another object store")
    count, pending = 0, [str(objects)]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                count += 1
                if count > MAX_OBJECT_ENTRIES:
                    raise _refusal(
                        git_dir, f"its objects folder holds more than {MAX_OBJECT_ENTRIES} files "
                        "and folders (git gc in the repository packs them)",
                    )  # fmt: skip
                # Windows: a junction is no symlink to the entry, but its reparse tag is there.
                link = entry.is_symlink() or (
                    os.name == "nt" and is_link(entry.stat(follow_symlinks=False))
                )
                inner = not link and entry.is_dir(follow_symlinks=False)
                if link or not (inner or entry.is_file(follow_symlinks=False)):
                    where = Path(entry.path).relative_to(git_dir).as_posix()
                    raise _refusal(git_dir, f"{where} is a link or is no file")
                if inner:
                    pending.append(entry.path)
    return objects


@contextlib.contextmanager
def _own_folder(git_dir: Path):
    """(a Git folder made for one read of HEAD, the objects folder to read with it) for git_dir,
    a .git folder that the caller has chosen and found to be a folder it may use.

    Git opens nothing of git_dir but its objects folder. Its HEAD comes from _own_head(), its
    packed-refs, when the ref is not a loose file, is a copy of the one in git_dir, and its
    config is _OWN_CONFIG: the config of git_dir, and whatever that includes, is not read by
    anyone. The objects stay where they are and are read once _own_objects() has passed them.
    So Git reads the folder made here and the object files of git_dir, and nothing that a file
    of git_dir names.

    What Git then cannot do is refused before it runs (GuardError): SHA-256 objects and
    reftable refs, HEAD or a ref that is a link, objects shared through alternates, and an
    objects folder or a packed-refs past the limits above. The folder is removed afterwards."""
    try:
        head, packed = _own_head(git_dir)
        refs = _own_file(git_dir, "packed-refs", MAX_PACKED_REFS_BYTES) if packed else None
        objects = _own_objects(git_dir)
    except OSError as exc:  # not "not there": something could not be looked at or read
        raise _refusal(git_dir, f"it could not be looked at ({type(exc).__name__})") from None
    try:
        folder = tempfile.TemporaryDirectory(prefix="depbee_git_")
    except OSError as exc:  # its message would name the folder
        raise GuardError(
            f"The temporary Git folder could not be created ({type(exc).__name__})"
        ) from None
    with folder as made:
        own = Path(made)
        (own / "refs").mkdir()
        (own / "config").write_bytes(_OWN_CONFIG)
        (own / "HEAD").write_bytes(head)
        if refs is not None:
            (own / "packed-refs").write_bytes(refs)
        yield own, objects


def read_base_lock(project: Path, ref: str, git_dir: Path | None = None) -> bytes:
    """Raw bytes of project/package-lock.json as committed in ref (any commit-ish).

    git_dir: the .git folder of project or of a folder above it, which the caller has chosen
    and found to be a folder it may use. Only HEAD is read then, and Git reads neither that
    folder's config nor anything its files name (_own_folder); the file is named by its path
    from the folder git_dir is in. None: Git finds the repository from project, as git does in
    a terminal."""
    if not ref or ref.startswith("-"):
        raise GuardError(f"Invalid Git ref: {ref!r}")
    if git_dir is None:
        # Git resolves ./ against cwd (the project) into the path from the repository root.
        return _read_lock(project, ref, project, "./package-lock.json", None)
    if ref != "HEAD":
        raise GuardError(f"Only HEAD is read from a chosen Git folder, not {ref!r}")
    lock = (project.relative_to(git_dir.parent) / "package-lock.json").as_posix()
    with _own_folder(git_dir) as (folder, objects):
        return _read_lock(project, ref, folder, lock, objects)


def _read_lock(project: Path, ref: str, folder: Path, lock: str, objects: Path | None) -> bytes:
    """read_base_lock()'s two Git commands, run in folder (_git): the commit of ref, then the
    blob at lock in that commit. project only names the project in an error."""
    code, out, err = _git(
        folder, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}",
        objects=objects,
    )  # fmt: skip
    commit = out.decode("ascii", "replace").strip()
    if code or not _COMMIT.fullmatch(commit):
        raise GuardError(f"Git cannot resolve {ref} to a commit in {project}{_detail(err)}")
    code, out, err = _git(
        folder, "cat-file", "blob", f"{commit}:{lock}", limit=MAX_JSON_BYTES, objects=objects
    )
    if code:
        raise GuardError(f"No package-lock.json for {project} in Git ref {ref}{_detail(err)}")
    return out
