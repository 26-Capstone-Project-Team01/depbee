"""A dashboard in a container: the one folder its projects are mounted under (docs/docker.md).

A container has no desktop for the folder dialog (.picker) and sees the host's projects only
where they are mounted. DEPBEE_CONTAINER_PROJECTS, which the image sets to /projects, names the
one folder they are mounted under and makes the dashboard a container's. It then listens on
every interface of the container, at a port that is published to the host's 127.0.0.1 under the
same number (app.serve). Its "프로젝트 폴더 선택" opens the folders below that folder instead of a
dialog (listing()).

And a project there is only what the mounted folder really holds. Whenever the dashboard is
about to register, list, read, check, scan or apply something, the folder and each file it
reads must be in the mounted folder as they are spelled, with no link on the way (problem()).
That is asked each time, not once at registration: what a folder holds can change. A path
outside the mounted folder, such as one an older history kept, is refused by its spelling and
never looked at.

A scan reads HEAD's lockfile from the project's own Git folder (repository()), and Git itself
is given less than that folder: a HEAD and a config that depbee writes, and the folder's
object files once each is seen to be a file of its own (inputs.git._own_folder). The
repository's config, whatever it includes, and anything else its files name are not read. All
of this holds for a checkout that stays as it is while one request uses it: an entry that is
replaced between the look and the read is not caught.

Without the variable, as on a desktop, nothing here applies. Nothing here registers, reads or
writes a project.
"""

import os
import stat
from pathlib import Path

from .. import mcp
from ..contracts import GuardError
from ..inputs.git import is_link

VARIABLE = "DEPBEE_CONTAINER_PROJECTS"
# Every interface of the container: Docker sends the published port to its own, never to the
# container's 127.0.0.1. What reaches it from the host is decided by how the port is published.
BIND = "0.0.0.0"
PORT = 5757  # when --port names none: a container has to know its port before it is published
MAX_AT = 1024  # characters of a listed folder's path below the mounted one
MAX_FOLDERS = 200  # subfolders shown of one folder; the rest are counted


def root() -> Path | None:
    """The folder the projects are mounted under: DEPBEE_CONTAINER_PROJECTS (read on each call;
    empty means unset), None outside a container. A relative one is a GuardError, never a folder
    under wherever depbee happens to run."""
    configured = os.environ.get(VARIABLE)
    if not configured:
        return None
    if not Path(configured).is_absolute():
        raise GuardError(
            f"{VARIABLE} must be the absolute path of the folder the projects are mounted under"
        )
    return Path(configured)


def _top() -> Path | None:
    """root() with its links resolved, None when it names no folder that is there."""
    top = root()
    real = None if top is None else mcp._unlinked(top, VARIABLE)
    return real if real is not None and stat.S_ISDIR(real.stat().st_mode) else None


def problem(path: Path, kind=stat.S_ISDIR) -> str | None:
    """Why a container's dashboard may not use path as it is spelled, or None when it may:

    "outside": it is not the mounted folder or a path below it. That is told from the spelling
    alone (a relative path and one with ".." are outside), so nothing of such a path is ever
    looked at. "link": a part of it below the mounted folder is a link (symlink, junction),
    which is not read: where it leads does not matter. "missing": a part of it is not there.
    "kind": it is there but not what kind says, a folder (stat.S_ISREG: a regular file).

    Each part is looked at with lstat, which follows nothing."""
    top = _top()
    if top is None or not path.is_absolute() or ".." in path.parts or not path.is_relative_to(top):
        return "outside"
    current, mode = top, None
    for part in path.relative_to(top).parts:
        current = current / part
        try:
            mode = os.lstat(current)
        except (OSError, ValueError):  # ValueError: a name no file system holds (a NUL in it)
            return "missing"
        if is_link(mode):
            return "link"
    # Without a part the path is the mounted folder itself, which _top() found to be a folder.
    return None if kind(stat.S_IFDIR if mode is None else mode.st_mode) else "kind"


def repository(project: Path) -> Path:
    """The Git folder a scan of project reads HEAD's lockfile from: the .git of project or of
    the nearest folder above it, no further up than the mounted folder. project: a folder that
    problem() has passed.

    The scan names this folder to Git's reader (inputs.git.read_base_lock), so Git finds no
    repository of its own, neither above the mounted folder nor through a .git file, and reads
    only what that reader lets it (inputs.git._own_folder). The folder must hold its objects
    itself: a commondir file, an alternates file or a linked objects folder means another
    folder's, and a worktree's or a submodule's .git is a file that names one. Any of them is
    a GuardError before Git runs, with nothing they name looked at."""
    top = _top()
    for folder in (project, *project.parents):
        git_dir = folder / ".git"
        entry = problem(git_dir)
        if entry != "missing":
            break
        if folder == top:
            raise GuardError(
                f"Git cannot resolve HEAD to a commit in {project}: no .git folder at or above "
                "it in the mounted folder"
            )
    pointers = (git_dir / "commondir", git_dir / "objects" / "info" / "alternates")
    own = entry is None and problem(git_dir / "objects") is None
    if not own or any(problem(pointer, stat.S_ISREG) != "missing" for pointer in pointers):
        raise GuardError(
            f"The .git of {folder} is not a Git folder with its own objects (it is a link, a "
            ".git file of a worktree or submodule, or it names another folder in commondir or "
            "alternates). A container's dashboard reads Git history only from such a folder "
            "in the mounted folder: scan with depbee scan --base-lock instead"
        )
    return git_dir


def _plain(part: str) -> bool:
    """A folder name the picker links to: one name, shown as it is spelled."""
    return part not in ("", ".", "..") and "\\" not in part and part.isprintable()


def _project(folder: Path) -> bool:
    """folder holds a package-lock.json that is a file itself, not a link to one."""
    try:
        return stat.S_ISREG(os.lstat(folder / "package-lock.json").st_mode)
    except OSError:
        return False


def _listed(entry: os.DirEntry) -> bool:
    """A subfolder the picker shows: a folder itself (no link), not hidden, not node_modules."""
    name = entry.name
    return (
        _plain(name)
        and not name.startswith(".")
        and name != "node_modules"
        and entry.is_dir(follow_symlinks=False)
        and not is_link(entry.stat(follow_symlinks=False))
    )


def listing(at: str) -> dict | None:
    """The picker's view of one folder among the mounted ones. at: its path below the mounted
    folder as the picker's own links spell it, names joined with "/" ("" is the mounted folder).
    None for anything else: a name that is empty, "." or "..", a folder that is not there or
    that a link leads to, and whenever no mounted folder is there. So only the mounted folder
    and what is really inside it is ever listed.

    {at; path: the folder's absolute path, which its registration form sends; trail: (name, at)
    of each folder from below the mounted one down to this one; project: it holds a
    package-lock.json file; folders: {name, at, path, project} of its subfolders by name, at
    most MAX_FOLDERS; more: how many subfolders that leaves out}."""
    parts = at.split("/") if at else []
    if len(at) > MAX_AT or not all(map(_plain, parts)):
        return None
    try:
        top = _top()
        if top is None:
            return None
        # A name such as C: would replace top in the join on Windows: problem() sees that too.
        folder = top.joinpath(*parts)
        if problem(folder) is not None:
            return None
        with os.scandir(folder) as entries:
            names = sorted((entry.name for entry in entries if _listed(entry)), key=str.casefold)
    except (GuardError, OSError, ValueError):
        return None
    return {
        "at": at,
        "path": str(folder),
        "trail": [(part, "/".join(parts[: index + 1])) for index, part in enumerate(parts)],
        "project": _project(folder),
        "folders": [
            {
                "name": name,
                "at": "/".join([*parts, name]),
                "path": str(folder / name),
                "project": _project(folder / name),
            }
            for name in names[:MAX_FOLDERS]
        ],
        "more": max(0, len(names) - MAX_FOLDERS),
    }
