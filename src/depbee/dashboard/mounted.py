"""A dashboard in a container: the one folder its projects are mounted under (docs/docker.md).

A container has no desktop for the folder dialog (.picker) and sees the host's projects only
where they are mounted. DEPBEE_CONTAINER_PROJECTS, which the image sets to /projects, names the
one folder they are mounted under and makes the dashboard a container's. It then listens on
every interface of the container, at a port that is published to the host's 127.0.0.1 under the
same number (app.serve). Its "프로젝트 폴더 선택" opens the folders below that folder instead of a
dialog (listing()). And no folder outside it is registered or used as a project, however its
path was given: typed, sent in a form, behind a link or kept in the history (holds()).

Without the variable, as on a desktop, nothing here applies. Nothing here registers, reads or
writes a project.
"""

import os
import stat
from pathlib import Path

from .. import mcp
from ..contracts import GuardError

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


def holds(real: Path) -> bool:
    """real, a path whose links are resolved (mcp._unlinked), is the mounted folder or lies
    below it. Always True outside a container, where any local folder is a project's."""
    if root() is None:
        return True
    top = _top()
    return top is not None and real.is_relative_to(top)


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
        and not mcp._is_link(entry.stat(follow_symlinks=False))
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
        folder = top.joinpath(*parts)
        # The join must only have added the names: on Windows one like C: would replace top.
        if folder.parts != (*top.parts, *parts) or mcp._unlinked(folder, "folder") != folder:
            return None
        if not stat.S_ISDIR(os.lstat(folder).st_mode):
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
