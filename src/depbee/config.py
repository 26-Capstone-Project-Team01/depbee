"""User settings (`depbee setup`): the trusted model and known malicious index folders.

One JSON file, config.json, in the user's depbee settings folder (user_dir()): a folder of the
user's home, or the absolute folder the user named in DEPBEE_CONFIG_DIR. It is never the current
folder, a project being checked or the folder of the history file, so nothing a project holds
can pass for the user's settings. The service reads the file once for each request, after an
explicit option and after DEPBEE_MODEL_DIR and DEPBEE_KNOWN_MALICIOUS_DIR, so that one
`depbee setup <folder>` replaces the two paths in every later command and MCP registration.
Nothing is downloaded and nothing is searched for: only the folder the user named is saved.

The folder is the user's alone when depbee creates it (make_dir()). One that already exists is
used as it is, and open_to_others() tells whether other accounts can open it.
"""

import contextlib
import json
import os
import re
import tempfile
import time
from pathlib import Path

from .contracts import GuardError, parse_json

FILE = "config.json"
# The subfolder of the folder given to `depbee setup` that each setting comes from.
LAYOUT = {"model_dir": "model", "known_malicious_dir": "index"}
MAX_BYTES = 64 * 1024
REPLACE_TRIES = 20  # times write_atomic() tries its os.replace(), 0.05 s apart
# An access list entry (SDDL) that allows a group which is not one account: Everyone,
# Authenticated Users, Users, Guests, Interactive, Anonymous, Network, Domain Users and Guests.
_GROUP_ENTRY = re.compile(r"\(A;[^;()]*;[^;()]*;[^;()]*;[^;()]*;(?:WD|AU|BU|BG|IU|AN|NU|DU|DG)\)")


def user_dir() -> Path:
    """The user's depbee settings folder, for config.json and the background dashboard's files:
    DEPBEE_CONFIG_DIR (read on each call; empty means unset), else ~/.config/depbee.

    Both must be absolute: a relative DEPBEE_CONFIG_DIR is a GuardError, never a folder under
    wherever depbee happens to run, and a home that is not absolute counts as no home
    (RuntimeError, as from Path.home()). DEPBEE_HISTORY_DB does not move this folder: that
    variable may be relative, and its folder may be a project's.
    """
    configured = os.environ.get("DEPBEE_CONFIG_DIR")
    if configured:
        if not Path(configured).is_absolute():
            raise GuardError(
                "DEPBEE_CONFIG_DIR must be the absolute path of a folder of yours, not a "
                "relative one"
            )
        return Path(configured)
    home = Path.home()
    if not home.is_absolute():
        raise RuntimeError("The home folder is not an absolute path")
    return home / ".config" / "depbee"


def _elevated() -> bool:
    """A Windows process run as administrator: what it creates is owned by Administrators."""
    if os.name != "nt":
        return False
    import ctypes

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def make_dir(folder: Path) -> None:
    """Create the settings folder if it is missing, for this user alone: mode 0700. On Windows,
    Python 3.12.4 and later turn that mode into an access list of the folder's owner, SYSTEM
    and Administrators, which the files in it inherit; an older Python ignores it there. A
    folder that exists keeps the access its owner gave it (open_to_others()).

    Not in an elevated Windows process: its folder would be owned by the Administrators group,
    and a list for the owner alone could then shut the same user out of it in an ordinary
    terminal. There the new folder gets the access list of the folder it is in, as before."""
    folder.mkdir(mode=0o777 if _elevated() else 0o700, parents=True, exist_ok=True)


def _access_list(folder: Path) -> str:
    """The folder's Windows access list (DACL) as SDDL text; OSError if it cannot be read."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
    )  # fmt: skip
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = (
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    )  # fmt: skip
    descriptor, text = ctypes.c_void_p(), ctypes.c_void_p()
    # 1: SE_FILE_OBJECT; 4: DACL_SECURITY_INFORMATION; 1: SDDL_REVISION_1.
    error = advapi32.GetNamedSecurityInfoW(
        str(folder), 1, 4, None, None, None, None, ctypes.byref(descriptor)
    )
    if error:
        raise ctypes.WinError(error)
    try:
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, 1, 4, ctypes.byref(text), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(text.value)
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.LocalFree(descriptor)


def open_to_others(folder: Path) -> bool:
    """Other accounts of this computer can open what depbee keeps in folder: on Windows, where a
    file gets the access list of its folder, that list allows a group that is not one account
    (Everyone, Users, Authenticated Users, ...). False if that cannot be told (no such folder,
    a list that cannot be read) and on other systems, where depbee creates its files for the
    user alone (mode 0600) whatever the folder allows."""
    if os.name != "nt":
        return False
    try:
        return _GROUP_ENTRY.search(_access_list(folder)) is not None
    except OSError:
        return False


def write_atomic(target: Path, text: str) -> None:
    """Write text to target, a file of the settings folder, through a temporary file in that
    folder and os.replace(), so a reader sees the old file or the new one, never a part of one.
    The folder is created for the user alone if it is missing (make_dir()), and the file is the
    user's alone where the system has file modes (0600). Windows refuses the replace while
    another process has the old file open, as a reader has for an instant, so it is tried again
    for about a second."""
    make_dir(target.parent)
    handle, temporary = tempfile.mkstemp(
        dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        for attempt in range(REPLACE_TRIES):
            try:
                os.replace(temporary, target)
                return
            except PermissionError:
                if attempt == REPLACE_TRIES - 1:
                    raise
                time.sleep(0.05)
    finally:
        with contextlib.suppress(OSError):  # gone once replaced
            os.unlink(temporary)


def path() -> Path:
    return user_dir() / FILE


def load() -> dict | None:
    """The saved settings {assets_dir, model_dir, known_malicious_dir}, or None if nothing was
    saved (or the user has no home folder). A file that cannot be read or is not what save()
    writes is a GuardError, as is a relative DEPBEE_CONFIG_DIR: broken settings never count as
    no settings, which would drop the model or the known malicious check without a word."""
    try:
        file = path()
    except RuntimeError:
        return None
    try:
        with file.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise GuardError(f"depbee settings cannot be read ({type(exc).__name__}): {file}") from exc
    invalid = f"depbee settings are not valid, run depbee setup again: {file}"
    if len(raw) > MAX_BYTES:
        raise GuardError(invalid)
    try:
        settings, _ = parse_json(raw, file)
    except GuardError as exc:
        raise GuardError(invalid) from exc
    for key in LAYOUT:
        # Absolute only: a relative folder would be looked up in the project being checked.
        value = settings.get(key, "")
        if value is not None and not (isinstance(value, str) and Path(value).is_absolute()):
            raise GuardError(invalid)
    return settings


def save(assets_dir: Path, model_dir: Path | None, known_malicious_dir: Path | None) -> dict:
    """Replace the settings with these folders (None: not connected) and return them with the
    file's path. The caller has checked what the folders hold (service.setup_assets)."""
    settings = {
        "assets_dir": os.path.abspath(assets_dir),
        "model_dir": model_dir and os.path.abspath(model_dir),
        "known_malicious_dir": known_malicious_dir and os.path.abspath(known_malicious_dir),
    }
    try:
        file = path()
        write_atomic(file, json.dumps(settings, ensure_ascii=True, indent=2) + "\n")
    except (RuntimeError, OSError) as exc:
        raise GuardError(
            f"depbee settings cannot be saved ({type(exc).__name__}); without a home folder, "
            "set DEPBEE_CONFIG_DIR to the absolute path of a folder of yours"
        ) from exc
    return {**settings, "path": str(file)}


def clear() -> bool:
    """Remove the saved settings; False if there were none."""
    try:
        path().unlink()
    except (FileNotFoundError, RuntimeError):
        return False
    except OSError as exc:
        raise GuardError(f"depbee settings cannot be removed ({type(exc).__name__})") from exc
    return True
