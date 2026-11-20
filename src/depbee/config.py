"""User settings (`depbee setup`): the trusted model and known malicious index folders.

One JSON file, config.json, in the user's depbee settings folder (user_dir()): a folder of the
user's home, or the absolute folder the user named in DEPBEE_CONFIG_DIR. It is never the current
folder, a project being checked or the folder of the history file, so nothing a project holds
can pass for the user's settings. The service reads the file on each call, after an explicit
option and after DEPBEE_MODEL_DIR and DEPBEE_KNOWN_MALICIOUS_DIR, so that one
`depbee setup <folder>` replaces the two paths in every later command and MCP registration.
Nothing is downloaded and nothing is searched for: only the folder the user named is saved.
"""

import contextlib
import json
import os
import tempfile
import time
from pathlib import Path

from .contracts import GuardError, parse_json

FILE = "config.json"
# The subfolder of the folder given to `depbee setup` that each setting comes from.
LAYOUT = {"model_dir": "model", "known_malicious_dir": "index"}
MAX_BYTES = 64 * 1024
REPLACE_TRIES = 20  # times write_atomic() tries its os.replace(), 0.05 s apart


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


def write_atomic(target: Path, text: str) -> None:
    """Write text to target through a temporary file in its folder and os.replace(), so a reader
    sees the old file or the new one, never a part of one. The file is the user's alone where
    the system has file modes (0600). Windows refuses the replace while another process has the
    old file open, as a reader has for an instant, so it is tried again for about a second."""
    target.parent.mkdir(parents=True, exist_ok=True)
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


def saved_dir(key: str) -> Path | None:
    """The folder saved for key (a LAYOUT key), or None if none is."""
    settings = load()
    return Path(settings[key]) if settings and settings[key] else None


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
