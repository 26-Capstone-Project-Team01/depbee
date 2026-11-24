"""The dashboard's theme as the user chose it on the rail (docs/dashboard-design.md): the system's,
light or dark. Saved in the user's settings folder (config.user_dir()), not in the browser: the
dashboard takes a free port at each start, and a browser keeps what a page stores for one port
only. A file of its own, beside config.json, so that a broken one never touches the settings the
service reads. Whatever cannot be read is the system's theme."""

import json

from .. import config
from ..contracts import GuardError

THEMES = ("system", "light", "dark")
FILE = "dashboard.json"
MAX_BYTES = 4096


def next_of(value: str) -> str:
    """The theme one press of the rail's button moves to: system, light, dark, then system."""
    return THEMES[(THEMES.index(value) + 1) % len(THEMES)]


def load() -> str:
    """The saved theme; "system" when nothing is saved or the file cannot be used."""
    try:
        path = config.user_dir() / FILE
        if path.stat().st_size > MAX_BYTES:
            return "system"
        value = json.loads(path.read_text("utf-8")).get("theme")
    except (OSError, ValueError, AttributeError, GuardError, RuntimeError):
        return "system"
    return value if value in THEMES else "system"


def save(value: str) -> None:
    """Save the theme. ValueError for one that is not a theme; OSError, GuardError or
    RuntimeError (no home) when the settings folder cannot be written."""
    if value not in THEMES:
        raise ValueError(value)
    config.write_atomic(config.user_dir() / FILE, json.dumps({"theme": value}) + "\n")
