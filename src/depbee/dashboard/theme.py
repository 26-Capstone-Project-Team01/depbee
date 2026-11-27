"""The dashboard's theme as the user chose it on the rail (docs/dashboard-design.md): the system's,
light or dark. Saved in the user's settings folder (config.user_dir()), not in the browser: a
page is drawn with it from the start, without a script, and a browser keeps what a page stores
for one port only, so a dashboard started on another port (--port) would not have it. A file of
its own, beside config.json and the background dashboard's files (lifecycle:
dashboard.json, .lock and .log), so that a broken one never touches what the service or the
background dashboard reads. Whatever cannot be read is the system's theme, and reading never
waits: a page is drawn with it."""

import json
import os
import stat

from .. import config
from ..contracts import GuardError

THEMES = ("system", "light", "dark")
FILE = "dashboard-theme.json"
MAX_BYTES = 4096


def next_of(value: str) -> str:
    """The theme one press of the rail's button moves to: system, light, dark, then system."""
    return THEMES[(THEMES.index(value) + 1) % len(THEMES)]


def load() -> str:
    """The saved theme; "system" when nothing is saved or the file cannot be used. The file is
    opened without waiting (a pipe in its place has no writer to wait for), must be a regular
    file once open, and at most MAX_BYTES of it are read."""
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        handle = os.open(config.user_dir() / FILE, flags)
        try:
            if not stat.S_ISREG(os.fstat(handle).st_mode):
                return "system"
            data = os.read(handle, MAX_BYTES + 1)
        finally:
            os.close(handle)
        if len(data) > MAX_BYTES:
            return "system"
        value = json.loads(data.decode("utf-8")).get("theme")
    except (OSError, ValueError, AttributeError, GuardError, RuntimeError):
        return "system"
    return value if value in THEMES else "system"


def save(value: str) -> None:
    """Save the theme. ValueError for one that is not a theme; OSError, GuardError or
    RuntimeError (no home) when the settings folder cannot be written."""
    if value not in THEMES:
        raise ValueError(value)
    config.write_atomic(config.user_dir() / FILE, json.dumps({"theme": value}) + "\n")
