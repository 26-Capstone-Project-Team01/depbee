"""The folder dialog behind the dashboard's "프로젝트 폴더 선택" button.

A browser never tells a server the absolute path of a local folder (a file input uploads names
and contents), so the desktop's own folder dialog is opened instead: by tkinter, in a child
process that lives for that one question. choose() starts the child and reads its answer; this
file, run as a script, is the child.

The child gets nothing from the server: no arguments, no input and no module path. It runs as a
file under -I -B and imports the standard library only, so neither the session nor a project
folder's code reaches it, and it writes nothing but its answer, into a pipe: one line of ASCII
JSON, {"folder": the absolute path, or null when the dialog was closed without a choice}. That
path is an input like a typed one: the caller checks it as it checks those. Nothing here
registers, reads or writes a project. Standard library only.
"""

import json
import os
import subprocess
import sys
import time

PICK_SECONDS = 90  # how long the dialog may stay open; then the child is killed
POLL_SECONDS = 0.1  # how often choose() asks stopping() while the dialog is open
MAX_ANSWER = 64 * 1024  # bytes of an answer; a path the dashboard registers is far shorter
TITLE = "depbee에 등록할 프로젝트 폴더 선택"
_SCRIPT = os.path.abspath(__file__)


def choose(stopping=lambda: False) -> tuple[str, str | None]:
    """Ask the user for one folder: ("chosen", its absolute path), ("cancelled", None) when the
    dialog was closed without a choice, ("timeout", None) when it was still open after
    PICK_SECONDS, ("stopped", None) when stopping() said that the caller is ending, or
    ("unavailable", None) when no dialog could be shown (no desktop session, a Python without
    tkinter, any other failure of the child).

    Blocks until then, so it belongs in a worker thread. stopping is asked before the child is
    started, which then never is, and every POLL_SECONDS while the dialog is open, which is
    then closed. Only this call ever touches the child, and the child is gone when this returns:
    killed if it was still there, and waited for. It runs in the user's home folder: where a
    dialog without a memory of its own opens, and not the server's current folder, which may be
    a project under inspection."""
    if stopping():
        return "stopped", None
    try:
        process = subprocess.Popen(
            [sys.executable, "-I", "-B", _SCRIPT],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            cwd=os.path.expanduser("~"),
        )  # fmt: skip
    except OSError:
        return "unavailable", None
    deadline = time.monotonic() + PICK_SECONDS
    try:
        while True:
            try:
                answer, _ = process.communicate(timeout=POLL_SECONDS)
                break
            except subprocess.TimeoutExpired:  # still open; a later call loses no output
                if stopping():
                    return "stopped", None
                if time.monotonic() >= deadline:
                    return "timeout", None
    finally:
        if process.poll() is None:  # stopped, out of time or interrupted: close the dialog
            process.kill()
            process.communicate()  # returns once the child has exited and its pipe is closed
    if process.returncode != 0 or len(answer) > MAX_ANSWER:
        return "unavailable", None
    try:
        folder = json.loads(answer)["folder"]
    except (ValueError, LookupError, TypeError):
        return "unavailable", None
    if folder is None:
        return "cancelled", None
    return ("chosen", folder) if isinstance(folder, str) else ("unavailable", None)


def _unseen() -> bool:
    """Windows: this process has no desktop the user sees (a service, an SSH session), where the
    dialog would wait unseen until the time limit. False when that cannot be told, and
    elsewhere, where Tk itself fails without a display."""
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes

    class Flags(ctypes.Structure):  # USEROBJECTFLAGS
        _fields_ = [("inherit", wintypes.BOOL), ("reserved", wintypes.BOOL),
                    ("flags", wintypes.DWORD)]  # fmt: skip

    user32 = ctypes.WinDLL("user32")
    user32.GetProcessWindowStation.restype = wintypes.HANDLE
    user32.GetUserObjectInformationW.argtypes = (
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, wintypes.LPDWORD,
    )  # fmt: skip
    flags = Flags()
    told = user32.GetUserObjectInformationW(
        user32.GetProcessWindowStation(), 1, ctypes.byref(flags), ctypes.sizeof(flags), None
    )  # 1: UOI_FLAGS
    return bool(told) and not flags.flags & 1  # 1: WSF_VISIBLE


def _child() -> None:
    """The child process: the dialog, then its answer on stdout. Without tkinter or a display
    the import or Tk() raises; that nonzero exit is choose()'s "unavailable"."""
    if _unseen():
        raise SystemExit(1)
    import tkinter
    from tkinter import filedialog

    root = tkinter.Tk()
    root.withdraw()  # no window of its own: only the dialog
    # The server is not the program in front, so the dialog would open behind the browser.
    root.attributes("-topmost", True)
    root.update()
    folder = filedialog.askdirectory(parent=root, title=TITLE, mustexist=True)
    root.destroy()
    answer = {"folder": os.path.abspath(folder) if folder else None}
    sys.stdout.write(json.dumps(answer, ensure_ascii=True))


if __name__ == "__main__":
    _child()
