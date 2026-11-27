"""Local dashboard (`depbee dashboard`, SVC-07): registered projects, their dependencies, stored
scan and update-preview reports, and update previews and applies, on 127.0.0.1 only.

Verdicts, reasons and exit codes are shown as stored and never recomputed; the wording comes
from depbee.cli. Update previews and applies go through depbee.service (preview_files,
update_gate, apply_preview), which alone decides what may be applied. The web libraries (extra
[web]) are imported only by .app, which serve() loads.
"""

import importlib
import importlib.metadata
import importlib.util
import sys
from pathlib import Path

from ..contracts import GuardError

#: The web extra of pyproject.toml (the tests keep the two equal) by the name each is imported
#: under: what serve() tells a depbee without them to install.
WEB = {
    "starlette": "starlette>=1.10,<2",
    "jinja2": "jinja2>=3.1.6,<4",
    "uvicorn": "uvicorn>=0.54,<0.55",
}


def _recorded(name: str) -> bool:
    """Whether this Python's install records hold a distribution of that name, its module there
    or not. pip goes by that record: a plain install is then not sure to bring the module back."""
    try:
        importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return False
    return True


def _without_web(exc: ImportError) -> str:
    """What to say when .app cannot be imported. Only a web library that is the module not found
    and is neither importable nor recorded as installed gets an install command, which names
    every such library: named requirements and not ".[web]", since an installed depbee runs in
    folders that are not its checkout, where pip finds no project to take the extra from. The
    command ends the text, the cause before it, so that all that follows the lead can be typed
    as it is. Any other failure (a library that is broken, shadowed or left without its module,
    or something a library imports itself) gets the Python and the cause: installing would be a
    guess, and would hide that cause behind another library that happens to be absent."""
    absent = [
        name for name in WEB if importlib.util.find_spec(name) is None and not _recorded(name)
    ]
    if exc.name in absent:
        from ..analysis.extractor import _with_this_python

        return (
            f"depbee dashboard could not import its web libraries: {exc}. Not installed: "
            f"{', '.join(absent)}. Install into the Python that runs depbee"
            + _with_this_python(*(WEB[name] for name in absent))
        )
    why = (
        f"{exc.name} is recorded as installed there"
        if exc.name in WEB and _recorded(exc.name)
        else "what failed is not a web library missing from that Python"
    )
    return (
        "depbee dashboard could not import its web libraries with the Python that runs depbee "
        f"({sys.executable}): {exc}. No install command is suggested: {why}."
    )


def serve(
    port: int = 0, *, model_dir: Path | None = None, cache_dir: Path | None = None,
    no_cache: bool = False, known_malicious_dir: Path | None = None, background=None,
) -> None:  # fmt: skip
    """Serve the dashboard on 127.0.0.1:port (0: a free port) until interrupted.
    model_dir, cache_dir, no_cache, known_malicious_dir: for update previews, as in depbee
    update. background: the lifecycle.Instance to serve as (depbee
    dashboard --background)."""
    try:
        app = importlib.import_module(".app", __name__)
    except ImportError as exc:
        raise GuardError(_without_web(exc)) from exc
    app.serve(port, model_dir=model_dir, cache_dir=cache_dir, no_cache=no_cache,
              known_malicious_dir=known_malicious_dir, background=background)  # fmt: skip
