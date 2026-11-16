"""Local history dashboard (`depbee dashboard`, SVC-07): registered projects, their dependencies
and stored scan and update-preview reports, on 127.0.0.1 only.

Read-only except registering a project. Verdicts, reasons and exit codes are shown as stored and
never recomputed; the wording comes from depbee.cli. The web libraries (extra [web]) are imported
only by .app, which serve() loads.
"""

import importlib

from ..contracts import GuardError


def serve(port: int = 0) -> None:
    """Serve the dashboard on 127.0.0.1:port (0: a free port) until interrupted."""
    try:
        app = importlib.import_module(".app", __name__)
    except ImportError as exc:
        raise GuardError(
            f'depbee dashboard needs Starlette, Jinja2 and uvicorn: pip install -e ".[web]" ({exc})'
        ) from exc
    app.serve(port)
