"""Local dashboard (`depbee dashboard`, SVC-07): registered projects, their dependencies, stored
scan and update-preview reports, and update previews and applies, on 127.0.0.1 only. In a
container (.mounted) it listens inside the container for a port published to the host's
127.0.0.1, and its projects are the folders mounted into it.

Verdicts, reasons and exit codes are shown as stored and never recomputed; the wording comes
from depbee.cli. Update previews and applies go through depbee.service (preview_files,
update_gate, apply_preview), which alone decides what may be applied. The web libraries (extra
[web]) are imported only by .app, which serve() loads.
"""

import importlib
from pathlib import Path

from ..contracts import GuardError


def serve(
    port: int = 0, *, model_dir: Path | None = None, cache_dir: Path | None = None,
    no_cache: bool = False, known_malicious_dir: Path | None = None, background=None,
) -> None:  # fmt: skip
    """Serve the dashboard on 127.0.0.1:port (0: a free port) until interrupted; in a container,
    where app.serve() says. model_dir, cache_dir, no_cache, known_malicious_dir: for update
    previews, as in depbee update. background: the lifecycle.Instance to serve as (depbee
    dashboard --background)."""
    try:
        app = importlib.import_module(".app", __name__)
    except ImportError as exc:
        raise GuardError(
            f'depbee dashboard needs Starlette, Jinja2 and uvicorn: pip install -e ".[web]" ({exc})'
        ) from exc
    app.serve(port, model_dir=model_dir, cache_dir=cache_dir, no_cache=no_cache,
              known_malicious_dir=known_malicious_dir, background=background)  # fmt: skip
