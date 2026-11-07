"""Persistent cache of extracted features, reused between runs for the same compared versions.

The key binds everything the features depend on (see ``ExtractorAnalyzer._cache_key``); the entry
holds only the features. Verdicts, scores, explanations and evidence are recomputed on every run.
The directory is a trust boundary: entries are checked for shape and key, but that does not prove
who wrote them. Use a directory only you can write to, never one a pull request can fill.
"""

import contextlib
import json
import math
import os
import tempfile
from pathlib import Path

from ..contracts import GuardError, digest, parse_json
from . import bounded

FORMAT = 2  # 2: features keep the extractor's key order (format 1 stored them sorted)
MAX_ENTRY_BYTES = 1024 * 1024


def default_dir() -> Path:
    return Path.home() / ".cache" / "depbee"


def _path(directory: Path, key: dict) -> Path:
    return directory / f"{digest(key)}.json"


def _feature(value: object) -> bool:
    if isinstance(value, float):
        return math.isfinite(value)
    return value is None or isinstance(value, (bool, int, str))


def load(directory: Path, key: dict) -> dict | None:
    """Features stored under key; None (a miss) if absent, unreadable, too large or malformed."""
    try:
        with _path(directory, key).open("rb") as stream:
            raw = stream.read(MAX_ENTRY_BYTES + 1)
        if len(raw) > MAX_ENTRY_BYTES:
            return None
        entry, _ = parse_json(raw, "cache entry")
    except (OSError, GuardError):
        return None
    features = entry.get("features")
    if set(entry) != {"format", "key", "features"} or entry["format"] != FORMAT:
        return None
    if entry["key"] != key or not isinstance(features, dict) or not features:
        return None
    return features if all(_feature(v) for v in features.values()) else None


def store(directory: Path, key: dict, features: dict) -> None:
    """Write the entry atomically (temporary file, then os.replace). A failure only skips caching.

    Only features that load() would accept are written, so a stored entry is never a miss.
    Inside a time budget (analysis.bounded), the deadline is checked last, right before the
    entry is published: once it has passed, TimeLimitError is raised, the temporary file is
    removed and nothing else in the directory changes. An os.replace that started in time is
    not undone if it ends late; the caller then refuses its own result (bounded.check()).
    """
    if not isinstance(features, dict) or not features or not all(map(_feature, features.values())):
        return
    entry = {"format": FORMAT, "key": key, "features": features}
    try:
        # Not sorted: a cache hit reports the features in the order a cold run does.
        raw = json.dumps(entry, ensure_ascii=True, allow_nan=False).encode()
    except (TypeError, ValueError):
        return
    if len(raw) > MAX_ENTRY_BYTES:
        return
    target = _path(directory, key)  # every argument is ready before the last deadline check
    try:
        directory.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
    except OSError:
        return
    published = False
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(raw)
        bounded.check()  # serializing and writing may have used up the change's time
        os.replace(temporary, target)  # nothing runs between the check and the rename
        published = True
    except OSError:
        pass
    finally:
        if not published:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
