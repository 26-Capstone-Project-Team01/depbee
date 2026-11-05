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

FORMAT = 1
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
    """
    if not isinstance(features, dict) or not features or not all(map(_feature, features.values())):
        return
    entry = {"format": FORMAT, "key": key, "features": features}
    try:
        raw = json.dumps(entry, ensure_ascii=True, allow_nan=False, sort_keys=True).encode()
    except (TypeError, ValueError):
        return
    if len(raw) > MAX_ENTRY_BYTES:
        return
    try:
        directory.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
    except OSError:
        return
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(raw)
        os.replace(temporary, _path(directory, key))
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
