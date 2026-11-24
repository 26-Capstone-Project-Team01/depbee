"""Persistent cache of extracted features, reused between runs for the same compared versions.

The key binds everything the features depend on (see ``ExtractorAnalyzer._cache_key``); the entry
holds the features and the static rule checks of the same two unpacked versions (analysis.rules),
which the caller checks again. Verdicts, scores, explanations and evidence are recomputed on every
run.
The directory is a trust boundary: entries are checked for shape and key, but that does not prove
who wrote them. Use a directory only you can write to, never one a pull request can fill.
"""

import contextlib
import json
import math
import os
import stat
import tempfile
from pathlib import Path

from ..contracts import GuardError, digest, parse_json
from . import bounded

# In every key, next to the depbee version (ExtractorAnalyzer._cache_key). Raise it by hand when
# a change alters stored entries or the features depbee extracts without a new depbee version;
# nothing detects such a change. 2: features keep the extractor's key order (1 sorted them).
# 3: the entry holds the rule checks too (rules), so an entry without them is a miss.
FORMAT = 3
MAX_ENTRY_BYTES = 1024 * 1024


def default_dir() -> Path:
    return Path.home() / ".cache" / "depbee"


def _path(directory: Path, key: dict) -> Path:
    return directory / f"{digest(key)}.json"


def _feature(value: object) -> bool:
    if isinstance(value, float):
        return math.isfinite(value)
    return value is None or isinstance(value, (bool, int, str))


def _nonblocking(path: str, flags: int) -> int:
    """os.open for open(opener=...): a FIFO opened for reading would wait for a writer, and the
    parent with it, unless O_NONBLOCK is set (Windows has no FIFOs here and no such flag)."""
    return os.open(path, flags | getattr(os, "O_NONBLOCK", 0))


def load(directory: Path, key: dict) -> tuple[dict, list | None] | None:
    """(features, rules) stored under key; None (a miss) if absent, unreadable, too large or
    malformed. rules is a list or None as stored; its checks are the caller's (analysis.rules).

    Only a regular file is read, checked on the opened descriptor itself, so a FIFO or device
    at the path is a miss and nothing can swap the file between the check and the read.
    """
    try:
        with open(_path(directory, key), "rb", opener=_nonblocking) as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return None
            raw = stream.read(MAX_ENTRY_BYTES + 1)
        if len(raw) > MAX_ENTRY_BYTES:
            return None
        entry, _ = parse_json(raw, "cache entry")
    except (OSError, GuardError):
        return None
    features, rules = entry.get("features"), entry.get("rules")
    if set(entry) != {"format", "key", "features", "rules"} or entry["format"] != FORMAT:
        return None
    if entry["key"] != key or not isinstance(features, dict) or not features:
        return None
    if not (rules is None or isinstance(rules, list)):
        return None
    return (features, rules) if all(_feature(v) for v in features.values()) else None


def store(directory: Path, key: dict, features: dict, rules: list | None = None) -> None:
    """Write the entry atomically (temporary file, then os.replace). A failure only skips caching.

    Only features that load() would accept are written, so a stored entry is never a miss.
    Inside a time budget (analysis.bounded), the deadline is checked last, right before the
    entry is published: once it has passed, TimeLimitError is raised, the temporary file is
    removed and nothing else in the directory changes. An os.replace that started in time is
    not undone if it ends late; the caller then refuses its own result (bounded.check()).
    """
    if not isinstance(features, dict) or not features or not all(map(_feature, features.values())):
        return
    if not (rules is None or isinstance(rules, list)):
        return
    entry = {"format": FORMAT, "key": key, "features": features, "rules": rules}
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
