"""Pick the version a model input is compared against, using the training data's rule.

The model was trained on pairs whose old version is "the version a user receiving the new
version was most likely running": the highest earlier stable in the same release line
(npm-malware-package-pairs ``derived/pairs/baseline_rule.py``). Scoring a lockfile jump such as
1.2.0 -> 1.5.3 directly would feed the model a pair unlike anything it saw, so the analyzer
compares the installed version with that predecessor instead and keeps the lockfile version
only as context.

Differences from the training rule, both because they need data that inference does not have:
- Candidates are checked against OSV MAL-* records only when a known malicious index is
  connected (``exclude``, D-16), and then only by listed versions and bounded ranges; never
  against the training archive. Malicious versions are normally unpublished, so they are
  usually absent from ``versions`` anyway.
- Candidates published within 24 hours before the new version are not payload-verified.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from ..contracts import GuardError

_SEMVER = re.compile(
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?\Z"
)


@dataclass(frozen=True)
class Baseline:
    version: str
    level: str  # "L1": same release line, "L2": latest stable of an earlier line


def _stable_core(version: str) -> tuple[int, int, int] | None:
    """(major, minor, patch) of a stable version; None for prereleases and non-semver.

    Build metadata is ignored, as in semver precedence. Prereleases, including 0.0.0-<branch>
    snapshot builds, are never installed by ^ or ~ ranges.
    """
    match = _SEMVER.match(version) if isinstance(version, str) else None
    if match is None or match[4]:
        return None
    return int(match[1]), int(match[2]), int(match[3])


def is_stable(version: str) -> bool:
    return _stable_core(version) is not None


def release_line(core: tuple[int, int, int]) -> tuple[int, ...]:
    """npm caret range unit: >=1.0.0 is the major, 0.y.z is 0.y, and 0.0.z is all of 0.0."""
    return (core[0],) if core[0] > 0 else (0, core[1])


def _timestamp(value: str) -> datetime:
    """Registry publish time; must carry a timezone so that any two can be compared."""
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GuardError(f"Registry publish time is not an ISO 8601 time: {value[:64]!r}") from exc
    if stamp.utcoffset() is None:
        raise GuardError(f"Registry publish time has no timezone: {value[:64]!r}")
    return stamp


def select_baseline(
    packument: dict, new_version: str, exclude: Callable[[str], bool] | None = None
) -> Baseline | None:
    """Return the stable predecessor of a stable ``new_version``, or None if there is none.

    exclude: called with a candidate version in the order the rule would pick them, until one is
    not excluded; an excluded candidate is skipped (D-16, known malicious versions).
    """
    new = _stable_core(new_version)
    if new is None:
        raise GuardError(f"Baseline rule only covers stable versions: {new_version}")
    times = packument.get("time") or {}
    versions = packument.get("versions") or {}
    if not isinstance(times.get(new_version), str):
        raise GuardError(f"Registry has no publish time for {new_version}")
    published = _timestamp(times[new_version])

    candidates = []
    for version, stamp in times.items():
        # Only versions whose tarball is still downloadable can be compared.
        if version == new_version or version not in versions or not isinstance(stamp, str):
            continue
        core = _stable_core(version)
        if core is None or core >= new or _timestamp(stamp) >= published:
            continue
        candidates.append((core, version))

    same_line = [c for c in candidates if release_line(c[0]) == release_line(new)]
    excluded = set()
    for level, pool in (("L1", same_line), ("L2", candidates)):
        for _, version in sorted(pool, reverse=True):
            if version in excluded:
                continue
            if exclude is None or not exclude(version):
                return Baseline(version, level)
            excluded.add(version)
    return None
