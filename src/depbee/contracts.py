"""Small, versioned contracts shared by adapters and the CLI."""

import hashlib
import json
import math
import time
from pathlib import Path
from typing import Protocol

SCHEMA_VERSION = 1
MAX_JSON_BYTES = 20 * 1024 * 1024


class GuardError(ValueError):
    """An input or integration problem that must not become an allow result."""


class OutOfScopeError(GuardError):
    """Input the model was not trained on. Reported as incomplete and never scored."""


def _unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(raw: bytes, source: object) -> tuple[dict, str]:
    """Check JSON bytes from a file or Git and hash them as given; source names them in errors."""
    if len(raw) > MAX_JSON_BYTES:
        raise GuardError(f"JSON exceeds {MAX_JSON_BYTES} bytes: {source}")
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise GuardError(f"Invalid JSON: {source}") from exc
    if not isinstance(value, dict):
        raise GuardError(f"Expected JSON object: {source}")
    return value, hashlib.sha256(raw).hexdigest()


def read_json(path: Path) -> tuple[dict, str]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    return parse_json(raw, path)


def digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()


def finite_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GuardError(f"{label} must be a number")
    try:
        number = float(value)
    except OverflowError as exc:
        raise GuardError(f"{label} is too large") from exc
    if not math.isfinite(number):
        raise GuardError(f"{label} must be finite")
    return number


def elapsed_since(started: float) -> float:
    """Seconds on the monotonic clock since started, in milliseconds; always finite and >= 0."""
    seconds = time.monotonic() - started
    return round(seconds, 3) if math.isfinite(seconds) and seconds > 0 else 0.0


class Analyzer(Protocol):
    """Implement with a teammate's Python function or a trusted CLI adapter."""

    def analyze(self, request: dict) -> dict: ...


class Predictor(Protocol):
    feature_schema: str
    feature_names: list[str]
    threshold: float
    model_id: str

    def predict(self, features: dict[str, object]) -> float: ...


class KnownMaliciousDetector(Protocol):
    """Known malicious records (docs/result-contract-draft.md 3). The attributes are the report's
    detectors.known_malicious. pipeline.scan() reports an exception or a malformed return value
    as failed, never as not_hit."""

    source: str
    list_as_of: str  # ISO 8601 UTC with Z
    list_sha256: str | None

    def match(self, name: str, version: str) -> list[dict]:
        """Records naming this npm registry version, each {advisory_id: str, match_kind:
        "listed_version" or "affected_range", affected: str or None}; empty if none."""
        ...


class RuleDetector(Protocol):
    """Rules run on a change and its complete analysis result (contract 3, D-15)."""

    ruleset_version: str

    def check(self, change: dict, analysis: dict) -> list[dict]:
        """One record per rule run: {rule_id: str, rule_version: str, status: "hit", "not_hit"
        or "failed", evidence: [str], locations: [{file: str, line: int or None}], detail: str
        or None}."""
        ...
