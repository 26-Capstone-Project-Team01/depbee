"""Known malicious index (KM-01): OSV npm MAL-* records matched by exact name and version.

build_index() turns an OSV npm snapshot (all.zip) into index.json and manifest.json; load() checks
such a folder and returns a KnownMaliciousIndex, the contracts.KnownMaliciousDetector that
pipeline.scan() takes. The index is read from a local file only: nothing is fetched while
checking, so the same index always gives the same matches. Standard library only.

Rules (docs/contracts.md 4, client-dev 2.3.1 recommended defaults):
- Only MAL-* records of the npm ecosystem; withdrawn records are left out of the index.
- Names match exactly, case included (no normalization).
- Versions compare by SemVer 2.0 precedence (section 11), build metadata ignored.
- The npm security placeholder 0.0.1-security never matches, whatever the record says.
- Which ranges count when a record also lists versions: _match_ranges() (decided 2026-11-17;
  revisit with the fixed verdict table).
- Baseline candidates (D-16) are excluded by listed versions and bounded ranges only.
"""

import hashlib
import io
import json
import re
import struct
import zipfile
import zlib
from datetime import datetime
from pathlib import Path, PurePosixPath

from .contracts import GuardError, _unique_object, check_sha256, read_json
from .pipeline import UTC_TIME

INDEX_FORMAT = "depbee-known-malicious-index"
MANIFEST_FORMAT = "depbee-known-malicious-manifest"
FORMAT_VERSION = 1
SOURCE = "OSV npm MAL"
# The real index is about 16 MB, close to contracts.MAX_JSON_BYTES (20 MiB).
MAX_INDEX_BYTES = 128 * 1024 * 1024
# Snapshot limits (build_index): the 2026-10 npm all.zip is 218 MB with 230,001 records of
# 385 MB in all; the largest record is far below a megabyte.
MAX_SNAPSHOT_BYTES = 1024 * 1024 * 1024
MAX_SNAPSHOT_ENTRIES = 2_000_000
# The 2026-10 all.zip has a 15,043,787-byte central directory (230,001 entries, ZIP64); about four
# times that. zipfile reads exactly this many bytes and builds one entry per record of at least
# 46 bytes inside them, so the limit bounds the entries it creates (at most about 1.46 million),
# whatever count the end record declares.
MAX_CENTRAL_DIRECTORY_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_SNAPSHOT_UNPACKED = 4 * 1024 * 1024 * 1024
MAX_AFFECTED = 256  # contract: matches[].affected is at most 256 characters
SECURITY_PLACEHOLDER = "0.0.1-security"

_NUMBER = r"0|[1-9]\d*"
_IDENTIFIER = rf"(?:{_NUMBER}|\d*[A-Za-z-][0-9A-Za-z-]*)"
# SemVer 2.0, ASCII only (no leading zeros, no empty identifiers); group 4 is the prerelease.
SEMVER = re.compile(
    rf"({_NUMBER})\.({_NUMBER})\.({_NUMBER})(?:-({_IDENTIFIER}(?:\.{_IDENTIFIER})*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
    re.ASCII,
)
# As npm semver (classes/semver.js): major, minor and patch are at most Number.MAX_SAFE_INTEGER;
# checking 16 digits first keeps int() off Python's digit limit (a ValueError). Numeric prerelease
# identifiers have no limit and are compared without int() (version_key).
MAX_NUMBER_DIGITS = 16
MAX_SAFE_INTEGER = 2**53 - 1
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_RECORD_FILE = re.compile(r"MAL-[^/]+\.json")
# Below every version: OSV introduced "0".
_ZERO = (-1,)
_EVENTS = ("introduced", "fixed", "last_affected")
_UPPER = {"fixed": "<", "last_affected": "<="}


def version_key(version: str) -> tuple:
    """SemVer 2.0 precedence key; build metadata is ignored. GuardError if not strict SemVer or
    major, minor or patch is above 2**53 - 1."""
    match = SEMVER.fullmatch(version) if isinstance(version, str) else None
    if match is None:
        raise GuardError(f"Not a strict SemVer 2.0 version: {str(version)[:64]!r}")

    def number(text: str) -> int:
        if len(text) > MAX_NUMBER_DIGITS or int(text) > MAX_SAFE_INTEGER:
            raise GuardError(f"Version number is too large: {str(version)[:64]!r}")
        return int(text)

    pre = match[4]
    if pre is None:
        release = (1,)  # a release is above all of its prereleases
    else:
        # Numbers (no leading zeros) by digit count, then text: numeric order. Below any word.
        release = (0, tuple((0, len(i), i) if i.isdigit() else (1, i) for i in pre.split(".")))
    return number(match[1]), number(match[2]), number(match[3]), release


def query_key(version: str) -> tuple:
    """Key of a version to look up: build metadata is cut first, the rest must be strict."""
    if not isinstance(version, str):
        raise GuardError("Known malicious lookup needs a version string")
    return version_key(version.split("+", 1)[0])


def _bound_key(text: str) -> tuple:
    return _ZERO if text == "0" else version_key(text)


SECURITY_KEY = version_key(SECURITY_PLACEHOLDER)


def _inside(key: tuple, interval: list) -> bool:
    low, upper, high = interval
    if key < _bound_key(low):
        return False
    if upper is None:
        return True
    return key < _bound_key(high) if upper == "<" else key <= _bound_key(high)


def _match_ranges(versions: list, intervals: list) -> list:
    """Range policy, the one place to change (client-dev 2.3.1 3, decided 2026-11-17; revisit with
    the fixed verdict table): a record that lists versions matches by those and its bounded
    ranges only; unbounded ranges (all versions, or "X and later") count only for records without
    versions. Alternatives: OSV's union (return intervals) or the training rule (return [] if
    versions else intervals)."""
    return [i for i in intervals if i[1] is not None] if versions else intervals


def _range_text(interval: list) -> str:
    low, upper, high = interval
    return f">={low}" if upper is None else f">={low} {upper}{high}"


def _cut(text: str) -> str:
    return text if len(text) <= MAX_AFFECTED else text[: MAX_AFFECTED - 3] + "..."


def utc_time_problem(value: object) -> str | None:
    """Why value is not ISO 8601 UTC ending in Z (pipeline's list_as_of rule), else None."""
    if isinstance(value, str) and UTC_TIME.fullmatch(value):
        try:
            datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
            return None
        except ValueError:  # e.g. month 13
            pass
    return f"list_as_of must be an ISO 8601 UTC time ending in Z: {str(value)[:64]!r}"


class KnownMaliciousIndex:
    """contracts.KnownMaliciousDetector over a checked index (load()). match() and
    baseline_records() use only data checked when it was loaded."""

    def __init__(self, header: dict, packages: dict, list_sha256: str) -> None:
        self.source = header["source"]
        self.list_as_of = header["list_as_of"]
        self.list_sha256 = list_sha256
        self.snapshot_sha256 = header["snapshot_sha256"]
        self.counts = header["counts"]
        self._packages = packages

    def match(self, name: str, version: str) -> list[dict]:
        """One match per record naming this version, by advisory_id: listed_version if the
        record lists it (affected: the record's versions), else affected_range (affected: the
        range it is in). GuardError if version without build metadata is not strict SemVer."""
        key = query_key(version)
        if key == SECURITY_KEY:
            return []
        found = []
        for advisory, versions, intervals in self._packages.get(name, ()):
            if any(version_key(v) == key for v in versions):
                found.append((advisory, "listed_version", ", ".join(versions)))
                continue
            for interval in _match_ranges(versions, intervals):
                if _inside(key, interval):
                    found.append((advisory, "affected_range", _range_text(interval)))
                    break
        return [
            {"advisory_id": advisory, "match_kind": kind, "affected": _cut(affected)}
            for advisory, kind, affected in sorted(found)
        ]

    def baseline_records(self, name: str, version: str) -> list[str]:
        """advisory_ids of the records that list version or have it in a bounded range: such a
        version is no baseline candidate (D-16). Unbounded ranges are never used here."""
        key = query_key(version)
        if key == SECURITY_KEY:
            return []
        return [
            advisory
            for advisory, versions, intervals in self._packages.get(name, ())
            if any(version_key(v) == key for v in versions)
            or any(i[1] is not None and _inside(key, i) for i in intervals)
        ]


# --- building the index from an OSV snapshot ---------------------------------------------------


def _intervals(events: list[tuple[str, str]]) -> list[list]:
    """OSV SEMVER events, sorted by version (the record's order is not trusted), as intervals
    [low, upper, high]: upper "<" (fixed), "<=" (last_affected) or None with high None."""
    order = {"introduced": 0, "fixed": 1, "last_affected": 1}
    events = sorted(events, key=lambda e: (_bound_key(e[1]), order[e[0]], e[1]))
    intervals, low = [], None
    for kind, text in events:
        if kind == "introduced":
            low = text if low is None else low
        elif low is not None:
            intervals.append([low, _UPPER[kind], text])
            low = None
    if low is not None:
        intervals.append([low, None, None])
    return intervals


def _range(value: object) -> tuple[list | None, str | None]:
    """(intervals, None) for a usable SEMVER range, else (None, reason)."""
    if not isinstance(value, dict) or value.get("type") != "SEMVER":
        return None, "range_not_semver"
    events = value.get("events")
    if not isinstance(events, list) or not events:
        return None, "range_without_events"
    parsed = []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return None, "range_unknown_event"
        ((kind, text),) = event.items()
        if kind == "limit":
            return None, "range_limit_event"
        if kind not in _EVENTS or not isinstance(text, str):
            return None, "range_unknown_event"
        try:
            if kind != "introduced" or text != "0":
                version_key(text)
        except GuardError:
            return None, "range_bound_not_semver"
        parsed.append((kind, text))
    kinds = {kind for kind, _ in parsed}
    if "introduced" not in kinds:
        return None, "range_without_introduced"
    if {"fixed", "last_affected"} <= kinds:
        return None, "range_fixed_and_last_affected"
    return _intervals(parsed), None


def _record(raw: bytes, stem: str, parts: dict) -> tuple[dict | None, str | None]:
    """({name: [versions, intervals]}, None) of one MAL record, else (None, reason). Dropped
    versions and ranges are counted in parts."""
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object)
    except (ValueError, RecursionError):  # also an integer past Python's digit limit
        return None, "record_not_json"
    if not isinstance(value, dict) or value.get("id") != stem:
        return None, "record_id_mismatch"
    if "withdrawn" in value:
        return None, "withdrawn"
    affected = value.get("affected")
    if not isinstance(affected, list):
        return None, "affected_missing"
    names: dict[str, list] = {}
    for item in affected:
        package = item.get("package") if isinstance(item, dict) else None
        if not isinstance(package, dict) or package.get("ecosystem") != "npm":
            parts["affected_not_npm"] = parts.get("affected_not_npm", 0) + 1
            continue
        name = package.get("name")
        if not isinstance(name, str) or not name:
            parts["affected_name_invalid"] = parts.get("affected_name_invalid", 0) + 1
            continue
        listed = item.get("versions", [])
        # A list must stay a list: an item whose versions are all unusable is left out, never
        # turned into one without versions, whose unbounded ranges would then match.
        if not isinstance(listed, list):
            parts["versions_not_list"] = parts.get("versions_not_list", 0) + 1
            continue
        valid = []
        for version in listed:
            try:
                version_key(version)
                valid.append(version)
            except GuardError:
                parts["version_not_semver"] = parts.get("version_not_semver", 0) + 1
        if listed and not valid:
            parts["versions_all_invalid"] = parts.get("versions_all_invalid", 0) + 1
            continue
        versions, intervals = names.setdefault(name, [[], []])
        versions.extend(valid)
        ranges = item.get("ranges", [])
        for found in ranges if isinstance(ranges, list) else [None]:
            usable, reason = _range(found)
            if reason:
                parts[reason] = parts.get(reason, 0) + 1
            else:
                intervals.extend(usable)
    names = {name: pair for name, pair in names.items() if pair[0] or pair[1]}
    if not names:
        return None, "nothing_to_match"
    return names, None


_END = b"PK\x05\x06"
_END_FORMAT = "<4s4H2LH"  # 22 bytes
_ZIP64_LOCATOR = b"PK\x06\x07"  # 20 bytes, right before the end record
_ZIP64_END = b"PK\x06\x06"
_ZIP64_END_FORMAT = "<4sQ2H2L4Q"  # 56 bytes, right before the locator


def _central_directory(data: bytes) -> tuple[int, int]:
    """(central directory bytes, declared entries) of a zip, found the way zipfile finds them:
    the end record at the very end (no comment) or the last one in the final 64 KiB + 22 bytes,
    replaced by the ZIP64 end record when a ZIP64 locator sits right before it. GuardError if
    there is no end record. Reads the bytes only; public zipfile API has no such step."""
    end = len(data) - 22
    if not (end >= 0 and data[end : end + 4] == _END and data[-2:] == b"\0\0"):
        end = data.rfind(_END, max(len(data) - 65535 - 22, 0))
        if end < 0 or len(data) - end < 22:
            raise GuardError("Snapshot is not a readable zip file: no end of central directory")
    fields = struct.unpack(_END_FORMAT, data[end : end + 22])
    entries, size = fields[4], fields[5]
    locator = end - 20
    if locator >= 0 and data[locator : locator + 4] == _ZIP64_LOCATOR:
        record = locator - 56
        if record >= 0 and data[record : record + 4] == _ZIP64_END:
            fields = struct.unpack(_ZIP64_END_FORMAT, data[record:locator])
            entries, size = fields[7], fields[8]
    return size, entries


try:
    from lzma import LZMAError as _LZMA_ERROR
except ImportError:  # without lzma, zipfile refuses LZMA entries with RuntimeError
    _LZMA_ERROR = RuntimeError

# What zipfile raises for an archive it cannot read: a bad or unsupported structure, method or
# version (NotImplementedError), an encrypted entry (RuntimeError), a damaged stream (zlib.error,
# LZMAError; bz2 gives OSError).
_ZIP_ERRORS = (
    zipfile.BadZipFile, OSError, ValueError, NotImplementedError, RuntimeError, EOFError,
    zlib.error, struct.error, _LZMA_ERROR,
)  # fmt: skip


def build_index(snapshot: bytes, list_as_of: str) -> tuple[bytes, bytes, dict]:
    """(index.json bytes, manifest.json bytes, header) from the bytes of an OSV npm all.zip.

    list_as_of: when all.zip was downloaded, ISO 8601 UTC ending in Z. The zip is read in
    memory, never unpacked to files. Only top-level MAL-*.json records are read; every other
    entry, withdrawn record and unusable record, version or range is counted by reason in the
    header (counts.skipped_records, counts.skipped_parts). The same snapshot and list_as_of always
    give the same bytes. GuardError for a bad list_as_of, a snapshot over the limits (checked on
    the end record before zipfile reads the central directory), not a zip, or a zip that cannot
    be read (encrypted, unsupported or damaged).
    """
    problem = utc_time_problem(list_as_of)
    if problem:
        raise GuardError(problem)
    if len(snapshot) > MAX_SNAPSHOT_BYTES:
        raise GuardError(f"Snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes")
    directory, declared = _central_directory(snapshot)
    if directory > MAX_CENTRAL_DIRECTORY_BYTES:
        raise GuardError(f"Snapshot central directory exceeds {MAX_CENTRAL_DIRECTORY_BYTES} bytes")
    if declared > MAX_SNAPSHOT_ENTRIES:
        raise GuardError(f"Snapshot has more than {MAX_SNAPSHOT_ENTRIES} entries")
    try:
        archive = zipfile.ZipFile(io.BytesIO(snapshot))
        entries = archive.infolist()
    except _ZIP_ERRORS as exc:
        raise GuardError(f"Snapshot is not a readable zip file: {exc}") from exc
    if len(entries) > MAX_SNAPSHOT_ENTRIES:
        raise GuardError(f"Snapshot has more than {MAX_SNAPSHOT_ENTRIES} entries")
    if sum(entry.file_size for entry in entries) > MAX_SNAPSHOT_UNPACKED:
        raise GuardError(f"Snapshot unpacks to more than {MAX_SNAPSHOT_UNPACKED} bytes")
    skipped, parts, packages = {}, {}, {}
    records = 0
    for entry in entries:
        if not _RECORD_FILE.fullmatch(entry.filename):
            reason = "not_mal" if PurePosixPath(entry.filename).suffix == ".json" else "not_record"
            skipped[reason] = skipped.get(reason, 0) + 1
            continue
        if entry.file_size > MAX_RECORD_BYTES:
            raise GuardError(f"Snapshot record {entry.filename} exceeds {MAX_RECORD_BYTES} bytes")
        if entry.flag_bits & 0x1:
            raise GuardError(f"Snapshot record {entry.filename} is encrypted")
        try:
            with archive.open(entry) as stream:
                raw = stream.read(MAX_RECORD_BYTES + 1)
        except _ZIP_ERRORS as exc:
            raise GuardError(f"Snapshot record {entry.filename} cannot be read: {exc}") from exc
        if len(raw) > MAX_RECORD_BYTES:
            raise GuardError(f"Snapshot record {entry.filename} exceeds {MAX_RECORD_BYTES} bytes")
        names, reason = _record(raw, entry.filename[: -len(".json")], parts)
        if reason:
            skipped[reason] = skipped.get(reason, 0) + 1
            continue
        records += 1
        advisory = entry.filename[: -len(".json")]
        for name, (versions, intervals) in names.items():
            packages.setdefault(name, []).append([advisory, versions, intervals])
    header = {
        "format": INDEX_FORMAT,
        "format_version": FORMAT_VERSION,
        "source": SOURCE,
        "list_as_of": list_as_of,
        "snapshot_sha256": hashlib.sha256(snapshot).hexdigest(),
        "counts": {
            "records": records,
            "names": len(packages),
            "skipped_records": skipped,
            "skipped_parts": parts,
        },
    }
    body = {
        **header,
        "packages": [[name, sorted(packages[name])] for name in sorted(packages)],
    }
    index = _dump(body)
    manifest = _dump({
        "format": MANIFEST_FORMAT,
        "format_version": FORMAT_VERSION,
        "index_sha256": hashlib.sha256(index).hexdigest(),
        "source": SOURCE,
        "list_as_of": list_as_of,
        "snapshot_sha256": header["snapshot_sha256"],
    })  # fmt: skip
    return index, manifest, header


def _dump(value: dict) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()


# --- loading ---------------------------------------------------------------------------------

_COPIES = ("source", "list_as_of", "snapshot_sha256")


def _require(ok: bool, where: Path, what: str) -> None:
    if not ok:
        raise GuardError(f"Known malicious index {where}: {what}")


def _header(value: dict, where: Path, form: str, keys: set) -> None:
    _require(set(value) == keys, where, f"expected exactly the keys {', '.join(sorted(keys))}")
    _require(value["format"] == form, where, f"format is not {form}")
    _require(type(value["format_version"]) is int, where, "format_version is not an integer")
    _require(value["format_version"] == FORMAT_VERSION, where,
             f"format_version {value['format_version']} is not {FORMAT_VERSION}")  # fmt: skip
    _require(isinstance(value["source"], str) and value["source"] != "", where, "bad source")
    problem = utc_time_problem(value["list_as_of"])
    _require(problem is None, where, problem or "")
    _require(isinstance(value["snapshot_sha256"], str)
             and _SHA256.fullmatch(value["snapshot_sha256"]) is not None, where,
             "snapshot_sha256 is not 64 lowercase hex digits")  # fmt: skip


def _counts(value: object, where: Path) -> None:
    def number(n):
        return type(n) is int and n >= 0

    _require(isinstance(value, dict)
             and set(value) == {"records", "names", "skipped_records", "skipped_parts"}
             and number(value["records"]) and number(value["names"])
             and all(isinstance(value[k], dict) and all(number(n) for n in value[k].values())
                     for k in ("skipped_records", "skipped_parts")), where,
             "counts is not {records, names, skipped_records, skipped_parts}")  # fmt: skip


def _bound_ok(text: object, zero: bool) -> bool:
    if not isinstance(text, str):
        return False
    try:
        _bound_key(text) if zero else version_key(text)
    except GuardError:
        return False
    return True


def _interval_ok(interval: object) -> bool:
    if not isinstance(interval, list) or len(interval) != 3 or not _bound_ok(interval[0], True):
        return False
    if interval[1] is None:
        return interval[2] is None
    return interval[1] in ("<", "<=") and _bound_ok(interval[2], False)


def _record_problem(record: object, last: str | None) -> str | None:
    """Why one index record [advisory_id, versions, ranges] is unusable, else None."""
    if not isinstance(record, list) or len(record) != 3:
        return "a record is not [advisory_id, versions, ranges]"
    advisory, versions, intervals = record
    if not isinstance(advisory, str) or not advisory or (last is not None and advisory <= last):
        return "advisory ids are not sorted, unique strings"
    if not isinstance(versions, list) or not all(_bound_ok(v, False) for v in versions):
        return f"{advisory[:64]!r} has a version that is not strict SemVer"
    if not isinstance(intervals, list) or not (versions or intervals):
        return f"{advisory[:64]!r} has no versions or ranges"
    if not all(_interval_ok(interval) for interval in intervals):
        return f"{advisory[:64]!r} has a malformed range"
    return None


def _packages(value: object, where: Path, counts: dict) -> dict:
    """{name: records} after checking every entry; the names must be sorted and unique."""
    _require(isinstance(value, list), where, "packages is not a list")
    packages, previous = {}, None
    for entry in value:
        if not isinstance(entry, list) or len(entry) != 2:
            _require(False, where, "a package is not [name, records]")
        name, records = entry
        if not isinstance(name, str) or not name or (previous is not None and name <= previous):
            _require(False, where, f"package names are not sorted, unique strings at {name!r:.64}")
        previous = name
        if not isinstance(records, list) or not records:
            _require(False, where, f"no records for {name[:64]!r}")
        last = None
        for record in records:
            problem = _record_problem(record, last)
            if problem:
                _require(False, where, f"{name[:64]!r}: {problem}")
            last = record[0]
        packages[name] = records
    _require(len(packages) == counts["names"], where, "counts.names does not match the packages")
    return packages


# The last index load() checked: (key, index). The real index takes about 0.6-1.7 s to check,
# which the long-running mcp and dashboard would otherwise pay on every call.
_last: tuple | None = None


def _state(path: Path) -> tuple[int, int]:
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns


def load(directory: Path, sha256: dict | None = None) -> KnownMaliciousIndex:
    """Check directory/manifest.json and directory/index.json and return the index.

    The index bytes must have the manifest's index_sha256, the manifest's copies of source,
    list_as_of and snapshot_sha256 must equal the index header, and every entry is checked before
    use. Any problem (missing or unreadable file, size, JSON, duplicate key, format, type, hash or
    copy mismatch, list_as_of) is a GuardError: a broken index is never treated as no index.
    Both files are read once and hashed on every call, and what is parsed is what was hashed; the
    checked index of the previous call is reused only for the same folder, file sizes,
    modification times and both hashes.

    sha256, for the index shipped with depbee (bundled.SHA256), is {"manifest.json": ...,
    "index.json": ...}: the SHA-256 each file's bytes must have before they are parsed. A folder
    the caller chose has none, and its index need only be the one its manifest names.
    """
    global _last
    directory = Path(directory)
    manifest_path, index_path = directory / "manifest.json", directory / "index.json"
    fixed = (None, None) if sha256 is None else (sha256["manifest.json"], sha256["index.json"])
    try:
        manifest, manifest_sha256 = read_json(manifest_path, fixed[0])
    except OSError as exc:
        raise GuardError(f"Known malicious index manifest cannot be read: {manifest_path}") from exc
    except ValueError as exc:  # GuardError, or an integer past Python's digit limit
        raise GuardError(f"Known malicious index manifest is invalid: {exc}") from exc
    keys = {"format", "format_version", "index_sha256", *_COPIES}
    _header(manifest, manifest_path, MANIFEST_FORMAT, keys)
    expected = manifest["index_sha256"]
    _require(isinstance(expected, str) and _SHA256.fullmatch(expected) is not None, manifest_path,
             "index_sha256 is not 64 lowercase hex digits")  # fmt: skip
    try:
        with index_path.open("rb") as stream:
            raw = stream.read(MAX_INDEX_BYTES + 1)
    except OSError as exc:
        raise GuardError(f"Known malicious index cannot be read: {index_path}") from exc
    _require(len(raw) <= MAX_INDEX_BYTES, index_path, f"exceeds {MAX_INDEX_BYTES} bytes")
    actual = check_sha256(raw, fixed[1], index_path)
    _require(actual == expected, index_path, "SHA-256 does not match the manifest's index_sha256")
    try:
        key = (str(directory.resolve()), _state(manifest_path), _state(index_path),
               manifest_sha256, actual)  # fmt: skip
    except OSError as exc:
        raise GuardError(f"Known malicious index cannot be read: {directory}") from exc
    # Read the memo once: another thread may replace it between the comparison and the return.
    last = _last
    if last is not None and last[0] == key:
        return last[1]
    try:
        body = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, RecursionError) as exc:  # also an integer past Python's digit limit
        raise GuardError(f"Known malicious index {index_path}: invalid JSON ({exc})") from exc
    _require(isinstance(body, dict), index_path, "not a JSON object")
    _header(body, index_path, INDEX_FORMAT, {"format", "format_version", "counts", "packages",
                                              *_COPIES})  # fmt: skip
    _counts(body["counts"], index_path)
    for copied in _COPIES:
        _require(
            manifest[copied] == body[copied], manifest_path, f"{copied} differs from the index"
        )
    packages = _packages(body["packages"], index_path, body["counts"])
    index = KnownMaliciousIndex(body, packages, actual)
    _last = (key, index)
    return index
