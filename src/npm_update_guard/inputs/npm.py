"""Identify changes from package-lock v2/v3 without running npm or fetching packages."""

import re
from pathlib import Path
from urllib.parse import urlparse

from ..contracts import SCHEMA_VERSION, GuardError, digest, read_json

VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z")


def _snapshot(path: Path) -> tuple[dict, str]:
    lock, sha256 = read_json(path)
    if type(lock.get("lockfileVersion")) is not int or lock["lockfileVersion"] not in (2, 3):
        raise GuardError("Only package-lock.json lockfileVersion 2 and 3 are supported")
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise GuardError("package-lock.json must contain a packages object")
    entries = {}
    for location, record in packages.items():
        if location == "":
            continue
        if not isinstance(record, dict):
            raise GuardError(f"Invalid lock entry: {location}")
        # Workspace source entries are represented by their node_modules links.
        if "node_modules/" not in location:
            continue
        inferred_name = location.rsplit("node_modules/", 1)[-1]
        name = record.get("name", inferred_name)
        fields = {
            "name": name,
            "version": record.get("version"),
            "resolved": record.get("resolved"),
            "integrity": record.get("integrity"),
        }
        for field, value in fields.items():
            if value is not None and (not isinstance(value, str) or not value):
                raise GuardError(f"Invalid {field} in lock entry: {location}")
        entries[location] = {
            "name": name,
            "version": record.get("version"),
            "resolved": record.get("resolved"),
            "integrity": record.get("integrity"),
            "link": bool(record.get("link", False)),
        }
    return entries, sha256


def _unsupported(before: dict | None, after: dict | None) -> str | None:
    if after is None:
        return "removed"
    if before is None:
        return "no_previous_version"
    if before["name"] != after["name"]:
        return "package_identity_changed"
    for entry in (before, after):
        version = entry["version"]
        if entry["link"] or not version or not VERSION.fullmatch(version):
            return "workspace_or_non_registry_version"
        source = urlparse(entry["resolved"] or "")
        if source.scheme != "https" or source.netloc != "registry.npmjs.org":
            return "unsupported_registry_source"
        if not entry["integrity"]:
            return "missing_integrity"
    if before["version"] == after["version"]:
        return "same_version_artifact_changed"
    return None


def build_request(project: Path, base_lock: Path) -> dict:
    head_lock = project / "package-lock.json"
    if not project.is_dir():
        raise GuardError(f"Project directory not found: {project}")
    before, base_hash = _snapshot(base_lock)
    after, head_hash = _snapshot(head_lock)
    changes = []
    for location in sorted(before.keys() | after.keys()):
        old, new = before.get(location), after.get(location)
        if old == new:
            continue
        reason = _unsupported(old, new)
        change = {"location": location, "before": old, "after": new}
        changes.append(
            {
                "change_id": digest(change),
                **change,
                "kind": "removed" if new is None else "added" if old is None else "updated",
                "analyzable": reason is None,
                "reason": reason,
            }
        )
    request = {
        "schema_version": SCHEMA_VERSION,
        "base_lock_sha256": base_hash,
        "head_lock_sha256": head_hash,
        "changes": changes,
    }
    return {"request_id": digest(request), **request}
