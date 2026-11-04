"""Identify changes from package-lock v2/v3 without running npm or fetching packages."""

import re
from pathlib import Path
from urllib.parse import urlparse

from ..contracts import SCHEMA_VERSION, GuardError, digest, parse_json, read_json
from .git import read_base_lock

VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z")
# npm package names (npm docs, package.json "name"): URL-safe characters only, at most 214 with
# the scope, no leading "." or "_" except that a scoped name may start with "_". Uppercase stays
# allowed for old packages. A leading "." is refused everywhere so "." and ".." never reach a URL.
_NAME_REST = r"[A-Za-z0-9._~!*'()-]*"
PACKAGE_NAME = re.compile(
    rf"(?:@[A-Za-z0-9~!*'()-]{_NAME_REST}/[A-Za-z0-9_~!*'()-]|[A-Za-z0-9~!*'()-]){_NAME_REST}"
)
MAX_NAME_LENGTH = 214
# A version exactly as the registry stores it: semver with ASCII digits, no build metadata.
_NUMBER = r"(?:0|[1-9][0-9]*)"
EXACT_VERSION = re.compile(rf"{_NUMBER}\.{_NUMBER}\.{_NUMBER}(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
REGISTRY_LOCATION = "registry.npmjs.org"


def _snapshot(loaded: tuple[dict, str]) -> tuple[dict, str]:
    lock, sha256 = loaded
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
    if before is not None and before["name"] != after["name"]:
        return "package_identity_changed"
    # The analyzer compares the installed version with its registry predecessor, not with the
    # previous lock entry, so only the version that will be installed must be a registry tarball.
    # Newly added dependencies are therefore analyzable too.
    version = after["version"]
    if after["link"] or not version or not VERSION.fullmatch(version):
        return "workspace_or_non_registry_version"
    source = urlparse(after["resolved"] or "")
    if source.scheme != "https" or source.netloc != "registry.npmjs.org":
        return "unsupported_registry_source"
    if not after["integrity"]:
        return "missing_integrity"
    if before is not None and before["version"] == after["version"]:
        return "same_version_artifact_changed"
    return None


def build_request(
    project: Path, base_lock: Path | None = None, *, base_ref: str | None = None
) -> dict:
    """Compare project/package-lock.json with base_lock, else with its copy in Git base_ref.

    base_ref defaults to HEAD. Either way the base bytes get the same checks and SHA-256.
    """
    if base_lock is not None and base_ref is not None:
        raise GuardError("Use either a base lockfile or a Git base ref, not both")
    head_lock = project / "package-lock.json"
    if not project.is_dir():
        raise GuardError(f"Project directory not found: {project}")
    if base_lock is not None:
        base = read_json(base_lock)
    else:
        ref = "HEAD" if base_ref is None else base_ref
        base = parse_json(read_base_lock(project, ref), f"{ref}:{head_lock}")
    before, base_hash = _snapshot(base)
    after, head_hash = _snapshot(read_json(head_lock))
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


def check_package_spec(name: str, version: str) -> None:
    """Accept only an exact npm registry name and version. Runs before any network access."""
    if not isinstance(name, str) or len(name) > MAX_NAME_LENGTH or not PACKAGE_NAME.fullmatch(name):
        raise GuardError(f"Invalid npm package name: {name!r}")
    if not isinstance(version, str) or not EXACT_VERSION.fullmatch(version):
        raise GuardError(
            f"Version must be an exact version such as 1.2.3 (no range, tag or URL): {version!r}"
        )


def build_package_request(name: str, version: str, packument: dict) -> dict:
    """Request to check one registry version without a lockfile: one added change, no base.

    The version's registry manifest must name this package and version, with a
    registry.npmjs.org tarball and dist.integrity. That integrity is registry metadata, not a hash
    of downloaded bytes. There is no lockfile, so the request has no lockfile hashes and is marked
    input_kind "package"; request_id is the digest of the checked content.
    """
    check_package_spec(name, version)
    where = f"npm registry metadata for {name}@{version}"
    if not isinstance(packument, dict):
        raise GuardError(f"{where} is not a JSON object")
    versions = packument.get("versions")
    # The analyzer reads both objects (baseline selection), so check their type here.
    if not isinstance(versions, dict) or not isinstance(packument.get("time"), dict):
        raise GuardError(f"{where} lacks versions or time objects")
    manifest = versions.get(version)
    if manifest is None:
        raise GuardError(f"npm registry does not serve {name}@{version}")
    if (
        not isinstance(manifest, dict)
        or manifest.get("name") != name
        or manifest.get("version") != version
    ):
        raise GuardError(f"{where} describes another package or version")
    dist = manifest.get("dist") if isinstance(manifest.get("dist"), dict) else {}
    for field in ("tarball", "integrity"):
        if not isinstance(dist.get(field), str) or not dist[field].strip():
            raise GuardError(f"{where} has no dist.{field}")
    after = {
        "name": name,
        "version": version,
        "resolved": dist["tarball"],
        "integrity": dist["integrity"],
        "link": False,
    }
    # Same rule as lockfile entries; with the checks above only the tarball source can fail it.
    if _unsupported(None, after):
        raise GuardError(f"{where} has a tarball outside https://{REGISTRY_LOCATION}")
    change = {"location": REGISTRY_LOCATION, "before": None, "after": after}
    request = {
        "schema_version": SCHEMA_VERSION,
        "input_kind": "package",
        "changes": [
            {
                "change_id": digest(change),
                **change,
                "kind": "added",
                "analyzable": True,
                "reason": None,
            }
        ],
    }
    return {"request_id": digest(request), **request}
