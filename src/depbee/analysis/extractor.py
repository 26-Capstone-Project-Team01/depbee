"""Analyze changes with the team's feature-extractor. Package code is read, never executed.

For each analyzable change, the installed version is compared with its registry predecessor
(``baseline.select_baseline``), the same pairing the model was trained on. The lockfile's
previous version is kept only as context in the evidence.
"""

import base64
import dataclasses
import hashlib
import importlib.metadata
import json
import platform
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from ..contracts import SCHEMA_VERSION, GuardError, digest, elapsed_since
from . import bounded, cache, registry
from .artifact import validate
from .baseline import is_stable, select_baseline

#: Features of feature-extractor's package_json (7) and obfuscation (22) extractors.
FEATURE_SCHEMA = "depbee-features-v1"
BOOLEAN_FEATURES = (
    "installScriptPresent",
    "installScriptAdded",
    "scriptEntryAdded",
    "newDependencyAdded",
)
CATEGORICAL_FEATURES = ("updateType",)
_OBF_METRICS = (
    "HexIdentRatio",
    "HexNumberRatio",
    "BracketAccessRatio",
    "EscapeDensity",
    "ShortIdentRatio",
    "MeanIdentLength",
    "WhitespaceRatio",
)
#: Empty in the training data when there is no file to measure (e.g. no changed JS).
NULLABLE_FEATURES = tuple(
    f"obf{metric}{part}" for metric in _OBF_METRICS for part in ("New", "Change", "ChangedCode")
)
#: Same definitions as feature-extractor's package_json extractor.
INSTALL_SCRIPT_KEYS = ("preinstall", "install", "postinstall")
DEPENDENCY_FIELDS = ("dependencies", "optionalDependencies")

_MAX_EVIDENCE_TEXT = 120
_MAX_LISTED_DEPENDENCIES = 5


def _installed_identity() -> dict | None:
    """Provenance of the installed feature-extractor, or None if it cannot be verified.

    Verified: pip installed it from Git at exactly the commit that depbee's ``extract`` extra pins
    (direct_url.json; not editable, not a local folder) and every installed module still has the
    hash pip recorded. Only then are extracted features reused between runs (analysis.cache).
    """
    try:
        dist = importlib.metadata.distribution("feature-extractor")
        direct = json.loads(dist.read_text("direct_url.json") or "null")
        pins = importlib.metadata.requires("depbee") or []
    except (importlib.metadata.PackageNotFoundError, ValueError):
        return None
    vcs = direct.get("vcs_info") if isinstance(direct, dict) else None
    if not isinstance(vcs, dict) or vcs.get("vcs") != "git" or "dir_info" in direct:
        return None
    pinned = f"feature-extractor @ git+{direct.get('url')}@{vcs.get('commit_id')}"
    if pinned not in (pin.split(";")[0].strip() for pin in pins):
        return None
    recorded = {}
    for file in dist.files or []:
        if file.parts[0] != "feature_extractor" or file.hash is None:
            continue
        try:
            data = Path(dist.locate_file(file)).read_bytes()
        except OSError:
            return None
        actual = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if file.hash.mode != "sha256" or actual != file.hash.value:
            return None  # changed after install
        recorded[file.as_posix()] = file.hash.value
    if not recorded:
        return None
    return {
        "commit": vcs["commit_id"],
        "url": direct["url"],
        "files_sha256": digest(recorded),
        "python": platform.python_version(),  # tarfile and re behaviour can change between them
    }


class _RegistrySource:
    """feature-extractor SnapshotSource for registry versions, used instead of its
    RegistrySnapshotSource: the snapshot comes from the packument depbee checked (the pinned
    loader's public build_snapshot, which fetches nothing without include_source), and the source
    tree from depbee's checked download (analysis.registry), unpacked under work. feature-extractor's
    build_row uses only get_snapshot of the sources it is given."""

    def __init__(self, packument: dict, build_snapshot: Callable, work: Path) -> None:
        self._packument = packument
        self._build_snapshot = build_snapshot
        self._work = work

    def get_snapshot(self, package: str, version: str, *, include_source: bool = False):
        snapshot = self._build_snapshot(self._packument, package, version)
        if not include_source:
            return snapshot
        data = registry.tarball(package, version, self._packument["versions"][version]["dist"])
        target = Path(tempfile.mkdtemp(prefix="version_", dir=self._work))
        source = registry.unpack(data, target, f"{package}@{version} tarball")
        return dataclasses.replace(snapshot, source_dir=source)


class FeatureExtractorBackend:
    """The calls into feature-extractor, kept apart so tests can run without network access.

    Registry metadata and tarballs are downloaded by analysis.registry, never by
    feature-extractor, so its size, address and integrity checks apply to everything read. The
    metadata download and the extraction (both downloads, unpacking and feature extraction) run
    in child processes of analysis.bounded, killed when the change's time budget runs out.
    """

    def __init__(self) -> None:
        try:
            from feature_extractor.core.errors import FeatureExtractorError
            from feature_extractor.core.loader import build_snapshot
            from feature_extractor.core.pipeline import build_row, resolve_extractors
            from feature_extractor.core.sources import LocalArchiveSnapshotSource
        except ImportError as exc:
            raise GuardError(
                'Install analyzer dependencies: python -m pip install -e ".[extract]"'
            ) from exc
        self.errors = (
            FeatureExtractorError,
            registry.RegistryError,
            bounded.StepError,
            bounded.TimeLimitError,
        )
        self.version = f"feature-extractor {importlib.metadata.version('feature-extractor')}"
        self.identity = _installed_identity()
        self.fetch_packument = registry.packument
        self._build_snapshot = build_snapshot
        self._build_row = build_row
        self._extractors = resolve_extractors(None)
        self._local_source = LocalArchiveSnapshotSource

    def extract(
        self, name: str, old: str, new: str, packument: dict, local: Path | None
    ) -> tuple[dict, dict]:
        """Return (features, package.json of the new version), both from the given packument.

        Both manifests and their dist objects must already be checked (ExtractorAnalyzer does).
        Runs in a bounded child process; only the two versions' manifests and publish times are
        sent. The work folder is the caller's, so it is removed even when the child is killed.
        """
        compared = [v for v in (old, new) if v in packument["versions"]]  # new may be local only
        slim = {
            "versions": {v: packument["versions"][v] for v in compared},
            "time": {v: packument["time"][v] for v in (old, new) if v in packument["time"]},
        }
        with tempfile.TemporaryDirectory(prefix="depbee_src_", ignore_cleanup_errors=True) as work:
            features, new_json = bounded.run(
                self._extract_here, (name, old, new, slim, local, Path(work))
            )
        return features, new_json

    def _extract_here(
        self, name: str, old: str, new: str, packument: dict, local: Path | None, work: Path
    ) -> tuple[dict, dict]:
        source = _RegistrySource(packument, self._build_snapshot, work)
        new_source = self._local_source(local, packument) if local else source
        # label is a dataset column; inference does not use it.
        row = self._build_row(
            name, old, new, 0, self._extractors, old_source=source, new_source=new_source
        )
        new_json = (
            new_source.get_snapshot(name, new).package_json if local else packument["versions"][new]
        )
        return row.features, new_json


def _short(text: str) -> str:
    return text if len(text) <= _MAX_EVIDENCE_TEXT else text[:_MAX_EVIDENCE_TEXT] + "..."


def _integrity_tokens(value: object) -> set[str]:
    return set(value.split()) if isinstance(value, str) else set()


def _object(value: object, label: str) -> dict:
    """Registry data is untrusted: a non-object fails the analysis instead of crashing it."""
    if not value:
        return {}
    if not isinstance(value, dict):
        raise GuardError(f"Registry metadata {label} is not an object")
    return value


def _dist(packument: dict, name: str, version: str) -> dict:
    """dist of a compared version. feature-extractor c24761d reads dist.tarball without type
    checks (loader.py:100), so a malformed manifest must fail before it is called."""
    manifest = packument["versions"][version]
    if not isinstance(manifest, dict):
        raise GuardError(f"Registry metadata of {name}@{version} is not an object")
    if not isinstance(manifest.get("dist"), dict):
        raise GuardError(f"Registry metadata of {name}@{version} has no dist object")
    return manifest["dist"]


def _dependencies(manifest: dict) -> set[str]:
    return {d for field in DEPENDENCY_FIELDS for d in _object(manifest.get(field), field)}


class ExtractorAnalyzer:
    """``Analyzer`` that runs feature-extractor in-process for each analyzable change.

    ``local_sources`` maps (package, version) to a directory holding a copy of that version
    (``.../package/package.json``), for versions the registry no longer serves. Such copies
    cannot be checked against the lockfile integrity, which the evidence states.
    ``progress``, if given, is called as ``progress(index, total, change)`` before each change.
    ``cache_dir`` enables the persistent feature cache (``analysis.cache``) for registry versions,
    used only together with ``cache_model``, the verified model (its ``identity`` hashes are part
    of the key, and its ``encode`` must accept cached and newly stored features), and a backend
    whose installed provenance is verified (``backend.identity``); otherwise nothing is read or
    written. After ``analyze()``, ``measurements`` maps each analyzed change_id to (elapsed seconds
    on the monotonic clock for metadata, cache and extraction, whether the cache supplied the
    features).
    """

    def __init__(
        self,
        local_sources: dict[tuple[str, str], Path] | None = None,
        backend: FeatureExtractorBackend | None = None,
        progress: Callable[[int, int, dict], None] | None = None,
        *,
        cache_dir: Path | None = None,
        cache_model=None,
    ) -> None:
        self.backend = backend or FeatureExtractorBackend()
        self.local_sources = dict(local_sources or {})
        self.progress = progress
        verified = isinstance(getattr(self.backend, "identity", None), dict) and isinstance(
            getattr(cache_model, "identity", None), dict
        )
        self.cache_dir = cache_dir if verified else None
        self.cache_model = cache_model
        self.measurements: dict[str, tuple[float, bool]] = {}
        self._packuments: dict[str, dict] = {}

    def analyze(self, request: dict) -> dict:
        changes = [c for c in request["changes"] if c["analyzable"]]
        wanted = {(c["after"]["name"], c["after"]["version"]) for c in changes}
        unused = sorted(set(self.local_sources) - wanted)
        if unused:
            # A typo would otherwise silently fall back to the registry.
            name, version = unused[0]
            raise GuardError(f"Local source matches no analyzable change: {name}@{version}")
        # A package request (check) has no lockfile; the evidence must not mention one.
        package_input = request.get("input_kind") == "package"
        results = []
        for index, change in enumerate(changes, start=1):
            if self.progress:
                self.progress(index, len(changes), change)
            started = time.monotonic()
            with bounded.budget():  # one time budget per change (check: the service's)
                result, cache_hit = self._analyze(change, package_input)
            self.measurements[change["change_id"]] = (elapsed_since(started), cache_hit)
            results.append({"change_id": change["change_id"], **result})
        artifact = {
            "schema_version": SCHEMA_VERSION,
            "request_id": request["request_id"],
            "analyzer_version": self.backend.version,
            "feature_schema": FEATURE_SCHEMA,
            "results": results,
        }
        return validate(artifact, request)

    def _analyze(self, change: dict, package_input: bool) -> tuple[dict, bool]:
        try:
            return self._analyze_change(change, package_input)
        except (GuardError, OSError, *self.backend.errors) as exc:
            return {"status": "failed", "error": str(exc) or type(exc).__name__}, False

    def packument(self, name: str) -> dict:
        """Registry metadata of name, fetched once per analyzer and reused by later calls.

        Raises GuardError unless it is an object with versions and time objects, the rule of
        inputs.npm.build_package_request; the analysis reads both without further type checks.
        """
        if name not in self._packuments:
            packument = self.backend.fetch_packument(name)
            if not isinstance(packument, dict):
                raise GuardError(f"npm registry metadata for {name} is not a JSON object")
            if not isinstance(packument.get("versions"), dict) or not isinstance(
                packument.get("time"), dict
            ):
                raise GuardError(f"npm registry metadata for {name} lacks versions or time objects")
            self._packuments[name] = packument
        return self._packuments[name]

    def _cache_key(self, name: str, new: str, baseline: str, packument: dict) -> dict:
        """Everything the features depend on; any change makes a new key (a miss).

        Not the request, the lockfile's previous version or the location: the same compared pair
        yields the same features, and evidence about the request is rebuilt on every run.
        """
        versions, times = packument["versions"], packument["time"]
        return {
            "format": cache.FORMAT,
            "feature_schema": FEATURE_SCHEMA,
            "extractor": self.backend.identity,
            "model": self.cache_model.identity,
            "package": name,
            "version": new,
            "baseline": baseline,
            "integrity": [versions[baseline]["dist"].get("integrity"),
                          versions[new]["dist"].get("integrity")],  # fmt: skip
            "manifests": digest([versions[baseline], versions[new]]),
            "time": [times.get(baseline), times.get(new)],
        }

    def _analyze_change(self, change: dict, package_input: bool) -> tuple[dict, bool]:
        name, new = change["after"]["name"], change["after"]["version"]
        if not is_stable(new):
            return {
                "status": "unsupported",
                "reason": "out_of_training_scope",
                "error": f"{new} is a prerelease; the model was trained on stable versions only",
            }, False
        packument = self.packument(name)
        local = self.local_sources.get((name, new))
        if local is None:
            if (packument.get("versions") or {}).get(new) is None:
                raise GuardError(f"Registry no longer serves {name}@{new}")
            # The tarball is later checked against this registry integrity (analysis.registry).
            published = _integrity_tokens(_dist(packument, name, new).get("integrity"))
            if not published & _integrity_tokens(change["after"]["integrity"]):
                raise GuardError("Lockfile integrity does not match the registry integrity")
        baseline = select_baseline(packument, new)
        if baseline is None:
            return {
                "status": "unsupported",
                "reason": "no_baseline",
                "error": f"No earlier stable version of {name} to compare {new} with",
            }, False
        _dist(packument, name, baseline.version)
        # Local copies are never cached: the key cannot bind files outside the registry.
        key = None
        if self.cache_dir is not None and local is None:
            key = self._cache_key(name, new, baseline.version, packument)
        features = cache.load(self.cache_dir, key) if key else None
        if features is not None and not self._model_accepts(features):
            features = None  # damaged or foreign entry: extract again
        cache_hit = features is not None
        if cache_hit:
            new_json = packument["versions"][new]
        else:
            features, new_json = self.backend.extract(name, baseline.version, new, packument, local)
        old_json = packument["versions"][baseline.version]
        result = {
            "status": "complete",
            "baseline_version": baseline.version,
            "features": features,
            "evidence": self._evidence(
                change, baseline, local, old_json, new_json, features, package_input
            ),
        }
        # The parent parsed the metadata, read the cache and built the evidence after the last
        # child step (a cache hit has none): a result finished past the budget is not used.
        bounded.check()
        if key and not cache_hit and self._model_accepts(features):
            cache.store(self.cache_dir, key, features)
        return result, cache_hit

    def _model_accepts(self, features: dict) -> bool:
        """Whether the cache model scores these features. Missing or wrongly typed features are
        not reused or stored, and neither are unsupported ones (an unseen category, an
        OutOfScopeError): the plan keeps failed and unsupported results out of the cache."""
        try:
            self.cache_model.encode(features)
        except GuardError:  # includes OutOfScopeError
            return False
        return True

    def _evidence(
        self, change, baseline, local, old_json, new_json, features, package_input
    ) -> list[str]:
        new = change["after"]["version"]
        if baseline.level == "L1":
            line = "같은 release line의 직전 stable"
        else:
            line = "이전 release line의 최신 stable"
        evidence = [f"비교: {baseline.version} → {new} ({line})"]
        if package_input:
            evidence.append("lockfile 없이 registry 정보로 검사")
        elif change["before"] is None:
            evidence.append("lockfile에 새로 추가된 의존성")
        elif change["before"]["version"] != baseline.version:
            evidence.append(f"lockfile의 이전 버전은 {change['before']['version']}")
        if local:
            evidence.append("새 버전을 로컬 사본에서 읽음(registry 무결성 확인 안 함)")

        if not isinstance(old_json, dict) or not isinstance(new_json, dict):
            raise GuardError("Registry metadata of a compared version is not an object")
        old_scripts = _object(old_json.get("scripts"), "scripts")
        new_scripts = _object(new_json.get("scripts"), "scripts")
        for key in INSTALL_SCRIPT_KEYS:
            if key in new_scripts and key not in old_scripts:
                evidence.append(_short(f"설치 스크립트 추가: {key} = {new_scripts[key]}"))

        added = sorted(_dependencies(new_json) - _dependencies(old_json))
        if added:
            listed = ", ".join(added[:_MAX_LISTED_DEPENDENCIES])
            more = len(added) - _MAX_LISTED_DEPENDENCIES
            suffix = f" 외 {more}개" if more > 0 else ""
            evidence.append(_short(f"새 의존성 {len(added)}개: {listed}{suffix}"))
        evidence.append(f"추가·수정된 JS 파일 {features.get('obfChangedFileCount')}개")
        return evidence
