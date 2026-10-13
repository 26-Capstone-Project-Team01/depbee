"""Analyze changes with the team's feature-extractor. Package code is read, never executed.

For each analyzable change, the installed version is compared with its registry predecessor
(``baseline.select_baseline``), the same pairing the model was trained on. The lockfile's
previous version is kept only as context in the evidence.
"""

import importlib.metadata
from collections.abc import Callable
from pathlib import Path

from ..contracts import SCHEMA_VERSION, GuardError
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


class FeatureExtractorBackend:
    """The calls into feature-extractor, kept apart so tests can run without network access."""

    def __init__(self) -> None:
        try:
            from feature_extractor.core.errors import FeatureExtractorError
            from feature_extractor.core.loader import fetch_packument
            from feature_extractor.core.pipeline import build_row, resolve_extractors
            from feature_extractor.core.sources import (
                LocalArchiveSnapshotSource,
                RegistrySnapshotSource,
            )
        except ImportError as exc:
            raise GuardError(
                'Install analyzer dependencies: python -m pip install -e ".[extract]"'
            ) from exc
        self.errors = (FeatureExtractorError,)
        self.version = f"feature-extractor {importlib.metadata.version('feature-extractor')}"
        self.fetch_packument = fetch_packument
        self._build_row = build_row
        self._extractors = resolve_extractors(None)
        self._local_source = LocalArchiveSnapshotSource
        self._registry_source = RegistrySnapshotSource

    def extract(
        self, name: str, old: str, new: str, packument: dict, local: Path | None
    ) -> tuple[dict, dict]:
        """Return (features, package.json of the new version)."""
        registry = self._registry_source()
        try:
            new_source = self._local_source(local, packument) if local else registry
            # label is a dataset column; inference does not use it.
            row = self._build_row(
                name, old, new, 0, self._extractors, old_source=registry, new_source=new_source
            )
            new_json = (
                new_source.get_snapshot(name, new).package_json
                if local
                else packument["versions"][new]
            )
        finally:
            registry.close()
        return row.features, new_json


def _short(text: str) -> str:
    return text if len(text) <= _MAX_EVIDENCE_TEXT else text[:_MAX_EVIDENCE_TEXT] + "..."


def _integrity_tokens(value: object) -> set[str]:
    return set(value.split()) if isinstance(value, str) else set()


def _dependencies(manifest: dict) -> set[str]:
    return {d for field in DEPENDENCY_FIELDS for d in (manifest.get(field) or {})}


class ExtractorAnalyzer:
    """``Analyzer`` that runs feature-extractor in-process for each analyzable change.

    ``local_sources`` maps (package, version) to a directory holding a copy of that version
    (``.../package/package.json``), for versions the registry no longer serves. Such copies
    cannot be checked against the lockfile integrity, which the evidence states.
    ``progress``, if given, is called as ``progress(index, total, change)`` before each change.
    """

    def __init__(
        self,
        local_sources: dict[tuple[str, str], Path] | None = None,
        backend: FeatureExtractorBackend | None = None,
        progress: Callable[[int, int, dict], None] | None = None,
    ) -> None:
        self.backend = backend or FeatureExtractorBackend()
        self.local_sources = dict(local_sources or {})
        self.progress = progress
        self._packuments: dict[str, dict] = {}

    def analyze(self, request: dict) -> dict:
        changes = [c for c in request["changes"] if c["analyzable"]]
        wanted = {(c["after"]["name"], c["after"]["version"]) for c in changes}
        unused = sorted(set(self.local_sources) - wanted)
        if unused:
            # A typo would otherwise silently fall back to the registry.
            name, version = unused[0]
            raise GuardError(f"Local source matches no analyzable change: {name}@{version}")
        results = []
        for index, change in enumerate(changes, start=1):
            if self.progress:
                self.progress(index, len(changes), change)
            results.append({"change_id": change["change_id"], **self._analyze(change)})
        artifact = {
            "schema_version": SCHEMA_VERSION,
            "request_id": request["request_id"],
            "analyzer_version": self.backend.version,
            "feature_schema": FEATURE_SCHEMA,
            "results": results,
        }
        return validate(artifact, request)

    def _analyze(self, change: dict) -> dict:
        try:
            return self._analyze_change(change)
        except (GuardError, OSError, *self.backend.errors) as exc:
            return {"status": "failed", "error": str(exc) or type(exc).__name__}

    def _packument(self, name: str) -> dict:
        if name not in self._packuments:
            self._packuments[name] = self.backend.fetch_packument(name)
        return self._packuments[name]

    def _analyze_change(self, change: dict) -> dict:
        name, new = change["after"]["name"], change["after"]["version"]
        if not is_stable(new):
            return {
                "status": "unsupported",
                "reason": "out_of_training_scope",
                "error": f"{new} is a prerelease; the model was trained on stable versions only",
            }
        packument = self._packument(name)
        local = self.local_sources.get((name, new))
        if local is None:
            manifest = (packument.get("versions") or {}).get(new)
            if manifest is None:
                raise GuardError(f"Registry no longer serves {name}@{new}")
            registry = _integrity_tokens((manifest.get("dist") or {}).get("integrity"))
            if not registry & _integrity_tokens(change["after"]["integrity"]):
                raise GuardError("Lockfile integrity does not match the registry integrity")
        baseline = select_baseline(packument, new)
        if baseline is None:
            return {
                "status": "unsupported",
                "reason": "no_baseline",
                "error": f"No earlier stable version of {name} to compare {new} with",
            }
        features, new_json = self.backend.extract(name, baseline.version, new, packument, local)
        old_json = packument["versions"][baseline.version]
        return {
            "status": "complete",
            "baseline_version": baseline.version,
            "features": features,
            "evidence": self._evidence(change, baseline, local, old_json, new_json, features),
        }

    def _evidence(self, change, baseline, local, old_json, new_json, features) -> list[str]:
        new = change["after"]["version"]
        if baseline.level == "L1":
            line = "같은 release line의 직전 stable"
        else:
            line = "이전 release line의 최신 stable"
        evidence = [f"비교: {baseline.version} → {new} ({line})"]
        if change["before"] is None:
            evidence.append("lockfile에 새로 추가된 의존성")
        elif change["before"]["version"] != baseline.version:
            evidence.append(f"lockfile의 이전 버전은 {change['before']['version']}")
        if local:
            evidence.append("새 버전을 로컬 사본에서 읽음(registry 무결성 확인 안 함)")

        old_scripts = old_json.get("scripts") or {}
        new_scripts = new_json.get("scripts") or {}
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
