"""Analyze changes with the team's depbee-analyzer. Package code is read, never executed.

For each analyzable change, the installed version is compared with its registry predecessor
(``baseline.select_baseline``), the same pairing the model was trained on. The lockfile's
previous version is kept only as context in the evidence.
"""

import base64
import dataclasses
import hashlib
import importlib.metadata
import json
import ntpath
import os
import platform
import shlex
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from .. import __version__
from ..contracts import SCHEMA_VERSION, GuardError, digest, elapsed_since
from . import bounded, cache, registry
from .artifact import validate
from .baseline import is_stable, select_baseline

#: Features of depbee-analyzer's package_json (7) and obfuscation (22) extractors.
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
#: Same definitions as depbee-analyzer's package_json extractor.
INSTALL_SCRIPT_KEYS = ("preinstall", "install", "postinstall")
DEPENDENCY_FIELDS = ("dependencies", "optionalDependencies")

_MAX_EVIDENCE_TEXT = 120
_MAX_LISTED_DEPENDENCIES = 5


def _installed_identity() -> dict | None:
    """Provenance of the installed depbee-analyzer, or None if it cannot be verified.

    Verified: pip installed it from Git at exactly the commit that depbee's ``extract`` extra pins
    (direct_url.json; not editable, not a local folder) and every installed module still has the
    hash pip recorded. Only then are extracted features reused between runs (analysis.cache).
    """
    try:
        dist = importlib.metadata.distribution("depbee-analyzer")
        direct = json.loads(dist.read_text("direct_url.json") or "null")
        pins = importlib.metadata.requires("depbee") or []
    except (importlib.metadata.PackageNotFoundError, ValueError):
        return None
    vcs = direct.get("vcs_info") if isinstance(direct, dict) else None
    if not isinstance(vcs, dict) or vcs.get("vcs") != "git" or "dir_info" in direct:
        return None
    pinned = f"depbee-analyzer @ git+{direct.get('url')}@{vcs.get('commit_id')}"
    if pinned not in (pin.split(";")[0].strip() for pin in pins):
        return None
    recorded = {}
    for file in dist.files or []:
        if file.parts[0] != "depbee_analyzer" or file.hash is None:
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


def _with_this_python(requirement: str) -> str:
    """The end of an instruction: the command that installs requirement into the Python that
    runs this depbee, named by its own path. The depbee of an environment that is not activated
    is a supported way to run it (docs/usage.md), and there the shell's python can be another
    environment's: a bare "python -m pip" would install into that one. Each form takes a path
    with spaces or quotes. On Windows it is PowerShell's, the shell of the guides, where & calls
    a quoted path and a single quote inside one is doubled: PowerShell 5.1 and 7 read U+2018 to
    U+201B (the curly ones, as in a user name O'Brien typed with U+2019) as single quotes too.
    But & reads a path with [, ] or a backtick as a wildcard pattern (5.1 always, 7 when the file
    is missing) and can run another environment's python.exe. For such a path the command finds
    the file by name in the folder opened with -LiteralPath, goes back and calls what it found,
    so pip still runs where the user is (a relative requirement like .[extract] keeps its
    meaning). -ErrorAction Stop keeps a missing folder from finding the python.exe of the folder
    the user is in; Get-Command's own -ErrorAction Continue keeps a user's Stop preference from
    skipping Pop-Location. A file name with [, ] or a backtick is a pattern to every PowerShell
    lookup, escaped or not one way in 5.1 and the other in 7, so that one (never a real
    interpreter's) is given to Command Prompt, which takes a quoted path as it is.
    Elsewhere the POSIX shells' quoting."""
    python = sys.executable or "python"
    if os.name == "nt":

        def quote(text: str) -> str:
            return "'" + text.translate({ord(q): q * 2 for q in "'\u2018\u2019\u201a\u201b"}) + "'"

        install = f"-m pip install {quote(requirement)}"
        pattern = set("[]`")
        folder, name = ntpath.split(python)
        if pattern.isdisjoint(python):
            return f", in PowerShell: & {quote(python)} {install}"
        if pattern.isdisjoint(name):
            found = quote(".\\" + name)
            return (
                f", in PowerShell: & $(Push-Location -LiteralPath {quote(folder)} -ErrorAction Stop; "
                f"Get-Command {found} -ErrorAction Continue; Pop-Location) {install}"
            )
        return f', in Command Prompt (cmd): "{python}" -m pip install "{requirement}"'
    return f": {shlex.quote(python)} -m pip install {shlex.quote(requirement)}"


def _how_to_get_the_analyzer() -> str:
    """What a user without depbee-analyzer can do, said for the depbee at hand.

    In depbee's image (the variable its Dockerfile sets, as dashboard.mounted reads it) nothing
    can be installed: there is no pip and no source tree, so the answer is the default image.
    An installed depbee names the public commit its own metadata pins and its own interpreter:
    a command for any folder and any PATH. Only depbee run from a source tree, which has no
    metadata, is sent to the extra.
    """
    if os.environ.get("DEPBEE_CONTAINER_PROJECTS"):
        return (
            "This image has no depbee-analyzer: it was built with --target core. Build the "
            "default image in a depbee checkout instead: docker build -t depbee:local ."
        )
    try:
        pins = importlib.metadata.requires("depbee") or []
    except importlib.metadata.PackageNotFoundError:
        pins = []
    for pin in pins:
        if pin.startswith("depbee-analyzer @"):
            return (
                "depbee-analyzer is missing. Install the commit that this depbee pins into the "
                "Python that runs it" + _with_this_python(pin.split(";")[0].strip())
            )
    return (
        "depbee-analyzer is missing. In a depbee checkout, install it into the Python that "
        "runs depbee" + _with_this_python(".[extract]")
    )


class _RegistrySource:
    """depbee-analyzer SnapshotSource for registry versions, used instead of its
    RegistrySnapshotSource: the snapshot comes from the packument depbee checked (the pinned
    loader's public build_snapshot, which fetches nothing without include_source), and the source
    tree from depbee's checked download (analysis.registry), unpacked under work. depbee-analyzer's
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
    """The calls into depbee-analyzer, kept apart so tests can run without network access.

    Registry metadata and tarballs are downloaded by analysis.registry, never by
    depbee-analyzer, so its size, address and integrity checks apply to everything read. The
    metadata download and the extraction (both downloads, unpacking and feature extraction) run
    in child processes of analysis.bounded, killed when the change's time budget runs out.
    """

    def __init__(self) -> None:
        try:
            from depbee_analyzer.core.errors import FeatureExtractorError
            from depbee_analyzer.core.loader import build_snapshot
            from depbee_analyzer.core.pipeline import build_row, resolve_extractors
            from depbee_analyzer.core.sources import LocalArchiveSnapshotSource
        except ImportError as exc:
            raise GuardError(f"{_how_to_get_the_analyzer()} ({exc})") from exc
        self.errors = (
            FeatureExtractorError,
            registry.RegistryError,
            bounded.StepError,
            bounded.TimeLimitError,
        )
        self.version = f"depbee-analyzer {importlib.metadata.version('depbee-analyzer')}"
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
    """dist of a compared version. The analyzer reads dist.tarball without type
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
    """``Analyzer`` that runs depbee-analyzer in-process for each analyzable change.

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
    ``known_malicious``, if given, is the run's known malicious index (``known_malicious.load``):
    baseline candidates it lists or has in a bounded range are skipped (D-16), and the evidence
    says so. The cache key needs nothing more: it already holds the chosen baseline.
    """

    def __init__(
        self,
        local_sources: dict[tuple[str, str], Path] | None = None,
        backend: FeatureExtractorBackend | None = None,
        progress: Callable[[int, int, dict], None] | None = None,
        *,
        cache_dir: Path | None = None,
        cache_model=None,
        known_malicious=None,
    ) -> None:
        self.backend = backend or FeatureExtractorBackend()
        self.local_sources = dict(local_sources or {})
        self.progress = progress
        verified = isinstance(getattr(self.backend, "identity", None), dict) and isinstance(
            getattr(cache_model, "identity", None), dict
        )
        self.cache_dir = cache_dir if verified else None
        self.cache_model = cache_model
        self.known_malicious = known_malicious
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

        depbee's own code (downloads, unpacking, the calls into depbee-analyzer) is covered by
        its version, and within one version only by cache.FORMAT, which is raised by hand.

        Not the request, the lockfile's previous version or the location: the same compared pair
        yields the same features, and evidence about the request is rebuilt on every run.
        """
        versions, times = packument["versions"], packument["time"]
        return {
            "format": cache.FORMAT,
            "depbee": __version__,
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
        skipped: list[tuple[str, list[str]]] = []

        def known(version: str) -> bool:
            records = self.known_malicious.baseline_records(name, version)
            if records:
                skipped.append((version, records))
            return bool(records)

        baseline = select_baseline(packument, new, known if self.known_malicious else None)
        if baseline is None:
            excluded = "".join(f"; {v} skipped as known malicious ({', '.join(ids)})"
                               for v, ids in skipped)  # fmt: skip
            return {
                "status": "unsupported",
                "reason": "no_baseline",
                "error": f"No earlier stable version of {name} to compare {new} with{excluded}",
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
                change, baseline, local, old_json, new_json, features, package_input, skipped
            ),
        }
        # The parent parsed the metadata, read the cache, built the evidence and checks the
        # features itself; none of that is in a child, so the deadline is checked here.
        if key and not cache_hit and self._model_accepts(features):
            bounded.check()  # write nothing for a result already too late
            cache.store(self.cache_dir, key, features)  # checks again before publishing
        bounded.check()  # accept only a result finished in time: cold, cache hit or no cache
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
        self, change, baseline, local, old_json, new_json, features, package_input, skipped=()
    ) -> list[str]:
        new = change["after"]["version"]
        if baseline.level == "L1":
            line = "같은 release line의 직전 stable"
        else:
            line = "이전 release line의 최신 stable"
        evidence = [f"비교: {baseline.version} → {new} ({line})"]
        for version, records in skipped:  # D-16
            evidence.append(
                _short(f"비교 기준 후보에서 뺌: {version} (기지 악성 기록 {', '.join(records)})")
            )
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
