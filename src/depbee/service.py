"""Shared entry point for the CLI and later Actions, MCP and dashboard: assembly only.

Detection and verdicts stay in pipeline.scan(); output formats and exit handling stay with callers.
"""

import contextlib
import hashlib
import json
import os
import secrets
import shutil
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from . import __version__, bundled, config
from .analysis import bounded, cache
from .analysis.artifact import ArtifactAnalyzer
from .contracts import GuardError, elapsed_since, parse_json
from .inference.lightgbm import LightGBMPredictor
from .inputs import npm_cli
from .inputs.npm import (
    EXACT_VERSION,
    PACKAGE_NAME,
    build_package_request,
    build_request,
    check_package_spec,
    read_dependencies,
)
from .known_malicious import load
from .pipeline import scan

NPMRC_NOTICE = "프로젝트 .npmrc는 복사하지 않았습니다. 사용자·전역 npm 설정은 적용될 수 있습니다."
PREVIEW_NOTICE = "미리보기만 했고 프로젝트 파일은 아무것도 바꾸지 않았습니다."
APPLY_MODES = ("lockfile", "install")
# Fixed apply notices (apply_update); no package text and no path, the backup has its own field.
UNCHANGED_NOTICE = "프로젝트 파일은 바꾸지 않았습니다."
LOCKFILE_NOTICE = "lockfile만 반영했고 node_modules는 설치하지 않았습니다."
SCRIPTS_NOTICE = (
    "설치 스크립트는 실행하지 않았습니다(npm ci --ignore-scripts). 설치 스크립트가 필요한 "
    "패키지는 검토한 뒤 직접 npm rebuild를 실행합니다."
)
NPMRC_INSTALL_NOTICE = (
    "프로젝트 .npmrc가 있어 설치하지 않았습니다. lockfile만 반영한 뒤 .npmrc를 직접 검토하고 "
    "npm ci --ignore-scripts로 설치합니다."
)
RESTORE_NOTICE = (
    "depbee는 자동으로 되돌리지 않습니다. 되돌리려면 백업 폴더의 package.json과 "
    "package-lock.json을 프로젝트에 복사하고, 설치한 node_modules도 되돌리려면 그 뒤 "
    "npm ci --ignore-scripts를 실행합니다."
)
# depbee guard ci (install_checked): changes analyzed per call, as for the MCP tools.
GUARD_MAX_PACKAGES = 20
GUARD_CHANGED = (
    "package-lock.json or Git HEAD changed while depbee checked the project; nothing was "
    "installed. Run depbee guard ci again"
)
GUARD_MISMATCH = (
    "The check's report does not match the planned lockfile changes; nothing was installed"
)
# The environment variable of each asset folder (_sources), by its settings key, model first.
ASSET_VARIABLES = {
    "model_dir": "DEPBEE_MODEL_DIR", "known_malicious_dir": "DEPBEE_KNOWN_MALICIOUS_DIR",
}  # fmt: skip


def list_dependencies(project: Path, *, declared: bool = False) -> list[dict]:
    """The project's installed dependencies from package-lock.json, without npm or the network:
    [{location, name, version, direct}] (inputs.npm.read_dependencies). declared: each row also
    gets "declared", the root entry's dependency fields that name it. Raises GuardError, OSError
    or ValueError for a missing or invalid lockfile, as a scan would."""
    return read_dependencies(project, declared=declared)


def plan_project(
    project: Path, base_lock: Path | None = None, *, base_ref: str | None = None,
    git_dir: Path | None = None,
) -> dict:  # fmt: skip
    """Changed version pairs between the base lockfile and project/package-lock.json.

    The base is base_lock, else project/package-lock.json in Git base_ref (default HEAD), read
    from the repository Git finds for project or, given git_dir, from that Git folder alone
    (inputs.git.read_base_lock).
    """
    return build_request(project, base_lock, base_ref=base_ref, git_dir=git_dir)


def _local_sources(
    specs: list[str], extract: bool, root: Path | None
) -> dict[tuple[str, str], Path]:
    if not specs:
        return {}
    if not extract or root is None:
        raise GuardError("--local-source requires --extract and --local-root")
    root = root.resolve()
    sources = {}
    for spec in specs:
        target, separator, directory = spec.partition("=")
        name, at, version = target.rpartition("@")
        if not separator or not at or not name or not version or not directory:
            raise GuardError(f"--local-source must look like NAME@VERSION=DIR: {spec}")
        path = (root / directory).resolve()
        if not path.is_relative_to(root) or not path.is_dir():
            raise GuardError(f"--local-source directory must exist under --local-root: {spec}")
        if (name, version) in sources:
            raise GuardError(f"Duplicate --local-source: {name}@{version}")
        sources[(name, version)] = path
    return sources


def scan_project(
    project: Path,
    base_lock: Path | None = None,
    *,
    base_ref: str | None = None,
    analysis: Path | None = None,
    extract: bool = False,
    local_sources: list[str] | None = None,
    local_root: Path | None = None,
    model_dir: Path | None = None,
    progress: Callable[[int, int, dict], None] | None = None,
    cache_dir: Path | None = None,
    no_cache: bool = False,
    known_malicious_dir: Path | None = None,
    git_dir: Path | None = None,
    strict_sources: bool = False,
) -> dict:
    """Build the request, pick the analyzer and model, and return the pipeline.scan() report.

    base_lock, base_ref, git_dir: the base lockfile, as in plan_project().
    analysis: trusted precomputed analysis JSON. extract: run depbee-analyzer instead.
    local_sources: NAME@VERSION=DIR specs under local_root (extract only).
    model_dir: trusted model directory. If None, DEPBEE_MODEL_DIR is read on each call, and if
    that is empty or unset, the folder saved by depbee setup, else the model shipped with depbee
    (_sources). A bad path is an error and never falls back to another model.
    known_malicious_dir: trusted known malicious index folder (known_malicious.load), read right
    after the model. If None, DEPBEE_KNOWN_MALICIOUS_DIR is read on each call, then the folder
    saved by depbee setup, then the index shipped with depbee. A bad index is an error, never
    "no index" and never another index. The same index is matched against the changes and, with
    extract, keeps known malicious versions out of the baseline candidates (D-16). The saved
    settings are read once for the call, so its model and index are those of one saved setup.
    progress: called per extracted package; the caller decides how to show it.
    cache_dir, no_cache: the extracted-feature cache (default ~/.cache/depbee); see _cache_dir().
    With extract=True the report also has elapsed_seconds (in total and per result) and cache_hit.
    With extract=False, progress, local_root and the cache options are ignored, and any
    local_sources raise GuardError.
    strict_sources (extract only, install_checked): the analyzer also fails a change whose
    lockfile entry and analyzed registry dist do not name the same tarball URL and single
    sha512 digest (ExtractorAnalyzer strict_sources). False leaves every call as it was.

    Raises GuardError, OSError, ValueError or RecursionError for bad options or invalid inputs
    (lockfiles, analysis, model); the caller maps them to its error output.
    """
    started = time.monotonic()
    # Intended error priority: option conflict before reading lockfiles, local sources after.
    if analysis and extract:
        raise GuardError("Use either an analysis file or extraction, not both")
    request = plan_project(project, base_lock, base_ref=base_ref, git_dir=git_dir)
    sources = _local_sources(local_sources or [], extract, local_root)
    predictor, detectors = _assets(model_dir, known_malicious_dir)
    if not extract:
        analyzer = ArtifactAnalyzer(analysis) if analysis else None
        return scan(request, analyzer, predictor, **detectors)
    from .analysis.extractor import ExtractorAnalyzer

    strict = {"strict_sources": True} if strict_sources else {}
    analyzer = ExtractorAnalyzer(
        sources, progress=progress, **_cache_options(predictor, cache_dir, no_cache), **detectors,
        **strict,
    )  # fmt: skip
    report = scan(request, analyzer, predictor, **_with_rules(detectors, analyzer))
    return _timed(report, analyzer, started)


def _with_rules(detectors: dict, analyzer) -> dict:
    """detectors with the analyzer's static rules (analysis.rules: run on the pairs it unpacks),
    if it has them. Like the index (_assets), a detector that is not there is no keyword, so a
    caller's own detector (as in tests) is not replaced by None. A stand-in analyzer without a
    ruleset version (a mock) has none."""
    found = getattr(analyzer, "rules", None)
    if isinstance(getattr(found, "ruleset_version", None), str):
        return {**detectors, "rules": found}
    return detectors


def _assets(
    model_dir: Path | None, known_malicious_dir: Path | None
) -> tuple[LightGBMPredictor | None, dict]:
    """The model and the known malicious index of one request: (the predictor or None, the
    known_malicious keyword for scan() and ExtractorAnalyzer), each from its _sources() folder.

    The model is loaded first, then the index. Without an index the keyword is empty: scan() and
    ExtractorAnalyzer are then called exactly as before (a caller's own detector, as in tests,
    is not replaced by None)."""
    predictor, index = (
        _load(key, source, folder) if source else None
        for key, (source, folder) in _sources(model_dir, known_malicious_dir).items()
    )
    return predictor, ({"known_malicious": index} if index is not None else {})


def _sources(
    model_dir: Path | None, known_malicious_dir: Path | None
) -> dict[str, tuple[str | None, Path | None]]:
    """Where each asset of one request comes from: {key: (source, folder)}, model first.

    The folder given ("option"), else its environment variable read on this call ("environment";
    empty counts as unset), else the one `depbee setup` saved for the user ("saved"), else the
    one shipped with depbee ("bundled"). Each asset on its own: saved settings that name only
    one of the two leave the other to the shipped one. The first source that names a folder is
    the only one used. If what it names is gone or does not load, that is an error and never a
    reason to use the next source: a model or an index is not replaced by another without a
    word. (None, None) only where depbee has no shipped folder for the asset.

    The saved settings are read once, and only if a folder is still missing, so the model and
    the index of one request are those of one saved setup even if a depbee setup replaces the
    file meanwhile. The next request reads them again. Never read from the project being checked
    or the current folder."""
    given = {"model_dir": model_dir, "known_malicious_dir": known_malicious_dir}
    found, saved = {}, None
    for key, variable in ASSET_VARIABLES.items():
        if given[key] is not None:
            found[key] = ("option", Path(given[key]))
        elif os.environ.get(variable):
            found[key] = ("environment", Path(os.environ[variable]))
        else:
            if saved is None:
                saved = config.load() or {}
            if saved.get(key):
                found[key] = ("saved", Path(saved[key]))
            elif key in bundled.DIRS:
                found[key] = ("bundled", bundled.DIRS[key])
            else:
                found[key] = (None, None)
    return found


def _load(key: str, source: str, folder: Path):
    """One asset as every scan loads it: the predictor of a model folder, or the index of a
    known malicious folder. The shipped one must also be the released files (bundled.load)."""
    loader = LightGBMPredictor if key == "model_dir" else load
    return bundled.load(key, loader) if source == "bundled" else loader(folder)


def active_assets(
    model_dir: Path | None = None, known_malicious_dir: Path | None = None
) -> dict:
    """The model and the index a scan given these folders would use now, for an entry point to
    show: {"model_dir": {source, folder, version, error}, "known_malicious_dir": {...}}.

    source is "option", "environment", "saved" or "bundled" (_sources), or None with no asset.
    Each asset is loaded as a scan loads it, so version (the model's model_id, the index's
    list_as_of) is that of files that passed every check. One that does not load has version
    None and error, the message a scan would stop with. Nothing is saved or changed.

    Raises GuardError for settings that cannot be read, as a scan does."""
    active = {}
    for key, (source, folder) in _sources(model_dir, known_malicious_dir).items():
        version = error = None
        if source:
            try:
                asset = _load(key, source, folder)
                version = asset.model_id if key == "model_dir" else asset.list_as_of
            except (OSError, ValueError, RecursionError) as exc:  # as cli.main() reports them
                error = str(exc) or type(exc).__name__
        active[key] = {
            "source": source, "folder": folder and str(folder), "version": version,
            "error": error,
        }  # fmt: skip
    return active


def setup_assets(assets_dir: Path) -> dict:
    """Save assets_dir as the user's trusted asset folder for every later command.

    assets_dir/model (model.txt, manifest.json) and assets_dir/index (index.json,
    manifest.json) are each loaded here as a scan loads them. A subfolder whose name is not
    there is saved as null, which leaves that asset to the one shipped with depbee (_sources);
    at least one must exist. Nothing is saved, and the settings of an earlier setup stay, if one
    fails to load (GuardError, OSError or ValueError, as from a scan) or if its name is taken by
    something that is no folder (a file, a broken link): that is a damaged asset folder, not one
    without that asset. Nothing is downloaded.
    Returns config.save()'s settings with model_id and list_as_of (None for a null folder).
    """
    root = Path(os.path.abspath(assets_dir))
    found = {}
    for key, name in config.LAYOUT.items():
        if (root / name).is_dir():
            found[key] = root / name
        elif os.path.lexists(root / name):
            raise GuardError(
                f"{root / name} is not a folder (a file or a broken link has its name); "
                "nothing was saved"
            )
    if not found:
        raise GuardError(
            f"No model or index folder in {root}: expected model/ (model.txt, manifest.json) "
            "and index/ (index.json, manifest.json)"
        )
    model, index = found.get("model_dir"), found.get("known_malicious_dir")
    model_id = LightGBMPredictor(model).model_id if model else None
    list_as_of = load(index).list_as_of if index else None
    return {**config.save(root, model, index), "model_id": model_id, "list_as_of": list_as_of}


def _cache_options(predictor, cache_dir: Path | None, no_cache: bool) -> dict:
    """ExtractorAnalyzer cache options; none without a verified model or with no_cache.

    The analyzer also requires verified depbee-analyzer provenance before it uses the cache.
    """
    if no_cache or not isinstance(getattr(predictor, "identity", None), dict):
        return {}
    if cache_dir is None:
        try:
            cache_dir = cache.default_dir()
        except RuntimeError:  # no home directory: run without the cache
            return {}
    return {"cache_dir": cache_dir, "cache_model": predictor}


def _timed(report: dict, analyzer, started: float, fetched: dict | None = None) -> dict:
    """Add extraction times: per result (null and false if not analyzed) and for the whole call.

    fetched: seconds spent on a result's metadata before analyze() (check), added to its time.
    """
    for row in report["results"]:
        seconds, hit = analyzer.measurements.get(row["change_id"], (None, False))
        if seconds is not None:
            seconds = round(seconds + (fetched or {}).get(row["change_id"], 0.0), 3)
        row["elapsed_seconds"], row["cache_hit"] = seconds, hit
    results = report.pop("results")
    return {**report, "elapsed_seconds": elapsed_since(started), "results": results}


def check_package(
    name: str,
    version: str,
    *,
    model_dir: Path | None = None,
    progress: Callable[[int, int, dict], None] | None = None,
    cache_dir: Path | None = None,
    no_cache: bool = False,
    known_malicious_dir: Path | None = None,
) -> dict:
    """Check one npm registry version without a lockfile and return the pipeline.scan() report.

    name, version: an exact registry name (scoped or not) and version, checked before any
    network access. The version is compared with its stable predecessor, as in scan --extract.
    The registry metadata is fetched once and used for both the request and the analysis; the
    downloaded tarballs are checked against its dist.integrity (analysis.registry).
    model_dir, progress, cache_dir, no_cache, known_malicious_dir: as in scan_project(). The
    model and then the index are loaded before the registry is read. The report has the elapsed_seconds and cache_hit of scan --extract.

    Raises GuardError, OSError or ValueError for an invalid name or version, unreadable or
    invalid registry metadata, or a bad model; the caller maps them to its error output.
    """
    started = time.monotonic()
    check_package_spec(name, version)
    from .analysis.extractor import ExtractorAnalyzer

    predictor, detectors = _assets(model_dir, known_malicious_dir)
    analyzer = ExtractorAnalyzer(
        progress=progress, **_cache_options(predictor, cache_dir, no_cache), **detectors
    )
    # The metadata read and the analysis of the one change share its time budget.
    with bounded.budget():
        fetch_started = time.monotonic()
        try:
            packument = analyzer.packument(name)
        except analyzer.backend.errors as exc:
            raise GuardError(f"Cannot read npm registry metadata for {name}: {exc}") from exc
        fetched = elapsed_since(fetch_started)
        request = build_package_request(name, version, packument)
        # The one change's metadata was read before analyze(); count it in that result's time.
        report = scan(request, analyzer, predictor, **_with_rules(detectors, analyzer))
    return _timed(report, analyzer, started, {request["changes"][0]["change_id"]: fetched})


def preview_update(
    project: Path,
    packages: list[str] | None = None,
    *,
    model_dir: Path | None = None,
    progress: Callable[[int, int, dict], None] | None = None,
    cache_dir: Path | None = None,
    no_cache: bool = False,
    known_malicious_dir: Path | None = None,
) -> dict:
    """Preview npm update in a temporary copy and check the lockfile it would write.

    packages: bare package.json dependency names; None or empty updates everything, always
    within the package.json ranges. Only package.json and package-lock.json are copied (never
    the project's .npmrc) and npm runs there with --package-lock-only --ignore-scripts; the
    project itself is only read. The new lockfile is checked against the project's current one
    with scan_project(extract=True), whose report is returned unchanged next to a preview:
    {preview: {targets, npm_version, package_json_sha256, package_lock_sha256,
    new_package_lock_sha256, package_json_changed, changed_count, project_npmrc_ignored,
    notices}, report}. targets is null for everything.
    model_dir, progress, cache_dir, no_cache, known_malicious_dir: as in scan_project() (the model
    and the index are read after npm, as the scan of the new lockfile reads them).

    Raises GuardError, OSError or ValueError for unsupported projects, invalid names, npm
    failures and the errors of scan_project(); the caller maps them to its error output. Errors
    about the temporary folder or the files in it never name its path, and a folder that cannot
    be created or removed is a GuardError.
    """
    result, _, _ = _preview(
        project, packages, model_dir=model_dir, progress=progress, cache_dir=cache_dir,
        no_cache=no_cache, known_malicious_dir=known_malicious_dir,
    )  # fmt: skip
    return result


def preview_files(
    project: Path,
    packages: list[str] | None = None,
    *,
    model_dir: Path | None = None,
    progress: Callable[[int, int, dict], None] | None = None,
    cache_dir: Path | None = None,
    no_cache: bool = False,
    known_malicious_dir: Path | None = None,
) -> tuple[dict, bytes, bytes]:
    """preview_update()'s {preview, report} and the new package.json and lockfile bytes, for a
    caller that keeps them in memory and applies them later with apply_preview() (the
    dashboard). Same arguments, preview, report and errors as preview_update(); the bytes are
    never written to a file here.
    """
    return _preview(
        project, packages, model_dir=model_dir, progress=progress, cache_dir=cache_dir,
        no_cache=no_cache, known_malicious_dir=known_malicious_dir,
    )  # fmt: skip


def _preview(
    project: Path, packages: list[str] | None, **scan_options
) -> tuple[dict, bytes, bytes]:
    """preview_update()'s result and the new package.json and lockfile bytes, in memory only:
    they leave the temporary folder as values, never as files."""
    names = list(packages or [])
    package_bytes, lock_bytes, package = npm_cli.read_project(project)
    npm_cli.check_names(names, package)
    npmrc = os.path.lexists(project / ".npmrc")
    try:
        folder = tempfile.TemporaryDirectory(prefix="depbee_preview_")
    except OSError as exc:  # its message would name the folder
        raise GuardError(
            f"The temporary preview folder could not be created ({type(exc).__name__})"
        ) from None
    try:
        with folder as tmp:
            work, base = Path(tmp) / "project", Path(tmp) / "base-package-lock.json"
            try:
                work.mkdir()
                # The bytes hashed below are the bytes npm and the scan see, even if the project
                # changes meanwhile.
                (work / "package.json").write_bytes(package_bytes)
                (work / "package-lock.json").write_bytes(lock_bytes)
                base.write_bytes(lock_bytes)
                npm_version = npm_cli.update_lock(work, names)
                new_package = (work / "package.json").read_bytes()
                new_lock = (work / "package-lock.json").read_bytes()
                _, new_lock_sha256 = parse_json(new_lock, work / "package-lock.json")
                report = scan_project(work, base, extract=True, **scan_options)
            except (GuardError, OSError, ValueError) as exc:
                if Path(tmp).name not in str(exc):
                    raise  # npm errors, or about the model or cache folders the caller gave
                raise GuardError(
                    "A file in the temporary preview folder could not be written, read or "
                    f"checked ({type(exc).__name__})"
                ) from None
    except OSError:
        if not os.path.lexists(folder.name):
            raise
        raise GuardError("The temporary preview folder could not be removed") from None
    preview = {
        "targets": names or None,
        "npm_version": npm_version,
        "package_json_sha256": hashlib.sha256(package_bytes).hexdigest(),
        "package_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "new_package_lock_sha256": new_lock_sha256,
        "package_json_changed": new_package != package_bytes,
        "changed_count": len(report["results"]),
        "project_npmrc_ignored": npmrc,
        "notices": [NPMRC_NOTICE] * npmrc + [PREVIEW_NOTICE],
    }
    return {"preview": preview, "report": report}, new_package, new_lock


def apply_update(
    project: Path,
    packages: list[str] | None = None,
    *,
    mode: str,
    confirm: bool = False,
    model_dir: Path | None = None,
    progress: Callable[[int, int, dict], None] | None = None,
    cache_dir: Path | None = None,
    no_cache: bool = False,
    known_malicious_dir: Path | None = None,
) -> dict:
    """Preview, check and apply npm update in one call: {preview, report, apply}.

    mode: "lockfile" writes the checked package-lock.json (and package.json if npm changed it)
    to the project; "install" then runs npm ci --ignore-scripts there. confirm: the user's one
    explicit confirmation of every item the gate lists (update_gate()). The preview and its
    errors are those of preview_update(), whose notice that nothing was changed is left out
    here; the apply is apply_preview()'s.
    """
    if mode not in APPLY_MODES:
        raise GuardError(f"Unknown apply mode: {mode!r}")
    result, new_package, new_lock = _preview(
        project, packages, model_dir=model_dir, progress=progress, cache_dir=cache_dir,
        no_cache=no_cache, known_malicious_dir=known_malicious_dir,
    )  # fmt: skip
    preview = result["preview"]
    preview["notices"] = [notice for notice in preview["notices"] if notice != PREVIEW_NOTICE]
    apply = apply_preview(project, result, new_package, new_lock, mode=mode, confirm=confirm)
    return {**result, "apply": apply}


def _gate_item(row: dict, causes: list[str]) -> dict:
    return {
        "location": row.get("location"),
        "package": row.get("package"),
        "before_version": row.get("before_version"),
        "after_version": row.get("after_version"),
        "status": row.get("status"),
        "reason": row.get("reason"),
        "score": row.get("score"),
        "known_malicious_status": (row.get("known_malicious") or {}).get("status"),
        "ml_status": (row.get("ml") or {}).get("status"),
        "causes": causes,
    }


def update_gate(report: dict) -> tuple[list[dict], list[dict]]:
    """(refused, to confirm) items of report.results, from the per-item fields only.

    The top-level exit_code is not used: 2 (unfinished) would hide 1 (risk), as in
    actions.decide(). A known malicious match (known_malicious.status hit) is always refused.
    An ML hit, an incomplete item, or a known malicious check that did not say not_hit
    (not_run, failed) needs the user's confirmation. A removed item installs nothing, so only a
    match would refuse it. Each item has its location, package, versions, status, reason, score,
    the two detector statuses and causes: known_malicious_hit, ml_hit, incomplete,
    known_malicious_unchecked.
    """
    refused, confirm = [], []
    for row in report["results"]:
        known = (row.get("known_malicious") or {}).get("status")
        if known == "hit":
            refused.append(_gate_item(row, ["known_malicious_hit"]))
            continue
        if row.get("status") == "removed":
            continue
        causes = ["ml_hit"] * ((row.get("ml") or {}).get("status") == "hit")
        causes += ["incomplete"] * (row.get("status") == "incomplete")
        causes += ["known_malicious_unchecked"] * (known != "not_hit")
        if causes:
            confirm.append(_gate_item(row, causes))
    return refused, confirm


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def apply_preview(
    project: Path, result: dict, new_package: bytes, new_lock: bytes, *, mode: str,
    confirm: bool = False, ready: Callable[[], None] | None = None,
) -> dict:  # fmt: skip
    """Apply a checked preview ({preview, report} and the new file bytes of the same preview).

    ready: with mode install, run right before npm ci starts (npm_cli.clean_install); its
    GuardError stops the install as install_failed with its message.

    Nothing is written when there is no change, a known malicious match, items to confirm and no
    confirm, a project .npmrc with mode install (refused: npm ci would read it), or when the
    project no longer passes read_project(), its two files differ from the preview's hashes or
    new_lock from preview.new_package_lock_sha256, or when the new files fail the same checks
    (npm_cli.check_files). Mode install also refuses a node_modules that is not a folder of the
    project itself (npm_cli.check_install_dir: npm ci empties it, and a link would lead that
    elsewhere), a new lockfile entry without integrity and a scratch folder (temporary folder
    for npm's missing paths) that lands inside the project.
    Otherwise the two original files go to a new backup folder next to the history file first,
    then each changed file is written to a temporary file in the project and swapped in with
    os.replace(). Mode install then runs npm ci --ignore-scripts (npm_cli.clean_install) and
    checks that npm left package.json and the lockfile as written. Nothing is ever restored
    automatically.

    Returns {mode, outcome, reason, error, blocked, confirmation_required, confirmed, files,
    backup, npm_version, npm_ci_exit_code, notices}. outcome: applied, unchanged (no change),
    refused (nothing changed; reason known_malicious_hit, confirmation_required, project_npmrc,
    project_unsupported, project_changed, new_lock_mismatch, new_files_unsupported,
    integrity_missing, scratch_in_project) or failed (reason backup_failed,
    write_failed, install_failed, lockfile_changed; files lists what was already replaced).
    error is a message without npm output or temporary paths.
    """
    if mode not in APPLY_MODES:
        raise GuardError(f"Unknown apply mode: {mode!r}")
    preview, report = result["preview"], result["report"]
    blocked, required = update_gate(report)
    apply = {
        "mode": mode, "outcome": None, "reason": None, "error": None, "blocked": blocked,
        "confirmation_required": required, "confirmed": bool(confirm), "files": [],
        "backup": None, "npm_version": None, "npm_ci_exit_code": None, "notices": [],
    }  # fmt: skip

    def done(outcome: str, reason: str | None = None, error: str | None = None) -> dict:
        notices = []
        if outcome in ("unchanged", "refused") or (outcome == "failed" and not apply["files"]):
            notices.append(UNCHANGED_NOTICE)
        if reason == "project_npmrc":
            notices.append(NPMRC_INSTALL_NOTICE)
        if outcome == "applied" and mode == "lockfile":
            notices.append(LOCKFILE_NOTICE)
        if apply["npm_ci_exit_code"] is not None:
            notices.append(SCRIPTS_NOTICE)
        if apply["backup"] is not None:
            notices.append(RESTORE_NOTICE)
        apply.update(outcome=outcome, reason=reason, error=error, notices=notices)
        return apply

    if not report["results"]:
        return done("unchanged")
    if blocked:
        return done("refused", "known_malicious_hit")
    if required and not confirm:
        return done("refused", "confirmation_required")
    if mode == "install" and os.path.lexists(project / ".npmrc"):
        return done("refused", "project_npmrc")
    try:
        package_bytes, lock_bytes, _ = npm_cli.read_project(project)
        if mode == "install":
            npm_cli.check_install_dir(project)
    except (GuardError, OSError, ValueError) as exc:
        return done("refused", "project_unsupported", str(exc))
    if (_sha256(package_bytes), _sha256(lock_bytes)) != (
        preview["package_json_sha256"], preview["package_lock_sha256"],
    ):  # fmt: skip
        return done("refused", "project_changed")
    if _sha256(new_lock) != preview["new_package_lock_sha256"]:
        return done("refused", "new_lock_mismatch")
    try:
        # The scan only marks what npm resolved outside the registry as incomplete, which a
        # confirmation lets through; npm ci would then fetch it.
        npm_cli.check_files(
            new_package, new_lock, "the new package.json", "the new package-lock.json"
        )
    except (GuardError, RecursionError) as exc:
        return done("refused", "new_files_unsupported", str(exc))
    if mode == "install":
        missing = npm_cli.missing_integrity(new_lock)
        if missing:
            shown = ", ".join(loc for loc, _ in missing[:5]) + (", ..." if len(missing) > 5 else "")
            bundled = sum(in_bundle for _, in_bundle in missing)
            return done(
                "refused", "integrity_missing",
                f"{len(missing)} lockfile entries have no valid integrity to check: {shown}"
                + (f"; {bundled} of them bundled (bundleDependencies), which depbee does not "
                   "install: apply the lockfile only and install yourself" if bundled else ""),
            )  # fmt: skip
    writes = [
        (name, old, new)
        for name, old, new in (("package-lock.json", lock_bytes, new_lock),
                               ("package.json", package_bytes, new_package))
        if new != old
    ]  # fmt: skip

    def change(scratch: Path | None) -> dict:
        """Back up, replace and, given a scratch folder, install."""
        try:
            apply["backup"] = str(_backup(project, mode, package_bytes, lock_bytes, writes))
        except (ImportError, RuntimeError, OSError, ValueError) as exc:
            error = f"The backup could not be written ({type(exc).__name__})"
            return done("failed", "backup_failed", error)
        try:
            _replace(project, writes, apply["files"])
        except OSError as exc:
            replaced = ", ".join(f["path"] for f in apply["files"]) or "none"
            return done(
                "failed", "write_failed",
                f"The project files could not be replaced ({type(exc).__name__}); "
                f"replaced before the error: {replaced}",
            )  # fmt: skip
        if scratch is None:
            return done("applied")
        try:
            version, code = npm_cli.clean_install(project.absolute(), scratch, ready)
        except (GuardError, OSError) as exc:
            if isinstance(exc, GuardError) and "depbee_install_" not in str(exc):
                error = str(exc)  # npm_cli's own messages: no npm output
            else:
                error = f"npm ci could not be run ({type(exc).__name__})"
            return done("failed", "install_failed", error)
        apply["npm_version"], apply["npm_ci_exit_code"] = version, code
        if code:
            return done("failed", "install_failed", f"npm ci failed with exit code {code}")
        try:
            kept = [(project / "package.json").read_bytes(),
                    (project / "package-lock.json").read_bytes()] == [new_package, new_lock]  # fmt: skip
        except OSError:
            kept = False
        if not kept:
            error = "npm ci changed package.json or package-lock.json"
            return done("failed", "lockfile_changed", error)
        return done("applied")

    if mode == "lockfile":
        return change(None)
    try:
        folder = tempfile.TemporaryDirectory(prefix="depbee_install_")
    except OSError as exc:
        error = f"The temporary install folder could not be created ({type(exc).__name__})"
        return done("failed", "install_failed", error)
    try:
        # The missing --git and --globalconfig files must not be paths of the project: checked
        # before anything changes, on the real paths (links and junctions resolved).
        if _inside(Path(folder.name), project):
            return done("refused", "scratch_in_project")
        return change(Path(folder.name))
    finally:
        try:
            folder.cleanup()
        except OSError:
            if apply["outcome"] == "applied":
                done(
                    "failed", "install_failed", "The temporary install folder could not be removed"
                )


def install_checked(
    project: Path, *, progress: Callable[[int, int, dict], None] | None = None
) -> dict:
    """depbee guard ci: install the project's package-lock.json with npm ci --ignore-scripts only
    if its change from Git HEAD passes a check made now on exactly those bytes: {report, apply}.

    No asset, cache or base option: the model, the index and the cache are the ones every
    command uses (_sources, the default cache), and the base is always the lockfile in Git HEAD,
    so the caller cannot pick an easier model or baseline. Refused with GuardError before the
    check: another install_checked() of the same project still running (_install_lock: refused,
    not waited for), a project that read_project() refuses, a bundle or a nested shrinkwrap
    anywhere in the tree (_tree_problem), a project .npmrc, a node_modules that is not the
    project's own folder, a lock entry without a valid integrity, and more than
    GUARD_MAX_PACKAGES changes to analyze. The scan runs with strict_sources: a change whose
    lockfile entry and the dist of the packument the analysis fetched once and uses do not name
    the same tarball URL and single sha512 digest is a failed (held) change, on a cache hit as
    on a download, and the registry is never asked again here. The scan must have read the
    plan's bytes and base (same request_id as the plan made with the hashed files), and its
    report must have exactly the plan's changes (_guard_rows), else GuardError. Without an added
    or updated change npm is never started: no change is "unchanged", removals only are
    "refused" (removal_only). An install needs every added or updated change analyzed with a
    complete pass (_complete_pass) and exit code 0; an item that is no pass while the gate
    would let it through is a GuardError. apply_preview() with mode install and no confirmation
    then refuses any item the gate lists, compares the two files once more and, right before
    npm ci starts, the files, the .npmrc, the plan and node_modules again (ready). Nothing in
    the project is written. A process that writes the files after that last comparison is not
    stopped; npm ci's own check afterwards reports it. apply_preview() itself, as the
    dashboard and update --apply use it, is unchanged.
    """
    # One real path for the whole call: a link or junction re-pointed meanwhile, even to a
    # folder with the same files, does not move where npm ci runs.
    project = Path(os.path.realpath(os.path.abspath(project)))
    with _install_lock(project):
        package_bytes, lock_bytes, package = npm_cli.read_project(project)
        entry = _entry_problem(lock_bytes)
        if entry:
            raise GuardError(
                f"{entry}; depbee guard ci downloads and installs nothing for such a lockfile"
            )
        shape = _tree_problem(package, lock_bytes)
        if shape:
            raise GuardError(
                f"{shape}: npm installs that part of the tree from inside another package, not "
                "from the lockfile's own tarball and digest that depbee guard ci checks. Nothing "
                "was downloaded or installed; install such a project yourself after review"
            )
        if os.path.lexists(project / ".npmrc"):
            raise GuardError(
                "The project has a .npmrc, which npm ci would read: depbee does not install "
                "it. Review the .npmrc and install yourself"
            )
        npm_cli.check_install_dir(project)
        missing = npm_cli.missing_integrity(lock_bytes)
        if missing:
            raise GuardError(
                f"{len(missing)} lockfile entries have no valid integrity to check (first: "
                f"{missing[0][0]}); depbee does not install them"
            )
        sums = (_sha256(package_bytes), _sha256(lock_bytes))
        plan = plan_project(project)
        if plan["head_lock_sha256"] != sums[1]:
            raise GuardError(GUARD_CHANGED)

        def limit(index: int, total: int, change: dict) -> None:
            if total > GUARD_MAX_PACKAGES:
                raise GuardError(
                    f"{total} changed packages to analyze; depbee guard ci analyzes at most "
                    f"{GUARD_MAX_PACKAGES}. Nothing was installed"
                )
            if progress:
                progress(index, total, change)

        # Strict sources: each change is analyzed only if npm ci would check the very tarball the
        # analysis checks, judged from the one packument the analysis itself fetched and uses.
        report = scan_project(project, extract=True, progress=limit, strict_sources=True)
        if report["request_id"] != plan["request_id"]:
            raise GuardError(GUARD_CHANGED)
        installs = _guard_rows(plan, report)
        if not installs:  # nothing analyzed to install: no change, or removals only
            if plan["changes"]:
                return {"report": report, "apply": _not_applied("refused", "removal_only")}
            return {"report": report, "apply": _not_applied("unchanged", None)}
        passed = [change["analyzable"] and _complete_pass(row) for change, row in installs]
        if all(passed) and report["exit_code"] != 0:
            raise GuardError(GUARD_MISMATCH)
        if not all(passed) and update_gate(report) == ([], []):
            raise GuardError(GUARD_MISMATCH)  # not a pass, yet the gate would let it through
        started = []

        def ready() -> None:
            current_package, current_lock, _ = npm_cli.read_project(project)
            if (
                (_sha256(current_package), _sha256(current_lock)) != sums
                or os.path.lexists(project / ".npmrc")
                or plan_project(project)["request_id"] != plan["request_id"]
            ):
                raise GuardError(
                    "package.json, package-lock.json, .npmrc or Git HEAD changed after the "
                    "check; npm ci was not started"
                )
            npm_cli.check_install_dir(project)  # npm ci empties it first: still a folder here
            if os.path.realpath(project) != str(project):
                raise GuardError("The project folder's path now leads through a link; npm ci was "
                                 "not started")  # fmt: skip
            started.append(True)  # nothing below stops npm ci from starting

        preview = {"package_json_sha256": sums[0], "package_lock_sha256": sums[1],
                   "new_package_lock_sha256": sums[1]}  # fmt: skip
        apply = apply_preview(
            project, {"preview": preview, "report": report}, package_bytes, lock_bytes,
            mode="install", ready=ready,
        )  # fmt: skip
    # npm that could not be started at all never ran, though ready() had finished.
    unstarted = (apply["error"] or "").startswith(npm_cli.NPM_NOT_STARTED)
    return {"report": report, "apply": {**apply, "npm_ci_started": bool(started) and not unstarted}}


def _entry_problem(lock_bytes: bytes) -> str | None:
    """Which lock entry has no package name and version a registry install could use (a null or
    malformed name; a version depbee check would not take: 01.2.3 is not SemVer, 1.2.3+build is
    valid SemVer that this guard does not support), if any: such an entry stops the call before
    any download, of the other entries too."""
    lock, _ = parse_json(lock_bytes, "package-lock.json")  # read_project() checked its shape
    for location, entry in lock["packages"].items():
        if not location:
            continue
        name = entry.get("name", location.rpartition("node_modules/")[2])
        version = entry.get("version")
        if not isinstance(name, str) or len(name) > 214 or not PACKAGE_NAME.fullmatch(name):
            return f"The lockfile entry {location} has no valid package name"
        if not isinstance(version, str) or not EXACT_VERSION.fullmatch(version):
            return f"The lockfile entry {location} has no valid version"
    return None


def _tree_problem(package: dict, lock_bytes: bytes) -> str | None:
    """Which part of the tree npm ci would take from inside another package, if any: a bundle
    (bundleDependencies or bundledDependencies of package.json or of any lock entry, the root's
    included, and any entry marked inBundle, which comes in its parent's tarball) or a package
    with its own npm-shrinkwrap.json (hasShrinkwrap), whose subtree npm reads from that file.
    Only these markers npm writes are read; npm's handling of them is not modelled."""
    bundles = ("bundleDependencies", "bundledDependencies")
    for field in bundles:
        if package.get(field):
            return f"package.json has {field}"
    lock, _ = parse_json(lock_bytes, "package-lock.json")  # read_project() checked its shape
    for location, entry in lock["packages"].items():
        where = location or "the lockfile's root entry"
        if entry.get("hasShrinkwrap"):
            return f"{where} has its own npm-shrinkwrap.json (hasShrinkwrap)"
        if entry.get("inBundle"):
            return f"{where} is bundled inside another package (inBundle)"
        for field in bundles:
            if entry.get(field):
                return f"{where} has {field}"
    return None


def _guard_rows(plan: dict, report: dict) -> list[tuple[dict, dict]]:
    """(change, report row) of each added or updated change of the plan, in plan order.
    GuardError unless the report has exactly one row per planned change, with the change's
    location, versions and removal: a report that does not describe the plan installs nothing."""
    rows = {}
    for row in report["results"]:
        if not isinstance(row, dict) or row.get("change_id") in rows:
            raise GuardError(GUARD_MISMATCH)
        rows[row.get("change_id")] = row
    if rows.keys() != {change["change_id"] for change in plan["changes"]}:
        raise GuardError(GUARD_MISMATCH)
    pairs = []
    for change in plan["changes"]:
        row = rows[change["change_id"]]
        expected = (change["location"], (change["before"] or {}).get("version"),
                    (change["after"] or {}).get("version"), change["kind"] == "removed")  # fmt: skip
        found = (row.get("location"), row.get("before_version"), row.get("after_version"),
                 row.get("status") == "removed")  # fmt: skip
        if found != expected:
            raise GuardError(GUARD_MISMATCH)
        if change["kind"] != "removed":
            pairs.append((change, row))
    return pairs


def _complete_pass(row: dict) -> bool:
    """An analyzed item that every connected check passed: not flagged with an ML risk score,
    the ML path below the threshold and the known malicious list checked without a match."""
    return (
        row.get("status") == "not_flagged"
        and isinstance(row.get("score"), int | float)
        and (row.get("ml") or {}).get("status") == "not_hit"
        and (row.get("known_malicious") or {}).get("status") == "not_hit"
    )


def _not_applied(outcome: str, reason: str | None) -> dict:
    """An apply document (apply_preview()'s fields and npm_ci_started) of an install that never
    reached npm."""
    return {
        "mode": "install", "outcome": outcome, "reason": reason, "error": None, "blocked": [],
        "confirmation_required": [], "confirmed": False, "files": [], "backup": None,
        "npm_version": None, "npm_ci_exit_code": None, "notices": [UNCHANGED_NOTICE],
        "npm_ci_started": False,
    }  # fmt: skip


@contextlib.contextmanager
def _install_lock(project: Path):
    """Hold the install lock of this project (its real path), a lock on a file in locks/ next
    to the history file that the system frees when the process ends; GuardError if another
    process or call holds it."""
    from . import history

    key = hashlib.sha256(os.path.normcase(os.path.realpath(project)).encode("utf-8", "replace"))
    try:
        folder = Path(os.path.abspath(history.db_path())).parent / "locks"
        folder.mkdir(parents=True, exist_ok=True)
        stream = open(folder / f"install-{key.hexdigest()[:32]}.lock", "a+b")  # noqa: SIM115
    except (OSError, RuntimeError) as exc:
        raise GuardError(f"The install lock could not be opened ({type(exc).__name__})") from None
    locked = False
    try:
        try:
            if os.name == "nt":
                import msvcrt

                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError:
            raise GuardError(
                "Another depbee guard ci is checking or installing this project; nothing was "
                "installed. Run it again when that one has ended"
            ) from None
        yield
    finally:
        if locked and os.name == "nt":
            with contextlib.suppress(OSError):
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        stream.close()


def _inside(path: Path, folder: Path) -> bool:
    """path is folder or under it, comparing real paths (case-folded on Windows)."""
    real, top = (Path(os.path.normcase(os.path.realpath(p))) for p in (path, folder))
    return real.is_relative_to(top)


def _backup(
    project: Path, mode: str, package_bytes: bytes, lock_bytes: bytes, writes: list
) -> Path:
    """A new folder under backups/ next to the history file (history.db_path(): never chosen by
    the project) with the two original files and backup.json; never removed by depbee."""
    from . import history  # its sqlite3 import stays out of the commands that do not apply

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    folder = Path(os.path.abspath(history.db_path())).parent / "backups"
    folder = folder / f"{stamp}-{secrets.token_hex(4)}"
    folder.mkdir(parents=True)
    (folder / "package.json").write_bytes(package_bytes)
    (folder / "package-lock.json").write_bytes(lock_bytes)
    new = {name: _sha256(data) for name, _, data in writes}
    about = {
        "project": str(project.absolute()),
        "created_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "depbee_version": __version__,
        "mode": mode,
        "package_json_sha256": _sha256(package_bytes),
        "package_lock_sha256": _sha256(lock_bytes),
        "new_package_json_sha256": new.get("package.json"),
        "new_package_lock_sha256": new.get("package-lock.json"),
    }
    text = json.dumps(about, ensure_ascii=True, indent=2) + "\n"
    (folder / "backup.json").write_text(text, encoding="utf-8", newline="\n")
    return folder


def _replace(project: Path, writes: list, replaced: list) -> None:
    """Write every new file to a temporary file in the project, then os.replace() each in turn,
    adding {path, sha256, new_sha256} to replaced; temporary files never stay behind."""
    temporary = []
    try:
        for name, _, data in writes:
            handle, path = tempfile.mkstemp(prefix=f".{name}.", suffix=".depbee", dir=project)
            temporary.append(path)
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
            shutil.copymode(project / name, path)
        for (name, old, new), path in zip(writes, temporary, strict=True):
            os.replace(path, project / name)
            replaced.append({"path": name, "sha256": _sha256(old), "new_sha256": _sha256(new)})
    finally:
        for path in temporary:
            with contextlib.suppress(OSError):  # gone once replaced
                os.unlink(path)
