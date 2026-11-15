"""Shared entry point for the CLI and later Actions, MCP and dashboard: assembly only.

Detection and verdicts stay in pipeline.scan(); output formats and exit handling stay with callers.
"""

import hashlib
import os
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from .analysis import bounded, cache
from .analysis.artifact import ArtifactAnalyzer
from .contracts import GuardError, elapsed_since, read_json
from .inference.lightgbm import LightGBMPredictor
from .inputs import npm_cli
from .inputs.npm import build_package_request, build_request, check_package_spec
from .pipeline import scan

NPMRC_NOTICE = "프로젝트 .npmrc는 적용하지 않았습니다(공개 registry 기준 미리보기)."
PREVIEW_NOTICE = "미리보기만 했고 프로젝트 파일은 아무것도 바꾸지 않았습니다."


def plan_project(
    project: Path, base_lock: Path | None = None, *, base_ref: str | None = None
) -> dict:
    """Changed version pairs between the base lockfile and project/package-lock.json.

    The base is base_lock, else project/package-lock.json in Git base_ref (default HEAD).
    """
    return build_request(project, base_lock, base_ref=base_ref)


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
) -> dict:
    """Build the request, pick the analyzer and model, and return the pipeline.scan() report.

    base_lock, base_ref: the base lockfile, as in plan_project().
    analysis: trusted precomputed analysis JSON. extract: run feature-extractor instead.
    local_sources: NAME@VERSION=DIR specs under local_root (extract only).
    model_dir: trusted model directory. If None, DEPBEE_MODEL_DIR is read on each call; empty or
    unset means no model. A bad path is an error and never falls back to another model.
    progress: called per extracted package; the caller decides how to show it.
    cache_dir, no_cache: the extracted-feature cache (default ~/.cache/depbee); see _cache_dir().
    With extract=True the report also has elapsed_seconds (in total and per result) and cache_hit.
    With extract=False, progress, local_root and the cache options are ignored, and any
    local_sources raise GuardError.

    Raises GuardError, OSError, ValueError or RecursionError for bad options or invalid inputs
    (lockfiles, analysis, model); the caller maps them to its error output.
    """
    started = time.monotonic()
    # Intended error priority: option conflict before reading lockfiles, local sources after.
    if analysis and extract:
        raise GuardError("Use either an analysis file or extraction, not both")
    request = plan_project(project, base_lock, base_ref=base_ref)
    sources = _local_sources(local_sources or [], extract, local_root)
    predictor = _predictor(model_dir)
    if not extract:
        analyzer = ArtifactAnalyzer(analysis) if analysis else None
        return scan(request, analyzer, predictor)
    from .analysis.extractor import ExtractorAnalyzer

    analyzer = ExtractorAnalyzer(
        sources, progress=progress, **_cache_options(predictor, cache_dir, no_cache)
    )
    return _timed(scan(request, analyzer, predictor), analyzer, started)


def _predictor(model_dir: Path | None) -> LightGBMPredictor | None:
    """model_dir, else DEPBEE_MODEL_DIR read on this call; empty or unset means no model."""
    env_model = os.environ.get("DEPBEE_MODEL_DIR")
    if model_dir is None and env_model:
        model_dir = Path(env_model)
    return LightGBMPredictor(model_dir) if model_dir else None


def _cache_options(predictor, cache_dir: Path | None, no_cache: bool) -> dict:
    """ExtractorAnalyzer cache options; none without a verified model or with no_cache.

    The analyzer also requires verified feature-extractor provenance before it uses the cache.
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
) -> dict:
    """Check one npm registry version without a lockfile and return the pipeline.scan() report.

    name, version: an exact registry name (scoped or not) and version, checked before any
    network access. The version is compared with its stable predecessor, as in scan --extract.
    The registry metadata is fetched once and used for both the request and the analysis; the
    downloaded tarballs are checked against its dist.integrity (analysis.registry).
    model_dir, progress, cache_dir, no_cache: as in scan_project(). The model is loaded before
    the registry is read. The report has the elapsed_seconds and cache_hit of scan --extract.

    Raises GuardError, OSError or ValueError for an invalid name or version, unreadable or
    invalid registry metadata, or a bad model; the caller maps them to its error output.
    """
    started = time.monotonic()
    check_package_spec(name, version)
    from .analysis.extractor import ExtractorAnalyzer

    predictor = _predictor(model_dir)
    analyzer = ExtractorAnalyzer(
        progress=progress, **_cache_options(predictor, cache_dir, no_cache)
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
        report = scan(request, analyzer, predictor)
    return _timed(report, analyzer, started, {request["changes"][0]["change_id"]: fetched})


def preview_update(
    project: Path,
    packages: list[str] | None = None,
    *,
    model_dir: Path | None = None,
    progress: Callable[[int, int, dict], None] | None = None,
    cache_dir: Path | None = None,
    no_cache: bool = False,
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
    model_dir, progress, cache_dir, no_cache: as in scan_project().

    Raises GuardError, OSError or ValueError for unsupported projects, invalid names, npm
    failures and the errors of scan_project(); the caller maps them to its error output.
    """
    names = list(packages or [])
    package_bytes, lock_bytes, package = npm_cli.read_project(project)
    npm_cli.check_names(names, package)
    npmrc = os.path.lexists(project / ".npmrc")
    with tempfile.TemporaryDirectory(prefix="depbee_preview_", ignore_cleanup_errors=True) as tmp:
        work, base = Path(tmp) / "project", Path(tmp) / "base-package-lock.json"
        work.mkdir()
        # The bytes hashed below are the bytes npm and the scan see, even if the project changes.
        (work / "package.json").write_bytes(package_bytes)
        (work / "package-lock.json").write_bytes(lock_bytes)
        base.write_bytes(lock_bytes)
        npm_version = npm_cli.update_lock(work, names)
        new_package = (work / "package.json").read_bytes()
        _, new_lock_sha256 = read_json(work / "package-lock.json")
        report = scan_project(
            work, base, extract=True, model_dir=model_dir, progress=progress,
            cache_dir=cache_dir, no_cache=no_cache,
        )  # fmt: skip
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
    return {"preview": preview, "report": report}
