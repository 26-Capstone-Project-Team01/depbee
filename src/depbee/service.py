"""Shared entry point for the CLI and later Actions, MCP and dashboard: assembly only.

Detection and verdicts stay in pipeline.scan(); output formats and exit handling stay with callers.
"""

import os
import time
from collections.abc import Callable
from pathlib import Path

from .analysis import cache
from .analysis.artifact import ArtifactAnalyzer
from .contracts import GuardError, elapsed_since
from .inference.lightgbm import LightGBMPredictor
from .inputs.npm import build_package_request, build_request, check_package_spec
from .pipeline import scan


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
    identity = getattr(predictor, "identity", None)
    if no_cache or not isinstance(identity, dict):
        return {}
    if cache_dir is None:
        try:
            cache_dir = cache.default_dir()
        except RuntimeError:  # no home directory: run without the cache
            return {}
    return {"cache_dir": cache_dir, "model_identity": identity}


def _timed(report: dict, analyzer, started: float) -> dict:
    """Add extraction times: per result (null and false if not analyzed) and for the whole call."""
    for row in report["results"]:
        row["elapsed_seconds"], row["cache_hit"] = analyzer.measurements.get(
            row["change_id"], (None, False)
        )
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
    The registry metadata is fetched once and used for both the request and the analysis; its
    dist.integrity is registry metadata, not a hash of the downloaded tarball.
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
    try:
        packument = analyzer.packument(name)
    except analyzer.backend.errors as exc:
        raise GuardError(f"Cannot read npm registry metadata for {name}: {exc}") from exc
    request = build_package_request(name, version, packument)
    return _timed(scan(request, analyzer, predictor), analyzer, started)
