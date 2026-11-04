"""Shared entry point for the CLI and later Actions, MCP and dashboard: assembly only.

Detection and verdicts stay in pipeline.scan(); output formats and exit handling stay with callers.
"""

import os
from collections.abc import Callable
from pathlib import Path

from .analysis.artifact import ArtifactAnalyzer
from .contracts import GuardError
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
) -> dict:
    """Build the request, pick the analyzer and model, and return the pipeline.scan() report.

    base_lock, base_ref: the base lockfile, as in plan_project().
    analysis: trusted precomputed analysis JSON. extract: run feature-extractor instead.
    local_sources: NAME@VERSION=DIR specs under local_root (extract only).
    model_dir: trusted model directory. If None, DEPBEE_MODEL_DIR is read on each call; empty or
    unset means no model. A bad path is an error and never falls back to another model.
    progress: called per extracted package; the caller decides how to show it.
    With extract=False, progress and local_root are ignored; any local_sources raise GuardError.

    Raises GuardError, OSError, ValueError or RecursionError for bad options or invalid inputs
    (lockfiles, analysis, model); the caller maps them to its error output.
    """
    # Intended error priority: option conflict before reading lockfiles, local sources after.
    if analysis and extract:
        raise GuardError("Use either an analysis file or extraction, not both")
    request = plan_project(project, base_lock, base_ref=base_ref)
    sources = _local_sources(local_sources or [], extract, local_root)
    analyzer = None
    if analysis:
        analyzer = ArtifactAnalyzer(analysis)
    elif extract:
        from .analysis.extractor import ExtractorAnalyzer

        analyzer = ExtractorAnalyzer(sources, progress=progress)
    return scan(request, analyzer, _predictor(model_dir))


def _predictor(model_dir: Path | None) -> LightGBMPredictor | None:
    """model_dir, else DEPBEE_MODEL_DIR read on this call; empty or unset means no model."""
    env_model = os.environ.get("DEPBEE_MODEL_DIR")
    if model_dir is None and env_model:
        model_dir = Path(env_model)
    return LightGBMPredictor(model_dir) if model_dir else None


def check_package(
    name: str,
    version: str,
    *,
    model_dir: Path | None = None,
    progress: Callable[[int, int, dict], None] | None = None,
) -> dict:
    """Check one npm registry version without a lockfile and return the pipeline.scan() report.

    name, version: an exact registry name (scoped or not) and version, checked before any
    network access. The version is compared with its stable predecessor, as in scan --extract.
    The registry metadata is fetched once and used for both the request and the analysis; its
    dist.integrity is registry metadata, not a hash of the downloaded tarball.
    model_dir, progress: as in scan_project(). The model is loaded before the registry is read.

    Raises GuardError, OSError or ValueError for an invalid name or version, unreadable or
    invalid registry metadata, or a bad model; the caller maps them to its error output.
    """
    check_package_spec(name, version)
    from .analysis.extractor import ExtractorAnalyzer

    analyzer = ExtractorAnalyzer(progress=progress)
    predictor = _predictor(model_dir)
    try:
        packument = analyzer.packument(name)
    except analyzer.backend.errors as exc:
        raise GuardError(f"Cannot read npm registry metadata for {name}: {exc}") from exc
    return scan(build_package_request(name, version, packument), analyzer, predictor)
