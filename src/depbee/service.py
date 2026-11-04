"""Shared entry point for the CLI and later Actions, MCP and dashboard: assembly only.

Detection and verdicts stay in pipeline.scan(); output formats and exit handling stay with callers.
"""

from collections.abc import Callable
from pathlib import Path

from .analysis.artifact import ArtifactAnalyzer
from .contracts import GuardError
from .inference.lightgbm import LightGBMPredictor
from .inputs.npm import build_request
from .pipeline import scan


def plan_project(project: Path, base_lock: Path) -> dict:
    """Changed version pairs between the base lockfile and project/package-lock.json."""
    return build_request(project, base_lock)


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
    base_lock: Path,
    *,
    analysis: Path | None = None,
    extract: bool = False,
    local_sources: list[str] | None = None,
    local_root: Path | None = None,
    model_dir: Path | None = None,
    progress: Callable[[int, int, dict], None] | None = None,
) -> dict:
    """Build the request, pick the analyzer and model, and return the pipeline.scan() report.

    analysis: trusted precomputed analysis JSON. extract: run feature-extractor instead.
    local_sources: NAME@VERSION=DIR specs under local_root (extract only).
    progress: called per extracted package; the caller decides how to show it.
    With extract=False, progress and local_root are ignored; any local_sources raise GuardError.

    Raises GuardError, OSError, ValueError or RecursionError for bad options or invalid inputs
    (lockfiles, analysis, model); the caller maps them to its error output.
    """
    # Intended error priority: option conflict before reading lockfiles, local sources after.
    if analysis and extract:
        raise GuardError("Use either an analysis file or extraction, not both")
    request = plan_project(project, base_lock)
    sources = _local_sources(local_sources or [], extract, local_root)
    analyzer = None
    if analysis:
        analyzer = ArtifactAnalyzer(analysis)
    elif extract:
        from .analysis.extractor import ExtractorAnalyzer

        analyzer = ExtractorAnalyzer(sources, progress=progress)
    predictor = LightGBMPredictor(model_dir) if model_dir else None
    return scan(request, analyzer, predictor)
