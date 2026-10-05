from pathlib import Path

from ..contracts import SCHEMA_VERSION, GuardError, read_json


def validate(artifact: dict, request: dict) -> dict:
    """Check an analysis result against its request. Every analyzer's output goes through this."""
    if artifact.get("schema_version") != SCHEMA_VERSION:
        raise GuardError("Unsupported analysis schema_version")
    if artifact.get("request_id") != request["request_id"]:
        raise GuardError("Analysis request_id does not match these lockfiles")
    if not isinstance(artifact.get("analyzer_version"), str) or not artifact["analyzer_version"]:
        raise GuardError("analysis.analyzer_version is required")
    if not isinstance(artifact.get("feature_schema"), str) or not artifact["feature_schema"]:
        raise GuardError("analysis.feature_schema is required")
    rows = artifact.get("results")
    if not isinstance(rows, list):
        raise GuardError("analysis.results must be an array")
    expected = {c["change_id"] for c in request["changes"] if c["analyzable"]}
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("change_id"), str):
            raise GuardError("Each analysis result must have a change_id")
        identity = row["change_id"]
        if identity not in expected or identity in seen:
            raise GuardError("Unknown or duplicate analysis change_id")
        seen.add(identity)
        if row.get("status") not in ("complete", "failed", "unsupported"):
            raise GuardError("Analysis status must be complete, failed or unsupported")
        if row["status"] == "complete":
            features = row.get("features")
            if not isinstance(features, dict):
                raise GuardError("Complete analysis requires features")
            # Types are checked against the model manifest by the predictor.
            for value in features.values():
                if value is not None and not isinstance(value, (bool, int, float, str)):
                    raise GuardError("Feature values must be numbers, booleans, text or null")
            evidence = row.get("evidence", [])
            if not isinstance(evidence, list) or not all(isinstance(e, str) for e in evidence):
                raise GuardError("evidence must be an array of text strings")
            baseline = row.get("baseline_version")
            if baseline is not None and (not isinstance(baseline, str) or not baseline):
                raise GuardError("baseline_version must be a version string")
        elif not isinstance(row.get("error"), str) or not row["error"]:
            raise GuardError("Failed or unsupported analysis requires an error message")
        if row["status"] == "unsupported" and (
            not isinstance(row.get("reason"), str) or not row["reason"]
        ):
            raise GuardError("Unsupported analysis requires a reason code")
    # Missing rows are reported per package as incomplete by the pipeline.
    return artifact


class ArtifactAnalyzer:
    """Consume precomputed JSON; never execute code from the target project."""

    def __init__(self, path: Path):
        self.path = path

    def analyze(self, request: dict) -> dict:
        artifact, _ = read_json(self.path)
        return validate(artifact, request)
