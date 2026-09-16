from pathlib import Path

from ..contracts import SCHEMA_VERSION, GuardError, read_json


class ArtifactAnalyzer:
    """Consume precomputed JSON; never execute code from the target project."""

    def __init__(self, path: Path):
        self.path = path

    def analyze(self, request: dict) -> dict:
        artifact, _ = read_json(self.path)
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
            if row.get("status") not in ("complete", "failed"):
                raise GuardError("Analysis status must be complete or failed")
            if row["status"] == "complete":
                if not isinstance(row.get("features"), dict):
                    raise GuardError("Complete analysis requires features")
                evidence = row.get("evidence", [])
                if not isinstance(evidence, list) or not all(isinstance(e, str) for e in evidence):
                    raise GuardError("evidence must be an array of text strings")
            elif not isinstance(row.get("error"), str) or not row["error"]:
                raise GuardError("Failed analysis requires an error message")
        # Missing rows are reported per package as incomplete by the pipeline.
        return artifact
