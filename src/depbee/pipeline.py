"""Orchestration independent of terminal, analyzer implementation, or ML framework."""

from .contracts import (
    SCHEMA_VERSION,
    Analyzer,
    GuardError,
    OutOfScopeError,
    Predictor,
    finite_number,
)

LOCKFILE_SCOPE = "changed npm lockfile entries only; not a whole-project safety assessment"
PACKAGE_SCOPE = (
    "one npm registry version checked without a lockfile; not a whole-project safety assessment"
)


def scan(request: dict, analyzer: Analyzer | None, predictor: Predictor | None) -> dict:
    artifact = analyzer.analyze(request) if analyzer else None
    if artifact and predictor and artifact["feature_schema"] != predictor.feature_schema:
        raise GuardError("Analyzer feature_schema does not match model feature_schema")
    records = {r["change_id"]: r for r in artifact["results"]} if artifact else {}
    explain = getattr(predictor, "explain", None)
    results = []
    for change in request["changes"]:
        item = {
            "change_id": change["change_id"],
            "location": change["location"],
            "package": (change["after"] or change["before"])["name"],
            "before_version": change["before"]["version"] if change["before"] else None,
            "after_version": change["after"]["version"] if change["after"] else None,
            "status": "incomplete",
            "score": None,
            "evidence": [],
        }
        row = records.get(change["change_id"])
        if change["kind"] == "removed":
            item.update(status="removed", reason="not_installed_in_head")
        elif not change["analyzable"]:
            item["reason"] = change["reason"]
        elif row is None:
            item["reason"] = "analysis_missing"
        elif row["status"] == "failed":
            item.update(reason="analysis_failed", detail=row["error"])
        elif row["status"] == "unsupported":
            item.update(reason=row["reason"], detail=row["error"])
        elif predictor is None:
            item["reason"] = "model_missing"
        else:
            item.update(
                compared_version=row.get("baseline_version"),
                features=row["features"],
                evidence=row.get("evidence", []),
            )
            try:
                score = finite_number(predictor.predict(row["features"]), "model score")
                if not 0 <= score <= 1:
                    raise GuardError("Model score is outside [0, 1]")
                item.update(
                    status="flagged" if score >= predictor.threshold else "not_flagged",
                    score=score,
                )
                if explain:
                    explained = explain(row["features"])
                    item["explanation"] = explained["top"]
                    item["explanation_rest"] = {
                        key: explained[key] for key in ("others_sum", "others_count", "base_value")
                    }
            except OutOfScopeError as exc:
                item.update(reason="out_of_training_scope", detail=str(exc))
            except GuardError as exc:
                item.update(
                    status="incomplete", score=None, reason="inference_failed", detail=str(exc)
                )
        results.append(item)
    incomplete = any(r["status"] == "incomplete" for r in results)
    flagged = any(r["status"] == "flagged" for r in results)
    exit_code = 2 if incomplete else 1 if flagged else 0
    # Only a package request (check, no lockfile) adds input_kind; lockfile reports are unchanged.
    package = {"input_kind": "package"} if request.get("input_kind") == "package" else {}
    # Verified identities only: a model without one, or an analyzer without a verified
    # feature-extractor backend (--analysis, unverified install), gives null. No install URL (D-10).
    model = getattr(predictor, "identity", None)
    extractor = getattr(getattr(analyzer, "backend", None), "identity", None)
    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": request["request_id"],
        **package,
        "scope": PACKAGE_SCOPE if package else LOCKFILE_SCOPE,
        "status": "incomplete" if incomplete else "flagged" if flagged else "passed",
        "exit_code": exit_code,
        "model_id": predictor.model_id if predictor else None,
        "threshold": predictor.threshold if predictor else None,
        "analyzer_version": artifact["analyzer_version"] if artifact else None,
        # Before results, so service._timed() puts elapsed_seconds after it unchanged.
        "provenance": {
            "model": _identity(model, ("model_sha256", "manifest_sha256")),
            "feature_extractor": _identity(extractor, ("commit", "files_sha256", "python")),
        },
        "results": results,
    }


def _identity(value: object, keys: tuple[str, ...]) -> dict | None:
    """Those keys of a verified identity; null unless every one is a string (contract 3.1)."""
    if isinstance(value, dict) and all(isinstance(value.get(key), str) for key in keys):
        return {key: value[key] for key in keys}
    return None
