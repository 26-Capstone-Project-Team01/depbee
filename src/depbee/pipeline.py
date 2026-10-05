"""Orchestration independent of terminal, analyzer implementation, or ML framework."""

from .contracts import (
    SCHEMA_VERSION,
    Analyzer,
    GuardError,
    OutOfScopeError,
    Predictor,
    finite_number,
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
                    item["explanation"] = explain(row["features"])
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
    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": request["request_id"],
        "scope": "changed npm lockfile entries only; not a whole-project safety assessment",
        "status": "incomplete" if incomplete else "flagged" if flagged else "passed",
        "exit_code": exit_code,
        "model_id": predictor.model_id if predictor else None,
        "threshold": predictor.threshold if predictor else None,
        "analyzer_version": artifact["analyzer_version"] if artifact else None,
        "results": results,
    }
