"""Orchestration independent of terminal, analyzer implementation, or ML framework."""

import copy
import re
from datetime import datetime

from .contracts import (
    SCHEMA_VERSION,
    Analyzer,
    GuardError,
    KnownMaliciousDetector,
    OutOfScopeError,
    Predictor,
    RuleDetector,
    finite_number,
)
from .inputs.npm import registry_version_problem

LOCKFILE_SCOPE = "changed npm lockfile entries only; not a whole-project safety assessment"
PACKAGE_SCOPE = (
    "one npm registry version checked without a lockfile; not a whole-project safety assessment"
)


def _text(value: object) -> bool:
    return isinstance(value, str)


def _maybe_text(value: object) -> bool:
    return value is None or isinstance(value, str)


def _texts(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(text, str) for text in value)


# Fields of detector records in contract order (docs/result-contract-draft.md 3).
KNOWN_MALICIOUS_INFO = {"source": _text, "list_as_of": _text, "list_sha256": _maybe_text}
RULES_INFO = {"ruleset_version": _text}
MATCH = {
    "advisory_id": _text,
    "match_kind": lambda v: v in ("listed_version", "affected_range"),
    "affected": _maybe_text,
}
CHECK = {
    "rule_id": _text,
    "rule_version": _text,
    "status": lambda v: v in ("hit", "not_hit", "failed"),
    "evidence": _texts,
    "locations": lambda v: isinstance(v, list),
    "detail": _maybe_text,
}
LOCATION = {"file": _text, "line": lambda v: v is None or type(v) is int}
AGREEMENT = {
    ("hit", "hit"): "both_hit",
    ("hit", "not_hit"): "rule_only",
    ("not_hit", "hit"): "ml_only",
    ("not_hit", "not_hit"): "neither_hit",
}


def _record(value: object, fields: dict, what: str) -> dict:
    """A copy with exactly the contract fields in contract order; GuardError if any is bad."""
    if not isinstance(value, dict) or any(
        key not in value or not valid(value[key]) for key, valid in fields.items()
    ):
        raise GuardError(f"Detector gave a malformed {what}")
    return {key: copy.deepcopy(value[key]) for key in fields}


def _detector_info(detector: object, fields: dict, what: str) -> dict | None:
    """The report's detectors entry; a malformed one is a configuration error, not a result."""
    if detector is None:
        return None
    return _record({k: getattr(detector, k) for k in fields if hasattr(detector, k)}, fields, what)


UTC_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?Z", re.ASCII)


def _list_as_of_problem(info: dict | None) -> str | None:
    """Why list_as_of is not ISO 8601 UTC with Z (contract 3.1), else None."""
    value = info and info["list_as_of"]
    if value is None:
        return None
    try:
        if UTC_TIME.fullmatch(value):
            datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
            return None
    except ValueError:  # e.g. month 13
        pass
    return "Known malicious list_as_of is not an ISO 8601 UTC time ending in Z"


def _slot(status: str, reason: str | None = None, detail: str | None = None, **found) -> dict:
    return {"status": status, "reason": reason, "detail": detail, **found}


def _failure(exc: Exception) -> str:
    return str(exc) or type(exc).__name__


def _known_malicious(
    detector: KnownMaliciousDetector | None, change: dict, list_problem: str | None = None
) -> dict:
    if detector is None:
        return _slot("not_run", "detector_not_configured", matches=[])
    if change["kind"] == "removed":
        return _slot("not_run", "not_installed_in_head", matches=[])
    # D-5: an exact registry name and version is checked even if it is not analyzed.
    if not change["analyzable"]:
        try:
            problem = registry_version_problem(change["after"])
        except GuardError as exc:  # e.g. an unparsable tarball URL: this change only fails
            return _slot("failed", "input_failed", str(exc), matches=[])
        if problem:
            return _slot("not_run", "not_analyzable", matches=[])
    try:
        found = detector.match(change["after"]["name"], change["after"]["version"])
        if not isinstance(found, list):
            raise GuardError("Known malicious detector must return a list")
        matches = [_record(match, MATCH, "known malicious match") for match in found]
    except Exception as exc:  # any detector error is failed, never not_hit
        return _slot("failed", "detector_failed", _failure(exc), matches=[])
    if list_problem and not matches:  # an undated list cannot give not_hit; a hit still stands
        return _slot("failed", "detector_failed", list_problem, matches=[])
    return _slot("hit" if matches else "not_hit", matches=matches)


def _rules(
    detector: RuleDetector | None, change: dict, analyzer: Analyzer | None, row: dict | None
) -> dict:
    if detector is None:
        return _slot("not_run", "detector_not_configured", checks=[])
    if change["kind"] == "removed":
        return _slot("not_run", "not_installed_in_head", checks=[])
    if not change["analyzable"]:
        return _slot("not_run", "not_analyzable", checks=[])
    if analyzer is None:
        return _slot("not_run", "analyzer_not_configured", checks=[])
    if row is not None and row["status"] == "unsupported":
        return _slot("not_run", "analysis_unsupported", checks=[])
    if row is None or row["status"] == "failed":
        return _slot("failed", "input_failed", checks=[])
    try:
        # Copies, so a detector cannot change the request or the report's features and evidence.
        found = detector.check(copy.deepcopy(change), copy.deepcopy(row))
        if not isinstance(found, list):
            raise GuardError("Rule detector must return a list")
        checks = [_record(check, CHECK, "rule check") for check in found]
        for check in checks:
            check["locations"] = [_record(x, LOCATION, "rule location") for x in check["locations"]]
    except Exception as exc:  # any detector error is failed, never not_hit
        return _slot("failed", "detector_failed", _failure(exc), checks=[])
    statuses = {check["status"] for check in checks}
    if "hit" in statuses:
        return _slot("hit", checks=checks)
    if "failed" in statuses:  # the failed rules' checks[].detail explain it
        return _slot("failed", "detector_failed", checks=checks)
    return _slot("not_hit", checks=checks)


def scan(
    request: dict,
    analyzer: Analyzer | None,
    predictor: Predictor | None,
    *,
    known_malicious: KnownMaliciousDetector | None = None,
    rules: RuleDetector | None = None,
) -> dict:
    """The report. Detectors are optional (D-15); without them the verdicts are the ML path's."""
    detectors = {
        "known_malicious": _detector_info(known_malicious, KNOWN_MALICIOUS_INFO, "list identity"),
        "rules": _detector_info(rules, RULES_INFO, "ruleset version"),
    }
    list_problem = _list_as_of_problem(detectors["known_malicious"])
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
        ml = "not_run"  # the ML path alone (contract 4.1), whatever the detectors say
        if change["kind"] == "removed":
            item.update(status="removed", reason="not_installed_in_head")
        elif not change["analyzable"]:
            item["reason"] = change["reason"]
        elif row is None:
            item["reason"] = "analysis_missing"
            ml = "failed" if analyzer else "not_run"
        elif row["status"] == "failed":
            item.update(reason="analysis_failed", detail=row["error"])
            ml = "failed"
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
                ml = "hit" if score >= predictor.threshold else "not_hit"
                item.update(status="flagged" if ml == "hit" else "not_flagged", score=score)
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
                ml = "failed"
        malicious = _known_malicious(known_malicious, change, list_problem)
        rule = _rules(rules, change, analyzer, row)
        if malicious["status"] == "hit":
            # D-2, ahead of D-7: a low score or an unfinished ML path never cancels it. The ML
            # path's reason and detail stay, and a failed detector stays in its own slot.
            item["status"] = "flagged"
        elif "failed" in (malicious["status"], rule["status"]):
            # D-7. An unfinished ML path keeps its reason; a finished one keeps its score.
            if item["status"] != "incomplete":
                item.update(status="incomplete", reason="detection_failed")
        item.update(
            known_malicious=malicious,
            rules=rule,
            ml={"status": ml},
            # Display only (D-4): a disagreement never changes status or exit_code.
            rule_ml_agreement=AGREEMENT.get((rule["status"], ml), "undetermined"),
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
        "detectors": detectors,
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
