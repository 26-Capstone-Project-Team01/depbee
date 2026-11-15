import argparse
import errno
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .contracts import GuardError
from .service import check_package, plan_project, preview_update, scan_project

STATUS_LABELS = {
    "flagged": "위험",
    "not_flagged": "통과",
    "incomplete": "보류",
    "removed": "삭제",
}
OVERALL_LABELS = {
    "flagged": "위험 판정 있음",
    "passed": "통과",
    "incomplete": "보류(완료하지 못한 항목 있음)",
}
REASON_LABELS = {
    "analysis_missing": "분석 결과 없음",
    "analysis_failed": "분석 실패",
    "model_missing": "모델 없음",
    "inference_failed": "추론 실패",
    "out_of_training_scope": "학습 범위 밖 입력",
    "no_baseline": "비교할 이전 stable 버전 없음",
    "not_installed_in_head": "현재 lockfile에서 삭제됨",
    "package_identity_changed": "같은 위치의 패키지 이름이 바뀜",
    "workspace_or_non_registry_version": "workspace·링크 또는 registry 버전이 아님",
    "unsupported_registry_source": "npm 공식 registry가 아닌 출처",
    "missing_integrity": "lockfile에 integrity 없음",
    "same_version_artifact_changed": "같은 버전인데 파일 출처·해시가 바뀜",
    "detection_failed": "연결된 탐지기 실패",
}
# Detector slots (docs/result-contract-draft.md 3.2, 3.3); their reasons are a separate namespace.
RULE_STATUS_LABELS = {"hit": "적중", "not_hit": "미적중", "not_run": "미실행", "failed": "실패"}
KNOWN_STATUS_LABELS = {**RULE_STATUS_LABELS, "hit": "일치"}
DETECTOR_REASON_LABELS = {
    "detector_not_configured": "탐지기 연결 안 됨",
    "not_installed_in_head": "현재 lockfile에서 삭제됨",
    "not_analyzable": "분석 대상이 아닌 변경",
    "analyzer_not_configured": "분석기 연결 안 됨",
    "analysis_unsupported": "분석기가 지원하지 않는 변경",
    "input_failed": "탐지기 입력을 얻지 못함",
    "detector_failed": "탐지기 실패",
}
MATCH_KIND_LABELS = {"listed_version": "버전 목록에 있음", "affected_range": "영향 범위에 들어감"}
AGREEMENT_LABELS = {
    "both_hit": "둘 다 적중",
    "rule_only": "규칙만 적중(불일치)",
    "ml_only": "ML 위험 점수만 기준 이상(불일치)",
    "neither_hit": "둘 다 미적중(정상 판정이 아님)",
    "undetermined": "판단하지 않음(규칙이나 ML이 미실행 또는 실패)",
}
ML_LABELS = {"hit": "기준 이상", "not_hit": "기준 미만", "not_run": "미실행", "failed": "실패"}
NOT_CONFIGURED = "연결 안 됨(미실행)"
FEATURE_LABELS = {
    "installScriptPresent": "새 버전에 설치 스크립트 있음",
    "installScriptAdded": "설치 스크립트 추가",
    "scriptEntryAdded": "scripts 항목 추가",
    "newDependencyAdded": "새 의존성 추가",
    "newDependencyCount": "새 의존성 수",
    "updateType": "업데이트 종류",
    "updateInterval": "이전 버전과의 배포 간격",
    "obfChangedFileCount": "추가·수정된 JS 파일 수",
}
METRIC_LABELS = {
    "HexIdentRatio": "16진 형태 식별자 비율",
    "HexNumberRatio": "16진 숫자 비율",
    "BracketAccessRatio": "대괄호 속성 접근 비율",
    "EscapeDensity": "이스케이프 밀도",
    "ShortIdentRatio": "짧은 식별자 비율",
    "MeanIdentLength": "평균 식별자 길이",
    "WhitespaceRatio": "공백 비율",
}
PART_LABELS = {"New": "새 버전", "Change": "변화량", "ChangedCode": "바뀐 코드"}
STATUS_ORDER = {"flagged": 0, "incomplete": 1, "not_flagged": 2, "removed": 3}
# --output is always a JSON file; markdown is a stdout format (e.g. a GitHub job summary).
FORMATS = ("text", "json", "markdown")
SAFETY_NOTE = "'통과'는 모델의 판정일 뿐 패키지가 안전하다는 보증이 아닙니다."


def _cache_arguments(cmd: argparse.ArgumentParser) -> None:
    cache = cmd.add_mutually_exclusive_group()
    cache.add_argument(
        "--cache-dir",
        type=Path,
        help="Extracted-feature cache (default ~/.cache/depbee); use a directory only you can write",
    )
    cache.add_argument("--no-cache", action="store_true", help="Neither read nor write the cache")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze npm updates without installing packages")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("plan", "Export changed version pairs"),
        ("scan", "Analyze changed versions and score them with a LightGBM model"),
    ):
        cmd = commands.add_parser(name, help=help_text)
        cmd.add_argument(
            "project", type=Path, help="Directory containing the new package-lock.json"
        )
        base = cmd.add_mutually_exclusive_group()
        base.add_argument("--base-lock", type=Path, help="Previous package-lock.json")
        base.add_argument(
            "--base-ref",
            metavar="REF",
            help="Use the project's package-lock.json committed in this Git revision "
            "(default without --base-lock: HEAD)",
        )
        cmd.add_argument(
            "--output", type=Path, help="Write a NEW JSON file (never overwrite inputs)"
        )
        if name == "scan":
            source = cmd.add_mutually_exclusive_group()
            source.add_argument("--analysis", type=Path, help="Trusted analyzer output JSON")
            source.add_argument(
                "--extract",
                action="store_true",
                help="Run feature-extractor on each changed version (needs .[extract])",
            )
            cmd.add_argument(
                "--local-source",
                action="append",
                default=[],
                metavar="NAME@VERSION=DIR",
                help="With --extract: read this version from DIR under --local-root "
                "instead of the registry (for versions the registry no longer serves)",
            )
            cmd.add_argument(
                "--local-root", type=Path, help="Directory that every --local-source must be in"
            )
            cmd.add_argument("--model-dir", type=Path, help="Trusted manifest.json + model.txt")
            cmd.add_argument("--format", choices=FORMATS, default="text")
            _cache_arguments(cmd)
    check = commands.add_parser(
        "check",
        help="Check one npm registry version without a lockfile (needs .[extract])",
    )
    check.add_argument(
        "package",
        metavar="NAME@VERSION",
        help="Exact registry version without +build metadata, "
        "e.g. lodash@4.17.21 or @scope/name@1.0.0",
    )
    check.add_argument("--output", type=Path, help="Write a NEW JSON file (never overwrite inputs)")
    check.add_argument("--model-dir", type=Path, help="Trusted manifest.json + model.txt")
    check.add_argument("--format", choices=FORMATS, default="text")
    _cache_arguments(check)
    update = commands.add_parser(
        "update",
        help="Preview npm update in a temporary copy and check the new lockfile; nothing in the "
        "project is changed (needs Node.js with npm and .[extract])",
    )
    update.add_argument(
        "packages",
        nargs="*",
        metavar="NAME",
        help="package.json dependency names to update within their ranges (default: all)",
    )
    update.add_argument(
        "--project", type=Path, default=Path("."), help="Project directory (default: current)"
    )
    update.add_argument(
        "--output", type=Path, help="Write a NEW JSON file (never overwrite inputs)"
    )
    update.add_argument("--model-dir", type=Path, help="Trusted manifest.json + model.txt")
    update.add_argument("--format", choices=FORMATS, default="text")
    _cache_arguments(update)
    serve = commands.add_parser(
        "mcp",
        help="Serve the read-only check_package and scan_lockfile tools over MCP stdio "
        "(needs .[mcp] and, to analyze, .[extract])",
    )
    serve.add_argument("--model-dir", type=Path, help="Trusted manifest.json + model.txt")
    return parser


def _split_package(spec: str) -> tuple[str, str]:
    """NAME@VERSION as check takes it (CLI and MCP); the service checks the two parts."""
    name, at, version = spec.rpartition("@")
    if not at or not name:
        raise GuardError(f"check needs NAME@VERSION, e.g. lodash@4.17.21: {spec!r}")
    return name, version


def _clean(value: object) -> str:
    """Escape characters that a package could use to control the terminal."""
    text = str(value)
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in text)


def _feature_label(name: str) -> str:
    if name in FEATURE_LABELS:
        return FEATURE_LABELS[name]
    for metric, metric_label in METRIC_LABELS.items():
        for part, part_label in PART_LABELS.items():
            if name == f"obf{metric}{part}":
                return f"{metric_label}({part_label})"
    return name


def _feature_value(name: str, value: object) -> str:
    if value is None:
        return "계산 대상 없음"
    if isinstance(value, bool):
        return "예" if value else "아니오"
    if name == "updateInterval":
        return f"{value / 86400:.1f}일"
    if isinstance(value, float):
        return f"{value:.3g}"
    return _clean(value)


def _progress(index: int, total: int, change: dict) -> None:
    after = change["after"]
    name = f"{_clean(after['name'])}@{_clean(after['version'])}"
    print(f"분석 중 {index}/{total}: {name}", file=sys.stderr, flush=True)


def _summary(results: list[dict], package_input: bool) -> str:
    counts = Counter(row["status"] for row in results)
    text = (
        f"{'검사한 패키지' if package_input else '바뀐 의존성'} {len(results)}개: "
        f"위험 {counts['flagged']}, 통과 {counts['not_flagged']}, 보류 {counts['incomplete']}"
    )
    return text + (f", 삭제 {counts['removed']}" if counts["removed"] else "")


# The helpers below only read the report: status, reason and exit_code come from pipeline.scan().
# esc and label are _clean/_text_label for text and _md/_md_label for Markdown.


def _text_label(labels: dict, value: object) -> str:
    return labels[value] if value in labels else _clean(value)


def _notices(report: dict) -> list[tuple[str, str]]:
    """Emphasized notices ahead of the results: known malicious matches, then unfinished items."""
    rows = report["results"]
    known = sum((row.get("known_malicious") or {}).get("status") == "hit" for row in rows)
    pending = sum(row["status"] == "incomplete" for row in rows)
    notices = []
    if known:
        notices.append((
            f"경고: 기지 악성 기록 일치 {known}개.",
            "낮은 ML 위험 점수는 이 경고를 취소하지 않습니다. 이 일치로 위험 판정했습니다.",
        ))  # fmt: skip
    if pending:
        notices.append((f"보류 {pending}개.", "검사를 끝내지 못한 항목이며 통과가 아닙니다."))
    return notices


def _detector_setup(report: dict, esc) -> list[str]:
    """Which detectors besides the model ran; an unconnected one is said here, not per result."""
    if "detectors" not in report:
        return []
    known, rules = report["detectors"]["known_malicious"], report["detectors"]["rules"]
    return [
        "기지 악성 목록: "
        + (f"{esc(known['source'])}, 기준 시점 {esc(known['list_as_of'])}" if known
           else NOT_CONFIGURED),
        "규칙: " + (esc(rules["ruleset_version"]) if rules else NOT_CONFIGURED),
    ]  # fmt: skip


def _ml_score(row: dict, label) -> str | None:
    """The ML risk score with the ML path's own status (contract 4.1); not a probability.

    An unknown ml.status is shown as other unknown states are (label); no ml field shows none.
    """
    status = (row.get("ml") or {}).get("status")
    shown = None if status is None else label(ML_LABELS, status)
    if row["score"] is not None:
        return f"{row['score']:.3f}" + (f" ({shown})" if shown is not None else "")
    if row["status"] != "removed" and shown is not None:
        return f"없음({shown})"
    return None


def _alternative(row: dict) -> tuple[str, str] | None:
    """A version already in the report to consider instead of a risky one, and where it came from.

    depbee has not checked it and it is no safety guarantee. None when there is nothing sound to
    show: not flagged, another package at the location, or the same version as the risky one.
    """
    if row["status"] != "flagged" or row.get("reason") == "package_identity_changed":
        return None
    if row["before_version"] is not None:
        version, source = row["before_version"], "lockfile의 이전 버전"
    else:
        version, source = row.get("compared_version"), "비교 기준 버전"
    if version is None or version == row["after_version"]:
        return None
    return version, source


def _slot(slot: dict, labels: dict, esc, label) -> str:
    text = label(labels, slot["status"])
    if slot.get("reason"):
        text += f" ({label(DETECTOR_REASON_LABELS, slot['reason'])})"
    if slot.get("detail"):
        text += f", 상세: {esc(slot['detail'])}"
    return text


def _detector_lines(row: dict, esc, label) -> list[tuple[str, list[str]]]:
    """Each connected detector's slot of one result as a line and its sub-lines."""
    lines = []
    known, rules = row.get("known_malicious"), row.get("rules")
    if known and known.get("reason") != "detector_not_configured":
        matches = [
            f"{esc(match['advisory_id'])} ({label(MATCH_KIND_LABELS, match['match_kind'])}"
            + (f", 영향 버전 {esc(match['affected'])}" if match["affected"] is not None else "")
            + ")"
            for match in known["matches"]
        ]
        lines.append((f"기지 악성: {_slot(known, KNOWN_STATUS_LABELS, esc, label)}", matches))
    if rules and rules.get("reason") != "detector_not_configured":
        checks = []
        for check in rules["checks"]:
            text = (f"{label(RULE_STATUS_LABELS, check['status'])} {esc(check['rule_id'])}"
                    f" {esc(check['rule_version'])}")  # fmt: skip
            if check["evidence"]:
                text += ", 근거: " + "; ".join(esc(evidence) for evidence in check["evidence"])
            if check["locations"]:
                places = (f"{x['file']}:{x['line']}" if x["line"] is not None else x["file"]
                          for x in check["locations"])  # fmt: skip
                text += ", 위치: " + ", ".join(esc(place) for place in places)
            if check["detail"]:
                text += f", 상세: {esc(check['detail'])}"
            checks.append(text)
        lines.append((f"규칙: {_slot(rules, RULE_STATUS_LABELS, esc, label)}", checks))
        agreement = label(AGREEMENT_LABELS, row["rule_ml_agreement"])
        lines.append((f"규칙/ML: {agreement}. 판정에 쓰지 않는 표시입니다.", []))
    return lines


def _print_text(report: dict) -> None:
    # A console code page (e.g. cp949) may not encode every character in package data.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    package_input = report.get("input_kind") == "package"
    status = OVERALL_LABELS.get(report["status"], report["status"])
    print(f"depbee 검사 결과: {status} (종료 코드 {report['exit_code']})")
    print(_summary(report["results"], package_input))
    for emphasized, rest in _notices(report):
        print(f"{emphasized} {rest}")
    if report["model_id"]:
        print(f"모델: {_clean(report['model_id'])}, 판정 기준 점수 {report['threshold']}")
    for line in _detector_setup(report, _clean):
        print(line)
    if package_input:
        print(
            "범위: lockfile 없이 registry 정보로 이 버전 하나만 검사했습니다. "
            "프로젝트 전체의 안전성 평가가 아닙니다."
        )
    else:
        print(
            "범위: lockfile에서 바뀐 의존성만 검사했습니다. 프로젝트 전체의 안전성 평가가 아닙니다."
        )
    # Only extraction reports (scan --extract, check) carry times.
    if report.get("elapsed_seconds") is not None:
        print(f"소요 시간: {report['elapsed_seconds']:.3f}초")
    # Risky and unfinished results first; the JSON report keeps the lockfile order.
    rows = sorted(
        report["results"],
        key=lambda r: (STATUS_ORDER.get(r["status"], len(STATUS_ORDER)), -(r["score"] or 0.0)),
    )
    for row in rows:
        label = STATUS_LABELS.get(row["status"], row["status"])
        version = row["after_version"] or row["before_version"]
        print()
        print(f"[{label}] {_clean(row['package'])}@{_clean(version)}  ({_clean(row['location'])})")
        score = _ml_score(row, _text_label)
        if score is not None:
            print(f"  ML 위험 점수: {score}")
        if row.get("reason"):
            reason = REASON_LABELS.get(row["reason"], row["reason"])
            print(f"  이유: {_clean(reason)}")
        alternative = _alternative(row)
        if alternative:
            print(f"  대안(안전 보증 아님): {_clean(alternative[0])} ({alternative[1]})")
        if row.get("detail"):
            print(f"  상세: {_clean(row['detail'])}")
        for line, subs in _detector_lines(row, _clean, _text_label):
            print(f"  {line}")
            for sub in subs:
                print(f"    - {sub}")
        if row.get("elapsed_seconds") is not None:
            cached = " (캐시한 feature 사용)" if row.get("cache_hit") else ""
            print(f"  분석 시간: {row['elapsed_seconds']:.3f}초{cached}")
        if row["evidence"]:
            print("  추출된 사실:")
            for evidence in row["evidence"]:
                print(f"    - {_clean(evidence)}")
        rest = row.get("explanation_rest")
        if row.get("explanation") or rest:
            print("  판단에 크게 작용한 특징 (+ 위험 쪽, - 정상 쪽):")
            for item in row.get("explanation", []):
                sign = "+" if item["contribution"] > 0 else "-"
                name = item["feature"]
                print(
                    f"    {sign} {_feature_label(name)} = {_feature_value(name, item['value'])}"
                    f" ({item['contribution']:+.2f})"
                )
        if rest:
            shown = sum(item["contribution"] for item in row.get("explanation", []))
            total = shown + rest["others_sum"] + rest["base_value"]
            print(
                f"    나머지 특징 {rest['others_count']}개 합 {rest['others_sum']:+.2f},"
                f" 모델 기준값 {rest['base_value']:+.2f}"
                f" (합계 {total:+.2f} → 점수 {row['score']:.3f})"
            )
    print()
    print(SAFETY_NOTE)


def _md(value: object) -> str:
    """Report text as a Markdown code span, so that no HTML, link, image, emphasis or autolink in
    package data is rendered. Control characters are escaped as in text output; the fence is
    longer than any backtick run inside, and the padding spaces are dropped by CommonMark."""
    text = _clean(value)
    fence = "`" * (max((len(run) for run in re.findall("`+", text)), default=0) + 1)
    return f"{fence} {text} {fence}"


def _md_label(labels: dict, value: object) -> str:
    """Our Korean label, or the unknown value from the report as a code span."""
    return labels[value] if value in labels else _md(value)


def _cell(text: str) -> str:
    # GFM splits table cells on every unescaped pipe, even inside code spans.
    return text.replace("|", "\\|")


def _print_markdown(report: dict) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    package_input = report.get("input_kind") == "package"
    timed = report.get("elapsed_seconds") is not None
    lines = [
        f"## depbee 검사 결과: {_md_label(OVERALL_LABELS, report['status'])}"
        f" (종료 코드 {report['exit_code']})",
        "",
        f"- {_summary(report['results'], package_input)}",
    ]
    lines += [f"- **{emphasized}** {rest}" for emphasized, rest in _notices(report)]
    if report["model_id"]:
        lines.append(f"- 모델: {_md(report['model_id'])}, 판정 기준 점수 {report['threshold']}")
    lines += [f"- {line}" for line in _detector_setup(report, _md)]
    checked = (
        "lockfile 없이 registry 정보로 이 버전 하나만" if package_input
        else "lockfile에서 바뀐 의존성만"
    )  # fmt: skip
    lines.append(f"- 범위: {checked} 검사했습니다. 프로젝트 전체의 안전성 평가가 아닙니다.")
    if timed:
        lines.append(f"- 소요 시간: {report['elapsed_seconds']:.3f}초")
    rows = sorted(
        report["results"],
        key=lambda r: (STATUS_ORDER.get(r["status"], len(STATUS_ORDER)), -(r["score"] or 0.0)),
    )
    # Detector columns only when a detector is connected; otherwise the list above says so.
    connected = [
        (key, name, labels)
        for key, name, labels in (("known_malicious", "기지 악성", KNOWN_STATUS_LABELS),
                                  ("rules", "규칙", RULE_STATUS_LABELS))
        if (report.get("detectors") or {}).get(key) is not None
    ]  # fmt: skip
    if rows:
        header = ["판정", "패키지", "설치될 버전", "비교 버전", *(c[1] for c in connected),
                  "ML 위험 점수", "이유", "위치"]  # fmt: skip
        lines += ["", "| " + " | ".join(header + ["분석 시간"] * timed) + " |",
                  "|" + " --- |" * (len(header) + timed)]  # fmt: skip
    for row in rows:
        cells = [
            _md_label(STATUS_LABELS, row["status"]),
            _md(row["package"]),
            _md(row["after_version"]) if row["after_version"] is not None else "-",
            _md(row["compared_version"]) if row.get("compared_version") is not None else "-",
        ]
        for key, _, labels in connected:
            status = (row.get(key) or {}).get("status")
            cell = "-" if status is None else _md_label(labels, status)
            cells.append(f"**{cell}**" if key == "known_malicious" and status == "hit" else cell)
        score = _ml_score(row, _md_label)
        cells += [
            score if score is not None else "-",
            _md_label(REASON_LABELS, row["reason"]) if row.get("reason") else "-",
            _md(row["location"]),
        ]
        if timed:
            seconds = row.get("elapsed_seconds")
            cache = ", 캐시 사용" if row.get("cache_hit") else ""
            cells.append(f"{seconds:.3f}초{cache}" if seconds is not None else "-")
        lines.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    for row in rows:
        lines += _markdown_details(row)
    lines += ["", f"> {SAFETY_NOTE}"]
    print("\n".join(lines))


def _markdown_details(row: dict) -> list[str]:
    """Detector slots, extracted facts and the model's explanation of one result, kept apart."""
    explanation, rest = row.get("explanation") or [], row.get("explanation_rest")
    detectors = _detector_lines(row, _md, _md_label)
    alternative = _alternative(row)
    if not (
        alternative or row.get("detail") or detectors or row.get("evidence") or explanation or rest
    ):
        return []
    target = _md(f"{row['package']}@{row['after_version'] or row['before_version']}")
    lines = ["", f"### {_md_label(STATUS_LABELS, row['status'])}: {target}", ""]
    if alternative:
        # The heading has no location and rows without details have no section, so say which.
        lines.append(
            f"- 대안(안전 보증 아님): {_md(alternative[0])}"
            f" ({alternative[1]}, 위치 {_md(row['location'])})"
        )
    if row.get("detail"):
        lines.append(f"- 상세: {_md(row['detail'])}")
    for line, subs in detectors:
        lines.append(f"- {line}")
        lines += [f"  - {sub}" for sub in subs]
    if row.get("evidence"):
        lines.append("- 추출된 사실:")
        lines += [f"  - {_md(evidence)}" for evidence in row["evidence"]]
    if explanation or rest:
        lines.append("- 모델 설명, ML 위험 점수에 크게 작용한 특징(기여도 + 위험 쪽, - 정상 쪽):")
        for item in explanation:
            name = item["feature"]
            label = _feature_label(name)
            label = _md(name) if label == name else label
            lines.append(
                f"  - {label} = {_md(_feature_value(name, item['value']))}"
                f" ({item['contribution']:+.2f})"
            )
        if rest:
            shown = sum(item["contribution"] for item in explanation)
            total = shown + rest["others_sum"] + rest["base_value"]
            lines.append(
                f"  - 나머지 특징 {rest['others_count']}개 합 {rest['others_sum']:+.2f},"
                f" 모델 기준값 {rest['base_value']:+.2f}"
                f" (합계 {total:+.2f} → 점수 {row['score']:.3f})"
            )
    return lines


def _preview_lines(preview: dict, esc) -> list[str]:
    """The update preview header; the report follows with its own renderer."""
    targets = preview["targets"]
    return [
        "대상: " + (", ".join(esc(name) for name in targets) if targets
                    else "package.json 범위 안의 전체 의존성"),
        f"npm {esc(preview['npm_version'])}, package.json "
        + ("바뀜" if preview["package_json_changed"] else "변경 없음")
        + f", lockfile에서 바뀐 항목 {preview['changed_count']}개",
        *preview["notices"],
    ]  # fmt: skip


def _emit(report: dict, args: argparse.Namespace, preview: dict | None = None) -> None:
    data = report if preview is None else {"preview": preview, "report": report}
    payload = json.dumps(data, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
    if args.command == "plan" or args.format == "json":
        print(payload, end="")
        return
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    if args.format == "markdown":
        if preview is not None:
            lines = ["## depbee 업데이트 미리보기", ""]
            lines += [f"- {line}" for line in _preview_lines(preview, _md)]
            print("\n".join(lines) + "\n")
        _print_markdown(report)
        return
    if preview is not None:
        print("depbee 업데이트 미리보기")
        for line in _preview_lines(preview, _clean):
            print(line)
        print()
    _print_text(report)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "mcp":
            from .mcp import serve

            serve(args.model_dir)
            return 0
        # Refuse a taken --output before any download or extraction; _emit's "x" mode still
        # guards against a file created meanwhile. Same error text as that open().
        if args.output is not None and args.output.exists():
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(args.output))
        if args.command == "plan":
            _emit(plan_project(args.project, args.base_lock, base_ref=args.base_ref), args)
            return 0
        progress = None
        # Extraction takes seconds per package; show progress unless stdout is JSON.
        if args.format == "text" and (args.command in ("check", "update") or args.extract):
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(errors="backslashreplace")
            progress = _progress
        if args.command == "update":
            result = preview_update(
                args.project,
                args.packages,
                model_dir=args.model_dir,
                progress=progress,
                cache_dir=args.cache_dir,
                no_cache=args.no_cache,
            )
            _emit(result["report"], args, result["preview"])
            return result["report"]["exit_code"]
        if args.command == "check":
            name, version = _split_package(args.package)
            report = check_package(
                name,
                version,
                model_dir=args.model_dir,
                progress=progress,
                cache_dir=args.cache_dir,
                no_cache=args.no_cache,
            )
            _emit(report, args)
            return report["exit_code"]
        report = scan_project(
            args.project,
            args.base_lock,
            base_ref=args.base_ref,
            analysis=args.analysis,
            extract=args.extract,
            local_sources=args.local_source,
            local_root=args.local_root,
            model_dir=args.model_dir,
            progress=progress,
            cache_dir=args.cache_dir,
            no_cache=args.no_cache,
        )
        _emit(report, args)
        return report["exit_code"]
    except (GuardError, OSError, ValueError, RecursionError) as exc:
        error = {"status": "error", "exit_code": 2, "error": str(exc)}
        print(json.dumps(error, ensure_ascii=True), file=sys.stderr)
        return 2
