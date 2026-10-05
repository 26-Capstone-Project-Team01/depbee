import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analysis.artifact import ArtifactAnalyzer
from .contracts import GuardError
from .inference.lightgbm import LightGBMPredictor
from .inputs.npm import build_request
from .pipeline import scan

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
}
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
        cmd.add_argument("--base-lock", required=True, type=Path, help="Previous package-lock.json")
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
            cmd.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _local_sources(args: argparse.Namespace) -> dict[tuple[str, str], Path]:
    if not args.local_source:
        return {}
    if not args.extract or args.local_root is None:
        raise GuardError("--local-source requires --extract and --local-root")
    root = args.local_root.resolve()
    sources = {}
    for spec in args.local_source:
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


def _analyzer(args: argparse.Namespace):
    sources = _local_sources(args)
    if args.analysis:
        return ArtifactAnalyzer(args.analysis)
    if args.extract:
        from .analysis.extractor import ExtractorAnalyzer

        return ExtractorAnalyzer(sources)
    return None


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


def _print_text(report: dict) -> None:
    # A console code page (e.g. cp949) may not encode every character in package data.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    status = OVERALL_LABELS.get(report["status"], report["status"])
    print(f"depbee 검사 결과: {status} (종료 코드 {report['exit_code']})")
    if report["model_id"]:
        print(f"모델: {_clean(report['model_id'])}, 판정 기준 점수 {report['threshold']}")
    print("범위: lockfile에서 바뀐 의존성만 검사했습니다. 프로젝트 전체의 안전성 평가가 아닙니다.")
    for row in report["results"]:
        label = STATUS_LABELS.get(row["status"], row["status"])
        version = row["after_version"] or row["before_version"]
        print()
        print(f"[{label}] {_clean(row['package'])}@{_clean(version)}  ({_clean(row['location'])})")
        if row["score"] is not None:
            print(f"  점수: {row['score']:.3f}")
        if row.get("reason"):
            reason = REASON_LABELS.get(row["reason"], row["reason"])
            print(f"  이유: {_clean(reason)}")
        if row.get("detail"):
            print(f"  상세: {_clean(row['detail'])}")
        if row["evidence"]:
            print("  추출된 사실:")
            for evidence in row["evidence"]:
                print(f"    - {_clean(evidence)}")
        if row.get("explanation"):
            print("  모델 판단에 크게 작용한 feature (+ 위험 쪽, - 정상 쪽):")
            for item in row["explanation"]:
                sign = "+" if item["contribution"] > 0 else "-"
                name = item["feature"]
                print(
                    f"    {sign} {_feature_label(name)} = {_feature_value(name, item['value'])}"
                    f" ({item['contribution']:+.2f})"
                )
    print()
    print("'통과'는 모델의 판정일 뿐 패키지가 안전하다는 보증이 아닙니다.")


def _emit(report: dict, args: argparse.Namespace) -> None:
    payload = json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
    if args.command == "plan" or args.format == "json":
        print(payload, end="")
        return
    _print_text(report)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        request = build_request(args.project, args.base_lock)
        if args.command == "plan":
            _emit(request, args)
            return 0
        analyzer = _analyzer(args)
        predictor = LightGBMPredictor(args.model_dir) if args.model_dir else None
        report = scan(request, analyzer, predictor)
        _emit(report, args)
        return report["exit_code"]
    except (GuardError, OSError, ValueError, RecursionError) as exc:
        error = {"status": "error", "exit_code": 2, "error": str(exc)}
        print(json.dumps(error, ensure_ascii=True), file=sys.stderr)
        return 2
