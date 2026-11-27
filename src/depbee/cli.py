import argparse
import errno
import json
import os
import re
import shlex
import subprocess
import sys
from collections import Counter
from pathlib import Path

from . import __version__, config, terminal
from .actions import plain_number, score_raw, score_text
from .contracts import GuardError
from .service import (
    APPLY_MODES,
    ASSET_VARIABLES,
    active_assets,
    apply_update,
    check_package,
    install_checked,
    plan_project,
    preview_update,
    scan_project,
    setup_assets,
)

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
# A report without the detector fields (older than them, contract 6): unknown, never not_hit.
NOT_CHECKED = "확인 안 됨"
# After an ML status derived from older fields when a report has no ml (contract 4.1, 6).
ML_DERIVED = "참고값"
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
# update --apply (service.apply_update): outcome, mode, reason and gate cause labels.
OUTCOME_LABELS = {
    "applied": "반영함",
    "unchanged": "바뀐 항목 없음(반영할 것 없음)",
    "refused": "반영하지 않음",
    "failed": "실패",
}
MODE_LABELS = {"lockfile": "lockfile 반영", "install": "설치까지(npm ci --ignore-scripts)"}
CONFIRM_OPTION = "--confirm-warnings"
APPLY_REASON_LABELS = {
    "known_malicious_hit": "기지 악성 기록 일치(예외 없이 거부)",
    "confirmation_required": f"확인이 필요한 항목이 있는데 {CONFIRM_OPTION}가 없음",
    "project_npmrc": "프로젝트 .npmrc가 있어 설치 거부",
    "project_unsupported": "미리보기 뒤 프로젝트가 지원 범위를 벗어남",
    "project_changed": "미리보기 뒤 package.json 또는 package-lock.json이 바뀜",
    "new_lock_mismatch": "반영할 lockfile이 검사한 것과 다름",
    "new_files_unsupported": "npm이 계산한 새 파일이 지원 범위를 벗어남(registry 밖 출처 등)",
    "integrity_missing": "새 lockfile에 유효한 integrity 없는 항목이 있어 설치 거부",
    "scratch_in_project": "설치용 임시 폴더가 프로젝트 안에 생김(TMP·TEMP 확인)",
    "backup_failed": "원본을 백업하지 못함",
    "write_failed": "프로젝트 파일을 바꾸지 못함",
    "install_failed": "npm ci 실패",
    "lockfile_changed": "npm ci 뒤 package.json 또는 package-lock.json이 반영한 것과 다름",
}
CAUSE_LABELS = {
    "known_malicious_hit": "기지 악성 기록 일치",
    "ml_hit": "ML 위험 점수 기준 이상",
    "incomplete": "보류(통과가 아님)",
    "known_malicious_unchecked": "기지 악성 목록 미확인",
}
# depbee guard ci (service.install_checked) and its settings commands (depbee.guard).
GUARD_REASON_LABELS = {
    **APPLY_REASON_LABELS,
    "confirmation_required": "확인이 필요한 항목이 있어 설치하지 않음(가드는 확인 없이 통과한 결과만 설치)",
    "project_changed": "검사 뒤 package.json 또는 package-lock.json이 바뀜",
    "removal_only": "삭제만 있어 검사한 설치 항목이 없음",
}
GUARD_REMOVAL = (
    "Git HEAD와 비교해 삭제만 있어 depbee가 검사한 설치 항목이 없으므로 설치하지 않았습니다. 남은 "
    "의존성을 그대로 설치할지는 사용자가 정하고, 정하면 사용자가 터미널에서 직접 "
    "npm ci --ignore-scripts를 실행합니다."
)
GUARD_OUTCOME_LABELS = {
    "applied": "설치함",
    "unchanged": "검사한 변경 없음(설치하지 않음)",
    "refused": "설치하지 않음",
    "failed": "실패(설치하지 않았거나 끝내지 못함)",
}
GUARD_INSTALLED = (
    "검사한 package-lock.json 그대로 설치했습니다. "
    "통과는 모델과 목록의 판정일 뿐 안전 보증이 아닙니다."
)
GUARD_NOTHING = (
    "Git HEAD와 비교해 바뀐 의존성이 없어 검사한 것이 없으므로 설치하지 않았습니다. 변경 0건은 통과가 "
    "아닙니다. 커밋된 의존성을 그대로 설치할지는 사용자가 정하고, 정하면 사용자가 터미널에서 직접 "
    "npm ci --ignore-scripts를 실행합니다."
)
GUARD_STOPPED = (
    "설치하지 않았습니다. 판정과 이유를 사용자에게 보여 주고 결정을 기다리세요. 파일이 바뀌었으면 "
    "변경을 확인한 뒤 depbee guard ci를 다시 실행합니다."
)
GUARD_CI_FAILED = (
    "npm ci를 실행했지만 끝내지 못했거나 그 뒤 파일이 검사한 것과 달라졌습니다. node_modules는 중간 "
    "상태일 수 있습니다. 판정과 오류를 사용자에게 보여 주고, 원인을 확인한 뒤 depbee guard ci를 다시 "
    "실행합니다."
)
GUARD_ABSENT = "  depbee 설치 가드 훅이 없습니다. depbee guard enable SETTINGS로 추가합니다."
GUARD_NOT_RUN = (
    "  설정 파일의 명령은 실행하지 않았습니다. 이 depbee로 다시 켜려면 depbee guard enable SETTINGS를 "
    "실행하고, 위 항목은 직접 확인해 고치거나 지웁니다."
)
GUARD_SELF_TEST_PASSED = (
    "  자가 시험 통과: 검사 없는 npm 설치를 거부하고 조회 명령은 그대로 둡니다."
)
GUARD_SELF_TEST_FAILED = "  자가 시험 실패: {problem}"
GUARD_LINK = "  (링크 {named}이(가) 가리키는 파일입니다. 링크는 그대로 둡니다.)"
GUARD_SAME = "바꿀 것이 없습니다."
GUARD_ENABLED = (
    "depbee 설치 가드 훅을 추가했습니다. 다른 설정과 훅은 그대로입니다. Claude Code는 설정 파일 변경을 "
    "다시 읽으며, /hooks에서 확인할 수 있습니다. Claude Code 2.1.295 이상이 필요합니다(onFailure)."
)
GUARD_DISABLED = "depbee 설치 가드 훅을 제거했습니다. 다른 설정과 훅은 그대로입니다."
GUARD_BACKUP = (
    "이전 파일은 사용자 전용 폴더에 백업했습니다: {backup}\n"
    "되돌리려면 그 파일을 {path}에 복사합니다."
)
# No path or package text: the report above is already printed and unchanged.
HISTORY_FAILED = (
    "depbee: 이 검사 결과를 로컬 이력에 기록하지 못했습니다. 출력과 종료 코드는 그대로입니다."
)
# update --apply only, after its result is printed; the error JSON of the file follows it.
OUTPUT_FAILED = (
    "depbee: 업데이트 반영 결과를 --output 파일에 쓰지 못했습니다. 반영 결과는 출력에 있는 그대로이며, "
    "다음 오류는 이 파일에 관한 것입니다."
)
WARNING = "경고:"  # starts the known malicious notice (_notices); _print_text colors by it
# Colors of an apply outcome on an interactive terminal (terminal.painter tones).
OUTCOME_TONES = {
    "applied": "passed", "unchanged": "removed", "refused": "incomplete", "failed": "flagged",
}  # fmt: skip
# depbee dashboard --background, --status and --stop (dashboard.lifecycle): the line after the
# address, or the only line.
BACKGROUND_STARTED = (
    "백그라운드에서 실행 중입니다. 이 주소를 브라우저에서 여세요. 주소를 다시 보려면 "
    "depbee dashboard --status, 종료하려면 depbee dashboard --stop을 실행하세요."
)
BACKGROUND_RUNNING = (
    "이미 백그라운드에서 실행 중이어서 새로 시작하지 않았습니다. 옵션을 바꿔 다시 시작하려면 "
    "depbee dashboard --stop 뒤에 실행하세요."
)
BACKGROUND_STATUS = (
    "백그라운드에서 실행 중입니다(PID {pid}, 시작 {started_at}). 종료하려면 "
    "depbee dashboard --stop을 실행하세요."
)
BACKGROUND_NONE = (
    "실행 중인 백그라운드 대시보드가 없습니다. 시작하려면 depbee dashboard --background를 "
    "실행하세요."
)
BACKGROUND_UNRESPONSIVE = (
    "백그라운드 대시보드 프로세스가 있지만 응답하지 않습니다(시작 중이거나, 하던 작업을 "
    "마치고 종료하는 중). 잠시 뒤 다시 확인하세요."
)
BACKGROUND_STOPPED = (
    "백그라운드 대시보드를 종료했습니다. 다시 시작할 때까지 그 주소는 열리지 않습니다."
)
# depbee setup (config, service.setup_assets, service.active_assets).
ASSET_NAMES = {"model_dir": "모델", "known_malicious_dir": "기지 악성 색인"}
# What an asset's version is: the model's model_id, the index's list_as_of.
VERSION_LABELS = {"model_dir": "모델 ID", "known_malicious_dir": "기준 시점"}
# Where an asset in use comes from (service.active_assets); variable: ASSET_VARIABLES of it.
SOURCE_LABELS = {
    "option": "명령 옵션",
    "environment": "환경 변수 {variable}",
    "saved": "저장된 설정",
    "bundled": "depbee 동봉 기본값",
}
SETUP_NONE = "저장된 자산 설정이 없습니다."
SETUP_HOW = (
    "다른 모델이나 색인을 쓰려면 depbee setup DIR을 실행하세요. DIR/model에는 model.txt와 "
    "manifest.json, DIR/index에는 index.json과 manifest.json을 둡니다. 두 폴더 중 없는 쪽은 "
    "depbee에 동봉된 기본값을 그대로 씁니다."
)
SETUP_CLEARED = (
    "저장된 자산 설정을 지웠습니다. 옵션이나 환경 변수로 지정하지 않으면 모델과 기지 악성 "
    "색인 모두 depbee에 동봉된 기본값을 씁니다."
)
# In place of a folder that depbee setup DIR did not save (DIR has no such subfolder).
SETUP_DEFAULT = "저장하지 않음(depbee 동봉 기본값 사용)"
SETUP_SAVED = (
    "이제 scan, check, update, dashboard, mcp에 --model-dir과 --known-malicious-dir을 주지 "
    "않아도 이 자산을 씁니다. 에이전트에도 경로 옵션 없이 등록합니다."
)
# Instead of the registration commands, when this copy has no command that runs it from any
# folder (_installed).
SETUP_NOT_INSTALLED = (
    "  지금 실행한 depbee는 이 Python에 설치된 사본이 아니어서(설치하지 않은 소스 폴더에서 "
    "실행했거나, 같은 Python에 다른 사본이 설치돼 있음) 에이전트가 다른 폴더에서 이 버전을 "
    "실행할 명령이 없습니다. 에이전트가 쓸 Python 환경에 이 버전을 설치한 뒤, 그 환경의 "
    "depbee로 depbee setup DIR을 다시 실행하면 등록 명령이 나옵니다."
)
# On stderr of an interactive terminal, after a setup or a background start (_warn_shared).
SHARED_FOLDER = (
    "주의: 사용자 설정 폴더({folder})는 이 PC의 다른 계정도 열 수 있습니다(Users, Everyone 같은 "
    "그룹에 권한이 있음). 이 폴더에는 신뢰하는 자산 경로(config.json)와 백그라운드 대시보드의 "
    "주소·제어 값(dashboard.json)이 있습니다. 폴더 권한에서 그 그룹을 빼거나, 아직 없는 "
    "경로를 DEPBEE_CONFIG_DIR로 지정해 depbee가 본인 전용 폴더를 만들게 하세요."
)
# Run by the Python that runs this depbee, started in no particular folder: 0 if what it
# imports as depbee is the folder given (_installed).
_SAME_COPY = (
    "import os, sys, depbee; sys.exit(not os.path.samefile(depbee.__path__[0], sys.argv[1]))"
)


def _cache_arguments(cmd: argparse.ArgumentParser) -> None:
    cache = cmd.add_mutually_exclusive_group()
    cache.add_argument(
        "--cache-dir",
        type=Path,
        help="Extracted-feature cache (default ~/.cache/depbee); use a directory only you can write",
    )
    cache.add_argument("--no-cache", action="store_true", help="Neither read nor write the cache")


def _asset_directory(value: str) -> Path:
    if not value.strip():
        raise argparse.ArgumentTypeError("give a non-empty trusted directory or omit the option")
    return Path(value)


def _asset_arguments(cmd: argparse.ArgumentParser) -> None:
    cmd.add_argument(
        "--model-dir",
        type=_asset_directory,
        help="Trusted manifest.json + model.txt (default: DEPBEE_MODEL_DIR, then the folder "
        "saved by depbee setup, then the model shipped with depbee)",
    )
    cmd.add_argument(
        "--known-malicious-dir",
        type=_asset_directory,
        help="Trusted manifest.json + index.json of a known malicious list (default: "
        "DEPBEE_KNOWN_MALICIOUS_DIR, then the folder saved by depbee setup, then the index "
        "shipped with depbee)",
    )


def _parser() -> argparse.ArgumentParser:
    # The top of --help is the start screen's (main() without arguments): terminal.head, guide.
    parser = argparse.ArgumentParser(
        prog="depbee",
        description="\n".join(terminal.head(__version__, sys.stdout)),
        epilog="\n".join(terminal.guide()),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
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
                help="Run depbee-analyzer on each changed version (needs .[extract])",
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
            _asset_arguments(cmd)
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
    _asset_arguments(check)
    check.add_argument("--format", choices=FORMATS, default="text")
    _cache_arguments(check)
    update = commands.add_parser(
        "update",
        help="Preview npm update in a temporary copy and check the new lockfile; with --apply, "
        "write it to the project or also run npm ci --ignore-scripts (needs Node.js with npm "
        "and .[extract])",
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
    _asset_arguments(update)
    update.add_argument("--format", choices=FORMATS, default="text")
    _cache_arguments(update)
    update.add_argument(
        "--apply",
        choices=APPLY_MODES,
        help="After the check, write the checked package-lock.json (and package.json if npm "
        "changed it) to the project (lockfile), or also run npm ci --ignore-scripts there "
        "(install; refused if the project has a .npmrc). The two original files are backed up "
        "next to the history file first. Known malicious matches are always refused",
    )
    update.add_argument(
        CONFIRM_OPTION,
        action="store_true",
        help="With --apply: proceed although the output lists items with an ML risk score at or "
        "above the threshold, incomplete items, or items not checked against a known malicious "
        "list (every item while no such list is connected). Known malicious matches are refused "
        "anyway",
    )
    setup = commands.add_parser(
        "setup",
        help="Show the model and the known malicious index in use: their folders, the model ID "
        "and the list time (by default those shipped with depbee; nothing is written). With "
        "DIR, save a trusted asset folder of your own once (DIR/model and DIR/index) for every "
        "later command and MCP registration",
    )
    setup.add_argument(
        "assets_dir",
        nargs="?",
        type=_asset_directory,
        metavar="DIR",
        help="Folder with model/ (model.txt, manifest.json) and index/ (index.json, "
        "manifest.json); for a subfolder that does not exist, the asset shipped with depbee "
        "stays in use",
    )
    setup.add_argument(
        "--clear",
        action="store_true",
        help="Remove the saved settings: back to the model and index shipped with depbee",
    )
    guard = commands.add_parser(
        "guard",
        help="Claude Code install guard (docs/claude-guard.md): install a checked lockfile, or "
        "add, check or remove the PreToolUse hook in one settings file",
    )
    actions = guard.add_subparsers(dest="guard_command", required=True)
    ci = actions.add_parser(
        "ci",
        help="Check the project's package-lock.json change from Git HEAD now and, only if at "
        "least one added or updated package was analyzed and every item passes, install those "
        "same bytes with npm ci --ignore-scripts; no change or removals only install nothing "
        "(needs Node.js with npm and .[extract]). No model, index, cache or base option",
    )
    ci.add_argument("project", nargs="?", type=Path, default=Path("."), help="Project directory")
    ci.add_argument("--format", choices=("text", "json"), default="text")
    for name, help_text in (
        ("enable", "Add the guard's hook (this Python, exec form) to SETTINGS after a self-test; "
                   "every other setting and hook stays"),
        ("status", "Show the guard's hook in SETTINGS and self-test it; exit 0 only if it works"),
        ("disable", "Remove the guard's hook from SETTINGS; every other setting and hook stays"),
    ):  # fmt: skip
        action = actions.add_parser(name, help=help_text)
        action.add_argument(
            "settings", type=Path, metavar="SETTINGS",
            help="A Claude Code settings file, e.g. .claude/settings.local.json of a project",
        )  # fmt: skip
    serve = commands.add_parser(
        "mcp",
        help="Serve the read-only check_package and scan_lockfile tools over MCP stdio "
        "(needs .[mcp] and, to analyze, .[extract])",
    )
    _asset_arguments(serve)
    dashboard = commands.add_parser(
        "dashboard",
        help="Serve the local dashboard on 127.0.0.1: registered projects, their dependencies "
        "and recorded reports, update previews and applies (needs .[web]; previews also need "
        "Node.js with npm and .[extract])",
    )
    from .dashboard import DEFAULT_PORT  # no web library is imported with it

    # No default here: _dashboard() tells a port that was given from one that was not.
    dashboard.add_argument(
        "--port", type=int,
        help=f"Port on 127.0.0.1 (default {DEFAULT_PORT}, so that the address stays "
        f"http://127.0.0.1:{DEFAULT_PORT}/ after a restart; 0: a free port)",
    )  # fmt: skip
    _asset_arguments(dashboard)
    _cache_arguments(dashboard)
    mode = dashboard.add_mutually_exclusive_group()
    mode.add_argument(
        "--background",
        action="store_true",
        help="Start it as a background process that outlives this terminal, wait until it "
        "answers and print its address; if one already runs, print that one's address instead",
    )
    mode.add_argument(
        "--status",
        action="store_true",
        help="Print the address of the running background dashboard, if there is one",
    )
    mode.add_argument(
        "--stop",
        action="store_true",
        help="Ask the background dashboard to stop and wait until its process has ended",
    )
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
            f"{WARNING} 기지 악성 기록 일치 {known}개.",
            "낮은 ML 위험 점수는 이 경고를 취소하지 않습니다. 이 일치로 위험 판정했습니다.",
        ))  # fmt: skip
    if pending:
        notices.append((f"보류 {pending}개.", "검사를 끝내지 못한 항목이며 통과가 아닙니다."))
    return notices


def _detector_setup(report: dict, esc) -> list[str]:
    """Which detectors besides the model ran; an unconnected one is said here, not per result.

    Each stored entry and each field of it is read on its own, so that a broken neighbor hides
    nothing: a field that is missing or null is said to be unknown and never filled in (no list
    time the report does not have), an entry that is missing or not an object is NOT_CHECKED (a
    report older than the detectors, contract 6) and only a null entry is NOT_CONFIGURED."""
    detectors = report.get("detectors")

    def entry(key: str) -> dict | str:
        found = detectors.get(key, ()) if isinstance(detectors, dict) else ()  # (): no entry
        if found is None:
            return NOT_CONFIGURED
        return found if isinstance(found, dict) else NOT_CHECKED

    def field(found: dict, name: str) -> str:
        return "확인할 수 없음" if found.get(name) is None else esc(found[name])

    known, rules = entry("known_malicious"), entry("rules")
    if isinstance(known, dict):
        known = f"{field(known, 'source')}, 기준 시점 {field(known, 'list_as_of')}"
    if isinstance(rules, dict):
        rules = field(rules, "ruleset_version")
    return [f"기지 악성 목록: {known}", f"규칙: {rules}"]


def _ml_status(row: dict, report: dict) -> tuple[str | None, bool]:
    """ml.status, and whether it is only derived: a report without ml (older) gets the contract
    4.1 value from its status and reason, a reference value (contract 6). Before the detectors
    existed the item status was the ML path's own."""
    if "ml" in row:
        return (row["ml"] or {}).get("status"), False
    status, reason = row.get("status"), row.get("reason")
    if status == "flagged":
        return "hit", True
    if status == "not_flagged":
        return "not_hit", True
    if status == "removed":
        return "not_run", True
    if status == "incomplete":
        connected = isinstance(report.get("analyzer_version"), str)
        failed = reason in ("analysis_failed", "inference_failed") or (
            reason == "analysis_missing" and connected
        )
        return ("failed" if failed else "not_run"), True
    return None, False


def _ml_score(row: dict, label, report: dict) -> str | None:
    """The ML risk score with the ML path's own status (contract 4.1); not a probability.

    An unknown ml.status is shown as other unknown states are (label); one derived for a report
    without ml is marked ML_DERIVED. The number is actions.score_text()'s, worded against the
    report's own threshold so that it never reads as contradicting the status beside it.
    """
    status, derived = _ml_status(row, report)
    shown = None if status is None else label(ML_LABELS, status)
    if shown is not None and derived:
        shown += f", {ML_DERIVED}"
    if row.get("score") is not None:
        score = score_text(row["score"], report.get("threshold"))
        return score + (f" ({shown})" if shown is not None else "")
    if row["status"] != "removed" and shown is not None:
        return f"없음({shown})"
    return None


def _raw_score(row: dict, report: dict) -> str | None:
    """The stored score as the JSON has it, for the details of an item whose shown score
    (_ml_score) is not that very value. None without a score or when the two are the same."""
    if row.get("score") is None:
        return None
    return score_raw(row["score"], report.get("threshold"))


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


def _slot_status(slot: dict, labels: dict, label) -> str:
    """The slot's status, with the count of failed rule checks under any other status: rules
    hit with some checks failed (DEC-01 n4) shows both, so that the item's detection_failed
    reason does not read as contradicting it."""
    text = label(labels, slot["status"])
    failed = sum(check.get("status") == "failed" for check in slot.get("checks") or [])
    if failed and slot["status"] != "failed":
        text += f", 실패 {failed}개"
    return text


def _slot(slot: dict, labels: dict, esc, label) -> str:
    text = _slot_status(slot, labels, label)
    if slot.get("reason"):
        text += f" ({label(DETECTOR_REASON_LABELS, slot['reason'])})"
    if slot.get("detail"):
        text += f", 상세: {esc(slot['detail'])}"
    return text


def _unchecked(row: dict, key: str, report: dict) -> bool:
    """The result has no slot for this detector and the report does not say it was unconnected
    (a report older than the detectors): shown as NOT_CHECKED, never as not_hit (contract 6)."""
    return key not in row and (report.get("detectors") or {}).get(key, True) is not None


def _detector_lines(row: dict, esc, label, report: dict) -> list[tuple[str, list[str]]]:
    """Each connected detector's slot of one result as a line and its sub-lines; a slot missing
    from an older report is NOT_CHECKED."""
    lines = []
    known, rules = row.get("known_malicious"), row.get("rules")
    if _unchecked(row, "known_malicious", report):
        lines.append((f"기지 악성: {NOT_CHECKED}", []))
    elif known and known.get("reason") != "detector_not_configured":
        matches = [
            f"{esc(match['advisory_id'])} ({label(MATCH_KIND_LABELS, match['match_kind'])}"
            + (f", 영향 버전 {esc(match['affected'])}" if match["affected"] is not None else "")
            + ")"
            for match in known["matches"]
        ]
        lines.append((f"기지 악성: {_slot(known, KNOWN_STATUS_LABELS, esc, label)}", matches))
    if _unchecked(row, "rules", report):
        lines.append((f"규칙: {NOT_CHECKED}", []))
    elif rules and rules.get("reason") != "detector_not_configured":
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
        if "rule_ml_agreement" in row:
            agreement = label(AGREEMENT_LABELS, row["rule_ml_agreement"])
            lines.append((f"규칙/ML: {agreement}. 판정에 쓰지 않는 표시입니다.", []))
    return lines


def _ordered(results: list[dict]) -> list[dict]:
    """D-13: risky, unfinished, passed, removed, then by ML risk score (the JSON keeps the
    lockfile order)."""
    return sorted(
        results,
        key=lambda r: (STATUS_ORDER.get(r["status"], len(STATUS_ORDER)), -(r.get("score") or 0.0)),
    )


def _rest_line(row: dict, threshold: object = None) -> str:
    """The explanation_rest line: the other features, the base value and their total. threshold:
    the report's, so that the score at its end is worded as the item's own (_ml_score)."""
    rest = row["explanation_rest"]
    shown = sum(item["contribution"] for item in row.get("explanation") or [])
    total = shown + rest["others_sum"] + rest["base_value"]
    score_note = (
        f" → 점수 {score_text(row['score'], threshold)}" if row.get("score") is not None else ""
    )
    return (
        f"나머지 특징 {rest['others_count']}개 합 {rest['others_sum']:+.2f},"
        f" 모델 기준값 {rest['base_value']:+.2f}"
        f" (합계 {total:+.2f}{score_note})"
    )


def _print_text(report: dict, paint=terminal.plain, mark: str = "") -> None:
    """The report as text. paint and mark are for an interactive terminal (_emit): colors of
    the verdict words and the bee mark before the first line; by default the text has neither."""
    # A console code page (e.g. cp949) may not encode every character in package data.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    package_input = report.get("input_kind") == "package"
    status = paint(report["status"], OVERALL_LABELS.get(report["status"], report["status"]))
    print(f"{mark}depbee 검사 결과: {status} (종료 코드 {report['exit_code']})")
    print(_summary(report["results"], package_input))
    for emphasized, rest in _notices(report):
        tone = "flagged" if emphasized.startswith(WARNING) else "incomplete"
        print(f"{paint(tone, emphasized)} {rest}")
    if report["model_id"]:
        threshold = plain_number(report.get("threshold"))
        print(f"모델: {_clean(report['model_id'])}, 판정 기준 점수 {threshold}")
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
    for row in _ordered(report["results"]):
        label = paint(row["status"], STATUS_LABELS.get(row["status"], row["status"]))
        version = row["after_version"] or row["before_version"]
        print()
        print(f"[{label}] {_clean(row['package'])}@{_clean(version)}  ({_clean(row['location'])})")
        score = _ml_score(row, _text_label, report)
        if score is not None:
            print(f"  ML 위험 점수: {score}")
        raw = _raw_score(row, report)
        if raw is not None:
            print(f"  점수 원값: {raw}")
        if row.get("reason"):
            reason = REASON_LABELS.get(row["reason"], row["reason"])
            print(f"  이유: {_clean(reason)}")
        alternative = _alternative(row)
        if alternative:
            print(f"  대안(안전 보증 아님): {_clean(alternative[0])} ({alternative[1]})")
        if row.get("detail"):
            print(f"  상세: {_clean(row['detail'])}")
        for line, subs in _detector_lines(row, _clean, _text_label, report):
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
            print(f"    {_rest_line(row, report.get('threshold'))}")
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


def _md_location(location: object) -> str:
    """A lockfile location as a Markdown code span that spells no two locations alike: each
    backslash is doubled before _md. Otherwise a control character, which _clean writes as a
    backslash and its code, would read as a location that holds those very characters."""
    return _md(str(location).replace("\\", "\\\\"))


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
        threshold = plain_number(report.get("threshold"))
        lines.append(f"- 모델: {_md(report['model_id'])}, 판정 기준 점수 {threshold}")
    lines += [f"- {line}" for line in _detector_setup(report, _md)]
    checked = (
        "lockfile 없이 registry 정보로 이 버전 하나만" if package_input
        else "lockfile에서 바뀐 의존성만"
    )  # fmt: skip
    lines.append(f"- 범위: {checked} 검사했습니다. 프로젝트 전체의 안전성 평가가 아닙니다.")
    if timed:
        lines.append(f"- 소요 시간: {report['elapsed_seconds']:.3f}초")
    rows = _ordered(report["results"])
    # Detector columns only when a detector is connected (otherwise the list above says so) or
    # when the report predates them (then each cell says NOT_CHECKED).
    connected = [
        (key, name, labels)
        for key, name, labels in (("known_malicious", "기지 악성", KNOWN_STATUS_LABELS),
                                  ("rules", "규칙", RULE_STATUS_LABELS))
        if (report.get("detectors") or {}).get(key, True) is not None
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
            slot = row.get(key) or {}
            status = slot.get("status")
            if _unchecked(row, key, report):
                cell = NOT_CHECKED
            else:
                cell = "-" if status is None else _slot_status(slot, labels, _md_label)
            cells.append(f"**{cell}**" if key == "known_malicious" and status == "hit" else cell)
        score = _ml_score(row, _md_label, report)
        cells += [
            score if score is not None else "-",
            _md_label(REASON_LABELS, row["reason"]) if row.get("reason") else "-",
            _md_location(row["location"]),
        ]
        if timed:
            seconds = row.get("elapsed_seconds")
            cache = ", 캐시 사용" if row.get("cache_hit") else ""
            cells.append(f"{seconds:.3f}초{cache}" if seconds is not None else "-")
        lines.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    for row in rows:
        lines += _markdown_details(row, report)
    lines += ["", f"> {SAFETY_NOTE}"]
    print("\n".join(lines))


def _markdown_details(row: dict, report: dict) -> list[str]:
    """Detector slots, extracted facts and the model's explanation of one result, kept apart."""
    explanation, rest = row.get("explanation") or [], row.get("explanation_rest")
    detectors = _detector_lines(row, _md, _md_label, report)
    alternative = _alternative(row)
    raw = _raw_score(row, report)
    if not (
        alternative or raw or row.get("detail") or detectors or row.get("evidence")
        or explanation or rest
    ):  # fmt: skip
        return []
    target = _md(f"{row['package']}@{row['after_version'] or row['before_version']}")
    lines = ["", f"### {_md_label(STATUS_LABELS, row['status'])}: {target}", ""]
    if raw:
        # Rows of one package and version share the heading: the location says whose value it is.
        lines += [f"- 점수 원값: {raw}", f"- 위치: {_md_location(row['location'])}"]
    if alternative:
        # The heading has no location and rows without details have no section, so say which.
        lines.append(
            f"- 대안(안전 보증 아님): {_md(alternative[0])}"
            f" ({alternative[1]}, 위치 {_md_location(row['location'])})"
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
            lines.append(f"  - {_rest_line(row, report.get('threshold'))}")
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


def _apply_item(item: dict, esc, label, threshold: object = None) -> str:
    """One item of the update gate. threshold: the report's, which words the score."""
    version = item["after_version"] or item["before_version"]
    causes = []
    for cause in item["causes"]:
        text = label(CAUSE_LABELS, cause)
        if cause == "incomplete" and item.get("reason"):
            text += f", 이유: {label(REASON_LABELS, item['reason'])}"
        causes.append(text)
    if item.get("score") is not None:
        causes.append(f"ML 위험 점수 {score_text(item['score'], threshold)}")
    status = label(STATUS_LABELS, item["status"])
    return (f"[{status}] {esc(item['package'])}@{esc(version)} ({esc(item['location'])}): "
            + "; ".join(causes))  # fmt: skip


def _apply_lines(
    apply: dict, esc, label, *, reasons: dict = APPLY_REASON_LABELS,
    confirmed: str = f"{CONFIRM_OPTION}로 확인함",
    retry: str | None = f"위 항목을 검토한 뒤 진행하려면 {CONFIRM_OPTION}를 함께 줍니다.",
    threshold: object = None,
) -> list[tuple[str, list[str]]]:  # fmt: skip
    """The update --apply section after the report: lines and their sub-lines. reasons,
    confirmed and retry: the wording that names the CLI option, which the dashboard replaces.
    threshold: the threshold of the report the apply was decided from (_apply_item)."""
    lines = [(f"방식: {label(MODE_LABELS, apply['mode'])}", [])]
    if apply["reason"]:
        lines.append((f"이유: {label(reasons, apply['reason'])}", []))
    if apply["error"]:
        lines.append((f"오류: {esc(apply['error'])}", []))
    if apply["blocked"]:
        lines.append((
            f"기지 악성 기록 일치로 거부한 항목 {len(apply['blocked'])}개:",
            [_apply_item(item, esc, label, threshold) for item in apply["blocked"]],
        ))  # fmt: skip
    if apply["confirmation_required"]:
        state = confirmed if apply["confirmed"] else "확인하지 않음"
        lines.append((
            f"확인이 필요한 항목 {len(apply['confirmation_required'])}개({state}):",
            [_apply_item(item, esc, label, threshold)
             for item in apply["confirmation_required"]],
        ))  # fmt: skip
    refused_unconfirmed = (
        apply["outcome"] == "refused" and apply["reason"] == "confirmation_required"
    )
    if refused_unconfirmed and retry:
        lines.append((retry, []))
    for changed in apply["files"]:
        lines.append((f"바꾼 파일: {esc(changed['path'])} (sha256 {changed['sha256'][:12]}... → "
                      f"{changed['new_sha256'][:12]}...)", []))  # fmt: skip
    if apply["backup"]:
        lines.append((f"원본 백업: {esc(apply['backup'])}", []))
    if apply["npm_ci_exit_code"] is not None:
        lines.append((f"npm {esc(apply['npm_version'])}, npm ci 종료 코드 "
                      f"{apply['npm_ci_exit_code']}", []))  # fmt: skip
    lines += [(notice, []) for notice in apply["notices"]]
    return lines


def _apply_exit(report: dict, apply: dict) -> int:
    """The report's exit code; 2 for a failed apply, and for a refused one whose report is 0
    (the requested apply did not happen)."""
    if apply["outcome"] == "failed":
        return 2
    if apply["outcome"] == "refused":
        return report["exit_code"] or 2
    return report["exit_code"]


def _check_output(output: Path) -> None:
    """Refuse an --output that cannot be created, before any download, npm run or apply: a taken
    path (the error text of _emit's "x" open) or one below something that is not a folder.
    Missing folders pass: _emit makes them, and its "x" mode still guards against a file created
    meanwhile."""
    if os.path.lexists(output):
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(output))
    for parent in output.parents:
        if os.path.lexists(parent):
            if not parent.is_dir():
                raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(parent))
            return


def _emit(
    report: dict, args: argparse.Namespace, preview: dict | None = None, apply: dict | None = None
) -> OSError | None:
    """Write --output, then print. With an apply, an --output that cannot be written is returned
    instead of raised: what the apply did to the project is printed first, and the caller records
    it before raising the error. Without one nothing was changed and nothing is printed."""
    data = report if preview is None else {"preview": preview, "report": report}
    if apply is not None:
        data["apply"] = apply
    payload = json.dumps(data, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
    failed = None
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
        except OSError as exc:
            if apply is None:
                raise
            failed = exc
    _show(payload, report, args, preview, apply)
    return failed


def _show(
    payload: str, report: dict, args: argparse.Namespace, preview: dict | None, apply: dict | None
) -> None:
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
        if apply is not None:
            outcome = _md_label(OUTCOME_LABELS, apply["outcome"])
            lines = ["", f"## depbee 업데이트 반영: {outcome}", ""]
            shown = _apply_lines(apply, _md, _md_label, threshold=report.get("threshold"))
            for line, subs in shown:
                lines += [f"- {line}", *(f"  - {sub}" for sub in subs)]
            print("\n".join(lines))
        return
    # On an interactive terminal only: the bee mark, colors and the next steps (terminal). A
    # pipe or a file gets the text as it always was.
    human = terminal.interactive(sys.stdout)
    paint = terminal.painter(sys.stdout)
    mark = f"{paint('mark', terminal.MARK)} " if human else ""
    if preview is not None:
        print(f"{mark}depbee 업데이트 미리보기")
        for line in _preview_lines(preview, _clean):
            print(line)
        print()
        mark = ""
    _print_text(report, paint, mark)
    if apply is not None:
        print()
        outcome = paint(
            OUTCOME_TONES.get(apply["outcome"], ""), _text_label(OUTCOME_LABELS, apply["outcome"])
        )
        print(f"depbee 업데이트 반영: {outcome}")
        shown = _apply_lines(apply, _clean, _text_label, threshold=report.get("threshold"))
        for line, subs in shown:
            print(line)
            for sub in subs:
                print(f"  - {sub}")
    if human:
        steps = terminal.next_steps(args.command, report, apply)
        if steps:
            print()
            print(paint("strong", terminal.NEXT_TITLE))
            for line in terminal.bullets(steps):
                print(line)


def _record(
    kind: str,
    args: argparse.Namespace,
    report: dict,
    preview: dict | None = None,
    apply: dict | None = None,
) -> None:
    """Add a printed report to the local history if its project is registered (depbee.history).

    Never changes stdout or the exit code: any failure is one fixed line on stderr. The import
    is here so that a Python without sqlite3 still runs every command.
    """
    try:
        from . import history

        scan = preview is None  # update has no base options
        history.record(
            kind, args.project, report, preview,
            base_ref=args.base_ref if scan else None,
            base_lock=args.base_lock is not None if scan else None, apply=apply,
        )  # fmt: skip
    except Exception:
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(errors="backslashreplace")
        print(HISTORY_FAILED, file=sys.stderr)


def _installed() -> bool:
    """This copy of depbee is the one its Python imports when started in any folder: an
    installed one, an editable install included. It is asked of that Python itself, without the
    current folder (-P) and without PYTHONPATH (-E), as an agent starts the registered command.
    False for a source folder that only runs through PYTHONPATH or the current folder, and for
    one beside another installed copy: the console script would then start that other copy."""
    try:
        check = subprocess.run(
            [sys.executable, "-P", "-E", "-c", _SAME_COPY, str(Path(__file__).parent)],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=60,
        )  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        return False
    return check.returncode == 0


def _launcher() -> str:
    """The command that starts this depbee from any folder, quoted for a shell: the console
    script beside the Python that runs it, else that Python with -P -m depbee (-P: the current
    folder is no import path). Only for a copy that is _installed()."""
    quote = (lambda text: f'"{text}"') if os.name == "nt" else shlex.quote
    script = Path(sys.executable).with_name("depbee.exe" if os.name == "nt" else "depbee")
    return quote(str(script)) if script.is_file() else f"{quote(sys.executable)} -P -m depbee"


def _warn_shared(folder: Path) -> None:
    """Tell a person at a terminal (stderr) that the settings folder is open to other accounts
    (config.open_to_others). Captured or piped output stays as it was."""
    if terminal.interactive(sys.stderr) and config.open_to_others(folder):
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(errors="backslashreplace")
        print(SHARED_FOLDER.format(folder=_clean(folder)), file=sys.stderr)


def _active_lines(active: dict) -> list[str]:
    """One line per asset in use (service.active_assets): its folder, then its version and
    where it comes from, or why it does not load."""
    lines = []
    for key, name in ASSET_NAMES.items():
        asset = active[key]
        if asset["source"] is None:
            lines.append(f"  {name}: 연결 안 됨")
            continue
        source = SOURCE_LABELS[asset["source"]].format(variable=ASSET_VARIABLES[key])
        if asset["error"] is None:
            detail = f"{VERSION_LABELS[key]} {_clean(asset['version'])}, {source}"
        else:
            detail = f"{source}, 읽지 못함: {_clean(asset['error'])}"
        lines.append(f"  {name}: {_clean(asset['folder'])} ({detail})")
    return lines


def _setup(args: argparse.Namespace) -> int:
    """depbee setup: save or clear the user's asset folder (config), or show the assets in use.
    Showing writes nothing; it is 2 if an asset in use does not load, as a scan would be."""
    if args.clear:
        if args.assets_dir is not None:
            raise GuardError("setup takes DIR or --clear, not both")
        print(SETUP_CLEARED if config.clear() else SETUP_NONE)
        return 0
    if args.assets_dir is None:
        saved = config.load()
        active = active_assets()
        print(SETUP_NONE if saved is None else f"저장된 자산 설정: {_clean(config.path())}")
        for line in _active_lines(active):
            print(line)
        if saved is None:
            print(SETUP_HOW)
        else:
            _warn_shared(config.path().parent)
        return 2 if any(asset["error"] is not None for asset in active.values()) else 0
    saved = setup_assets(args.assets_dir)
    print(f"자산 설정을 저장했습니다: {_clean(saved['path'])}")
    versions = {"model_dir": saved["model_id"], "known_malicious_dir": saved["list_as_of"]}
    for key, name in ASSET_NAMES.items():
        if saved[key] is None:
            print(f"  {name}: {SETUP_DEFAULT}")
        else:
            print(f"  {name}: {_clean(saved[key])} ({VERSION_LABELS[key]} {_clean(versions[key])})")
    print(SETUP_SAVED)
    if _installed():
        launcher = _clean(_launcher())
        print(f"  Claude Code: claude mcp add --scope user depbee -- {launcher} mcp")
        print(f"  Codex: codex mcp add depbee -- {launcher} mcp")
    else:
        print(SETUP_NOT_INSTALLED)
    _warn_shared(Path(saved["path"]).parent)
    return 0


def _dashboard(args: argparse.Namespace) -> int:
    """depbee dashboard: serve here until Ctrl+C, or start, show or stop the background one."""
    options = {"model_dir": args.model_dir, "cache_dir": args.cache_dir,
               "no_cache": args.no_cache, "known_malicious_dir": args.known_malicious_dir}  # fmt: skip
    from .dashboard import DEFAULT_PORT, serve

    port = DEFAULT_PORT if args.port is None else args.port
    if not (args.background or args.status or args.stop):
        serve(port, **options)
        return 0
    from .dashboard import lifecycle

    if args.background:
        state, started = lifecycle.start(port, **options)
        print(state["url"])
        print(BACKGROUND_STARTED if started else BACKGROUND_RUNNING)
        _warn_shared(config.user_dir())
        return 0
    if args.port is not None or any(options.values()):
        raise GuardError("--status and --stop take no other option")
    if args.stop:
        print(BACKGROUND_STOPPED if lifecycle.stop() else BACKGROUND_NONE)
        return 0
    kind, state = lifecycle.status()
    if kind == "running":
        print(state["url"])
        print(BACKGROUND_STATUS.format(pid=state["pid"], started_at=state["started_at"]))
        return 0
    print(BACKGROUND_UNRESPONSIVE if kind == "unresponsive" else BACKGROUND_NONE)
    return 2 if kind == "unresponsive" else 0


def _guard_ci(args: argparse.Namespace) -> int:
    """depbee guard ci (service.install_checked): 0 only when it installed."""
    progress = _progress if args.format == "text" else None
    if progress and hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(errors="backslashreplace")
    result = install_checked(args.project, progress=progress)
    report, apply = result["report"], result["apply"]
    if args.format == "json":
        print(json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False))
    else:
        _print_text(report)
        print()
        print(f"depbee 검사 후 설치: {_text_label(GUARD_OUTCOME_LABELS, apply['outcome'])}")
        shown = _apply_lines(
            apply, _clean, _text_label, reasons=GUARD_REASON_LABELS, retry=None,
            threshold=report.get("threshold"),
        )  # fmt: skip
        for line, subs in shown:
            print(line)
            for sub in subs:
                print(f"  - {sub}")
        if apply["outcome"] == "applied":
            print(GUARD_INSTALLED)
        elif apply["outcome"] == "unchanged":
            print(GUARD_NOTHING)
        elif apply["reason"] == "removal_only":
            print(GUARD_REMOVAL)
        else:
            # A timeout ends npm ci without an exit code: whether it started is the guard's own.
            print(GUARD_CI_FAILED if apply["npm_ci_started"] else GUARD_STOPPED)
    return 0 if apply["outcome"] == "applied" else _apply_exit(report, apply) or 2


def _guard_settings(args: argparse.Namespace) -> int:
    """depbee guard enable, status and disable on the one settings file given."""
    from . import guard

    named = Path(os.path.abspath(args.settings))
    path = guard.settings_file(named)
    settings, original = guard.read_settings(path)
    # The only Python a self-test runs: this depbee's own, never a command the file names.
    python = os.path.abspath(sys.executable)
    print(f"설정 파일: {_clean(path)}")
    if path != named:
        print(GUARD_LINK.format(named=_clean(named)))
    if args.guard_command == "status":
        found, wrong = guard.problems(settings, python)
        for problem in wrong:
            print(f"  확인 필요: {_clean(problem)}")
        if wrong or not found:
            print(GUARD_NOT_RUN if wrong else GUARD_ABSENT)
            return 2
        print(f"  훅: {_clean(python)} {' '.join(guard.HOOK_ARGS)} (matcher {guard.MATCHER}, "
              "onFailure block)")  # fmt: skip
        problem = guard.self_test(python)
        print(GUARD_SELF_TEST_FAILED.format(problem=_clean(problem)) if problem
              else GUARD_SELF_TEST_PASSED)  # fmt: skip
        return 2 if problem else 0
    if args.guard_command == "enable":
        problem = guard.self_test(python)
        if problem:
            raise GuardError(
                f"The hook did not answer its self-test, nothing was written: {problem}"
            )
        updated = guard.with_guard(settings, python)
    else:
        updated, _ = guard.without_guard(settings, python)
    if updated == settings:
        print(GUARD_SAME)
    else:
        saved = guard.write_settings(path, updated, original)
        print(GUARD_ENABLED if args.guard_command == "enable" else GUARD_DISABLED)
        if saved is not None:
            print(GUARD_BACKUP.format(backup=_clean(saved), path=_clean(path)))
            _warn_shared(saved.parent)
    for problem in guard.problems(updated, python)[1]:  # what enable or disable left alone
        print(f"  주의: {_clean(problem)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    # Korean help and screens must not fail on a stream whose encoding lacks a character.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    if not arguments:
        # The start screen instead of argparse's usage error; still 2: nothing was checked.
        print("\n".join([*terminal.head(__version__, sys.stdout), "", *terminal.guide()]))
        return 2
    args = _parser().parse_args(arguments)
    try:
        if args.command == "mcp":
            from .mcp import serve

            serve(args.model_dir, args.known_malicious_dir)
            return 0
        if args.command == "dashboard":
            return _dashboard(args)
        if args.command == "setup":
            return _setup(args)
        if args.command == "guard":
            return _guard_ci(args) if args.guard_command == "ci" else _guard_settings(args)
        if args.output is not None:
            _check_output(args.output)
        if args.command == "plan":
            request = plan_project(args.project, args.base_lock, base_ref=args.base_ref)
            _emit(request, args)
            if terminal.interactive(sys.stdout):  # stdout stays the JSON alone
                changes = request["changes"]
                print(terminal.PLAN_STEP.format(
                    count=len(changes), analyzable=sum(c["analyzable"] for c in changes),
                ), file=sys.stderr)  # fmt: skip
            return 0
        progress = None
        # Extraction takes seconds per package; show progress unless stdout is JSON.
        if args.format == "text" and (args.command in ("check", "update") or args.extract):
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(errors="backslashreplace")
            progress = _progress
        if args.command == "update":
            if args.confirm_warnings and args.apply is None:
                raise GuardError(f"{CONFIRM_OPTION} needs --apply")
            options = {"model_dir": args.model_dir, "progress": progress,
                       "cache_dir": args.cache_dir, "no_cache": args.no_cache,
                       "known_malicious_dir": args.known_malicious_dir}  # fmt: skip
            if args.apply is None:
                result = preview_update(args.project, args.packages, **options)
            else:
                result = apply_update(args.project, args.packages, mode=args.apply,
                                      confirm=args.confirm_warnings, **options)  # fmt: skip
            report, apply = result["report"], result.get("apply")
            failed = _emit(report, args, result["preview"], apply)
            _record("update_preview", args, report, result["preview"], apply)
            if failed is not None:  # the apply is printed and recorded; now the file's error
                if hasattr(sys.stderr, "reconfigure"):
                    sys.stderr.reconfigure(errors="backslashreplace")
                print(OUTPUT_FAILED, file=sys.stderr)
                raise failed
            return report["exit_code"] if apply is None else _apply_exit(report, apply)
        if args.command == "check":
            name, version = _split_package(args.package)
            report = check_package(
                name,
                version,
                model_dir=args.model_dir,
                progress=progress,
                cache_dir=args.cache_dir,
                no_cache=args.no_cache,
                known_malicious_dir=args.known_malicious_dir,
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
            known_malicious_dir=args.known_malicious_dir,
        )
        _emit(report, args)
        _record("scan", args, report)
        return report["exit_code"]
    except (GuardError, OSError, ValueError, RecursionError) as exc:
        error = {"status": "error", "exit_code": 2, "error": str(exc)}
        print(json.dumps(error, ensure_ascii=True), file=sys.stderr)
        return 2
