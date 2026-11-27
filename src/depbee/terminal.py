"""What a person at a terminal sees beyond the plain report: the bee mark, colors, the start
screen, the next steps and the dashboard's start (launch()).

The mark, the colors, the next steps and the dashboard's start are for an interactive terminal
only (interactive()). A pipe, a file, JSON, Markdown, MCP stdio and the GitHub Action get the
same bytes as without this module. Colors only repeat what the words already say ([위험], [보류], ...): they are never the
only signal, and NO_COLOR, TERM=dumb or a console without ANSI support turns them off.
"""

import os
import shutil
import time
import unicodedata
from collections import Counter

from .service import update_gate

# ASCII only, so that any console code page and font shows it.
STAMP = (r"   \\ //", r" -(||||)o", r'   "  "')
MARK = "-(||||)o"  # one line, in front of a report's first line
TAGLINE = (
    "npm 패키지를 설치하기 전에 버전 변경을 검사합니다.",
    "검사는 패키지 코드를 실행하지 않습니다.",
)
# The start screen's commands (ASCII, so that padding by characters lines them up).
GUIDE = (
    ("depbee check lodash@4.17.21", "설치 전에 정확한 버전 하나 검사"),
    ("depbee scan . --extract", "커밋하지 않은 lockfile 변경 검사"),
    ("depbee update", "npm update 미리보기와 검사, --apply로 반영"),
    ("depbee dashboard --background", "로컬 대시보드 실행 (--status, --stop)"),
    ("depbee setup DIR", "자산 폴더를 한 번 저장 (DIR/model, DIR/index)"),
    ("depbee mcp", "에이전트용 MCP 서버 (stdio)"),
)
GUIDE_END = (
    "종료 코드: 0 통과, 1 위험, 2 보류 또는 오류",
    "'통과'와 낮은 점수는 안전 보증이 아닙니다.",
    "명령별 옵션: depbee <명령> --help",
)
NEXT_TITLE = "다음 동작"
NOTHING_CHANGED = "바뀐 의존성이 없어 검사할 것이 없습니다."
KNOWN_STEP = (
    "기지 악성 기록과 일치한 {count}개 항목은 설치하거나 업데이트하지 마세요. "
    "다른 버전을 쓰려면 그 버전을 다시 검사하세요."
)
ML_STEP = (
    "ML 위험 점수가 기준 이상인 {count}개 항목은 위의 추출된 사실과 판단 근거를 검토한 뒤 "
    "설치 여부를 정하세요."
)
# Unfinished items whose reason has a direct remedy; analysis_missing only after scan.
REASON_STEPS = {
    "model_missing": (
        "모델이 연결되지 않아 {count}개 항목을 판정하지 못했습니다. 모델 폴더가 있으면 "
        "depbee setup DIR로 한 번 저장하거나 --model-dir로 지정하세요."
    ),
    "analysis_missing": (
        "분석 결과가 없어 {count}개 항목을 판정하지 못했습니다. --extract(또는 이 변경을 담은 "
        "--analysis 파일)로 다시 실행하세요."
    ),
}
PENDING_STEP = (
    "보류 {count}개는 통과가 아닙니다. 항목의 이유를 확인하고, 설치하려면 직접 검토하세요."
)
PASS_STEP = (
    "위험이나 보류 항목이 없습니다. 설치는 검사한 버전 그대로 진행하고, 버전을 바꾸면 다시 "
    "검사하세요."
)
INDEX_STEP = (
    "기지 악성 목록이 연결되지 않아 알려진 악성 버전인지는 확인하지 않았습니다. 색인 폴더가 "
    "있으면 depbee setup DIR 또는 --known-malicious-dir로 연결하세요."
)
APPLY_STEP = (
    "반영하려면 같은 명령에 --apply lockfile을, 설치까지 하려면 --apply install을 붙이세요."
)
CONFIRM_STEP = (
    " 확인이 필요한 항목이 {count}개 있어, 검토한 뒤 --confirm-warnings도 함께 줘야 합니다."
)
BLOCKED_STEP = "기지 악성 기록 일치가 있어 이 업데이트는 반영할 수 없습니다."
PLAN_STEP = (
    "바뀐 의존성 {count}개 중 분석할 수 있는 변경은 {analyzable}개입니다. 검사하려면 같은 "
    "프로젝트와 기준으로 depbee scan에 --extract를 붙여 실행하세요."
)
# The dashboard's start on an interactive terminal (launch()), by who started it: this terminal,
# a background start, or a background start that found one running. First the steps, each a
# thing the start had done before this is shown, with what is known of it ({address}: the host
# and port of the dashboard's address); then the lines under the address.
LAUNCH_TITLE = "depbee 대시보드"
LAUNCH = {
    "foreground": (
        (
            ("포트 열기", "{address}"),
            ("화면 준비", "이 PC에서만 열립니다"),
            ("실행 중", "이 터미널 (포그라운드)"),
        ),
        ("브라우저에서 위 주소를 여세요.", "종료하려면 Ctrl+C를 누르세요."),
    ),
    "started": (
        (
            ("실행 여부 확인", "실행 중인 대시보드 없음"),
            ("백그라운드 시작", "터미널을 닫아도 계속 실행"),
            ("응답 확인", "준비 완료"),
        ),
        (
            "브라우저에서 위 주소를 여세요.",
            "주소 다시 보기: depbee dashboard --status",
            "종료: depbee dashboard --stop",
        ),
    ),
    "running": (
        (
            ("실행 여부 확인", "이미 백그라운드에서 실행 중"),
            ("새로 시작하지 않음", "옵션은 실행 중인 대시보드 그대로"),
        ),
        (
            "브라우저에서 위 주소를 여세요.",
            "옵션을 바꾸려면 depbee dashboard --stop 뒤에 다시 시작하세요.",
        ),
    ),
}
# What the steps and the address box are drawn with: line characters where the terminal draws
# each in one column (_line_drawing), else ASCII. The box's corners and sides in reading order,
# then a step's mark and the line between two steps.
# The line characters are written as escapes: they are for a terminal and never on a page of
# the dashboard, whose font test reads the characters of this package's sources.
_DRAWN = ("\u250c", "\u2500", "\u2510", "\u2502", "\u2514", "\u2518", "\u25c6", "\u2502")
_TYPED = ("+", "-", "+", "|", "+", "+", "*", "|")
FLIGHT = 14  # columns the bee flies inside the address box; its trail fills them
FLIGHT_STEP = 2  # columns a frame
FLIGHT_SECONDS = 0.06  # a frame
# ANSI SGR codes by tone: the report's statuses, plus mark, strong and dim.
_SGR = {
    "flagged": "1;31", "incomplete": "1;33", "passed": "32", "not_flagged": "32",
    "removed": "2", "dim": "2", "strong": "1", "mark": "33",
}  # fmt: skip
_VIRTUAL_TERMINAL = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING


def interactive(stream) -> bool:
    """A person is reading stream: it is a terminal, not a pipe, a file or a capture."""
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):  # no such method, or a closed stream
        return False


def plain(tone: str, text: str) -> str:
    return text


def painter(stream):
    """paint(tone, text) for stream: text in the tone's color if stream is a terminal that takes
    ANSI colors and the user has not turned them off, else text itself (plain)."""
    if not (interactive(stream) and _colors(stream)):
        return plain
    return lambda tone, text: f"\x1b[{_SGR[tone]}m{text}\x1b[0m" if tone in _SGR else text


def _colors(stream) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if os.name != "nt":
        return True
    # A Windows console shows ANSI colors only in virtual terminal mode. It is switched on here;
    # a console that refuses (or a stream that is no console) stays plain.
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.GetConsoleMode.argtypes = (wintypes.HANDLE, wintypes.LPDWORD)
        kernel32.SetConsoleMode.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        handle = msvcrt.get_osfhandle(stream.fileno())
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(
            mode.value & _VIRTUAL_TERMINAL
            or kernel32.SetConsoleMode(handle, mode.value | _VIRTUAL_TERMINAL)
        )
    except (OSError, ValueError, AttributeError):
        return False


def _width(text: str) -> int:
    """Terminal columns text takes: a wide (Korean) character takes two."""
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def head(version: str, stream) -> list[str]:
    """The top of the start screen and of --help: the bee stamp with the name and version on an
    interactive terminal, the name and version alone elsewhere; then the tagline."""
    if not interactive(stream):
        return [f"depbee {version}", *TAGLINE]
    paint = painter(stream)
    top, middle, bottom = (paint("mark", line) for line in STAMP)
    return [top, f"{middle}  depbee {version}", bottom, *TAGLINE]


def _line_drawing(stream) -> bool:
    """Whether stream's terminal takes line characters and draws each in one column. They are
    of ambiguous width: a Windows console window with a Korean font draws them two columns wide,
    which breaks a box, so on Windows only a terminal that names itself (Windows Terminal, an
    editor's terminal) gets them, and anywhere only a UTF-8 stream."""
    if os.name == "nt" and not (os.environ.get("WT_SESSION") or os.environ.get("TERM_PROGRAM")):
        return False
    return "utf" in (getattr(stream, "encoding", None) or "").lower()


def launch(stream, kind: str, url: str, pause=time.sleep) -> None:
    """Write the dashboard's start to stream, an interactive terminal: the steps of LAUNCH[kind]
    one under another, then url in a box, then what to do next as bullets(). Where stream is
    not interactive the callers write their plain lines instead.

    In a terminal wide enough the bee mark is inside the box and flies to the address. Where
    the terminal takes colors (painter()) the box's middle line is rewritten in place a few
    times, with carriage returns only and for under half a second; what stays is the last
    frame, which a terminal without colors gets at once, so NO_COLOR and TERM=dumb turn the
    flight off too. A narrower terminal gets the mark beside the title and the address alone
    in the box, or with no box; a step that does not fit beside its name goes under it.
    pause: what waits between two frames (a test passes its own)."""
    steps, notes = LAUNCH[kind]
    paint = painter(stream)
    columns = shutil.get_terminal_size().columns
    corner, across, turn, side, foot, end, dot, rail = _DRAWN if _line_drawing(stream) else _TYPED
    address = url.removeprefix("http://").rstrip("/")
    steps = [(label, detail.format(address=address)) for label, detail in steps]

    def fits(inner: int) -> bool:
        return 2 + 1 + inner + 1 < columns  # the indent, a side, the inside, a side

    flight = 2 + FLIGHT + len(MARK) + 2 + len(url) + 2
    flies = fits(flight)
    inner = flight if flies else len(url) + 4
    title = paint("strong", LAUNCH_TITLE)
    lines = ["", f"  {title}" if flies else f"  {paint('mark', MARK)}  {title}", ""]
    pad = max(_width(label) for label, _ in steps) + 2
    beside = all(5 + pad + _width(detail) < columns for _, detail in steps)
    for index, (label, detail) in enumerate(steps):
        last = index == len(steps) - 1
        name = paint("strong", label)
        if beside:
            gap = " " * (pad - _width(label))
            lines.append(f"  {paint('mark', dot)}  {name}{gap}{paint('dim', detail)}")
            if not last:
                lines.append(f"  {paint('dim', rail)}")
        else:
            lines.append(f"  {paint('mark', dot)}  {name}")
            lines.append(f"  {paint('dim', ' ' if last else rail)}  {paint('dim', detail)}")
    lines.append("")
    ending = ["", *bullets(list(notes))]
    if not fits(inner):  # too narrow for any box: the address alone
        print("\n".join([*lines, f"  {paint('strong', url)}", *ending]), file=stream, flush=True)
        return
    edge = paint("mark", side)

    def middle(flown: int) -> str:
        """The box's middle line, the bee flown columns along with its trail behind it."""
        if not flies:
            return f"  {edge}  {paint('strong', url)}  {edge}"
        trail = paint("dim", ("- " * FLIGHT)[:flown])
        ahead = " " * (FLIGHT - flown)
        return f"  {edge}  {trail}{paint('mark', MARK)}{ahead}  {paint('strong', url)}  {edge}"

    print("\n".join([*lines, "  " + paint("mark", corner + across * inner + turn)]), file=stream)
    if flies and paint is not plain:
        for flown in range(0, FLIGHT, FLIGHT_STEP):
            stream.write("\r" + middle(flown))
            stream.flush()
            pause(FLIGHT_SECONDS)
        stream.write("\r")
    bottom = "  " + paint("mark", foot + across * inner + end)
    print("\n".join([middle(FLIGHT), bottom, *ending]), file=stream, flush=True)


def guide() -> list[str]:
    """The start guide for the terminal's width: each command beside its description if every
    line fits, else the description under its command."""
    pad = max(len(command) for command, _ in GUIDE) + 2
    rows = [f"  {command:<{pad}}{text}" for command, text in GUIDE]
    if max(map(_width, rows)) >= shutil.get_terminal_size().columns:
        rows = [line for command, text in GUIDE for line in (f"  {command}", f"      {text}")]
    return ["시작하기", *rows, "", *GUIDE_END]


def bullets(steps: list[str]) -> list[str]:
    """steps as "  - " bullets that fit the terminal's width: broken at spaces, the later lines
    of a step indented under its text. A word wider than the terminal is left whole."""
    limit = shutil.get_terminal_size().columns - 1
    lines = []
    for step in steps:
        line = "  -"
        for word in step.split(" "):
            if _width(line) + 1 + _width(word) > limit and line.strip(" -"):
                lines.append(line)
                line = "   "
            line += f" {word}"
        lines.append(line)
    return lines


def next_steps(command: str, report: dict, apply: dict | None = None) -> list[str]:
    """What the reader can do after this report, most urgent first. Only from the report's own
    fields and service.update_gate(), the gate an apply goes through, so the steps never say
    more than the verdicts do. command: scan, check or update; apply: update's apply document,
    None for a preview."""
    if not report["results"]:
        return [NOTHING_CHANGED]
    blocked, confirm = update_gate(report)
    steps = [KNOWN_STEP.format(count=len(blocked))] if blocked else []
    hits = sum("ml_hit" in item["causes"] for item in confirm)
    if hits:
        steps.append(ML_STEP.format(count=hits))
    pending = Counter(item["reason"] for item in confirm if "incomplete" in item["causes"])
    for reason, text in REASON_STEPS.items():
        if reason != "analysis_missing" or command == "scan":
            count = pending.pop(reason, 0)
            if count:
                steps.append(text.format(count=count))
    if pending:
        steps.append(PENDING_STEP.format(count=sum(pending.values())))
    # A report that only removes dependencies passes too, but has no version to install.
    installs = any(row["status"] != "removed" for row in report["results"])
    if installs and report["exit_code"] == 0 and command != "update":
        steps.append(PASS_STEP)
    if "detectors" in report and report["detectors"]["known_malicious"] is None:
        steps.append(INDEX_STEP)
    if command == "update" and apply is None:
        confirmation = CONFIRM_STEP.format(count=len(confirm)) if confirm else ""
        steps.append(BLOCKED_STEP if blocked else APPLY_STEP + confirmation)
    return steps
