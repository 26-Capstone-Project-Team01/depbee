"""The dashboard's web app (extra [web]): Starlette routes, Jinja2 pages and the uvicorn server.

Only depbee.dashboard.serve() imports this module. History goes through depbee.history (a new
connection per call), lockfile rows through service.list_dependencies(), package.json for
individual update buttons, and every verdict,
label and line through the depbee.cli helpers the text output uses.

Every page but the first is one console: the registered projects are tabs (_tabs), and a
project has three views, its packages, its update candidates and its history. A candidate is
only ever a stored update preview of that project made from the files as they are now
(_update_state); a GET reads files and the history and never runs npm or reaches the network.
The session's first page is the overview of the registered projects (_portfolio, _chart), and
the management page when the address asks for it (?manage=1). While no project is registered it
is the start page instead: one button that adds the first one, and nothing else. Registering
that first project comes back to the overview (enroll); a later one opens its own project.

A project is registered by its folder's path: typed into the form, or chosen in the desktop's
own folder dialog (.picker, a child process), which is checked as a typed one is. In a container
(.mounted) the dialog's button opens the folders mounted into it instead, and only a folder
among those is registered or used: each time a project is listed, checked, scanned or applied
there, its folder, the files read and the Git folder are looked at again (_found, _refused,
mounted.repository), and a link is never followed.

The pages work without a script. The one script (static/app.js, from under the session like the
stylesheets) only marks a button whose request is running, stops a second request meanwhile and
moves the focus to the first candidate a check returned.
"""

import hashlib
import hmac
import importlib.resources
import os
import re
import secrets
import socket
import stat
import sys
import threading
from collections import Counter, OrderedDict
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import parse_qs, quote, unquote, urlencode

import jinja2
import uvicorn
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import QueryParams
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from .. import history, mcp, service
from ..actions import plain_number, score_text
from ..cli import (
    APPLY_REASON_LABELS,
    CAUSE_LABELS,
    KNOWN_STATUS_LABELS,
    MODE_LABELS,
    NOT_CHECKED,
    NOT_CONFIGURED,
    OUTCOME_LABELS,
    OVERALL_LABELS,
    REASON_LABELS,
    RULE_STATUS_LABELS,
    SAFETY_NOTE,
    STATUS_LABELS,
    _alternative,
    _apply_item,
    _apply_lines,
    _clean,
    _detector_lines,
    _detector_setup,
    _feature_label,
    _feature_value,
    _ml_score,
    _notices,
    _ordered,
    _preview_lines,
    _rest_line,
    _slot,
    _summary,
    _text_label,
    _unchecked,
)
from ..contracts import MAX_JSON_BYTES, GuardError, read_json
from ..inputs.npm import MAX_NAME_LENGTH, PACKAGE_NAME
from ..inputs.npm_cli import DEPENDENCY_FIELDS, UPDATE_NAME
from . import mounted, picker, theme

HOST = "127.0.0.1"
MAX_BODY = 16 * 1024  # bytes of a request body (Starlette answers 413 above it)
MAX_FIELDS = 4  # form fields; the largest form (apply) has three
MAX_PATH = 1024  # characters of a path to register
MAX_TARGETS = 1024  # characters of the update target names field
KEPT_PREVIEWS = 10  # update previews kept in memory; the oldest is dropped first
RECENT_RUNS = 10  # runs per project in the list's trend table
MAX_ID = 2**63 - 1  # SQLite's largest integer; a larger id in a URL is simply not found
MAX_ITEM = 40  # characters of a candidate's key (<run id>.<position>) carried through a check
# The history stores a lone surrogate in a result row's location as the text \udXXX, which a
# location can also hold as it is: a stored location with this text may stand for either.
ESCAPED_SURROGATE = "\\ud"
# The hexagon mark (style.css .cell) next to a stored status; the words beside it say the status.
CELLS = {"flagged": "risk", "incomplete": "hold", "not_flagged": "pass"}
TAB_STATES = {
    "flagged": ("risk", "위험"),
    "incomplete": ("hold", "보류"),
    "passed": ("pass", "통과"),
}
# The rail's order of the projects by their state (_rail): what needs a look first, then a run
# whose result is not one a report has (drawn as none), then what was never checked, then what
# passed. The first three are what the rail counts as needing a look.
RAIL_ORDER = ("gone", "risk", "hold", "unknown", "none", "pass")
# The packages view's tabs (show): every entry, those with a current candidate, those no current
# check covers, and those a check covered that have no candidate (_kind).
SHOWS = ("all", "candidates", "unchecked", "none")
# The overview's state of a project (_portfolio), in the order its chart lists them, what needs
# a look first: the hexagon mark, the words, and whether the chart lists the state while no
# project is in it. The first three are the stored status of the project's newest run.
STATES = {
    "risk": ("risk", "위험", True),
    "hold": ("hold", "보류", True),
    "pass": ("pass", "통과", True),
    "none": ("none", "미검사", True),
    "stale": ("stale", "파일 바뀜", False),
    "gone": ("gone", "폴더 없음", False),
    "unknown": ("none", "알 수 없음", False),
}
# The mark of a stored apply outcome on the overview: only an apply that changed the files is a
# success, a refusal stops and a failure is told from it by its own mark.
APPLY_CELLS = {"applied": "pass", "refused": "risk", "failed": "fail"}
# Whether one candidate could be applied (_decision), worded as the update gate decides it.
DECISIONS = {
    "refused": ("risk", "반영 거부"),
    "confirm": ("hold", "확인 필요"),
    "free": ("pass", "반영 가능"),
}
# The updates view's groups of candidates (_grouped), what needs a look first: by whether each
# could be applied (DECISIONS), and a removal that could be apart, after them.
GROUPS = (
    ("refused", "반영 거부"),
    ("confirm", "확인 필요"),
    ("free", "반영 가능"),
    ("removed", "삭제"),
)
REFUSED_WHY = (
    "기지 악성 색인과 일치한 버전입니다. 낮은 ML 위험 점수는 이 거부를 취소하지 않으며, 확인으로도 "
    "반영할 수 없습니다."
)
CONFIRM_WHY = "반영하려면 사용자 확인이 필요합니다"
FREE_WHY = (
    "기지 악성 색인과 일치하지 않고 ML 위험 점수가 판정 기준 미만입니다. 검사 결과일 뿐 안전 보증이 "
    "아닙니다."
)
FREE_OTHER_WHY = "거부하거나 확인할 사유가 없습니다. 검사 결과일 뿐 안전 보증이 아닙니다."
REMOVED_WHY = "삭제되는 항목이라 새로 설치되는 것이 없습니다."
# The lockfile root entry's fields that declare a direct dependency, as the packages table
# words them next to "직접" (inputs.npm.DEPENDENCY_FIELDS).
DECLARED_LABELS = {
    "dependencies": "일반",
    "devDependencies": "개발",
    "optionalDependencies": "선택",
    "peerDependencies": "피어",
}
NPM_PAGE = "https://www.npmjs.com/package/"
# The stylesheets and the one script, each under its own route /static/<name>: nothing else of
# static/ is served, and no file name is ever taken from a request.
STYLES = ("style.css", "overview.css")
SCRIPT = "app.js"
# The two bundled fonts (scripts/build_dashboard_fonts.py), under static/fonts/, each on its own
# route like the stylesheets: the licences and the coverage list beside them are not served.
FONTS = ("NotoSansKR-depbee.woff2", "JetBrainsMono-depbee.woff2")
# The tab icon, the brand's hexagon cell. Served under the session like the stylesheet: without
# it a browser asks for /favicon.ico, which has no session and is a 403 in its console.
ICON = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path fill="#f4b10b" '
    'stroke="#18202b" d="M8 1l6 3.5v7L8 15l-6-3.5v-7z"/></svg>'
)
# script-src 'self' is the one script file (SCRIPT): no inline script or handler ever runs.
# font-src 'self' is the bundled fonts (FONTS): no font is loaded from elsewhere.
CSP = (
    "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; font-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)
# What a browser says of where a request comes from (Sec-Fetch-Site): the dashboard's own page,
# or the user (the address bar, a reload). A browser that sends nothing is left to Origin.
OWN_SITES = (b"same-origin", b"none")
# no-referrer would make a form POST's Origin "null" (Fetch 3.2), which the POST check refuses.
SECURITY_HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"same-origin"),
    (b"cache-control", b"no-store"),
]
KIND_LABELS = {"scan": "검사(scan)", "update_preview": "업데이트 미리보기"}
# The rail's theme button (theme.py): each theme as the button names it now, and as the words
# that say what the next press does.
THEME_WORDS = {
    "system": ("시스템 설정", "시스템 설정 따르기"),
    "light": ("밝게", "밝게 바꾸기"),
    "dark": ("어둡게", "어둡게 바꾸기"),
}
THEME_FAILED_TITLE = "화면 테마를 저장하지 못했습니다"
THEME_FAILED = "설정 폴더에 쓸 수 없어 지금 화면 테마를 그대로 둡니다."
# The pages of the console a GET opens (under the session): where the theme form may go back to.
PAGES = re.compile(
    r"/(?:|model|projects/mounted|projects/[0-9]+(?:/updates|/history)?|runs/[0-9]+|previews/[A-Za-z0-9_-]+)"
)
MAX_BACK = 2048  # characters of the address the theme form goes back to, decoded
MODEL_LIMITS = (
    "학습 데이터 버전과 공격 유형별 탐지율은 저장된 보고서에 출처가 없어 보이지 않습니다."
)
REGISTER_ERRORS = {
    "long": f"경로가 너무 깁니다({MAX_PATH}자 이하).",
    "local": "로컬 폴더 경로가 아닙니다(빈 값, 네트워크 공유·장치 경로, Windows 예약 이름).",
    "absolute": "절대 경로를 입력하세요.",
    "link": "링크를 확인할 수 없거나 네트워크 공유·장치로 가는 링크가 있는 경로입니다.",
    "folder": "폴더를 찾을 수 없습니다.",
    "lockfile": "폴더에 package-lock.json 파일이 없습니다.",
    "unreadable": "경로를 확인할 수 없습니다.",
    "outside": "컨테이너에 연결한 프로젝트 폴더 밖의 경로는 등록할 수 없습니다(링크를 거치는 경로 "
    "포함).",
}
# The container's folder picker (.mounted) was asked for something it does not list.
MOUNTED_MISSING = "컨테이너에 연결한 프로젝트 폴더 안의 폴더가 아닙니다."
# The folder dialog gave no folder (picker.choose); both open the form for a typed path.
PICK_ERRORS = {
    "unavailable": "폴더 선택 창을 열 수 없습니다(데스크톱 화면이 없거나 이 Python에 tkinter가 "
    "없음). 아래에 폴더 경로를 직접 입력하세요.",
    "timeout": f"폴더 선택 창에서 {picker.PICK_SECONDS}초 안에 폴더를 고르지 않아 창을 닫았습니다. "
    "다시 선택하거나 아래에 폴더 경로를 직접 입력하세요.",
}
PICK_OPEN_TITLE = "폴더 선택 창이 이미 열려 있습니다"
PICK_OPEN = "먼저 연 폴더 선택 창이 아직 열려 있어 창을 새로 열지 않았습니다."
# The dialog is not the browser's window and may open without the keyboard: the keys that switch
# to it where this dashboard runs.
SWITCH_KEYS = "Cmd+Tab" if sys.platform == "darwin" else "Alt+Tab"
# This page was made while the first dialog was open and does not change when a folder is chosen
# there, and reloading it would send the dialog's POST again: PICK_REOPEN is a link (a GET).
PICK_OPEN_NOTE = (
    "먼저 연 창에서 폴더를 고르거나 그 창을 닫으세요. 이 화면은 저절로 바뀌지 않으니, 폴더를 고른 "
    "뒤 아래 링크로 프로젝트 관리를 다시 열어 등록됐는지 확인하세요. 이 화면을 새로 고치면 폴더 "
    f"선택 요청을 다시 보내게 됩니다. 창이 보이지 않으면 {SWITCH_KEYS}으로 전환하세요."
)
PICK_REOPEN = "프로젝트 관리 다시 열기"
PICK_STOPPED = (
    "대시보드를 종료하는 중이어서 폴더 선택을 취소했고 프로젝트를 등록하지 않았습니다. 대시보드를 "
    "다시 시작한 뒤 새 주소에서 다시 선택하세요."
)
SESSION_REFUSED = (
    "세션 주소가 맞지 않습니다. depbee dashboard가 이번 실행에서 출력한 주소로 여세요."
)
FORM_REFUSED = "폼의 세션 값이 맞지 않습니다. 화면을 새로 열고 다시 시도하세요."
BUSY = "다른 검사, 업데이트 확인이나 반영이 실행 중입니다. 끝난 뒤 다시 시도하세요."
BUSY_TITLE = "다른 작업이 실행 중입니다"
BUSY_NOTE = (
    "먼저 보낸 작업은 계속 실행됩니다. 끝나면 그 결과를 프로젝트의 업데이트와 기록 화면에서 볼 수 "
    "있습니다."
)
PREVIEW_GONE = (
    "이 업데이트 미리보기가 없습니다(이미 반영을 시도했거나, 오래되어 지워졌거나, 대시보드를 다시 "
    "시작함). 프로젝트 화면에서 업데이트 확인을 다시 실행하세요."
)
PREVIEW_GONE_TITLE = "미리보기가 없습니다"
PROJECT_MISSING = "등록한 프로젝트 폴더를 찾을 수 없습니다."
# A container's dashboard found package.json or package-lock.json to be a link or no file
# (_refused): nothing read it, and nothing ran.
INPUT_REFUSED = (
    "프로젝트의 package.json이나 package-lock.json이 링크이거나 일반 파일이 아니어서 읽지 "
    "않았습니다. 컨테이너의 대시보드는 연결한 폴더 안에 있는 실제 파일만 읽습니다."
)
PREVIEW_FAILED = "업데이트 확인을 끝내지 못했습니다(파일이나 데이터를 읽거나 쓰지 못함)."
SCAN_TITLE = "검사 오류"  # error.html's heading for a scan (default: the update one)
SCAN_FAILED = "검사를 끝내지 못했습니다(파일이나 데이터를 읽거나 쓰지 못함)."
SCAN_NOT_RECORDED = (
    "이 검사를 로컬 이력에 기록하지 못했습니다(이력 파일이 없거나 쓰지 못함). 검사 결과는 아래와 "
    "같습니다."
)
APPLY_FAILED = "반영 중 예기치 않은 오류가 났습니다. 프로젝트 파일과 백업 폴더를 직접 확인하세요."
TARGETS_TOO_LONG = f"대상 이름이 너무 깁니다({MAX_TARGETS}자 이하)."
CHOOSE_MODE = "반영 방식(lockfile 반영 또는 설치까지)을 하나 고르세요."
CONFIRM_NEEDED = "확인이 필요한 항목이 있습니다. 목록을 검토하고 확인란을 선택한 뒤 진행하세요."
NPMRC_NO_INSTALL = (
    "이 미리보기 때 프로젝트 .npmrc가 있어 설치까지는 고를 수 없습니다. lockfile만 반영한 뒤 "
    ".npmrc를 직접 검토하고 npm ci --ignore-scripts로 설치합니다."
)
PREVIEW_NOT_RECORDED = (
    "이 미리보기를 로컬 이력에 기록하지 못했습니다(이력 파일이 없거나 쓰지 못함). 반영해도 반영 "
    "기록은 남지 않습니다."
)
APPLY_NOT_RECORDED = (
    "반영 기록을 로컬 이력에 남기지 못했습니다. 위 결과와 백업 위치는 실제로 일어난 일입니다."
)
STARTED = "이 주소를 브라우저에서 여세요. 종료하려면 Ctrl+C를 누르세요."
# In a container the address is the host's, where the port has to be published under its number.
CONTAINER_STARTED = (
    "이 주소를 호스트의 브라우저에서 여세요. 컨테이너의 {port}번 포트를 호스트의 127.0.0.1에만 "
    "같은 번호로 게시해야 열립니다(docker run -p 127.0.0.1:{port}:{port}). 종료하려면 Ctrl+C를 "
    "누르거나 docker stop을 실행하세요."
)
STOPPED = "대시보드를 종료했습니다. 위 주소는 더 이상 열리지 않습니다."
# _apply_lines wording without the CLI option: a dashboard apply, and a stored one (CLI or here).
DASHBOARD_REASONS = {
    **APPLY_REASON_LABELS,
    "confirmation_required": "확인이 필요한 항목이 있는데 확인하지 않음",
}
CONFIRMED_HERE = "대시보드에서 확인함"
CONFIRMED_STORED = "확인함"
RETRY_HERE = "업데이트 확인을 다시 실행하고 목록을 검토한 뒤 확인 단계에서 진행합니다."


def _finalize(value):
    """Every {{ }} string is _clean'ed (control, bidi and zero-width characters and lone
    surrogates become visible escapes) before autoescape: html.escape alone keeps them."""
    return _clean(value) if isinstance(value, str) else value


def _when(value: object) -> object:
    """A stored UTC time (ISO 8601 with Z) as "2026-11-21 09:30 UTC"; anything else as it is."""
    try:
        stamp = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return value
    return value if stamp.tzinfo is None else stamp.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


ENV = jinja2.Environment(
    loader=jinja2.PackageLoader("depbee.dashboard", "templates"),
    autoescape=True,  # set here, not left to the file extension
    finalize=_finalize,
    undefined=jinja2.StrictUndefined,
)
ENV.filters["when"] = _when
# A stored threshold in full, and a stored score worded against one, as the text output has them.
ENV.filters["plain"] = plain_number
ENV.filters["score"] = score_text
ENV.filters["short"] = lambda path: _short_path(path)  # defined below; looked up at render


def _text(status: int, text: str) -> Response:
    return Response(text, status, media_type="text/plain; charset=utf-8")


class Guard:
    """Wraps the whole app. Every request: exactly one Host header equal to 127.0.0.1:<port>
    (any case), else 400; a path under /s/<session>/ with this run's session (compared with
    hmac.compare_digest), else 403; a request other than GET or HEAD also needs Origin exactly
    http://127.0.0.1:<port> and, when the browser says where the request comes from
    (Sec-Fetch-Site), one of OWN_SITES, else 403 (the form handlers check the form's session
    field). The app sees the path without the /s/<session> prefix. Cookies are neither read nor
    set. Every response, errors included, gets SECURITY_HEADERS."""

    def __init__(self, app, port: int, session: str):
        self.app, self.session = app, session.encode()
        self.host, self.origin = f"{HOST}:{port}".encode(), f"http://{HOST}:{port}".encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":  # no websockets; lifespan is off
            return

        async def secured(message):
            if message["type"] == "http.response.start":
                message = {**message, "headers": [*message.get("headers", []), *SECURITY_HEADERS]}
            await send(message)

        refused, path = self.refused(scope)
        if refused is not None:
            await _text(*refused)(scope, receive, secured)
            return
        await self.app({**scope, "path": path}, receive, secured)

    def refused(self, scope) -> tuple[tuple[int, str] | None, str]:
        """(status and fixed text, or None) and the path after /s/<session>."""
        headers = scope["headers"]  # ASGI header names are lowercase
        hosts = [value for name, value in headers if name == b"host"]
        if len(hosts) != 1 or hosts[0].lower() != self.host:
            return (400, "잘못된 Host 헤더입니다."), ""
        parts = scope["path"].split("/", 3)  # "", "s", session, rest
        given = parts[2].encode("utf-8", "replace") if len(parts) == 4 else b""
        if parts[:2] != ["", "s"] or not hmac.compare_digest(given, self.session):
            return (403, SESSION_REFUSED), ""
        if scope["method"] not in ("GET", "HEAD"):
            sites = [value.lower() for name, value in headers if name == b"sec-fetch-site"]
            if [v for n, v in headers if n == b"origin"] != [self.origin] or any(
                site not in OWN_SITES for site in sites
            ):
                return (403, "다른 출처의 요청은 받지 않습니다."), ""
        return None, "/" + parts[3]


def build_app(
    port: int, session: str, stopping=None, *, model_dir: Path | None = None,
    cache_dir: Path | None = None, no_cache: bool = False,
    known_malicious_dir: Path | None = None,
):  # fmt: skip
    """The guarded ASGI app for 127.0.0.1:port; session is the value in the address printed at
    start (/s/<session>/), which every link, redirect and form carries. model_dir, cache_dir,
    no_cache, known_malicious_dir: for update previews, as in depbee update.

    stopping: a function that says whether the server of this app has been asked to end
    (serve() gives its server's own flag). From then on the folder dialog is not opened, an open
    one is closed, and neither registers a folder. None: nothing ends the app."""
    base = f"/s/{session}"
    scan_options = {"model_dir": model_dir, "cache_dir": cache_dir, "no_cache": no_cache}
    if known_malicious_dir is not None:  # else the options stay as before (the service's default)
        scan_options["known_malicious_dir"] = known_malicious_dir

    def page(request: Request, name: str, status: int = 200, *, project: dict | None = None,
             section: str | None = None, tabs: list[dict] | None = None, **context) -> Response:  # fmt: skip
        """A page of the console. project: the registered project the page is about, shown as
        the open tab (the template gets its tab); section: the view the page belongs to
        (packages, updates, history; manage and model for the two pages outside a project).
        Every template also gets contained: this dashboard is a container's (.mounted), where
        a page says what choosing a folder and installing do there, not on a desktop. And the
        theme the user chose (theme.py) with the rail's button for the next one, whose form goes
        back to this page: only a page a GET opened has that button, as an answer to a POST has
        no address to come back to (theme_back None)."""
        tabs = _tabs(project) if tabs is None else tabs
        chosen = theme.load()
        # The way back keeps the page's query but a check's one-time return (checked): coming
        # back must not land on that check and move the focus again.
        query = urlencode([(k, v) for k, v in request.query_params.multi_items() if k != "checked"])
        back = base + request.url.path + (f"?{query}" if query else "")
        html = ENV.get_template(name).render(
            safety_note=SAFETY_NOTE, base=base, session=session, tabs=tabs, section=section,
            contained=mounted.root() is not None,
            project=next((tab for tab in tabs if tab["current"]), None), rail=_rail(tabs),
            attention=sum(tab["cell"] in RAIL_ORDER[:3] for tab in tabs),
            theme=chosen, theme_next=theme.next_of(chosen), theme_words=THEME_WORDS,
            theme_back=back if request.method == "GET" else None, **context,
        )  # fmt: skip
        # _finalize has escaped lone surrogates; backslashreplace keeps any left from a 500.
        body = html.encode("utf-8", "backslashreplace")
        return Response(body, status, media_type="text/html; charset=utf-8")

    def stopped(request: Request, status: int, title: str, message: str, note: str | None,
                project: dict | None = None) -> Response:  # fmt: skip
        """A request that ran nothing (another one is running, or its preview is gone), as a
        page with the tabs: a double click must not end on bare text with no way on."""
        return page(request, "error.html", status, project=project, section="updates",
                    title=title, message=message, note=note)  # fmt: skip

    async def read_form(request: Request) -> dict | Response:
        """The urlencoded form whose session field is this run's session, or the refusal."""
        kind = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if kind != "application/x-www-form-urlencoded":
            return _text(415, "폼(application/x-www-form-urlencoded)만 받습니다.")
        body = await request.body()  # at most MAX_BODY (Starlette max_body_size)
        try:
            form = parse_qs(body.decode("ascii"), keep_blank_values=True,
                            max_num_fields=MAX_FIELDS, errors="strict")  # fmt: skip
        except ValueError:  # also UnicodeError
            return _text(400, "폼을 읽을 수 없습니다.")
        given = form.get("session", [])
        if len(given) != 1 or not hmac.compare_digest(given[0].encode(), session.encode()):
            return _text(403, FORM_REFUSED)
        return form

    def projects(request: Request, status: int = 200, error: str | None = None, *,
                 typed: bool = False, manual: bool = False) -> Response:  # fmt: skip
        """The management page. error: why nothing was registered; typed: it is about the path
        typed into the form (else about the folder dialog); manual: the form for a typed path
        is shown open."""
        # The tabs are the list: each with its recent runs for the trend table.
        return page(request, "projects.html", status, section="manage",
                    tabs=_tabs(None, RECENT_RUNS), error=error, typed=typed,
                    manual=typed or manual, pick_seconds=picker.PICK_SECONDS,
                    switch_keys=SWITCH_KEYS)  # fmt: skip

    def home(request: Request) -> Response:
        """The session's first page. While no project is registered it is the start page,
        whatever the address asks for: one button that sends the form of pick, and no console
        around it. From then on it is the overview of the registered projects, and the
        management page when the address asks for it (?manage=1): a closed folder dialog and
        the link of a refused one lead there, so that a registration that did not happen never
        ends on the overview."""
        tabs = _tabs(None)
        if not tabs:
            return page(request, "start.html", section="start", tabs=tabs)
        if request.query_params.getlist("manage") == ["1"]:
            return projects(request)
        portfolio = _portfolio(tabs)
        return page(request, "overview.html", section="overview", tabs=tabs,
                    portfolio=portfolio, chart=_chart(portfolio))  # fmt: skip

    def enroll(request: Request, path: str, typed: bool) -> Response:
        """Register the folder at path, however it was given (the dialog, the container's list
        of mounted folders, a typed path); a path that fails the registration checks registers
        nothing. The first project of all opens the overview, where it stands with nothing
        inspected yet: the start page's one button ends there. Every later registration opens
        its own project, as does registering a folder again."""
        problem = _registration_problem(path)
        if problem:  # the input is not echoed
            return projects(request, 400, REGISTER_ERRORS[problem], typed=typed)
        first = not history.list_projects()
        project_id = history.register_project(Path(path))
        return RedirectResponse(f"{base}/" if first else f"{base}/projects/{project_id}", 303)

    async def register(request: Request) -> Response:
        form = await read_form(request)
        if isinstance(form, Response):
            return form
        paths = form.get("path", [])
        if len(paths) != 1:
            return _text(400, "경로 하나를 입력하세요.")
        return enroll(request, paths[0], True)

    picking = threading.Lock()  # one folder dialog at a time; pages stay open meanwhile
    # What picker.choose is given to watch: nothing in an app without a server that ends.
    watch = () if stopping is None else (stopping,)

    def ending() -> bool:
        return stopping is not None and stopping()

    async def pick(request: Request) -> Response:
        """Open the desktop's folder dialog (POST from the management page) and register the
        folder chosen there. The dialog runs in a child process that a worker thread waits for
        (picker.choose). Closing it registers nothing, and so does a dialog that cannot be
        shown or is still open at its time limit: those open the form for a typed path.

        A server that has been asked to end opens no dialog, and picker.choose closes the open
        one, so that the server does not wait for it. ending() is asked again after the answer,
        here in the server's own thread, where the stop request is taken too: an answer that
        comes back after that request registers nothing either.

        A container has no desktop: there the same button leads to the folders mounted into it
        (mounted_folders), and no dialog is ever started."""
        form = await read_form(request)
        if isinstance(form, Response):
            return form
        if mounted.root() is not None:
            return RedirectResponse(f"{base}/projects/mounted", 303)
        if ending():
            return _text(503, PICK_STOPPED)
        if not picking.acquire(blocking=False):
            return page(request, "error.html", 409, section="manage", title=PICK_OPEN_TITLE,
                        message=PICK_OPEN, note=PICK_OPEN_NOTE, reopen=PICK_REOPEN)  # fmt: skip
        try:
            outcome, folder = await run_in_threadpool(picker.choose, *watch)
        finally:
            picking.release()
        if outcome == "stopped" or ending():
            return _text(503, PICK_STOPPED)
        if outcome == "cancelled":
            return RedirectResponse(f"{base}/?manage=1", 303)
        if outcome != "chosen":
            return projects(request, 503, PICK_ERRORS[outcome], manual=True)
        return enroll(request, folder, False)

    def mounted_folders(request: Request) -> Response:
        """The container's folder picker: the folders below the mounted one that the at query
        names (mounted.listing), each project among them with the form that registers its path
        as a typed one is registered. It lists names and registers nothing; outside a container
        there is no such page."""
        top, given = mounted.root(), request.query_params.getlist("at")
        if top is None or len(given) > 1:
            return _text(404, MOUNTED_MISSING)
        view = mounted.listing(given[0] if given else "")
        if view is None and given not in ([], [""]):
            return _text(404, MOUNTED_MISSING)
        # Without a view the mounted folder itself is not there: the page says how to mount one.
        return page(request, "mounted.html", section="manage", root=str(top), view=view)

    def held(found: dict, state: dict) -> list[dict]:
        """The update previews of the project that this process still holds, newest first: the
        only ones that can be applied. A copy: the request handlers of other threads add and
        drop previews meanwhile."""
        return [
            {"id": preview_id, "run_id": kept["run_id"], "created_at": kept["created_at"],
             "lines": _preview_lines(kept["result"]["preview"], _clean)[:2],
             "current": _made_from(kept["result"]["preview"]) == state["now"]}
            for preview_id, kept in reversed(list(previews.items()))
            if kept["project_id"] == found["id"]
        ]  # fmt: skip

    def project(request: Request) -> Response:
        """The packages view: what package-lock.json installs, and for each entry the candidate
        a current update check found for it, that it found none, or that nothing was checked.
        The search, the kind and the tab (show) narrow the list together (_filters); each tab
        counts the rows the search and the kind leave, and a tab with none lists them all.
        selected: the candidate opened beside the list, one of the rows the filters leave: the
        one the address names (_selected), which after a check is the first one that check
        returned (_landing); returned: what the check that sent the browser here found
        (_returned)."""
        found = _project(request.path_params["project_id"])
        if found is None:
            return _text(404, "등록된 프로젝트가 아닙니다.")
        params = request.query_params
        filters = _filters(params)
        if filters is None:
            return _text(400, "패키지 이름이나 의존성 종류를 확인하세요.")
        query, scope, show = filters
        dependencies, problem = _dependencies(found["path"])
        direct_count = sum(row["direct"] for row in dependencies)
        state = _update_state(found)
        candidates = {row["location"]: row for row in state["rows"]}
        listed = [
            {**row, "candidate": candidates.get(row["location"]),
             "checked": state["full"] is not None or row["location"] in state["covered"],
             "declared": ", ".join(DECLARED_LABELS[field] for field in row["declared"]),
             "declared_as": _declared_as(row)}
            for row in _listed(dependencies, query, scope)
        ]  # fmt: skip
        kinds = [_kind(row) for row in listed]
        counts = {key: len(kinds) if key == "all" else kinds.count(key) for key in SHOWS}
        # A tab with nothing in it lists everything: an address kept from before, or a search
        # that leaves none of that tab, never empties the list.
        show = show if counts[show] else "all"
        rows = [row for row, kind in zip(listed, kinds, strict=True) if show in ("all", kind)]
        head = _head(found, dependencies, problem, state)
        targets = _preview_targets(found["path"]) if any(row["direct"] for row in rows) else set()
        shown = [row["candidate"] for row in rows if row["candidate"] is not None]
        selected = _selected(params, shown)
        returned = _returned(params, state, shown, selected)
        return page(request, "project.html", project=found, section="packages", rows=rows,
                    direct_count=direct_count, nested_count=len(dependencies) - direct_count,
                    query=query, scope=scope, show=show, counts=counts,
                    targets=targets, max_query=MAX_NAME_LENGTH, problem=problem, state=state,
                    returned=returned, selected=selected, previews=held(found, state),
                    head=head)  # fmt: skip

    def updates(request: Request) -> Response:
        """The updates view: the named check, the previews this process still holds (held) and
        the current candidates in groups (_grouped). selected: the candidate opened beside the
        list, the first one shown when the address names none."""
        found = _project(request.path_params["project_id"])
        if found is None:
            return _text(404, "등록된 프로젝트가 아닙니다.")
        state = _update_state(found)
        last = state["last"]
        applied = history.list_applies(found["id"], 1) if last else []
        applied_at = (
            applied[0]["created_at"]
            if applied and applied[0]["run_id"] == last["id"] and applied[0]["outcome"] == "applied"
            else None
        )
        head = _head(found, *_dependencies(found["path"]), state)
        groups = _grouped(state["rows"])
        shown = [row for group in groups for row in group["rows"]]
        return page(request, "updates.html", project=found, section="updates", state=state,
                    head=head, groups=groups,
                    previews=held(found, state), applied_at=applied_at, max_targets=MAX_TARGETS,
                    selected=_selected(request.query_params, shown))  # fmt: skip

    def project_history(request: Request) -> Response:
        """The history view: the project's applies and runs, each run linked to its report."""
        found = _project(request.path_params["project_id"])
        if found is None:
            return _text(404, "등록된 프로젝트가 아닙니다.")
        runs = [_run_row(run) for run in history.list_runs(found["id"])]
        applies = [_apply_row(row) for row in history.list_applies(found["id"])]
        head = _head(found, *_dependencies(found["path"]), _update_state(found), len(runs))
        scores = history.list_run_scores(found["id"])
        return page(request, "history.html", project=found, section="history", runs=runs,
                    head=head,
                    applies=applies, score_history=scores,
                    score_chart=_score_chart(scores))  # fmt: skip

    def run(request: Request) -> Response:
        run_id = request.path_params["run_id"]
        stored = history.get_run(run_id) if run_id <= MAX_ID else None
        if stored is None:
            return _text(404, "저장된 실행이 아닙니다.")
        preview, applied = stored["preview"], stored["apply"]
        return page(
            request, "run.html", run=_run_row(stored), project=_project(stored["project_id"]),
            section="history",
            preview=None if preview is None else _preview_lines(preview, _clean),
            apply=None if applied is None else _apply_view(
                applied["apply"], CONFIRMED_STORED, threshold=stored["report"].get("threshold")),
            **_report(stored["report"]),
        )  # fmt: skip

    # Update previews of this process only, newest last: {id: project_id, run_id, result,
    # new_package, new_lock, created_at}. The new file bytes never go to a file or the history.
    previews: OrderedDict[str, dict] = OrderedDict()
    busy = threading.Lock()  # one preview or apply at a time; pages stay open meanwhile

    def preview_page(request: Request, kept: dict, preview_id: str, status: int = 200,
                     error: str | None = None) -> Response:  # fmt: skip
        result = kept["result"]
        blocked, required = service.update_gate(result["report"])
        threshold = result["report"].get("threshold")
        return page(
            request, "preview.html", status, preview_id=preview_id, error=error,
            project=_project(kept["project_id"]), section="updates", created_at=kept["created_at"],
            run_id=kept["run_id"], not_recorded=PREVIEW_NOT_RECORDED if kept["run_id"] is None
            else None, lines=_preview_lines(result["preview"], _clean),
            blocked=[_apply_item(item, _clean, _text_label, threshold) for item in blocked],
            blocked_reason=APPLY_REASON_LABELS["known_malicious_hit"],
            required=[_apply_item(item, _clean, _text_label, threshold) for item in required],
            changed=bool(result["report"]["results"]),
            npmrc=NPMRC_NO_INSTALL if result["preview"]["project_npmrc_ignored"] else None,
            modes=list(MODE_LABELS.items()), **_report(result["report"]),
        )  # fmt: skip

    async def check_update(request: Request) -> Response:
        """Preview and check an update of a registered project (POST from its page)."""
        form = await read_form(request)
        if isinstance(form, Response):
            return form
        found = _project(request.path_params["project_id"])
        if found is None:
            return _text(404, "등록된 프로젝트가 아닙니다.")
        targets = form.get("packages", [""])
        if len(targets) != 1:
            return _text(400, "대상 이름 칸이 하나여야 합니다.")
        if len(targets[0]) > MAX_TARGETS:
            return page(request, "error.html", 400, project=found, section="updates",
                        message=TARGETS_TOO_LONG)  # fmt: skip
        if not _found(found["path"]):  # the registered path, checked as at registration
            return page(request, "error.html", 400, project=found, section="updates",
                        message=PROJECT_MISSING)  # fmt: skip
        if _refused(found["path"], "package.json", "package-lock.json"):
            return page(request, "error.html", 400, project=found, section="updates",
                        message=INPUT_REFUSED)  # fmt: skip
        if not busy.acquire(blocking=False):
            return stopped(request, 409, BUSY_TITLE, BUSY, BUSY_NOTE, found)
        try:
            outcome = await run_in_threadpool(
                _run_preview, Path(found["path"]), targets[0].split(), scan_options
            )
        finally:
            busy.release()
        if isinstance(outcome, str):
            return page(request, "error.html", 400, project=found, section="updates",
                        message=outcome)  # fmt: skip
        result, new_package, new_lock, run_id = outcome
        preview_id = secrets.token_urlsafe(16)
        previews[preview_id] = {
            "project_id": found["id"], "run_id": run_id, "result": result,
            "new_package": new_package, "new_lock": new_lock, "created_at": _now(),
        }  # fmt: skip
        while len(previews) > KEPT_PREVIEWS:
            previews.popitem(last=False)
        # Sent from the packages view and recorded: back to that list, where the first candidate
        # this check returned is opened (_landing). The preview stays held and nothing is
        # applied. Any other check opens its preview, as before.
        back = _back(form)
        if back is not None and run_id is not None:
            landing = await run_in_threadpool(_landing, found, back, run_id)
            return RedirectResponse(f"{base}/projects/{found['id']}?{landing}", 303)
        return RedirectResponse(f"{base}/previews/{preview_id}", 303)

    async def scan(request: Request) -> Response:
        """Scan a registered project's uncommitted lockfile change against Git HEAD, as depbee
        scan --extract does by default (POST from its page); the same one-at-a-time lock."""
        form = await read_form(request)
        if isinstance(form, Response):
            return form
        found = _project(request.path_params["project_id"])
        if found is None:
            return _text(404, "등록된 프로젝트가 아닙니다.")
        if not _found(found["path"]):  # the registered path, checked as at registration
            return page(request, "error.html", 400, project=found, section="updates",
                        message=PROJECT_MISSING, title=SCAN_TITLE)  # fmt: skip
        if _refused(found["path"], "package-lock.json"):
            return page(request, "error.html", 400, project=found, section="updates",
                        message=INPUT_REFUSED, title=SCAN_TITLE)  # fmt: skip
        if not busy.acquire(blocking=False):
            return stopped(request, 409, BUSY_TITLE, BUSY, BUSY_NOTE, found)
        try:
            outcome = await run_in_threadpool(_run_scan, Path(found["path"]), scan_options)
        finally:
            busy.release()
        if isinstance(outcome, str):
            return page(request, "error.html", 400, project=found, section="updates",
                        message=outcome, title=SCAN_TITLE)  # fmt: skip
        report, run_id = outcome
        if run_id is None:  # the result is not hidden when it could not be recorded
            return page(request, "scanned.html", project=found, section="updates",
                        not_recorded=SCAN_NOT_RECORDED, **_report(report))  # fmt: skip
        return RedirectResponse(f"{base}/runs/{run_id}", 303)

    def show_preview(request: Request) -> Response:
        preview_id = request.path_params["preview_id"]
        kept = previews.get(preview_id)
        if kept is None:
            return stopped(request, 404, PREVIEW_GONE_TITLE, PREVIEW_GONE, None)
        return preview_page(request, kept, preview_id)

    async def apply(request: Request) -> Response:
        """Apply a kept preview once: the preview leaves memory before the service runs, so a
        reload or a resent form finds nothing to apply."""
        form = await read_form(request)
        if isinstance(form, Response):
            return form
        preview_id = request.path_params["preview_id"]
        kept = previews.get(preview_id)
        if kept is None:
            return stopped(request, 404, PREVIEW_GONE_TITLE, PREVIEW_GONE, None)
        modes = form.get("mode", [])
        if len(modes) != 1 or modes[0] not in service.APPLY_MODES:
            return preview_page(request, kept, preview_id, 400, CHOOSE_MODE)
        mode, confirmed = modes[0], form.get("confirm", []) == ["yes"]
        _, required = service.update_gate(kept["result"]["report"])
        if required and not confirmed:
            return preview_page(request, kept, preview_id, 400, CONFIRM_NEEDED)
        if mode == "install" and kept["result"]["preview"]["project_npmrc_ignored"]:
            return preview_page(request, kept, preview_id, 400, NPMRC_NO_INSTALL)
        found = _project(kept["project_id"])
        if found is None or not _found(found["path"]):
            return page(request, "error.html", 400, project=found, section="updates",
                        message=PROJECT_MISSING)  # fmt: skip
        # Looked at again here: the files may have changed since the preview read them.
        if _refused(found["path"], "package.json", "package-lock.json"):
            return page(request, "error.html", 400, project=found, section="updates",
                        message=INPUT_REFUSED)  # fmt: skip
        if not busy.acquire(blocking=False):
            return stopped(request, 409, BUSY_TITLE, BUSY, BUSY_NOTE, found)
        try:
            kept = previews.pop(preview_id, None)
            if kept is None:
                return stopped(request, 404, PREVIEW_GONE_TITLE, PREVIEW_GONE, None, found)
            outcome = await run_in_threadpool(_run_apply, Path(found["path"]), kept, mode,
                                              confirmed)  # fmt: skip
        finally:
            busy.release()
        if isinstance(outcome, str):
            return page(request, "error.html", 500, project=found, section="updates",
                        message=outcome)  # fmt: skip
        applied, recorded = outcome
        return page(
            request, "applied.html", project=found, section="updates",
            run_id=kept["run_id"] if recorded else None,
            not_recorded=None if recorded else (
                APPLY_NOT_RECORDED if kept["run_id"] is not None else PREVIEW_NOT_RECORDED),
            apply=_apply_view(applied, CONFIRMED_HERE, RETRY_HERE,
                              kept["result"]["report"].get("threshold")),
        )  # fmt: skip

    def model(request: Request) -> Response:
        return page(request, "model.html", section="model", models=_models(),
                    limits=MODEL_LIMITS)  # fmt: skip

    async def choose_theme(request: Request) -> Response:
        """The rail's theme form (theme.py): save the theme chosen and go back to the page the
        form was on (_way_back). A theme that cannot be saved leaves the one there was, and the
        page says so. Nothing else waits for this: it runs while a check runs."""
        form = await read_form(request)
        if isinstance(form, Response):
            return form
        given, back = form.get("theme", []), form.get("back", [])
        if len(given) != 1 or given[0] not in theme.THEMES or len(back) > 1:
            return _text(400, "화면 테마를 확인하세요.")
        try:
            await run_in_threadpool(theme.save, given[0])
        except (OSError, GuardError, RuntimeError):
            return page(request, "error.html", 503, title=THEME_FAILED_TITLE,
                        message=THEME_FAILED, note="")  # fmt: skip
        return RedirectResponse(_way_back(base, back[0] if back else ""), 303)

    def asset(name: str, media_type: str):
        """The handler of one file of static/ (STYLES, SCRIPT, fonts/ FONTS): the file is the
        route's own."""

        def served(request: Request) -> Response:
            file = importlib.resources.files("depbee.dashboard").joinpath(
                "static", *name.split("/")
            )
            return Response(file.read_bytes(), media_type=media_type)

        return served

    def icon(request: Request) -> Response:
        return Response(ICON, media_type="image/svg+xml")

    def failed(request: Request, exc: Exception) -> Response:
        # No exception text: it can hold paths or package strings.
        return _text(500, "요청을 처리하지 못했습니다(이력 데이터베이스나 파일을 읽지 못함).")

    app = Starlette(
        routes=[
            Route("/", home),
            Route("/projects", register, methods=["POST"]),
            Route("/projects/pick", pick, methods=["POST"]),
            Route("/projects/mounted", mounted_folders),
            Route("/projects/{project_id:int}", project),
            Route("/projects/{project_id:int}/updates", updates),
            Route("/projects/{project_id:int}/history", project_history),
            Route("/projects/{project_id:int}/previews", check_update, methods=["POST"]),
            Route("/projects/{project_id:int}/scans", scan, methods=["POST"]),
            Route("/previews/{preview_id}", show_preview),
            Route("/previews/{preview_id}/apply", apply, methods=["POST"]),
            Route("/runs/{run_id:int}", run),
            Route("/model", model),
            Route("/theme", choose_theme, methods=["POST"]),
            *(Route(f"/static/{name}", asset(name, "text/css; charset=utf-8")) for name in STYLES),
            Route(f"/static/{SCRIPT}", asset(SCRIPT, "text/javascript; charset=utf-8")),
            *(
                Route(f"/static/fonts/{name}", asset(f"fonts/{name}", "font/woff2"))
                for name in FONTS
            ),
            Route("/static/icon.svg", icon),
        ],
        exception_handlers={Exception: failed},
        max_body_size=MAX_BODY,
    )
    app.router.redirect_slashes = False  # its redirect would drop the /s/<session> prefix
    return Guard(app, port, session)


def _found(path: str) -> bool:
    """The registered folder still exists, looked at as at registration (no share or device).
    In a container it is a folder of the mounted one as it is spelled (mounted.problem): a path
    outside that folder, as an older history may hold, is not looked at."""
    try:
        if mounted.root() is not None:
            return mounted.problem(Path(path)) is None
        real = mcp._unlinked(mcp._local_path(path, "project"), "project")
        return real is not None and stat.S_ISDIR(real.stat().st_mode)
    except (GuardError, OSError, ValueError):
        return False


def _refused(path: str, *names: str) -> bool:
    """A container's dashboard must not read one of the files names of the registered folder at
    path: it is there, but not as a regular file of the mounted folder itself (a link, or
    something that is no file), or it cannot be looked at (mounted.problem). Asked each time
    before a file is read or a service is given the folder, since the file may have changed
    since it was last read. Only a file that is really missing is not refused: its reader's own
    error says that it is missing. Always False on a desktop, which reads a file through its
    links as before."""
    return mounted.root() is not None and any(
        mounted.problem(Path(path) / name, stat.S_ISREG) not in (None, "missing") for name in names
    )


def _registration_problem(text: str) -> str | None:
    """A REGISTER_ERRORS key, or None for an absolute local folder with a regular
    package-lock.json file. The MCP path checks: shares, device paths, reserved names and links
    to them are refused before anything behind them is touched. In a container the folder and
    its lockfile must be in the mounted folder as they are spelled (mounted.problem): a path
    outside it is refused before anything of it is looked at, and a link wherever it leads."""
    if len(text) > MAX_PATH:
        return "long"
    try:
        path = mcp._local_path(text, "path")
    except GuardError:
        return "local"
    if not path.is_absolute():
        return "absolute"
    try:
        if mounted.root() is not None:
            for target, kind, missing in ((path, stat.S_ISDIR, "folder"),
                                          (path / "package-lock.json", stat.S_ISREG, "lockfile")):  # fmt: skip
                problem = mounted.problem(target, kind)
                if problem in ("outside", "link"):
                    return "outside"
                if problem is not None:
                    return "unreadable" if problem == "unreadable" else missing
            return None
        folder = mcp._unlinked(path, "path")
        if folder is None or not stat.S_ISDIR(folder.stat().st_mode):
            return "folder"
        lock = mcp._unlinked(path / "package-lock.json", "package-lock.json")
        if lock is None or not stat.S_ISREG(lock.stat().st_mode):
            return "lockfile"
    except GuardError:
        return "link"
    except (OSError, ValueError):
        return "unreadable"
    return None


def _way_back(base: str, given: str) -> str:
    """The address the theme form goes back to: given, when it is a page of this console that a
    GET opens (PAGES under base, with the query it had), else the console's first page. Never
    another site, another session, a form's own address or a file."""
    home = f"{base}/"
    if len(unquote(given)) > MAX_BACK or not given.isprintable() or "\\" in given or "#" in given:
        return home
    if not given.startswith(home):
        return home
    return given if PAGES.fullmatch(given[len(base) :].partition("?")[0]) else home


def _project(project_id: int) -> dict | None:
    return next((p for p in history.list_projects() if p["id"] == project_id), None)


def _short_path(path: str) -> str:
    """A registered path as the overview and a project's head show it: "…", its separator and
    its last three folders, or the path itself when it has no more than three below its drive
    or root. A path is a Windows one by its drive or its UNC "\\\\", else a POSIX one (a
    container's), where a backslash is part of a folder's name. The separator shown is the one
    the path is written with; the whole path is on hover (title) and on project management."""
    windows = re.match(r"[A-Za-z]:|\\\\", path) is not None
    pure = PureWindowsPath(path) if windows else PurePosixPath(path)
    parts = pure.parts[1:] if pure.anchor else pure.parts
    if len(parts) <= 3:
        return path
    separator = "\\" if windows and "\\" in path else "/"
    return "…" + separator + separator.join(parts[-3:])


def _names(paths: list[str]) -> list[str]:
    """A tab name per registered path: the folder name, with as many parent folders in front as
    it takes to tell it from every other registered path, joined with "/" (a backslash is drawn
    as a won sign by Korean fonts); the path itself if it takes all of it. Names are compared as
    the OS compares paths, so folders that differ only in case on Windows count as the same
    name."""
    folded = [Path(os.path.normcase(path)).parts for path in paths]
    names = []
    for index, path in enumerate(paths):
        parts, own, depth = Path(path).parts, folded[index], 1
        while depth < len(own) and any(
            other[-depth:] == own[-depth:] for at, other in enumerate(folded) if at != index
        ):
            depth += 1
        names.append("/".join(parts[-depth:]) if depth < len(parts) else path)
    return names


def _tabs(current: dict | None, recent: int = 1) -> list[dict]:
    """Every registered project as a tab of the console, in registration order: the project
    with its name (_names), whether its folder is still there, its latest runs (recent of them,
    as _run_row) and the hexagon mark and words of its state. The state is a missing folder
    first, else the latest run's stored status: never a new verdict."""
    projects = history.list_projects()
    tabs = []
    for project, name in zip(projects, _names([p["path"] for p in projects]), strict=True):
        runs = history.list_runs(project["id"], recent)
        found = _found(project["path"])
        if not found:
            cell, state = "gone", "폴더를 찾을 수 없음"
        elif not runs:
            cell, state = "none", "실행 기록 없음"
        else:
            status = runs[0]["status"]
            cell, short = TAB_STATES.get(status) or ("none", "알 수 없음")
            state = f"최근 실행 {short}"
        tabs.append({
            **project, "name": name, "found": found, "cell": cell, "state": state,
            "runs": [_run_row(run) for run in runs],
            "current": current is not None and project["id"] == current["id"],
        })  # fmt: skip
    return tabs


def _head(found: dict, dependencies: list[dict], problem: str | None, state: dict,
          runs: int | None = None) -> dict:  # fmt: skip
    """How many each view of a project holds, for its head's links: packages, the lockfile's
    entries (None when it cannot be read); updates, the current candidates (_update_state);
    history, the stored runs (counted here unless given). full: whether a current check covers
    everything, so the head's check button says it checks again."""
    if runs is None:
        runs = history.count_runs(found["id"])
    return {"packages": None if problem else len(dependencies), "updates": len(state["rows"]),
            "history": runs, "full": state["full"] is not None}  # fmt: skip


def _rail(tabs: list[dict]) -> list[dict]:
    """The tabs (_tabs) in the rail's order (RAIL_ORDER), each state in registration order. The
    state is the tab's, a stored status (a none mark with a run is a result that is unknown):
    the rail hashes no file, so "파일 바뀜" is the overview's alone."""

    def state(tab: dict) -> str:
        return "unknown" if tab["cell"] == "none" and tab["runs"] else tab["cell"]

    return sorted(tabs, key=lambda tab: RAIL_ORDER.index(state(tab)))


def _portfolio(tabs: list[dict]) -> list[dict]:
    """The overview's row of each registered project (tabs: _tabs()): its id, name, path and
    whether its folder is found, with what the history says of it.

    run: its newest run, a scan or an update preview alike (a _run_row(), None without one).
    state: that run's stored status as one of STATES, with cell and label: gone for a folder
    that is not found, whatever was stored; none without a run; stale for an update preview
    that the project's files no longer are (_stale); unknown for a status that is not one of
    the three a report has. Never a new verdict.

    attempt: its most recently recorded apply, whatever the outcome (history.latest_applies):
    {run_id, created_at, mode, outcome and reason worded as in the history view, cell, applied
    (it changed the files)}, None if nothing was ever tried. success: the last apply that did
    change the files, {run_id, created_at}, only when the newest attempt is not that one.

    The newest run is the one the tab already has, and both kinds of apply are read once for
    all the projects. Only stored run and apply columns are read, no report or apply document;
    the two project files are hashed only for a project whose newest run is an update preview."""
    portfolio = []
    attempts, successes = history.latest_applies(applied=False), history.latest_applies()
    for tab in tabs:
        run = tab["runs"][0] if tab["runs"] else None
        attempt, success = attempts.get(tab["id"]), successes.get(tab["id"])
        if not tab["found"]:
            state = "gone"
        elif run is None:
            state = "none"
        elif tab["cell"] == "none":  # a run, but its stored status is none of TAB_STATES
            state = "unknown"
        elif run["preview"] and _stale(tab, run["id"], success):
            state = "stale"
        else:
            state = tab["cell"]
        cell, label, _ = STATES[state]
        row = {**{key: tab[key] for key in ("id", "name", "path", "found")},
               "state": state, "cell": cell, "label": label, "run": run,
               "attempt": None, "success": None}  # fmt: skip
        if attempt is not None:
            applied = attempt["outcome"] == "applied"
            reason = attempt["reason"]
            row["attempt"] = {
                "run_id": attempt["run_id"], "created_at": attempt["created_at"],
                "mode": _text_label(MODE_LABELS, attempt["mode"]),
                "outcome": _text_label(OUTCOME_LABELS, attempt["outcome"]),
                "reason": None if reason is None else _text_label(DASHBOARD_REASONS, reason),
                "cell": APPLY_CELLS.get(attempt["outcome"], "none"), "applied": applied,
            }  # fmt: skip
            if not applied and success is not None:
                row["success"] = {key: success[key] for key in ("run_id", "created_at")}
        portfolio.append(row)
    return portfolio


def _stale(project: dict, run_id: int, applied: dict | None) -> bool:
    """Whether the project's package.json and package-lock.json are no longer the files that
    its newest run, the update preview run_id, says something of: neither the two files it was
    made from (history.list_previews finds it first among the previews of the files as they
    are now) nor the two that applying it left (applied: the project's last apply that changed
    its files, history.latest_applies). A file that cannot be read is not one of those either.
    A scan stores no hash of its files, so this is never asked of one."""
    now = (_sha256(project["path"], "package.json"), _sha256(project["path"], "package-lock.json"))
    if None in now:
        return True
    current = history.list_previews(project["id"], *now)
    if current and current[0]["id"] == run_id:
        return False
    if applied is None or applied["run_id"] != run_id:
        return True
    left = (applied["new_package_json_sha256"] or applied["package_json_sha256"],
            applied["new_package_lock_sha256"])  # fmt: skip
    return left != now


def _chart(portfolio: list[dict]) -> list[dict]:
    """The overview's chart: how many of the registered projects are in each state of STATES,
    in that order, as {key, cell, label, count}. A state that says something went wrong with
    the folder or the files is listed only while a project is in it."""
    counts = Counter(row["state"] for row in portfolio)
    return [{"key": key, "cell": cell, "label": label, "count": counts[key]}
            for key, (cell, label, always) in STATES.items() if always or counts[key]]  # fmt: skip


def _sha256(folder: str, name: str) -> str | None:
    """SHA-256 of the regular file name in a registered folder, reached as at registration; None
    if it is not there, cannot be read or is larger than any file depbee previews."""
    try:
        if _refused(folder, name):
            return None
        real = mcp._unlinked(mcp._local_path(folder, "project") / name, name)
        if real is None:
            return None
        mode = real.stat()
        if not stat.S_ISREG(mode.st_mode) or mode.st_size > MAX_JSON_BYTES:
            return None
        with real.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except (GuardError, OSError, ValueError):
        return None


def _made_from(preview: object) -> tuple:
    """The SHA-256 of the package.json and package-lock.json an update preview was made from."""
    if not isinstance(preview, dict):
        return (None, None)
    return (preview.get("package_json_sha256"), preview.get("package_lock_sha256"))


def _update_state(project: dict) -> dict:
    """What the history says about updating the project's files as they are now; nothing here
    runs npm or reaches the network. Only this project's update previews made from package.json
    and package-lock.json with the SHA-256 they have now count as current checks, however many
    other runs came after them (history.list_previews; _candidates): a result from other files
    or from another project is never a current candidate. now: the two hashes (None for a file
    that cannot be read); last: the newest update preview when the files can be read and none
    is current."""
    now = (_sha256(project["path"], "package.json"), _sha256(project["path"], "package-lock.json"))
    readable = None not in now
    checks = history.list_previews(project["id"], *now) if readable else []
    newest = (
        history.list_runs(project["id"], 1, "update_preview") if readable and not checks else []
    )
    return {"now": now, "readable": readable, "last": newest[0] if newest else None,
            **_candidates(checks)}  # fmt: skip


def _candidates(checks: list[dict]) -> dict:
    """The update candidates of current checks (history.list_previews: newest first, down to
    the newest check of everything). Each lockfile location takes the newest check that covers
    it. A check covers the locations of its result rows, its targets' own locations
    (node_modules/<name>) and, without targets, every location; a covered location without a
    row has no candidate. Locations are compared as the lockfile and the reports spell them. A
    stored location is that spelling unless it holds ESCAPED_SURROGATE, and only a check with
    such a stored location has its locations read from its stored report.

    Only a check that covers a location no newer check covers is used, and beyond that only the
    stored reports of the used checks with a candidate row are read (history.get_run). checks:
    {id, created_at, targets (the names, None for everything)} of the checks used, newest
    first; rows: _result() views in the report order (D-13) with before, after, the run and the
    row's position in its report (the anchor on the run page), and model_id, threshold and
    list_as_of (of the known malicious list) as that report stores them, None for what it does
    not say; covered: the locations the used checks cover; full: the check of everything among
    them (as in checks), None if only named packages were checked; summary: the counts as the
    text output words them, None without a row."""
    reports = {}  # run -> its stored report, read once

    def report_of(run_id: int) -> dict:
        if run_id not in reports:
            reports[run_id] = history.get_run(run_id)["report"]
        return reports[run_id]

    owners = {}  # location -> (run of the newest check that covers it, its row's position or None)
    listed = []
    for check in checks:
        targets = check["targets"]
        names = [n for n in targets if isinstance(n, str)] if isinstance(targets, list) else []
        locations = check["locations"]
        if any(isinstance(place, str) and ESCAPED_SURROGATE in place for place in locations):
            locations = [row["location"] for row in report_of(check["id"])["results"]]
        for position, location in enumerate(locations):
            owners.setdefault(location, (check["id"], position))
        for name in names:
            owners.setdefault(f"node_modules/{name}", (check["id"], None))
        # Joined here: a filter's safe string would be escaped twice after _finalize.
        listed.append({"id": check["id"], "created_at": check["created_at"],
                       "targets": None if targets is None else ", ".join(names)})  # fmt: skip
    used = {run_id for run_id, _ in owners.values()}
    shown = [check for check in listed if check["id"] in used or check["targets"] is None]
    positions = {}  # run -> the positions of its candidate rows, in report order
    for run_id, position in owners.values():
        if position is not None:
            positions.setdefault(run_id, []).append(position)
    picked = {}  # id(a candidate's report row) -> its run, its position and its report
    for run_id, wanted in positions.items():
        report = report_of(run_id)
        for position in wanted:
            picked[id(report["results"][position])] = (run_id, position, report)
    raw = _ordered([report["results"][position] for _, position, report in picked.values()])
    rows = []
    for row in raw:
        run_id, position, report = picked[id(row)]
        detectors = report.get("detectors")
        known = detectors.get("known_malicious") if isinstance(detectors, dict) else None
        rows.append({**_result(row, report), "before": row["before_version"],
                     "after": row["after_version"], "run_id": run_id, "position": position,
                     "model_id": report.get("model_id"), "threshold": report.get("threshold"),
                     "list_as_of": known.get("list_as_of") if isinstance(known, dict) else None,
                     })  # fmt: skip
    full = shown[-1] if shown and shown[-1]["targets"] is None else None
    return {"checks": shown, "rows": rows, "covered": set(owners), "full": full,
            "summary": _summary(raw, False) if raw else None}  # fmt: skip


def _selected(params, shown: list[dict]) -> dict | None:
    """The update candidate a view opens beside its list: one of shown, the candidate rows the
    view lists (_candidates rows, in the view's order). It is the row whose run and position the
    item query names, written <run id>.<position> as in the row's link to its report; else the
    first row shown, None when the view shows none.

    The query is only compared as text with the keys of the rows shown: it is never read as a
    number and nothing is looked up by it. So an item that is repeated, malformed, of a check
    of other files or of another project, or of a row the view's filter leaves out is the same
    as no item."""
    given = params.getlist("item")
    first = shown[0] if shown else None
    if len(given) != 1:
        return first
    return next((row for row in shown if f"{row['run_id']}.{row['position']}" == given[0]), first)


def _score_chart(entries: list[dict]) -> dict | None:
    """The history view's chart of the peak ML score of each run (history.list_run_scores
    entries, newest first), drawn on a 440 by 160 box: runs from the oldest on the left (x 44 to
    420), scores from 0 at y 125 to 1 at y 15. None for fewer than two runs: the table is enough.

    points (oldest first): x, y (None for a run without a score), id, score, threshold (each
    None unless a number from 0 to 1), label (the score as the score filter words it, against
    that run's threshold) and over (at or over that threshold). segments: the polyline points
    of each unbroken stretch of scored runs. threshold: the y of the one threshold every run
    shares, else None and ticks: the x and y of each run's own. inline: whether the values of
    the points over their threshold fit beside them (else the page lists them under the chart).
    summary: the chart said in words, for its aria-label, from the stored scores."""
    if len(entries) < 2:
        return None

    def number(value: object) -> float | None:
        if isinstance(value, bool) or not isinstance(value, int | float) or not 0 <= value <= 1:
            return None
        return value

    def spot(value: float) -> float | int:
        value = round(value, 2)
        return int(value) if value == int(value) else value

    runs = entries[::-1]
    step = (420 - 44) / (len(runs) - 1)
    points, segments, line = [], [], []
    for index, run in enumerate(runs):
        score, threshold = number(run["peak_score"]), number(run["threshold"])
        x = spot(44 + index * step)
        y = None if score is None else spot(125 - score * 110)
        points.append({
            "x": x, "y": y, "id": run["id"], "score": score, "threshold": threshold,
            "label": "점수 없음" if score is None else score_text(score, run["threshold"]),
            "over": score is not None and threshold is not None and score >= threshold,
        })  # fmt: skip
        if y is None:
            if line:
                segments.append(" ".join(line))
            line = []
        else:
            line.append(f"{x},{y}")
    if line:
        segments.append(" ".join(line))
    shared = {point["threshold"] for point in points}
    threshold = next(iter(shared)) if len(shared) == 1 else None
    ticks = [] if threshold is not None else [
        {"x": point["x"], "y": spot(125 - point["threshold"] * 110)}
        for point in points if point["threshold"] is not None
    ]  # fmt: skip
    # A value is drawn centred over its point in 11px mono, about 6.7 units a character.
    labelled = [point for point in points if point["over"]]
    inline = all(len(point["label"]) * 6.7 + 6 <= step for point in labelled)
    scored = [point for point in points if point["score"] is not None]
    compared = [point for point in scored if point["threshold"] is not None]
    summary = f"최근 {len(points)}회 실행의 최고 ML 위험 점수"
    if scored:
        top = max(scored, key=lambda point: point["score"])
        summary += f", 가장 높은 값은 실행 #{top['id']}의 {top['label']}"
    if compared:
        summary += f", 판정 기준 이상 {len(labelled)}회"
    if len(compared) < len(scored):
        summary += f", 기준을 비교할 수 없는 실행 {len(scored) - len(compared)}회"
    if len(scored) < len(points):
        summary += f", 점수 없는 실행 {len(points) - len(scored)}회"
    return {"width": 440, "height": 160, "points": points, "segments": segments,
            "threshold": None if threshold is None else spot(125 - threshold * 110),
            "ticks": ticks, "inline": inline, "summary": summary + "."}  # fmt: skip


def _grouped(rows: list[dict]) -> list[dict]:
    """The updates view's candidates (_update_state rows) in groups, GROUPS' order, the empty ones
    left out: {key, cell (None for removals), label, rows (in the given order)}. A removal that
    could be applied is a group of its own; one that is refused or to confirm stays in that
    group, as what it needs is not told by its being a removal."""

    def key(row: dict) -> str:
        decided = row["decision"]["key"]
        return "removed" if decided == "free" and row["status"] == "removed" else decided

    return [
        {"key": name, "cell": DECISIONS[name][0] if name in DECISIONS else None, "label": label,
         "rows": [row for row in rows if key(row) == name]}
        for name, label in GROUPS
        if any(key(row) == name for row in rows)
    ]  # fmt: skip


def _filters(params) -> tuple[str, str, str] | None:
    """What narrows the packages view's list, from its query: (the name searched for, the kind
    of dependency, the tab: one of SHOWS). The three apply together. None for a query the view
    refuses: a value given twice, a name that is too long or not printable, a kind that is not
    one of the three, or a tab that is not one of SHOWS. The candidates-only filter of before
    (only) is no query of the view any more and changes nothing."""
    query, scope = params.get("q", "").strip(), params.get("scope", "all")
    show = params.getlist("show")
    if (
        len(params.getlist("q")) > 1
        or len(params.getlist("scope")) > 1
        or len(query) > MAX_NAME_LENGTH
        or not query.isprintable()
        or scope not in ("all", "direct", "nested")
        or len(show) > 1
        or (show and show[0] not in SHOWS)
    ):
        return None
    return query, scope, show[0] if show else "all"


def _kind(row: dict) -> str:
    """The tab (SHOWS) of a packages row: it has a current candidate, a current check covered it
    and found none, or no current check covered it."""
    if row["candidate"] is not None:
        return "candidates"
    return "none" if row["checked"] else "unchecked"


def _listed(dependencies: list[dict], query: str, scope: str) -> list[dict]:
    """The lockfile entries the packages view lists under a search and a kind (_filters), in
    the lockfile's order: those of the kind whose name holds the name searched for, whatever
    its case."""
    needle = query.casefold()
    return [
        row
        for row in dependencies
        if (scope == "all" or row["direct"] == (scope == "direct"))
        and (not needle or needle in _clean(row["name"] or "").casefold())
    ]


def _back(form: dict) -> list[tuple[str, str]] | None:
    """The query of the packages view that a check was sent from, as the pairs which that
    view's own links write: the form's back field, read as the view reads its address
    (_filters), with the candidate it had open (item). None without the field: the check was
    not sent from that view.

    The redirect after the check is always an address of that view, built from these pairs and
    never from the field's text: a field the view would refuse is the view without a filter."""
    given = form.get("back")
    if given is None:
        return None
    params = QueryParams(given[0] if len(given) == 1 else "")
    query, scope, show = _filters(params) or ("", "all", "all")
    pairs = []
    if query:
        pairs.append(("q", query))
    if scope != "all":
        pairs.append(("scope", scope))
    if show != "all":
        pairs.append(("show", show))
    items = params.getlist("item")
    if len(items) == 1 and len(items[0]) <= MAX_ITEM:
        pairs.append(("item", items[0]))
    return pairs


def _landing(project: dict, back: list[tuple[str, str]], run_id: int) -> str:
    """The query and the fragment of the packages view's address that a recorded check sent
    from that view comes back to: back (_back) with the run as checked, at the candidate the
    view opens or at the line that says there is none to open.

    The view opens the candidate its address names (_selected). So the first candidate this
    run returned among the rows that view lists (_listed) becomes the item, at #picked, the
    link of the open candidate. When it returned none there, the candidate that was open stays
    the item and the address goes to #check-status, the line that says what the check found,
    never to #picked: that is then the candidate of an older check. The browser follows the
    fragment itself, so the place is the same with the script and without it, and the address
    still names what is open once the run is taken off it.

    The candidate is looked for under the search and the kind alone, whatever the tab, and when
    there is one the tab is dropped: a check sent from the tab of unchecked rows has just made
    them checked. When there is none the tab stays (the view lists everything when that tab is
    left empty)."""
    kept = dict(back)
    dependencies, _ = _dependencies(project["path"])
    returned = {
        row["location"]: row for row in _update_state(project)["rows"] if row["run_id"] == run_id
    }
    listed = _listed(dependencies, kept.get("q", ""), kept.get("scope", "all"))
    first = next((returned[row["location"]] for row in listed if row["location"] in returned), None)
    if first is not None:
        kept.pop("show", None)
        kept["item"] = f"{first['run_id']}.{first['position']}"
    kept["checked"] = run_id
    return urlencode(kept) + ("#check-status" if first is None else "#picked")


def _returned(params, state: dict, shown: list[dict], selected: dict | None) -> dict | None:
    """What the packages view says of the check that sent the browser to it (the redirect of
    check_update names its run in the checked query): {id, full (it checked everything), count
    (how many current candidates it found), first (the first of them among shown, the
    candidate rows the view lists; None when the view's filters leave none)}.

    None unless checked is given once and is the run of one of the project's current checks
    (state["checks"]). It is only compared as text with those runs: never read as a number,
    and nothing is looked up by it. So the run of other files or of another project, a
    repeated or malformed value and no value at all are all the same.

    None too when first is not selected, the candidate the view opens: the address names
    another one, which _landing never writes, and the view says nothing of a check whose
    first candidate is not the one it shows."""
    given = params.getlist("checked")
    check = next((c for c in state["checks"] if [str(c["id"])] == given), None)
    if check is None:
        return None
    first = next((row for row in shown if row["run_id"] == check["id"]), None)
    if first is not None and first is not selected:
        return None
    return {
        "id": check["id"], "full": check["targets"] is None,
        "count": sum(row["run_id"] == check["id"] for row in state["rows"]),
        "first": first,
    }  # fmt: skip


def _dependencies(path: str) -> tuple[list[dict], str | None]:
    """The lockfile's dependencies, or a fixed message (no error text, which can hold paths)."""
    folder = Path(path)
    if not _found(path):
        return [], "프로젝트 폴더를 찾을 수 없습니다."
    try:
        if _refused(path, "package-lock.json"):
            return [], "package-lock.json이 일반 파일이 아닙니다."
        lock = mcp._unlinked(folder / "package-lock.json", "package-lock.json")
        if lock is None:
            return [], "package-lock.json이 없습니다."
        if not stat.S_ISREG(lock.stat().st_mode):
            return [], "package-lock.json이 일반 파일이 아닙니다."
        return service.list_dependencies(folder, declared=True), None
    except (GuardError, OSError, ValueError, RecursionError):
        return [], "package-lock.json을 읽을 수 없습니다(지원하지 않는 형식이거나 손상됨)."


def _declared_as(row: dict) -> str | None:
    """The name the root declares a direct dependency under when it is not the package's own
    name (an alias): the location says it, nothing is read out of the dependency spec."""
    name = row["location"].removeprefix("node_modules/")
    return name if row["direct"] and name != row["name"] else None


def _preview_targets(path: str) -> set[str]:
    """Peer-only entries in the lockfile cannot be targeted by npm update."""
    try:
        if _refused(path, "package.json"):
            return set()
        manifest = mcp._unlinked(Path(path) / "package.json", "package.json")
        if manifest is None or not stat.S_ISREG(manifest.lstat().st_mode):
            return set()
        package, _ = read_json(manifest)
    except (GuardError, OSError, ValueError, RecursionError):
        return set()
    return {
        name
        for field in DEPENDENCY_FIELDS
        if isinstance(package.get(field), dict)
        for name in package[field]
        if len(name) <= MAX_NAME_LENGTH and UPDATE_NAME.fullmatch(name)
    }


def _run_row(run: dict) -> dict:
    status = run["status"]
    return {
        "id": run["id"],
        "kind": _text_label(KIND_LABELS, run["kind"]),
        "preview": run["kind"] == "update_preview",
        "created_at": run["created_at"],
        "status": "-" if status is None else _text_label(OVERALL_LABELS, status),
        "exit_code": run["exit_code"],
        "model_id": run["model_id"],
        "counts": run["counts"],
    }


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _run_preview(project: Path, names: list[str], options: dict) -> tuple | str:
    """(result, new package.json, new lockfile, run id or None) of service.preview_files, recorded
    as the CLI records an update preview; or the message of the error page. A GuardError's own
    message is shown (it says what is missing, e.g. Node.js or the analyzer); other errors are a
    fixed message. Runs in a worker thread."""
    try:
        result, new_package, new_lock = service.preview_files(project, names, **options)
    except GuardError as exc:
        return str(exc)
    except (OSError, ValueError, RecursionError):
        return PREVIEW_FAILED
    try:
        run_id = history.record("update_preview", project, result["report"], result["preview"])
    except Exception:  # the preview stays usable; the page says it was not recorded
        run_id = None
    return result, new_package, new_lock, run_id


def _run_scan(project: Path, options: dict) -> tuple | str:
    """(report, run id or None) of service.scan_project with extraction against Git HEAD,
    recorded as depbee scan records it without base options; or the error page's message
    (a GuardError's own, else fixed). Runs in a worker thread. In a container Git is handed the
    project's own Git folder (mounted.repository) and looks for no other."""
    try:
        chosen = {} if mounted.root() is None else {"git_dir": mounted.repository(project)}
        report = service.scan_project(project, None, base_ref=None, extract=True, **options,
                                      **chosen)  # fmt: skip
    except GuardError as exc:
        return str(exc)
    except (OSError, ValueError, RecursionError):
        return SCAN_FAILED
    try:
        run_id = history.record("scan", project, report, None, base_ref=None, base_lock=False)
    except Exception:  # the report is still shown; the page says it was not recorded
        run_id = None
    return report, run_id


def _run_apply(project: Path, kept: dict, mode: str, confirmed: bool) -> tuple | str:
    """(apply document, recorded) of service.apply_preview on the registered path, its apply
    added to the preview's run when that run was recorded; or the error page's message."""
    try:
        applied = service.apply_preview(project, kept["result"], kept["new_package"],
                                        kept["new_lock"], mode=mode, confirm=confirmed)  # fmt: skip
    except (GuardError, OSError, ValueError, RecursionError):
        return APPLY_FAILED
    if kept["run_id"] is None:
        return applied, False
    try:
        recorded = history.record_apply(kept["run_id"], kept["result"]["preview"], applied)
    except Exception:  # the files changed anyway: the result page still shows what happened
        recorded = None
    return applied, recorded is not None


def _report(report: dict) -> dict:
    """The context of report.html: the report as the text output shows it. Each result keeps
    its position in the stored report, the anchor a candidate row links to. The band at its top:
    the overall result (its words and mark) and how many results there are of each status."""
    package_input = report.get("input_kind") == "package"
    position = {id(row): index for index, row in enumerate(report["results"])}
    found = Counter(row["status"] for row in report["results"])
    return {
        "overall_label": _text_label(OVERALL_LABELS, report["status"]),
        "overall_cell": TAB_STATES.get(report["status"], ("none",))[0],
        "exit_code": _clean(report["exit_code"]),
        "counts": {"all": len(report["results"]), "risk": found["flagged"],
                   "hold": found["incomplete"], "pass": found["not_flagged"],
                   "removed": found["removed"]},
        "notices": _notices(report),
        "model_id": report.get("model_id"), "threshold": report.get("threshold"),
        "setup": _detector_setup(report, _clean), "package_input": package_input,
        "results": [{**_result(row, report), "position": position[id(row)]}
                    for row in _ordered(report["results"])],
    }  # fmt: skip


def _apply_view(
    applied: dict, confirmed: str, retry: str | None = None, threshold: object = None
) -> dict:
    """An apply document as cli._apply_lines shows it, with the dashboard's wording. threshold:
    the threshold of the report it was decided from."""
    return {
        "outcome": _text_label(OUTCOME_LABELS, applied["outcome"]),
        "lines": _apply_lines(
            applied,
            _clean,
            _text_label,
            reasons=DASHBOARD_REASONS,
            confirmed=confirmed,
            retry=retry,
            threshold=threshold,
        ),  # fmt: skip
    }


def _apply_row(row: dict) -> dict:
    """One row of the project's apply history (history.list_applies), as stored."""
    return {
        "run_id": row["run_id"], "created_at": row["created_at"],
        "mode": _text_label(MODE_LABELS, row["mode"]),
        "outcome": _text_label(OUTCOME_LABELS, row["outcome"]),
        "reason": "-" if row["reason"] is None else _text_label(DASHBOARD_REASONS, row["reason"]),
        "confirmed": "예" if row["confirmed"] else "아니요",
        "backup": row["backup"], "npm_ci_exit_code": row["npm_ci_exit_code"],
    }  # fmt: skip


def npm_link(name: object) -> str | None:
    """The npm page of a valid package name: fixed prefix and the percent-encoded name. No link
    for anything else, and none from report, lockfile or registry URLs."""
    if not isinstance(name, str) or len(name) > MAX_NAME_LENGTH or not PACKAGE_NAME.fullmatch(name):
        return None
    return NPM_PAGE + quote(name, safe="@/")


def _decision(row: dict) -> dict:
    """Whether this one result could be applied as an update, by the update gate's own rule
    (service.update_gate, asked of the row alone; nothing is decided here): refused for a known
    malicious match whatever its score, to confirm for an ML hit, an unfinished item or a list
    that did not say not_hit, else free. {key, cell, label, why (one line)}. The gate of a real
    apply reads the whole preview, not one row."""
    refused, confirm = service.update_gate({"results": [row]})
    if refused:
        key, why = "refused", REFUSED_WHY
    elif confirm:
        causes = []
        for cause in confirm[0]["causes"]:
            text = _text_label(CAUSE_LABELS, cause)
            if cause == "incomplete" and row.get("reason"):
                text += f", 이유: {_text_label(REASON_LABELS, row['reason'])}"
            causes.append(text)
        key, why = "confirm", f"{CONFIRM_WHY}: {'; '.join(causes)}."
    elif row.get("status") == "removed":
        key, why = "free", REMOVED_WHY
    else:
        scored = (row.get("ml") or {}).get("status") == "not_hit"
        key, why = "free", FREE_WHY if scored else FREE_OTHER_WHY
    cell, label = DECISIONS[key]
    return {"key": key, "cell": cell, "label": label, "why": why}


def _signal(row: dict, key: str, labels: dict, report: dict) -> dict:
    """One detector slot of a result on its own (key: known_malicious or rules), as the report
    words it: {cell, status, lines (its matches or checks), note (the display-only line on how
    the rules and the ML path agree)}. A slot the report does not have is said to be unknown or
    unconnected and never not_hit (cli._unchecked). The mark is a risk for a hit, a hold for a
    failure and hollow for what did not run; a slot that ran and found nothing has none."""
    slot = row.get(key)
    if not slot:
        missing = NOT_CHECKED if _unchecked(row, key, report) else NOT_CONFIGURED
        return {"cell": "none", "status": missing, "lines": [], "note": None}
    # The slot alone, so that cli._detector_lines words its matches or checks and nothing else.
    alone = {"known_malicious": None, "rules": None, key: slot}
    if key == "rules" and "rule_ml_agreement" in row:
        alone["rule_ml_agreement"] = row["rule_ml_agreement"]
    found = _detector_lines(alone, _clean, _text_label, {})
    return {
        "cell": {"hit": "risk", "failed": "hold", "not_hit": None}.get(slot.get("status"), "none"),
        "status": _slot(slot, labels, _clean, _text_label),
        "lines": found[0][1] if found else [],
        "note": found[1][0] if len(found) > 1 else None,
    }


def _gauge(score: object, threshold: object) -> dict | None:
    """The ML tile's gauge in the inspector, drawn from 0 to 100: the score's bar (width), the
    threshold's place (tick, None for one that is not a number from 0 to 1) and whether the score
    is at or over it (over). None for a score that is not a number from 0 to 1: the tile then
    shows the score's words alone."""

    def place(value: object) -> float | int | None:
        if isinstance(value, bool) or not isinstance(value, int | float) or not 0 <= value <= 1:
            return None
        spot = round(value * 100, 2)
        return int(spot) if spot == int(spot) else spot

    width = place(score)
    if width is None:
        return None
    tick = place(threshold)
    return {"width": width, "tick": tick, "over": tick is not None and score >= threshold}


def _result(row: dict, report: dict) -> dict:
    """One result as the text output shows it; the facts and the model's explanation apart.
    score_raw: the stored score as the report's JSON writes it, None without one. decision:
    whether it could be applied (_decision); known and rules: its two detector slots, each on
    its own (_signal)."""
    explanation = row.get("explanation") or []
    scale = max((abs(item["contribution"]) for item in explanation), default=0) or 1
    alternative = _alternative(row)
    return {
        "status": row["status"],
        "label": _text_label(STATUS_LABELS, row["status"]),
        "cell": CELLS.get(row["status"], "none"),
        "decision": _decision(row),
        "known": _signal(row, "known_malicious", KNOWN_STATUS_LABELS, report),
        "rules": _signal(row, "rules", RULE_STATUS_LABELS, report),
        "package": row["package"],
        "version": row["after_version"] or row["before_version"],
        "before": row.get("before_version"),
        "after": row.get("after_version"),
        "location": row["location"],
        "npm": npm_link(row["package"]),
        "score": _ml_score(row, _text_label, report),
        "score_raw": None if row.get("score") is None else repr(row["score"]),
        "gauge": _gauge(row.get("score"), report.get("threshold")),
        "compared": row.get("compared_version"),
        "reason": _text_label(REASON_LABELS, row["reason"]) if row.get("reason") else None,
        "alternative": None if alternative is None else (alternative[0], alternative[1]),
        "detail": row.get("detail"),
        "detectors": _detector_lines(row, _clean, _text_label, report),
        "known_hit": (row.get("known_malicious") or {}).get("status") == "hit",
        "evidence": row.get("evidence") or [],
        "explanation": [
            {
                "risk": item["contribution"] > 0,
                "feature": _feature_label(item["feature"]),
                "value": _feature_value(item["feature"], item["value"]),
                "contribution": f"{item['contribution']:+.2f}",
                "width": round(100 * abs(item["contribution"]) / scale),
            }
            for item in explanation
        ],
        "rest": _rest_line(row, report.get("threshold")) if row.get("explanation_rest") else None,
    }


def _models() -> list[dict]:
    """Each model seen in stored runs, from its latest run's report, newest first."""
    latest: dict[tuple, dict] = {}
    for project in history.list_projects():
        for run in history.list_runs(project["id"]):
            key = (run["model_id"], run["model_sha256"])
            seen = latest.setdefault(key, {"run": run["id"], "runs": 0})
            seen["runs"] += 1
            seen["run"] = max(seen["run"], run["id"])
    models = []
    for seen in sorted(latest.values(), key=lambda s: -s["run"]):
        stored = history.get_run(seen["run"])
        report = stored["report"]
        provenance = report.get("provenance") or {}
        extractor = provenance.get("feature_extractor") or {}
        models.append({
            "model_id": report.get("model_id"),
            "threshold": report.get("threshold"),
            "model_sha256": (provenance.get("model") or {}).get("model_sha256"),
            "manifest_sha256": (provenance.get("model") or {}).get("manifest_sha256"),
            "analyzer_version": report.get("analyzer_version"),
            "extractor": [f"{k}: {extractor[k]}" for k in ("commit", "files_sha256", "python")
                          if extractor.get(k) is not None],
            "provenance": "provenance" in report,
            "runs": seen["runs"],
            "last": stored["created_at"],
        })  # fmt: skip
    return models


def serve(
    port: int, *, model_dir: Path | None = None, cache_dir: Path | None = None,
    no_cache: bool = False, known_malicious_dir: Path | None = None, background=None,
) -> None:  # fmt: skip
    """Bind 127.0.0.1:port (0 picks a free one), print the session address once and serve until
    Ctrl+C, which ends with one line and no traceback. The session is in the address line only:
    no access log, and errors never quote requests.

    background (lifecycle.Instance): serve as the background instance instead. The address is
    not printed but published in the instance's state file once the port is bound, and the
    instance's control endpoint, in front of the app, can end the server as Ctrl+C does.

    Either way the server is asked to end by its should_exit flag, which uvicorn's handler of
    Ctrl+C sets as the control endpoint does. It then finishes the requests it has, and the app
    is given that flag (build_app's stopping) so that an open folder dialog is not one of them
    for long: it is closed, and its request registers nothing.

    In a container (dashboard.mounted) the socket is bound on every interface of the container,
    which is where Docker sends a published port, and port 0 means mounted.PORT: the container
    cannot see which host port it was published under, so that must be the same number. The
    address printed, and the only Host and Origin the app takes, stay those of 127.0.0.1 at
    that port: the host's side of a port published to 127.0.0.1 alone."""
    if not 0 <= port <= 65535:
        raise GuardError("--port must be between 0 and 65535")
    # Only when given, so that build_app is called as before without an index.
    known = {"known_malicious_dir": known_malicious_dir} if known_malicious_dir else {}
    contained = mounted.root() is not None
    bind = mounted.BIND if contained else HOST
    sock = socket.create_server((bind, (port or mounted.PORT) if contained else port))
    try:
        actual = sock.getsockname()[1]
        session = secrets.token_urlsafe(32)
        app = build_app(actual, session, lambda: server.should_exit, model_dir=model_dir,
                        cache_dir=cache_dir, no_cache=no_cache, **known)  # fmt: skip
        if background is not None:
            app = background.control(app, lambda: setattr(server, "should_exit", True))
        config = uvicorn.Config(
            app, host=bind, port=actual, access_log=False,
            server_header=False, proxy_headers=False, log_level="warning", lifespan="off",
            ws="none",
        )  # fmt: skip
        server = uvicorn.Server(config)
        # The session's first page, whatever is registered: it reads the history when opened.
        url = f"http://{HOST}:{actual}/s/{session}/"
        if background is None:
            print(url, flush=True)
            print(CONTAINER_STARTED.format(port=actual) if contained else STARTED, flush=True)
        else:
            background.publish(url, actual)
        try:
            server.run(sockets=[sock])
        except KeyboardInterrupt:
            # After its graceful shutdown uvicorn re-raises the captured Ctrl+C (capture_signals).
            print(STOPPED, flush=True)
    finally:
        sock.close()
