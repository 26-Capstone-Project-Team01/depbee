"""The dashboard's web app (extra [web]): Starlette routes, Jinja2 pages and the uvicorn server.

Only depbee.dashboard.serve() imports this module. History goes through depbee.history (a new
connection per call), lockfile rows through service.list_dependencies(), package.json for
individual update buttons, and every verdict,
label and line through the depbee.cli helpers the text output uses.
"""

import hmac
import importlib.resources
import secrets
import socket
import sqlite3
import stat
import threading
from collections import OrderedDict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, quote

import jinja2
import uvicorn
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from .. import history, mcp, service
from ..cli import (
    APPLY_REASON_LABELS,
    MODE_LABELS,
    OUTCOME_LABELS,
    OVERALL_LABELS,
    REASON_LABELS,
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
    _summary,
    _text_label,
)
from ..contracts import GuardError, read_json
from ..inputs.npm import MAX_NAME_LENGTH, PACKAGE_NAME
from ..inputs.npm_cli import DEPENDENCY_FIELDS, UPDATE_NAME

HOST = "127.0.0.1"
MAX_BODY = 16 * 1024  # bytes of a request body (Starlette answers 413 above it)
MAX_FIELDS = 4  # form fields; the largest form (apply) has three
MAX_PATH = 1024  # characters of a path to register
MAX_TARGETS = 1024  # characters of the update target names field
KEPT_PREVIEWS = 10  # update previews kept in memory; the oldest is dropped first
RECENT_RUNS = 10  # runs per project in the list's trend table
MAX_ID = 2**63 - 1  # SQLite's largest integer; a larger id in a URL is simply not found
NPM_PAGE = "https://www.npmjs.com/package/"
CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'"
)
# no-referrer would make a form POST's Origin "null" (Fetch 3.2), which the POST check refuses.
SECURITY_HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"same-origin"),
    (b"cache-control", b"no-store"),
]
KIND_LABELS = {"scan": "검사(scan)", "update_preview": "업데이트 미리보기"}
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
}
SESSION_REFUSED = (
    "세션 주소가 맞지 않습니다. depbee dashboard가 이번 실행에서 출력한 주소로 여세요."
)
FORM_REFUSED = "폼의 세션 값이 맞지 않습니다. 화면을 새로 열고 다시 시도하세요."
BUSY = "다른 검사, 업데이트 확인이나 반영이 실행 중입니다. 끝난 뒤 다시 시도하세요."
PREVIEW_GONE = (
    "이 업데이트 미리보기가 없습니다(이미 반영을 시도했거나, 오래되어 지워졌거나, 대시보드를 다시 "
    "시작함). 프로젝트 화면에서 업데이트 확인을 다시 실행하세요."
)
PROJECT_MISSING = "등록한 프로젝트 폴더를 찾을 수 없습니다."
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


ENV = jinja2.Environment(
    loader=jinja2.PackageLoader("depbee.dashboard", "templates"),
    autoescape=True,  # set here, not left to the file extension
    finalize=_finalize,
    undefined=jinja2.StrictUndefined,
)


def _text(status: int, text: str) -> Response:
    return Response(text, status, media_type="text/plain; charset=utf-8")


class Guard:
    """Wraps the whole app. Every request: exactly one Host header equal to 127.0.0.1:<port>
    (any case), else 400; a path under /s/<session>/ with this run's session (compared with
    hmac.compare_digest), else 403; a request other than GET or HEAD also needs Origin exactly
    http://127.0.0.1:<port>, else 403 (the form handlers check the form's session field). The
    app sees the path without the /s/<session> prefix. Cookies are neither read nor set. Every
    response, errors included, gets SECURITY_HEADERS."""

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
        if scope["method"] not in ("GET", "HEAD") and [v for n, v in headers if n == b"origin"] != [
            self.origin
        ]:
            return (403, "다른 출처의 요청은 받지 않습니다."), ""
        return None, "/" + parts[3]


def build_app(
    port: int, session: str, *, model_dir: Path | None = None, cache_dir: Path | None = None,
    no_cache: bool = False, known_malicious_dir: Path | None = None,
):  # fmt: skip
    """The guarded ASGI app for 127.0.0.1:port; session is the value in the address printed at
    start (/s/<session>/), which every link, redirect and form carries. model_dir, cache_dir,
    no_cache, known_malicious_dir: for update previews, as in depbee update."""
    base = f"/s/{session}"
    scan_options = {"model_dir": model_dir, "cache_dir": cache_dir, "no_cache": no_cache}
    if known_malicious_dir is not None:  # else the options stay as before (the service's default)
        scan_options["known_malicious_dir"] = known_malicious_dir

    def page(request: Request, name: str, status: int = 200, **context) -> Response:
        html = ENV.get_template(name).render(
            safety_note=SAFETY_NOTE, base=base, session=session, **context
        )
        # _finalize has escaped lone surrogates; backslashreplace keeps any left from a 500.
        body = html.encode("utf-8", "backslashreplace")
        return Response(body, status, media_type="text/html; charset=utf-8")

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

    def projects(request: Request, status: int = 200, error: str | None = None) -> Response:
        rows = []
        for project in history.list_projects():
            runs = [_run_row(run) for run in history.list_runs(project["id"], RECENT_RUNS)]
            rows.append({**project, "name": Path(project["path"]).name or project["path"],
                         "found": _found(project["path"]), "runs": runs})  # fmt: skip
        return page(request, "projects.html", status, projects=rows, error=error)

    async def register(request: Request) -> Response:
        form = await read_form(request)
        if isinstance(form, Response):
            return form
        paths = form.get("path", [])
        if len(paths) != 1:
            return _text(400, "경로 하나를 입력하세요.")
        problem = _registration_problem(paths[0])
        if problem:  # the input is not echoed
            return projects(request, 400, REGISTER_ERRORS[problem])
        project_id = history.register_project(Path(paths[0]))
        return RedirectResponse(f"{base}/projects/{project_id}", 303)

    def project(request: Request) -> Response:
        found = _project(request.path_params["project_id"])
        if found is None:
            return _text(404, "등록된 프로젝트가 아닙니다.")
        params = request.query_params
        query = params.get("q", "").strip()
        scope = params.get("scope", "all")
        if (
            len(params.getlist("q")) > 1
            or len(params.getlist("scope")) > 1
            or len(query) > MAX_NAME_LENGTH
            or not query.isprintable()
            or scope not in ("all", "direct", "nested")
        ):
            return _text(400, "패키지 이름이나 의존성 종류를 확인하세요.")
        dependencies, problem = _dependencies(found["path"])
        direct_count = sum(row["direct"] for row in dependencies)
        needle = query.casefold()
        rows = [
            row
            for row in dependencies
            if (scope == "all" or row["direct"] == (scope == "direct"))
            and (not needle or needle in _clean(row["name"] or "").casefold())
        ]
        targets = _preview_targets(found["path"]) if any(row["direct"] for row in rows) else set()
        runs = [_run_row(run) for run in history.list_runs(found["id"])]
        applies = [_apply_row(row) for row in history.list_applies(found["id"])]
        return page(request, "project.html", project=found, found=_found(found["path"]),
                    project_name=Path(found["path"]).name or found["path"], rows=rows,
                    direct_count=direct_count, nested_count=len(dependencies) - direct_count,
                    query=query, scope=scope, targets=targets, max_query=MAX_NAME_LENGTH,
                    problem=problem, runs=runs, applies=applies, max_targets=MAX_TARGETS)  # fmt: skip

    def run(request: Request) -> Response:
        run_id = request.path_params["run_id"]
        stored = history.get_run(run_id) if run_id <= MAX_ID else None
        if stored is None:
            return _text(404, "저장된 실행이 아닙니다.")
        preview, applied = stored["preview"], stored["apply"]
        return page(
            request, "run.html", run=_run_row(stored), project=_project(stored["project_id"]),
            preview=None if preview is None else _preview_lines(preview, _clean),
            apply=None if applied is None else _apply_view(applied["apply"], CONFIRMED_STORED),
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
        return page(
            request, "preview.html", status, preview_id=preview_id, error=error,
            project=_project(kept["project_id"]), created_at=kept["created_at"],
            run_id=kept["run_id"], not_recorded=PREVIEW_NOT_RECORDED if kept["run_id"] is None
            else None, lines=_preview_lines(result["preview"], _clean),
            blocked=[_apply_item(item, _clean, _text_label) for item in blocked],
            blocked_reason=APPLY_REASON_LABELS["known_malicious_hit"],
            required=[_apply_item(item, _clean, _text_label) for item in required],
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
            return page(request, "error.html", 400, project=found, message=TARGETS_TOO_LONG)
        if not _found(found["path"]):  # the registered path, checked as at registration
            return page(request, "error.html", 400, project=found, message=PROJECT_MISSING)
        if not busy.acquire(blocking=False):
            return _text(409, BUSY)
        try:
            outcome = await run_in_threadpool(
                _run_preview, Path(found["path"]), targets[0].split(), scan_options
            )
        finally:
            busy.release()
        if isinstance(outcome, str):
            return page(request, "error.html", 400, project=found, message=outcome)
        result, new_package, new_lock, run_id = outcome
        preview_id = secrets.token_urlsafe(16)
        previews[preview_id] = {
            "project_id": found["id"], "run_id": run_id, "result": result,
            "new_package": new_package, "new_lock": new_lock, "created_at": _now(),
        }  # fmt: skip
        while len(previews) > KEPT_PREVIEWS:
            previews.popitem(last=False)
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
            return page(request, "error.html", 400, project=found, message=PROJECT_MISSING,
                        title=SCAN_TITLE)  # fmt: skip
        if not busy.acquire(blocking=False):
            return _text(409, BUSY)
        try:
            outcome = await run_in_threadpool(_run_scan, Path(found["path"]), scan_options)
        finally:
            busy.release()
        if isinstance(outcome, str):
            return page(request, "error.html", 400, project=found, message=outcome,
                        title=SCAN_TITLE)  # fmt: skip
        report, run_id = outcome
        if run_id is None:  # the result is not hidden when it could not be recorded
            return page(request, "scanned.html", project=found, not_recorded=SCAN_NOT_RECORDED,
                        **_report(report))  # fmt: skip
        return RedirectResponse(f"{base}/runs/{run_id}", 303)

    def show_preview(request: Request) -> Response:
        preview_id = request.path_params["preview_id"]
        kept = previews.get(preview_id)
        if kept is None:
            return _text(404, PREVIEW_GONE)
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
            return _text(404, PREVIEW_GONE)
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
            return page(request, "error.html", 400, project=found, message=PROJECT_MISSING)
        if not busy.acquire(blocking=False):
            return _text(409, BUSY)
        try:
            kept = previews.pop(preview_id, None)
            if kept is None:
                return _text(404, PREVIEW_GONE)
            outcome = await run_in_threadpool(_run_apply, Path(found["path"]), kept, mode,
                                              confirmed)  # fmt: skip
        finally:
            busy.release()
        if isinstance(outcome, str):
            return page(request, "error.html", 500, project=found, message=outcome)
        applied, recorded = outcome
        return page(
            request, "applied.html", project=found, run_id=kept["run_id"] if recorded else None,
            not_recorded=None if recorded else (
                APPLY_NOT_RECORDED if kept["run_id"] is not None else PREVIEW_NOT_RECORDED),
            apply=_apply_view(applied, CONFIRMED_HERE, RETRY_HERE),
        )  # fmt: skip

    def model(request: Request) -> Response:
        return page(request, "model.html", models=_models(), limits=MODEL_LIMITS)

    def style(request: Request) -> Response:
        css = importlib.resources.files("depbee.dashboard").joinpath("static", "style.css")
        return Response(css.read_bytes(), media_type="text/css; charset=utf-8")

    def failed(request: Request, exc: Exception) -> Response:
        # No exception text: it can hold paths or package strings.
        return _text(500, "요청을 처리하지 못했습니다(이력 데이터베이스나 파일을 읽지 못함).")

    app = Starlette(
        routes=[
            Route("/", projects),
            Route("/projects", register, methods=["POST"]),
            Route("/projects/{project_id:int}", project),
            Route("/projects/{project_id:int}/previews", check_update, methods=["POST"]),
            Route("/projects/{project_id:int}/scans", scan, methods=["POST"]),
            Route("/previews/{preview_id}", show_preview),
            Route("/previews/{preview_id}/apply", apply, methods=["POST"]),
            Route("/runs/{run_id:int}", run),
            Route("/model", model),
            Route("/static/style.css", style),
        ],
        exception_handlers={Exception: failed},
        max_body_size=MAX_BODY,
    )
    app.router.redirect_slashes = False  # its redirect would drop the /s/<session> prefix
    return Guard(app, port, session)


def _found(path: str) -> bool:
    """The registered folder still exists, looked at as at registration (no share or device)."""
    try:
        real = mcp._unlinked(mcp._local_path(path, "project"), "project")
        return real is not None and stat.S_ISDIR(real.stat().st_mode)
    except (GuardError, OSError, ValueError):
        return False


def _registration_problem(text: str) -> str | None:
    """A REGISTER_ERRORS key, or None for an absolute local folder with a regular
    package-lock.json file. The MCP path checks: shares, device paths, reserved names and links
    to them are refused before anything behind them is touched."""
    if len(text) > MAX_PATH:
        return "long"
    try:
        path = mcp._local_path(text, "path")
    except GuardError:
        return "local"
    if not path.is_absolute():
        return "absolute"
    try:
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


def _project(project_id: int) -> dict | None:
    return next((p for p in history.list_projects() if p["id"] == project_id), None)


def _dependencies(path: str) -> tuple[list[dict], str | None]:
    """The lockfile's dependencies, or a fixed message (no error text, which can hold paths)."""
    folder = Path(path)
    if not _found(path):
        return [], "프로젝트 폴더를 찾을 수 없습니다."
    try:
        lock = mcp._unlinked(folder / "package-lock.json", "package-lock.json")
        if lock is None:
            return [], "package-lock.json이 없습니다."
        if not stat.S_ISREG(lock.stat().st_mode):
            return [], "package-lock.json이 일반 파일이 아닙니다."
        return service.list_dependencies(folder), None
    except (GuardError, OSError, ValueError, RecursionError):
        return [], "package-lock.json을 읽을 수 없습니다(지원하지 않는 형식이거나 손상됨)."


def _preview_targets(path: str) -> set[str]:
    """Peer-only entries in the lockfile cannot be targeted by npm update."""
    try:
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
    message is shown (it says what is missing, e.g. Node.js or .[extract]); other errors are a
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
    (a GuardError's own, else fixed). Runs in a worker thread."""
    try:
        report = service.scan_project(project, None, base_ref=None, extract=True, **options)
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
    """The context of report.html: the report as the text output shows it."""
    package_input = report.get("input_kind") == "package"
    return {
        "overall": f"{_text_label(OVERALL_LABELS, report['status'])}"
                   f" (종료 코드 {_clean(report['exit_code'])})",
        "summary": _summary(report["results"], package_input), "notices": _notices(report),
        "model_id": report.get("model_id"), "threshold": report.get("threshold"),
        "setup": _detector_setup(report, _clean), "package_input": package_input,
        "results": [_result(row, report) for row in _ordered(report["results"])],
    }  # fmt: skip


def _apply_view(applied: dict, confirmed: str, retry: str | None = None) -> dict:
    """An apply document as cli._apply_lines shows it, with the dashboard's wording."""
    return {
        "outcome": _text_label(OUTCOME_LABELS, applied["outcome"]),
        "lines": _apply_lines(
            applied,
            _clean,
            _text_label,
            reasons=DASHBOARD_REASONS,
            confirmed=confirmed,
            retry=retry,
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


def _result(row: dict, report: dict) -> dict:
    """One result as the text output shows it; the facts and the model's explanation apart."""
    explanation = row.get("explanation") or []
    scale = max((abs(item["contribution"]) for item in explanation), default=0) or 1
    alternative = _alternative(row)
    return {
        "status": row["status"],
        "label": _text_label(STATUS_LABELS, row["status"]),
        "package": row["package"],
        "version": row["after_version"] or row["before_version"],
        "location": row["location"],
        "npm": npm_link(row["package"]),
        "score": _ml_score(row, _text_label, report),
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
        "rest": _rest_line(row) if row.get("explanation_rest") else None,
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
    no_cache: bool = False, known_malicious_dir: Path | None = None,
) -> None:  # fmt: skip
    """Bind 127.0.0.1:port (0 picks a free one), print the session address once and serve until
    Ctrl+C, which ends with one line and no traceback. The session is in the address line only:
    no access log, and errors never quote requests."""
    if not 0 <= port <= 65535:
        raise GuardError("--port must be between 0 and 65535")
    # Only when given, so that build_app is called as before without an index.
    known = {"known_malicious_dir": known_malicious_dir} if known_malicious_dir else {}
    sock = socket.create_server((HOST, port))
    try:
        actual = sock.getsockname()[1]
        session = secrets.token_urlsafe(32)
        config = uvicorn.Config(
            build_app(actual, session, model_dir=model_dir, cache_dir=cache_dir,
                      no_cache=no_cache, **known), host=HOST, port=actual, access_log=False,
            server_header=False, proxy_headers=False, log_level="warning", lifespan="off",
            ws="none",
        )  # fmt: skip
        try:
            projects = history.list_projects()
        except (history.HistoryError, OSError, sqlite3.Error, RuntimeError):
            projects = []  # The existing dashboard error page handles history read failures.
        target = f"projects/{projects[0]['id']}" if len(projects) == 1 else ""
        print(f"http://{HOST}:{actual}/s/{session}/{target}", flush=True)
        print("이 주소를 브라우저에서 여세요. 종료하려면 Ctrl+C를 누르세요.", flush=True)
        try:
            uvicorn.Server(config).run(sockets=[sock])
        except KeyboardInterrupt:
            # After its graceful shutdown uvicorn re-raises the captured Ctrl+C (capture_signals).
            print(STOPPED, flush=True)
    finally:
        sock.close()
