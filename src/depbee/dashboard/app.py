"""The dashboard's web app (extra [web]): Starlette routes, Jinja2 pages and the uvicorn server.

Only depbee.dashboard.serve() imports this module. History goes through depbee.history (a new
connection per call), dependencies through service.list_dependencies(), and every verdict,
label and line through the depbee.cli helpers the text output uses.
"""

import hmac
import importlib.resources
import secrets
import socket
import stat
from pathlib import Path
from urllib.parse import parse_qs, quote

import jinja2
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from .. import history, mcp, service
from ..cli import (
    OVERALL_LABELS,
    REASON_LABELS,
    SAFETY_NOTE,
    STATUS_LABELS,
    _alternative,
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
from ..contracts import GuardError
from ..inputs.npm import MAX_NAME_LENGTH, PACKAGE_NAME

HOST = "127.0.0.1"
MAX_BODY = 16 * 1024  # bytes of a request body (Starlette answers 413 above it)
MAX_FIELDS = 4  # form fields; the registration form has two
MAX_PATH = 1024  # characters of a path to register
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
SESSION_REFUSED = "세션 주소가 맞지 않습니다. depbee dashboard가 이번 실행에서 출력한 주소로 여세요."
FORM_REFUSED = "폼의 세션 값이 맞지 않습니다. 화면을 새로 열고 다시 시도하세요."


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
        if scope["method"] not in ("GET", "HEAD") and [
            v for n, v in headers if n == b"origin"
        ] != [self.origin]:
            return (403, "다른 출처의 요청은 받지 않습니다."), ""
        return None, "/" + parts[3]


def build_app(port: int, session: str):
    """The guarded ASGI app for 127.0.0.1:port; session is the value in the address printed at
    start (/s/<session>/), which every link, redirect and form carries."""
    base = f"/s/{session}"

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
            rows.append({**project, "found": _found(project["path"]), "runs": runs})
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
        dependencies, problem = _dependencies(found["path"])
        runs = [_run_row(run) for run in history.list_runs(found["id"])]
        return page(request, "project.html", project=found, found=_found(found["path"]),
                    dependencies=dependencies, problem=problem, runs=runs)  # fmt: skip

    def run(request: Request) -> Response:
        run_id = request.path_params["run_id"]
        stored = history.get_run(run_id) if run_id <= MAX_ID else None
        if stored is None:
            return _text(404, "저장된 실행이 아닙니다.")
        report, preview = stored["report"], stored["preview"]
        package_input = report.get("input_kind") == "package"
        return page(
            request, "run.html", run=_run_row(stored), project=_project(stored["project_id"]),
            overall=f"{_text_label(OVERALL_LABELS, report['status'])}"
                    f" (종료 코드 {_clean(report['exit_code'])})",
            summary=_summary(report["results"], package_input), notices=_notices(report),
            model_id=report.get("model_id"), threshold=report.get("threshold"),
            setup=_detector_setup(report, _clean), package_input=package_input,
            preview=None if preview is None else _preview_lines(preview, _clean),
            results=[_result(row, report) for row in _ordered(report["results"])],
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


def serve(port: int) -> None:
    """Bind 127.0.0.1:port (0 picks a free one), print the session address once and serve until
    Ctrl+C. The session is in that line only: no access log, and errors never quote requests."""
    if not 0 <= port <= 65535:
        raise GuardError("--port must be between 0 and 65535")
    sock = socket.create_server((HOST, port))
    try:
        actual = sock.getsockname()[1]
        session = secrets.token_urlsafe(32)
        config = uvicorn.Config(
            build_app(actual, session), host=HOST, port=actual, access_log=False,
            server_header=False, proxy_headers=False, log_level="warning", lifespan="off",
            ws="none",
        )  # fmt: skip
        print(f"http://{HOST}:{actual}/s/{session}/", flush=True)
        print("이 주소를 브라우저에서 여세요. 종료하려면 Ctrl+C를 누르세요.", flush=True)
        uvicorn.Server(config).run(sockets=[sock])
    finally:
        sock.close()
