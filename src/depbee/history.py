"""Local history of scan and update-preview reports for projects registered in the dashboard.

Standard library only. Reports are stored as given: verdicts, reasons and exit codes are never
recomputed, and nothing here detects anything. The CLI records through record(), which never
creates the database; only register_project() does. The dashboard (planned) uses the same API.
"""

import contextlib
import json
import os
import sqlite3
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from . import __version__

# PRAGMA user_version of a depbee history database; separate from contracts.SCHEMA_VERSION.
USER_VERSION = 1
TIMEOUT = 1.5  # seconds to wait for a lock; the CLI has already printed its report
KINDS = ("scan", "update_preview")
STATUSES = ("flagged", "not_flagged", "incomplete", "removed")
RESULT_COLUMNS = (
    "change_id", "location", "package", "before_version", "after_version", "status", "score",
    "known_malicious_status", "rules_status", "ml_status",
)  # fmt: skip
RUN_COLUMNS = (
    "id", "project_id", "kind", "created_at", "depbee_version", "base_ref", "base_lock",
    "status", "exit_code", "model_id", "model_sha256", *STATUSES,
)  # fmt: skip
SCHEMA = """
CREATE TABLE projects (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    path TEXT NOT NULL,
    registered_at TEXT NOT NULL
);
CREATE TABLE runs (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects (id),
    kind TEXT NOT NULL,
    created_at TEXT NOT NULL,
    depbee_version TEXT NOT NULL,
    base_ref TEXT,
    base_lock INTEGER,
    status TEXT,
    exit_code INTEGER,
    model_id TEXT,
    model_sha256 TEXT,
    flagged INTEGER NOT NULL,
    not_flagged INTEGER NOT NULL,
    incomplete INTEGER NOT NULL,
    removed INTEGER NOT NULL,
    report TEXT NOT NULL,
    preview TEXT
);
CREATE INDEX runs_by_project ON runs (project_id, id);
CREATE TABLE results (
    run_id INTEGER NOT NULL REFERENCES runs (id),
    position INTEGER NOT NULL,
    change_id TEXT,
    location TEXT,
    package TEXT,
    before_version TEXT,
    after_version TEXT,
    status TEXT,
    score REAL,
    known_malicious_status TEXT,
    rules_status TEXT,
    ml_status TEXT,
    PRIMARY KEY (run_id, position)
);
"""


class HistoryError(Exception):
    """The file is not a history database this depbee can write (newer or not depbee's)."""


def db_path() -> Path:
    """DEPBEE_HISTORY_DB (read on each call; empty means unset), else a file under the home.

    Path.home() raises RuntimeError if there is no home directory.
    """
    configured = os.environ.get("DEPBEE_HISTORY_DB")
    if configured:
        return Path(configured)
    return Path.home() / ".local" / "share" / "depbee" / "history.sqlite3"


def _text(value: object) -> object:
    """A string SQLite can store: a lone surrogate from a lockfile becomes \\udc80 text."""
    if isinstance(value, str):
        return value.encode("utf-8", "backslashreplace").decode("utf-8")
    return value


def _project(project: Path | str) -> tuple[str, str]:
    """(key, display path): the resolved absolute path, case-folded on Windows for the key."""
    path = str(Path(project).resolve())
    return _text(os.path.normcase(path)), _text(path)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False)


def _connect(path: Path, create: bool):
    """A closing() connection; without create the file must exist and is never created."""
    mode = "rwc" if create else "rw"
    uri = f"{path.resolve().as_uri()}?mode={mode}"
    connection = sqlite3.connect(uri, timeout=TIMEOUT, isolation_level=None, uri=True)
    return contextlib.closing(connection)


@contextlib.contextmanager
def _write(connection):
    """One BEGIN IMMEDIATE transaction (the same on Python 3.11 to 3.13)."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise


def _check(connection, create: bool = False) -> bool:
    """True if the database is ours at USER_VERSION; False if empty and create may set it up."""
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version > USER_VERSION:
        raise HistoryError(f"History database version {version} is newer than {USER_VERSION}")
    if version == USER_VERSION:
        return True
    tables = connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
    if version != 0 or tables or not create:
        raise HistoryError("Not a depbee history database")
    return False


def register_project(project: Path | str) -> int:
    """Register an existing project folder and return its id; creates the database if needed.

    Registering again keeps the first registration. Web input checks (UNC, device paths,
    reserved names, links) belong to the dashboard's boundary, not here.
    """
    if not Path(project).is_dir():
        raise ValueError("The project must be an existing directory")
    key, display = _project(project)
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(path, create=True) as connection, _write(connection):
        if not _check(connection, create=True):
            # Statement by statement: executescript() would commit outside this transaction.
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {USER_VERSION}")
        connection.execute(
            "INSERT OR IGNORE INTO projects (key, path, registered_at) VALUES (?, ?, ?)",
            (key, display, _now()),
        )
        return connection.execute("SELECT id FROM projects WHERE key = ?", (key,)).fetchone()[0]


def record(
    kind: str,
    project: Path | str,
    report: dict,
    preview: dict | None = None,
    *,
    base_ref: str | None = None,
    base_lock: bool | None = None,
) -> int | None:
    """Store one report for a registered project and return the run id.

    kind: "scan" or "update_preview" (then preview is the update preview). base_ref, base_lock:
    the scan's --base-ref value and whether --base-lock was given (None for update previews).
    Returns None without touching anything if there is no home directory, no database file or
    the project is not registered. Raises sqlite3.Error, HistoryError, OSError or ValueError if
    the database cannot be read or written; the caller decides how to report that.
    """
    if kind not in KINDS:
        raise ValueError(f"Unknown history kind: {kind}")
    try:
        path = db_path()
    except RuntimeError:  # no home directory: no history, as the feature cache
        return None
    if not path.exists():
        return None
    key, _ = _project(project)
    results = report["results"]
    counts = Counter(row.get("status") for row in results)
    model = (report.get("provenance") or {}).get("model") or {}
    run = (
        kind, _now(), __version__, _text(base_ref), base_lock, _text(report.get("status")),
        report.get("exit_code"), _text(report.get("model_id")), _text(model.get("model_sha256")),
        *(counts[status] for status in STATUSES), _json(report),
        None if preview is None else _json(preview),
    )  # fmt: skip
    # The first seven columns are result keys; the last three the detector slots' statuses.
    rows = [
        [row.get(name) for name in RESULT_COLUMNS[:7]]
        + [(row.get(slot) or {}).get("status") for slot in ("known_malicious", "rules", "ml")]
        for row in results
    ]
    with _connect(path, create=False) as connection:
        _check(connection)
        if connection.execute("SELECT 1 FROM projects WHERE key = ?", (key,)).fetchone() is None:
            return None
        with _write(connection):
            _check(connection)
            (project_id,) = connection.execute(
                "SELECT id FROM projects WHERE key = ?", (key,)
            ).fetchone()
            run_id = connection.execute(
                f"INSERT INTO runs (project_id, {', '.join(RUN_COLUMNS[2:])}, report, preview) "
                f"VALUES (?, {', '.join('?' * (len(RUN_COLUMNS) - 2))}, ?, ?)",
                (project_id, *run),
            ).lastrowid
            connection.executemany(
                f"INSERT INTO results (run_id, position, {', '.join(RESULT_COLUMNS)}) "
                f"VALUES (?, ?, {', '.join('?' * len(RESULT_COLUMNS))})",
                [
                    (run_id, position, *(_text(value) for value in row))
                    for position, row in enumerate(rows)
                ],
            )
        return run_id


def _read(query: str, parameters: tuple = ()) -> list[sqlite3.Row]:
    """Rows of a read-only query; none if there is no database (it is not created)."""
    path = db_path()
    if not path.exists():
        return []
    with _connect(path, create=False) as connection:
        _check(connection)
        connection.row_factory = sqlite3.Row
        return connection.execute(query, parameters).fetchall()


def list_projects() -> list[dict]:
    """Registered projects in registration order: {id, path, registered_at}."""
    rows = _read("SELECT id, path, registered_at FROM projects ORDER BY id")
    return [dict(row) for row in rows]


def _run(row: sqlite3.Row) -> dict:
    run = {name: row[name] for name in RUN_COLUMNS if name not in STATUSES}
    run["base_lock"] = None if run["base_lock"] is None else bool(run["base_lock"])
    run["counts"] = {status: row[status] for status in STATUSES}
    return run


def list_runs(project_id: int, limit: int | None = None) -> list[dict]:
    """A project's runs, newest first, without the stored documents.

    Each run has the report's status, exit_code, model_id and model_sha256 as stored, and
    counts per item status ({flagged, not_flagged, incomplete, removed}) for trends.
    """
    query = f"SELECT {', '.join(RUN_COLUMNS)} FROM runs WHERE project_id = ? ORDER BY id DESC"
    parameters: tuple = (project_id,)
    if limit is not None:
        query, parameters = query + " LIMIT ?", (project_id, limit)
    return [_run(row) for row in _read(query, parameters)]


def get_run(run_id: int) -> dict | None:
    """One run with its report, preview (None for a scan) and result rows in report order."""
    runs = _read(f"SELECT {', '.join(RUN_COLUMNS)}, report, preview FROM runs WHERE id = ?",
                 (run_id,))  # fmt: skip
    if not runs:
        return None
    (row,) = runs
    run = _run(row)
    run["report"] = json.loads(row["report"])
    run["preview"] = None if row["preview"] is None else json.loads(row["preview"])
    rows = _read(
        f"SELECT {', '.join(RESULT_COLUMNS)} FROM results WHERE run_id = ? ORDER BY position",
        (run_id,),
    )
    run["results"] = [dict(result) for result in rows]
    return run
