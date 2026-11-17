"""Local history of scan and update-preview reports for projects registered in the dashboard.

Standard library only. Reports are stored as given: verdicts, reasons and exit codes are never
recomputed, and nothing here detects anything. The CLI records through record(), which never
creates the database; only register_project() does. The dashboard uses the same API. An update
apply (service.apply_update) is stored next to its update_preview run, or added to that run
later with record_apply() (the dashboard); never the new lockfile.
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
# 2 added the applies table; a version 1 file is upgraded in the transaction of its next write.
USER_VERSION = 2
# PRAGMA application_id ("DPBE"): marks the file as a depbee history; the version alone does not.
APPLICATION_ID = 0x44504245
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
APPLY_COLUMNS = (
    "id", "run_id", "created_at", "mode", "outcome", "reason", "confirmed",
    "package_json_sha256", "package_lock_sha256", "new_package_json_sha256",
    "new_package_lock_sha256", "backup", "npm_version", "npm_ci_exit_code",
)  # fmt: skip
# Version 2: one row per update apply, tied to the update_preview run of the same command.
# apply is the whole apply document (service.apply_update); the new lockfile is never stored.
SCHEMA_2 = """
CREATE TABLE applies (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL UNIQUE REFERENCES runs (id),
    created_at TEXT NOT NULL,
    mode TEXT NOT NULL,
    outcome TEXT NOT NULL,
    reason TEXT,
    confirmed INTEGER NOT NULL,
    package_json_sha256 TEXT,
    package_lock_sha256 TEXT,
    new_package_json_sha256 TEXT,
    new_package_lock_sha256 TEXT,
    backup TEXT,
    npm_version TEXT,
    npm_ci_exit_code INTEGER,
    apply TEXT NOT NULL
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
    """(key, display path) of the resolved absolute path.

    The key is the path case-folded on Windows, as ASCII JSON: reversible, so a lone surrogate
    and the literal text \\udc80 stay different projects. The display path is _text().
    """
    path = str(Path(project).resolve())
    return _json(os.path.normcase(path)), _text(path)


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


def _check(connection, create: bool = False) -> int:
    """The user_version of our database (1 to USER_VERSION), or 0 if it is empty and create may
    set it up.

    Ours means APPLICATION_ID; any other file is refused whatever its user_version, and so is a
    newer one.
    """
    application = connection.execute("PRAGMA application_id").fetchone()[0]
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if application == APPLICATION_ID:
        if version > USER_VERSION:
            raise HistoryError(f"History database version {version} is newer than {USER_VERSION}")
        if version >= 1:
            return version
    elif application == version == 0 and create:
        tables = connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
        if not tables:
            return 0
    raise HistoryError("Not a depbee history database")


def _upgrade(connection, version: int) -> None:
    """Bring a database _check() returned version for to USER_VERSION, inside the caller's write
    transaction: the tables and both header values roll back with it."""
    # Statement by statement: executescript() would commit outside this transaction.
    script = (SCHEMA if version == 0 else "") + (SCHEMA_2 if version < 2 else "")
    for statement in script.split(";"):
        if statement.strip():
            connection.execute(statement)
    if version == 0:
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
    if version < USER_VERSION:
        connection.execute(f"PRAGMA user_version = {USER_VERSION}")


def register_project(project: Path | str) -> int:
    """Register an existing project folder and return its id; creates the database if needed.

    Registering again keeps the first registration. Web input checks (UNC, device paths,
    reserved names, links) belong to the dashboard's boundary, not here. Without a home
    directory (and no DEPBEE_HISTORY_DB) this and the read functions raise RuntimeError; only
    record() skips.
    """
    if not Path(project).is_dir():
        raise ValueError("The project must be an existing directory")
    key, display = _project(project)
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(path, create=True) as connection, _write(connection):
        _upgrade(connection, _check(connection, create=True))
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
    apply: dict | None = None,
) -> int | None:
    """Store one report for a registered project and return the run id.

    kind: "scan" or "update_preview" (then preview is the update preview). base_ref, base_lock:
    the scan's --base-ref value and whether --base-lock was given (None for update previews).
    apply: the apply document of service.apply_update for this update preview, stored in the
    same transaction as its run (applies table: the original hashes from the preview, the new
    ones of the files it replaced).
    Returns None without touching anything if there is no home directory, no database file or
    the project is not registered. Raises sqlite3.Error, HistoryError, OSError or ValueError if
    the database cannot be read or written; the caller decides how to report that.
    """
    if kind not in KINDS:
        raise ValueError(f"Unknown history kind: {kind}")
    if apply is not None and (kind != "update_preview" or preview is None):
        raise ValueError("An apply is recorded with its update preview")
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
            _upgrade(connection, _check(connection))
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
            if apply is not None:
                _insert_apply(connection, run_id, preview, apply)
        return run_id


def _insert_apply(connection, run_id: int, preview: dict, apply: dict) -> int:
    """One applies row inside the caller's write transaction: the original hashes from the
    preview, the new ones of the files the apply replaced, and the whole apply document."""
    new = {f["path"]: f["new_sha256"] for f in apply.get("files") or []}
    values = (
        run_id, _now(), _text(apply.get("mode")), _text(apply.get("outcome")),
        _text(apply.get("reason")), bool(apply.get("confirmed")),
        _text(preview.get("package_json_sha256")), _text(preview.get("package_lock_sha256")),
        _text(new.get("package.json")), _text(new.get("package-lock.json")),
        _text(apply.get("backup")), _text(apply.get("npm_version")),
        apply.get("npm_ci_exit_code"), _json(apply),
    )  # fmt: skip
    return connection.execute(
        f"INSERT INTO applies ({', '.join(APPLY_COLUMNS[1:])}, apply) "
        f"VALUES ({', '.join('?' * len(APPLY_COLUMNS))})",
        values,
    ).lastrowid


def record_apply(run_id: int, preview: dict, apply: dict) -> int | None:
    """Add an apply (service.apply_preview) to an update_preview run recorded earlier and return
    its applies id: the dashboard applies a preview after recording it. Same columns as
    record()'s apply, in one BEGIN IMMEDIATE transaction that also upgrades a version 1 file.

    Returns None without touching anything if there is no home directory, no database file or
    no such run. Raises ValueError for a run that is not an update_preview or already has an
    apply (one apply per preview, applies.run_id UNIQUE), and sqlite3.Error, HistoryError or
    OSError if the database cannot be read or written.
    """
    try:
        path = db_path()
    except RuntimeError:  # no home directory: no history, as in record()
        return None
    if not path.exists():
        return None
    with _connect(path, create=False) as connection:
        _check(connection)
        with _write(connection):
            version = _check(connection)
            row = connection.execute("SELECT kind FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                return None
            if row[0] != "update_preview":
                raise ValueError("An apply is recorded with its update preview")
            if version >= 2 and connection.execute(
                "SELECT 1 FROM applies WHERE run_id = ?", (run_id,)
            ).fetchone():
                raise ValueError("This update preview already has an apply")
            _upgrade(connection, version)
            return _insert_apply(connection, run_id, preview, apply)


def _read(query: str, parameters: tuple = (), since: int = 1) -> list[sqlite3.Row]:
    """Rows of a read-only query; none if there is no database (it is not created) or it is
    older than version since (a version 1 file has no applies table and is not upgraded here)."""
    path = db_path()
    if not path.exists():
        return []
    with _connect(path, create=False) as connection:
        if _check(connection) < since:
            return []
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


def _apply(row: sqlite3.Row) -> dict:
    apply = {name: row[name] for name in APPLY_COLUMNS}
    apply["confirmed"] = bool(apply["confirmed"])
    apply["apply"] = json.loads(row["apply"])
    return apply


def list_applies(project_id: int, limit: int | None = None) -> list[dict]:
    """A project's update applies, newest first: the applies columns (run_id is the update
    preview run of the same command) and the stored apply document as apply."""
    columns = ", ".join(f"a.{name}" for name in APPLY_COLUMNS)
    query = (
        f"SELECT {columns}, a.apply FROM applies a JOIN runs r ON r.id = a.run_id "
        "WHERE r.project_id = ? ORDER BY a.id DESC"
    )
    parameters: tuple = (project_id,)
    if limit is not None:
        query, parameters = query + " LIMIT ?", (project_id, limit)
    return [_apply(row) for row in _read(query, parameters, since=2)]


def get_run(run_id: int) -> dict | None:
    """One run with its report, preview (None for a scan), result rows in report order and apply
    (as in list_applies(), None if the run applied nothing)."""
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
    applies = _read(f"SELECT {', '.join(APPLY_COLUMNS)}, apply FROM applies WHERE run_id = ?",
                    (run_id,), since=2)  # fmt: skip
    run["apply"] = _apply(applies[0]) if applies else None
    return run
