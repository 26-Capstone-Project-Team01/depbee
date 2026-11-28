"""Local history of scan and update-preview reports for projects registered in the dashboard.

Standard library only. Reports are stored as given: verdicts, reasons and exit codes are never
recomputed, and nothing here detects anything. The CLI records through record(), which never
creates the database; only register_project() does. The dashboard uses the same API. An update
apply (service.apply_update) is stored next to its update_preview run, or added to that run
later with record_apply() (the dashboard); never the new lockfile. An update_preview run also
has a previews row (the hashes of the two files it was made from and its targets), so that the
previews of given files are found without reading the stored documents (list_previews()).

A project leaves the list by unregister_project(), which only marks its row: its runs stay
stored under it, nothing more is recorded for it, and registering the folder again brings it
back with them. No projects row is ever deleted: SQLite gives the id of a deleted last row to
the next project, which would then own the runs left behind. Each unregistration raises the
row's generation, so that whoever kept something of the project (a dashboard, an update
preview in its memory) can tell that the project left the list since, also once it is back.

The dashboards of this computer share the file. What one of them runs on a project (a check, a
scan, an apply) holds that project meanwhile (hold_project): a lock of the operating system on
a file beside the history, never one of the database, which the system frees if the process
dies. unregister_project() needs the same hold, so a project never leaves the list under work
that runs on it, in this process or another.
"""

import contextlib
import errno
import hashlib
import json
import os
import sqlite3
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from . import __version__

# PRAGMA user_version of a depbee history database; separate from contracts.SCHEMA_VERSION.
# 2 added the applies table, 3 the previews table and 4 projects.unregistered_at and
# projects.generation; an older file is upgraded in the transaction of its next write.
USER_VERSION = 4
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
# Version 3: one row per update_preview run with the SHA-256 of the package.json and the
# package-lock.json its preview document says it was made from, and the document's targets as
# JSON (NULL: a preview of everything). Its index finds a project's previews of given files
# without reading a stored document: runs.preview lies behind runs.report, which can be large.
# runs_by_kind finds a project's newest run of one kind without passing every newer run of the
# other kind.
SCHEMA_3 = """
CREATE TABLE previews (
    run_id INTEGER PRIMARY KEY REFERENCES runs (id),
    project_id INTEGER NOT NULL REFERENCES projects (id),
    created_at TEXT NOT NULL,
    package_json_sha256 TEXT,
    package_lock_sha256 TEXT,
    targets TEXT
);
CREATE INDEX previews_by_files
    ON previews (project_id, package_json_sha256, package_lock_sha256, run_id);
CREATE INDEX runs_by_kind ON runs (project_id, kind, id);
"""
# Version 4: when a project was taken off the list (unregister_project), NULL while it is
# registered, and how many times it was (generation). Its row stays, so that its runs keep
# their project and its id is never given to another one.
SCHEMA_4 = """
ALTER TABLE projects ADD COLUMN unregistered_at TEXT;
ALTER TABLE projects ADD COLUMN generation INTEGER NOT NULL DEFAULT 0
"""
# In a query _read() runs: the condition that a projects row is registered, and its
# generation. A file older than version 4 has neither column: every project in it is
# registered, at generation 0.
REGISTERED, GENERATION = "{registered}", "{generation}"
INSERT_PREVIEW = (
    "INSERT INTO previews (run_id, project_id, created_at, package_json_sha256, "
    "package_lock_sha256, targets) VALUES (?, ?, ?, ?, ?, ?)"
)


class HistoryError(Exception):
    """The file is not a history database this depbee can write (newer or not depbee's)."""


class ProjectBusy(Exception):
    """Another dashboard process, or another hold of this one, works on the project."""


class ProjectGone(Exception):
    """The project is not registered now, or left the list since the generation asked for."""


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


def _connect(path: Path, create: bool, *, read_only: bool = False):
    """A closing() connection; without create the file must exist and is never created. A
    read_only one never writes the file or its journal: an interrupted write is left for the
    next writer to roll back, and reading fails until then."""
    mode = "ro" if read_only else "rwc" if create else "rw"
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


def _preview_columns(preview: object) -> tuple:
    """What the previews table keeps of an update preview document: the SHA-256 of the
    package.json and the package-lock.json it was made from and its targets as JSON (None for a
    preview of everything). A value that is not a string, or anything that is not a document,
    is None: such a run is stored and never found by its files."""
    if not isinstance(preview, dict):
        return (None, None, None)
    hashes = (preview.get("package_json_sha256"), preview.get("package_lock_sha256"))
    targets = preview.get("targets")
    return (
        *(_text(value) if isinstance(value, str) else None for value in hashes),
        None if targets is None else _json(targets),
    )


def _stored_columns(preview: str | None) -> tuple:
    """_preview_columns() of a preview as runs.preview stores it. Text that is not JSON (never
    written by depbee) is no document: one such row must not stop the upgrade of the file."""
    try:
        return _preview_columns(None if preview is None else json.loads(preview))
    except ValueError:
        return (None, None, None)


def _upgrade(connection, version: int) -> None:
    """Bring a database _check() returned version for to USER_VERSION, inside the caller's write
    transaction: the tables, their rows and both header values roll back with it."""
    # Statement by statement: executescript() would commit outside this transaction.
    script = (
        (SCHEMA if version == 0 else "")
        + (SCHEMA_2 if version < 2 else "")
        + (SCHEMA_3 if version < 3 else "")
        + (SCHEMA_4 if version < 4 else "")
    )
    for statement in script.split(";"):
        if statement.strip():
            connection.execute(statement)
    if 0 < version < 3:  # the update previews recorded before the previews table
        runs = connection.execute(
            "SELECT id, project_id, created_at, preview FROM runs WHERE kind = 'update_preview'"
        ).fetchall()
        connection.executemany(
            INSERT_PREVIEW, [(*run[:3], *_stored_columns(run[3])) for run in runs]
        )
    if version == 0:
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
    if version < USER_VERSION:
        connection.execute(f"PRAGMA user_version = {USER_VERSION}")


class Hold:
    """A project held for one piece of work (hold_project). release() frees it, once, from any
    thread; the system frees it too when the process ends. Also a context manager."""

    def __init__(self, stream):
        self._stream = stream

    def release(self) -> None:
        stream, self._stream = self._stream, None
        if stream is None:
            return
        if os.name == "nt":
            import msvcrt

            with contextlib.suppress(OSError):
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.release()


def _lock_project(project_id: int) -> Hold:
    """The system's lock on a file in locks/ beside the history file (the way of the install
    lock, service._install_lock), without waiting: ProjectBusy while any other open file holds
    it, in this process or another. Both the folder and the file's name come from the history
    file's real path (case-folded on Windows for the name), so every path to one history file,
    a link in another folder too, reaches one lock file; the name also has the project's id, so
    project 1 of another history file in the same folder is another project. OSError if the
    file cannot be opened or the file system has no locks."""
    database = os.path.realpath(db_path())
    key = hashlib.sha256(os.path.normcase(database).encode("utf-8", "replace")).hexdigest()[:32]
    folder = Path(database).parent / "locks"
    folder.mkdir(parents=True, exist_ok=True)
    stream = open(folder / f"project-{key}-{project_id}.lock", "a+b")  # noqa: SIM115
    try:
        if os.name == "nt":
            import msvcrt

            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        stream.close()
        if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):  # held
            raise ProjectBusy(project_id) from None
        raise
    return Hold(stream)


def hold_project(project_id: int, generation: int) -> Hold:
    """Hold a registered project for the whole of a check, a scan or an apply that a dashboard
    runs on it, and return the hold to release() when that has ended. generation: the project's
    as list_projects() gave it when the work, or the update preview it applies, was asked for.

    Under the hold the registration is read afresh: ProjectGone unless the project is registered
    now at that generation, so nothing starts on a project that left the list, and nothing kept
    from before it left is used once it is back. ProjectBusy without waiting while another hold
    has the project: no two pieces of work on one project, and none while it is unregistered
    (unregister_project takes the same hold). No database lock is kept; the database is read
    once. Raises sqlite3.Error, HistoryError or OSError if that or the lock file fails.
    """
    hold = _lock_project(project_id)
    try:
        found = _read(
            f"SELECT {GENERATION} FROM projects WHERE id = ? AND {REGISTERED}", (project_id,)
        )
        if not found or found[0][0] != generation:
            raise ProjectGone(project_id)
    except BaseException:
        hold.release()
        raise
    return hold


def register_project(project: Path | str) -> int:
    """Register an existing project folder and return its id; creates the database if needed.

    Registering again keeps the first registration. A folder that was unregistered
    (unregister_project) is registered anew under the id it had, with the runs stored for it and
    at its old place in the list; registered_at is then the time of this call, and its
    generation stays the one its unregistration gave it. Web input checks
    (UNC, device paths, reserved names, links) belong to the dashboard's boundary, not here.
    Without a home directory (and no DEPBEE_HISTORY_DB) this and the read functions raise
    RuntimeError; only record() skips.
    """
    if not Path(project).is_dir():
        raise ValueError("The project must be an existing directory")
    key, display = _project(project)
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(path, create=True) as connection, _write(connection):
        _upgrade(connection, _check(connection, create=True))
        now = _now()
        connection.execute(
            "INSERT OR IGNORE INTO projects (key, path, registered_at) VALUES (?, ?, ?)",
            (key, display, now),
        )
        connection.execute(
            "UPDATE projects SET unregistered_at = NULL, registered_at = ? "
            "WHERE key = ? AND unregistered_at IS NOT NULL",
            (now, key),
        )
        return connection.execute("SELECT id FROM projects WHERE key = ?", (key,)).fetchone()[0]


def unregister_project(project_id: int) -> bool:
    """Take a registered project off the list, and return whether this call did.

    Only the project's row is marked, and its generation raised: its runs, results, applies and
    previews stay stored under it, and nothing of its folder is read or written (the folder may
    be gone). From then on list_projects() leaves it out, record() and record_apply() store
    nothing for it, get_run() finds none of its runs and hold_project() refuses it, until
    register_project() is given the same folder again; what was kept at the earlier generation
    is refused for good.

    Done under the project's hold (hold_project): ProjectBusy, with nothing changed, while a
    dashboard of any process runs a check, a scan or an apply on it. False without touching
    anything if there is no database file, no such project, or the project is already
    unregistered. Raises sqlite3.Error, HistoryError or OSError if the database or the lock file
    cannot be read or written, and RuntimeError without a home directory.
    """
    path = db_path()
    if not path.exists():
        return False
    if not _read(f"SELECT 1 FROM projects WHERE id = ? AND {REGISTERED}", (project_id,)):
        return False  # before any lock file is made for an id that is no project's
    with _lock_project(project_id), _connect(path, create=False) as connection:
        _check(connection)
        with _write(connection):
            version = _check(connection)
            listed = "" if version < 4 else " AND unregistered_at IS NULL"
            found = connection.execute(
                f"SELECT 1 FROM projects WHERE id = ?{listed}", (project_id,)
            ).fetchone()
            if found is None:  # nothing to mark: an older file is left as it is
                return False
            _upgrade(connection, version)
            connection.execute(
                "UPDATE projects SET unregistered_at = ?, generation = generation + 1 "
                "WHERE id = ?",
                (_now(), project_id),
            )
            return True


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
    ones of the files it replaced). An update preview also gets its previews row there (the
    hashes of the files it was made from and its targets), by which list_previews() finds it.
    Returns None without touching anything if there is no home directory, no database file or
    the project is not registered (never, or no longer: unregister_project). Raises
    sqlite3.Error, HistoryError, OSError or ValueError if
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
    created_at = _now()
    run = (
        kind, created_at, __version__, _text(base_ref), base_lock, _text(report.get("status")),
        report.get("exit_code"), _text(report.get("model_id")), _text(model.get("model_sha256")),
        *(counts[status] for status in STATUSES), _json(report),
        None if preview is None else _json(preview),
    )  # fmt: skip
    columns = _preview_columns(preview) if kind == "update_preview" else None
    # The first seven columns are result keys; the last three the detector slots' statuses.
    rows = [
        [row.get(name) for name in RESULT_COLUMNS[:7]]
        + [(row.get(slot) or {}).get("status") for slot in ("known_malicious", "rules", "ml")]
        for row in results
    ]
    with _connect(path, create=False) as connection:
        listed = "" if _check(connection) < 4 else " AND unregistered_at IS NULL"
        registered = f"SELECT 1 FROM projects WHERE key = ?{listed}"
        if connection.execute(registered, (key,)).fetchone() is None:
            return None
        with _write(connection):
            _upgrade(connection, _check(connection))
            # Asked again under the write lock: the project may have been unregistered since.
            found = connection.execute(
                "SELECT id FROM projects WHERE key = ? AND unregistered_at IS NULL", (key,)
            ).fetchone()
            if found is None:
                return None
            (project_id,) = found
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
            if columns is not None:
                connection.execute(INSERT_PREVIEW, (run_id, project_id, created_at, *columns))
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

    Returns None without touching anything if there is no home directory, no database file,
    no such run, or the run's project is not registered any more (unregister_project): nothing
    is added to what an unregistered project has stored. Raises ValueError for a run that is
    not an update_preview or already has an
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
            row = connection.execute(
                "SELECT kind, project_id FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
            if row is None:
                return None
            if version >= 4 and connection.execute(
                "SELECT 1 FROM projects WHERE id = ? AND unregistered_at IS NOT NULL", (row[1],)
            ).fetchone():
                return None
            if row[0] != "update_preview":
                raise ValueError("An apply is recorded with its update preview")
            if (
                version >= 2
                and connection.execute(
                    "SELECT 1 FROM applies WHERE run_id = ?", (run_id,)
                ).fetchone()
            ):
                raise ValueError("This update preview already has an apply")
            _upgrade(connection, version)
            return _insert_apply(connection, run_id, preview, apply)


def _read(query: str, parameters: tuple = (), since: int = 1) -> list[sqlite3.Row]:
    """Rows of a read-only query; none if there is no database (it is not created) or it is
    older than version since (a version 1 file has no applies table and is not upgraded here).
    REGISTERED in the query is the condition that a projects row is registered, GENERATION
    that row's generation."""
    path = db_path()
    if not path.exists():
        return []
    with _connect(path, create=False, read_only=True) as connection:
        version = _check(connection)
        if version < since:
            return []
        connection.row_factory = sqlite3.Row
        registered, generation = ("1", "0") if version < 4 else (
            "unregistered_at IS NULL", "generation"
        )  # fmt: skip
        query = query.replace(REGISTERED, registered).replace(GENERATION, generation)
        return connection.execute(query, parameters).fetchall()


def list_projects() -> list[dict]:
    """Registered projects in registration order: {id, path, registered_at, generation}. One
    that was unregistered is not listed; registered again, it is back at the place its id gives
    it. generation: how many times the project was unregistered (0 in a file older than version
    4). The same id at the same generation is a project that never left the list in between."""
    rows = _read(
        f"SELECT id, path, registered_at, {GENERATION} AS generation FROM projects "
        f"WHERE {REGISTERED} ORDER BY id"
    )
    return [dict(row) for row in rows]


def _run(row: sqlite3.Row) -> dict:
    run = {name: row[name] for name in RUN_COLUMNS if name not in STATUSES}
    run["base_lock"] = None if run["base_lock"] is None else bool(run["base_lock"])
    run["counts"] = {status: row[status] for status in STATUSES}
    return run


def count_runs(project_id: int) -> int:
    """How many runs a project has stored, without reading them (the dashboard's history tab)."""
    rows = _read("SELECT COUNT(*) FROM runs WHERE project_id = ?", (project_id,))
    return rows[0][0] if rows else 0


def list_runs(project_id: int, limit: int | None = None, kind: str | None = None) -> list[dict]:
    """A project's runs, newest first, without the stored documents; kind: only its scans or
    only its update previews (KINDS).

    Each run has the report's status, exit_code, model_id and model_sha256 as stored, and
    counts per item status ({flagged, not_flagged, incomplete, removed}) for trends.
    """
    query = f"SELECT {', '.join(RUN_COLUMNS)} FROM runs WHERE project_id = ?"
    parameters: tuple = (project_id,)
    if kind is not None:
        query, parameters = query + " AND kind = ?", (*parameters, kind)
    query += " ORDER BY id DESC"
    if limit is not None:
        query, parameters = query + " LIMIT ?", (*parameters, limit)
    return [_run(row) for row in _read(query, parameters)]


def list_run_scores(project_id: int, limit: int = 10) -> list[dict]:
    """Stored peak ML score and scored item count for each recent run, newest first, with the
    threshold of that run's stored report (None if it has none): the one a reader compares the
    peak with. Reads the stored reports of these runs alone."""
    rows = _read(
        """SELECT recent.id, recent.created_at, recent.model_id, recent.report,
                  MAX(item.score) AS peak_score, COUNT(item.position) AS scored_count
           FROM (SELECT id, created_at, model_id, report FROM runs
                 WHERE project_id = ? ORDER BY id DESC LIMIT ?) AS recent
           LEFT JOIN results AS item ON item.run_id = recent.id
                AND typeof(item.score) IN ('real', 'integer') AND item.score BETWEEN 0 AND 1
           GROUP BY recent.id ORDER BY recent.id DESC""",
        (project_id, limit),
    )
    found = []
    for row in rows:
        run = dict(row)
        run["threshold"] = json.loads(run.pop("report")).get("threshold")
        found.append(run)
    return found


def list_previews(
    project_id: int, package_json_sha256: str, package_lock_sha256: str
) -> list[dict]:
    """A project's update previews made from the package.json and the package-lock.json with
    these SHA-256, newest first: {id, created_at, targets, locations}. targets is the preview's
    (None for a preview of everything) and locations are its result rows' locations in report
    order, as stored. The list ends with the newest preview of everything: older previews of
    the same files are not read.

    Reads the previews table and the result rows, never a stored document. A file older than
    version 3 has no such table and is not upgraded here: there each stored preview of the
    project is read, newest first, until that preview of everything.
    """
    files = (package_json_sha256, package_lock_sha256)
    path = db_path()
    if not path.exists():
        return []
    with _connect(path, create=False, read_only=True) as connection:
        if _check(connection) >= 3:
            runs = connection.execute(
                "SELECT run_id, created_at, targets FROM previews WHERE project_id = ? AND "
                "package_json_sha256 = ? AND package_lock_sha256 = ? ORDER BY run_id DESC",
                (project_id, *files),
            )
        else:
            stored = connection.execute(
                "SELECT id, created_at, preview FROM runs WHERE project_id = ? AND "
                "kind = 'update_preview' ORDER BY id DESC",
                (project_id,),
            )
            runs = (
                (run_id, created_at, columns[2])
                for run_id, created_at, preview in stored
                if (columns := _stored_columns(preview))[:2] == files
            )
        found = []
        # shortcut: one small query per preview read; join the result rows instead if projects
        # ever pile up thousands of previews of named packages without one of everything.
        for run_id, created_at, targets in runs:  # read row by row, so that the break ends it
            rows = connection.execute(
                "SELECT location FROM results WHERE run_id = ? ORDER BY position", (run_id,)
            )
            found.append({
                "id": run_id, "created_at": created_at,
                "targets": None if targets is None else json.loads(targets),
                "locations": [location for (location,) in rows],
            })  # fmt: skip
            if targets is None:
                break
        return found


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


def latest_applies(*, applied: bool = True) -> dict[int, dict]:
    """Each project's most recently recorded update apply, by project id: the last applies row
    written for it as {run_id, created_at, mode, outcome, reason} with the SHA-256 the apply
    stored (package_json_sha256 of the package.json its preview was made from, and
    new_package_json_sha256 and new_package_lock_sha256 of the files it replaced, None for a
    file it left as it was).

    applied (the default): the last apply that changed the project's files (outcome applied).
    One that was refused, failed or found nothing to change is not one, and a later one of
    those does not hide it. Without it: the last attempt, whatever its outcome. Either way an
    older preview that was applied after a newer one counts by its apply, and created_at is
    when that was. A project without such an apply has no entry, and a file older than version
    2 has none at all: it has no applies table and is not upgraded here.

    One pass over the applies for all the projects together, each with the project of its run,
    then the row of each project's greatest apply id. No stored document is read and no run
    that was never applied; asked project by project instead, every project that applied
    nothing would pass the applies of all the others."""
    columns = ("run_id", "created_at", "mode", "outcome", "reason", "package_json_sha256",
               "new_package_json_sha256", "new_package_lock_sha256")  # fmt: skip
    only = "WHERE a.outcome = 'applied' " if applied else ""
    # CROSS JOIN keeps applies the outer loop. Left to choose, SQLite walks the runs of every
    # project, which are many more than the applies.
    rows = _read(
        f"SELECT r.project_id, {', '.join(f'a.{name}' for name in columns)} "
        "FROM applies a CROSS JOIN runs r ON r.id = a.run_id WHERE a.id IN ("
        "SELECT MAX(a.id) FROM applies a CROSS JOIN runs r ON r.id = a.run_id "
        f"{only}GROUP BY r.project_id)",
        since=2,
    )
    return {row["project_id"]: {name: row[name] for name in columns} for row in rows}


def get_run(run_id: int) -> dict | None:
    """One run with its report, preview (None for a scan), result rows in report order and apply
    (as in list_applies(), None if the run applied nothing). None too for a run of a project
    that is unregistered: it stays stored, and is found again once its folder is registered
    again."""
    runs = _read(
        f"SELECT {', '.join(RUN_COLUMNS)}, report, preview FROM runs WHERE id = ? "
        f"AND project_id IN (SELECT id FROM projects WHERE {REGISTERED})",
        (run_id,),
    )
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
