"""Local history (HIST-01): register, record and read back; the CLI output never changes.

Synthetic only and inside each test run's folder (Fixture sets DEPBEE_HISTORY_DB there without
creating the file): no npm, registry or package code.
"""

import contextlib
import gc
import io
import json
import os
import sqlite3
import stat
import subprocess
import sys
import warnings
from pathlib import Path, PurePosixPath
from unittest import mock

from test_extract import FakeBackend, packument
from test_mcp import TIMES, MCPFixture
from test_update import UpdateFixture
from test_workflow import FakePredictor, Fixture, package

from depbee import history, mcp
from depbee.cli import HISTORY_FAILED, main
from depbee.service import scan_project

FORMATS = ("text", "json", "markdown")


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def sql(path, query, *parameters):
    with contextlib.closing(sqlite3.connect(path)) as connection:
        rows = connection.execute(query, parameters).fetchall()
        connection.commit()
        return rows


def files(root):
    return sorted(str(p.relative_to(root)) for p in Path(root).rglob("*"))


def make_older(db, version):
    """Turn a database of this version into one as the version 2 or 3 code left it: without
    the columns version 4 added and, for 2, the table and the index version 3 added."""
    for column in ("unregistered_at", "generation"):
        sql(db, f"ALTER TABLE projects DROP COLUMN {column}")
    if version < 3:
        sql(db, "DROP TABLE previews")
        sql(db, "DROP INDEX runs_by_kind")
    sql(db, f"PRAGMA user_version = {version}")


def make_version_3(db, project):
    """A history file written statement by statement as the version 3 code wrote it, not a
    newer one cut down: its three schema scripts, its two header values, and one registered
    project with an update preview run, that run's result row, previews row and apply. Returns
    (project id, run id)."""
    key, path = history._project(project)
    report = {"status": "passed", "exit_code": 0, "threshold": 0.5, "results": []}
    with contextlib.closing(sqlite3.connect(db, isolation_level=None)) as connection:
        for script in (history.SCHEMA, history.SCHEMA_2, history.SCHEMA_3):
            for statement in script.split(";"):
                if statement.strip():
                    connection.execute(statement)
        connection.execute(f"PRAGMA application_id = {history.APPLICATION_ID}")
        connection.execute("PRAGMA user_version = 3")
        connection.execute("INSERT INTO projects (key, path, registered_at) VALUES "
                           "(?, ?, '2026-11-20T00:00:00.000Z')", (key, path))  # fmt: skip
        connection.execute(
            "INSERT INTO runs (project_id, kind, created_at, depbee_version, status, exit_code, "
            "flagged, not_flagged, incomplete, removed, report, preview) VALUES (1, "
            "'update_preview', '2026-11-20T00:00:01.000Z', '0.0.0', 'passed', 0, 0, 1, 0, 0, ?, ?)",
            (json.dumps(report), json.dumps(PREVIEW)),
        )
        connection.execute("INSERT INTO results (run_id, position, location, package, status) "
                           "VALUES (1, 0, 'node_modules/example', 'example', 'not_flagged')")
        connection.execute(history.INSERT_PREVIEW, (1, 1, "2026-11-20T00:00:01.000Z",
                                                    "a" * 64, "b" * 64, None))  # fmt: skip
        connection.execute(
            "INSERT INTO applies (run_id, created_at, mode, outcome, confirmed, apply) VALUES "
            "(1, '2026-11-20T00:00:02.000Z', 'lockfile', 'applied', 0, ?)",
            (json.dumps(apply_document()),),
        )
    return 1, 1


def tree(root, *skipped):
    """Every file and folder under root but the skipped ones and what is under them, with each
    file's bytes and time of change: what must be the same after something that may not touch
    them."""
    found = {}
    for path in sorted(Path(root).rglob("*")):
        if any(path == skip or skip in path.parents for skip in skipped):
            continue
        found[str(path.relative_to(root))] = (
            None if path.is_dir() else (path.read_bytes(), path.stat().st_mtime_ns)
        )
    return found


class HistoryFixture(Fixture):
    def setUp(self):
        super().setUp()
        self.db = Path(os.environ["DEPBEE_HISTORY_DB"])
        self.analysis = self.root / "analysis.json"
        self.adapter()  # FakePredictor scores it 0.9: flagged, exit 1
        patcher = mock.patch("depbee.service.LightGBMPredictor", return_value=FakePredictor())
        patcher.start()
        self.addCleanup(patcher.stop)

    def scan_argv(self, fmt="json", *extra):
        return ["scan", str(self.project), "--base-lock", str(self.base), "--analysis",
                str(self.analysis), "--model-dir", "m", "--format", fmt, *extra]  # fmt: skip

    def runs(self):
        return sql(self.db, "SELECT count(*) FROM runs")[0][0]

    def baseline(self):
        """(code, stdout, stderr) per format with no history database."""
        self.assertFalse(self.db.exists())
        return {fmt: run(self.scan_argv(fmt)) for fmt in FORMATS}


class StoreTests(HistoryFixture):
    def test_recent_scores_keep_zero_and_unscored_runs_distinct(self):
        project_id = history.register_project(self.project)
        other = self.root / "other"
        other.mkdir()
        history.register_project(other)
        report = scan_project(self.project, self.base, analysis=self.analysis, model_dir=Path("m"))
        history.record("scan", other, report)
        recorded = history.record("scan", self.project, report)
        report["results"][0]["score"] = 0.0
        zero = history.record("scan", self.project, report)
        report["results"][0]["score"] = None
        absent = history.record("scan", self.project, report)
        rows = history.list_run_scores(project_id)
        self.assertEqual(
            [(r["id"], r["peak_score"], r["scored_count"]) for r in rows],
            [(absent, None, 0), (zero, 0.0, 1), (recorded, 0.9, 1)],
        )
        self.assertEqual(history.list_run_scores(project_id, limit=2), rows[:2])

    def test_register_record_and_read_back(self):
        project_id = history.register_project(self.project)
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(4,)])
        self.assertEqual(sql(self.db, "PRAGMA application_id"), [(history.APPLICATION_ID,)])
        self.assertEqual(history.register_project(self.project), project_id)
        (project,) = history.list_projects()
        self.assertEqual(project["path"], str(self.project.resolve()))
        report = scan_project(self.project, self.base, analysis=self.analysis, model_dir=Path("m"))
        first = history.record("scan", self.project, report, base_ref="main", base_lock=False)
        second = history.record("scan", self.project, report, base_lock=True)
        runs = history.list_runs(project_id)
        self.assertEqual([r["id"] for r in runs], [second, first])  # newest first
        self.assertEqual([r["id"] for r in history.list_runs(project_id, limit=1)], [second])
        self.assertEqual((runs[1]["base_ref"], runs[1]["base_lock"]), ("main", False))
        self.assertEqual((runs[0]["base_ref"], runs[0]["base_lock"]), (None, True))
        stored = history.get_run(first)
        self.assertEqual(stored["report"], report)
        self.assertIsNone(stored["preview"])
        self.assertEqual(
            (stored["kind"], stored["status"], stored["exit_code"], stored["model_id"]),
            ("scan", "flagged", 1, "unit-test"),
        )
        self.assertEqual(stored["counts"], {"flagged": 1, "not_flagged": 0, "incomplete": 0,
                                            "removed": 0})  # fmt: skip
        self.assertTrue(stored["created_at"].endswith("Z"))
        (row,) = stored["results"]
        self.assertEqual(row["change_id"], report["results"][0]["change_id"])
        self.assertEqual((row["package"], row["after_version"], row["score"]),
                         ("example", "1.1.0", 0.9))  # fmt: skip
        self.assertEqual((row["known_malicious_status"], row["ml_status"]), ("not_run", "hit"))
        self.assertIsNone(stored["apply"])
        self.assertEqual(history.list_applies(project_id), [])
        self.assertIsNone(history.get_run(second + 1))

    def test_register_creates_the_folders_and_needs_an_existing_project(self):
        os.environ["DEPBEE_HISTORY_DB"] = str(self.root / "a" / "b" / "history.sqlite3")
        with self.assertRaises(ValueError):
            history.register_project(self.root / "missing")
        self.assertFalse((self.root / "a").exists())
        history.register_project(self.project)
        self.assertTrue((self.root / "a" / "b" / "history.sqlite3").is_file())

    def test_reading_without_a_database_creates_nothing(self):
        before = files(self.root)
        # Even if the file disappears after the existence check, opening does not create it.
        with self.assertRaises(sqlite3.OperationalError), history._connect(self.db, create=False):
            pass
        self.assertEqual(history.list_projects(), [])
        self.assertEqual(history.list_runs(1), [])
        self.assertIsNone(history.get_run(1))
        self.assertIsNone(history.record("scan", self.project, {"results": []}))
        self.assertEqual(files(self.root), before)

    def test_newer_foreign_and_broken_files_are_not_written(self):
        def newer():
            history.register_project(self.project)
            sql(self.db, "PRAGMA user_version = 5")

        def foreign():
            sql(self.db, "CREATE TABLE other (x)")

        def lookalike():  # another program's file at version 1 with the same projects table
            sql(self.db, "CREATE TABLE projects (id INTEGER PRIMARY KEY, key TEXT NOT NULL "
                "UNIQUE, path TEXT NOT NULL, registered_at TEXT NOT NULL)")  # fmt: skip
            sql(self.db, "PRAGMA user_version = 1")

        def broken():
            self.db.write_bytes(b"not a database, synthetic\n" * 10)

        def empty():
            self.db.write_bytes(b"")

        report = {"status": "passed", "exit_code": 0, "results": []}
        for label, make in (("newer", newer), ("foreign", foreign), ("lookalike", lookalike),
                            ("broken", broken)):  # fmt: skip
            with self.subTest(label):
                make()
                before = self.db.read_bytes()
                with self.assertRaises((history.HistoryError, sqlite3.DatabaseError)):
                    history.register_project(self.project)
                with self.assertRaises((history.HistoryError, sqlite3.DatabaseError)):
                    history.record("scan", self.project, report)
                self.assertEqual(self.db.read_bytes(), before)
                self.db.unlink()
        empty()  # an empty file is not ours for record(); register_project() may set it up
        with self.assertRaises(history.HistoryError):
            history.record("scan", self.project, report)
        self.assertEqual(self.db.read_bytes(), b"")
        history.register_project(self.project)
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(4,)])

    def test_a_failed_first_registration_leaves_no_marks(self):
        # The application_id and user_version roll back with the schema.
        with mock.patch.object(history, "_now", side_effect=RuntimeError("synthetic")):
            with self.assertRaises(RuntimeError):
                history.register_project(self.project)
        self.assertEqual(sql(self.db, "PRAGMA application_id"), [(0,)])
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(0,)])
        self.assertEqual(sql(self.db, "SELECT count(*) FROM sqlite_master"), [(0,)])
        history.register_project(self.project)  # still an empty file it may set up
        self.assertEqual(sql(self.db, "PRAGMA application_id"), [(history.APPLICATION_ID,)])

    def test_a_lone_surrogate_and_its_escape_text_are_different_projects(self):
        # POSIX names: byte 0x80 + "x" is "\udc80x"; a folder may also be named "\\udc80x".
        # resolve() is fixed so that the same strings are tested on every OS (PurePosixPath keeps
        # the backslash a Windows path would read as a separator).
        real = Path.resolve
        a, b = self.root / "a", self.root / "b"
        a.mkdir()
        b.mkdir()
        fixed = {str(a): PurePosixPath("/p/\udc80x"), str(b): PurePosixPath("/p/\\udc80x")}
        report = {"status": "passed", "exit_code": 0, "results": []}

        def resolve(path, *args, **kwargs):
            return fixed.get(str(path)) or real(path, *args, **kwargs)

        with mock.patch.object(Path, "resolve", resolve):
            self.assertNotEqual(history._project(a)[0], history._project(b)[0])
            id_a = history.register_project(a)
            self.assertIsNone(history.record("scan", b, report))  # b is not registered
            self.assertEqual(sql(self.db, "SELECT count(*) FROM runs"), [(0,)])
            id_b = history.register_project(b)
            self.assertNotEqual(id_a, id_b)
            run_b = history.record("scan", b, report)
        self.assertEqual(history.get_run(run_b)["project_id"], id_b)
        self.assertEqual(history.list_runs(id_a), [])

    def test_project_key_is_the_resolved_path(self):
        project_id = history.register_project(self.project)
        alias = self.project / ".." / self.project.name
        self.assertEqual(history.register_project(alias), project_id)
        if os.name == "nt":  # os.path.normcase folds case on Windows only
            self.assertEqual(history.register_project(str(self.project).upper()), project_id)
        self.assertEqual(len(history.list_projects()), 1)

    def test_lone_surrogate_and_null_score_are_stored(self):
        history.register_project(self.project)
        self.new["packages"]["node_modules/\udc80x"] = package()
        self.save_locks()
        code, out, err = run(["scan", str(self.project), "--base-lock", str(self.base),
                              "--format", "json"])  # fmt: skip
        self.assertEqual((code, err), (2, ""))  # no analysis: incomplete, no score
        (run_row,) = history.list_runs(1)
        stored = history.get_run(run_row["id"])
        self.assertEqual(stored["report"], json.loads(out))
        locations = [r["location"] for r in stored["results"]]
        self.assertIn("node_modules/\\udc80x", locations)  # text, not a lone surrogate
        self.assertIn("node_modules/\udc80x", [r["location"] for r in stored["report"]["results"]])
        self.assertEqual([r["score"] for r in stored["results"]], [None, None])
        self.assertEqual(sql(self.db, "SELECT score FROM results"), [(None,), (None,)])

    def test_empty_variable_means_the_home_location(self):
        home = self.root / "home"
        os.environ["DEPBEE_HISTORY_DB"] = ""
        with mock.patch("depbee.history.Path.home", return_value=home):
            self.assertEqual(history.db_path(), home / ".local" / "share" / "depbee" /
                             "history.sqlite3")  # fmt: skip
            before = files(self.root)
            self.assertEqual(run(self.scan_argv())[2], "")
            self.assertEqual(files(self.root), before)

    def test_no_home_directory_skips_the_history(self):
        expected = run(self.scan_argv())
        os.environ.pop("DEPBEE_HISTORY_DB")
        with mock.patch("depbee.history.Path.home", side_effect=RuntimeError("no home")):
            self.assertIsNone(history.record("scan", self.project, {"results": []}))
            self.assertEqual(run(self.scan_argv()), expected)


PREVIEW = {"package_json_sha256": "a" * 64, "package_lock_sha256": "b" * 64,
           "new_package_lock_sha256": "c" * 64}  # fmt: skip


def apply_document(outcome="applied"):
    """A synthetic apply document in the shape service.apply_update returns."""
    files = [{"path": "package-lock.json", "sha256": "b" * 64, "new_sha256": "c" * 64}]
    return {
        "mode": "install", "outcome": outcome, "reason": None, "error": None,
        "confirmation_required": [{"location": "node_modules/example", "causes": ["ml_hit"]}],
        "confirmed": True, "blocked": [], "files": files if outcome == "applied" else [],
        "backup": "C:/synthetic/backups/x" if outcome == "applied" else None,
        "npm_version": "11.6.1", "npm_ci_exit_code": 0, "notices": [],
    }  # fmt: skip


class ApplyStoreTests(HistoryFixture):
    """user_version 2: the applies table, the upgrade of version 1 files and the read API."""

    def report(self):
        return scan_project(self.project, self.base, analysis=self.analysis, model_dir=Path("m"))

    def make_version_1(self, register=True):
        """A database as the version 1 code wrote it, with this project registered."""
        with contextlib.closing(sqlite3.connect(self.db, isolation_level=None)) as connection:
            for statement in history.SCHEMA.split(";"):
                if statement.strip():
                    connection.execute(statement)
            connection.execute(f"PRAGMA application_id = {history.APPLICATION_ID}")
            connection.execute("PRAGMA user_version = 1")
            if register:
                key, path = history._project(self.project)
                connection.execute("INSERT INTO projects (key, path, registered_at) VALUES "
                                   "(?, ?, '2026-11-16T00:00:00.000Z')", (key, path))  # fmt: skip

    def tables(self):
        return {name for (name,) in sql(self.db, "SELECT name FROM sqlite_master WHERE "
                                                 "type = 'table'")}  # fmt: skip

    def test_an_apply_is_stored_with_its_update_preview_run(self):
        project_id = history.register_project(self.project)
        self.assertIn("applies", self.tables())
        apply = apply_document()
        run_id = history.record("update_preview", self.project, self.report(), PREVIEW,
                                apply=apply)  # fmt: skip
        stored = history.get_run(run_id)["apply"]
        self.assertEqual(stored["apply"], apply)
        self.assertEqual(
            {k: stored[k] for k in ("run_id", "mode", "outcome", "reason", "confirmed",
                                    "package_json_sha256", "package_lock_sha256",
                                    "new_package_json_sha256", "new_package_lock_sha256",
                                    "backup", "npm_version", "npm_ci_exit_code")},
            {"run_id": run_id, "mode": "install", "outcome": "applied", "reason": None,
             "confirmed": True, "package_json_sha256": "a" * 64, "package_lock_sha256": "b" * 64,
             "new_package_json_sha256": None, "new_package_lock_sha256": "c" * 64,
             "backup": "C:/synthetic/backups/x", "npm_version": "11.6.1", "npm_ci_exit_code": 0},
        )  # fmt: skip
        self.assertTrue(stored["created_at"].endswith("Z"))
        refused = history.record("update_preview", self.project, self.report(), PREVIEW,
                                 apply=apply_document("refused"))  # fmt: skip
        self.assertEqual([a["run_id"] for a in history.list_applies(project_id)], [refused, run_id])
        self.assertEqual(len(history.list_applies(project_id, limit=1)), 1)
        self.assertIsNone(history.get_run(refused)["apply"]["new_package_lock_sha256"])
        with self.assertRaises(ValueError):
            history.record("scan", self.project, self.report(), apply=apply)

    def test_an_apply_added_later_to_its_update_preview_run(self):
        # The dashboard records the preview first and its apply after the user confirmed.
        self.assertIsNone(history.record_apply(1, PREVIEW, apply_document()))  # no database
        project_id = history.register_project(self.project)
        run_id = history.record("update_preview", self.project, self.report(), PREVIEW)
        self.assertIsNone(history.get_run(run_id)["apply"])
        apply = apply_document()
        self.assertIsInstance(history.record_apply(run_id, PREVIEW, apply), int)
        stored = history.get_run(run_id)["apply"]
        self.assertEqual(stored["apply"], apply)
        # The same columns as record() stores for the same preview and apply.
        same = history.record("update_preview", self.project, self.report(), PREVIEW, apply=apply)
        columns = [k for k in history.APPLY_COLUMNS if k not in ("id", "run_id", "created_at")]
        self.assertEqual({k: stored[k] for k in columns},
                         {k: history.get_run(same)["apply"][k] for k in columns})  # fmt: skip
        self.assertEqual([a["run_id"] for a in history.list_applies(project_id)], [same, run_id])
        before = self.db.read_bytes()
        self.assertIsNone(history.record_apply(999, PREVIEW, apply))  # no such run
        self.assertEqual(self.db.read_bytes(), before)
        scan_run = history.record("scan", self.project, self.report())
        before = self.db.read_bytes()
        for other in (run_id, same, scan_run):  # already applied, or not an update preview
            with self.subTest(run=other), self.assertRaises(ValueError):
                history.record_apply(other, PREVIEW, apply_document("refused"))
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(len(history.list_applies(project_id)), 2)

    def test_record_apply_upgrades_version_1_and_skips_without_a_home(self):
        self.make_version_1()
        run_id = history.record("update_preview", self.project, self.report(), PREVIEW)
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(4,)])  # record() upgraded it
        sql(self.db, "DROP TABLE applies")
        make_older(self.db, 2)
        sql(self.db, "PRAGMA user_version = 1")
        history.record_apply(run_id, PREVIEW, apply_document())
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(4,)])
        self.assertEqual(history.get_run(run_id)["apply"]["outcome"], "applied")
        # The run recorded before the previews table is found by its files again.
        self.assertEqual([check["id"] for check in history.list_previews(1, "a" * 64, "b" * 64)],
                         [run_id])  # fmt: skip
        os.environ.pop("DEPBEE_HISTORY_DB")
        with mock.patch("pathlib.Path.home", side_effect=RuntimeError("no home")):
            self.assertIsNone(history.record_apply(run_id, PREVIEW, apply_document()))

    def test_version_1_is_read_as_is_and_upgraded_by_the_next_write(self):
        self.make_version_1()
        before = self.db.read_bytes()
        (project,) = history.list_projects()
        self.assertEqual(history.list_runs(project["id"]), [])
        self.assertEqual(history.list_applies(project["id"]), [])
        self.assertIsNone(history.get_run(1))
        (self.root / "other").mkdir()
        self.assertIsNone(history.record("scan", self.root / "other", self.report()))
        self.assertEqual(self.db.read_bytes(), before)  # reads and skipped records do not upgrade
        run_id = history.record("update_preview", self.project, self.report(), PREVIEW,
                                apply=apply_document())  # fmt: skip
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(4,)])
        self.assertEqual(sql(self.db, "PRAGMA application_id"), [(history.APPLICATION_ID,)])
        self.assertLessEqual({"applies", "previews"}, self.tables())
        self.assertEqual(history.get_run(run_id)["apply"]["outcome"], "applied")

    def test_registering_also_upgrades_version_1(self):
        self.make_version_1(register=False)
        history.register_project(self.project)
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(4,)])
        self.assertLessEqual({"applies", "previews"}, self.tables())

    def test_a_failed_upgrading_write_leaves_version_1(self):
        self.make_version_1()
        real = history._now
        calls = []

        def now():  # the run's time is taken before the transaction, the apply's inside it
            calls.append(1)
            if len(calls) > 1:
                raise RuntimeError("synthetic")
            return real()

        with mock.patch.object(history, "_now", now), self.assertRaises(RuntimeError):
            history.record("update_preview", self.project, self.report(), PREVIEW,
                           apply=apply_document())  # fmt: skip
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(1,)])
        self.assertFalse({"applies", "previews"} & self.tables())
        self.assertEqual(sql(self.db, "SELECT count(*) FROM runs"), [(0,)])


def preview_document(targets=None, files=("a" * 64, "b" * 64)):
    """A synthetic update preview document for these targets, made from files with these two
    SHA-256 (package.json, package-lock.json)."""
    return {**PREVIEW, "targets": targets, "package_json_sha256": files[0],
            "package_lock_sha256": files[1]}  # fmt: skip


class PreviewStoreTests(HistoryFixture):
    """user_version 3: the previews table. A project's update previews of given package.json and
    package-lock.json files are found through it, however many other runs the project has."""

    FILES = ("a" * 64, "b" * 64)
    OTHER = ("d" * 64, "e" * 64)

    def setUp(self):
        super().setUp()
        self.project_id = history.register_project(self.project)
        self.report = scan_project(self.project, self.base, analysis=self.analysis,
                                   model_dir=Path("m"))  # fmt: skip
        self.nothing = {**self.report, "results": []}
        self.location = self.report["results"][0]["location"]

    def check(self, targets=None, files=FILES, report=None, project=None):
        return history.record("update_preview", project or self.project, report or self.report,
                              preview_document(targets, files))  # fmt: skip

    def found(self, files=FILES, project_id=None):
        checks = history.list_previews(project_id or self.project_id, *files)
        return [(check["id"], check["targets"], check["locations"]) for check in checks]

    def make_version_2(self):
        """The database as the version 2 code left it: without what versions 3 and 4 added."""
        make_older(self.db, 2)

    def test_previews_of_the_same_files_newest_first_down_to_one_of_everything(self):
        everything = self.check()
        named = self.check(["example"])
        self.check(files=self.OTHER)
        history.record("scan", self.project, self.report)  # not an update preview
        none = self.check(["other"], report=self.nothing)
        self.assertEqual(self.found(), [(none, ["other"], []), (named, ["example"], [self.location]),
                                        (everything, None, [self.location])])  # fmt: skip
        self.assertEqual(
            [check["created_at"] for check in history.list_previews(self.project_id, *self.FILES)],
            [history.get_run(run)["created_at"] for run in (none, named, everything)],
        )
        for _ in range(12):  # runs in between do not hide them
            self.check(["other"], files=self.OTHER, report=self.nothing)
            history.record("scan", self.project, self.report)
        self.assertEqual([check[0] for check in self.found()], [none, named, everything])
        newer = self.check()  # a later preview of everything: the older ones are not read
        self.assertEqual(self.found(), [(newer, None, [self.location])])
        self.assertEqual(len(self.found(self.OTHER)), 13)
        self.assertEqual(self.found(("f" * 64, "b" * 64)), [])  # another package.json
        self.assertEqual(history.list_previews(self.project_id + 1, *self.FILES), [])

    def test_previews_of_another_project_with_the_same_files_are_not_found(self):
        (self.root / "other").mkdir()
        other_id = history.register_project(self.root / "other")
        mine = self.check()
        theirs = self.check(["example"], project=self.root / "other")
        self.assertEqual(self.found(), [(mine, None, [self.location])])
        self.assertEqual(self.found(project_id=other_id), [(theirs, ["example"], [self.location])])

    def test_runs_of_one_kind(self):
        preview = self.check()
        scan = history.record("scan", self.project, self.report)
        self.assertEqual([run["id"] for run in history.list_runs(self.project_id)], [scan, preview])
        self.assertEqual(
            [run["id"] for run in history.list_runs(self.project_id, kind="update_preview")],
            [preview],
        )
        self.assertEqual([run["id"] for run in history.list_runs(self.project_id, 1, "scan")],
                         [scan])  # fmt: skip

    def test_a_preview_without_its_hashes_is_stored_and_never_found(self):
        # Reports and previews are stored as given; only a document's own strings are indexed.
        bare = history.record("update_preview", self.project, self.report)
        odd = history.record("update_preview", self.project, self.report,
                             {"package_json_sha256": 5, "package_lock_sha256": None,
                              "targets": "example"})  # fmt: skip
        self.assertEqual(
            sql(self.db, "SELECT run_id, package_json_sha256, package_lock_sha256, targets "
                         "FROM previews ORDER BY run_id"),
            [(bare, None, None, None), (odd, None, None, '"example"')],
        )  # fmt: skip
        self.assertEqual(self.found(), [])
        self.assertIsNone(history.get_run(bare)["preview"])
        self.assertEqual(history.list_runs(self.project_id, 1, "update_preview")[0]["id"], odd)

    def test_a_version_2_file_is_read_as_it_is_and_indexed_by_the_next_write(self):
        everything, named = self.check(), self.check(["example"])
        stale = self.check(files=self.OTHER)
        bare = history.record("update_preview", self.project, self.report)
        broken = self.check()  # its stored document will not be JSON
        scan = history.record("scan", self.project, self.report)
        self.make_version_2()
        sql(self.db, "UPDATE runs SET preview = 'not a document' WHERE id = ?", broken)
        before = self.db.read_bytes()
        expected = [(named, ["example"], [self.location]), (everything, None, [self.location])]
        self.assertEqual(self.found(), expected)  # found by reading the stored previews
        self.assertEqual([check[0] for check in self.found(self.OTHER)], [stale])
        self.assertEqual(history.list_runs(self.project_id, 1, "update_preview")[0]["id"], broken)
        self.assertEqual(self.db.read_bytes(), before)  # reads do not upgrade
        self.assertEqual(history.record("scan", self.project, self.report), scan + 1)
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(4,)])
        self.assertEqual(
            sql(self.db, "SELECT run_id, project_id, package_json_sha256, package_lock_sha256, "
                         "targets FROM previews ORDER BY run_id"),
            [(everything, self.project_id, "a" * 64, "b" * 64, None),
             (named, self.project_id, "a" * 64, "b" * 64, '["example"]'),
             (stale, self.project_id, "d" * 64, "e" * 64, None),
             (bare, self.project_id, None, None, None),
             (broken, self.project_id, None, None, None)],
        )  # fmt: skip
        self.assertEqual(
            sql(self.db, "SELECT count(*) FROM previews p JOIN runs r ON r.id = p.run_id "
                         "WHERE p.created_at = r.created_at"), [(5,)])  # fmt: skip
        self.assertEqual(self.found(), expected)  # the same answer through the index
        self.assertEqual([check[0] for check in self.found(self.OTHER)], [stale])

    def test_a_failed_upgrade_leaves_version_2(self):
        run = self.check()
        self.make_version_2()
        (self.root / "other").mkdir()
        # The table and its rows roll back with the registration that fails after them.
        with mock.patch.object(history, "_now", side_effect=RuntimeError("synthetic")):
            with self.assertRaises(RuntimeError):
                history.register_project(self.root / "other")
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(2,)])
        self.assertEqual(sql(self.db, "SELECT name FROM sqlite_master WHERE name LIKE 'previews%' "
                                      "OR name = 'runs_by_kind'"), [])  # fmt: skip
        self.assertEqual(len(history.list_projects()), 1)
        self.assertEqual([check[0] for check in self.found()], [run])


class UnregisterTests(HistoryFixture):
    """user_version 4: a project taken off the list. Its row is marked and nothing is deleted;
    nothing more is recorded for it, and its folder registered again is the same project."""

    ROWS = ("projects", "runs", "results", "applies", "previews")

    def setUp(self):
        super().setUp()
        self.other = self.root / "other"
        self.other.mkdir()
        self.report = scan_project(self.project, self.base, analysis=self.analysis,
                                   model_dir=Path("m"))  # fmt: skip
        # What an unregistration may not touch: the folders, a source file, a backup of an
        # apply (kept beside the history file) and whatever else the run's folder holds.
        (self.project / "index.js").write_text("module.exports = 1;\n", "utf-8")
        backup = self.root / "backups" / "20261128T000000Z-synthetic"
        backup.mkdir(parents=True)
        (backup / "package-lock.json").write_text("{}\n", "utf-8")

    def stored(self):
        return {name: sql(self.db, f"SELECT count(*) FROM {name}")[0][0] for name in self.ROWS}

    def outside(self):
        """Everything but the history file, what SQLite keeps beside it, and depbee's own
        lock files beside it (locks/, where the install lock is too)."""
        return tree(self.root, self.db, self.db.with_name(self.db.name + "-journal"),
                    self.root / "locks")  # fmt: skip

    def two_projects(self):
        """Two registered projects: the first with a scan and an applied update preview, the
        second with a scan."""
        first, second = (history.register_project(p) for p in (self.project, self.other))
        scan = history.record("scan", self.project, self.report)
        applied = history.record("update_preview", self.project, self.report,
                                 preview_document(), apply=apply_document())  # fmt: skip
        kept = history.record("scan", self.other, self.report)
        return first, second, scan, applied, kept

    def test_one_project_leaves_the_list_and_every_row_and_file_stays(self):
        first, second, scan, applied, kept = self.two_projects()
        rows, files_before = self.stored(), self.outside()
        self.assertIs(history.unregister_project(first), True)
        self.assertEqual([p["id"] for p in history.list_projects()], [second])
        self.assertEqual(self.stored(), rows)  # marked, never deleted
        self.assertEqual(self.outside(), files_before)
        (marked,) = sql(self.db, "SELECT unregistered_at FROM projects WHERE id = ?", first)
        self.assertRegex(marked[0], r"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\Z")
        self.assertEqual(
            sql(self.db, "SELECT unregistered_at FROM projects WHERE id = ?", second), [(None,)]
        )
        # Its runs are stored and not found; the other project's are as before.
        self.assertIsNone(history.get_run(scan))
        self.assertIsNone(history.get_run(applied))
        self.assertEqual(history.get_run(kept)["project_id"], second)
        self.assertEqual([run["id"] for run in history.list_runs(second)], [kept])
        # Done once: a second call, an id that never was and a missing file change nothing.
        before = self.db.read_bytes()
        self.assertIs(history.unregister_project(first), False)
        self.assertIs(history.unregister_project(99), False)
        self.assertEqual(self.db.read_bytes(), before)
        self.db.unlink()
        self.assertIs(history.unregister_project(first), False)
        self.assertFalse(self.db.exists())

    def test_a_folder_that_is_gone_is_unregistered_without_looking_for_it(self):
        gone = history.register_project(self.other)
        self.other.rmdir()
        # By its id alone: the project's path is neither resolved nor looked at.
        with mock.patch.object(history, "_project", side_effect=AssertionError("no path")), \
                mock.patch.object(Path, "is_dir", side_effect=AssertionError("no folder")):
            self.assertIs(history.unregister_project(gone), True)
        self.assertEqual(history.list_projects(), [])
        self.assertFalse(self.other.exists())

    def test_nothing_is_recorded_for_it_and_no_run_brings_it_back(self):
        first, second, *_ = self.two_projects()
        history.unregister_project(first)
        rows, before = self.stored(), self.db.read_bytes()
        self.assertIsNone(history.record("scan", self.project, self.report))
        self.assertIsNone(history.record("update_preview", self.project, self.report,
                                         preview_document(), apply=apply_document()))  # fmt: skip
        # The CLI's own scan of that folder prints its report as without a history, and stores
        # nothing: neither a run nor the project.
        code, out, err = run(self.scan_argv())
        self.assertEqual((code, err), (1, ""))
        self.assertEqual(json.loads(out)["status"], "flagged")
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(self.stored(), rows)
        self.assertEqual([p["id"] for p in history.list_projects()], [second])
        # The other project is still recorded.
        self.assertIsNotNone(history.record("scan", self.other, self.report))

    def test_a_run_that_ends_after_its_project_left_is_not_stored(self):
        # The project is asked for once more under the write lock: it may have left the list
        # between record()'s first look and its write.
        first, *_ = self.two_projects()
        rows = self.stored()
        upgrade = history._upgrade

        def leaving(connection, version):
            upgrade(connection, version)
            connection.execute("UPDATE projects SET unregistered_at = 'x' WHERE id = ?", (first,))

        with mock.patch.object(history, "_upgrade", side_effect=leaving):
            self.assertIsNone(history.record("scan", self.project, self.report))
        self.assertEqual(self.stored(), rows)

    def test_registering_the_folder_again_is_the_same_project_with_its_runs(self):
        first, second, scan, applied, _ = self.two_projects()
        (was,) = history.list_projects()[:1]
        history.unregister_project(first)
        # No id is given twice: a project registered meanwhile is a new one without runs, also
        # after the newest project of all was unregistered.
        third = history.register_project(self.root)
        self.assertEqual(third, second + 1)
        history.unregister_project(third)
        fourth = self.root / "fourth"
        fourth.mkdir()
        self.assertEqual(history.register_project(fourth), third + 1)
        self.assertEqual(history.list_runs(third + 1), [])
        rows = self.stored()
        self.assertEqual(history.register_project(self.project), first)
        self.assertEqual({**rows}, self.stored())  # the row it had, not a new one
        listed = history.list_projects()
        self.assertEqual([p["id"] for p in listed], [first, second, third + 1])  # its old place
        self.assertEqual(listed[0]["path"], was["path"])
        self.assertGreater(listed[0]["registered_at"], was["registered_at"])
        self.assertEqual([run["id"] for run in history.list_runs(first)], [applied, scan])
        self.assertEqual(history.get_run(applied)["apply"]["outcome"], "applied")
        self.assertEqual(len(history.list_applies(first)), 1)
        self.assertEqual(history.record("scan", self.project, self.report), self.runs())
        # Registering it once more keeps this registration.
        again = history.list_projects()[0]
        self.assertEqual(history.register_project(self.project), first)
        self.assertEqual(history.list_projects()[0], again)

    def test_older_files_are_read_as_they_are_and_upgraded_by_the_unregistration(self):
        for version in (3, 2, 1):
            with self.subTest(version):
                if version == 1:
                    ApplyStoreTests.make_version_1(self)
                    first = 1
                else:
                    first, second, scan, *_ = self.two_projects()
                    make_older(self.db, version)
                before = self.db.read_bytes()
                # Every project of an older file is registered, and reading does not upgrade.
                self.assertIn(first, [p["id"] for p in history.list_projects()])
                if version > 1:
                    self.assertEqual(history.get_run(scan)["project_id"], first)
                self.assertIs(history.unregister_project(99), False)
                self.assertEqual(self.db.read_bytes(), before)
                rows = {name: count for name, count in self.stored_of(version).items()}
                self.assertIs(history.unregister_project(first), True)
                self.assertEqual(sql(self.db, "PRAGMA user_version"), [(4,)])
                self.assertEqual({k: v for k, v in self.stored().items() if k in rows}, rows)
                self.assertNotIn(first, [p["id"] for p in history.list_projects()])
                self.assertIsNone(history.record("scan", self.project, self.report))
                self.assertEqual(history.register_project(self.project), first)
                self.assertIn(first, [p["id"] for p in history.list_projects()])
                if version > 1:
                    self.assertEqual(history.get_run(scan)["project_id"], first)
                self.db.unlink()

    def stored_of(self, version):
        """stored() of a file of an older version, which lacks the later tables."""
        names = self.ROWS[: {1: 3, 2: 4, 3: 5}[version]]
        return {name: sql(self.db, f"SELECT count(*) FROM {name}")[0][0] for name in names}

    def columns(self):
        return [row[1] for row in sql(self.db, "PRAGMA table_info(projects)")]

    def test_a_file_the_version_3_code_wrote_keeps_all_it_holds(self):
        first, run_id = make_version_3(self.db, self.project)
        before, rows = self.db.read_bytes(), self.stored()
        self.assertEqual(self.columns(), ["id", "key", "path", "registered_at"])
        (was,) = history.list_projects()
        stored = history.get_run(run_id)
        self.assertEqual((stored["project_id"], stored["apply"]["outcome"]), (first, "applied"))
        self.assertEqual(self.db.read_bytes(), before)  # read as it is
        # An unregistration that fails after the upgrade leaves the version 3 file whole: the
        # new column, the version and the mark roll back together.
        with mock.patch.object(history, "_now", side_effect=RuntimeError("synthetic")):
            with self.assertRaises(RuntimeError):
                history.unregister_project(first)
        self.assertEqual(self.columns(), ["id", "key", "path", "registered_at"])
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(3,)])
        self.assertEqual(history.list_projects(), [was])
        # The one that succeeds upgrades it and deletes nothing.
        self.assertIs(history.unregister_project(first), True)
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(4,)])
        self.assertEqual(self.columns()[-2:], ["unregistered_at", "generation"])
        self.assertEqual((self.stored(), history.list_projects()), (rows, []))
        self.assertIsNone(history.get_run(run_id))
        self.assertIsNone(history.record("scan", self.project, self.report))
        # Registered again, the project has the run, the preview and the apply it had.
        self.assertEqual(history.register_project(self.project), first)
        self.assertEqual(history.get_run(run_id), stored)
        self.assertEqual([c["id"] for c in history.list_previews(first, "a" * 64, "b" * 64)],
                         [run_id])  # fmt: skip
        self.assertEqual(history.latest_applies()[first]["run_id"], run_id)
        self.assertEqual(self.stored(), rows)

    def test_registering_a_folder_unregistered_in_an_older_looking_file(self):
        # A version 3 file with a registered project: registering upgrades it and changes no
        # registration (no row is unregistered in a file that never had the column).
        first, second, *_ = self.two_projects()
        make_older(self.db, 3)
        was = history.list_projects()
        self.assertEqual(history.register_project(self.project), first)
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(4,)])
        self.assertEqual(history.list_projects(), was)

    def generations(self):
        return {project["id"]: project["generation"] for project in history.list_projects()}

    def test_each_unregistration_raises_the_generation_of_that_project_alone(self):
        first, second, *_ = self.two_projects()
        self.assertEqual(self.generations(), {first: 0, second: 0})
        history.unregister_project(first)
        self.assertEqual(self.generations(), {second: 0})
        history.register_project(self.project)
        self.assertEqual(self.generations(), {first: 1, second: 0})
        history.register_project(self.project)  # registering what is registered changes nothing
        history.unregister_project(first)
        history.register_project(self.project)
        self.assertEqual(self.generations(), {first: 2, second: 0})
        # A file of an older version has no generation: 0, read without a write.
        make_older(self.db, 3)
        before = self.db.read_bytes()
        self.assertEqual(self.generations(), {first: 0, second: 0})
        history.hold_project(first, 0).release()
        self.assertEqual(self.db.read_bytes(), before)

    def test_a_hold_is_refused_for_a_project_that_left_the_list_also_once_it_is_back(self):
        first, second, *_ = self.two_projects()
        history.hold_project(first, 0).release()
        history.unregister_project(first)
        for when in ("unregistered", "registered again"):
            with self.subTest(when), self.assertRaises(history.ProjectGone):
                history.hold_project(first, 0)
            history.register_project(self.project)
        with history.hold_project(first, 1):  # the registration of now
            pass
        for project_id, generation in ((second, 1), (99, 0)):
            with self.assertRaises(history.ProjectGone):
                history.hold_project(project_id, generation)
        history.hold_project(first, 1).release()  # a refusal left nothing held
        self.db.unlink()
        with self.assertRaises(history.ProjectGone):
            history.hold_project(first, 1)
        self.assertFalse(self.db.exists())

    def test_work_on_a_project_and_its_unregistration_never_overlap(self):
        first, second, *_ = self.two_projects()
        hold = history.hold_project(first, 0)
        before = self.db.read_bytes()
        with self.assertRaises(history.ProjectBusy):
            history.unregister_project(first)
        with self.assertRaises(history.ProjectBusy):  # nor two pieces of work on one project
            history.hold_project(first, 0)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(sorted(self.generations()), [first, second])
        # Another project is free meanwhile: for work, and to leave the list.
        history.hold_project(second, 0).release()
        self.assertIs(history.unregister_project(second), True)
        # The database is not locked meanwhile: a run of the held project is recorded.
        self.assertIsNotNone(history.record("scan", self.project, self.report))
        hold.release()
        hold.release()  # once is enough, twice is harmless
        self.assertIs(history.unregister_project(first), True)
        # Only lock files of these two projects of this history file were made.
        names = sorted(path.name for path in (self.root / "locks").iterdir())
        self.assertEqual(len(names), 2)
        for name, project_id in zip(names, sorted((first, second), key=str), strict=True):
            self.assertRegex(name, rf"\Aproject-[0-9a-f]{{32}}-{project_id}\.lock\Z")
        self.assertEqual({name[:40] for name in names}, {names[0][:40]})

    def test_a_hold_is_of_one_history_file(self):
        # Two history files in one folder each have a project 1: neither blocks the other.
        first, *_ = self.two_projects()
        mine = history.hold_project(first, 0)
        self.addCleanup(mine.release)
        with mock.patch.dict(os.environ, {"DEPBEE_HISTORY_DB": str(self.root / "second.sqlite3")}):
            self.assertEqual(history.register_project(self.project), first)
            history.hold_project(first, 0).release()
            self.assertIs(history.unregister_project(first), True)
        with self.assertRaises(history.ProjectBusy):
            history.unregister_project(first)

    def test_every_path_to_one_history_file_reaches_the_same_hold(self):
        # A link to the history file in another folder is the same history: work held through
        # one path stops an unregistration through the other, and the other way round.
        first, *_ = self.two_projects()
        aliases = self.root / "aliases"
        aliases.mkdir()
        alias = aliases / "linked.sqlite3"
        try:
            alias.symlink_to(self.db)
        except OSError:
            self.skipTest("this account cannot create symbolic links")
        for held_by, asked_by in ((self.db, alias), (alias, self.db)):
            with self.subTest(held_by=held_by.name):
                with mock.patch.dict(os.environ, {"DEPBEE_HISTORY_DB": str(held_by)}):
                    hold = history.hold_project(first, 0)
                with mock.patch.dict(os.environ, {"DEPBEE_HISTORY_DB": str(asked_by)}):
                    with self.assertRaises(history.ProjectBusy):
                        history.unregister_project(first)
                    with self.assertRaises(history.ProjectBusy):
                        history.hold_project(first, 0)
                hold.release()
        # One lock file, beside the real history file; none beside the link.
        self.assertEqual(len(list((self.root / "locks").iterdir())), 1)
        self.assertFalse((aliases / "locks").exists())
        with mock.patch.dict(os.environ, {"DEPBEE_HISTORY_DB": str(alias)}):
            self.assertIs(history.unregister_project(first), True)
        self.assertNotIn(first, self.generations())

    def test_another_process_holds_the_project_until_it_ends_or_dies(self):
        first, second, *_ = self.two_projects()
        source = str(Path(history.__file__).resolve().parents[1])
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from depbee import history; "
                "hold = history.hold_project(int(sys.argv[2]), 0); "
                "print('held', history.__file__, flush=True); sys.stdin.read()")  # fmt: skip
        child = subprocess.Popen([sys.executable, "-c", code, source, str(first)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                 encoding="utf-8")  # fmt: skip
        self.addCleanup(lambda: (child.kill(), child.wait(), child.stdout.close(),
                                 child.stdin.close()))  # fmt: skip
        said = child.stdout.readline().split(" ", 1)
        self.assertEqual(said[0], "held", said)
        self.assertEqual(Path(said[1].strip()).resolve(), Path(history.__file__).resolve())
        before = self.db.read_bytes()
        with self.assertRaises(history.ProjectBusy):
            history.unregister_project(first)
        with self.assertRaises(history.ProjectBusy):
            history.hold_project(first, 0)
        self.assertEqual(self.db.read_bytes(), before)
        history.hold_project(second, 0).release()  # the other project is free
        # The process dies without releasing: the system frees the hold, nothing is left to
        # clean up, and the project can leave the list.
        child.kill()
        child.wait()
        self.assertIs(history.unregister_project(first), True)
        self.assertEqual(self.generations(), {second: 0})

    def test_no_apply_is_added_to_what_an_unregistered_project_has_stored(self):
        first, *_ = self.two_projects()
        run_id = history.record("update_preview", self.project, self.report, preview_document())
        history.unregister_project(first)
        rows, before = self.stored(), self.db.read_bytes()
        self.assertIsNone(history.record_apply(run_id, preview_document(), apply_document()))
        self.assertEqual((self.stored(), self.db.read_bytes()), (rows, before))
        # Registered again, the run is the project's and takes its apply.
        history.register_project(self.project)
        self.assertIsNotNone(history.record_apply(run_id, preview_document(), apply_document()))
        self.assertEqual(history.get_run(run_id)["apply"]["outcome"], "applied")

    def test_an_unregistration_that_fails_changes_nothing(self):
        first, *_ = self.two_projects()

        def locked():
            holder = sqlite3.connect(self.db, isolation_level=None)
            holder.execute("BEGIN IMMEDIATE")  # another writer holds the lock
            self.addCleanup(holder.close)
            return holder.close

        def newer():
            sql(self.db, "PRAGMA user_version = 5")
            return lambda: sql(self.db, "PRAGMA user_version = 4")

        def older_and_broken():  # the upgrade rolls back with the mark that fails after it
            make_older(self.db, 3)
            patcher = mock.patch.object(history, "_now", side_effect=RuntimeError("synthetic"))
            patcher.start()
            self.addCleanup(patcher.stop)  # also when the case fails before its undo
            return lambda: None

        for label, make, error in (
            ("locked", locked, sqlite3.OperationalError), ("newer", newer, history.HistoryError),
            ("older and broken", older_and_broken, RuntimeError),
        ):  # fmt: skip
            with self.subTest(label), mock.patch.object(history, "TIMEOUT", 0.1):
                undo = make()
                before = self.db.read_bytes()
                with self.assertRaises(error):
                    history.unregister_project(first)
                self.assertEqual(self.db.read_bytes(), before)
                undo()
                self.assertIn(first, [p["id"] for p in history.list_projects()])
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(3,)])  # as the last case left it


class CliTests(HistoryFixture):
    def test_without_a_database_nothing_is_created(self):
        os.environ["DEPBEE_HISTORY_DB"] = str(self.root / "deep" / "history.sqlite3")
        before = files(self.root)
        for fmt in FORMATS:
            run(self.scan_argv(fmt))
        self.assertEqual(files(self.root), before)

    def test_unregistered_project_is_not_recorded(self):
        expected = self.baseline()
        (self.root / "other").mkdir()
        history.register_project(self.root / "other")
        before = self.db.read_bytes()
        self.assertEqual({fmt: run(self.scan_argv(fmt)) for fmt in FORMATS}, expected)
        self.assertEqual((self.runs(), self.db.read_bytes()), (0, before))

    def test_registered_scan_is_recorded_with_the_same_output(self):
        expected = self.baseline()
        history.register_project(self.project)
        for count, fmt in enumerate(FORMATS, 1):
            with self.subTest(format=fmt):
                self.assertEqual(run(self.scan_argv(fmt)), expected[fmt])  # bytes as without
                self.assertEqual(self.runs(), count)
        (newest, *_) = history.list_runs(1)
        stored = history.get_run(newest["id"])
        self.assertEqual(stored["report"], json.loads(expected["json"][1]))
        self.assertEqual((stored["kind"], stored["base_ref"], stored["base_lock"]),
                         ("scan", None, True))  # fmt: skip

    def test_plan_check_and_failed_runs_are_not_recorded(self):
        history.register_project(self.project)
        taken = self.root / "taken.json"
        taken.write_text("{}", encoding="utf-8")
        for argv in (
            ["plan", str(self.project), "--base-lock", str(self.base)],
            ["scan", str(self.project), "--base-lock", str(self.root / "missing.json")],
            [*self.scan_argv(), "--output", str(taken)],
            ["check", "example@latest"],
        ):
            with self.subTest(argv[0]):
                code, _, err = run(argv)
                self.assertEqual(code, 0 if argv[0] == "plan" else 2)
                self.assertNotIn(HISTORY_FAILED, err)
        self.assertEqual(self.runs(), 0)

    def test_a_failed_record_keeps_stdout_and_exit_code(self):
        expected = self.baseline()

        def locked():
            history.register_project(self.project)
            holder = sqlite3.connect(self.db, isolation_level=None)
            holder.execute("BEGIN IMMEDIATE")  # another writer holds the lock
            self.addCleanup(holder.close)
            return lambda: holder.close()

        def read_only():
            history.register_project(self.project)
            os.chmod(self.db, stat.S_IREAD)

            def restore():  # also on failure, so that the run folder can be removed
                if self.db.exists():
                    os.chmod(self.db, stat.S_IREAD | stat.S_IWRITE)

            self.addCleanup(restore)
            return restore

        def broken():
            self.db.write_bytes(b"not a database, synthetic\n" * 10)

        def newer():
            history.register_project(self.project)
            sql(self.db, "PRAGMA user_version = 5")

        def foreign():
            sql(self.db, "CREATE TABLE other (x)")

        for label, make in (("locked", locked), ("read-only", read_only), ("broken", broken),
                            ("newer", newer), ("foreign", foreign)):  # fmt: skip
            with self.subTest(label), mock.patch.object(history, "TIMEOUT", 0.1):
                undo = make()
                for fmt in FORMATS:
                    code, out, err = run(self.scan_argv(fmt))
                    self.assertEqual((code, out), expected[fmt][:2])
                    self.assertEqual(err, HISTORY_FAILED + "\n")
                if undo:
                    undo()
                if label in ("locked", "read-only"):
                    self.assertEqual(self.runs(), 0)
                self.db.unlink()

    def test_connections_are_closed(self):
        history.register_project(self.project)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.assertEqual(run(self.scan_argv())[2], "")
            history.list_projects(), history.list_runs(1), history.get_run(1)
            sql(self.db, "PRAGMA user_version = 5")
            self.assertEqual(run(self.scan_argv())[2], HISTORY_FAILED + "\n")
            gc.collect()
        self.assertFalse([w for w in caught if issubclass(w.category, ResourceWarning)])
        os.remove(self.db)  # on Windows an open connection would keep the file


class EntryPointTests(MCPFixture):
    def test_every_result_kind_is_counted_and_check_and_mcp_are_not_recorded(self):
        db = Path(os.environ["DEPBEE_HISTORY_DB"])
        history.register_project(self.project)
        self.mixed()
        code, out, err = run(["scan", str(self.project), "--base-lock", str(self.base),
                              "--extract", "--model-dir", "m", "--format", "json"])  # fmt: skip
        self.assertEqual(err, "")
        report = json.loads(out)
        (stored,) = history.list_runs(1)
        self.assertEqual((stored["exit_code"], stored["status"]), (code, report["status"]))
        statuses = [row["status"] for row in report["results"]]
        self.assertEqual(stored["counts"], {s: statuses.count(s) for s in history.STATUSES})
        self.assertEqual(set(statuses), set(history.STATUSES))
        rows = history.get_run(stored["id"])["results"]
        self.assertEqual(
            [(r["location"], r["status"], r["score"]) for r in rows],
            [(r["location"], r["status"], r["score"]) for r in report["results"]],
        )
        self.assertIn(None, [r["score"] for r in rows])
        # The MCP tools and check run the same services but never record.
        mcp.scan_lockfile(str(self.project), str(self.base), model_dir=Path("m"))
        self.backend = FakeBackend(
            packument(dict(TIMES)), features={"signal": 0.2, "obfChangedFileCount": 2}
        )
        self.assertEqual(run(["check", "example@1.1.0", "--model-dir", "m"])[0], 0)
        mcp.check_package("example@1.1.0", model_dir=Path("m"))
        self.assertEqual(sql(db, "SELECT count(*) FROM runs"), [(1,)])


class UpdateRecordTests(UpdateFixture):
    def test_registered_update_preview_is_recorded_with_the_same_output(self):
        db = Path(os.environ["DEPBEE_HISTORY_DB"])
        # Fixed times so that the outputs can be compared byte for byte.
        with mock.patch("depbee.service.elapsed_since", return_value=0.0):
            expected = {fmt: self.cli("--format", fmt) for fmt in FORMATS}
            self.assertFalse(db.exists())
            history.register_project(self.upd)
            for fmt in FORMATS:
                with self.subTest(format=fmt):
                    self.assertEqual(self.cli("--format", fmt), expected[fmt])
        (newest, *older) = history.list_runs(1)
        self.assertEqual(len(older), 2)
        stored = history.get_run(newest["id"])
        output = json.loads(expected["json"][1])
        self.assertEqual((stored["kind"], stored["base_ref"], stored["base_lock"]),
                         ("update_preview", None, None))  # fmt: skip
        self.assertEqual(stored["preview"], output["preview"])
        self.assertEqual(stored["report"], output["report"])
        self.assertEqual(stored["exit_code"], expected["json"][0])
        # Only the preview's hashes are kept, never the new lockfile itself.
        self.assertNotIn(self.head.read_text(encoding="utf-8"), db.read_bytes().decode("latin-1"))
