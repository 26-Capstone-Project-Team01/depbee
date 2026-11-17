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
    def test_register_record_and_read_back(self):
        project_id = history.register_project(self.project)
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(2,)])
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
            sql(self.db, "PRAGMA user_version = 3")

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
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(2,)])

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
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(2,)])  # record() upgraded it
        sql(self.db, "DROP TABLE applies")
        sql(self.db, "PRAGMA user_version = 1")
        history.record_apply(run_id, PREVIEW, apply_document())
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(2,)])
        self.assertEqual(history.get_run(run_id)["apply"]["outcome"], "applied")
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
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(2,)])
        self.assertEqual(sql(self.db, "PRAGMA application_id"), [(history.APPLICATION_ID,)])
        self.assertIn("applies", self.tables())
        self.assertEqual(history.get_run(run_id)["apply"]["outcome"], "applied")

    def test_registering_also_upgrades_version_1(self):
        self.make_version_1(register=False)
        history.register_project(self.project)
        self.assertEqual(sql(self.db, "PRAGMA user_version"), [(2,)])
        self.assertIn("applies", self.tables())

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
        self.assertNotIn("applies", self.tables())
        self.assertEqual(sql(self.db, "SELECT count(*) FROM runs"), [(0,)])


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
            sql(self.db, "PRAGMA user_version = 3")

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
            sql(self.db, "PRAGMA user_version = 3")
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
