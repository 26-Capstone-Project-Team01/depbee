"""Dashboard overview (the session's first page): which page the root address opens, what the
overview is given of each registered project (`portfolio`), that a registration that did not
happen stays on the management page, the start address and the stylesheets that are served.

Backend only. Each request is a real one through the in-process TestClient; what a view renders
(the template's name and the keyword arguments of its render) is captured by replacing Jinja's
get_template in the test alone, so nothing here needs the overview's markup. Synthetic only, as
in test_dashboard.py: stored reports of pipeline.scan() with a fake predictor, in each test
run's folder; no server, dialog, npm or registry.
"""

import contextlib
import io
import itertools
import shutil
import sqlite3
from unittest import mock

import test_dashboard  # the modules: their test classes, imported by name, would run again here
import test_dashboard_picker
from test_history import sql

from depbee import history
from depbee.cli import MODE_LABELS, OUTCOME_LABELS, OVERALL_LABELS, main

S, SESSION, PREVIEW = test_dashboard.S, test_dashboard.SESSION, test_dashboard.PREVIEW
RUN = ("id", "created_at", "status", "counts", "cell")  # what the overview is given of a run


class OverviewTests(test_dashboard.DashboardFixture):
    pick = test_dashboard_picker.PickRouteTests.pick

    def rendered(self, request):
        """(response, template name, template context) of request(), one request that renders
        a page."""
        template = mock.Mock(**{"render.return_value": "<html></html>"})
        with mock.patch.object(self.app.ENV, "get_template", return_value=template) as named:
            response = request()
        (name,) = named.call_args.args
        return response, name, template.render.call_args.kwargs

    def view(self, url):
        response, name, context = self.rendered(lambda: self.get(url))
        self.assertEqual(response.status_code, 200, url)
        return name, context

    def another(self, name="second"):
        """(folder, id) of one more registered project."""
        folder = self.root / name
        folder.mkdir()
        (folder / "package-lock.json").write_bytes(self.head.read_bytes())
        return folder, history.register_project(folder)

    def test_the_first_page_is_the_overview_once_a_project_is_registered(self):
        for url in ("/", "/?manage=1"):  # nothing registered: the page that registers
            name, context = self.view(url)
            self.assertEqual((name, context["section"], context["tabs"]),
                             ("projects.html", "manage", []), url)  # fmt: skip
            self.assertNotIn("portfolio", context)
        self.assertFalse(self.db.exists())  # looking creates no history
        first = history.register_project(self.project)
        name, context = self.view("/")
        self.assertEqual((name, context["section"]), ("overview.html", "overview"))
        self.assertEqual(context["portfolio"], [{
            "id": first, "name": "project", "path": str(self.project.resolve()), "found": True,
            "scan": None, "preview": None, "apply": None}])  # fmt: skip
        self.assertEqual([tab["id"] for tab in context["tabs"]], [first])
        _, second = self.another()
        # Only manage=1, given once, asks for the management page.
        for url in ("/", "/?manage=0", "/?manage=", "/?manage=1&manage=1", "/?other=1"):
            name, context = self.view(url)
            self.assertEqual(name, "overview.html", url)
            self.assertEqual([(row["id"], row["name"]) for row in context["portfolio"]],
                             [(first, "project"), (second, "second")], url)  # fmt: skip
        name, context = self.view("/?manage=1")
        self.assertEqual((name, context["section"], len(context["tabs"])),
                         ("projects.html", "manage", 2))  # fmt: skip
        # Every other page is where it was.
        for url, expected in ((f"/projects/{first}", "project.html"), ("/model", "model.html"),
                              (f"/projects/{first}/updates", "updates.html"),
                              (f"/projects/{second}/history", "history.html")):  # fmt: skip
            self.assertEqual(self.view(url)[0], expected, url)

    def test_each_project_shows_its_newest_scan_its_preview_alone_and_its_last_real_apply(self):
        ticks = (f"2026-11-21T00:{n // 60:02d}:{n % 60:02d}.000Z" for n in itertools.count())
        clock = mock.patch.object(history, "_now", side_effect=lambda: next(ticks))
        clock.start()
        self.addCleanup(clock.stop)
        first = history.register_project(self.project)
        (second, _), (third, _) = self.another(), self.another("third")
        passed, flagged = self.scan_with(0.1), self.scan_with(0.9)
        document = test_dashboard.applied_document

        def preview(folder=self.project):
            return history.record("update_preview", folder, flagged, PREVIEW)

        def attempt(folder, *outcome, **extra):
            """A new update preview of the project in folder and an apply of it with this
            outcome (applied if none is given): its run."""
            run_id = preview(folder)
            history.record_apply(run_id, PREVIEW, document(*outcome, **extra))
            return run_id

        scan = history.record("scan", self.project, passed)
        # Two previews alone, as depbee update leaves them, and one that is applied. Then twelve
        # attempts that changed nothing: more runs than any list of recent ones holds.
        old, alone, done = preview(), preview(), attempt(self.project)
        later = [attempt(self.project, "refused", "project_changed"),
                 attempt(self.project, "failed", "install_failed", mode="install"),
                 attempt(self.project, "unchanged"),
                 *(attempt(self.project, "refused", "confirmation_required") for _ in range(9))]  # fmt: skip
        # Two other projects with one preview each: refused in one, applied in the other.
        attempt(second, "refused", "project_changed")
        theirs = attempt(third)

        def run(run_id, status, item, cell):
            ((created_at,),) = sql(self.db, "SELECT created_at FROM runs WHERE id = ?", run_id)
            counts = {"flagged": 0, "not_flagged": 0, "incomplete": 0, "removed": 0, item: 1}
            return dict(zip(RUN, (run_id, created_at, OVERALL_LABELS[status], counts, cell),
                            strict=True))  # fmt: skip

        def applied(run_id, outcome, mode):
            ((at,),) = sql(self.db, "SELECT created_at FROM applies WHERE run_id = ?", run_id)
            return {"run_id": run_id, "created_at": at, "outcome": OUTCOME_LABELS[outcome],
                    "mode": MODE_LABELS[mode]}  # fmt: skip

        def shown(portfolio):
            return [(row["scan"] and {key: row["scan"][key] for key in RUN},
                     row["preview"] and {key: row["preview"][key] for key in RUN},
                     row["apply"]) for row in portfolio]  # fmt: skip

        # The preview that nothing was applied from and the apply that changed the files are
        # still the ones shown after the later attempts; a preview that was refused is neither.
        seen = (run(scan, "passed", "not_flagged", "pass"), run(alone, "flagged", "flagged", "risk"))
        expected = [(*seen, applied(done, "applied", "lockfile")), (None, None, None),
                    (None, None, applied(theirs, "applied", "lockfile"))]  # fmt: skip
        self.assertEqual(shown(self.view("/")[1]["portfolio"]), expected)
        # The oldest preview is applied last of all: the apply shown is that one, at its own
        # time, which is after the newest run of the project.
        history.record_apply(old, PREVIEW, document(mode="install"))
        expected[0] = (*seen, applied(old, "applied", "install"))
        self.assertEqual(shown(self.view("/")[1]["portfolio"]), expected)
        self.assertGreater(expected[0][2]["created_at"],
                           run(later[-1], "flagged", "flagged", "risk")["created_at"])  # fmt: skip
        # The attempts that changed nothing stay in the project's history and on their runs.
        attempts = self.view(f"/projects/{first}/history")[1]["applies"]
        self.assertEqual((len(attempts), {row["outcome"] for row in attempts}),
                         (14, set(OUTCOME_LABELS.values())))  # fmt: skip
        name, context = self.view(f"/runs/{later[0]}")
        self.assertEqual((name, context["apply"]["outcome"]),
                         ("run.html", OUTCOME_LABELS["refused"]))  # fmt: skip
        # The stored documents are not opened: text that is no JSON in their place changes
        # nothing. And nothing is written.
        sql(self.db, "UPDATE runs SET report = 'no JSON', preview = 'no JSON'")
        sql(self.db, "UPDATE applies SET apply = 'no JSON'")
        before = self.db.read_bytes()
        self.assertEqual(shown(self.view("/")[1]["portfolio"]), expected)
        self.assertEqual(self.db.read_bytes(), before)
        # A folder that is gone keeps its row and what the history says of it.
        shutil.rmtree(third)
        portfolio = self.view("/")[1]["portfolio"]
        self.assertEqual(([row["found"] for row in portfolio], shown(portfolio)),
                         ([True, True, False], expected))  # fmt: skip

    def work(self):
        """(SQLite VM steps, context) of opening the overview once. The steps are counted on
        every connection the history opens, in hundreds a statement, so a read of a row or two
        counts as none."""
        steps, connect = 0, sqlite3.connect

        def counted(*args, **kwargs):
            connection = connect(*args, **kwargs)

            def tick():
                nonlocal steps
                steps += 100
                return 0  # go on

            connection.set_progress_handler(tick, 100)
            return connection

        with mock.patch.object(sqlite3, "connect", counted):
            context = self.view("/")[1]
        return steps, context

    def test_a_project_that_applied_nothing_does_not_pass_the_applies_of_another(self):
        applied, others = 1500, 10
        history.register_project(self.project)
        report = self.scan_with(0.1)
        seed = history.record("update_preview", self.project, report, PREVIEW,
                              apply=test_dashboard.applied_document())  # fmt: skip
        # As many more applied previews of the project: copies of the rows the history wrote.
        run_columns = ", ".join((*history.RUN_COLUMNS[1:], "report", "preview"))
        apply_columns = ", ".join((*history.APPLY_COLUMNS[2:], "apply"))
        with contextlib.closing(sqlite3.connect(self.db)) as connection, connection:
            for _ in range(applied):
                last = connection.execute(
                    f"INSERT INTO runs ({run_columns}) SELECT {run_columns} FROM runs WHERE id = ?",
                    (seed,)).lastrowid  # fmt: skip
                connection.execute(
                    f"INSERT INTO applies (run_id, {apply_columns}) SELECT ?, {apply_columns} "
                    "FROM applies WHERE run_id = ?", (last, seed))  # fmt: skip
        alone, context = self.work()
        self.assertEqual([row["apply"]["run_id"] for row in context["portfolio"]], [last])
        # Projects that looked at updates and applied none.
        for number in range(others):
            folder, _ = self.another(f"other{number}")
            history.record("update_preview", folder, report, PREVIEW)
        together, context = self.work()
        self.assertEqual([row["apply"] and row["apply"]["run_id"] for row in context["portfolio"]],
                         [last, *[None] * others])  # fmt: skip
        # What the projects add stays under one step per apply of the first project for each of
        # them: passing its applies again for a project takes several steps an apply.
        self.assertLess(together - alone, others * applied)

    def test_a_registration_that_did_not_happen_stays_on_the_management_page(self):
        history.register_project(self.project)
        self.assertEqual(self.view("/")[0], "overview.html")  # the first page from here on

        def assert_managed(rendered, status, error):
            response, name, context = rendered
            self.assertEqual(
                (response.status_code, name, context["section"], context["error"],
                 context["manual"]), (status, "projects.html", "manage", error, True))  # fmt: skip

        missing = str(self.root / "missing")  # a typed path that is refused
        assert_managed(self.rendered(lambda: self.post(missing, SESSION)), 400,
                       self.app.REGISTER_ERRORS["folder"])  # fmt: skip
        with mock.patch.object(test_dashboard_picker.picker, "choose") as choose:
            for outcome in ("unavailable", "timeout"):
                choose.return_value = (outcome, None)
                assert_managed(self.rendered(self.pick), 503, self.app.PICK_ERRORS[outcome])
            choose.return_value = ("cancelled", None)
            closed = self.pick()
            self.assertEqual((closed.status_code, closed.headers["location"]),
                             (303, f"{S}/?manage=1"))  # fmt: skip
            self.assertEqual(self.view(closed.headers["location"].removeprefix(S))[0],
                             "projects.html")  # fmt: skip
            # A second dialog while one is open is refused, on a page of the management section.
            seen = []

            def open_dialog():
                choose.side_effect = None
                seen.append(self.rendered(self.pick))
                return "cancelled", None

            choose.side_effect = open_dialog
            self.assertEqual(self.pick().headers["location"], f"{S}/?manage=1")
            ((response, name, context),) = seen
            self.assertEqual((response.status_code, name, context["section"], context["reopen"]),
                             (409, "error.html", "manage", self.app.PICK_REOPEN))  # fmt: skip
            # A folder that is registered opens its own project, as before.
            folder = self.root / "chosen"
            folder.mkdir()
            (folder / "package-lock.json").write_bytes(self.head.read_bytes())
            choose.return_value = ("chosen", str(folder))
            opened = self.pick()
            self.assertEqual((opened.status_code, opened.headers["location"]),
                             (303, f"{S}/projects/2"))  # fmt: skip
        self.assertEqual(self.post(str(self.project), SESSION).headers["location"],
                         f"{S}/projects/1")  # fmt: skip
        self.assertEqual(len(history.list_projects()), 2)

    def test_a_history_file_of_an_older_format_is_shown_as_it_is(self):
        history.register_project(self.project)
        report = self.scan_with(0.1)
        scan = history.record("scan", self.project, self.scan_with(0.9))
        alone = history.record("update_preview", self.project, report, PREVIEW)
        done = history.record("update_preview", self.project, report, PREVIEW,
                              apply=test_dashboard.applied_document())  # fmt: skip
        # As the version 2 code left the file, then as the version 1 code did: without the
        # tables and the index that came later. A file without an applies table says of no
        # preview that it was applied: its newest preview is shown, and no apply.
        for version, dropped, preview, applied in (
            (2, ("TABLE previews", "INDEX runs_by_kind"), alone, done),
            (1, ("TABLE applies",), done, None),
        ):
            for thing in dropped:
                sql(self.db, f"DROP {thing}")
            sql(self.db, f"PRAGMA user_version = {version}")
            before = self.db.read_bytes()
            (row,) = self.view("/")[1]["portfolio"]
            self.assertEqual(
                (row["scan"]["id"], row["scan"]["cell"], row["preview"]["id"],
                 row["preview"]["cell"], row["apply"] and row["apply"]["run_id"]),
                (scan, "risk", preview, "pass", applied), version)  # fmt: skip
            self.assertEqual(self.db.read_bytes(), before)  # looking does not upgrade the file

    def test_the_start_address_is_the_first_page_and_only_listed_stylesheets_are_served(self):
        hosts = []

        class Server:
            def __init__(self, config):
                hosts.append(config.host)

            def run(self, sockets):
                hosts.append(sockets[0].getsockname()[0])
                raise KeyboardInterrupt  # as uvicorn ends after Ctrl+C

        def register(count):
            return count and (history.register_project(self.project) if count == 1
                              else self.another())  # fmt: skip

        for count in range(3):  # nothing registered, one project, two
            register(count)
            out = io.StringIO()
            background = mock.Mock(**{"control.side_effect": lambda app, stop: app})
            with (
                mock.patch.object(self.app.uvicorn, "Server", Server),
                contextlib.redirect_stdout(out),
            ):
                self.assertEqual(main(["dashboard", "--port", "0"]), 0)  # the foreground command
                self.app.serve(0, background=background)  # as the background instance serves
            for url in (out.getvalue().splitlines()[0], background.publish.call_args.args[0]):
                self.assertRegex(url, r"\Ahttp://127\.0\.0\.1:\d+/s/[A-Za-z0-9_-]{43}/\Z", count)
        self.assertEqual(set(hosts), {"127.0.0.1"})
        self.assertEqual(self.app.STYLES, ("style.css", "overview.css"))
        package = self.root / "package"
        (package / "static").mkdir(parents=True)
        for name in (*self.app.STYLES, "secret.css"):
            (package / "static" / name).write_text(f"/* {name} */", encoding="utf-8")
        (package / "outside.css").write_text("/* outside */", encoding="utf-8")
        with mock.patch.object(self.app.importlib.resources, "files", return_value=package) as of:
            for name in self.app.STYLES:
                response = self.get(f"/static/{name}")
                self.assertEqual(
                    (response.status_code, response.headers["content-type"], response.text),
                    (200, "text/css; charset=utf-8", f"/* {name} */"))  # fmt: skip
            # Any other name is no page at all: no file is looked for.
            for url in ("/static/secret.css", "/static/", "/static/overview.css/",
                        "/static/%2e%2e/outside.css", "/static/..%2foutside.css",
                        "/static/overview.css%2f..%2fsecret.css", "/static/style.css%00",
                        "/static/OVERVIEW.CSS"):  # fmt: skip
                self.assertEqual(self.get(url).status_code, 404, url)
            self.assertEqual(of.call_args_list, [mock.call("depbee.dashboard")] * 2)

    def test_reading_never_rolls_back_an_interrupted_write(self):
        history.register_project(self.project)
        crash = self.root / "recovery.db"
        journal = self.root / "recovery.db-journal"
        # The files as a writer that stopped halfway leaves them: copied inside its transaction,
        # after the small cache made it write unfinished pages into the file.
        with contextlib.closing(sqlite3.connect(self.db)) as writer:
            writer.executescript(
                "PRAGMA journal_mode=DELETE; PRAGMA cache_size=5; BEGIN IMMEDIATE; "
                "UPDATE projects SET path='pending'; CREATE TABLE stress(page);"
            )
            writer.executemany("INSERT INTO stress VALUES (zeroblob(7000))", [()] * 70)
            shutil.copyfile(self.db, crash)
            shutil.copyfile(f"{self.db}-journal", journal)
            writer.rollback()
        before = crash.read_bytes(), journal.read_bytes()
        self.assertNotEqual(before[0], self.db.read_bytes())  # the unfinished write is in it
        reads = (history.list_projects, lambda: history.list_previews(1, "a" * 64, "b" * 64))
        with mock.patch.dict("os.environ", {"DEPBEE_HISTORY_DB": str(crash)}):
            for read in reads:
                # Refused, not recovered: rolling back is left to the next write.
                with self.assertRaisesRegex(sqlite3.OperationalError, "readonly"):
                    read()
                self.assertEqual(crash.read_bytes(), before[0])
                self.assertEqual(journal.read_bytes(), before[1])
