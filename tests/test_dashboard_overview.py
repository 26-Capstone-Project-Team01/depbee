"""Dashboard overview (the console's first page): which page the root address opens, what the
overview is given of each registered project (`portfolio`) and of all of them together
(`chart`), what the page says of them, that a registration that did not happen stays on the
management page, the start address and the files of static/ that are served.

Each request is a real one through the in-process TestClient. What a view renders (the
template's name and the keyword arguments of its render) is captured by replacing Jinja's
get_template in the test alone, so only the tests of the page itself need the overview's markup.
Synthetic only, as in test_dashboard.py: stored reports of pipeline.scan() with a fake predictor,
in each test run's folder; no server, dialog, npm or registry.
"""

import contextlib
import io
import itertools
import re
import shutil
import sqlite3
from pathlib import Path
from unittest import mock

import test_dashboard  # the modules: their test classes, imported by name, would run again here
import test_dashboard_picker
from test_apply import sha
from test_history import sql

from depbee import history
from depbee.cli import MODE_LABELS, OUTCOME_LABELS, OVERALL_LABELS, main

CSRF, PREVIEW = test_dashboard.CSRF, test_dashboard.PREVIEW
document = test_dashboard.applied_document
# The chart's entries for the states it always lists, with no project in any of them.
CORE = [{"key": key, "cell": key, "label": label, "count": 0}
        for key, label in (("risk", "위험"), ("hold", "보류"), ("pass", "통과"), ("none", "미검사"))]  # fmt: skip


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

    def made_from(self, folder, **changes):
        """An update preview document made from the folder's two files as they are now; the
        package.json is written first if the folder has none."""
        manifest = folder / "package.json"
        if not manifest.exists():
            manifest.write_text("{}", encoding="utf-8")
        return {**PREVIEW, "package_json_sha256": sha(manifest.read_bytes()),
                "package_lock_sha256": sha((folder / "package-lock.json").read_bytes()),
                **changes}  # fmt: skip

    def rows(self):
        """({project name: its row}, the chart) of one look at the overview."""
        context = self.view("/")[1]
        return {row["name"]: row for row in context["portfolio"]}, context["chart"]

    def states(self):
        return {name: row["state"] for name, row in self.rows()[0].items()}

    def ticking(self):
        """The history's clock, a second on at each call: every record has its own time."""
        ticks = (f"2026-11-21T00:{n // 60:02d}:{n % 60:02d}.000Z" for n in itertools.count())
        clock = mock.patch.object(history, "_now", side_effect=lambda: next(ticks))
        clock.start()
        self.addCleanup(clock.stop)

    def test_the_first_page_is_the_start_page_until_a_project_is_registered(self):
        # Nothing registered: the page that adds the first project, whatever the address asks.
        for url in ("/", "/?manage=1", "/?manage=0", "/?other=1"):
            name, context = self.view(url)
            self.assertEqual((name, context["section"], context["tabs"]),
                             ("start.html", "start", []), url)  # fmt: skip
            self.assertFalse({"portfolio", "chart"} & set(context), url)
        self.assertFalse(self.db.exists())  # looking creates no history
        first = history.register_project(self.project)
        name, context = self.view("/")
        self.assertEqual((name, context["section"]), ("overview.html", "overview"))
        self.assertEqual(context["portfolio"], [{
            "id": first, "name": "project", "path": str(self.project.resolve()), "found": True,
            "state": "none", "cell": "none", "label": "미검사", "run": None, "attempt": None,
            "success": None}])  # fmt: skip
        self.assertEqual(context["chart"], [*CORE[:3], {**CORE[3], "count": 1}])
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

    def test_each_project_is_in_the_state_of_its_newest_run_and_the_chart_counts_them(self):
        self.ticking()
        history.register_project(self.project)
        folders = {name: self.another(name)[0]
                   for name in ("held", "passed", "fresh", "moved", "gone", "odd", "again")}  # fmt: skip
        passed, flagged = self.scan_with(0.1), self.scan_with(0.9)
        history.record("scan", self.project, passed)  # an older run does not count
        newest = history.record("update_preview", self.project, flagged,
                                self.made_from(self.project))  # fmt: skip
        history.record("scan", folders["held"], self.scan_with(analyzer=False))
        history.record("scan", folders["passed"], passed)
        history.record("scan", folders["again"], passed)
        # A preview of files that the project no longer has; a folder that is gone, whatever
        # its last run said; and a status that is none of the three a report has.
        history.record("update_preview", folders["moved"], passed, self.made_from(folders["moved"]))
        (folders["moved"] / "package-lock.json").write_bytes(b"{}")
        gone = history.record("scan", folders["gone"], flagged)
        shutil.rmtree(folders["gone"])
        odd = history.record("scan", folders["odd"], passed)
        sql(self.db, "UPDATE runs SET status = 'odd' WHERE id = ?", odd)
        rows, chart = self.rows()
        self.assertEqual({name: (row["state"], row["cell"], row["label"])
                          for name, row in rows.items()}, {
            "project": ("risk", "risk", "위험"), "held": ("hold", "hold", "보류"),
            "passed": ("pass", "pass", "통과"), "again": ("pass", "pass", "통과"),
            "fresh": ("none", "none", "미검사"), "moved": ("stale", "stale", "파일 바뀜"),
            "gone": ("gone", "gone", "폴더 없음"), "odd": ("unknown", "none", "알 수 없음")})  # fmt: skip
        # Every project is counted once, in the order of what needs a look first.
        self.assertEqual([(entry["key"], entry["cell"], entry["label"], entry["count"])
                          for entry in chart], [
            ("risk", "risk", "위험", 1), ("hold", "hold", "보류", 1), ("pass", "pass", "통과", 2),
            ("none", "none", "미검사", 1), ("stale", "stale", "파일 바뀜", 1),
            ("gone", "gone", "폴더 없음", 1), ("unknown", "none", "알 수 없음", 1)])  # fmt: skip
        self.assertEqual(sum(entry["count"] for entry in chart), len(rows))
        # The run is the stored one, a scan or a preview alike, as the history view words it.
        self.assertEqual({key: rows["project"]["run"][key] for key in ("id", "status", "counts")},
                         {"id": newest, "status": OVERALL_LABELS["flagged"],
                          "counts": {"flagged": 1, "not_flagged": 0, "incomplete": 0,
                                     "removed": 0}})  # fmt: skip
        self.assertEqual((rows["gone"]["run"]["id"], rows["gone"]["found"], rows["fresh"]["run"]),
                         (gone, False, None))  # fmt: skip
        self.assertEqual(rows["odd"]["run"]["status"], "odd")
        # A state that says something went wrong is listed only while a project is in it.
        for name in ("moved", "odd"):
            shutil.rmtree(folders[name])
        self.assertEqual([(entry["key"], entry["count"]) for entry in self.rows()[1]],
                         [("risk", 1), ("hold", 1), ("pass", 2), ("none", 1), ("gone", 3)])  # fmt: skip

    def test_a_preview_counts_only_for_the_files_it_was_made_from_or_left(self):
        self.ticking()
        history.register_project(self.project)
        flagged, passed = self.scan_with(0.9), self.scan_with(0.1)
        lock = self.head.read_bytes()
        checked = history.record("update_preview", self.project, flagged,
                                 self.made_from(self.project))  # fmt: skip
        self.assertEqual(self.states(), {"project": "risk"})
        # Other files: the stored verdict is not said of them. The same bytes again: it is.
        for name in ("package-lock.json", "package.json"):
            with self.subTest(changed=name):
                file = self.project / name
                before = file.read_bytes()
                file.write_bytes(before + b"\n")
                row = self.rows()[0]["project"]
                self.assertEqual((row["state"], row["label"], row["run"]["id"]),
                                 ("stale", "파일 바뀜", checked))  # fmt: skip
                file.write_bytes(before)
                self.assertEqual(self.states(), {"project": "risk"})
        # A file that cannot be read is not the file that was checked either.
        manifest = (self.project / "package.json").read_bytes()
        (self.project / "package.json").unlink()
        self.assertEqual(self.states(), {"project": "stale"})
        (self.project / "package.json").write_bytes(manifest)
        # A scan stores no hash of its files: it is never said to be of other files.
        self.head.write_bytes(lock + b"\n")
        history.record("scan", self.project, passed)
        self.assertEqual(self.states(), {"project": "pass"})
        # A preview that was applied counts for the files its apply left, and for no others.
        new_lock = lock + b" "
        applied = history.record(
            "update_preview", self.project, passed, self.made_from(self.project),
            apply=document(files=[{"path": "package-lock.json", "sha256": sha(lock + b"\n"),
                                   "new_sha256": sha(new_lock)}]))  # fmt: skip
        self.assertEqual(self.states(), {"project": "pass"})  # not yet written: as checked
        self.head.write_bytes(new_lock)
        row = self.rows()[0]["project"]
        self.assertEqual((row["state"], row["run"]["id"], row["attempt"]["run_id"]),
                         ("pass", applied, applied))  # fmt: skip
        self.head.write_bytes(new_lock + b"\n")
        self.assertEqual(self.states(), {"project": "stale"})
        self.head.write_bytes(new_lock)
        # A refused apply left nothing: its preview counts for the files it was made from.
        history.record("update_preview", self.project, flagged, self.made_from(self.project),
                       apply=document("refused", "project_changed"))  # fmt: skip
        self.assertEqual(self.states(), {"project": "risk"})
        self.head.write_bytes(lock)
        self.assertEqual(self.states(), {"project": "stale"})
        # The stored documents are not opened: text that is no JSON in their place changes
        # nothing. And nothing is written.
        sql(self.db, "UPDATE runs SET report = 'no JSON', preview = 'no JSON'")
        sql(self.db, "UPDATE applies SET apply = 'no JSON'")
        before = self.db.read_bytes()
        self.head.write_bytes(new_lock)
        self.assertEqual(self.states(), {"project": "risk"})
        self.assertEqual(self.db.read_bytes(), before)

    def test_each_project_shows_its_newest_apply_attempt_and_its_last_success_apart(self):
        self.ticking()
        first = history.register_project(self.project)
        folders = {name: self.another(name)[0] for name in ("broke", "done", "same", "idle")}
        report = self.scan_with(0.9)
        reasons = self.app.DASHBOARD_REASONS

        def attempt(folder, *outcome, **extra):
            """A new update preview of the project in folder and an apply of it with this
            outcome (applied if none is given): its run."""
            run_id = history.record("update_preview", folder, report, PREVIEW)
            history.record_apply(run_id, PREVIEW, document(*outcome, **extra))
            return run_id

        def expected(run_id, outcome, mode="lockfile", reason=None, cell="none"):
            ((at,),) = sql(self.db, "SELECT created_at FROM applies WHERE run_id = ?", run_id)
            return {"run_id": run_id, "created_at": at, "mode": MODE_LABELS[mode],
                    "outcome": OUTCOME_LABELS[outcome], "cell": cell,
                    "reason": None if reason is None else reasons[reason],
                    "applied": outcome == "applied"}  # fmt: skip

        def success(run_id):
            ((at,),) = sql(self.db, "SELECT created_at FROM applies WHERE run_id = ?", run_id)
            return {"run_id": run_id, "created_at": at}

        def shown():
            return {name: (row["attempt"], row["success"]) for name, row in self.rows()[0].items()}

        # A preview that nothing was tried from, one that was applied, then twelve attempts that
        # changed nothing: more than any list of recent runs holds.
        old = history.record("update_preview", self.project, report, PREVIEW)
        done = attempt(self.project)
        later = [attempt(self.project, "failed", "install_failed", mode="install"),
                 attempt(self.project, "unchanged"),
                 *(attempt(self.project, "refused", "confirmation_required") for _ in range(9)),
                 attempt(self.project, "refused", "project_changed")]  # fmt: skip
        broke = attempt(folders["broke"], "failed", "install_failed", mode="install")
        theirs = attempt(folders["done"])
        same = attempt(folders["same"], "unchanged")
        history.record("update_preview", folders["idle"], report, PREVIEW)
        self.assertEqual(shown(), {
            # The newest attempt as it ended, with its stored reason; the last one that changed
            # the files apart from it, however many attempts came after.
            "project": (expected(later[-1], "refused", reason="project_changed", cell="risk"),
                        success(done)),
            "broke": (expected(broke, "failed", "install", "install_failed", "fail"), None),
            # The newest attempt is the success: it is not said twice.
            "done": (expected(theirs, "applied", cell="pass"), None),
            "same": (expected(same, "unchanged"), None),
            "idle": (None, None)})  # fmt: skip
        self.assertEqual({reasons[key] for key in ("project_changed", "install_failed")},
                         {"미리보기 뒤 package.json 또는 package-lock.json이 바뀜", "npm ci 실패"})  # fmt: skip
        # The oldest preview is applied last of all: the attempt shown is that one, at its own
        # time, which is after the newest run of the project.
        history.record_apply(old, PREVIEW, document(mode="install"))
        attempt_now, success_now = shown()["project"]
        self.assertEqual((attempt_now, success_now),
                         (expected(old, "applied", "install", cell="pass"), None))  # fmt: skip
        ((newest,),) = sql(self.db, "SELECT created_at FROM runs WHERE id = ?", later[-1])
        self.assertGreater(attempt_now["created_at"], newest)
        # Every attempt stays in the project's history and on its run.
        attempts = self.view(f"/projects/{first}/history")[1]["applies"]
        self.assertEqual((len(attempts), {row["outcome"] for row in attempts}),
                         (14, set(OUTCOME_LABELS.values())))  # fmt: skip
        name, context = self.view(f"/runs/{later[0]}")
        self.assertEqual((name, context["apply"]["outcome"]),
                         ("run.html", OUTCOME_LABELS["failed"]))  # fmt: skip

    def test_the_page_says_each_state_in_words_and_links_every_record_to_its_report(self):
        self.ticking()
        history.register_project(self.project)
        folders = {name: self.another(name)[0] for name in ("fresh", "moved", "gone")}
        passed, flagged = self.scan_with(0.1), self.scan_with(0.9)
        scan = history.record("scan", self.project, flagged)
        done = history.record("update_preview", folders["gone"], passed, PREVIEW,
                              apply=document())  # fmt: skip
        refused = history.record("update_preview", folders["gone"], flagged, PREVIEW,
                                 apply=document("refused", "known_malicious_hit"))  # fmt: skip
        stale = history.record("update_preview", folders["moved"], passed,
                               self.made_from(folders["moved"]))  # fmt: skip
        (folders["moved"] / "package-lock.json").write_bytes(b"{}")
        shutil.rmtree(folders["gone"])
        html = self.page("/")
        # The chart: its name, each state in words with its count, and one mark a project.
        self.assertIn('<h2 id="chart-title">프로젝트 4개의 최근 검사 상태</h2>', html)
        chart = html.split('<ul class="ov-states">', 1)[1].split("</ul>", 1)[0]
        states = re.findall(r'<li class="ov-(\w+)"><span class="ov-marks" aria-hidden="true">'
                            r'((?:<span class="cell \w+"></span>)*)</span>'
                            r'<span class="ov-label">([^<]+)</span> <b class="ov-count">(\d+)</b>'
                            r'<span class="visually-hidden">개</span></li>', chart)  # fmt: skip
        self.assertEqual([(key, marks.count("<span"), label, count)
                          for key, marks, label, count in states], [
            ("risk", 1, "위험", "1"), ("hold", 0, "보류", "0"), ("pass", 0, "통과", "0"),
            ("none", 1, "미검사", "1"), ("stale", 1, "파일 바뀜", "1"),
            ("gone", 1, "폴더 없음", "1")])  # fmt: skip
        self.assertEqual(chart.count("<li"), len(states))
        # A chart of what is stored: no picture, no drawing, nothing fetched. The rail's icons
        # are the only drawings of the page.
        for absent in ("<svg", "<canvas", "<img", "<meter"):
            self.assertNotIn(absent, html.split("<main", 1)[1])

        # One line a project, seven columns.
        self.assertEqual(re.findall(r'<th role="columnheader" scope="col">([^<]*)</th>', html),
                         ["프로젝트", "최근 검사", "위험", "보류", "검사 시각", "최근 반영 시도",
                          "마지막 성공 반영"])  # fmt: skip

        def cells(name):
            """The six cells of the project's row after its name, as text without the markup.
            Each starts with its column's name, which a narrow page shows beside the value."""
            row = html.split(f">{name}</a>", 1)[1].split("</tr>", 1)[0]
            text = [re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", cell)).strip()
                    for cell in re.split(r"<td [^>]*>", row)[1:]]  # fmt: skip
            return [re.sub(r" ([,.])", r"\1", cell) for cell in text]

        # Each project is the way into itself, with its folder under its name.
        for project_id, name in enumerate(("project", "fresh", "moved", "gone"), 1):
            self.assertIn(f'<a class="ov-name" href="/projects/{project_id}" title="{name}">{name}</a>', html)
        full = str(self.project.resolve())
        self.assertIn(
            f'<span class="ov-path" title="{full}">{self.app._short_path(full)}</span>', html
        )
        time = r"2026-11-21 00:\d\d UTC"
        found = cells("project")
        self.assertEqual(len(found), 6)
        self.assertRegex(found[0], rf"^최근 검사 위험, lockfile 변경 검사\(scan\) project 최근 검사 보고서 #{scan}$")
        self.assertEqual(found[1:3], ["위험 1", "보류 0"])
        self.assertRegex(found[3], rf"^검사 시각 {time}$")
        self.assertEqual(found[4:], ["최근 반영 시도 없음", "마지막 성공 반영 없음"])
        self.assertEqual(cells("fresh"), ["최근 검사 미검사, lockfile 변경 검사나 업데이트 미리보기 기록이 없습니다.",
                                          "위험 -", "보류 -", "검사 시각 -", "최근 반영 시도 없음",
                                          "마지막 성공 반영 없음"])  # fmt: skip
        # Why a state is not the stored result: in the chip's title and for a screen reader,
        # with the stored result spelled out.
        moved = "이 미리보기 뒤에 package.json이나 package-lock.json이 바뀌어 지금 파일의 결과가 아닙니다."
        found = cells("moved")
        self.assertRegex(found[0], rf"^최근 검사 파일 바뀜, {re.escape(moved)} 업데이트 검사\(update\): 통과 "
                                   rf"moved 최근 검사 보고서 #{stale}$")  # fmt: skip
        self.assertIn(f'<span class="verdict stale" title="{moved} 업데이트 검사(update): 통과">', html)
        self.assertEqual(found[1:3], ["위험 0", "보류 0"])
        gone = "폴더를 찾을 수 없습니다. 지난 기록은 그대로 열립니다. 업데이트 검사(update): 위험 판정 있음"
        found = cells("gone")
        self.assertRegex(found[0], rf"^최근 검사 폴더 없음, {re.escape(gone)} gone 최근 검사 보고서 #{refused}$")
        self.assertIn(f'<span class="verdict gone" title="{gone}">', html)
        self.assertEqual(found[1:3], ["위험 1", "보류 0"])
        # The attempt that was refused, why (in its chip's title and for a screen reader), and
        # apart from it the last one that succeeded.
        why = "기지 악성 기록 일치(예외 없이 거부)"
        self.assertRegex(found[4], rf"^최근 반영 시도 반영하지 않음, {re.escape(why)}, {time} "
                                   rf"gone 최근 반영 시도 보고서 #{refused}$")  # fmt: skip
        self.assertRegex(html, rf'<span class="verdict risk" title="{re.escape(why)}, {time}">')
        self.assertRegex(found[5], rf"^마지막 성공 반영 {time} gone 마지막 성공 반영 보고서 #{done}$")
        for run in (scan, stale, refused, done):
            self.assertIn(f'href="/runs/{run}"', html)
        self.assertIn('<a class="ov-add" href="/?manage=1">프로젝트 추가</a>', html)

    def test_the_last_success_is_the_newest_attempt_when_that_one_changed_the_files(self):
        self.ticking()
        history.register_project(self.project)
        run = history.record("update_preview", self.project, self.scan_with(0.1), PREVIEW,
                             apply=document())  # fmt: skip
        row = self.page("/").split(">project</a>", 1)[1].split("</tr>", 1)[0]
        attempt, last = re.split(r"<td [^>]*>", row)[-2:]
        self.assertIn('<span class="verdict pass" title="방식: lockfile 반영, ', attempt)
        self.assertIn(f'href="/runs/{run}"', attempt)
        self.assertIn(f'href="/runs/{run}"', last)
        self.assertNotIn("없음", last)

    def test_a_narrow_overview_stacks_each_project_as_a_card(self):
        css = (Path(self.app.__file__).parent / "static" / "overview.css").read_text("utf-8")
        narrow, wide = css.split("@container overview (min-width: 56rem)", 1)
        # Below it a project is a card whose values each carry their column's name.
        self.assertIn(".overview .ov-board thead { display: none; }", narrow)
        self.assertIn(".overview .ov-kind { display: block;", narrow)
        # Above it, one line of seven columns, and the names are the heads.
        self.assertRegex(wide, r"\.overview \.ov-cols, \.overview \.ov-row \{ display: grid; "
                               r"grid-template-columns:(?: minmax\([^)]*\)){7}; \}")  # fmt: skip
        self.assertIn(".overview .ov-kind { display: none; }", wide)
        self.assertIn(".overview .ov-row .ov-num { text-align: end; }", wide)  # under its head
        # The way into a project and to a report: a target a finger can hit, and a pointer's
        # in the wide table; a long name keeps the line one line there.
        self.assertRegex(narrow, r"\.overview \.ov-name, \.overview \.ov-rec a, \.overview \.ov-apply a \{[^}]*min-height: 2\.75rem")
        self.assertRegex(wide, r"\.overview \.ov-name, \.overview \.ov-rec a, \.overview \.ov-apply a \{[^}]*min-height: 2\.25rem")
        self.assertRegex(wide, r"\.overview \.ov-name \{[^}]*text-overflow: ellipsis")

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
                              apply=document())  # fmt: skip
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
        self.assertEqual([row["attempt"]["run_id"] for row in context["portfolio"]], [last])
        # Projects that looked at updates and applied none.
        for number in range(others):
            folder, _ = self.another(f"other{number}")
            history.record("update_preview", folder, report, self.made_from(folder))
        together, context = self.work()
        self.assertEqual([row["attempt"] and row["attempt"]["run_id"]
                          for row in context["portfolio"]], [last, *[None] * others])  # fmt: skip
        self.assertEqual([row["state"] for row in context["portfolio"]],
                         ["stale", *["pass"] * others])  # fmt: skip
        # What the projects add stays under one step per apply of the first project for each of
        # them: passing its applies again for a project takes several steps an apply.
        self.assertLess(together - alone, others * applied)

    def test_a_registration_that_did_not_happen_stays_on_the_management_page(self):
        history.register_project(self.project)
        self.assertEqual(self.view("/")[0], "overview.html")  # the first page from here on

        def assert_managed(rendered, status, error):
            response, name, context = rendered
            self.assertEqual((response.status_code, name, context["section"], context["error"]),
                             (status, "projects.html", "manage", error))  # fmt: skip
            # Nothing of a typed path is given to the page any more.
            self.assertFalse({"typed", "manual"} & set(context))

        with mock.patch.object(test_dashboard_picker.picker, "choose") as choose:
            choose.return_value = ("chosen", str(self.root / "missing"))  # a refused folder
            assert_managed(self.rendered(self.pick), 400, self.app.REGISTER_ERRORS["folder"])
            for outcome in ("unavailable", "timeout"):
                choose.return_value = (outcome, None)
                assert_managed(self.rendered(self.pick), 503, self.app.PICK_ERRORS[outcome])
            choose.return_value = ("cancelled", None)
            closed = self.pick()
            self.assertEqual((closed.status_code, closed.headers["location"]),
                             (303, "/?manage=1"))  # fmt: skip
            self.assertEqual(self.view(closed.headers["location"])[0],
                             "projects.html")  # fmt: skip
            # A second dialog while one is open is refused, on a page of the management section.
            seen = []

            def open_dialog():
                choose.side_effect = None
                seen.append(self.rendered(self.pick))
                return "cancelled", None

            choose.side_effect = open_dialog
            self.assertEqual(self.pick().headers["location"], "/?manage=1")
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
                             (303, "/projects/2"))  # fmt: skip
            choose.return_value = ("chosen", str(self.project))  # the first one again
            self.assertEqual(self.pick().headers["location"], "/projects/1")
        self.assertEqual(len(history.list_projects()), 2)

    def test_before_the_first_project_a_dialog_that_fails_ends_on_project_management(self):
        # The start page has the dialog's button alone. A dialog that cannot be used, and a
        # folder that is refused, end on project management, which says why above the same
        # button: on the start page the user would not know that nothing was registered.
        self.assertEqual(self.view("/")[0], "start.html")
        with mock.patch.object(test_dashboard_picker.picker, "choose") as choose:
            for outcome in ("unavailable", "timeout"):
                choose.return_value = (outcome, None)
                response, name, context = self.rendered(self.pick)
                self.assertEqual((response.status_code, name, context["tabs"], context["error"]),
                                 (503, "projects.html", [], self.app.PICK_ERRORS[outcome]))  # fmt: skip
            choose.return_value = ("chosen", str(self.root / "missing"))
            response, name, context = self.rendered(self.pick)
            self.assertEqual((response.status_code, name, context["error"]),
                             (400, "projects.html", self.app.REGISTER_ERRORS["folder"]))  # fmt: skip
            # Closing the dialog is no failure: the start page again.
            choose.return_value = ("cancelled", None)
            closed = self.pick()
            self.assertEqual(self.view(closed.headers["location"])[0],
                             "start.html")  # fmt: skip
            self.assertFalse(self.db.exists())
            # None of that registered anything: the next folder the dialog answers is the
            # first project of all, which ends on the overview.
            choose.return_value = ("chosen", str(self.project))
            self.assertEqual(self.pick().headers["location"], "/")
        self.assertEqual(self.view("/")[0], "overview.html")

    def reopened(self):
        """(template, context) of the first page of another run of the dashboard, with its own
        form value, at the same address and on the same history."""
        from starlette.testclient import TestClient

        client = TestClient(self.app.build_app(test_dashboard.PORT, "another-run-9876543210"),
                            base_url=test_dashboard.BASE)  # fmt: skip
        self.addCleanup(client.close)
        response, name, context = self.rendered(lambda: client.get("/"))
        self.assertEqual(response.status_code, 200)
        return name, context

    def test_the_first_project_of_all_opens_the_overview(self):
        first, second = self.root / "first", self.root / "second"
        for folder in (first, second):
            folder.mkdir(parents=True)
            (folder / "package-lock.json").write_bytes(self.head.read_bytes())

        with mock.patch.object(test_dashboard_picker.picker, "choose") as choose:

            def register(folder):
                choose.return_value = ("chosen", str(folder))
                return self.pick()

            self.assertEqual(self.view("/")[0], "start.html")
            # What registers nothing leaves the next folder the first: a closed dialog, one
            # that cannot be used, and a folder that is refused.
            for outcome, status in (("cancelled", 303), ("unavailable", 503)):
                choose.return_value = (outcome, None)
                self.assertEqual(self.pick().status_code, status)
            self.assertEqual(register(self.root / "missing").status_code, 400)
            self.assertEqual(history.list_projects(), [])
            response = register(first)
            self.assertEqual((response.status_code, response.headers["location"]),
                             (303, "/"))  # fmt: skip
            # That address is the overview now, with the project and nothing inspected.
            name, context = self.view("/")
            self.assertEqual((name, context["section"]), ("overview.html", "overview"))
            self.assertEqual(context["portfolio"], [{
                "id": 1, "name": "first", "path": str(first.resolve()), "found": True,
                "state": "none", "cell": "none", "label": "미검사", "run": None,
                "attempt": None, "success": None}])  # fmt: skip
            self.assertEqual(context["chart"], [*CORE[:3], {**CORE[3], "count": 1}])
            # Only the first of all: the same folder again, and the next one, open their own
            # project as before.
            self.assertEqual(register(first).headers["location"], "/projects/1")
            self.assertEqual(register(second).headers["location"], "/projects/2")
            self.assertEqual([project["path"] for project in history.list_projects()],
                             [str(first.resolve()), str(second.resolve())])  # fmt: skip
            # It is the history that holds them: another run opens the overview too.
            name, context = self.reopened()
            self.assertEqual((name, [row["name"] for row in context["portfolio"]]),
                             ("overview.html", ["first", "second"]))  # fmt: skip

    def test_a_history_file_of_an_older_format_is_shown_as_it_is(self):
        history.register_project(self.project)
        report = self.scan_with(0.1)
        history.record("scan", self.project, self.scan_with(0.9))
        history.record("update_preview", self.project, report, self.made_from(self.project))
        done = history.record("update_preview", self.project, report,
                              self.made_from(self.project), apply=document())  # fmt: skip
        # As the version 2 code left the file, then as the version 1 code did: without the
        # tables and the index that came later. The newest run is found either way, and its
        # files by the stored preview. A file without an applies table says of no preview that
        # an apply was tried.
        for version, dropped, attempted in (
            (2, ("TABLE previews", "INDEX runs_by_kind"), done),
            (1, ("TABLE applies",), None),
        ):
            for thing in dropped:
                sql(self.db, f"DROP {thing}")
            sql(self.db, f"PRAGMA user_version = {version}")
            before = self.db.read_bytes()
            (row,) = self.view("/")[1]["portfolio"]
            self.assertEqual(
                (row["run"]["id"], row["state"], row["attempt"] and row["attempt"]["run_id"],
                 row["success"]), (done, "pass", attempted, None), version)  # fmt: skip
            self.assertEqual(self.db.read_bytes(), before)  # looking does not upgrade the file

    def test_the_start_address_is_the_first_page_and_only_listed_files_are_served(self):
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
                self.assertRegex(url, r"\Ahttp://127\.0\.0\.1:[1-9]\d*/\Z", count)
        self.assertEqual(set(hosts), {"127.0.0.1"})
        # The stylesheets and the one script, each as what it is.
        self.assertEqual((self.app.STYLES, self.app.SCRIPT),
                         (("style.css", "overview.css", "check.css"), "app.js"))  # fmt: skip
        served = {**dict.fromkeys(self.app.STYLES, "text/css; charset=utf-8"),
                  self.app.SCRIPT: "text/javascript; charset=utf-8"}  # fmt: skip
        package = self.root / "package"
        (package / "static").mkdir(parents=True)
        for name in (*served, "secret.css", "secret.js"):
            (package / "static" / name).write_text(f"/* {name} */", encoding="utf-8")
        for name in ("outside.css", "outside.js"):
            (package / name).write_text("/* outside */", encoding="utf-8")
        with mock.patch.object(self.app.importlib.resources, "files", return_value=package) as of:
            for name, kind in served.items():
                response = self.get(f"/static/{name}")
                self.assertEqual(
                    (response.status_code, response.headers["content-type"], response.text),
                    (200, kind, f"/* {name} */"))  # fmt: skip
                # Never read as anything else, and never loaded by a page of another site.
                self.assertEqual(response.headers["x-content-type-options"], "nosniff")
                foreign = {"sec-fetch-site": "cross-site", "sec-fetch-mode": "no-cors"}
                self.assertEqual(self.get(f"/static/{name}", headers=foreign).status_code, 403)
            # Any other name is no page at all: no file is looked for.
            for url in ("/static/secret.css", "/static/secret.js", "/static/",
                        "/static/overview.css/", "/static/app.js/", "/static/%2e%2e/outside.css",
                        "/static/..%2foutside.js", "/static/overview.css%2f..%2fsecret.css",
                        "/static/app.js%2f..%2fsecret.js", "/static/style.css%00",
                        "/static/app.js%00", "/static/OVERVIEW.CSS", "/static/APP.JS",
                        "/static/app.mjs", "/static/app.js.map"):  # fmt: skip
                self.assertEqual(self.get(url).status_code, 404, url)
            self.assertEqual(of.call_args_list, [mock.call("depbee.dashboard")] * len(served))

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
        reads = (history.list_projects, lambda: history.list_previews(1, "a" * 64, "b" * 64),
                 history.latest_applies, lambda: history.latest_applies(applied=False))  # fmt: skip
        with mock.patch.dict("os.environ", {"DEPBEE_HISTORY_DB": str(crash)}):
            for read in reads:
                # Refused, not recovered: rolling back is left to the next write.
                with self.assertRaisesRegex(sqlite3.OperationalError, "readonly"):
                    read()
                self.assertEqual(crash.read_bytes(), before[0])
                self.assertEqual(journal.read_bytes(), before[1])
