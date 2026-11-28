"""Dashboard inspector selection: the update candidate that a project's packages and updates
views hand their template as `selected`, and what the item query (<run id>.<position>) selects.

Read from what a view renders its template with (the keyword arguments of the Jinja render,
captured here in the test alone), not from the markup, so that the tests hold whatever the pages
look like. Synthetic only, as in test_dashboard.py: stored reports of pipeline.scan() with a fake
list and predictor, in each test run's folder; no server, npm or registry.
"""

import json
import re
import socket
import subprocess
from unittest import mock

import test_dashboard  # the module: its test classes, imported by name, would run again here
from test_detectors import ADVISORY, KnownList, Rules, rule
from test_output_formats import older

from depbee import history, service

# package: its location, the installed version and the version an update would install, in the
# order of the stored report (the packages view lists by location instead). new is a dependency
# the update would add: it is not installed, so only the updates view lists it.
ROWS = {
    "other": ("node_modules/other", "1.0.0", "1.1.0"),
    "example": ("node_modules/example", "1.1.0", "1.2.0"),
    "inner": ("node_modules/example/node_modules/inner", "2.0.0", "2.1.0"),
    "new": ("node_modules/new", None, "3.0.0"),
}
CHECKED_WITH = ("model_id", "threshold", "list_as_of")


class InspectorTests(test_dashboard.DashboardFixture):
    """A project that installs example, inner and other, with a current check of everything
    whose stored report has a candidate for each of ROWS."""

    made_now = test_dashboard.CandidateTests.made_now
    check = test_dashboard.CandidateTests.check

    def setUp(self):
        super().setUp()
        self.old, self.new = test_dashboard.lock(), test_dashboard.lock("1.2.0")
        self.save_locks()
        self.manifest = self.project / "package.json"
        self.manifest.write_text(json.dumps(self.old["packages"][""]), encoding="utf-8")
        # example 1.1.0 -> 1.2.0, flagged: checked against a known malicious list, and without.
        self.report = self.rows(self.scan_with(0.9, known_malicious=KnownList()), *ROWS)
        self.unlisted = self.scan_with(0.9)
        self.write(self.head, self.old)  # the project as it is now
        self.project_id = history.register_project(self.project)
        self.packages = f"/projects/{self.project_id}"
        self.updates = f"{self.packages}/updates"
        self.checked = self.check(targets=None)
        self.keys = {name: f"{self.checked}.{position}" for position, name in enumerate(ROWS)}

    def rows(self, report, *names):
        """report with a result row for each of names (ROWS): copies of its only row."""
        (row,) = report["results"]
        return {**report, "results": [
            {**row, "package": name, "location": ROWS[name][0], "before_version": ROWS[name][1],
             "after_version": ROWS[name][2]} for name in names]}  # fmt: skip

    def context(self, url, item=None):
        """What the view renders its template with; item: the values of the item query."""
        template = mock.Mock()
        template.render.return_value = "<html></html>"
        with mock.patch.object(self.app.ENV, "get_template", return_value=template):
            response = self.get(url, params=None if item is None else {"item": item})
        self.assertEqual(response.status_code, 200, url)
        # The theme form's way back is the address itself, whatever the address holds.
        return {k: v for k, v in template.render.call_args.kwargs.items() if k != "theme_back"}

    def selected(self, url, item=None):
        return self.context(url, item)["selected"]

    def test_a_view_opens_its_first_candidate_or_the_one_the_item_names(self):
        # The packages view lists what is installed, by location; the updates view lists every
        # candidate in the report's order.
        for view, shown in ((self.packages, ("example", "inner", "other")), (self.updates, ROWS)):
            self.assertEqual(self.selected(view)["package"], next(iter(shown)), view)
            for name in shown:
                context = self.context(view, self.keys[name])
                row = context["selected"]
                self.assertEqual(row["package"], name, view)
                # The listed row itself, not a copy: a template can tell it by identity.
                self.assertTrue(any(row is listed for listed in context["state"]["rows"]), view)
        context = self.context(self.packages, self.keys["inner"])
        self.assertEqual([row["candidate"] is context["selected"] for row in context["rows"]],
                         [False, True, False])  # fmt: skip
        # The row says what the stored report says (app._result), the two versions, the run and
        # position its item names, what that report was checked with, and whether the lockfile's
        # root declares it (direct, app._mark_direct): nothing else.
        row = self.selected(self.updates, self.keys["example"])
        self.assertEqual(row, {
            **self.app._result(self.report["results"][1], self.report), "before": "1.1.0",
            "after": "1.2.0", "run_id": self.checked, "position": 1, "model_id": "unit-test",
            "threshold": 0.5, "list_as_of": KnownList.list_as_of, "direct": True})  # fmt: skip
        self.assertEqual((row["compared"], row["evidence"], row["explanation"]),
                         (None, ["synthetic evidence"], []))  # fmt: skip
        # Each detector's own verdict stays apart from the item's and from the model's.
        self.assertEqual((row["label"], row["score"], row["detectors"]),
                         ("위험", "0.900 (기준 이상)", [("기지 악성: 미적중", [])]))  # fmt: skip

    def test_the_packages_view_selects_among_the_rows_its_filter_leaves(self):
        for query, item, expected in (
            ("scope=nested", "inner", "inner"),  # shown under the filter
            ("scope=nested", "example", "inner"),  # filtered out: the first row shown instead
            ("scope=direct", "inner", "example"),
            ("scope=direct&q=OTH", "other", "other"),
            ("q=oth", "example", "other"),
            ("q=missing", "example", None),  # nothing is shown
            ("scope=all", "new", "example"),  # not installed: this view has no row of it
        ):
            with self.subTest(query=query, item=item):
                row = self.selected(f"{self.packages}?{query}&item={self.keys[item]}")
                self.assertEqual(row and row["package"], expected)
        # The filter is checked as before, and the updates view has none.
        refused = self.get(f"{self.packages}?scope=invalid&item={self.keys['inner']}")
        self.assertEqual(refused.status_code, 400)
        row = self.selected(f"{self.updates}?scope=nested&q=missing&item={self.keys['new']}")
        self.assertEqual(row["package"], "new")

    def test_an_item_that_is_not_one_key_of_a_shown_row_changes_nothing(self):
        key = self.keys["inner"]  # a row that both views show and neither opens first
        wide = key.translate(
            str.maketrans("0123456789", "０１２３４５６７８９")
        )  # int() reads these
        items = [
            "", "x", str(self.checked), f"{self.checked}.", ".2", f"{key}.0", f"{key}x", f" {key}",
            f"{key} ", f"+{key}", f"0{key}", f"{self.checked}.02", f"{self.checked}.-2",
            f"{self.checked}.9", f"{self.checked},2", wide,
            "9" * 5000 + ".2",  # more digits than int() converts
            [key, key], [key, "x"], ["x", key],  # repeated: neither the first nor the last
        ]  # fmt: skip
        for view in (self.packages, self.updates):
            plain = self.context(view)
            self.assertNotEqual(plain["selected"]["package"], "inner")
            for item in items:
                with self.subTest(view=view, item=str(item)[:40]):
                    # The template gets what it gets without an item: nothing says it was given.
                    self.assertEqual(self.context(view, item), plain)
            self.assertEqual(self.selected(view, key)["package"], "inner")

    def test_runs_of_other_files_or_another_project_are_never_opened_or_read(self):
        twin = self.root / "twin"
        twin.mkdir()
        for name in ("package.json", "package-lock.json"):
            (twin / name).write_bytes((self.project / name).read_bytes())
        twin_id = history.register_project(twin)
        foreign = self.check(
            project=twin, targets=None
        )  # the same files and rows, not this project
        stale = self.check(targets=None, package_lock_sha256="4" * 64)  # this project, other files
        unused = [mock.patch.object(*target) for target in (
            (service, "preview_files"), (service, "scan_project"), (service, "apply_preview"),
            (service, "check_package"), (subprocess, "Popen"), (socket, "create_connection"),
        )]  # fmt: skip
        calls = [patcher.start() for patcher in unused]
        for patcher in unused:
            self.addCleanup(patcher.stop)
        stored = self.db.read_bytes()
        for view in (self.packages, self.updates):
            plain = self.context(view)
            for run in (foreign, stale, stale + 1):  # the last is no run at all
                with (
                    self.subTest(view=view, run=run),
                    mock.patch.object(history, "get_run", wraps=history.get_run) as read,
                ):
                    self.assertEqual(self.context(view, f"{run}.2"), plain)
                    # Only the report of the current check is read, as without an item.
                    self.assertEqual(read.call_args_list, [mock.call(self.checked)])
        # The other project opens its own first row, whatever this project's key says.
        row = self.selected(f"/projects/{twin_id}/updates", self.keys["inner"])
        self.assertEqual((row["run_id"], row["package"]), (foreign, "other"))
        # Once the files change, the check that was current is one of other files too.
        self.head.write_bytes(self.head.read_bytes() + b"\n")
        with mock.patch.object(history, "get_run", wraps=history.get_run) as read:
            for view in (self.packages, self.updates):
                self.assertIsNone(self.selected(view), view)
                self.assertIsNone(self.selected(view, self.keys["inner"]), view)
        read.assert_not_called()
        self.assertEqual([called.call_count for called in calls], [0] * len(calls))
        self.assertEqual(self.db.read_bytes(), stored)  # looking wrote nothing

    def test_a_row_says_what_its_own_stored_report_was_checked_with_and_no_more(self):
        # Later checks of other alone: without a list, then a report older than the detector
        # fields that also has no model. What a report does not say stays None.
        bare = {**older(self.unlisted), "model_id": None, "threshold": None}
        for report, expected in ((self.unlisted, ("unit-test", 0.5, None)), (bare, (None,) * 3)):
            run = self.check(self.rows(report, "other"), targets=["other"])
            row = self.selected(self.updates, f"{run}.0")
            self.assertEqual((row["package"], *(row[key] for key in CHECKED_WITH)),
                             ("other", *expected))  # fmt: skip
            # The check of everything still gives the other rows, with its own values.
            row = self.selected(self.updates, self.keys["example"])
            self.assertEqual([row[key] for key in CHECKED_WITH],
                             ["unit-test", 0.5, KnownList.list_as_of])  # fmt: skip

    def test_the_tabs_and_the_search_narrow_the_list_together(self):
        # A later check of other alone found nothing: other is installed and has no candidate.
        self.check({**self.report, "results": []}, targets=["other"], changed_count=0)
        for query, expected, show in (
            ("", ["example", "inner", "other"], "all"),
            ("show=candidates", ["example", "inner"], "candidates"),
            ("show=candidates&q=IN", ["inner"], "candidates"),
            ("q=IN&show=candidates", ["inner"], "candidates"),  # in either order
            ("show=candidates&scope=direct", ["example"], "candidates"),
            ("show=candidates&scope=nested&q=inner", ["inner"], "candidates"),
            ("show=candidates&q=other", ["other"], "all"),  # the search leaves no candidate
            ("show=none", ["other"], "none"),
            ("q=other", ["other"], "all"),
        ):
            with self.subTest(query=query):
                context = self.context(f"{self.packages}?{query}")
                self.assertEqual([row["name"] for row in context["rows"]], expected)
                self.assertEqual(context["show"], show)
                # The tabs count what the search and the kind leave: their parts make the whole.
                counts = context["counts"]
                self.assertEqual(counts["candidates"] + counts["unchecked"] + counts["none"],
                                 counts["all"])  # fmt: skip
                self.assertEqual(context["query"], "IN" if "q=IN" in query else
                                 "inner" if "q=inner" in query else
                                 "other" if "q=other" in query else "")  # fmt: skip
        self.assertEqual(self.context(self.packages)["counts"],
                         {"all": 3, "candidates": 2, "unchecked": 0, "none": 1})  # fmt: skip
        # The view opens one of the rows the tab leaves.
        row = self.selected(f"{self.packages}?show=candidates&item={self.keys['inner']}")
        self.assertEqual(row["package"], "inner")
        self.assertIsNone(self.selected(f"{self.packages}?show=none&item={self.keys['inner']}"))
        for query in ("show=", "show=yes", "show=none&show=none", "show=candidates&show=none"):
            self.assertEqual(self.get(f"{self.packages}?{query}").status_code, 400, query)
        for query in ("only=0", "only=", "only=true", "only=1&only=1"):  # the old filter: no more
            self.assertEqual(self.get(f"{self.packages}?{query}").status_code, 200, query)

    def test_the_updates_view_groups_its_candidates_by_whether_they_could_be_applied(self):
        def first(report, name):
            return self.rows(report, name)["results"][0]

        free = first(self.scanned(0.1, known_malicious=KnownList()), "inner")
        held = first(self.scanned(analyzer=False, known_malicious=KnownList()), "example")
        refused = first(self.scanned(0.012, known_malicious=KnownList((ADVISORY,))), "other")
        removed = {**free, "package": "new", "location": ROWS["new"][0], "before_version": "3.0.0",
                   "after_version": None, "status": "removed", "score": None}  # fmt: skip
        report = self.scanned(0.1, known_malicious=KnownList())
        run = self.check({**report, "results": [free, held, removed, refused]}, targets=None)
        html = self.page(self.updates)
        # What needs a look first; each group says how many it holds; in a group, report order.
        groups = re.findall(r'<h3 class="group-title" id="group-(\w+)">(?:<span class="cell (\w+)" '
                            r'aria-hidden="true"></span>)?([^<]+) <span class="group-count">(\d+)개'
                            r"</span></h3>", html)  # fmt: skip
        self.assertEqual(groups, [("refused", "risk", "반영 거부", "1"), ("confirm", "hold", "확인 필요", "1"),
                                  ("free", "pass", "반영 가능", "1"), ("removed", "", "삭제", "1")])  # fmt: skip
        listed = re.findall(r'<tr><th scope="row">([^<]*)<span class="row-tags">', html)
        self.assertEqual(listed, ["other", "example", "inner", "new"])
        # The view opens the first candidate it shows: the riskiest.
        self.assertEqual(self.selected(self.updates)["package"], "other")
        # A row: the stored verdict and its reason on one line, the score, the way to its
        # evidence. The detectors and the facts are the inspector's.
        row = html.split('<th scope="row">example<span', 1)[1].split("</tr>", 1)[0]
        self.assertIn('<span class="verdict hold"><span class="cell hold" aria-hidden="true"></span>'
                      "보류</span>", row)  # fmt: skip
        self.assertIn('<p class="row-why">분석 결과 없음</p>', row)
        self.assertIn(
            f'href="{self.updates}?item={run}.1#candidate-evidence">근거 열기',
            row,
        )
        outside = html.split('<aside class="inspector"', 1)[0]
        for absent in ('class="detectors"', "synthetic evidence", f"/runs/{run}#r"):
            self.assertNotIn(absent, outside)
        # The named check is one line above, folded until it is opened.
        self.assertRegex(html, r'(?s)<div class="action-line">\s*<details class="named">\s*'
                               r"<summary>패키지를 지정해 업데이트 검사</summary>.*?"
                               rf'<form method="post" action="{self.packages}/previews"')  # fmt: skip
        self.assertIn('name="packages" type="text"', html)

    def test_the_updates_view_opens_its_riskiest_candidate_and_says_why_each_waits(self):
        def first(report, name):
            return self.rows(report, name)["results"][0]

        scored = first(self.scanned(0.9, known_malicious=KnownList()), "inner")  # an ML hit
        refused = first(self.scanned(0.012, known_malicious=KnownList((ADVISORY,))), "other")
        unlisted = first(self.scanned(0.1), "example")  # no known malicious list checked
        report = self.scanned(0.1, known_malicious=KnownList())
        self.check({**report, "results": [scored, refused, unlisted]}, targets=None)
        # The report's own order puts the ML hit first; the view opens the refused one.
        self.assertEqual(self.context(self.updates)["state"]["rows"][0]["package"], "inner")
        self.assertEqual(self.selected(self.updates)["package"], "other")
        html = self.page(self.updates)
        row = html.split('<th scope="row">example<span', 1)[1].split("</tr>", 1)[0]
        self.assertIn('<p class="row-why">', row)
        self.assertIn("기지 악성 목록 미확인", row)
        # The named preview updates what it names, with what that changes under it.
        self.assertNotIn("적은 이름만 계산", html)
        self.assertIn("그 직접 의존성만 대상으로 삼고, 그것이 필요로 하는 간접 의존성은 npm이 함께 다시 계산합니다", html)

    def test_grouped_puts_what_needs_a_look_first(self):
        def row(key, status="flagged", n=0):
            return {"decision": {"key": key}, "status": status, "n": n}

        rows = [row("free", n=1), row("confirm", n=2), row("free", "removed", 3),
                row("refused", n=4), row("refused", "removed", 5), row("free", "passed", 6)]  # fmt: skip
        self.assertEqual(
            [(g["key"], g["cell"], g["label"], [r["n"] for r in g["rows"]]) for g in self.app._grouped(rows)],
            [("refused", "risk", "반영 거부", [4, 5]), ("confirm", "hold", "확인 필요", [2]),
             ("free", "pass", "반영 가능", [1, 6]), ("removed", None, "삭제", [3])],
        )  # fmt: skip
        self.assertEqual(self.app._grouped([]), [])

    def test_a_tab_keeps_the_open_candidate_and_an_empty_tab_is_no_link(self):
        inner = self.keys["inner"]
        html = self.page(f"{self.packages}?item={inner}")
        tabs = html.split('<nav class="filter-tabs"', 1)[1].split("</nav>", 1)[0]
        self.assertIn(
            f'href="/projects/{self.project_id}?show=candidates&amp;item={inner}"',
            tabs,
        )
        self.assertIn(f'<input type="hidden" name="item" value="{inner}">', html)
        self.assertEqual(
            self.selected(f"{self.packages}?show=candidates&item={inner}")["package"], "inner"
        )
        # A search that leaves nothing: every tab is words, the open one marked.
        tabs = self.page(f"{self.packages}?q=missing").split('<nav class="filter-tabs"', 1)[1]
        tabs = tabs.split("</nav>", 1)[0]
        self.assertNotIn("<a ", tabs)
        self.assertIn(
            '<span class="filter-off" aria-current="true">전체 <span class="filter-count">0</span></span>',
            tabs,
        )

    def test_a_tab_with_nothing_to_show_lists_everything(self):
        # No current check: nothing is known, and an address kept from before lists everything.
        self.head.write_bytes(self.head.read_bytes() + b"\n")
        context = self.context(f"{self.packages}?show=candidates")
        self.assertEqual((context["show"], context["counts"]["candidates"], context["state"]["checks"],
                          len(context["rows"])), ("all", 0, [], 3))  # fmt: skip
        # A check of everything that found nothing: 0 is known, and the list is still whole.
        run = self.check({**self.report, "results": []}, targets=None, changed_count=0)
        context = self.context(f"{self.packages}?show=candidates")
        self.assertEqual((context["show"], context["counts"]["candidates"], len(context["rows"]),
                          [check["id"] for check in context["state"]["checks"]]),
                         ("all", 0, 3, [run]))  # fmt: skip

    def scanned(self, *signal, **detectors):
        """A report of example 1.1.0 to 1.2.0 as setUp's are: scanned while the lockfile is the
        one an update would write, which is then put back as it is now, byte for byte."""
        self.save_locks()
        try:
            return self.scan_with(*signal, **detectors)
        finally:
            self.write(self.head, self.old)

    def decided(self, report):
        (row,) = report["results"]
        decision = self.app._decision(row)
        # Never a rule of its own: what the update gate says of the report.
        refused, confirm = service.update_gate(report)
        self.assertEqual(decision["key"], "refused" if refused else "confirm" if confirm else
                         "free")  # fmt: skip
        return decision["cell"], decision["label"], decision["why"]

    def test_whether_a_candidate_could_be_applied_is_what_the_update_gate_says_of_it(self):
        listed, clean = KnownList((ADVISORY,)), KnownList()
        confirm = self.app.CONFIRM_WHY
        self.assertEqual(self.decided(self.scanned(0.1, known_malicious=clean)),
                         ("pass", "반영 가능", self.app.FREE_WHY))  # fmt: skip
        # A known malicious match is refused whatever the score, and the score stays as it is.
        low = self.scanned(0.1, known_malicious=listed)
        self.assertEqual(self.decided(low), ("risk", "반영 거부", self.app.REFUSED_WHY))
        self.assertEqual((low["results"][0]["score"], low["results"][0]["ml"]["status"]),
                         (0.1, "not_hit"))  # fmt: skip
        self.assertEqual(self.decided(self.scanned(0.9, known_malicious=listed))[1], "반영 거부")
        # What needs the user's confirmation says each cause, in the words of the gate.
        for report, causes in (
            (self.scanned(0.9, known_malicious=clean), "ML 위험 점수 기준 이상"),
            (self.scanned(0.9), "ML 위험 점수 기준 이상; 기지 악성 목록 미확인"),
            (self.scanned(0.1), "기지 악성 목록 미확인"),
            (self.scanned(analyzer=False, known_malicious=clean),
             "보류(통과가 아님), 이유: 분석 결과 없음"),
            (older(self.scanned(0.1)), "기지 악성 목록 미확인"),  # no slot is no not_hit
            (self.scanned(0.1, known_malicious=KnownList(error=RuntimeError("x"))),
             "보류(통과가 아님), 이유: 연결된 탐지기 실패; 기지 악성 목록 미확인"),
        ):  # fmt: skip
            with self.subTest(causes=causes):
                self.assertEqual(
                    self.decided(report), ("hold", "확인 필요", f"{confirm}: {causes}.")
                )
        # An entry that is removed installs nothing; a match would still refuse it.
        gone = self.scanned(0.1, known_malicious=clean)
        gone["results"][0].update(status="removed", after_version=None, score=None,
                                  ml={"status": "not_run"})  # fmt: skip
        self.assertEqual(self.decided(gone), ("pass", "반영 가능", self.app.REMOVED_WHY))
        gone["results"][0]["known_malicious"]["status"] = "hit"
        self.assertEqual(self.decided(gone)[1], "반영 거부")

    def test_each_detector_says_its_own_result_beside_the_decision(self):
        rules = Rules((rule("hit"), rule("failed", "R2", detail="timeout")))
        report = self.scanned(0.1, known_malicious=KnownList((ADVISORY,)), rules=rules)
        row = self.app._result(report["results"][0], report)
        # Refused by the list; the model's low score and the rules' result are still theirs.
        self.assertEqual((row["decision"]["label"], row["label"], row["score"], row["score_raw"]),
                         ("반영 거부", "위험", "0.100 (기준 미만)", "0.1"))  # fmt: skip
        self.assertEqual(row["known"], {
            "cell": "risk", "status": "일치", "note": None,
            "lines": ["EXAMPLE-ADVISORY-0001 (버전 목록에 있음, 영향 버전 1.1.0)"]})  # fmt: skip
        self.assertEqual((row["rules"]["cell"], row["rules"]["status"]),
                         ("risk", "적중, 실패 1개"))  # fmt: skip
        self.assertEqual(len(row["rules"]["lines"]), 2)
        self.assertIn("EXAMPLE-RULE-0001", row["rules"]["lines"][0])
        self.assertIn("판정에 쓰지 않는 표시입니다.", row["rules"]["note"])
        # Each slot is worded as the report words it (cli._detector_lines), and no more.
        self.assertEqual([line for line, _ in row["detectors"]],
                         [f"기지 악성: {row['known']['status']}",
                          f"규칙: {row['rules']['status']}", row["rules"]["note"]])  # fmt: skip
        self.assertEqual([subs for _, subs in row["detectors"]],
                         [row["known"]["lines"], row["rules"]["lines"], []])  # fmt: skip
        # A detector that is not connected did not run, and one that an older report does not
        # have is unknown: neither is a "found nothing".
        report = self.scanned(0.1, known_malicious=KnownList())
        row = self.app._result(report["results"][0], report)
        self.assertEqual(row["known"], {"cell": None, "status": "미적중", "lines": [],
                                        "note": None})  # fmt: skip
        self.assertEqual(row["rules"], {"cell": "none", "status": "미실행 (탐지기 연결 안 됨)",
                                        "lines": [], "note": None})  # fmt: skip
        old = older(report)
        row = self.app._result(old["results"][0], old)
        for slot in ("known", "rules"):
            self.assertEqual(row[slot], {"cell": "none", "status": "확인 안 됨", "lines": [],
                                         "note": None})  # fmt: skip
        failed = self.scanned(0.1, known_malicious=KnownList(error=RuntimeError("x")))
        row = self.app._result(failed["results"][0], failed)
        self.assertEqual((row["known"]["cell"], row["known"]["status"].split(" ")[0]),
                         ("hold", "실패"))  # fmt: skip

    def test_the_inspector_says_the_decision_then_the_three_detectors_then_the_evidence(self):
        tiny = 3.950535635136895e-07  # a real low score: its stored digits stay on the page
        report = self.rows(self.scanned(tiny, known_malicious=KnownList((ADVISORY,))), "other")
        run = self.check(report, targets=["other"])
        for view in (self.packages, self.updates):
            html = self.page(f"{view}?item={run}.0")
            panel = html.split('<aside class="inspector"', 1)[1].split("</aside>", 1)[0]
            # What a narrow screen never folds: the decision card, then one line per detector
            # and what must not be misread; the evidence comes after.
            top, body = panel.split('<div class="inspect-body">', 1)
            marks = ['<div class="ruling risk">',
                     '<p class="decision"><span class="cell risk" aria-hidden="true"></span>'
                     "반영 거부</p>", f'<p class="why">{self.app.REFUSED_WHY}</p>',
                     '<dl class="detectors">',
                     '<dt>기지 악성 색인</dt><dd><span class="cell risk" aria-hidden="true"></span>'
                     "<b>일치</b>",
                     '<dt>정적 규칙</dt><dd><span class="cell none" aria-hidden="true"></span>'
                     "<b>미실행 (탐지기 연결 안 됨)</b>",
                     '<dt>ML 점수</dt><dd><b class="score">&lt;0.001 (기준 미만)</b>',
                     '<rect class="fill" width="0" height="10"/>',
                     '<line class="tick" x1="50" x2="50" y1="0" y2="10"/>',
                     "정적 규칙: 실행하지 않은 것은 통과가 아닙니다.",
                     "이 화면에서는 반영하지 않습니다."]  # fmt: skip
            places = [top.find(mark) for mark in marks]
            self.assertNotIn(-1, places, view)
            self.assertEqual(places, sorted(places), view)  # in this order
            # The evidence keeps all it said before, each detector on its own.
            marks = ['<h3 id="known-title">기지 악성 색인</h3>',
                     "EXAMPLE-ADVISORY-0001 (버전 목록에 있음, 영향 버전 1.1.0)", "목록 기준 시점: ",
                     '<h3 id="rules-title">정적 규칙</h3>', '<h3 id="score-title">ML 모델</h3>',
                     "<dt>ML 위험 점수</dt><dd>&lt;0.001 (기준 미만)</dd>",
                     f"<dt>점수 원값</dt><dd>{tiny!r}</dd>", "<dt>판정 기준 점수</dt><dd>0.5</dd>",
                     "<dt>모델</dt><dd>unit-test</dd>", "synthetic evidence",
                     '<h3 id="basis-title">저장된 보고서</h3>',
                     f'<a href="/runs/{run}">#{run}</a>',
                     "보고서에서 전체 근거 보기"]  # fmt: skip
            places = [body.find(mark) for mark in marks]
            self.assertNotIn(-1, places, view)
            self.assertEqual(places, sorted(places), view)
            # The status is said once, in the summary.
            self.assertNotIn("<b>일치</b>", body)
            # The versions are the stored strings, each in full.
            self.assertIn("<dt>사용 버전</dt><dd>1.0.0</dd>", top)
            self.assertIn("<dt>후보 버전</dt><dd>1.1.0</dd>", top)
            self.assertNotIn("<form", panel if view == self.updates else "")
        # The list says the same decision in the candidate's own cell.
        cell = self.page(self.packages).split(f"item={run}.0#candidate-evidence", 1)[1]
        self.assertIn('<span class="verdict risk"><span class="cell risk" aria-hidden="true">'
                      "</span>반영 거부</span>", cell.split("</a>", 1)[0])  # fmt: skip
        # A candidate without a score says so in place of the gauge, and that it is no 0.
        unscored = self.rows(self.scanned(analyzer=False, known_malicious=KnownList()), "other")
        run = self.check(unscored, targets=["other"])
        panel = self.page(f"{self.updates}?item={run}.0").split('<aside class="inspector"', 1)[1]
        top, body = panel.split('<div class="inspect-body">', 1)
        self.assertIn("<dt>ML 점수</dt><dd><b>점수 없음</b>", top)
        self.assertIn("점수가 없는 것은 0점이 아닙니다.", top)
        self.assertNotIn('class="gauge"', panel)
        self.assertIn("<dt>ML 위험 점수</dt><dd>없음(미실행)</dd>", body)
        self.assertNotIn("점수 원값", panel)
        self.assertIn('<div class="ruling hold">', panel)
        # A score over the threshold fills its gauge in the risk colour.
        over = self.rows(self.scanned(0.87, known_malicious=KnownList()), "other")
        run = self.check(over, targets=["other"])
        panel = self.page(f"{self.updates}?item={run}.0").split('<aside class="inspector"', 1)[1]
        self.assertIn('<rect class="fill over" width="87" height="10"/>', panel)
        self.assertIn('<div class="ruling hold">', panel)

    def test_a_gauge_is_drawn_only_for_a_score_from_0_to_1(self):
        gauge = self.app._gauge
        self.assertEqual(gauge(0.012, 0.5), {"width": 1.2, "tick": 50, "over": False})
        self.assertEqual(gauge(0.87, 0.5), {"width": 87, "tick": 50, "over": True})
        self.assertEqual(gauge(0.5, 0.5), {"width": 50, "tick": 50, "over": True})
        self.assertEqual(gauge(0, None), {"width": 0, "tick": None, "over": False})
        self.assertEqual(gauge(1, 1.5), {"width": 100, "tick": None, "over": False})
        for score in (None, -0.1, 1.01, float("nan"), float("inf"), True, "0.5"):
            self.assertIsNone(gauge(score, 0.5), score)
        self.assertEqual(gauge(0.3, True), {"width": 30, "tick": None, "over": False})
