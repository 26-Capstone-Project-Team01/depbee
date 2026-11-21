"""Dashboard inspector selection: the update candidate that a project's packages and updates
views hand their template as `selected`, and what the item query (<run id>.<position>) selects.

Read from what a view renders its template with (the keyword arguments of the Jinja render,
captured here in the test alone), not from the markup, so that the tests hold whatever the pages
look like. Synthetic only, as in test_dashboard.py: stored reports of pipeline.scan() with a fake
list and predictor, in each test run's folder; no server, npm or registry.
"""

import json
import socket
import subprocess
from unittest import mock

import test_dashboard  # the module: its test classes, imported by name, would run again here
from test_detectors import KnownList
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
        return template.render.call_args.kwargs

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
        # position its item names, and what that report was checked with: nothing else.
        row = self.selected(self.updates, self.keys["example"])
        self.assertEqual(row, {
            **self.app._result(self.report["results"][1], self.report), "before": "1.1.0",
            "after": "1.2.0", "run_id": self.checked, "position": 1, "model_id": "unit-test",
            "threshold": 0.5, "list_as_of": KnownList.list_as_of})  # fmt: skip
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
        wide = key.translate(str.maketrans("0123456789", "０１２３４５６７８９"))  # int() reads these
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
        foreign = self.check(project=twin, targets=None)  # the same files and rows, not this project
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
