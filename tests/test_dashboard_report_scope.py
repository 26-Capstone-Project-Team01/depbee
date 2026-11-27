"""A lockfile report in which no incoming version was checked says so, and why.

No changed dependency, or removals alone, is a pass with exit code 0 although nothing new was
looked at. report.html adds one line for those two reports and for no other.

Synthetic only, as test_dashboard: reports of the real pipeline over the fixture's lockfiles with a
fake analyzer and predictor, stored with the history API and read through the in-process
TestClient; no server, Git, npm or registry.
"""

from unittest import mock

from test_dashboard import BASE, SESSION, S, ScreenFixture
from test_workflow import package

from depbee import history, service

LEAD = "새로 검사한 버전 없음"
UNCHANGED = "바뀐 의존성이 없어 검사할 것이 없습니다."
REMOVALS = "삭제만 있어 새로 들어오는 버전이 없습니다."
# label: (entries removed from the base, example updated, an analyzer, exit code, the reason shown)
CASES = {
    "no changes": ((), False, True, 0, UNCHANGED),
    "removals only": (("gone", "other"), False, True, 0, REMOVALS),
    "a removal beside a scored update": (("gone",), True, True, 0, None),
    "a removal beside a held update": (("gone",), True, False, 2, None),
}


class ScopeNoteTests(ScreenFixture):
    def scanned(self, removed=(), updated=False, analyzer=True):
        """The pipeline's report of these lockfiles: example at 1.0.0, updated to 1.1.0 or left
        alone, and the removed entries in the base alone."""
        self.old["packages"] = {f"node_modules/{n}": package() for n in ("example", *removed)}
        self.new["packages"] = {"node_modules/example": package("1.1.0" if updated else "1.0.0")}
        self.save_locks()
        return self.scan_with(analyzer=analyzer)

    def assert_note(self, html, reason):
        """The page has the note with this reason alone, or no note."""
        self.assertEqual(html.count(LEAD), 1 if reason else 0)
        for text in (UNCHANGED, REMOVALS):
            self.assertEqual(text in html, text == reason, text)

    def test_a_saved_run_says_when_no_incoming_version_was_checked(self):
        for label, (removed, updated, analyzer, exit_code, reason) in CASES.items():
            with self.subTest(label):
                report = self.scanned(removed, updated, analyzer)
                self.assertEqual(report["exit_code"], exit_code)
                self.assert_note(self.page(f"/runs/{self.record(report)}"), reason)

    def test_a_run_of_another_base_gets_the_note_without_a_claim_about_head(self):
        # depbee scan --base-ref v1.0.0: stored and shown by the same template.
        run = history.record("scan", self.project, self.scanned(), None, base_ref="v1.0.0",
                             base_lock=False)  # fmt: skip
        html = self.page(f"/runs/{run}")
        self.assert_note(html, UNCHANGED)
        (line,) = (line for line in html.splitlines() if LEAD in line)
        self.assertNotIn("HEAD", line)

    def test_one_version_checked_alone_has_no_note(self):
        # A depbee check report has no lockfile, so no changed dependency to speak of. Its one
        # result is never a removal; an empty stored one is what would reach the lockfile wording.
        report = {**self.scanned(), "input_kind": "package"}
        self.assert_note(self.page(f"/runs/{self.record(report)}"), None)

    def test_the_unrecorded_scan_and_the_update_preview_show_it_too(self):
        self.report = self.scanned(removed=("gone",))  # what the fixture's preview returns
        with mock.patch.object(service, "scan_project", return_value=self.report), \
             mock.patch.object(history, "record", return_value=None):  # fmt: skip
            unrecorded = self.client.post(f"{S}/projects/{self.project_id}/scans",
                                          data={"session": SESSION}, headers={"origin": BASE})  # fmt: skip
        self.assertEqual(unrecorded.status_code, 200)
        self.assert_note(unrecorded.text, REMOVALS)
        self.assert_note(self.page(f"/previews/{self.preview_id()}"), REMOVALS)
