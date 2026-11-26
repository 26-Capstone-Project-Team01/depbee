"""Which reports CI's check of a real scan accepts (.github/scripts/check_lodash_report.py).

These tests build reports from the checkout's manifests and analyzer pin. CI also runs the
checker against real scans from the Action, CLI update preview and MCP server, and compares
those of the Action, CLI scan, CLI update preview, MCP server and dashboard with one another.
"""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY / ".github" / "scripts" / "check_lodash_report.py"
FILES = "a" * 64  # a digest of installed analyzer files, in the form depbee writes
RULESET = "2026-11-16.1"
RULE_IDS = ("R_download_exec", "R_secret_send", "R_ci_secret_send", "R_install_root_wipe",
            "R_remote_admin_auth_override", "R_diff_obfuscation")  # fmt: skip
GONE = object()  # in place of a value: the key is not in the report at all


@unittest.skipUnless(SCRIPT.is_file(), "not run from a checkout")
class ReportCheckTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("check_lodash_report", SCRIPT)
        self.script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.script)
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        assets = REPOSITORY / "src" / "depbee" / "assets"
        manifest = (assets / "model" / "manifest.json").read_bytes()
        model = json.loads(manifest)
        index = json.loads((assets / "index" / "manifest.json").read_bytes())
        project = tomllib.loads((REPOSITORY / "pyproject.toml").read_text("utf-8"))
        (pin,) = project["project"]["optional-dependencies"]["extract"]
        self.report = {
            "request_id": "1" * 64, "analyzer_version": "depbee-analyzer 0.1.0",
            "status": "passed", "exit_code": 0, "model_id": model["model_id"], "threshold": 0.5,
            "detectors": {"known_malicious": {"list_as_of": index["list_as_of"],
                                              "list_sha256": index["index_sha256"]},
                          "rules": {"ruleset_version": RULESET}},
            "provenance": {
                "model": {"model_sha256": model["model_sha256"],
                          "manifest_sha256": hashlib.sha256(manifest).hexdigest()},
                "feature_extractor": {"commit": pin.rpartition("@")[2], "files_sha256": FILES},
            },
            "results": [{
                "change_id": "2" * 64, "location": "node_modules/lodash",
                "evidence": ["compared: 4.17.20 to 4.17.21"], "rule_ml_agreement": "neither_hit",
                "package": "lodash", "before_version": "4.17.20", "after_version": "4.17.21",
                "compared_version": "4.17.20", "status": "not_flagged", "score": 3.9e-07,
                # The interval between the two registry publication times, in seconds.
                "features": {"updateInterval": 16498102.739, "obfChangedFileCount": 12},
                "explanation": [{"feature": "updateInterval", "value": 16498102.739,
                                 "contribution": 1.4411851233672934}],
                "explanation_rest": {"others_sum": -2.1462282905653183, "others_count": 26,
                                     "base_value": -7.330612719319918},
                "ml": {"status": "not_hit"}, "known_malicious": {"status": "not_hit"},
                "rules": {"status": "not_hit", "checks": [
                    {"rule_id": rule_id, "rule_version": RULESET, "status": "not_hit"}
                    for rule_id in RULE_IDS]},
            }],
        }  # fmt: skip

    def refused(self, data, *arguments):
        """Whether the script ends with an error for this report, as a failed CI step does."""
        file = self.tmp / "report.json"
        file.write_text(json.dumps(data), "utf-8")
        try:
            with contextlib.redirect_stdout(io.StringIO()):  # its one line for the job's log
                self.script.main(str(file), *arguments)
        except (AssertionError, KeyError, TypeError, ValueError):
            return True
        return False

    def test_the_passing_report_is_accepted_alone_and_inside_another_answer(self):
        self.assertFalse(self.refused(self.report))
        self.assertFalse(self.refused({"preview": {}, "report": self.report}))  # depbee update
        # With the digest of the analyzer installed where the report was made.
        self.assertFalse(self.refused(self.report, FILES))
        # A review-level rule hit is display only and passes.
        hit = copy.deepcopy(self.report)
        hit["results"][0]["rules"]["status"] = "hit"
        hit["results"][0]["rules"]["checks"][0]["status"] = "hit"
        self.assertFalse(self.refused(hit))

    def test_a_report_that_does_not_prove_the_scan_is_refused(self):
        def changed(*path, to):
            """The passing report with the value at path replaced, or removed for to=GONE."""
            report = copy.deepcopy(self.report)
            at = report
            for key in path[:-1]:
                at = at[key]
            if to is GONE:
                del at[path[-1]]
            else:
                at[path[-1]] = to
            return report

        row = ("results", 0)
        model, analyzer = ("provenance", "model"), ("provenance", "feature_extractor")
        cases = {
            # Held, not passed: what an unreachable registry or a missing analyzer leaves.
            "held overall": {**changed("status", to="incomplete"), "exit_code": 2},
            "a held item": changed(*row, "status", to="incomplete"),
            "an item the model did not score": changed(*row, "ml", to={"status": "not_run"}),
            "no score": changed(*row, "score", to=None),
            "a score at the threshold": changed(*row, "score", to=0.5),
            "another comparison": changed(*row, "compared_version", to="4.17.19"),
            "another update": changed(*row, "after_version", to="4.17.22"),
            "two items": changed("results", to=self.report["results"] * 2),
            "a known malicious match": changed(*row, "known_malicious", to={"status": "hit"}),
            # Not this checkout's model, manifest or index.
            "another model ID": changed("model_id", to="D00-E00"),
            "other model bytes": changed(*model, "model_sha256", to="0" * 64),
            "another manifest": changed(*model, "manifest_sha256", to="0" * 64),
            "no manifest digest": changed(*model, "manifest_sha256", to=GONE),
            "another index": changed("detectors", "known_malicious", "list_sha256", to="0" * 64),
            "another list time": changed("detectors", "known_malicious", "list_as_of",
                                         to="2026-01-01T00:00:00Z"),  # fmt: skip
            # Not the verified Git install of the pinned analyzer.
            "an unverified analyzer": changed(*analyzer, to=None),  # null, as depbee writes it
            "another commit": changed(*analyzer, "commit", to="0" * 40),
            "no digest of the installed files": changed(*analyzer, "files_sha256", to=GONE),
            "a digest one digit short": changed(*analyzer, "files_sha256", to="a" * 63),
            "a digest in capitals": changed(*analyzer, "files_sha256", to="A" * 64),
            # The pinned analyzer's rules did not judge this update.
            "no rule detector": changed("detectors", "rules", to=None),
            "no rules entry": changed("detectors", "rules", to=GONE),
            "rules not run": changed(*row, "rules", to={"status": "not_run", "checks": []}),
            "an undetermined rule": changed(*row, "rules", "checks", 5, "status", to="failed"),
            "five rules": changed(*row, "rules", "checks",
                                  to=self.report["results"][0]["rules"]["checks"][:5]),
            "another rule version": changed(*row, "rules", "checks", 0, "rule_version", to="0"),
            "another ruleset": changed("detectors", "rules", "ruleset_version", to="0"),
            "other rules, one version": {**changed(*row, "rules", "checks", to=[
                {"rule_id": f"R{i}", "rule_version": "0", "status": "not_hit"}
                for i in range(6)]), "detectors": {**self.report["detectors"],
                                                    "rules": {"ruleset_version": "0"}}},
            "the rules in another order": changed(*row, "rules", "checks", to=list(reversed(
                self.report["results"][0]["rules"]["checks"]))),
            "not_hit over a hit": changed(*row, "rules", "checks", 2, "status", to="hit"),
            "hit over no hit": changed(*row, "rules", "status", to="hit"),
        }
        for name, report in cases.items():
            with self.subTest(name):
                self.assertTrue(self.refused(report))
        # The right form, but not the files installed where the report was made.
        self.assertTrue(self.refused(self.report, "b" * 64))

    def sources(self, **documents):
        """NAME=FILE arguments for these documents, each written to a file of its own."""
        for name, document in documents.items():
            (self.tmp / f"{name}.json").write_text(json.dumps(document), "utf-8")
        return [f"{name}={self.tmp / f'{name}.json'}" for name in documents]

    def compared(self, *arguments):
        """What the comparison ends with: None when the reports agree, else its message."""
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                self.script.compare(*arguments)
        except SystemExit as stopped:
            return stopped.code
        return None

    def entries(self):
        """The passing report as five entry points give it, each in its own envelope and with
        what belongs to one run or host made different: times, cache hits, the Python."""
        def run(number):
            report = copy.deepcopy(self.report)
            report["elapsed_seconds"] = number * 1.5
            report["provenance"]["feature_extractor"]["python"] = f"3.13.{number}"
            report["results"][0].update(elapsed_seconds=number * 1.25, cache_hit=number > 1)
            return report

        return {
            "action": run(1),
            "cli": run(2),
            "update": {"preview": {"npm_version": "11.6.1"}, "report": run(3)},
            "mcp": {"report": run(4), "notices": ["notice"], "package_data": {}},
            # history.get_run: the run's columns next to the stored report.
            "dashboard": {"id": 7, "kind": "scan", "status": "passed", "exit_code": 0,
                          "report": run(5), "preview": None, "results": [], "apply": None},
        }  # fmt: skip

    def test_reports_that_say_the_same_agree_whatever_holds_them(self):
        entries = self.entries()
        self.assertIsNone(self.compared(*self.sources(**entries)))
        # With the digest of the one analyzer install that made them all.
        self.assertIsNone(self.compared(*self.sources(**entries), FILES))
        with self.assertRaises(AssertionError):
            self.compared(*self.sources(**entries), "b" * 64)
        # What the model computed, in the last digits only, as another operating system's math
        # library gives it: the score, a contribution, the sum of the others and the base value.
        row = entries["dashboard"]["report"]["results"][0]
        row["score"] = 3.900000000000001e-07
        row["explanation"][0]["contribution"] = 1.4411851233672936
        row["explanation_rest"].update(others_sum=-2.146228290565318,
                                       base_value=-7.330612719319919)  # fmt: skip
        self.assertIsNone(self.compared(*self.sources(**entries)))

    def test_only_what_the_model_computed_may_differ_in_its_last_digits(self):
        def changed(*path, to):
            report = copy.deepcopy(self.report)
            at = report
            for key in path[:-1]:
                at = at[key]
            at[path[-1]] = to
            return report

        row = ("results", 0)
        cases = {
            # One millisecond more between the two publication times, which the analyzer reads
            # from the registry and the explanation repeats: the review's real report.
            "the interval": (
                {**changed(*row, "features", "updateInterval", to=16498102.74),
                 "results": [{**self.report["results"][0],
                              "features": {"updateInterval": 16498102.74,
                                           "obfChangedFileCount": 12},
                              "explanation": [{"feature": "updateInterval",
                                               "value": 16498102.74,
                                               "contribution": 1.4411851233672934}]}]},
                "results[0].features.updateInterval differs: cli=16498102.739, mcp=16498102.74\n"
                "results[0].explanation[0].value differs: cli=16498102.739, mcp=16498102.74"),
            "a threshold in its last digit": (
                changed("threshold", to=0.5000000000000001),
                "threshold differs: cli=0.5, mcp=0.5000000000000001"),
            "a count as a float": (
                changed(*row, "features", "obfChangedFileCount", to=12.0),
                "results[0].features.obfChangedFileCount differs: cli=12, mcp=12.0"),
            "one more among many": (
                changed(*row, "explanation_rest", "others_count", to=27),
                "results[0].explanation_rest.others_count differs: cli=26, mcp=27"),
            # Beyond the last digits, each of the four fields is named.
            "a contribution": (
                changed(*row, "explanation", 0, "contribution", to=1.4411851233),
                "results[0].explanation[0].contribution differs: "
                "cli=1.4411851233672934, mcp=1.4411851233"),
            "the sum of the others": (
                changed(*row, "explanation_rest", "others_sum", to=-2.1462282905),
                "results[0].explanation_rest.others_sum differs: "
                "cli=-2.1462282905653183, mcp=-2.1462282905"),
            "the base value": (
                changed(*row, "explanation_rest", "base_value", to=-7.3306127193),
                "results[0].explanation_rest.base_value differs: "
                "cli=-7.330612719319918, mcp=-7.3306127193"),
            # No number for a model output: false is not the score 0.0, nor is the integer 0.
            "a score of false": (
                changed(*row, "score", to=False), "results[0].score differs: cli=0.0, mcp=False"),
            "a score of integer zero": (
                changed(*row, "score", to=0), "results[0].score differs: cli=0.0, mcp=0"),
        }  # fmt: skip
        zero = changed(*row, "score", to=0.0)
        for name, (other, message) in cases.items():
            with self.subTest(name):
                one = zero if "score" in name else self.report
                self.assertFalse(self.refused(other))
                self.assertEqual(self.compared(*self.sources(cli=one, mcp={"report": other})),
                                 f"report parity failed\n{message}")  # fmt: skip

    def test_a_field_is_known_by_its_whole_path_not_by_its_last_name(self):
        """A feature may have the name of a field that is left out or allowed to differ in its
        last digits elsewhere in the report."""
        def named(**features):
            report = copy.deepcopy(self.report)
            report["results"][0]["features"].update(features)
            return report

        for name, (one, other, at) in {
            "score": (0.25, 0.25000000000000006, "features.score"),
            "contribution": (1.5, 1.5000000000000002, "features.contribution"),
            "base_value": (-7.5, -7.500000000000001, "features.base_value"),
            "cache_hit": (False, True, "features.cache_hit"),
            "elapsed_seconds": (1.25, 2.5, "features.elapsed_seconds"),
            "python": ("3.13.5", "3.13.18", "features.python"),
        }.items():
            with self.subTest(name):
                self.assertEqual(
                    self.compared(*self.sources(cli=named(**{name: one}),
                                                mcp=named(**{name: other}))),
                    f"report parity failed\nresults[0].{at} differs: cli={one!r}, mcp={other!r}")  # fmt: skip

    def test_one_changed_score_is_named_with_every_source(self):
        entries = self.entries()
        entries["mcp"]["report"]["results"][0]["score"] = 3.8e-07
        self.assertFalse(self.refused(entries["mcp"]))  # accepted by itself
        self.assertEqual(
            self.compared(*self.sources(**entries)),
            "report parity failed\n"
            "results[0].score differs: action=3.9e-07, cli=3.9e-07, update=3.9e-07, "
            "mcp=3.8e-07, dashboard=3.9e-07")  # fmt: skip

    def test_one_changed_rule_is_named_and_no_other(self):
        entries = self.entries()
        rules = entries["dashboard"]["report"]["results"][0]["rules"]
        rules["status"] = rules["checks"][1]["status"] = "hit"  # a hit alone passes: display only
        self.assertFalse(self.refused(entries["dashboard"]))
        self.assertEqual(
            self.compared(*self.sources(action=entries["action"], dashboard=entries["dashboard"])),
            "report parity failed\n"
            "results[0].rules.status differs: action='not_hit', dashboard='hit'\n"
            "results[0].rules.checks[R_secret_send].status differs: "
            "action='not_hit', dashboard='hit'")  # fmt: skip

    def test_other_differences_between_accepted_reports_are_named(self):
        cases = {
            "threshold": (("threshold",), 0.4, "threshold differs: cli=0.5, mcp=0.4"),
            "location": (("results", 0, "location"), "node_modules/a/node_modules/lodash",
                         "results[0].location differs: cli='node_modules/lodash', "
                         "mcp='node_modules/a/node_modules/lodash'"),
            "no location": (("results", 0, "location"), GONE,
                            "results[0].location differs: cli='node_modules/lodash', mcp=absent"),
            # The analyzer and what it found: none of these changes the verdict or the score.
            "analyzer files": (("provenance", "feature_extractor", "files_sha256"), "b" * 64,
                               "provenance.feature_extractor.files_sha256 differs: "
                               f"cli='{FILES}', mcp='{'b' * 64}'"),
            "analyzer version": (("analyzer_version",), "depbee-analyzer 0.2.0",
                                 "analyzer_version differs: cli='depbee-analyzer 0.1.0', "
                                 "mcp='depbee-analyzer 0.2.0'"),
            "agreement": (("results", 0, "rule_ml_agreement"), "ml_only",
                          "results[0].rule_ml_agreement differs: cli='neither_hit', "
                          "mcp='ml_only'"),
            "evidence": (("results", 0, "evidence", 0), "compared: 4.17.19 to 4.17.21",
                         "results[0].evidence[0] differs: cli='compared: 4.17.20 to 4.17.21', "
                         "mcp='compared: 4.17.19 to 4.17.21'"),
            "a rule's evidence": (("results", 0, "rules", "checks", 1, "evidence"), ["a.js:3"],
                                  "results[0].rules.checks[R_secret_send].evidence[0] differs: "
                                  "cli=absent, mcp='a.js:3'"),
            "another request": (("request_id",), "3" * 64,
                                f"request_id differs: cli='{'1' * 64}', mcp='{'3' * 64}'"),
            # 0 and false are equal in Python and are not the same exit code in a report.
            "exit code": (("exit_code",), False, "exit_code differs: cli=0, mcp=False"),
        }  # fmt: skip
        for name, (path, to, message) in cases.items():
            with self.subTest(name):
                changed = copy.deepcopy(self.report)
                at = changed
                for key in path[:-1]:
                    at = at[key]
                if to is GONE:
                    del at[path[-1]]
                else:
                    at[path[-1]] = to
                self.assertFalse(self.refused(changed))
                self.assertEqual(
                    self.compared(*self.sources(cli=self.report, mcp={"report": changed})),
                    f"report parity failed\n{message}")  # fmt: skip

    def test_a_comparison_needs_two_names_and_reports_that_each_prove_their_scan(self):
        held = {**self.report, "status": "incomplete", "exit_code": 2}
        (one,) = self.sources(cli=self.report)
        for name, arguments in {
            "one source": [one],
            "one name twice": [one, one],
            "a file without a name": [one, str(self.tmp / "cli.json")],
            "two held reports that agree": self.sources(action=held, mcp=held),
        }.items():
            with self.subTest(name), self.assertRaises(AssertionError):
                self.compared(*arguments)

    def test_the_command_ends_with_an_error_code_and_the_fields(self):
        changed = copy.deepcopy(self.report)
        changed["results"][0]["score"] = 3.8e-07

        def run(*arguments, flags=("-I",)):
            return subprocess.run([sys.executable, *flags, str(SCRIPT), *arguments],
                                  capture_output=True, text=True, encoding="utf-8")  # fmt: skip

        agreed = run("--compare", *self.sources(cli=self.report, mcp={"report": self.report}))
        self.assertEqual((agreed.returncode, agreed.stderr), (0, ""))
        self.assertIn("2 reports say the same (cli, mcp): score 3.9e-07", agreed.stdout)
        differed = run("--compare", *self.sources(cli=self.report, mcp={"report": changed}))
        self.assertEqual(differed.returncode, 1)
        self.assertEqual(differed.stderr, "report parity failed\n"
                         "results[0].score differs: cli=3.9e-07, mcp=3.8e-07\n")  # fmt: skip
        # The one-file form as before, and no silent pass where assert statements are off.
        (file,) = self.sources(held={**self.report, "status": "incomplete", "exit_code": 2})
        file = file.partition("=")[2]
        self.assertEqual(run(str(self.tmp / "cli.json"), FILES).returncode, 0)
        self.assertEqual(run(file).returncode, 1)
        self.assertNotEqual(run(file, flags=("-I", "-O")).returncode, 0)


if __name__ == "__main__":
    unittest.main()
