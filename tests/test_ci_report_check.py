"""Which reports CI's check of a real scan accepts (.github/scripts/check_lodash_report.py).

These tests build reports from the checkout's manifests and analyzer pin. CI also runs the
checker against real scans from the Action, CLI update preview and MCP server.
"""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
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
                "package": "lodash", "before_version": "4.17.20", "after_version": "4.17.21",
                "compared_version": "4.17.20", "status": "not_flagged", "score": 3.9e-07,
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


if __name__ == "__main__":
    unittest.main()
