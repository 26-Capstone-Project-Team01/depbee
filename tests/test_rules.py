"""The static rules of the pinned depbee-analyzer in the report (analysis.rules).

Synthetic, non-executable data only. The conversion tests give analysis.rules stub findings; the
pinned tests run the installed depbee-analyzer's scanner through the real service path on
synthetic tarballs that a FakeRegistry serves (no network; depbee-analyzer's own requests fail).
The two review-level hits are the benign counterexamples of the 11/20 review (handoffs): an SVG
passed as data to a checker after a download, and the words eval( and atob( in a comment.
"""

import copy
import importlib
import importlib.util
import json
import sys
import tarfile
import unittest
from pathlib import Path
from unittest import mock

from test_extract import FakeBackend, PackagePredictor, packument
from test_registry import FakeRegistry, linked_tgz, sri, tarball_url
from test_workflow import FakePredictor, Fixture

from depbee.analysis import rules
from depbee.analysis.extractor import ExtractorAnalyzer
from depbee.contracts import GuardError
from depbee.pipeline import scan
from depbee.service import check_package, scan_project

PINNED = importlib.util.find_spec("depbee_analyzer") is not None
NO_PIN = "Install .[extract] for the pinned depbee-analyzer"
RULE_IDS = ["R_download_exec", "R_secret_send", "R_ci_secret_send", "R_install_root_wipe",
            "R_remote_admin_auth_override", "R_diff_obfuscation"]  # fmt: skip
STRENGTH = {"R_download_exec": "review", "R_secret_send": "high_evidence",
            "R_ci_secret_send": "high_evidence", "R_install_root_wipe": "high_evidence",
            "R_remote_admin_auth_override": "review", "R_diff_obfuscation": "review"}  # fmt: skip
# Benign counterexamples: nothing here is run, and the URL is in a reserved test domain.
DATA_ARGUMENT = "curl -o logo.svg https://example.invalid/logo.svg && node verify.js logo.svg"
COMMENT = b"// Docs only: we never call eval( or atob( on user input.\nexports.ok = 1;\n"


def finding(rule_id, status="no_hit", paths=(), lines=(), reason="synthetic reason"):
    return {"rule_id": rule_id, "status": status, "disposition": STRENGTH.get(rule_id, "review"),
            "reason": reason, "paths": paths, "lines": lines}  # fmt: skip


def convert(rule_id, status="no_hit", old=(), new=(), hooks="", same=(), **found):
    lost = {"old": list(old), "new": list(new)}
    return rules.convert(finding(rule_id, status, **found), rules.RULESET, lost, hooks, set(same))


class ConversionTests(unittest.TestCase):
    """hit / no_hit / unknown and the missing inputs that could change each rule."""

    def test_complete_results(self):
        hit = convert("R_download_exec", "hit", paths=("package.json",), lines=(7,))
        self.assertEqual(hit, {
            "rule_id": "R_download_exec", "rule_version": rules.RULESET, "status": "hit",
            "evidence": ["검토용 적중(review): synthetic reason"],
            "locations": [{"file": "package.json", "line": 7}], "detail": None,
        })  # fmt: skip
        strong = convert("R_secret_send", "hit", paths=("package.json",), lines=(0,))
        self.assertEqual(strong["evidence"], ["강한 정적 근거(high_evidence): synthetic reason"])
        self.assertEqual(strong["locations"], [{"file": "package.json", "line": None}])  # 0: none
        self.assertEqual(convert("R_ci_secret_send"), {
            "rule_id": "R_ci_secret_send", "rule_version": rules.RULESET, "status": "not_hit",
            "evidence": [], "locations": [], "detail": None,
        })  # fmt: skip

    def test_locations_are_package_relative_and_bounded(self):
        paths = ("/etc/passwd", "C:/x.js", "a\\b.js", "../up.js", "", "ok/a.js", "ok/b.js")
        check = convert("R_diff_obfuscation", "hit", paths=paths, lines=(1, 2, 3, 4, 5, 6))
        self.assertEqual(check["locations"],
                         [{"file": "ok/a.js", "line": 6}, {"file": "ok/b.js", "line": None}])  # fmt: skip
        many = tuple(f"f{i}.js" for i in range(30))
        check = convert("R_diff_obfuscation", "hit", paths=many, lines=(1,) * 30)
        self.assertEqual(len(check["locations"]), rules.MAX_LOCATIONS)
        long = convert("R_diff_obfuscation", "hit", reason="x" * 1000)
        self.assertLessEqual(len(long["evidence"][0]), rules.MAX_TEXT + 3)

    def test_unknown_is_undetermined_never_not_hit(self):
        check = convert("R_secret_send", "unknown", reason="package.json 누락")
        self.assertEqual((check["status"], check["evidence"], check["locations"]),
                         ("failed", [], []))  # fmt: skip
        self.assertTrue(check["detail"].startswith(f"{rules.UNDETERMINED}: package.json 누락"))
        self.assertEqual(convert("R_secret_send", "maybe")["status"], "failed")

    def test_a_missing_file_holds_only_the_rules_that_read_it(self):
        big_js, big_wasm = "dist/bundle.js:size_limit", "bin/engine.wasm:size_limit"
        for rule_id in RULE_IDS:  # a file no rule reads changes nothing
            with self.subTest(rule_id, file="wasm"):
                self.assertEqual(convert(rule_id, new=[big_wasm], old=[big_wasm])["status"],
                                 "not_hit")  # fmt: skip
        held = {rule_id: convert(rule_id, new=[big_js])["status"] for rule_id in RULE_IDS}
        self.assertEqual(held, {**dict.fromkeys(RULE_IDS, "not_hit"),
                                "R_diff_obfuscation": "failed"})  # fmt: skip
        detail = convert("R_diff_obfuscation", new=[big_js])["detail"]
        self.assertIn("새 버전: dist/bundle.js(크기 제한)", detail)
        # A file left the same in both versions cannot make the obfuscation rule hit ...
        same = convert("R_diff_obfuscation", old=[big_js], new=[big_js], same=["dist/bundle.js"])
        self.assertEqual(same["status"], "not_hit")
        # ... but an install hook may newly run it, so the credential rule still cannot tell.
        hooks = "node dist/bundle.js"
        sent = convert("R_secret_send", old=[big_js], new=[big_js], same=["dist/bundle.js"],
                       hooks=hooks)  # fmt: skip
        self.assertEqual(sent["status"], "failed")
        self.assertEqual(convert("R_ci_secret_send", new=[".github/workflows/x.yml:read_error"])
                         ["status"], "failed")  # fmt: skip
        self.assertEqual(convert("R_remote_admin_auth_override", old=["src/index.js:size_limit"])
                         ["status"], "failed")  # fmt: skip

    def test_links_and_odd_entries_may_be_any_path(self):
        for kind in ("symlink", "link", "case", "outside_root"):
            with self.subTest(kind):
                entry = f"docs/readme.md:{kind}"
                statuses = {r: convert(r, new=[entry])["status"] for r in RULE_IDS}
                package_only = {"R_download_exec", "R_install_root_wipe"}
                self.assertEqual(statuses, {r: "not_hit" if r in package_only else "failed"
                                            for r in RULE_IDS})  # fmt: skip
        # A missing package.json holds even the rules that read nothing else.
        self.assertEqual(convert("R_download_exec", new=["package.json:size_limit"])["status"],
                         "failed")  # fmt: skip

    def test_a_hit_against_an_incomplete_earlier_version_is_held(self):
        hit = {"paths": ("lib/util.js",), "lines": (1,)}
        # Missing from the new version: what was found there is still new.
        kept = convert("R_diff_obfuscation", "hit", new=["lib/other.js:size_limit"], **hit)
        self.assertEqual(kept["status"], "hit")
        # Missing from the earlier version: the behaviour may have been there already.
        held = convert("R_diff_obfuscation", "hit", old=["lib/util.js:symlink"], **hit)
        self.assertEqual(held["status"], "failed")
        self.assertIn("이전 버전에서 이 규칙이 읽는 파일이 빠져 새로 생긴 것인지", held["detail"])
        self.assertIn("lib/util.js(링크)", held["detail"])
        self.assertIn("스캐너의 적중 근거: synthetic reason", held["detail"])
        # One that the rule does not read keeps the hit.
        wasm = convert("R_diff_obfuscation", "hit", old=["a.wasm:size_limit"], **hit)
        self.assertEqual(wasm["status"], "hit")

    def test_rules_this_table_does_not_know_count_every_missing_file(self):
        lost = {"old": [], "new": ["x.wasm:size_limit"]}
        check = rules.convert(finding("R_new_rule"), "9.9.9", lost, "", set())
        self.assertEqual((check["status"], check["rule_version"]), ("failed", "9.9.9"))

    def test_missing_files_are_named_briefly(self):
        entries = [f"lib/f{i}.js:size_limit" for i in range(5)]
        detail = convert("R_diff_obfuscation", new=entries)["detail"]
        self.assertIn(
            "lib/f0.js(크기 제한), lib/f1.js(크기 제한), lib/f2.js(크기 제한) 외 2개", detail
        )


class CheckedTests(unittest.TestCase):
    """Rule results from a child or a cache entry: anything but the full set is refused."""

    def full(self):
        return [convert(rule_id) for rule_id in RULE_IDS]

    def test_full_set_passes(self):
        self.assertEqual(rules.checked(self.full(), rules.RULESET), self.full())

    def test_partial_or_malformed_sets_are_refused(self):
        full = self.full()
        cases = {
            "empty": [],
            "not a list": {"checks": full},
            "missing rule": full[:-1],
            "duplicate rule": full + [full[0]],
            "other version": [{**c, "rule_version": "0"} for c in full],
            "unknown status": [{**full[0], "status": "unknown"}] + full[1:],
            "failed without detail": [{**full[0], "status": "failed"}] + full[1:],
            "detail without failure": [{**full[0], "detail": "x"}] + full[1:],
            "extra field": [{**full[0], "disposition": "review"}] + full[1:],
            "bad location": [{**full[0], "locations": [{"file": "a", "line": "1"}]}] + full[1:],
            "evidence not text": [{**full[0], "evidence": [1]}] + full[1:],
        }
        for label, value in cases.items():
            with self.subTest(label):
                self.assertIsNone(rules.checked(value, rules.RULESET))

    def test_results_answer_only_for_their_own_pair(self):
        found = rules.Results(rules.RULESET)
        change = {"change_id": "c1", "after": {"name": "example", "version": "1.1.0"}}
        with self.assertRaisesRegex(GuardError, "No rule scan result"):
            found.check(change, {"baseline_version": "1.0.1"})
        found.found["c1"] = {"pair": ["example", "1.0.1", "1.1.0"], "checks": self.full()}
        with self.assertRaisesRegex(GuardError, "No rule scan result"):
            found.check(change, {"baseline_version": "1.0.0"})  # another compared pair
        given = found.check(change, {"baseline_version": "1.0.1"})
        given[0]["status"] = "hit"  # a copy: the kept result does not change
        self.assertEqual(found.check(change, {"baseline_version": "1.0.1"}), self.full())
        found.found["c1"] = {"pair": ["example", "1.0.1", "1.1.0"], "error": "규칙 스캔 오류(X)"}
        with self.assertRaisesRegex(GuardError, r"규칙 스캔 오류\(X\)"):
            found.check(change, {"baseline_version": "1.0.1"})


class RulesBackend(FakeBackend):
    """FakeBackend with a ruleset: extract() also gives a rule result (rules, or none)."""

    ruleset_version = rules.RULESET

    def __init__(self, doc, found):
        super().__init__(doc)
        self.found = found

    def extract(self, name, old, new, doc, local):
        features, new_json, _ = super().extract(name, old, new, doc, local)
        return features, new_json, copy.deepcopy(self.found)


class AnalyzerTests(Fixture):
    """ExtractorAnalyzer keeps one result per analyzed change of its latest request."""

    def setUp(self):
        super().setUp()
        self.doc = packument({"1.0.0": "2026-01-01T00:00:00Z", "1.0.1": "2026-01-02T00:00:00Z",
                              "1.1.0": "2026-01-03T00:00:00Z"})  # fmt: skip

    def scan(self, found):
        analyzer = ExtractorAnalyzer(backend=RulesBackend(self.doc, found))
        return scan(self.request(), analyzer, PackagePredictor(), rules=analyzer.rules), analyzer

    def test_each_malformed_answer_is_a_detector_failure(self):
        full = [convert(rule_id) for rule_id in RULE_IDS]
        for label, found in (("none", None), ("empty", {"checks": []}),
                             ("partial", {"checks": full[:3]}), ("not a dict", [1])):  # fmt: skip
            with self.subTest(label):
                report, _ = self.scan(found)
                row = report["results"][0]
                self.assertEqual((row["rules"]["status"], row["rules"]["reason"], row["rules"]["checks"]),
                                 ("failed", "detector_failed", []))  # fmt: skip
                self.assertEqual((row["status"], row["reason"], row["score"]),
                                 ("incomplete", "detection_failed", 0.9))  # fmt: skip
        report, _ = self.scan({"checks": full, "cacheable": True})
        self.assertEqual((report["results"][0]["rules"]["status"], report["exit_code"]),
                         ("not_hit", 1))  # fmt: skip

    def test_a_stored_analysis_runs_no_rules(self):
        # A trusted --analysis file has features only: its rules are not run, never not_hit.
        self.adapter()
        with mock.patch("depbee.service.LightGBMPredictor", return_value=FakePredictor()):
            report = scan_project(self.project, self.base, analysis=self.root / "analysis.json",
                                  model_dir=Path("m"))  # fmt: skip
        row = report["results"][0]
        self.assertIsNone(report["detectors"]["rules"])
        self.assertEqual((row["rules"]["status"], row["rules"]["reason"], row["score"]),
                         ("not_run", "detector_not_configured", 0.9))  # fmt: skip

    @unittest.skipUnless(PINNED, NO_PIN)
    def test_an_analyzer_without_its_rules_is_the_missing_analyzer_error(self):
        from depbee.analysis.extractor import FeatureExtractorBackend

        with mock.patch.dict(sys.modules, {"depbee_analyzer.rules.diff_scan": None}), \
                self.assertRaisesRegex(GuardError, "depbee-analyzer"):  # fmt: skip
            FeatureExtractorBackend()

    def test_a_new_request_starts_without_earlier_results(self):
        full = [convert(rule_id) for rule_id in RULE_IDS]
        _, analyzer = self.scan({"checks": full, "cacheable": True})
        self.assertEqual(len(analyzer.rules.found), 1)
        analyzer.backend.extract = mock.Mock(side_effect=GuardError("synthetic download failure"))
        analyzer.analyze(self.request())
        self.assertEqual(analyzer.rules.found, {})  # the failed change keeps nothing


class RealFeatureModel(PackagePredictor):
    """Scores real depbee-analyzer features with a fixed number (the rules, not the model, are
    under test); identity and encode as a verified LightGBMPredictor, for the cache."""

    identity = {"model_sha256": "a" * 64, "manifest_sha256": "b" * 64}
    model_id = "rules-test"

    def __init__(self, score=0.1):
        self.score = score

    def encode(self, features):
        if len(features) != 29:
            raise GuardError("not the 29 features")
        return [0.0]

    def predict(self, features):
        self.encode(features)
        return self.score


def manifest(version, **extra):
    return json.dumps({"name": "example", "version": version, **extra}, indent=2).encode()


@unittest.skipUnless(PINNED, NO_PIN)
class PinnedRulesTests(Fixture):
    """The installed, pinned scanner through scan_project and check_package. The lockfile moves
    example 1.0.0 -> 1.1.0; the scanner compares 1.1.0 with its registry predecessor 1.0.1."""

    def setUp(self):
        super().setUp()
        self.doc = packument({"1.0.0": "2026-01-01T00:00:00Z", "1.0.1": "2026-01-02T00:00:00Z",
                              "1.1.0": "2026-01-03T00:00:00Z"})  # fmt: skip
        self.served = FakeRegistry()
        self.served.files["https://registry.npmjs.org/example"] = b""  # set in publish()
        self.model = RealFeatureModel()
        self.publish(
            {"package.json": manifest("1.0.1"), "index.js": b"module.exports = 1;\n"},
            {"package.json": manifest("1.1.0"), "index.js": b"module.exports = 2;\n"},
        )
        self.own_requests = mock.Mock(side_effect=AssertionError("depbee-analyzer fetched"))
        for patcher in (
            mock.patch("depbee.analysis.registry._open", self.served),
            mock.patch("depbee_analyzer.core.loader.requests.get", self.own_requests),
            mock.patch("depbee.service.LightGBMPredictor", side_effect=lambda _: self.model),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def publish(self, old, new, scripts=None):
        """Serve 1.0.1 and 1.1.0 as tarballs of {path or (path, link target): bytes}."""
        if scripts is not None:
            self.doc["versions"]["1.1.0"]["scripts"] = scripts
        for version, files in (("1.0.1", old), ("1.1.0", new)):
            entries = []
            for path, data in files.items():
                if isinstance(path, tuple):  # (name, target): a symbolic link, never unpacked
                    entries.append((f"package/{path[0]}", tarfile.SYMTYPE, path[1]))
                else:
                    entries.append((f"package/{path}", data))
            data = linked_tgz(*entries)
            self.doc["versions"][version]["dist"]["integrity"] = sri(data)
            self.served.files[tarball_url("example", version)] = data
        self.served.files["https://registry.npmjs.org/example"] = json.dumps(self.doc).encode()
        self.new["packages"]["node_modules/example"]["integrity"] = self.doc["versions"]["1.1.0"][
            "dist"
        ]["integrity"]
        self.save_locks()

    def scan(self, **options):
        options.setdefault("no_cache", True)
        return scan_project(self.project, self.base, extract=True, model_dir=Path("m"), **options)

    def statuses(self, row):
        return {check["rule_id"]: check["status"] for check in row["rules"]["checks"]}

    def test_clean_pair_runs_six_rules_on_the_compared_versions(self):
        for label, run in (("scan", self.scan),
                           ("check", lambda: check_package("example", "1.1.0", model_dir=Path("m"),
                                                           no_cache=True))):  # fmt: skip
            with self.subTest(label):
                report = run()
                row = report["results"][0]
                self.assertEqual(report["detectors"]["rules"], {"ruleset_version": rules.RULESET})
                self.assertEqual([c["rule_id"] for c in row["rules"]["checks"]], RULE_IDS)
                self.assertEqual(self.statuses(row), dict.fromkeys(RULE_IDS, "not_hit"))
                self.assertEqual({c["rule_version"] for c in row["rules"]["checks"]},
                                 {rules.RULESET})  # fmt: skip
                self.assertEqual((row["rules"]["status"], row["compared_version"]),
                                 ("not_hit", "1.0.1"))  # fmt: skip
                self.assertEqual((row["status"], row["score"], row["rule_ml_agreement"],
                                  report["exit_code"]), ("not_flagged", 0.1, "neither_hit", 0))  # fmt: skip
                self.assertEqual(len(row["features"]), 29)
        self.own_requests.assert_not_called()

    def test_review_hits_are_shown_and_never_change_the_verdict(self):
        scripts = {"postinstall": DATA_ARGUMENT}
        self.publish({"package.json": manifest("1.0.1"), "lib/util.js": b"exports.ok = 1;\n"},
                     {"package.json": manifest("1.1.0", scripts=scripts), "lib/util.js": COMMENT},
                     scripts)  # fmt: skip
        for score, status, agreement, code in ((0.1, "not_flagged", "rule_only", 0),
                                               (0.9, "flagged", "both_hit", 1)):  # fmt: skip
            with self.subTest(score=score):
                self.model.score = score
                report = self.scan()
                row = report["results"][0]
                checks = {c["rule_id"]: c for c in row["rules"]["checks"]}
                self.assertEqual(self.statuses(row), {**dict.fromkeys(RULE_IDS, "not_hit"),
                                                      "R_download_exec": "hit",
                                                      "R_diff_obfuscation": "hit"})  # fmt: skip
                download = checks["R_download_exec"]
                self.assertTrue(download["evidence"][0].startswith("검토용 적중(review): "))
                self.assertEqual(download["locations"][0]["file"], "package.json")
                self.assertGreater(download["locations"][0]["line"], 1)
                self.assertEqual(checks["R_diff_obfuscation"]["locations"],
                                 [{"file": "lib/util.js", "line": 1}])  # fmt: skip
                self.assertEqual((row["rules"]["status"], row["status"], row["score"],
                                  row["rule_ml_agreement"], report["exit_code"]),
                                 ("hit", status, score, agreement, code))  # fmt: skip

    def test_a_file_no_rule_reads_does_not_hold_the_item(self):
        engine = b"\0" * 2048  # over the scanner's file limit below, read by no rule
        self.publish(
            {"package.json": manifest("1.0.1"), "engine.wasm": engine},
            {"package.json": manifest("1.1.0"), "engine.wasm": engine + b"\1"},
        )
        with mock.patch("depbee_analyzer.rules.diff_scan.MAX_FILE", 1024):
            report = self.scan()
        row = report["results"][0]
        self.assertEqual(self.statuses(row), dict.fromkeys(RULE_IDS, "not_hit"))
        self.assertEqual((row["status"], report["exit_code"]), ("not_flagged", 0))

    def test_a_code_file_over_the_limit_is_undetermined_and_holds_the_item(self):
        bundle = b"//" + b"x" * 2048 + b"\n"
        self.publish({"package.json": manifest("1.0.1"), "same.js": bundle},
                     {"package.json": manifest("1.1.0"), "same.js": bundle,
                      "lib/bundle.js": bundle})  # fmt: skip
        with mock.patch("depbee_analyzer.rules.diff_scan.MAX_FILE", 1024):
            report = self.scan()
        row = report["results"][0]
        self.assertEqual(self.statuses(row), {**dict.fromkeys(RULE_IDS, "not_hit"),
                                              "R_diff_obfuscation": "failed"})  # fmt: skip
        detail = {c["rule_id"]: c["detail"] for c in row["rules"]["checks"]}["R_diff_obfuscation"]
        self.assertTrue(detail.startswith(f"{rules.UNDETERMINED}: 이 규칙이 읽는 파일이 빠져"))
        self.assertIn("새 버전: lib/bundle.js(크기 제한)", detail)
        self.assertNotIn("same.js", detail)  # skipped in both and the same: proven harmless
        self.assertEqual((row["rules"]["status"], row["rules"]["reason"], row["rules"]["detail"]),
                         ("failed", "detector_failed", None))  # fmt: skip
        # D-7 holds the item; the ML path's score and status stay.
        self.assertEqual((row["status"], row["reason"], row["score"], row["ml"]["status"],
                          row["rule_ml_agreement"], report["exit_code"]),
                         ("incomplete", "detection_failed", 0.1, "not_hit", "undetermined", 2))  # fmt: skip

    def test_a_hit_against_a_link_left_out_of_the_earlier_version_is_held(self):
        self.publish({"package.json": manifest("1.0.1"), "real.js": COMMENT,
                      ("lib/util.js", "../real.js"): None},
                     {"package.json": manifest("1.1.0"), "real.js": COMMENT,
                      "lib/util.js": COMMENT})  # fmt: skip
        row = self.scan()["results"][0]
        checks = {c["rule_id"]: c for c in row["rules"]["checks"]}
        held = checks["R_diff_obfuscation"]
        self.assertEqual(held["status"], "failed")
        self.assertIn("이전 버전: lib/util.js(링크)", held["detail"])
        self.assertIn("새로 생긴 것인지 확정할 수 없음", held["detail"])
        # The rules that read package.json only keep their results.
        self.assertEqual((checks["R_download_exec"]["status"],
                          checks["R_install_root_wipe"]["status"]), ("not_hit", "not_hit"))  # fmt: skip
        self.assertEqual((row["status"], row["reason"]), ("incomplete", "detection_failed"))

    def test_package_json_of_another_package_holds_every_rule(self):
        cases = {
            "another name": manifest("1.1.0").replace(b'"example"', b'"other"'),
            "another version": manifest("1.2.0"),
            "name of another type in both": None,
        }
        for label, new in cases.items():
            with self.subTest(label):
                old = manifest("1.0.1")
                if new is None:
                    old = json.dumps({"name": ["example"], "version": "1.0.1"}).encode()
                    new = json.dumps({"name": ["example"], "version": "1.1.0"}).encode()
                self.publish({"package.json": old}, {"package.json": new})
                row = self.scan()["results"][0]
                self.assertEqual(self.statuses(row), dict.fromkeys(RULE_IDS, "failed"))
                detail = row["rules"]["checks"][0]["detail"]
                self.assertTrue(detail.startswith(f"{rules.UNDETERMINED}: 비교한 package.json의"))
                self.assertEqual((row["status"], row["reason"], row["score"]),
                                 ("incomplete", "detection_failed", 0.1))  # fmt: skip

    def test_a_scan_error_keeps_the_features_and_the_score(self):
        cases = {
            "exception": (RuntimeError(r"C:\Users\someone\secret"), "규칙 스캔 오류(RuntimeError)"),
            "no rules": (
                [],
                "규칙 스캔 오류: The rule scan did not return each rule of its ruleset once",
            ),
        }
        for label, (effect, detail) in cases.items():
            with self.subTest(label):
                given = (
                    {"side_effect": effect}
                    if isinstance(effect, Exception)
                    else {"return_value": effect}
                )
                with mock.patch("depbee_analyzer.rules.diff_scan.scan_pair", **given):
                    report = self.scan()
                row = report["results"][0]
                self.assertEqual(row["rules"], {"status": "failed", "reason": "detector_failed",
                                                "detail": detail, "checks": []})  # fmt: skip
                self.assertEqual((row["status"], row["reason"], row["score"], len(row["features"]),
                                  report["exit_code"]), ("incomplete", "detection_failed", 0.1, 29, 2))  # fmt: skip

    def test_the_cache_keeps_the_rules_of_a_scan_and_never_a_partial_one(self):
        cache_dir = self.root / "cache"
        verified = {"commit": "c" * 40, "url": "https://example.test/x", "files_sha256": "f" * 64,
                    "python": "3.13.5"}  # fmt: skip
        identity = mock.patch(
            "depbee.analysis.extractor._installed_identity", return_value=verified
        )
        identity.start()
        self.addCleanup(identity.stop)
        scripts = {"postinstall": DATA_ARGUMENT}
        self.publish(
            {"package.json": manifest("1.0.1")},
            {"package.json": manifest("1.1.0", scripts=scripts)},
            scripts,
        )
        tarballs = {tarball_url("example", v) for v in ("1.0.1", "1.1.0")}

        def run():
            self.served.opened = []
            report = self.scan(no_cache=False, cache_dir=cache_dir)
            return report, report["results"][0], tarballs & set(self.served.opened)

        def same(row):
            return {k: v for k, v in row.items() if k not in ("elapsed_seconds", "cache_hit")}

        cold, cold_row, fetched = run()
        self.assertEqual((cold_row["cache_hit"], fetched), (False, tarballs))
        warm, warm_row, fetched = run()
        self.assertEqual((warm_row["cache_hit"], fetched), (True, set()))
        self.assertEqual(same(warm_row), same(cold_row))  # rules, features, score, evidence
        self.assertEqual(self.statuses(warm_row)["R_download_exec"], "hit")
        # An entry whose rule checks are damaged is a miss, scanned and stored again.
        [entry] = cache_dir.glob("*.json")
        stored = json.loads(entry.read_bytes())
        for damaged in ([], stored["rules"][:5], None):
            with self.subTest(damaged=damaged):
                entry.write_text(json.dumps({**stored, "rules": damaged}), encoding="utf-8")
                _, row, fetched = run()
                self.assertEqual((row["cache_hit"], fetched, same(row)),
                                 (False, tarballs, same(cold_row)))  # fmt: skip
                self.assertEqual(json.loads(entry.read_bytes())["rules"], stored["rules"])
        # A scan error or an unreadable file is not stored: the next run scans again.
        entry.unlink()
        read_root = importlib.import_module("depbee_analyzer.rules.diff_scan").read_root

        def unreadable(root):
            files, skipped = read_root(root)
            return files, skipped + ["notes.txt:read_error"]

        for label, patch in (("error", {"side_effect": RuntimeError("x")}),
                             ("unreadable", {"side_effect": unreadable})):  # fmt: skip
            target = "scan_pair" if label == "error" else "read_root"
            with (
                self.subTest(label),
                mock.patch(f"depbee_analyzer.rules.diff_scan.{target}", **patch),
            ):
                _, row, _ = run()
                self.assertEqual((row["cache_hit"], list(cache_dir.glob("*.json"))), (False, []))
        _, row, fetched = run()
        self.assertEqual((row["cache_hit"], self.statuses(row)), (False, self.statuses(cold_row)))
        self.assertEqual(len(list(cache_dir.glob("*.json"))), 1)

    def test_a_new_dependency_without_an_earlier_version_is_not_scanned(self):
        self.old["packages"].pop("node_modules/example")
        self.save_locks()
        for gone in ("1.0.0", "1.0.1"):
            self.doc["versions"].pop(gone)
            self.doc["time"].pop(gone)
        self.served.files["https://registry.npmjs.org/example"] = json.dumps(self.doc).encode()
        row = self.scan()["results"][0]
        self.assertEqual((row["rules"]["status"], row["rules"]["reason"], row["reason"]),
                         ("not_run", "analysis_unsupported", "no_baseline"))  # fmt: skip

    def test_a_failed_analysis_gives_the_rules_no_input(self):
        self.new["packages"]["node_modules/example"]["integrity"] = "sha512-" + "A" * 86 + "=="
        self.save_locks()
        row = self.scan()["results"][0]
        self.assertEqual((row["rules"]["status"], row["rules"]["reason"], row["reason"]),
                         ("failed", "input_failed", "analysis_failed"))  # fmt: skip
        self.assertNotIn(tarball_url("example", "1.1.0"), self.served.opened)

    def test_a_local_copy_of_the_new_version_is_scanned_where_it_is(self):
        copy_dir = self.root / "copy" / "package"
        (copy_dir / "lib").mkdir(parents=True)
        (copy_dir / "package.json").write_bytes(manifest("1.1.0"))
        (copy_dir / "lib" / "util.js").write_bytes(COMMENT)
        report = self.scan(local_sources=["example@1.1.0=copy"], local_root=self.root)
        row = report["results"][0]
        self.assertEqual(self.statuses(row)["R_diff_obfuscation"], "hit")
        self.assertNotIn(tarball_url("example", "1.1.0"), self.served.opened)


if __name__ == "__main__":
    unittest.main()
