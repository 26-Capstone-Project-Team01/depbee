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

from depbee.analysis import cache, registry, rules
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
VERIFY = b"module.exports = (file) => file.endsWith('.svg');\n"  # the checker DATA_ARGUMENT names
COMMENT = b"// Docs only: we never call eval( or atob( on user input.\nexports.ok = 1;\n"


def finding(rule_id, status="no_hit", paths=(), lines=(), reason="synthetic reason"):
    return {"rule_id": rule_id, "status": status, "disposition": STRENGTH.get(rule_id, "review"),
            "reason": reason, "paths": paths, "lines": lines}  # fmt: skip


def convert(rule_id, status="no_hit", old=(), new=(), refs=(), ruleset=rules.RULESET, **found):
    lost = {"old": list(old), "new": list(new)}
    return rules.convert(finding(rule_id, status, **found), ruleset, lost, set(refs))


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
        # Skipped in both versions, it is not known to be the same: still undetermined.
        both = convert("R_diff_obfuscation", old=[big_js], new=[big_js])
        self.assertEqual(both["status"], "failed")
        # The credential rule reads only the files an install hook names.
        sent = {refs: convert("R_secret_send", new=[big_js], refs=refs)["status"]
                for refs in ((), ("dist/bundle.js",))}  # fmt: skip
        self.assertEqual(sent, {(): "not_hit", ("dist/bundle.js",): "failed"})
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

    def test_a_file_an_install_hook_names_but_the_package_lacks(self):
        # Only R_secret_send follows a hook to its file; the others never read it.
        absent = "setup.js:absent"
        statuses = {r: convert(r, new=[absent], refs=["setup.js"])["status"] for r in RULE_IDS}
        self.assertEqual(statuses, {**dict.fromkeys(RULE_IDS, "not_hit"),
                                    "R_secret_send": "failed"})  # fmt: skip
        self.assertIn(
            "setup.js(설치 훅이 가리키지만 패키지에 없음)",
            convert("R_secret_send", new=[absent], refs=["setup.js"])["detail"],
        )
        # Missing from the earlier version: a hit may not be new.
        held = convert("R_secret_send", "hit", old=[absent], refs=["setup.js"],
                       paths=("package.json",), lines=(3,))  # fmt: skip
        self.assertEqual(held["status"], "failed")
        self.assertIn("새로 생긴 것인지 확정할 수 없음", held["detail"])
        # Missing from the new version only: what was found there still stands.
        kept = convert("R_secret_send", "hit", new=[absent], refs=["setup.js"],
                       paths=("package.json",), lines=(3,))  # fmt: skip
        self.assertEqual(kept["status"], "hit")
        # A file the hooks do not name is not read by the rule.
        self.assertEqual(convert("R_secret_send", new=["other.js:size_limit"],
                                 refs=["setup.js"])["status"], "not_hit")  # fmt: skip

    def test_the_hook_files_are_found_as_the_pinned_scanner_finds_them(self):
        manifest = {"scripts": {
            "postinstall": "node ./scripts/a.js && NODE_ENV=x node lib/B.CJS --flag; nodex c.js",
            "install": "node d.mjs", "preinstall": ["node e.js"], "test": "node f.js",
        }}  # fmt: skip
        self.assertEqual(rules._node_files(manifest), {"scripts/a.js", "lib/B.CJS", "d.mjs"})
        self.assertEqual(rules._node_files({"scripts": "node a.js"}), set())

    def test_the_two_manifests_must_be_the_compared_pair_read_strictly(self):
        pair = ("example", "1.0.1", "1.1.0")
        good = {"old": {"name": "example", "version": "1.0.1"},
                "new": {"name": "example", "version": "1.1.0"}}  # fmt: skip
        none = {"old": [], "new": []}
        self.assertIsNone(rules._identity_problem(good, none, pair))
        for label, manifests, lost in (
            ("unreadable", {**good, "old": None}, none),
            ("another name", {**good, "new": {"name": "other", "version": "1.1.0"}}, none),
            ("a name of another type", {"old": {**good["old"], "name": ["example"]},
                                        "new": {**good["new"], "name": ["example"]}}, none),
            ("case duplicate", good, {"old": ["PACKAGE.JSON:case"], "new": []}),
            ("over the size limit", good, {"old": [], "new": ["package.json:size_limit"]}),
        ):  # fmt: skip
            with self.subTest(label):
                problem = rules._identity_problem(manifests, lost, pair)
                self.assertTrue(problem.startswith(f"{rules.UNDETERMINED}: "), problem)
        files = {"package.json": b'{"name": "example", "name": "example", "version": "1.0.1"}'}
        self.assertIsNone(rules._manifest(files))  # a duplicate key: another reader may differ
        self.assertIsNone(rules._manifest({"package.json": b'{"name": "ex\xffample"}'}))
        self.assertIsNone(rules._manifest({"package.json": b"[]"}))

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
        check = rules.convert(finding("R_new_rule"), "9.9.9", lost, set())
        self.assertEqual((check["status"], check["rule_version"]), ("failed", "9.9.9"))
        # The pinned rule names under another ruleset version: READS may not describe them.
        statuses = {r: convert(r, new=["x.wasm:size_limit"], ruleset="9.9.9")["status"]
                    for r in RULE_IDS}  # fmt: skip
        self.assertEqual(statuses, dict.fromkeys(RULE_IDS, "failed"))

    def test_a_name_spelled_two_ways_holds_a_hit_in_either_version(self):
        hit = {"paths": ("lib/util.js",), "lines": (1,)}
        for kind in ("case", "alias"):
            with self.subTest(kind):
                held = convert("R_diff_obfuscation", "hit", new=[f"Lib/readme.txt:{kind}"], **hit)
                self.assertEqual(held["status"], "failed")
                self.assertIn("이름이 두 가지로 쓰여", held["detail"])
                # A rule that reads package.json only is not affected.
                self.assertEqual(
                    convert(
                        "R_download_exec",
                        "hit",
                        new=[f"Lib/x:{kind}"],
                        paths=("package.json",),
                        lines=(5,),
                    )["status"],
                    "hit",
                )

    def test_location_files_are_bounded_in_length(self):
        long = "a/" * 127 + "b.js"  # 258 characters
        check = convert("R_diff_obfuscation", "hit", paths=(long, "ok.js"), lines=(1, 2))
        self.assertEqual(check["locations"], [{"file": "ok.js", "line": 2}])
        self.assertFalse(rules._package_path("x" * (rules.MAX_PATH + 1)))
        self.assertTrue(rules._package_path("x" * rules.MAX_PATH))

    def test_missing_files_are_named_briefly(self):
        entries = [f"lib/f{i}.js:size_limit" for i in range(5)]
        detail = convert("R_diff_obfuscation", new=entries)["detail"]
        self.assertIn(
            "lib/f0.js(크기 제한), lib/f1.js(크기 제한), lib/f2.js(크기 제한) 외 2개", detail
        )


class UnpackNamesTests(Fixture):
    """analysis.registry.unpack reports names spelled in two cases and the files it wrote."""

    def unpack(self, *entries):
        omitted, written = [], []
        target = self.root / f"unpacked-{len(list(self.root.glob('unpacked-*')))}"
        target.mkdir()
        root = registry.unpack(linked_tgz(*entries), target, "x tarball", omitted, written)
        return root, sorted(omitted), sorted(written)

    def test_the_package_root_spelled_in_two_cases(self):
        two = (("package/package.json", b"{}"), ("package/index.js", b"a"),
               ("Package/package.json", b"{}"))  # fmt: skip
        if case_ignored(self.root):  # one folder: either package.json may be the one there
            root, omitted, written = self.unpack(*two)
            self.assertEqual(root.name, "package")
            self.assertEqual(omitted, ["package.json:case"])  # under the root, not outside it
            self.assertEqual(written, ["index.js", "package.json", "package.json"])
        else:  # two folders, each holding a package.json: no single package root, as before
            with self.assertRaisesRegex(registry.RegistryError, "no single package root"):
                self.unpack(*two)
        # A folder spelled like the root without a package.json is the root's on every platform.
        root, omitted, _ = self.unpack(("package/package.json", b"{}"), ("Package/notes.txt", b"n"))
        self.assertEqual((root.name, omitted), ("package", ["notes.txt:case"]))
        # An unrelated folder beside a plain root stays outside it, as before.
        root, omitted, _ = self.unpack(("package/package.json", b"{}"), ("docs/readme.md", b"r"))
        self.assertEqual((root.name, omitted), ("package", ["docs/readme.md:outside_root"]))

    def test_names_and_folders_spelled_in_two_cases(self):
        data = linked_tgz(("package/package.json", b"{}"), ("package/Src/readme.txt", b"a"),
                          ("package/src/index.js", b"b"), ("package/A.js", b"c"),
                          ("package/a.js", b"d"), ("package/A.js", b"e"),
                          ("other/x.js", b"f"))  # fmt: skip
        omitted, written = [], []
        target = self.root / "unpacked"
        target.mkdir()
        root = registry.unpack(data, target, "x tarball", omitted, written)
        self.assertEqual(root.name, "package")
        # Each later spelling of a folder or file name, on every platform; an exact repeat is
        # the same file (the later one is written, as npm does).
        self.assertEqual(sorted(omitted), ["a.js:case", "other/x.js:outside_root",
                                           "src/index.js:case"])  # fmt: skip
        self.assertEqual(sorted(written), ["A.js", "Src/readme.txt", "a.js", "package.json",
                                           "src/index.js"])  # fmt: skip


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
        hit = convert("R_download_exec", "hit", paths=("package.json",), lines=(5,))
        failed = convert("R_download_exec", "unknown")  # in full[0]'s place, as hit is
        # JSON values a damaged cache entry or child result can hold, each in one rule's place:
        # none may raise (an unhashable rule_id did) or pass.
        for label, check in {
            "rule_id an array": {**full[0], "rule_id": ["R_download_exec"]},
            "rule_id an object": {**full[0], "rule_id": {"R_download_exec": 1}},
            "rule_id empty": {**full[0], "rule_id": ""},
            "check a string": "R_download_exec",
            "check an array": ["R_download_exec"],
            "check null": None,
            "status an array": {**full[0], "status": ["not_hit"]},
            "version an array": {**full[0], "rule_version": [rules.RULESET]},
            "fields an array": dict.fromkeys(["rule_id"], ["x"]),
            "not_hit with evidence": {**full[0], "evidence": ["x"]},
            "not_hit with a location": {**full[0], "locations": hit["locations"]},
            "hit with a detail": {**hit, "detail": "x"},
            "hit without evidence": {**hit, "evidence": []},
            "hit with two evidence lines": {**hit, "evidence": ["a", "b"]},
            "hit with overlong evidence": {**hit, "evidence": ["x" * (rules.MAX_TEXT + 4)]},
            "hit at an absolute path": {**hit, "locations": [{"file": "/etc/passwd", "line": 1}]},
            "hit at a drive path": {**hit, "locations": [{"file": "C:/x.js", "line": 1}]},
            "hit at a backslash path": {**hit, "locations": [{"file": "a\\b.js", "line": 1}]},
            "hit above the root": {**hit, "locations": [{"file": "../x.js", "line": 1}]},
            "hit at no path": {**hit, "locations": [{"file": "", "line": 1}]},
            "hit at a path that is no text": {**hit, "locations": [{"file": ["a"], "line": 1}]},
            "hit at line 0": {**hit, "locations": [{"file": "a.js", "line": 0}]},
            "hit at a negative line": {**hit, "locations": [{"file": "a.js", "line": -3}]},
            "hit at line true": {**hit, "locations": [{"file": "a.js", "line": True}]},
            "hit with a location list too long": {
                **hit, "locations": [{"file": "a.js", "line": 1}] * (rules.MAX_LOCATIONS + 1)},
            "hit with a location that is no object": {**hit, "locations": ["a.js:1"]},
            "failed with evidence": {**failed, "evidence": ["x"]},
            "failed with a location": {**failed, "locations": hit["locations"]},
            "failed that is not undetermined": {**failed, "detail": "timeout"},
            "failed with an overlong detail": {**failed,
                                               "detail": failed["detail"] + "x" * rules.MAX_TEXT},
            # What a hand-edited entry could hold that no scan writes.
            "hit with a blank reason": {**hit, "evidence": ["검토용 적중(review):   "]},
            "hit with blank evidence": {**hit, "evidence": [" "]},
            "hit without its strength": {**hit, "evidence": ["synthetic reason"]},
            "hit with another rule's strength": {
                **hit, "evidence": ["강한 정적 근거(high_evidence): synthetic reason"]},
            "failed with a blank reason": {**failed, "detail": "판정 불가:   "},
        }.items():  # fmt: skip
            cases[label] = [check] + full[1:]
        cases["the rules in another order"] = list(reversed(full))
        cases["two rules swapped"] = [full[1], full[0], *full[2:]]
        for label, value in cases.items():
            with self.subTest(label):
                self.assertIsNone(rules.checked(value, rules.RULESET))

    def test_every_check_a_scan_makes_passes(self):
        made = {
            "R_download_exec": convert("R_download_exec", "hit", paths=("package.json",),
                                       lines=(0,)),  # a hit whose line was not found
            "R_secret_send": convert("R_secret_send", "unknown", reason="r" * 1000),
            "R_ci_secret_send": convert("R_ci_secret_send", new=["x.yml:symlink"]),
            "R_install_root_wipe": convert("R_install_root_wipe"),
            "R_remote_admin_auth_override": convert(
                "R_remote_admin_auth_override", "hit", paths=tuple(f"f{i}.js" for i in range(30)),
                lines=tuple(range(1, 31)), reason="x" * 1000),
            "R_diff_obfuscation": convert("R_diff_obfuscation", "hit", old=["a.js:size_limit"],
                                          paths=("a.js",), lines=(1,)),
        }  # fmt: skip
        self.assertEqual([c["status"] for c in made.values()],
                         ["hit", "failed", "failed", "not_hit", "hit", "failed"])  # fmt: skip
        value = list(made.values())
        self.assertIs(rules.checked(value, rules.RULESET), value)
        # Another ruleset: the same shapes, any rule ids, each once.
        other = [{**c, "rule_version": "9.9.9", "rule_id": f"R{i}"} for i, c in enumerate(value)]
        self.assertIs(rules.checked(other, "9.9.9"), other)
        self.assertIsNone(rules.checked(other + [other[0]], "9.9.9"))

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


def case_ignored(folder):
    """Whether the file system of folder ignores case in names (Windows, macOS by default)."""
    probe = folder / "case-probe"
    probe.write_bytes(b"")
    try:
        return (folder / "CASE-PROBE").exists()
    finally:
        probe.unlink()


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
                else:  # "/NAME": a member outside package/
                    entries.append((path[1:] if path.startswith("/") else f"package/{path}", data))
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

    def test_the_pinned_rules_are_the_installed_scanners(self):
        from depbee_analyzer.rules import diff_scan

        self.assertEqual(diff_scan.RULESET_VERSION, rules.RULESET)
        self.assertEqual([(i, d) for i, d, _ in diff_scan.RULES], list(rules.PINNED))
        self.assertEqual(set(rules.READS), {i for i, _ in rules.PINNED})

    def test_a_folder_the_scan_could_not_list_is_not_cached(self):
        # A walk that misses a folder (rglob passes over an error listing it) leaves a file the
        # archive named unseen: undetermined now, and not stored, so a later scan recovers.
        files = {"package.json": manifest("1.0.1"), "notes/a.txt": b"plain\n"}
        self.publish(files, {**files, "package.json": manifest("1.1.0")})
        read_root = importlib.import_module("depbee_analyzer.rules.diff_scan").read_root

        def unlisted(root):
            found, skipped = read_root(root)
            found.pop("notes/a.txt", None)
            return found, skipped

        with mock.patch("depbee_analyzer.rules.diff_scan.read_root", side_effect=unlisted):
            (held,) = self.cached_scans(1)
        detail = {c["rule_id"]: c["detail"] for c in held["rules"]["checks"]}["R_secret_send"]
        self.assertIn("notes/a.txt(보관된 이름과 읽힌 이름이 다름)", detail)
        self.assertEqual((held["status"], list((self.root / "cache").glob("*.json"))),
                         ("incomplete", []))  # fmt: skip
        first, second = self.cached_scans()
        self.assertEqual([(r["cache_hit"], self.statuses(r)) for r in (first, second)],
                         [(False, dict.fromkeys(RULE_IDS, "not_hit")),
                          (True, dict.fromkeys(RULE_IDS, "not_hit"))])  # fmt: skip

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
                     {"package.json": manifest("1.1.0", scripts=scripts), "lib/util.js": COMMENT,
                      "verify.js": VERIFY}, scripts)  # fmt: skip
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
        opened, real_open = [], Path.open

        def spy(path, *args, **kwargs):
            opened.append(Path(path).name)
            return real_open(path, *args, **kwargs)

        with (mock.patch("depbee_analyzer.rules.diff_scan.MAX_FILE", 1024),
              mock.patch.object(Path, "open", spy)):  # fmt: skip
            report = self.scan()
        row = report["results"][0]
        self.assertEqual(self.statuses(row), dict.fromkeys(RULE_IDS, "not_hit"))
        self.assertEqual((row["status"], report["exit_code"]), ("not_flagged", 0))
        # The scanner skipped it for its size and nothing read it after that.
        self.assertIn("package.json", opened)
        self.assertNotIn("engine.wasm", opened)

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
        # Skipped in both versions it is not read again, so it is not known to be the same.
        self.assertIn("이전 버전: same.js(크기 제한)", detail)
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
            {"package.json": manifest("1.1.0", scripts=scripts), "verify.js": VERIFY},
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
        # An entry whose rule checks alone are damaged is a miss: the second run scans again and
        # stores the entry anew, and the third uses it. The features in it stay as they were.
        [entry] = cache_dir.glob("*.json")
        stored = json.loads(entry.read_bytes())
        array_id, absolute = copy.deepcopy(stored["rules"]), copy.deepcopy(stored["rules"])
        array_id[0]["rule_id"] = [array_id[0]["rule_id"]]  # JSON array: was a TypeError
        hit = next(c for c in absolute if c["status"] == "hit")
        hit["locations"] = [{"file": "/etc/passwd", "line": 1}]  # no scan writes such a file
        for label, damaged in (
            ("empty", []), ("five rules", stored["rules"][:5]), ("null", None),
            ("rule_id an array", array_id), ("a check that is text", ["R_download_exec"]
                                             + stored["rules"][1:]),
            ("an absolute location", absolute), ("an object", {"checks": stored["rules"]}),
            ("a hit with a blank reason", [stored["rules"][0], {**stored["rules"][1],
                                           "status": "hit", "evidence": [" "]},
                                           *stored["rules"][2:]]),
            ("the rules reversed", list(reversed(stored["rules"]))),
        ):  # fmt: skip
            with self.subTest(label):
                entry.write_text(json.dumps({**stored, "rules": damaged}), encoding="utf-8")
                _, row, fetched = run()
                self.assertEqual((row["cache_hit"], fetched, same(row)),
                                 (False, tarballs, same(cold_row)))  # fmt: skip
                self.assertEqual(json.loads(entry.read_bytes()), stored)
                _, row, fetched = run()
                self.assertEqual((row["cache_hit"], fetched, same(row)),
                                 (True, set(), same(cold_row)))  # fmt: skip
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

    def test_a_malformed_child_result_keeps_the_features_and_the_score(self):
        cache_dir = self.root / "cache"
        verified = {"commit": "c" * 40, "url": "https://example.test/x", "files_sha256": "f" * 64,
                    "python": "3.13.5"}  # fmt: skip
        with mock.patch("depbee.analysis.extractor._installed_identity", return_value=verified):
            good = self.scan(no_cache=False, cache_dir=self.root / "good")["results"][0]
        checks = good["rules"]["checks"]
        for label, found in (
            ("rule_id an array", {"checks": [{**checks[0], "rule_id": ["R_download_exec"]}]
                                  + checks[1:], "cacheable": True}),
            ("checks text", {"checks": "not_hit", "cacheable": True}),
            ("error a number", {"error": 5}),
            ("an array", [checks]),
            ("null", None),
            ("cacheable text", {"checks": checks, "cacheable": "yes"}),
        ):  # fmt: skip
            with (self.subTest(label),
                  mock.patch("depbee.analysis.extractor._installed_identity",
                             return_value=verified),
                  mock.patch("depbee.analysis.extractor._scan_rules", return_value=found)):  # fmt: skip
                report = self.scan(no_cache=False, cache_dir=cache_dir)
                row = report["results"][0]
                if label == "cacheable text":  # valid checks, only not known to be cacheable
                    self.assertEqual((row["rules"], list(cache_dir.glob("*.json"))),
                                     (good["rules"], []))  # fmt: skip
                    continue
                self.assertEqual(row["rules"], {
                    "status": "failed", "reason": "detector_failed", "checks": [],
                    "detail": "규칙 스캔 결과가 없거나 형식이 맞지 않음"})  # fmt: skip
                self.assertEqual((row["status"], row["reason"], row["score"], row["features"],
                                  report["exit_code"]),
                                 ("incomplete", "detection_failed", 0.1, good["features"], 2))  # fmt: skip
                self.assertEqual(list(cache_dir.glob("*.json")), [])

    def test_a_case_duplicate_of_the_earlier_manifest_holds_every_rule(self):
        # The download hit reads package.json only, but which earlier package.json is the one
        # read is not certain (one file where case is ignored), so no rule result is final.
        scripts = {"postinstall": DATA_ARGUMENT}
        self.publish({"package.json": manifest("1.0.1"),
                      "PACKAGE.JSON": manifest("1.0.1", scripts=scripts)},
                     {"package.json": manifest("1.1.0", scripts=scripts), "verify.js": VERIFY},
                     scripts)  # fmt: skip
        row = self.scan()["results"][0]
        self.assertEqual(self.statuses(row), dict.fromkeys(RULE_IDS, "failed"))
        self.assertIn("package.json이 하나로 정해지지 않음", row["rules"]["checks"][0]["detail"])
        self.assertEqual((row["status"], row["score"]), ("incomplete", 0.1))

    def test_manifests_that_only_a_lenient_reader_accepts_hold_every_rule(self):
        # The scanner decodes package.json leniently (invalid UTF-8 replaced, the last of two
        # keys), so a pair it calls one package need not be the compared one.
        for label, old, new in (
            ("invalid UTF-8 in the name",
             b'{"name": "ex\xffample", "version": "1.0.1"}',
             b'{"name": "ex\xffample", "version": "1.1.0"}'),
            ("a duplicate key",
             b'{"name": "other", "name": "example", "version": "1.0.1"}',
             b'{"name": "other", "name": "example", "version": "1.1.0"}'),
        ):  # fmt: skip
            with self.subTest(label):
                self.publish({"package.json": old}, {"package.json": new})
                row = self.scan()["results"][0]
                self.assertEqual(self.statuses(row), dict.fromkeys(RULE_IDS, "failed"))
                self.assertIn("엄격한 UTF-8 JSON 객체로 읽을 수 없음",
                              row["rules"]["checks"][0]["detail"])  # fmt: skip

    def test_a_file_an_install_hook_names_but_the_package_lacks_holds_that_rule(self):
        scripts = {"postinstall": "node scripts/setup.js"}
        self.publish(
            {"package.json": manifest("1.0.1")},
            {"package.json": manifest("1.1.0", scripts=scripts)},
            scripts,
        )
        row = self.scan()["results"][0]
        self.assertEqual(self.statuses(row), {**dict.fromkeys(RULE_IDS, "not_hit"),
                                              "R_secret_send": "failed"})  # fmt: skip
        detail = {c["rule_id"]: c["detail"] for c in row["rules"]["checks"]}["R_secret_send"]
        self.assertIn("새 버전: scripts/setup.js(설치 훅이 가리키지만 패키지에 없음)", detail)
        # With the file there, nothing is missing.
        self.publish({"package.json": manifest("1.0.1")},
                     {"package.json": manifest("1.1.0", scripts=scripts),
                      "scripts/setup.js": b"console.log('ok');\n"}, scripts)  # fmt: skip
        self.assertEqual(self.statuses(self.scan()["results"][0]),
                         dict.fromkeys(RULE_IDS, "not_hit"))  # fmt: skip

    def test_a_folder_spelled_in_two_cases_holds_the_rules_that_read_paths(self):
        # Where case is ignored (Windows) Src/ and src/ are one folder, so src/index.js is read
        # as Src/index.js; the same names count on every platform.
        scripts = {"postinstall": DATA_ARGUMENT}
        self.publish({"package.json": manifest("1.0.1"), "lib/util.js": b"exports.ok = 1;\n"},
                     {"package.json": manifest("1.1.0", scripts=scripts), "verify.js": VERIFY,
                      "lib/util.js": COMMENT, "LIB/readme.txt": b"notes\n"}, scripts)  # fmt: skip
        row = self.scan()["results"][0]
        self.assertEqual(self.statuses(row), {**dict.fromkeys(RULE_IDS, "failed"),
                                              "R_download_exec": "hit",
                                              "R_install_root_wipe": "not_hit"})  # fmt: skip
        detail = {c["rule_id"]: c["detail"] for c in row["rules"]["checks"]}["R_diff_obfuscation"]
        self.assertIn("LIB/readme.txt(대소문자만 다른 이름)", detail)
        self.assertIn("이름이 두 가지로 쓰여 적중한 경로를 확정할 수 없음", detail)

    def cached_scans(self, runs=2):
        """runs scans with the feature cache of a verified analyzer: their first results."""
        verified = {"commit": "c" * 40, "url": "https://example.test/x", "files_sha256": "f" * 64,
                    "python": "3.13.5"}  # fmt: skip
        with mock.patch("depbee.analysis.extractor._installed_identity", return_value=verified):
            return [self.scan(no_cache=False, cache_dir=self.root / "cache")["results"][0]
                    for _ in range(runs)]  # fmt: skip

    @staticmethod
    def verdict(row):
        return {k: v for k, v in row.items() if k not in ("elapsed_seconds", "cache_hit")}

    def test_a_package_root_spelled_in_two_cases_holds_every_rule(self):
        # Two valid manifests in package/ and Package/: one folder where case is ignored, so the
        # package.json read may be either; two package roots elsewhere, which fails as before.
        scripts = {"postinstall": DATA_ARGUMENT}
        self.publish({"package.json": manifest("1.0.1")},
                     {"package.json": manifest("1.1.0"), "verify.js": VERIFY,
                      "/Package/package.json": manifest("1.1.0", scripts=scripts)},
                     scripts)  # fmt: skip
        cold, warm = self.cached_scans()
        if case_ignored(self.root):
            self.assertEqual(self.statuses(cold), dict.fromkeys(RULE_IDS, "failed"))
            self.assertIn("새 버전의 package.json이 하나로 정해지지 않음",
                          cold["rules"]["checks"][0]["detail"])  # fmt: skip
            self.assertEqual((cold["status"], cold["score"], cold["cache_hit"], warm["cache_hit"]),
                             ("incomplete", 0.1, False, True))  # fmt: skip
        else:
            self.assertEqual((cold["rules"]["status"], cold["rules"]["reason"], cold["reason"]),
                             ("failed", "input_failed", "analysis_failed"))  # fmt: skip
            self.assertEqual((cold["cache_hit"], warm["cache_hit"]), (False, False))
        self.assertEqual(self.verdict(warm), self.verdict(cold))
        # A plain root with an unrelated folder beside it keeps the results it had before: the
        # two rules that read package.json only are judged, the rest are held as before.
        self.publish(
            {"package.json": manifest("1.0.1")},
            {"package.json": manifest("1.1.0"), "/docs/readme.md": b"notes\n"},
        )
        cold, warm = self.cached_scans()
        self.assertEqual(self.statuses(cold), {**dict.fromkeys(RULE_IDS, "failed"),
                                               "R_download_exec": "not_hit",
                                               "R_install_root_wipe": "not_hit"})  # fmt: skip
        self.assertIn("docs/readme.md(패키지 폴더 밖)", cold["rules"]["checks"][1]["detail"])
        self.assertEqual((warm["cache_hit"], self.verdict(warm)), (True, self.verdict(cold)))

    def test_a_cache_entry_of_the_earlier_format_is_scanned_again(self):
        # The hook names a file the package lacks: 44806f5 (cache format 3) judged
        # R_secret_send not_hit there, this format holds it undetermined.
        scripts = {"postinstall": "node scripts/setup.js"}
        self.publish(
            {"package.json": manifest("1.0.1")},
            {"package.json": manifest("1.1.0", scripts=scripts)},
            scripts,
        )
        with mock.patch.object(cache, "FORMAT", 3):
            self.cached_scans(1)
        (entry,) = (self.root / "cache").glob("*.json")
        old = json.loads(entry.read_bytes())
        self.assertEqual(old["format"], 3)
        old["rules"] = [convert(rule_id) for rule_id in RULE_IDS]  # a sound entry of that format
        entry.write_text(json.dumps(old), encoding="utf-8")
        with mock.patch.object(cache, "FORMAT", 3):  # control: under format 3 it is used as it is
            (row,) = self.cached_scans(1)
        self.assertEqual((row["cache_hit"], self.statuses(row)["R_secret_send"]), (True, "not_hit"))
        # This format: the first scan misses and scans again, the second uses the new entry.
        self.served.opened = []
        first, second = self.cached_scans()
        self.assertIn(tarball_url("example", "1.1.0"), self.served.opened)
        self.assertEqual([(r["cache_hit"], self.statuses(r)["R_secret_send"]) for r in (first, second)],
                         [(False, "failed"), (True, "failed")])  # fmt: skip
        self.assertEqual(self.verdict(second), self.verdict(first))
        self.assertEqual(json.loads(entry.read_bytes()), old)  # left alone, never read again
        self.assertEqual(len(list((self.root / "cache").glob("*.json"))), 2)

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
