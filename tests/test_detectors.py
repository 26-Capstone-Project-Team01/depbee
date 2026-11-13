"""Detector slots of pipeline.scan() (SVC-03, docs/result-contract-draft.md 3, 4, D-2, D-7).

Synthetic only: fake detectors, FakePredictor and analysis JSON; no list, rule or package code.
"""

from test_workflow import FakePredictor, Fixture, package

from depbee.contracts import GuardError
from depbee.pipeline import scan

NOT_CONFIGURED = {"status": "not_run", "reason": "detector_not_configured", "detail": None}
ADVISORY = {"advisory_id": "EXAMPLE-ADVISORY-0001", "match_kind": "listed_version",
            "affected": "1.1.0"}  # fmt: skip


def rule(status="not_hit", rule_id="EXAMPLE-RULE-0001", detail=None, **extra):
    evidence, locations = (["synthetic evidence"], [{"file": "package/index.js", "line": 3}]) if (
        status == "hit") else ([], [])  # fmt: skip
    return {"rule_id": rule_id, "rule_version": "0.0.0-example", "status": status,
            "evidence": evidence, "locations": locations, "detail": detail, **extra}  # fmt: skip


NOT_HIT = (rule(),)


class KnownList:
    source = "EXAMPLE-KNOWN-MALICIOUS-LIST"
    list_as_of = "2026-11-01T00:00:00Z"
    list_sha256 = "1" * 64

    def __init__(self, result=(), error=None):
        self.result, self.error, self.calls = result, error, []

    def match(self, name, version):
        self.calls.append((name, version))
        if self.error:
            raise self.error
        return list(self.result) if isinstance(self.result, tuple) else self.result


class Rules:
    ruleset_version = "example-ruleset-0.0.0"

    def __init__(self, result=NOT_HIT, error=None):
        self.result, self.error, self.calls = result, error, []

    def check(self, change, analysis):
        self.calls.append((change["change_id"], analysis["status"]))
        if self.error:
            raise self.error
        return list(self.result) if isinstance(self.result, tuple) else self.result


class DetectorFixture(Fixture):
    def scan_with(self, signal=0.1, row=None, analyzer=True, **detectors):
        artifact = self.artifact({"signal": signal})
        if row is not None:
            artifact["results"][0] = {"change_id": artifact["results"][0]["change_id"], **row}
        return scan(self.request(), self.adapter(artifact) if analyzer else None, FakePredictor(),
                    **detectors)  # fmt: skip

    def verdict(self, report):
        item = report["results"][0]
        return (item["status"], report["status"], report["exit_code"], item["ml"]["status"],
                item["rule_ml_agreement"])  # fmt: skip


class NotConfiguredTests(DetectorFixture):
    def test_no_detector_only_adds_fields(self):
        self.old["packages"]["node_modules/gone"] = package()
        self.old["packages"]["node_modules/other"] = package()
        self.new["packages"]["node_modules/other"] = {
            **package("2.0.0"),
            "resolved": "https://evil.test/a.tgz",
        }
        self.save_locks()
        for signal, expected in ((0.1, ("not_flagged", 2)), (0.9, ("flagged", 2))):
            with self.subTest(signal=signal):
                report = self.scan_with(signal)
                self.assertEqual(report["detectors"], {"known_malicious": None, "rules": None})
                rows = {r["package"]: r for r in report["results"]}
                self.assertEqual((rows["example"]["status"], report["exit_code"]), expected)
                self.assertEqual(rows["gone"]["status"], "removed")
                self.assertEqual(rows["other"]["reason"], "unsupported_registry_source")
                for row in report["results"]:
                    self.assertEqual(row["known_malicious"], {**NOT_CONFIGURED, "matches": []})
                    self.assertEqual(row["rules"], {**NOT_CONFIGURED, "checks": []})
                    self.assertEqual(row["rule_ml_agreement"], "undetermined")
                self.assertEqual(
                    [rows[p]["ml"]["status"] for p in ("example", "gone", "other")],
                    ["hit" if signal > 0.5 else "not_hit", "not_run", "not_run"],
                )

    def test_ml_status_follows_the_ml_path(self):
        unsupported = {"status": "unsupported", "reason": "no_baseline", "error": "none"}
        for label, report, ml in (
            ("no analyzer", self.scan_with(analyzer=False), "not_run"),
            ("missing result", scan(self.request(), self.adapter({**self.artifact(), "results": []}),
                                    FakePredictor()), "failed"),
            ("analysis failed", self.scan_with(row={"status": "failed", "error": "x"}), "failed"),
            ("unsupported", self.scan_with(row=unsupported), "not_run"),
            ("no model", scan(self.request(), self.adapter(), None), "not_run"),
            ("inference failed", self.scan_with(signal="bad"), "failed"),
        ):  # fmt: skip
            with self.subTest(label):
                self.assertEqual(report["results"][0]["ml"], {"status": ml})
                self.assertEqual((report["results"][0]["status"], report["exit_code"]),
                                 ("incomplete", 2))  # fmt: skip


class ExitCodeTests(DetectorFixture):
    def test_known_malicious_hit_is_flagged_despite_a_low_score(self):
        known = KnownList((ADVISORY,))
        report = self.scan_with(0.1, known_malicious=known, rules=Rules())
        item = report["results"][0]
        self.assertEqual(self.verdict(report),
                         ("flagged", "flagged", 1, "not_hit", "neither_hit"))  # fmt: skip
        self.assertEqual((item["score"], known.calls), (0.1, [("example", "1.1.0")]))
        self.assertEqual(
            item["known_malicious"],
            {"status": "hit", "reason": None, "detail": None, "matches": [ADVISORY]},
        )
        self.assertNotIn("reason", item)
        self.assertEqual(report["detectors"], {
            "known_malicious": {"source": KnownList.source, "list_as_of": KnownList.list_as_of,
                                "list_sha256": KnownList.list_sha256},
            "rules": {"ruleset_version": Rules.ruleset_version}})  # fmt: skip

    def test_not_hit_changes_nothing(self):
        for signal, verdict in (
            (0.1, ("not_flagged", "passed", 0, "not_hit", "neither_hit")),
            (0.9, ("flagged", "flagged", 1, "hit", "ml_only")),
        ):
            with self.subTest(signal=signal):
                report = self.scan_with(signal, known_malicious=KnownList(), rules=Rules())
                self.assertEqual(self.verdict(report), verdict)

    def test_a_failed_detector_is_incomplete_and_keeps_the_score(self):
        for label, detectors, slot in (
            ("rules raise", {"rules": Rules(error=RuntimeError("rule engine crashed"))}, "rules"),
            ("list raises", {"known_malicious": KnownList(error=OSError("list unreadable"))},
             "known_malicious"),
        ):  # fmt: skip
            for signal, status in ((0.1, "not_flagged"), (0.9, "flagged")):
                with self.subTest(label, signal=signal):
                    report = self.scan_with(signal, **detectors)
                    item = report["results"][0]
                    self.assertEqual((item["status"], report["exit_code"]), ("incomplete", 2))
                    self.assertEqual((item["reason"], item["score"]), ("detection_failed", signal))
                    self.assertNotIn("detail", item)
                    self.assertEqual(item[slot]["status"], "failed")  # never not_hit
                    self.assertEqual(item[slot]["reason"], "detector_failed")
                    self.assertIn("unreadable" if slot != "rules" else "crashed",
                                  item[slot]["detail"])  # fmt: skip
                    self.assertEqual(item["ml"]["status"], "hit" if status == "flagged"
                                     else "not_hit")  # fmt: skip
                    self.assertEqual(item["rule_ml_agreement"], "undetermined")

    def test_a_malformed_result_is_failed(self):
        bad_rules = (
            {"not": "a list"},
            [None],
            [{"rule_id": "R"}],
            [rule(status="maybe")],
            [rule(evidence="not a list")],
            [rule(locations=[{"file": "a.js", "line": True}])],
            [rule(locations=[{"file": "a.js"}])],
        )
        for result in bad_rules:
            with self.subTest(rules=result):
                item = self.scan_with(rules=Rules(result))["results"][0]
                self.assertEqual((item["rules"]["status"], item["rules"]["reason"],
                                  item["rules"]["checks"], item["status"]),
                                 ("failed", "detector_failed", [], "incomplete"))  # fmt: skip
        bad_matches = ("hit", [{"advisory_id": "A"}], [{**ADVISORY, "match_kind": "guess"}],
                       [{**ADVISORY, "affected": 2}])  # fmt: skip
        for result in bad_matches:
            with self.subTest(matches=result):
                item = self.scan_with(known_malicious=KnownList(result))["results"][0]
                self.assertEqual((item["known_malicious"]["status"], item["status"]),
                                 ("failed", "incomplete"))  # fmt: skip

    def test_records_are_copies_in_contract_order(self):
        record = {**rule("hit"), "extra": "dropped"}
        record["locations"] = [{"line": 3, "file": "package/index.js", "col": 9}]
        report = self.scan_with(
            rules=Rules((record,)),
            known_malicious=KnownList(
                ({"affected": None, "match_kind": "affected_range", "advisory_id": "A", "x": 1},)
            ),
        )
        item = report["results"][0]
        self.assertEqual(list(item["rules"]["checks"][0]), list(rule()))
        self.assertEqual(item["rules"]["checks"][0]["locations"],
                         [{"file": "package/index.js", "line": 3}])  # fmt: skip
        self.assertEqual(
            item["known_malicious"]["matches"],
            [{"advisory_id": "A", "match_kind": "affected_range", "affected": None}],
        )
        item["rules"]["checks"][0]["evidence"].append("changed")
        self.assertEqual(record["evidence"], ["synthetic evidence"])

    def test_a_malformed_detector_identity_is_a_configuration_error(self):
        class NoDate(KnownList):
            list_as_of = None

        class NoVersion:
            def check(self, change, analysis):
                return []

        for detectors in ({"known_malicious": NoDate()}, {"rules": NoVersion()}):
            with self.subTest(detectors), self.assertRaises(GuardError):
                self.scan_with(**detectors)

    def test_a_list_date_out_of_format_fails_without_lowering_a_hit(self):
        # SVC-03-FIX-01 n3: list_as_of must be ISO 8601 UTC with Z (contract 3.1).
        for as_of in ("2026-11-01", "2026-11-01T00:00:00+00:00", "2026-13-01T00:00:00Z",
                      "2026-11-01T00:00:00z", "2026-11-01T00:00Z"):  # fmt: skip
            Undated = type("Undated", (KnownList,), {"list_as_of": as_of})
            with self.subTest(as_of):
                report = self.scan_with(0.1, known_malicious=Undated())
                item = report["results"][0]
                self.assertEqual((item["known_malicious"]["status"], item["known_malicious"]["reason"],
                                  item["status"], item["reason"], report["exit_code"]),
                                 ("failed", "detector_failed", "incomplete", "detection_failed", 2))  # fmt: skip
                self.assertIn("list_as_of", item["known_malicious"]["detail"])
                self.assertEqual(report["detectors"]["known_malicious"]["list_as_of"], as_of)
                report = self.scan_with(0.1, known_malicious=Undated((ADVISORY,)))
                self.assertEqual(self.verdict(report)[:3], ("flagged", "flagged", 1))
                self.assertEqual(report["results"][0]["known_malicious"]["matches"], [ADVISORY])
        Dated = type("Dated", (KnownList,), {"list_as_of": "2026-11-01T00:00:00.123Z"})
        item = self.scan_with(known_malicious=Dated())["results"][0]
        self.assertEqual(item["known_malicious"]["status"], "not_hit")

    def test_a_rule_detector_cannot_change_the_report(self):
        # SVC-03-FIX-01 n1: the detector gets copies of the change and the analysis result.
        class Mutating(Rules):
            def check(self, change, analysis):
                change["after"]["version"] = "9.9.9"
                analysis["features"].clear()
                analysis["evidence"].append("planted")
                return super().check(change, analysis)

        expected = self.scan_with(rules=Rules())["results"][0]
        item = self.scan_with(rules=Mutating())["results"][0]
        self.assertEqual((item["after_version"], item["features"], item["evidence"]),
                         (expected["after_version"], expected["features"], expected["evidence"]))  # fmt: skip
        self.assertEqual(item["rules"]["status"], "not_hit")

    def test_an_interrupt_is_not_a_detector_result(self):
        with self.assertRaises(KeyboardInterrupt):
            self.scan_with(rules=Rules(error=KeyboardInterrupt()))


class OverlapTests(DetectorFixture):
    def test_known_malicious_wins_over_a_failed_detector(self):
        report = self.scan_with(0.1, known_malicious=KnownList((ADVISORY,)),
                          rules=Rules(error=RuntimeError("crashed")))  # fmt: skip
        item = report["results"][0]
        self.assertEqual(self.verdict(report), ("flagged", "flagged", 1, "not_hit", "undetermined"))
        self.assertEqual((item["rules"]["status"], item["rules"]["reason"]),
                         ("failed", "detector_failed"))  # fmt: skip
        self.assertNotIn("reason", item)

    def test_both_with_an_unfinished_ml_path(self):
        # D-2 and D-7 (rules input_failed) on an analysis_failed change: flagged, ML reason kept.
        report = self.scan_with(
            row={"status": "failed", "error": "tarball mismatch"},
            known_malicious=KnownList((ADVISORY,)),
            rules=Rules(),
        )
        item = report["results"][0]
        self.assertEqual(self.verdict(report), ("flagged", "flagged", 1, "failed", "undetermined"))
        self.assertEqual((item["reason"], item["detail"], item["score"]),
                         ("analysis_failed", "tarball mismatch", None))  # fmt: skip
        self.assertEqual(item["rules"], {"status": "failed", "reason": "input_failed",
                                         "detail": None, "checks": []})  # fmt: skip

    def test_known_malicious_hit_without_a_baseline(self):
        # D-5 and the 11/13 rule: no_baseline is checked by name and version; flagged, ML not_run.
        known = KnownList((ADVISORY,))
        report = self.scan_with(row={"status": "unsupported", "reason": "no_baseline", "error": "none"},
                          known_malicious=known, rules=Rules())  # fmt: skip
        item = report["results"][0]
        self.assertEqual(self.verdict(report), ("flagged", "flagged", 1, "not_run", "undetermined"))
        self.assertEqual((item["reason"], known.calls), ("no_baseline", [("example", "1.1.0")]))
        self.assertEqual((item["rules"]["status"], item["rules"]["reason"]),
                         ("not_run", "analysis_unsupported"))  # fmt: skip
        known = KnownList()
        report = self.scan_with(row={"status": "unsupported", "reason": "no_baseline", "error": "none"},
                          known_malicious=known)  # fmt: skip
        self.assertEqual(report["results"][0]["known_malicious"]["status"], "not_hit")
        self.assertEqual(self.verdict(report)[:3], ("incomplete", "incomplete", 2))

    def test_known_malicious_hit_keeps_a_failed_ml_path(self):
        # Contract 4.1 gives failed here; the hit does not turn it into not_run.
        for label, kwargs in (
            ("analysis failed, no rule detector", {"row": {"status": "failed", "error": "x"}}),
            ("inference failed, rules ran", {"signal": "bad", "rules": Rules()}),
        ):  # fmt: skip
            with self.subTest(label):
                report = self.scan_with(known_malicious=KnownList((ADVISORY,)), **kwargs)
                self.assertEqual(self.verdict(report)[:4], ("flagged", "flagged", 1, "failed"))

    def test_a_failed_detector_keeps_the_unfinished_ml_reason(self):
        report = self.scan_with(row={"status": "failed", "error": "tarball mismatch"},
                          known_malicious=KnownList(), rules=Rules())  # fmt: skip
        item = report["results"][0]
        self.assertEqual(self.verdict(report), ("incomplete", "incomplete", 2, "failed",
                                                "undetermined"))  # fmt: skip
        self.assertEqual((item["reason"], item["detail"]), ("analysis_failed", "tarball mismatch"))

    def test_an_incomplete_item_elsewhere_still_gives_exit_2(self):
        self.old["packages"]["node_modules/other"] = package()
        self.new["packages"]["node_modules/other"] = {
            **package("2.0.0"),
            "resolved": "https://evil.test/a.tgz",
        }
        self.save_locks()
        report = self.scan_with(known_malicious=KnownList((ADVISORY,)))
        self.assertEqual((report["status"], report["exit_code"]), ("incomplete", 2))
        rows = {r["package"]: r for r in report["results"]}
        self.assertEqual(rows["example"]["status"], "flagged")


class AgreementTests(DetectorFixture):
    def test_disagreement_is_only_shown(self):
        # Neither rule_only nor ml_only becomes incomplete; status is the ML path's.
        for signal, result, rules, verdict in (
            (0.1, (rule("hit"), rule("not_hit", "R2")), "hit",
             ("not_flagged", "passed", 0, "not_hit", "rule_only")),
            (0.9, (rule(),), "not_hit", ("flagged", "flagged", 1, "hit", "ml_only")),
            (0.9, (rule("hit"),), "hit", ("flagged", "flagged", 1, "hit", "both_hit")),
        ):  # fmt: skip
            with self.subTest(signal=signal, rules=result):
                report = self.scan_with(signal, rules=Rules(result))
                self.assertEqual(self.verdict(report), verdict)
                self.assertEqual(report["results"][0]["rules"]["status"], rules)

    def test_a_rule_hit_with_a_failed_rule_is_not_d7(self):
        # SVC-03-FIX-01 m3: a hit with failed rules is rules hit, so D-7 does not apply and a low
        # score stays not_flagged; the failed rule is still shown in checks with its detail.
        report = self.scan_with(
            0.1, rules=Rules((rule("hit"), rule("failed", "R2", detail="timeout")))
        )
        item = report["results"][0]
        self.assertEqual(self.verdict(report), ("not_flagged", "passed", 0, "not_hit", "rule_only"))
        self.assertEqual((item["rules"]["status"], item["rules"]["reason"]), ("hit", None))
        self.assertEqual([(c["status"], c["detail"]) for c in item["rules"]["checks"]],
                         [("hit", None), ("failed", "timeout")])  # fmt: skip
        self.assertNotIn("reason", item)

    def test_rule_status_from_its_checks(self):
        for result, status, reason in (
            ((rule("hit"), rule("failed", "R2", detail="timeout")), "hit", None),
            ((rule("not_hit"), rule("failed", "R2", detail="timeout")), "failed",
             "detector_failed"),
            ((), "not_hit", None),
        ):  # fmt: skip
            with self.subTest(result=result):
                slot = self.scan_with(rules=Rules(result))["results"][0]["rules"]
                self.assertEqual((slot["status"], slot["reason"], slot["detail"]),
                                 (status, reason, None))  # fmt: skip
                self.assertEqual(len(slot["checks"]), len(result))


class InputTests(DetectorFixture):
    def test_which_changes_are_checked(self):
        # D-5: unanalyzed changes are checked when their registry name and version are certain.
        locks = {
            "same": (package(), {**package(), "integrity": "sha512-other"}),
            "nointegrity": (package(), {**package("2.0.0"), "integrity": None}),
            "renamed": (package(), {**package("2.0.0"), "name": "renamed-real"}),
            "elsewhere": (package(), {**package("2.0.0"), "resolved": "https://evil.test/a.tgz"}),
            "linked": (package(), {"version": "2.0.0", "link": True, "resolved": "../x"}),
            "gone": (package(), None),
        }
        for name, (old, new) in locks.items():
            self.old["packages"][f"node_modules/{name}"] = old
            if new is not None:
                self.new["packages"][f"node_modules/{name}"] = new
        self.save_locks()
        known, rules = KnownList(), Rules()
        report = self.scan_with(known_malicious=known, rules=rules)
        rows = {r["location"].rsplit("/", 1)[-1]: r for r in report["results"]}
        expected = {
            "example": ("not_hit", None, "not_hit", None),
            "same": ("not_hit", None, "not_run", "not_analyzable"),
            "nointegrity": ("not_hit", None, "not_run", "not_analyzable"),
            "renamed": ("not_hit", None, "not_run", "not_analyzable"),
            "elsewhere": ("not_run", "not_analyzable", "not_run", "not_analyzable"),
            "linked": ("not_run", "not_analyzable", "not_run", "not_analyzable"),
            "gone": ("not_run", "not_installed_in_head", "not_run", "not_installed_in_head"),
        }
        for name, (km, km_reason, rule_status, rule_reason) in expected.items():
            with self.subTest(name):
                row = rows[name]
                self.assertEqual((row["known_malicious"]["status"], row["known_malicious"]["reason"],
                                  row["rules"]["status"], row["rules"]["reason"]),
                                 (km, km_reason, rule_status, rule_reason))  # fmt: skip
        self.assertEqual(
            sorted(known.calls),
            [
                ("example", "1.1.0"),
                ("nointegrity", "2.0.0"),
                ("renamed-real", "2.0.0"),
                ("same", "1.0.0"),
            ],
        )
        self.assertEqual(len(rules.calls), 1)

    def test_an_unparsable_url_fails_only_that_change(self):
        # SVC-03-FIX-01 m1 (Revy's case): a renamed change whose tarball URL cannot be parsed
        # fails its own known malicious slot; the scan goes on and the other change's hit stays.
        class OnlyExample(KnownList):
            def match(self, name, version):
                return super().match(name, version) if name == "example" else []

        self.old["packages"]["node_modules/x"] = {**package(), "name": "x"}
        self.new["packages"]["node_modules/x"] = {
            **package(),
            "name": "y",
            "resolved": "https://[::1",
        }
        self.save_locks()
        known = OnlyExample((ADVISORY,))
        report = self.scan_with(known_malicious=known, rules=Rules())
        self.assertEqual((report["status"], report["exit_code"]), ("incomplete", 2))
        rows = {r["location"]: r for r in report["results"]}
        self.assertEqual(rows["node_modules/example"]["status"], "flagged")
        renamed = rows["node_modules/x"]
        self.assertEqual(
            (renamed["status"], renamed["reason"]), ("incomplete", "package_identity_changed")
        )
        self.assertEqual((renamed["known_malicious"]["status"], renamed["known_malicious"]["reason"]),
                         ("failed", "input_failed"))  # fmt: skip
        self.assertIn("cannot be parsed", renamed["known_malicious"]["detail"])
        self.assertEqual(known.calls, [("example", "1.1.0")])

    def test_rules_without_analysis_input(self):
        report = self.scan_with(analyzer=False, known_malicious=KnownList(), rules=Rules())
        item = report["results"][0]
        self.assertEqual((item["known_malicious"]["status"], item["rules"]["reason"],
                          item["reason"]), ("not_hit", "analyzer_not_configured",
                                            "analysis_missing"))  # fmt: skip
        self.assertEqual(self.verdict(report), ("incomplete", "incomplete", 2, "not_run",
                                                "undetermined"))  # fmt: skip
        report = scan(self.request(), self.adapter({**self.artifact(), "results": []}),
                      FakePredictor(), rules=Rules())  # fmt: skip
        self.assertEqual(report["results"][0]["rules"]["reason"], "input_failed")
        self.assertEqual(self.verdict(report)[3], "failed")

    def test_item_key_order(self):
        # A D-7 reason on a scored change comes after the ML fields, before the detector fields.
        report = self.scan_with(known_malicious=KnownList(), rules=Rules(error=RuntimeError("x")))
        self.assertEqual(list(report["results"][0]), [
            "change_id", "location", "package", "before_version", "after_version", "status",
            "score", "evidence", "compared_version", "features", "reason", "known_malicious",
            "rules", "ml", "rule_ml_agreement"])  # fmt: skip
