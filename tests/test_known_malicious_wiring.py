"""Known malicious index wiring (KM-01): service, CLI, Actions gate, MCP, dashboard options, D-16.

Synthetic only: indexes built from made-up MAL-EXAMPLE-* records, FakeBackend for
depbee-analyzer and the registry, fake predictors and a fake npm; no network, no package code.
"""

import contextlib
import hashlib
import io
import json
import os
import unittest
import uuid
from pathlib import Path
from unittest import mock

from test_cache import EXTRACTOR, Model
from test_dashboard import BASE, PORT, SESSION, ScreenFixture
from test_extract import FakeBackend, packument
from test_known_malicious import AS_OF, record, semver, snapshot
from test_mcp import NO_SDK, SDK, MCPFixture, entry
from test_update import UpdateFixture
from test_workflow import Fixture

from depbee import actions, known_malicious, mcp
from depbee.analysis import cache
from depbee.analysis.baseline import Baseline, select_baseline
from depbee.analysis.extractor import ExtractorAnalyzer
from depbee.cli import main
from depbee.known_malicious import build_index
from depbee.service import check_package, scan_project

LISTED = [record("MAL-EXAMPLE-0001", "example", ["1.1.0"])]  # the lockfile's new version
OTHER = [record("MAL-EXAMPLE-0002", "example-other", ["1.0.0"])]  # nothing in the lockfile


class IndexMixin:
    def index(self, records):
        """A new index folder under the run's root; returns (folder, index.json sha256)."""
        folder = self.root / f"km-{uuid.uuid4().hex[:8]}"
        folder.mkdir()
        index, manifest, _ = build_index(snapshot(records), AS_OF)
        (folder / "index.json").write_bytes(index)
        (folder / "manifest.json").write_bytes(manifest)
        return folder, hashlib.sha256(index).hexdigest()

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(known_malicious, "_last", None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()


def identity(sha256):
    return {"source": "OSV npm MAL", "list_as_of": AS_OF, "list_sha256": sha256}


class AssetArgumentTests(unittest.TestCase):
    def test_blank_asset_argument_is_rejected_before_running_the_command(self):
        for command in (
            ["scan", "."],
            ["check", "example@1.0.0"],
            ["update"],
            ["dashboard"],
            ["mcp"],
        ):
            for option in ("--model-dir", "--known-malicious-dir"):
                for blank in ("", "  "):
                    with self.subTest(command=command, option=option, blank=blank):
                        err = io.StringIO()
                        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
                            main([*command, option, blank])
                        self.assertEqual(cm.exception.code, 2)
                        self.assertIn(
                            f"{option}: give a non-empty trusted directory", err.getvalue()
                        )


class ServiceTests(IndexMixin, MCPFixture):
    def scan(self, **options):
        return scan_project(self.project, self.base, extract=True, model_dir=Path("m"), **options)

    def test_option_then_variable_then_none(self):
        listed, listed_sha = self.index(LISTED)
        other, other_sha = self.index(OTHER)
        os.environ["DEPBEE_KNOWN_MALICIOUS_DIR"] = str(listed)
        self.assertEqual(self.scan()["detectors"]["known_malicious"], identity(listed_sha))
        report = self.scan(known_malicious_dir=other)
        self.assertEqual(report["detectors"]["known_malicious"], identity(other_sha))
        for value in ("", None):
            with self.subTest(variable=value):
                if value is None:
                    os.environ.pop("DEPBEE_KNOWN_MALICIOUS_DIR")
                else:
                    os.environ["DEPBEE_KNOWN_MALICIOUS_DIR"] = value
                report = self.scan()
                self.assertEqual(report["detectors"], {"known_malicious": None, "rules": None})
                self.assertEqual(
                    report["results"][0]["known_malicious"],
                    {"status": "not_run", "reason": "detector_not_configured", "detail": None,
                     "matches": []},
                )  # fmt: skip

    def test_without_an_index_the_calls_are_unchanged(self):
        with mock.patch("depbee.service.scan") as scan, \
                mock.patch("depbee.analysis.extractor.ExtractorAnalyzer") as analyzer:  # fmt: skip
            analyzer.return_value.measurements = {}
            analyzer.return_value.packument.return_value = packument(
                {"1.0.0": "2026-01-01T00:00:00Z", "1.1.0": "2026-01-02T00:00:00Z"}
            )
            scan.side_effect = lambda *args, **kwargs: {"results": []}
            self.scan()
            check_package("example", "1.1.0")
        self.assertEqual((scan.call_count, analyzer.call_count), (2, 2))
        for call in scan.call_args_list:
            self.assertNotIn("known_malicious", call.kwargs)
        for call in analyzer.call_args_list:
            self.assertNotIn("known_malicious", call.kwargs)

    def test_one_index_for_matching_and_baselines(self):
        folder, _ = self.index(LISTED)
        with mock.patch("depbee.service.load", wraps=known_malicious.load) as load, \
                mock.patch("depbee.service.scan", wraps=mcp.service.scan) as scan, \
                mock.patch("depbee.analysis.extractor.ExtractorAnalyzer",
                           wraps=ExtractorAnalyzer) as analyzer:  # fmt: skip
            self.scan(known_malicious_dir=folder)
        load.assert_called_once_with(folder)
        self.assertIs(scan.call_args.kwargs["known_malicious"],
                      analyzer.call_args.kwargs["known_malicious"])  # fmt: skip

    def test_hit_with_a_low_score_is_flagged(self):
        folder, sha = self.index(LISTED)
        self.scores["example"] = 0.1
        code, out, err = self.run_cli("scan", str(self.project), "--base-lock", str(self.base),
                                      "--extract", "--model-dir", "m", "--known-malicious-dir",
                                      str(folder), "--format", "json")  # fmt: skip
        report = json.loads(out)
        (row,) = report["results"]
        self.assertEqual((code, err, report["exit_code"], report["status"]), (1, "", 1, "flagged"))
        self.assertEqual(report["detectors"]["known_malicious"], identity(sha))
        self.assertEqual((row["status"], row["score"], row["ml"]), ("flagged", 0.1,
                                                                    {"status": "not_hit"}))  # fmt: skip
        self.assertEqual(row["known_malicious"], {
            "status": "hit", "reason": None, "detail": None, "matches": [
                {"advisory_id": "MAL-EXAMPLE-0001", "match_kind": "listed_version",
                 "affected": "1.1.0"}]})  # fmt: skip
        other, _ = self.index(OTHER)
        code, out, _ = self.run_cli("scan", str(self.project), "--base-lock", str(self.base),
                                    "--extract", "--model-dir", "m", "--known-malicious-dir",
                                    str(other), "--format", "json")  # fmt: skip
        (row,) = json.loads(out)["results"]
        self.assertEqual((code, row["status"], row["known_malicious"]["status"]),
                         (0, "not_flagged", "not_hit"))  # fmt: skip

    def test_scanned_hit_with_a_low_score_fails_the_default_action_gate(self):
        # action.yml's "Scan with depbee" and "Decide from the report" steps on one scan: the
        # report.json the scan wrote, its Markdown, the lockfile it read and no fail-on.
        self.scores["quiet"] = 0.1  # the same low score, on a package no record lists
        self.old["packages"]["node_modules/quiet"] = entry("quiet", "1.0.0")
        self.new["packages"] = {"node_modules/quiet": entry("quiet", "1.1.0"),
                                "node_modules/example": self.new["packages"]["node_modules/example"]}  # fmt: skip
        self.write(self.base, self.old)
        # One key a line, as npm writes it; the listed entry is not the first one.
        self.head.write_text(json.dumps(self.new, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(self.head.read_text(encoding="utf-8").splitlines()[8],
                         '    "node_modules/example": {')  # fmt: skip

        def scan_then_decide(records, name):
            folder, _ = self.index(records)
            out = self.root / name
            report, markdown, summary = out / "report.json", out / "summary.md", out / "step.md"
            os.environ["GITHUB_STEP_SUMMARY"] = str(summary)
            printed = io.StringIO()
            # The workspace is the current folder and the lockfile input is relative to it.
            with contextlib.chdir(self.root):
                code, text, err = self.run_cli(
                    "scan", "project", "--base-lock", str(self.base), "--extract", "--model-dir",
                    "m", "--known-malicious-dir", str(folder), "--format", "markdown", "--output",
                    str(report))  # fmt: skip
                markdown.write_text(text, encoding="utf-8")
                with contextlib.redirect_stdout(printed):
                    decided = actions.main(["report", str(report), "--lockfile",
                                            "project/package-lock.json", "--fail-on", "",
                                            "--markdown", str(markdown)])  # fmt: skip
            results = json.loads(report.read_text("utf-8"))["results"]
            rows = {row["package"]: row for row in results}
            self.assertEqual((err, sorted(rows)), ("", ["example", "quiet"]))
            for row in results:
                self.assertEqual((row["score"], row["ml"]), (0.1, {"status": "not_hit"}))
            verdicts = {package: (row["status"], row["known_malicious"]["status"])
                        for package, row in rows.items()}  # fmt: skip
            return code, verdicts, decided, printed.getvalue().splitlines(), summary.read_text(
                "utf-8")  # fmt: skip

        code, verdicts, decided, lines, summary = scan_then_decide(LISTED, "listed")
        self.assertEqual((code, decided), (1, 1))
        self.assertEqual(verdicts, {"example": ("flagged", "hit"),
                                    "quiet": ("not_flagged", "not_hit")})  # fmt: skip
        # One annotation, an error on the listed entry's own line of the lockfile.
        self.assertEqual(lines, [
            "::error file=project/package-lock.json,line=9::depbee: example@1.1.0 "
            "(node_modules/example): 기지 악성 기록 일치(MAL-EXAMPLE-0001)"])  # fmt: skip
        self.assertTrue(summary.startswith("## depbee 검사 결과: 위험 판정 있음 (종료 코드 1)\n"))
        self.assertIn("### depbee Actions 판정: 실패\n", summary)
        self.assertIn("- 기지 악성 기록 일치 1개: 항상 실패\n", summary)
        self.assertIn("- ML 위험 점수 기준 이상 0개: 경고\n", summary)
        # The same change and scores against a list that names neither package: the gate passes,
        # so the failure above is the match and not something every such report gets.
        code, verdicts, decided, lines, summary = scan_then_decide(OTHER, "other")
        self.assertEqual((code, decided, lines), (0, 0, []))
        self.assertEqual(set(verdicts.values()), {("not_flagged", "not_hit")})
        self.assertIn("### depbee Actions 판정: 통과\n", summary)
        self.assertIn("- 기지 악성 기록 일치 0개: 항상 실패\n", summary)

    def test_scan_without_extract(self):
        folder, sha = self.index(LISTED)
        code, out, err = self.run_cli("scan", str(self.project), "--base-lock", str(self.base),
                                      "--known-malicious-dir", str(folder), "--format", "json")  # fmt: skip
        report = json.loads(out)
        (row,) = report["results"]
        # D-2: a hit stands even though nothing was analyzed or scored.
        self.assertEqual((code, row["status"], row["reason"], row["known_malicious"]["status"]),
                         (1, "flagged", "analysis_missing", "hit"))  # fmt: skip
        self.assertEqual(report["detectors"]["known_malicious"], identity(sha))
        self.assertEqual(self.backend.fetched, [])  # no registry read without --extract
        other, _ = self.index(OTHER)
        code, out, _ = self.run_cli("scan", str(self.project), "--base-lock", str(self.base),
                                    "--known-malicious-dir", str(other), "--format", "text")  # fmt: skip
        self.assertEqual(code, 2)  # unanalyzed, as before; the list did not match
        self.assertIn("기지 악성 목록: OSV npm MAL", out)

    def test_check_and_mcp_tools(self):
        folder, sha = self.index(LISTED)
        code, out, _ = self.run_cli("check", "example@1.1.0", "--model-dir", "m",
                                    "--known-malicious-dir", str(folder), "--format", "json")  # fmt: skip
        report = json.loads(out)
        self.assertEqual((code, report["results"][0]["known_malicious"]["status"]), (1, "hit"))
        response = mcp.check_package("example@1.1.0", model_dir=Path("m"),
                                     known_malicious_dir=folder)  # fmt: skip
        self.assertEqual(response["report"]["detectors"]["known_malicious"], identity(sha))
        self.assertEqual(response["report"]["exit_code"], 1)
        response = mcp.scan_lockfile(str(self.project), str(self.base), model_dir=Path("m"),
                                     known_malicious_dir=folder)  # fmt: skip
        self.assertEqual(response["report"]["results"][0]["known_malicious"]["status"], "hit")
        self.assertIn("경고: 기지 악성 기록 일치 1개. 낮은 ML 위험 점수는 이 경고를 취소하지 않습니다. "
                      "이 일치로 위험 판정했습니다.", response["notices"])  # fmt: skip

    def test_mcp_option_reaches_the_server(self):
        with mock.patch("depbee.mcp.serve") as serve:
            self.assertEqual(main(["mcp", "--known-malicious-dir", "km"]), 0)
            self.assertEqual(main(["mcp"]), 0)
        self.assertEqual([c.args for c in serve.call_args_list], [(None, Path("km")), (None, None)])

    def test_broken_index_is_an_error_before_the_registry(self):
        folder, _ = self.index(LISTED)
        (folder / "index.json").write_bytes(b"{}\n")
        cases = {
            "missing": str(self.root / "no-such-index"),
            "hash": str(folder),
        }
        for label, path in cases.items():
            for argv in (["scan", str(self.project), "--base-lock", str(self.base), "--extract"],
                         ["check", "example@1.1.0"]):  # fmt: skip
                with self.subTest(label=label, command=argv[0]):
                    code, out, err = self.run_cli(*argv, "--model-dir", "m",
                                                  "--known-malicious-dir", path)  # fmt: skip
                    self.assertEqual((code, out), (2, ""))
                    error = json.loads(err)
                    self.assertEqual(error["exit_code"], 2)
                    self.assertIn("Known malicious index", error["error"])
                    self.assertEqual(self.backend.fetched, [])
        os.environ["DEPBEE_KNOWN_MALICIOUS_DIR"] = str(folder)  # a broken one from the variable
        code, out, err = self.run_cli("scan", str(self.project), "--base-lock", str(self.base))
        self.assertEqual((code, out), (2, ""))
        self.assertIn("SHA-256", json.loads(err)["error"])
        response = mcp.check_package("example@1.1.0")
        self.assertIn("Known malicious index", response["error"]["error"])
        self.assertEqual(self.backend.fetched, [])


@unittest.skipUnless(SDK, NO_SDK)
class ServerTests(IndexMixin, MCPFixture):
    def test_build_server_passes_the_index_to_both_tools(self):
        import anyio
        from mcp import Client

        folder, sha = self.index(LISTED)
        server = mcp.build_server(Path("m"), folder)
        calls = (("check_package", {"package": "example@1.1.0"}),
                 ("scan_lockfile", {"project": str(self.project), "base_lock": str(self.base)}))  # fmt: skip

        async def run():
            async with Client(server) as client:
                return [await client.call_tool(name, arguments) for name, arguments in calls]

        for (name, _), result in zip(calls, anyio.run(run), strict=True):
            with self.subTest(name):
                self.assertFalse(result.is_error)
                report = json.loads(result.content[0].text)["report"]
                self.assertEqual(report["detectors"]["known_malicious"], identity(sha))
                self.assertEqual(report["results"][0]["known_malicious"]["status"], "hit")


class UpdateGateTests(IndexMixin, UpdateFixture):
    def setUp(self):
        super().setUp()
        analyzer = self.patch("depbee.analysis.extractor.ExtractorAnalyzer")
        analyzer.return_value.analyze.side_effect = lambda request: self.artifact({"signal": 0.1})
        analyzer.return_value.measurements = {}
        self.analyzer = analyzer

    def test_not_hit_needs_no_confirmation(self):
        folder, _ = self.index(OTHER)
        code, out, err = self.cli("--known-malicious-dir", str(folder), "--format", "json")
        report = json.loads(out)["report"]
        self.assertEqual((code, report["results"][0]["known_malicious"]["status"]), (0, "not_hit"))
        self.assertIn("known_malicious", self.analyzer.call_args.kwargs)
        code, out, err = self.cli("--known-malicious-dir", str(folder), "--apply", "lockfile",
                                  "--format", "json")  # fmt: skip
        apply = json.loads(out)["apply"]
        self.assertEqual((code, apply["outcome"], apply["confirmation_required"]),
                         (0, "applied", []))  # fmt: skip

    def test_without_an_index_every_item_still_needs_confirmation(self):
        code, out, _ = self.cli("--apply", "lockfile", "--format", "json")
        apply = json.loads(out)["apply"]
        self.assertEqual((code, apply["outcome"], apply["reason"]),
                         (2, "refused", "confirmation_required"))  # fmt: skip
        self.assertEqual(apply["confirmation_required"][0]["causes"], ["known_malicious_unchecked"])

    def test_hit_is_refused_even_when_confirmed(self):
        folder, _ = self.index(LISTED)
        before = self.project_state()
        code, out, _ = self.cli("--known-malicious-dir", str(folder), "--apply", "install",
                                "--confirm-warnings", "--format", "json")  # fmt: skip
        result = json.loads(out)
        self.assertEqual(result["report"]["results"][0]["status"], "flagged")
        self.assertEqual((code, result["apply"]["outcome"], result["apply"]["reason"]),
                         (1, "refused", "known_malicious_hit"))  # fmt: skip
        self.assertEqual(self.project_state(), before)


class DashboardOptionTests(Fixture):
    def test_options_carry_the_index_only_when_given(self):
        try:
            from depbee.dashboard import app
        except ImportError:
            self.skipTest("Starlette, Jinja2 and uvicorn (extra [web]) not installed")

        class Server:
            def __init__(self, config):
                pass

            def run(self, sockets):
                pass

        with mock.patch.object(app.uvicorn, "Server", Server), \
                mock.patch.object(app, "build_app", wraps=app.build_app) as built, \
                contextlib.redirect_stdout(io.StringIO()):  # fmt: skip
            self.assertEqual(main(["dashboard", "--known-malicious-dir", "km"]), 0)
            self.assertEqual(main(["dashboard"]), 0)
        self.assertEqual([call.kwargs for call in built.call_args_list], [
            {"model_dir": None, "cache_dir": None, "no_cache": False,
             "known_malicious_dir": Path("km")},
            {"model_dir": None, "cache_dir": None, "no_cache": False}])  # fmt: skip


class DashboardPreviewTests(ScreenFixture):
    def test_update_check_gets_the_index(self):
        from starlette.testclient import TestClient

        app = self.app.build_app(PORT, SESSION, known_malicious_dir=Path("km"))
        self.client = TestClient(app, base_url=BASE)
        self.addCleanup(self.client.close)
        self.preview_id("example")
        ((_, names, options),) = self.previewed
        self.assertEqual(names, ["example"])
        self.assertEqual(options, {"model_dir": None, "cache_dir": None, "no_cache": False,
                                   "known_malicious_dir": Path("km")})  # fmt: skip


class BaselineExclusionTests(IndexMixin, Fixture):
    """D-16 with ExtractorAnalyzer and FakeBackend: lockfile 1.0.0 -> 1.1.0, candidates 1.0.1
    (the rule's pick) and 1.0.0."""

    def setUp(self):
        super().setUp()
        self.doc = packument({"1.0.0": "2026-01-01T00:00:00Z", "1.0.1": "2026-01-02T00:00:00Z",
                              "1.1.0": "2026-01-03T00:00:00Z"})  # fmt: skip

    def analyze(self, records=None):
        backend = FakeBackend(self.doc)
        index = known_malicious.load(self.index(records)[0]) if records is not None else None
        options = {"known_malicious": index} if index else {}
        artifact = ExtractorAnalyzer(backend=backend, **options).analyze(self.request())
        return artifact["results"][0], backend

    def test_listed_or_bounded_candidates_are_skipped(self):
        cases = {
            "listed": [record("MAL-EXAMPLE-0101", "example", ["1.0.1"])],
            "bounded": [
                record(
                    "MAL-EXAMPLE-0101",
                    "example",
                    ranges=[semver(("introduced", "1.0.1"), ("fixed", "1.0.2"))],
                )
            ],  # fmt: skip
            "last_affected": [
                record(
                    "MAL-EXAMPLE-0101",
                    "example",
                    ranges=[semver(("introduced", "1.0.1"), ("last_affected", "1.0.1"))],
                )
            ],  # fmt: skip
        }
        for label, records in cases.items():
            with self.subTest(label):
                row, backend = self.analyze(records)
                self.assertEqual(row["baseline_version"], "1.0.0")
                self.assertEqual(backend.calls, [("example", "1.0.0", "1.1.0", None)])
                self.assertEqual(row["evidence"][:2], [
                    "비교: 1.0.0 → 1.1.0 (같은 release line의 직전 stable)",
                    "비교 기준 후보에서 뺌: 1.0.1 (기지 악성 기록 MAL-EXAMPLE-0101)"])  # fmt: skip

    def test_unbounded_withdrawn_and_other_records_are_not_used(self):
        cases = {
            "no index": None,
            "all versions": [
                record("MAL-EXAMPLE-0101", "example", ranges=[semver(("introduced", "0"))])
            ],  # fmt: skip
            "open": [
                record("MAL-EXAMPLE-0101", "example", ranges=[semver(("introduced", "1.0.1"))])
            ],
            "withdrawn": [
                record("MAL-EXAMPLE-0101", "example", ["1.0.1"], withdrawn="2026-01-01T00:00:00Z"),
                *OTHER,
            ],  # fmt: skip
            "ghsa": [record("GHSA-example-0001", "example", ["1.0.1"]), *OTHER],
            "other name": OTHER,
        }
        for label, records in cases.items():
            with self.subTest(label):
                row, _ = self.analyze(records)
                self.assertEqual(row["baseline_version"], "1.0.1")
                self.assertNotIn("비교 기준 후보에서 뺌", "\n".join(row["evidence"]))

    def test_every_candidate_skipped_is_no_baseline(self):
        row, backend = self.analyze([record("MAL-EXAMPLE-0101", "example", ["1.0.0", "1.0.1"])])
        self.assertEqual((row["status"], row["reason"]), ("unsupported", "no_baseline"))
        self.assertEqual(row["error"], "No earlier stable version of example to compare 1.1.0 with"
                         "; 1.0.1 skipped as known malicious (MAL-EXAMPLE-0101)"
                         "; 1.0.0 skipped as known malicious (MAL-EXAMPLE-0101)")  # fmt: skip
        self.assertEqual(backend.calls, [])

    def test_cache_key_changes_only_with_the_baseline(self):
        backend = FakeBackend(self.doc)
        backend.identity = dict(EXTRACTOR)
        keys = []
        real = cache.load

        def spy(folder, key):
            keys.append(key)
            return real(folder, key)

        def run(records):
            options = {}
            if records is not None:
                options["known_malicious"] = known_malicious.load(self.index(records)[0])
            analyzer = ExtractorAnalyzer(backend=backend, cache_dir=self.root / "cache",
                                         cache_model=Model(), **options)  # fmt: skip
            with mock.patch("depbee.analysis.cache.load", side_effect=spy):
                analyzer.analyze(self.request())
            return keys[-1]

        plain = run(None)
        self.assertEqual(run(OTHER), plain)  # an index that changes no baseline: the same key
        self.assertEqual(run([record("MAL-EXAMPLE-0101", "example", ranges=[
            semver(("introduced", "0"))])]), plain)  # fmt: skip
        skipped = run([record("MAL-EXAMPLE-0101", "example", ["1.0.1"])])
        self.assertEqual(skipped["baseline"], "1.0.0")
        changed = {k for k in plain if plain[k] != skipped[k]}
        self.assertEqual(changed, {"baseline", "manifests", "time"})  # all from the baseline


class SelectBaselineTests(unittest.TestCase):
    def test_exclude_is_asked_in_pick_order(self):
        doc = packument({"1.4.0": "2026-01-01T00:00:00Z", "2.0.0": "2026-01-02T00:00:00Z",
                         "2.0.1": "2026-01-03T00:00:00Z", "2.1.0": "2026-01-04T00:00:00Z"})  # fmt: skip
        asked = []

        def exclude(version):
            asked.append(version)
            return version.startswith("2.")

        self.assertEqual(select_baseline(doc, "2.1.0", exclude), Baseline("1.4.0", "L2"))
        self.assertEqual(asked, ["2.0.1", "2.0.0", "1.4.0"])  # each candidate asked once
        self.assertEqual(select_baseline(doc, "2.1.0"), Baseline("2.0.1", "L1"))
        self.assertEqual(select_baseline(doc, "2.1.0", lambda version: False),
                         Baseline("2.0.1", "L1"))  # fmt: skip
        self.assertIsNone(select_baseline(doc, "2.1.0", lambda version: True))
