"""Synthetic tests for the extractor analyzer, baseline rule and Korean output.

No network access and no package code: feature-extractor is replaced by FakeBackend.
"""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from test_contract import ExplainingPredictor
from test_workflow import FakePredictor, Fixture, package

from depbee.analysis.baseline import select_baseline
from depbee.analysis.extractor import ExtractorAnalyzer, FeatureExtractorBackend
from depbee.cli import _print_text, main
from depbee.contracts import GuardError, read_json
from depbee.inputs.npm import build_package_request, check_package_spec
from depbee.pipeline import LOCKFILE_SCOPE, PACKAGE_SCOPE, scan
from depbee.service import check_package, scan_project

INTEGRITY = "sha512-test-only-not-an-archive-digest"


def packument(times, name="example"):
    def manifest(version):
        tarball = f"https://registry.npmjs.org/{name}/-/{name.rpartition('/')[2]}-{version}.tgz"
        dist = {"integrity": INTEGRITY, "tarball": tarball}
        return {"name": name, "version": version, "dist": dist}

    return {
        "name": name,
        "time": {"created": "2020-01-01T00:00:00Z", **times},
        "versions": {v: manifest(v) for v in times},
    }


class BaselineTests(unittest.TestCase):
    def test_same_line_stable_predecessor(self):
        doc = packument(
            {
                "1.0.0": "2026-01-01T00:00:00Z",
                "1.0.1": "2026-01-02T00:00:00Z",
                "1.1.0-beta.1": "2026-01-03T00:00:00Z",
                "0.0.0-main.abc": "2026-01-04T00:00:00Z",
                "2.0.0": "2026-01-05T00:00:00Z",
                "1.1.0": "2026-01-06T00:00:00Z",
            }
        )
        baseline = select_baseline(doc, "1.1.0")
        self.assertEqual((baseline.version, baseline.level), ("1.0.1", "L1"))

    def test_earlier_line_when_new_starts_a_line(self):
        doc = packument({"1.4.0": "2026-01-01T00:00:00Z", "2.0.0": "2026-01-02T00:00:00Z"})
        baseline = select_baseline(doc, "2.0.0")
        self.assertEqual((baseline.version, baseline.level), ("1.4.0", "L2"))

    def test_zero_major_line_is_minor(self):
        doc = packument(
            {
                "0.2.9": "2026-01-01T00:00:00Z",
                "0.3.0": "2026-01-02T00:00:00Z",
                "0.3.1": "2026-01-03T00:00:00Z",
            }
        )
        self.assertEqual(select_baseline(doc, "0.3.1").version, "0.3.0")
        self.assertEqual(select_baseline(doc, "0.3.0").level, "L2")

    def test_excludes_later_published_and_unpublished_versions(self):
        doc = packument(
            {
                "1.0.0": "2026-01-01T00:00:00Z",
                "1.0.2": "2026-01-05T00:00:00Z",
                "1.0.3": "2026-01-03T00:00:00Z",
            }
        )
        doc["time"]["1.0.1"] = "2026-01-02T00:00:00Z"  # unpublished: no tarball
        # 1.0.2 was published after 1.0.3 (a backport), so it cannot be 1.0.3's predecessor.
        self.assertEqual(select_baseline(doc, "1.0.3").version, "1.0.0")

    def test_no_predecessor_and_prerelease(self):
        doc = packument({"1.0.0": "2026-01-01T00:00:00Z", "1.1.0-rc.1": "2026-01-02T00:00:00Z"})
        self.assertIsNone(select_baseline(doc, "1.0.0"))
        with self.assertRaises(GuardError):
            select_baseline(doc, "1.1.0-rc.1")

    def test_publish_times_need_a_timezone(self):
        # Different offsets compare by instant: 08:00+09:00 is 23:00Z, before 23:30Z.
        doc = packument({"1.0.0": "2026-01-02T08:00:00+09:00", "1.1.0": "2026-01-01T23:30:00Z"})
        self.assertEqual(select_baseline(doc, "1.1.0").version, "1.0.0")
        for bad in (
            {"1.0.0": "2026-01-01T00:00:00"},  # candidate without timezone
            {"1.1.0": "2026-01-02T00:00:00"},  # new version without timezone
            {"1.0.0": "2026-13-01T00:00:00Z"},  # not a time
        ):
            with self.subTest(bad=bad):
                doc = packument({"1.0.0": "2026-01-01T00:00:00Z", "1.1.0": "2026-01-02T00:00:00Z"})
                doc["time"].update(bad)
                with self.assertRaisesRegex(GuardError, "publish time"):
                    select_baseline(doc, "1.1.0")


class FakeBackend:
    """Stands in for feature-extractor; returns fixed features."""

    errors = ()
    version = "fake-extractor"

    def __init__(self, doc, features=None, new_json=None):
        self.doc = doc
        self.features = features or {"signal": 0.9, "obfChangedFileCount": 2}
        self.new_json = new_json
        self.calls = []
        self.fetched = []

    def fetch_packument(self, name):
        self.fetched.append(name)
        return self.doc

    def extract(self, name, old, new, doc, local):
        self.calls.append((name, old, new, local))
        return dict(self.features), self.new_json or doc["versions"][new]


class ExtractorAnalyzerTests(Fixture):
    def setUp(self):
        super().setUp()
        # Lockfile moves 1.0.0 -> 1.1.0; the model compares 1.1.0 with its predecessor 1.0.1.
        self.doc = packument(
            {
                "1.0.0": "2026-01-01T00:00:00Z",
                "1.0.1": "2026-01-02T00:00:00Z",
                "1.1.0": "2026-01-03T00:00:00Z",
            }
        )
        self.doc["versions"]["1.0.1"]["scripts"] = {"test": "x"}
        self.new_json = {
            "scripts": {"test": "x", "postinstall": "node setup.js"},
            "dependencies": {"left-pad": "^1.0.0"},
        }

    def run_analyzer(self, backend=None, local=None):
        backend = backend or FakeBackend(self.doc, new_json=self.new_json)
        return ExtractorAnalyzer(local, backend=backend).analyze(self.request()), backend

    def test_complete_result_compares_with_predecessor(self):
        artifact, backend = self.run_analyzer()
        row = artifact["results"][0]
        self.assertEqual(row["status"], "complete")
        self.assertEqual(row["baseline_version"], "1.0.1")
        self.assertEqual(backend.calls, [("example", "1.0.1", "1.1.0", None)])
        evidence = "\n".join(row["evidence"])
        self.assertIn("1.0.1 → 1.1.0", evidence)
        self.assertIn("lockfile의 이전 버전은 1.0.0", evidence)
        self.assertIn("postinstall = node setup.js", evidence)
        self.assertIn("새 의존성 1개: left-pad", evidence)

    def test_integrity_mismatch_fails(self):
        self.doc["versions"]["1.1.0"]["dist"]["integrity"] = "sha512-other"
        row = self.run_analyzer()[0]["results"][0]
        self.assertEqual(row["status"], "failed")
        self.assertIn("integrity", row["error"])

    def test_unpublished_version_fails_without_local_copy(self):
        del self.doc["versions"]["1.1.0"]
        self.assertEqual(self.run_analyzer()[0]["results"][0]["status"], "failed")

    def test_local_copy_skips_registry_and_says_so(self):
        del self.doc["versions"]["1.1.0"]
        local = {("example", "1.1.0"): self.root}
        row = self.run_analyzer(local=local)[0]["results"][0]
        self.assertEqual(row["status"], "complete")
        self.assertIn("로컬 사본", "\n".join(row["evidence"]))

    def test_progress_is_reported_before_each_change(self):
        calls = []
        backend = FakeBackend(self.doc, new_json=self.new_json)
        analyzer = ExtractorAnalyzer(
            backend=backend, progress=lambda i, n, c: calls.append((i, n, c["after"]["name"]))
        )
        analyzer.analyze(self.request())
        self.assertEqual(calls, [(1, 1, "example")])

    def test_malformed_compared_manifest_fails_before_extract(self):
        for version in ("1.0.1", "1.1.0"):  # baseline, new
            for label, value in (("manifest", "x"), ("dist", ["tarball"])):
                with self.subTest(version=version, label=label):
                    doc = copy.deepcopy(self.doc)
                    if label == "manifest":
                        doc["versions"][version] = value
                    else:
                        doc["versions"][version]["dist"] = value
                    artifact, backend = self.run_analyzer(FakeBackend(doc, new_json=self.new_json))
                    row = artifact["results"][0]
                    self.assertEqual(row["status"], "failed")
                    self.assertIn(f"Registry metadata of example@{version}", row["error"])
                    self.assertEqual(backend.calls, [])

    def test_unused_local_copy_is_an_error(self):
        with self.assertRaises(GuardError):
            self.run_analyzer(local={("example", "9.9.9"): self.root})

    def test_prerelease_is_out_of_scope(self):
        self.new["packages"]["node_modules/example"]["version"] = "1.2.0-beta.1"
        self.save_locks()
        row = self.run_analyzer()[0]["results"][0]
        self.assertEqual((row["status"], row["reason"]), ("unsupported", "out_of_training_scope"))

    def test_first_release_has_no_baseline(self):
        self.doc = packument({"1.1.0": "2026-01-03T00:00:00Z"})
        row = self.run_analyzer()[0]["results"][0]
        self.assertEqual((row["status"], row["reason"]), ("unsupported", "no_baseline"))
        report = scan(self.request(), ExtractorAnalyzer(backend=FakeBackend(self.doc)), None)
        self.assertEqual((report["exit_code"], report["results"][0]["reason"]), (2, "no_baseline"))


class CliTests(Fixture):
    def test_korean_text_escapes_control_characters(self):
        artifact = self.artifact()
        artifact["results"][0]["evidence"] = ["설치 스크립트 추가: postinstall = a\x1b[2Jb"]
        report = scan(self.request(), self.adapter(artifact), ExplainingPredictor())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            _print_text(report)
        text = out.getvalue()
        self.assertIn("depbee 검사 결과: 위험 판정 있음 (종료 코드 1)", text)
        self.assertIn("[위험] example@1.1.0", text)
        self.assertIn("+ signal = 0.9 (+1.50)", text)
        self.assertIn("나머지 특징 2개 합 -0.25, 모델 기준값 -1.00 (합계 +0.25 → 점수 0.900)", text)
        self.assertNotIn("\x1b", text)
        self.assertIn("\\u001b[2J", text)
        self.assertTrue(text.rstrip().endswith("패키지가 안전하다는 보증이 아닙니다."))

    def test_korean_text_lists_risky_results_first_with_counts(self):
        self.old["packages"]["node_modules/zeta"] = package()
        self.new["packages"]["node_modules/zeta"] = package("1.1.0")
        self.save_locks()
        artifact = self.artifact()
        # Lockfile order is example, zeta; only zeta is risky.
        artifact["results"][0]["features"] = {"signal": 0.2}
        report = scan(self.request(), self.adapter(artifact), ExplainingPredictor())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            _print_text(report)
        text = out.getvalue()
        self.assertIn("바뀐 의존성 2개: 위험 1, 통과 1, 보류 0", text)
        self.assertLess(text.index("[위험] zeta@1.1.0"), text.index("[통과] example@1.1.0"))
        self.assertEqual([r["package"] for r in report["results"]], ["example", "zeta"])

    def test_korean_text_for_missing_model(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["scan", str(self.project), "--base-lock", str(self.base)])
        self.assertEqual(code, 2)
        self.assertIn("이유: 분석 결과 없음", out.getvalue())

    def run_cli(self, *extra):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["scan", str(self.project), "--base-lock", str(self.base), *extra])
        return code, err.getvalue()

    def test_local_source_needs_extract_and_root(self):
        code, err = self.run_cli("--local-source", f"example@1.1.0={self.root}")
        self.assertEqual(code, 2)
        self.assertIn("--local-root", err)

    def test_local_source_must_stay_under_root(self):
        code, err = self.run_cli(
            "--extract", "--local-root", str(self.project), "--local-source", "example@1.1.0=.."
        )
        self.assertEqual(code, 2)
        self.assertIn("under --local-root", err)


class PackagePredictor(FakePredictor):
    """FakePredictor for the extractor's feature schema; scores the synthetic "signal"."""

    feature_schema = "depbee-features-v1"


class FetchError(Exception):
    pass


class CachingRegistrySource:
    """Stand-in for feature-extractor c24761d RegistrySnapshotSource: it fetches a packument
    only when its _packument_cache has none for the package, and reuses it for old and new.
    With include_source it reads dist.tarball as c24761d loader.py:55-56,100 do, unchecked,
    before the download, which is left out here."""

    def __init__(self, fetch):
        self._packument_cache = {}
        self.fetch = fetch
        self.snapshots = []

    def get_snapshot(self, package, version, *, include_source=False):
        packument = self._packument_cache.get(package)
        if packument is None:
            packument = self._packument_cache[package] = self.fetch(package)
        self.snapshots.append(packument)
        package_json = packument.get("versions", {}).get(version)
        if include_source:
            package_json.get("dist", {}).get("tarball")
        return SimpleNamespace(package_json=package_json)

    def close(self):
        pass


def stand_in_backend(fetch, sources):
    """Real FeatureExtractorBackend; only feature-extractor's pieces are stand-ins. build_row
    asks for source, as c24761d build_row does for the default (obfuscation) extractors."""

    def registry_source():
        sources.append(CachingRegistrySource(fetch))
        return sources[-1]

    def build_row(name, old, new, label, extractors, *, old_source, new_source):
        old_source.get_snapshot(name, old, include_source=True)
        new_source.get_snapshot(name, new, include_source=True)
        return SimpleNamespace(features={"signal": 0.9, "obfChangedFileCount": 2})

    backend = FeatureExtractorBackend.__new__(FeatureExtractorBackend)
    backend.errors, backend.version = (), "stand-in"
    backend.fetch_packument = fetch
    backend._build_row, backend._extractors = build_row, []
    backend._registry_source, backend._local_source = registry_source, None
    return backend


class PackageCheckTests(Fixture):
    """check NAME@VERSION with FakeBackend: no network, no package code, no real extraction."""

    def setUp(self):
        super().setUp()
        self.doc = packument(
            {
                "1.0.0": "2026-01-01T00:00:00Z",
                "1.0.1": "2026-01-02T00:00:00Z",
                "1.1.0": "2026-01-03T00:00:00Z",
                "1.2.0-beta.1": "2026-01-04T00:00:00Z",
            }
        )
        self.backend = FakeBackend(self.doc)
        backend = mock.patch(
            "depbee.analysis.extractor.FeatureExtractorBackend", return_value=self.backend
        )
        backend.start()
        self.addCleanup(backend.stop)

    def run_check(self, *args, model=None):
        """Real cli.main; model, if given, is what LightGBMPredictor returns."""
        out, err = io.StringIO(), io.StringIO()
        loader = (
            mock.patch("depbee.service.LightGBMPredictor", return_value=model)
            if model
            else contextlib.nullcontext()
        )
        with loader, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["check", *args])
        return code, out.getvalue(), err.getvalue()

    def test_name_and_version_are_checked_before_any_network(self):
        for name in ("example", "@scope/pkg", "@scope/_pkg", "JSONStream", "a.b-c_d~e", "a" * 214):
            with self.subTest(name=name):
                self.assertIsNone(check_package_spec(name, "1.0.0-rc.1"))
        for version in ("1.0.0", "1.0.0-0", "1.0.0-01a", "1.0.0-0-1", "1.0.0-alpha.0"):
            with self.subTest(version=version):
                self.assertIsNone(check_package_spec("example", version))
        bad_names = (
            "", "@scope", "@scope/", "@/pkg", ".hidden", "_private", "@.scope/pkg", "@_scope/pkg",
            "@scope/.pkg", "@scope/..", "..", "a/b", "@s/a/b", "a b", " a", "a\n", "a\x1b[2J",
            "https://evil.test/a", "a?b", "a#b", "a%2fb", "a:b", "é", "a" * 215,
        )  # fmt: skip
        bad_versions = (
            "", "latest", "^1.0.0", "~1.0.0", "1.x", ">=1.0.0", "1.0", "v1.0.0", "=1.0.0",
            "01.0.0", "1.0.0+build", "1.0.0 ", "1.0.0\n", "1.0.0 || 2.0.0", "file:../x",
            "git+https://x.test/a.git", "https://x.test/a.tgz", "١.٠.٠", "1.0.0-",
            "1.0.0-a..b", "1.0.0-01", "1.0.0-alpha.01", "1.0.0-00",
        )  # fmt: skip
        for name in bad_names:
            with self.subTest(name=name), self.assertRaisesRegex(GuardError, "package name"):
                check_package(name, "1.0.0")
        for version in bad_versions:
            with self.subTest(version=version), self.assertRaisesRegex(GuardError, "exact version"):
                check_package("example", version)
        # Valid SemVer, but outside the supported build-free form; the error says so.
        with self.assertRaisesRegex(GuardError, r"\+build metadata"):
            check_package("example", "1.0.0+build.1")
        self.assertEqual(self.backend.fetched, [])

    def test_cli_splits_name_at_version(self):
        self.backend.doc = packument(
            {"1.0.1": "2026-01-02T00:00:00Z", "1.1.0": "2026-01-03T00:00:00Z"}, name="@scope/pkg"
        )
        code, out, _ = self.run_check("@scope/pkg@1.1.0", "--format", "json")
        self.assertEqual(code, 2)  # no model
        self.assertEqual(json.loads(out)["results"][0]["package"], "@scope/pkg")
        self.assertEqual(self.backend.calls, [("@scope/pkg", "1.0.1", "1.1.0", None)])
        for spec in ("example", "@scope/pkg", "@1.0.0", "example@", "example@latest", "x@^1.0.0"):
            with self.subTest(spec=spec):
                code, out, err = self.run_check(spec)
                self.assertEqual((code, out), (2, ""))
                self.assertEqual(json.loads(err)["status"], "error")
        self.assertEqual(self.backend.fetched, ["@scope/pkg"])  # none for the bad specs

    def test_request_is_one_added_registry_change(self):
        request = build_package_request("example", "1.1.0", self.doc)
        self.assertEqual(list(request), ["request_id", "schema_version", "input_kind", "changes"])
        self.assertEqual(request["input_kind"], "package")
        [change] = request["changes"]
        self.assertEqual(
            {key: change[key] for key in ("location", "before", "kind", "analyzable", "reason")},
            {
                "location": "registry.npmjs.org",
                "before": None,
                "kind": "added",
                "analyzable": True,
                "reason": None,
            },
        )
        self.assertEqual(
            change["after"],
            {
                "name": "example",
                "version": "1.1.0",
                "resolved": "https://registry.npmjs.org/example/-/example-1.1.0.tgz",
                "integrity": INTEGRITY,
                "link": False,
            },
        )
        # The ids are digests of the checked content: same metadata, same ids.
        self.assertEqual(
            build_package_request("example", "1.1.0", copy.deepcopy(self.doc)), request
        )
        self.doc["versions"]["1.1.0"]["dist"]["integrity"] = "sha512-other"
        other = build_package_request("example", "1.1.0", self.doc)
        self.assertNotEqual(other["request_id"], request["request_id"])
        self.assertNotEqual(other["changes"][0]["change_id"], change["change_id"])

    def test_bad_registry_metadata_is_an_error(self):
        def broken(edit):
            doc = copy.deepcopy(self.doc)
            edit(doc)
            return doc

        def dist(**fields):
            return broken(lambda d: d["versions"]["1.1.0"]["dist"].update(fields))

        cases = {
            "not an object": [],
            "no versions": broken(lambda d: d.pop("versions")),
            "time not an object": broken(lambda d: d.update(time=["1.1.0"])),
            "version not served": broken(lambda d: d["versions"].pop("1.1.0")),
            "manifest not an object": broken(lambda d: d["versions"].update({"1.1.0": "x"})),
            "other version": broken(lambda d: d["versions"]["1.1.0"].update(version="1.1.1")),
            "other package": broken(lambda d: d["versions"]["1.1.0"].update(name="other")),
            "no dist": broken(lambda d: d["versions"]["1.1.0"].pop("dist")),
            "http tarball": dist(tarball="http://registry.npmjs.org/example/-/example-1.1.0.tgz"),
            "other host": dist(tarball="https://registry.npmjs.org.evil.test/example-1.1.0.tgz"),
            "tarball not text": dist(tarball=5),
            "no integrity": broken(lambda d: d["versions"]["1.1.0"]["dist"].pop("integrity")),
            "blank integrity": dist(integrity="  "),
            "integrity not text": dist(integrity=[INTEGRITY]),
        }
        for label, doc in cases.items():
            with self.subTest(label), self.assertRaises(GuardError):
                build_package_request("example", "1.1.0", doc)
        # Through the CLI it is an error JSON with exit 2, never a report.
        self.backend.doc = cases["no integrity"]
        code, out, err = self.run_check("example@1.1.0", "--format", "json")
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(
            json.loads(err)["error"],
            "npm registry metadata for example@1.1.0 has no dist.integrity",
        )

    def test_registry_read_failure_is_exit_2(self):
        self.backend.errors = (FetchError,)
        self.backend.fetch_packument = mock.Mock(side_effect=FetchError("404 Not Found"))
        code, out, err = self.run_check("example@1.1.0")
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(
            json.loads(err)["error"], "Cannot read npm registry metadata for example: 404 Not Found"
        )

    def test_scores_threshold_and_registry_evidence(self):
        for signal, expected in ((0.2, 0), (0.5, 1), (0.9, 1)):
            with self.subTest(signal=signal):
                self.backend.features = {"signal": signal, "obfChangedFileCount": 2}
                self.backend.fetched, self.backend.calls = [], []
                code, out, err = self.run_check(
                    "example@1.1.0", "--model-dir", "models/fake", "--format", "json",
                    model=PackagePredictor(),
                )  # fmt: skip
                report = json.loads(out)
                self.assertEqual((code, report["exit_code"], err), (expected, expected, ""))
                self.assertEqual(self.backend.fetched, ["example"])  # metadata read once
                self.assertEqual(self.backend.calls, [("example", "1.0.1", "1.1.0", None)])
        self.assertEqual((report["input_kind"], report["scope"]), ("package", PACKAGE_SCOPE))
        row = report["results"][0]
        self.assertEqual(
            (row["status"], row["compared_version"], row["before_version"]),
            ("flagged", "1.0.1", None),
        )
        self.assertEqual(
            row["evidence"],
            [
                "비교: 1.0.1 → 1.1.0 (같은 release line의 직전 stable)",
                "lockfile 없이 registry 정보로 검사",
                "추가·수정된 JS 파일 2개",
            ],
        )

    def test_text_names_the_registry_source_for_every_outcome(self):
        runs = {}
        self.backend.features = {"signal": 0.2, "obfChangedFileCount": 2}
        runs["passed"] = self.run_check(
            "example@1.1.0", "--model-dir", "m", model=PackagePredictor()
        )
        runs["model_missing"] = self.run_check("example@1.1.0")
        runs["prerelease"] = self.run_check("example@1.2.0-beta.1")
        failure = GuardError("synthetic extraction failure")
        with mock.patch.object(self.backend, "extract", side_effect=failure):
            runs["failed"] = self.run_check("example@1.1.0")
        self.backend.doc = packument({"1.1.0": "2026-01-03T00:00:00Z"})
        runs["no_baseline"] = self.run_check("example@1.1.0")
        expected = {
            "passed": (0, "[통과] example@1.1.0  (registry.npmjs.org)"),
            "model_missing": (2, "이유: 모델 없음"),
            "prerelease": (2, "이유: 학습 범위 밖 입력"),
            "failed": (2, "상세: synthetic extraction failure"),
            "no_baseline": (2, "이유: 비교할 이전 stable 버전 없음"),
        }
        for label, (code, out, err) in runs.items():
            with self.subTest(label):
                self.assertEqual(code, expected[label][0])
                self.assertIn(expected[label][1], out)
                self.assertIn("검사한 패키지 1개:", out)
                self.assertIn(
                    "범위: lockfile 없이 registry 정보로 이 버전 하나만 검사했습니다.", out
                )
                # Neither "바뀐 의존성" nor "lockfile에서 바뀐"/"lockfile에 새로 추가" wording.
                self.assertNotIn("바뀐 의존성", out)
                self.assertNotIn("lockfile에", out)
                self.assertTrue(out.rstrip().endswith("패키지가 안전하다는 보증이 아닙니다."))
                self.assertRegex(err, r"\A분석 중 1/1: example@1\.(1\.0|2\.0-beta\.1)\n\Z")

    def test_json_output_file_and_no_overwrite(self):
        output = self.root / "check.json"
        code, out, err = self.run_check(
            "example@1.1.0", "--format", "json", "--output", str(output)
        )
        self.assertEqual((code, err), (2, ""))  # no model; JSON format shows no progress
        self.assertEqual(output.read_bytes(), out.encode())
        self.assertEqual(read_json(output)[0]["results"][0]["reason"], "model_missing")
        original = output.read_bytes()
        code, out, err = self.run_check("example@1.1.0", "--output", str(output))
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(json.loads(err.splitlines()[-1])["status"], "error")
        self.assertEqual(output.read_bytes(), original)

    def test_model_dir_then_variable_then_none(self):
        os.environ["DEPBEE_MODEL_DIR"] = "models/from-env"
        with mock.patch(
            "depbee.service.LightGBMPredictor", return_value=PackagePredictor()
        ) as loader:
            self.assertEqual(check_package("example", "1.1.0")["exit_code"], 1)
            loader.assert_called_once_with(Path("models/from-env"))
            loader.reset_mock()
            check_package("example", "1.1.0", model_dir=Path("models/explicit"))
            loader.assert_called_once_with(Path("models/explicit"))
        os.environ["DEPBEE_MODEL_DIR"] = ""
        report = check_package("example", "1.1.0")
        self.assertEqual(report["results"][0]["reason"], "model_missing")
        # A bad model path stops the check before the registry is read.
        self.backend.fetched = []
        with self.assertRaises((OSError, GuardError)):
            check_package("example", "1.1.0", model_dir=self.root / "no-such-model")
        self.assertEqual(self.backend.fetched, [])

    def test_request_id_repeats_and_lockfile_reports_keep_their_fields(self):
        first = check_package("example", "1.1.0")
        self.assertEqual(check_package("example", "1.1.0"), first)
        request = build_package_request("example", "1.1.0", self.doc)
        self.assertEqual(first["request_id"], request["request_id"])
        lockfile = scan_project(self.project, self.base)
        self.assertNotIn("input_kind", lockfile)
        self.assertEqual(lockfile["scope"], LOCKFILE_SCOPE)

    def test_real_backend_snapshots_reuse_the_checked_packument(self):
        sources = []
        backend = stand_in_backend(self.backend.fetch_packument, sources)
        loader = mock.patch(
            "depbee.analysis.extractor.FeatureExtractorBackend", return_value=backend
        )
        with loader:
            report = check_package("example", "1.1.0")
        self.assertEqual(report["results"][0]["reason"], "model_missing")  # analysis complete
        self.assertEqual(self.backend.fetched, ["example"])  # one registry read in total
        self.assertEqual(len(sources[0].snapshots), 2)  # old and new
        self.assertTrue(all(doc is self.doc for doc in sources[0].snapshots))
        # A feature-extractor without that cache fails the analysis instead of fetching again.
        backend._registry_source = lambda: SimpleNamespace(close=lambda: None)
        with loader:
            row = check_package("example", "1.1.0")["results"][0]
        self.assertEqual(row["reason"], "analysis_failed")
        self.assertIn("packument cache", row["detail"])
        self.assertEqual(self.backend.fetched, ["example", "example"])  # analyzer only

    def test_malformed_baseline_stops_before_the_pinned_loader(self):
        # Before the check, c24761d loader.py:100 raised AttributeError: a traceback and exit 1.
        def baseline_dist_list(doc):
            doc["versions"]["1.0.1"]["dist"] = [doc["versions"]["1.0.1"]["dist"]]

        for label, edit, detail in (
            ("baseline manifest is a string", lambda d: d["versions"].update({"1.0.1": "x"}),
             "Registry metadata of example@1.0.1 is not an object"),
            ("baseline dist is a list", baseline_dist_list,
             "Registry metadata of example@1.0.1 has no dist object"),
        ):  # fmt: skip
            with self.subTest(label):
                self.backend.doc = copy.deepcopy(self.doc)
                edit(self.backend.doc)
                sources = []
                backend = stand_in_backend(self.backend.fetch_packument, sources)
                with mock.patch(
                    "depbee.analysis.extractor.FeatureExtractorBackend", return_value=backend
                ):
                    code, out, err = self.run_check("example@1.1.0", "--format", "json")
                report = json.loads(out)
                self.assertEqual((code, err, report["exit_code"]), (2, "", 2))
                row = report["results"][0]
                self.assertEqual((row["reason"], row["detail"]), ("analysis_failed", detail))
                self.assertEqual(sources, [])  # feature-extractor was not called

    def test_bad_publish_times_end_with_exit_2_not_a_traceback(self):
        for label, times in (
            ("mixed timezone", {"1.0.0": "2026-01-01T00:00:00", "1.1.0": "2026-01-02T00:00:00Z"}),
            ("new without timezone", {"1.0.0": "2026-01-01T00:00:00Z", "1.1.0": "2026-01-02"}),
            ("not a time", {"1.0.0": "2026-13-01T00:00:00Z", "1.1.0": "2026-01-02T00:00:00Z"}),
        ):
            with self.subTest(label):
                self.backend.doc = packument(times)
                code, out, err = self.run_check("example@1.1.0", "--format", "json")
                row = json.loads(out)["results"][0]
                self.assertEqual((code, err, row["reason"]), (2, "", "analysis_failed"))
                self.assertIn("publish time", row["detail"])

    def test_malformed_compared_metadata_fails_closed(self):
        edits = {
            "manifest": lambda d: d["versions"].update({"1.0.1": "x"}),
            "scripts": lambda d: d["versions"]["1.0.1"].update(scripts=["postinstall"]),
            "dependencies": lambda d: d["versions"]["1.0.1"].update(dependencies=7),
        }
        for label, edit in edits.items():
            with self.subTest(label):
                self.backend.doc = copy.deepcopy(self.doc)
                edit(self.backend.doc)
                code, out, _ = self.run_check(
                    "example@1.1.0", "--model-dir", "m", "--format", "json",
                    model=PackagePredictor(),
                )  # fmt: skip
                row = json.loads(out)["results"][0]
                self.assertEqual((code, row["reason"]), (2, "analysis_failed"))

    @unittest.skipUnless(
        importlib.util.find_spec("lightgbm"), "Install .[ml] for native integration tests"
    )
    def test_synthetic_native_model(self):
        import lightgbm as lgb
        import numpy as np

        # Purely synthetic numbers verify the connection, not detection quality.
        data = lgb.Dataset(np.array([[0.0], [0.1], [0.2], [0.8], [0.9], [1.0]]),
                           label=[0, 0, 0, 1, 1, 1], feature_name=["signal"])  # fmt: skip
        params = {"objective": "binary", "verbosity": -1, "num_threads": 1,
                  "min_data_in_leaf": 1, "min_data_in_bin": 1}  # fmt: skip
        lgb.train(params, data, num_boost_round=4).save_model(str(self.root / "model.txt"))
        manifest = {
            "schema_version": 1, "model_id": "synthetic-test-only",
            "feature_schema": "depbee-features-v1", "feature_names": ["signal"],
            "positive_class": "malicious", "objective": "binary", "threshold": 0.5,
            "model_sha256": hashlib.sha256((self.root / "model.txt").read_bytes()).hexdigest(),
        }  # fmt: skip
        self.write(self.root / "manifest.json", manifest)
        for signal, expected in ((0.1, 0), (0.9, 1)):
            with self.subTest(signal=signal):
                self.backend.features = {"signal": signal, "obfChangedFileCount": 2}
                code, out, _ = self.run_check(
                    "example@1.1.0", "--model-dir", str(self.root), "--format", "json"
                )
                self.assertEqual(
                    (code, json.loads(out)["model_id"]), (expected, "synthetic-test-only")
                )


if __name__ == "__main__":
    unittest.main()
