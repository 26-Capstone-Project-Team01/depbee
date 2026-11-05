"""Synthetic tests for the extractor analyzer, baseline rule and Korean output.

No network access and no package code: feature-extractor is replaced by FakeBackend.
"""

import contextlib
import copy
import dataclasses
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
from test_registry import FakeRegistry, Response, serve_tarballs, sri, tarball_url, tgz
from test_workflow import FakePredictor, Fixture, package

from depbee.analysis import registry
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
        # A null new-version manifest means "not served", tested above; the rest must not crash.
        shapes = ("x", 5, 1.5, True, False, [], {}, ["dist"])
        cases = [("manifest", value) for value in shapes] + [
            ("dist", value) for value in (["tarball"], "x", 5, None, True, False, [])
        ] + [("no dist", None)]
        for version in ("1.0.1", "1.1.0"):  # baseline, new
            for label, value in cases + ([("manifest", None)] if version == "1.0.1" else []):
                with self.subTest(version=version, label=label, value=value):
                    doc = copy.deepcopy(self.doc)
                    if label == "manifest":
                        doc["versions"][version] = value
                    elif label == "dist":
                        doc["versions"][version]["dist"] = value
                    else:
                        del doc["versions"][version]["dist"]
                    artifact, backend = self.run_analyzer(FakeBackend(doc, new_json=self.new_json))
                    row = artifact["results"][0]
                    self.assertEqual(row["status"], "failed")
                    self.assertIn(f"Registry metadata of example@{version}", row["error"])
                    self.assertEqual(backend.calls, [])

    def test_malformed_packument_fails_the_scan_change_not_the_cli(self):
        # Before the check in packument(), these raised AttributeError out of the analyzer.
        cases = {
            "packument list": [], "packument text": "x", "packument number": 5,
            "packument null": None, "versions list": {**self.doc, "versions": []},
            "versions text": {**self.doc, "versions": "x"},
            "versions number": {**self.doc, "versions": 5},
            "no versions": {k: v for k, v in self.doc.items() if k != "versions"},
            "time list": {**self.doc, "time": ["1.1.0"]}, "time text": {**self.doc, "time": "x"},
            "time number": {**self.doc, "time": 5},
            "no time": {k: v for k, v in self.doc.items() if k != "time"},
        }  # fmt: skip
        for label, doc in cases.items():
            with self.subTest(label):
                backend = FakeBackend(doc)
                with mock.patch(
                    "depbee.analysis.extractor.FeatureExtractorBackend", return_value=backend
                ):
                    out, err = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        code = main(["scan", str(self.project), "--base-lock", str(self.base),
                                     "--extract", "--format", "json", "--no-cache"])  # fmt: skip
                row = json.loads(out.getvalue())["results"][0]
                self.assertEqual((code, err.getvalue()), (2, ""))
                self.assertEqual(row["reason"], "analysis_failed")
                self.assertRegex(row["detail"], r"\Anpm registry metadata for example "
                                 r"(is not a JSON object|lacks versions or time objects)\Z")
                self.assertEqual(backend.calls, [])

    def test_lockfile_scan_unpacks_only_checked_registry_tarballs(self):
        served = serve_tarballs(self.doc, "example")
        self.new["packages"]["node_modules/example"]["integrity"] = (
            self.doc["versions"]["1.1.0"]["dist"]["integrity"]
        )
        self.save_locks()
        baseline_url = tarball_url("example", "1.0.1")
        good = copy.deepcopy(served.files)

        def other_host(doc):
            doc["versions"]["1.0.1"]["dist"]["tarball"] = "https://evil.test/example-1.0.1.tgz"

        def redirected(_doc):
            served.files[baseline_url] = Response(good[baseline_url], "https://evil.test/x")

        def tampered(_doc):
            served.files[tarball_url("example", "1.1.0")] += b"x"

        for label, edit, error, opened in (
            ("checked", lambda d: None, None, 2),
            ("baseline URL on another host", other_host, "tarball URL is not", 0),
            ("redirected off the registry", redirected, "outside https://registry.npmjs.org", 1),
            ("new version tarball tampered", tampered, "does not match its sha512 integrity", 2),
        ):  # fmt: skip
            with self.subTest(label):
                doc, served.files, served.opened = copy.deepcopy(self.doc), dict(good), []
                edit(doc)
                backend = stand_in_backend(FakeBackend(doc).fetch_packument, [])
                with mock.patch("depbee.analysis.registry._open", served):
                    row = ExtractorAnalyzer(backend=backend).analyze(self.request())["results"][0]
                self.assertEqual(row["status"], "failed" if error else "complete")
                if error:
                    self.assertIn(error, row["error"])
                self.assertEqual(len(served.opened), opened)

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


@dataclasses.dataclass(frozen=True)
class Snapshot:
    """Stand-in for feature-extractor's PackageVersionSnapshot, also a frozen dataclass."""

    package_json: dict
    source_dir: Path | None = None


def stand_in_backend(fetch, snapshots):
    """Real FeatureExtractorBackend and depbee download; feature-extractor's build_snapshot and
    build_row are stand-ins. build_snapshot reads versions[version] as c24761d loader.py:55-56
    does. build_row asks for source, as c24761d build_row does for the default (obfuscation)
    extractors, and reads both unpacked package.json files. Tarballs come from a FakeRegistry."""

    def build_snapshot(packument, package, version):
        snapshots.append(packument)
        return Snapshot(packument["versions"][version])

    def build_row(name, old, new, label, extractors, *, old_source, new_source):
        for source, version in ((old_source, old), (new_source, new)):
            snapshot = source.get_snapshot(name, version, include_source=True)
            unpacked = json.loads((snapshot.source_dir / "package.json").read_text("utf-8"))
            assert unpacked["version"] == version
        return SimpleNamespace(features={"signal": 0.9, "obfChangedFileCount": 2})

    backend = FeatureExtractorBackend.__new__(FeatureExtractorBackend)
    backend.errors, backend.version = (registry.RegistryError,), "stand-in"
    backend.fetch_packument = fetch
    backend._build_snapshot, backend._build_row = build_snapshot, build_row
    backend._extractors, backend._local_source = [], None
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
            "manifest number": broken(lambda d: d["versions"].update({"1.1.0": 5})),
            "manifest bool": broken(lambda d: d["versions"].update({"1.1.0": True})),
            "dist null": broken(lambda d: d["versions"]["1.1.0"].update(dist=None)),
            "dist number": broken(lambda d: d["versions"]["1.1.0"].update(dist=5)),
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
        # The analyzer checks the packument's shape when it is fetched, before the request.
        for doc in ([], {**self.doc, "time": []}):
            with self.subTest(doc=type(doc).__name__):
                self.backend.doc = doc
                code, out, err = self.run_check("example@1.1.0", "--format", "json")
                self.assertEqual((code, out), (2, ""))
                self.assertIn("npm registry metadata for example ", json.loads(err)["error"])

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

    def test_output_conflict_is_refused_before_any_registry_access(self):
        output = self.root / "taken.json"
        output.write_bytes(b"keep")
        for fmt in ("text", "json", "markdown"):
            with self.subTest(fmt):
                code, out, err = self.run_check("example@1.1.0", "--format", fmt,
                                                "--output", str(output))  # fmt: skip
                self.assertEqual((code, out), (2, ""))
                # One error line and no progress: nothing was fetched or extracted.
                self.assertEqual(json.loads(err)["error"],
                                 str(FileExistsError(17, os.strerror(17), str(output))))
                self.assertEqual((self.backend.fetched, self.backend.calls), ([], []))
        with mock.patch("depbee.analysis.extractor.ExtractorAnalyzer") as extractor:
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                code = main(["scan", str(self.project), "--base-lock", str(self.base),
                             "--extract", "--output", str(output)])  # fmt: skip
        self.assertEqual((code, json.loads(err.getvalue())["status"]), (2, "error"))
        extractor.assert_not_called()
        self.assertEqual(output.read_bytes(), b"keep")

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
        with mock.patch("time.monotonic", return_value=5.0):  # elapsed_seconds 0.0 in both
            first = check_package("example", "1.1.0")
            self.assertEqual(check_package("example", "1.1.0"), first)
        request = build_package_request("example", "1.1.0", self.doc)
        self.assertEqual(first["request_id"], request["request_id"])
        lockfile = scan_project(self.project, self.base)
        self.assertNotIn("input_kind", lockfile)
        self.assertEqual(lockfile["scope"], LOCKFILE_SCOPE)

    def test_real_backend_uses_the_checked_packument_and_verified_tarballs(self):
        snapshots = []
        served = serve_tarballs(self.doc, "example")
        backend = stand_in_backend(self.backend.fetch_packument, snapshots)
        loader = mock.patch(
            "depbee.analysis.extractor.FeatureExtractorBackend", return_value=backend
        )
        with loader, mock.patch("depbee.analysis.registry._open", served):
            report = check_package("example", "1.1.0", no_cache=True)
        self.assertEqual(report["results"][0]["reason"], "model_missing")  # analysis complete
        self.assertEqual(self.backend.fetched, ["example"])  # one metadata read in total
        self.assertEqual(len(snapshots), 2)  # old and new, both from the checked document
        # Only the two compared versions go to the extraction step, as the checked manifests.
        for snapshot in snapshots:
            self.assertEqual(set(snapshot["versions"]), {"1.0.1", "1.1.0"})
            self.assertTrue(all(snapshot["versions"][v] is self.doc["versions"][v]
                                for v in snapshot["versions"]))  # fmt: skip
        self.assertEqual(served.opened, [tarball_url("example", v) for v in ("1.0.1", "1.1.0")])
        # Bytes that do not match the registry integrity are never unpacked.
        served.files[tarball_url("example", "1.0.1")] += b"tampered"
        with loader, mock.patch("depbee.analysis.registry._open", served):
            row = check_package("example", "1.1.0", no_cache=True)["results"][0]
        self.assertEqual(row["reason"], "analysis_failed")
        self.assertEqual(row["detail"], "example@1.0.1 tarball does not match its sha512 integrity")

    def test_malformed_baseline_stops_before_the_pinned_loader(self):
        # Before the check, c24761d loader.py:100 raised AttributeError: a traceback and exit 1.
        def baseline_dist_list(doc):
            doc["versions"]["1.0.1"]["dist"] = [doc["versions"]["1.0.1"]["dist"]]

        def baseline_dist(value):
            return lambda d: d["versions"]["1.0.1"].update(dist=value)

        no_object = "Registry metadata of example@1.0.1 is not an object"
        no_dist = "Registry metadata of example@1.0.1 has no dist object"
        for label, edit, detail in (
            ("baseline manifest is a string", lambda d: d["versions"].update({"1.0.1": "x"}),
             no_object),
            ("baseline dist is a list", baseline_dist_list, no_dist),
            *((f"baseline manifest is {value!r}",
               lambda d, v=value: d["versions"].update({"1.0.1": v}), no_object)
              for value in (5, 1.5, None, True, False, [])),
            *((f"baseline dist is {value!r}", baseline_dist(value), no_dist)
              for value in ("x", 5, None, True, False)),
        ):  # fmt: skip
            with self.subTest(label):
                self.backend.doc = copy.deepcopy(self.doc)
                edit(self.backend.doc)
                snapshots, served = [], serve_tarballs(copy.deepcopy(self.doc), "example")
                backend = stand_in_backend(self.backend.fetch_packument, snapshots)
                with mock.patch(
                    "depbee.analysis.extractor.FeatureExtractorBackend", return_value=backend
                ), mock.patch("depbee.analysis.registry._open", served):
                    code, out, err = self.run_check("example@1.1.0", "--format", "json")
                report = json.loads(out)
                self.assertEqual((code, err, report["exit_code"]), (2, "", 2))
                row = report["results"][0]
                self.assertEqual((row["reason"], row["detail"]), ("analysis_failed", detail))
                self.assertEqual((snapshots, served.opened), ([], []))  # nothing called

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


@unittest.skipUnless(
    importlib.util.find_spec("feature_extractor"), "Install .[extract] for the pinned loader tests"
)
class PinnedLoaderTests(Fixture):
    """The installed, pinned feature-extractor (c24761d) behind the real backend: its loader,
    sources, pipeline and extractors run on synthetic tarballs. Only depbee's registry access is a
    FakeRegistry, and feature-extractor's own requests.get fails if it is ever called, so a pin
    change that fetches again or reads another document breaks these tests (PR #7 nit 3)."""

    def setUp(self):
        super().setUp()
        self.doc = packument({"1.0.0": "2026-01-01T00:00:00Z", "1.0.1": "2026-01-02T00:00:00Z",
                              "1.1.0": "2026-01-03T00:00:00Z"})  # fmt: skip
        # The registry manifest adds an install script that the tarball's package.json lacks, so
        # installScriptAdded shows which document feature-extractor read.
        self.doc["versions"]["1.1.0"]["scripts"] = {"postinstall": "node setup.js"}
        self.served = FakeRegistry()
        for version in self.doc["versions"]:
            files = {"package/package.json": json.dumps({"name": "example",
                                                         "version": version}).encode(),
                     "package/index.js": b"module.exports = 1;\n"}  # fmt: skip
            if version == "1.1.0":
                files["package/lib/added.js"] = b"exports.added = true;\n"
            data = tgz(files)
            self.doc["versions"][version]["dist"]["integrity"] = sri(data)
            self.served.files[tarball_url("example", version)] = data
        self.packument_url = "https://registry.npmjs.org/example"
        self.served.files[self.packument_url] = json.dumps(self.doc).encode()
        self.new["packages"]["node_modules/example"]["integrity"] = (
            self.doc["versions"]["1.1.0"]["dist"]["integrity"]
        )
        self.save_locks()
        self.own_requests = mock.Mock(side_effect=AssertionError("feature-extractor fetched"))
        for patcher in (mock.patch("depbee.analysis.registry._open", self.served),
                        mock.patch("feature_extractor.core.loader.requests.get",
                                   self.own_requests)):  # fmt: skip
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_one_metadata_read_and_the_checked_document_for_both_snapshots(self):
        from feature_extractor.core.loader import build_snapshot

        self.assertIs(FeatureExtractorBackend()._build_snapshot, build_snapshot)
        for label, run in (
            ("check", lambda: check_package("example", "1.1.0", no_cache=True)),
            ("scan", lambda: scan_project(self.project, self.base, extract=True, no_cache=True)),
        ):
            with self.subTest(label):
                self.served.opened = []
                row = run()["results"][0]
                self.assertEqual(row["reason"], "model_missing")  # analysis complete
                self.assertEqual(self.served.opened, [self.packument_url,
                                                      tarball_url("example", "1.0.1"),
                                                      tarball_url("example", "1.1.0")])  # fmt: skip
                self.own_requests.assert_not_called()

        analyzer = ExtractorAnalyzer()
        result = analyzer.analyze(self.request())["results"][0]
        features = result["features"]
        self.assertEqual(len(features), 29)
        self.assertEqual(features["installScriptAdded"], True)  # from the registry manifest
        self.assertEqual(features["obfChangedFileCount"], 1)  # from the unpacked tarballs
        self.assertIn("설치 스크립트 추가: postinstall = node setup.js", result["evidence"])

    def test_malformed_manifests_stop_before_the_pinned_loader(self):
        # Before f268b4a, c24761d loader.py:100 raised AttributeError here (traceback, exit 1).
        for label, edit in (
            ("baseline manifest is a string", lambda d: d["versions"].update({"1.0.1": "x"})),
            ("baseline dist is a list", lambda d: d["versions"]["1.0.1"].update(dist=["x"])),
            ("baseline dist is null", lambda d: d["versions"]["1.0.1"].update(dist=None)),
            ("baseline manifest is a number", lambda d: d["versions"].update({"1.0.1": 5})),
            ("versions is a list", lambda d: d.update(versions=[])),
            ("time is text", lambda d: d.update(time="x")),
        ):
            with self.subTest(label):
                doc = copy.deepcopy(self.doc)
                edit(doc)
                self.served.files[self.packument_url] = json.dumps(doc).encode()
                self.served.opened = []
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = main(["scan", str(self.project), "--base-lock", str(self.base),
                                 "--extract", "--format", "json", "--no-cache"])  # fmt: skip
                self.assertEqual((code, err.getvalue()), (2, ""))
                self.assertEqual(json.loads(out.getvalue())["results"][0]["reason"],
                                 "analysis_failed")  # fmt: skip
                self.assertEqual(self.served.opened, [self.packument_url])  # no tarball
                self.own_requests.assert_not_called()

    def test_local_copy_with_the_pinned_local_source(self):
        copy_root = self.root / "copies" / "example-1.1.0" / "package"
        copy_root.mkdir(parents=True)
        (copy_root / "package.json").write_text(json.dumps({"name": "example",
                                                            "version": "1.1.0"}), "utf-8")
        (copy_root / "index.js").write_text("module.exports = 2;\n", "utf-8")
        analyzer = ExtractorAnalyzer({("example", "1.1.0"): self.root / "copies"})
        row = analyzer.analyze(self.request())["results"][0]
        self.assertEqual(row["status"], "complete")
        self.assertEqual(row["features"]["installScriptAdded"], False)  # the copy's package.json
        self.assertIn("새 버전을 로컬 사본에서 읽음(registry 무결성 확인 안 함)", row["evidence"])
        # Only the baseline tarball came from the registry.
        self.assertEqual(self.served.opened, [self.packument_url, tarball_url("example", "1.0.1")])
        self.own_requests.assert_not_called()


if __name__ == "__main__":
    unittest.main()
