"""Feature cache, feature-extractor provenance and elapsed times (DEV-02e).

Synthetic data only: feature-extractor is FakeBackend, there is no network and no package code.
"""

import base64
import contextlib
import copy
import hashlib
import importlib.metadata
import io
import itertools
import json
import math
import threading
from pathlib import Path
from unittest import mock

from test_extract import FakeBackend, PackagePredictor, packument
from test_workflow import Fixture, package

from depbee.analysis import cache
from depbee.analysis.extractor import _installed_identity
from depbee.cli import main
from depbee.contracts import GuardError, OutOfScopeError, elapsed_since
from depbee.service import check_package, scan_project

EXTRACTOR = {"commit": "c" * 40, "url": "https://example.test/fx", "files_sha256": "f" * 64,
             "python": "3.13.5"}  # fmt: skip
MODEL = {"model_sha256": "a" * 64, "manifest_sha256": "b" * 64}


class Model(PackagePredictor):
    """FakePredictor with the hashes and input check a verified LightGBMPredictor exposes."""

    def __init__(self, identity=MODEL):
        self.identity = dict(identity)

    def encode(self, features):
        value = features.get("signal")
        if value == "unseen":
            raise OutOfScopeError("signal='unseen' is not a category the model was trained on")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise GuardError("signal must be a number")
        return [float(value)]

    def predict(self, features):
        self.encode(features)  # as LightGBMPredictor: an unseen category is out of scope
        return features["signal"]


class CacheFixture(Fixture):
    def setUp(self):
        super().setUp()
        self.doc = packument(
            {
                "1.0.0": "2026-01-01T00:00:00Z",
                "1.0.1": "2026-01-02T00:00:00Z",
                "1.1.0": "2026-01-03T00:00:00Z",
            }
        )
        self.backend = FakeBackend(self.doc, features={"signal": 0.2, "obfChangedFileCount": 2})
        self.backend.identity = dict(EXTRACTOR)
        self.model = Model()
        self.cache_dir = self.root / "cache"
        for patcher in (
            mock.patch("depbee.analysis.extractor.FeatureExtractorBackend",
                       side_effect=lambda: self.backend),
            # Read at call time so that a test can swap the model.
            mock.patch("depbee.service.LightGBMPredictor", side_effect=lambda _: self.model),
        ):  # fmt: skip
            patcher.start()
            self.addCleanup(patcher.stop)

    def scan(self, **options):
        options.setdefault("cache_dir", self.cache_dir)
        options.setdefault("model_dir", Path("m"))
        return scan_project(self.project, self.base, extract=True, **options)

    def entries(self):
        return sorted(self.cache_dir.glob("*.json")) if self.cache_dir.is_dir() else []

    @staticmethod
    def verdict(report):
        """The report without the fields that may differ between runs (times and cache_hit)."""
        rows = [{k: v for k, v in r.items() if k not in ("elapsed_seconds", "cache_hit")}
                for r in report["results"]]  # fmt: skip
        return {**{k: v for k, v in report.items() if k != "elapsed_seconds"}, "results": rows}


class CacheTests(CacheFixture):
    def test_cold_then_warm_reuses_features_and_rebuilds_evidence(self):
        cold = self.scan()
        self.assertEqual(len(self.backend.calls), 1)
        self.assertEqual(len(self.entries()), 1)
        warm = self.scan()
        self.assertEqual(len(self.backend.calls), 1)  # not extracted again
        self.assertEqual([r["cache_hit"] for r in (cold, warm) for r in r["results"]],
                         [False, True])  # fmt: skip
        self.assertEqual(self.verdict(warm), self.verdict(cold))
        self.assertIn("lockfile의 이전 버전은 1.0.0", warm["results"][0]["evidence"])
        # Another request, location and previous version still reuse the features, while the
        # evidence and ids are rebuilt for the current request.
        self.old["packages"] = {"node_modules/a/node_modules/example": package("1.0.1")}
        self.new["packages"] = {"node_modules/a/node_modules/example": package("1.1.0")}
        self.save_locks()
        moved = self.scan()["results"][0]
        self.assertEqual((moved["cache_hit"], len(self.backend.calls)), (True, 1))
        self.assertEqual(moved["location"], "node_modules/a/node_modules/example")
        self.assertNotEqual(moved["change_id"], cold["results"][0]["change_id"])
        self.assertNotIn("lockfile의 이전 버전", "\n".join(moved["evidence"]))
        self.assertEqual(moved["features"], cold["results"][0]["features"])

    def test_every_input_of_the_features_is_part_of_the_key(self):
        def edit_doc(edit):
            def apply():
                edit(self.doc)

            return apply

        def set_attr(target, name, value):
            return lambda: setattr(target, name, value)

        edits = {
            "model file": set_attr(self, "model", Model({**MODEL, "model_sha256": "d" * 64})),
            "model manifest": set_attr(self, "model", Model({**MODEL, "manifest_sha256": "e" * 64})),
            "extractor": set_attr(self.backend, "identity", {**EXTRACTOR, "commit": "0" * 40}),
            "baseline integrity": edit_doc(
                lambda d: d["versions"]["1.0.1"]["dist"].update(integrity="sha512-other")
            ),
            "new manifest": edit_doc(lambda d: d["versions"]["1.1.0"].update(description="x")),
            "baseline manifest": edit_doc(lambda d: d["versions"]["1.0.1"].update(scripts={})),
            "publish time": edit_doc(lambda d: d["time"].update({"1.0.1": "2026-01-02T01:00:00Z"})),
            "baseline": edit_doc(lambda d: (d["time"].update({"1.0.2": "2026-01-02T12:00:00Z"}),
                                            d["versions"].update({"1.0.2": copy.deepcopy(
                                                d["versions"]["1.0.1"])}))),
        }  # fmt: skip
        pristine = (copy.deepcopy(self.doc), self.model, dict(self.backend.identity))
        for label, edit in edits.items():
            with self.subTest(label):
                self.doc.clear()
                self.doc.update(copy.deepcopy(pristine[0]))
                self.model, self.backend.identity = pristine[1], dict(pristine[2])
                self.cache_dir = self.root / f"cache-{len(self.backend.calls)}"
                self.scan()
                calls = len(self.backend.calls)
                self.assertTrue(self.scan()["results"][0]["cache_hit"])
                edit()
                row = self.scan()["results"][0]
                self.assertEqual((row["cache_hit"], len(self.backend.calls)), (False, calls + 1))
                self.assertEqual(len(self.entries()), 2)

    def test_uncached_paths_read_and_write_nothing(self):
        self.scan()
        self.assertEqual(len(self.entries()), 1)
        for label, options, setup in (
            ("no_cache", {"no_cache": True}, None),
            ("no model", {"model_dir": None}, None),
            ("unverified feature-extractor", {}, lambda: setattr(self.backend, "identity", None)),
        ):
            with self.subTest(label):
                if setup:
                    setup()
                calls, before = len(self.backend.calls), self.entries()[0].read_bytes()
                rows = self.scan(**options)["results"]
                self.assertEqual(len(self.backend.calls), calls + 1)  # not read
                self.assertFalse(rows[0]["cache_hit"])
                self.assertEqual([p.read_bytes() for p in self.entries()], [before])  # not written
        # A local copy is never cached; neither is an --analysis file (no extraction at all).
        self.backend.identity = dict(EXTRACTOR)
        (self.root / "copy").mkdir()
        for _ in range(2):
            row = self.scan(local_root=self.root, local_sources=["example@1.1.0=copy"])
            self.assertFalse(row["results"][0]["cache_hit"])
        self.assertEqual(len(self.entries()), 1)
        self.assertEqual(self.backend.calls[-1][3], (self.root / "copy").resolve())
        self.adapter()
        report = scan_project(self.project, self.base, analysis=self.root / "analysis.json",
                              cache_dir=self.cache_dir)  # fmt: skip
        self.assertNotIn("elapsed_seconds", report)
        self.assertNotIn("cache_hit", report["results"][0])

    def test_failed_extraction_is_retried_not_cached(self):
        with mock.patch.object(self.backend, "extract", side_effect=GuardError("synthetic")):
            row = self.scan()["results"][0]
        self.assertEqual((row["reason"], row["cache_hit"], self.entries()), ("analysis_failed",
                                                                             False, []))  # fmt: skip
        self.assertIsNotNone(row["elapsed_seconds"])  # a failed row is still timed
        self.assertEqual(self.scan()["results"][0]["status"], "not_flagged")
        self.assertEqual((len(self.backend.calls), len(self.entries())), (1, 1))

    def test_damaged_or_foreign_entries_are_misses(self):
        self.scan()
        [entry] = self.entries()
        good = json.loads(entry.read_bytes())
        damaged = {
            "truncated": entry.read_bytes()[:-10],
            "not utf-8": b"\xff\xfe",
            "duplicate key": b'{"format": 1, "format": 1}',
            "array": b"[]",
            "other format": json.dumps({**good, "format": 2}).encode(),
            "other key": json.dumps({**good, "key": {**good["key"], "version": "9.9.9"}}).encode(),
            "extra field": json.dumps({**good, "note": 1}).encode(),
            "no features": json.dumps({**good, "features": {}}).encode(),
            "NaN feature": json.dumps({**good, "features": {"signal": math.nan}}).encode(),
            "infinite feature": json.dumps({**good, "features": {"signal": 12345.5}})
            .replace("12345.5", "1e999").encode(),
            "object feature": json.dumps({**good, "features": {"signal": {"x": 1}}}).encode(),
            "oversized": entry.read_bytes() + b" " * cache.MAX_ENTRY_BYTES,
            # Valid JSON values the model cannot take (checked with the model's encode).
            "model feature missing": json.dumps({**good, "features": {"other": 1}}).encode(),
            "text for a number": json.dumps({**good, "features": {"signal": "x"}}).encode(),
            "bool for a number": json.dumps({**good, "features": {"signal": True}}).encode(),
        }
        for label, raw in damaged.items():
            with self.subTest(label):
                entry.write_bytes(raw)
                calls = len(self.backend.calls)
                row = self.scan()["results"][0]
                self.assertEqual((row["cache_hit"], len(self.backend.calls)), (False, calls + 1))
                self.assertEqual(json.loads(entry.read_bytes()), good)  # rewritten from scratch

    def test_only_features_the_model_takes_are_stored(self):
        self.backend.features = {"signal": "x", "obfChangedFileCount": 2}  # not a number
        for _ in range(2):
            row = self.scan()["results"][0]
            self.assertEqual((row["reason"], row["cache_hit"]), ("inference_failed", False))
        self.assertEqual((len(self.backend.calls), self.entries()), (2, []))
        # Unsupported (an unseen category) is not cached either; the verdict itself is unchanged.
        self.backend.features = {"signal": "unseen", "obfChangedFileCount": 2}
        rows = [self.scan()["results"][0] for _ in range(2)]
        self.assertEqual([(r["reason"], r["cache_hit"]) for r in rows],
                         [("out_of_training_scope", False)] * 2)  # fmt: skip
        self.assertEqual((len(self.backend.calls), self.entries()), (4, []))

    def test_write_failures_only_skip_caching(self):
        self.cache_dir.write_bytes(b"not a directory")
        self.assertEqual(self.scan()["results"][0]["status"], "not_flagged")
        self.cache_dir.unlink()
        with mock.patch("depbee.analysis.cache.os.replace", side_effect=PermissionError("busy")):
            self.assertEqual(self.scan()["results"][0]["status"], "not_flagged")
        self.assertEqual(list(self.cache_dir.iterdir()), [])  # temporary file removed

    def test_concurrent_stores_never_expose_a_partial_entry(self):
        key = {"package": "example", "pad": "x" * 200_000}
        features = {"signal": 0.5, "text": "y" * 100_000}
        seen, stop = [], threading.Event()

        def write():
            for _ in range(20):
                cache.store(self.cache_dir, key, features)

        def read():
            while not stop.is_set():
                seen.append(cache.load(self.cache_dir, key))

        readers = [threading.Thread(target=read) for _ in range(4)]
        writers = [threading.Thread(target=write) for _ in range(4)]
        for thread in readers + writers:
            thread.start()
        for thread in writers:
            thread.join()
        stop.set()
        for thread in readers:
            thread.join()
        self.assertTrue(seen)
        self.assertTrue(all(value in (None, features) for value in seen))
        self.assertEqual(cache.load(self.cache_dir, key), features)
        self.assertEqual([p.name.startswith(".tmp-") for p in self.cache_dir.iterdir()], [False])


class TimeTests(CacheFixture):
    def test_times_with_a_fixed_clock(self):
        # Removed, non-registry, failed and complete rows in one request.
        self.old["packages"]["node_modules/gone"] = package()
        self.new["packages"]["node_modules/local"] = {**package(), "resolved": "file:x.tgz"}
        self.new["packages"]["node_modules/broken"] = package("2.0.0")
        self.save_locks()
        clock = itertools.count(100.0, 0.25)
        with mock.patch("time.monotonic", side_effect=lambda: next(clock)) as monotonic:
            report = self.scan()
        rows = {r["location"]: r for r in report["results"]}
        # Each analyzed change reads the clock twice in a row; the whole call spans every read.
        self.assertEqual(report["elapsed_seconds"], 0.25 * (monotonic.call_count - 1))
        self.assertEqual(list(report)[-2:], ["elapsed_seconds", "results"])
        for location, (seconds, hit, reason) in {
            "node_modules/example": (0.25, False, None),
            "node_modules/broken": (0.25, False, "analysis_failed"),  # 2.0.0 is not served
            "node_modules/local": (None, False, "unsupported_registry_source"),
            "node_modules/gone": (None, False, "not_installed_in_head"),
        }.items():
            with self.subTest(location):
                row = rows[location]
                self.assertEqual((row["elapsed_seconds"], row["cache_hit"], row.get("reason")),
                                 (seconds, hit, reason))  # fmt: skip
                self.assertEqual(list(row)[-2:], ["elapsed_seconds", "cache_hit"])

    def test_elapsed_is_finite_and_never_negative(self):
        for now, expected in ((10.0004, 0.0), (9.0, 0.0), (math.nan, 0.0), (math.inf, 0.0),
                              (12.3456, 2.346)):  # fmt: skip
            with self.subTest(now=now), mock.patch("time.monotonic", return_value=now):
                self.assertEqual(elapsed_since(10.0), expected)

    def test_check_counts_its_metadata_read_in_the_result_time(self):
        clock = itertools.count(100.0, 0.25)
        with mock.patch("time.monotonic", side_effect=lambda: next(clock)):
            report = check_package("example", "1.1.0", model_dir=Path("m"), no_cache=True)
        # Clock reads: call start; metadata before and after; analysis before and after; end.
        self.assertEqual(report["results"][0]["elapsed_seconds"], 0.5)
        self.assertEqual(report["elapsed_seconds"], 1.25)

    def test_check_reports_times_and_reuses_the_cache(self):
        first = check_package("example", "1.1.0", model_dir=Path("m"), cache_dir=self.cache_dir)
        second = check_package("example", "1.1.0", model_dir=Path("m"), cache_dir=self.cache_dir)
        self.assertEqual([r["results"][0]["cache_hit"] for r in (first, second)], [False, True])
        self.assertEqual(self.verdict(first), self.verdict(second))
        self.assertGreaterEqual(second["elapsed_seconds"], 0.0)
        self.assertEqual(self.backend.fetched, ["example", "example"])  # metadata still read

    def test_cli_options_and_text(self):
        def cli(*args):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["scan", str(self.project), "--base-lock", str(self.base), *args])
            return code, out.getvalue(), err.getvalue()

        extract = ("--extract", "--model-dir", "m", "--cache-dir", str(self.cache_dir))
        self.assertEqual(cli(*extract)[0], 0)
        code, out, _ = cli(*extract)
        self.assertEqual(code, 0)
        self.assertRegex(out, r"\n소요 시간: \d+\.\d{3}초\n")
        self.assertRegex(out, r"\n  분석 시간: \d+\.\d{3}초 \(캐시한 feature 사용\)\n")
        code, out, _ = cli("--extract", "--model-dir", "m", "--no-cache", "--format", "json")
        report = json.loads(out)
        self.assertEqual((code, report["results"][0]["cache_hit"]), (0, False))
        self.assertIsInstance(report["elapsed_seconds"], float)
        code, out, _ = cli()  # no extraction: no time lines
        self.assertNotIn("시간", out)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stop:
            main(["check", "example@1.1.0", "--no-cache", "--cache-dir", "x"])
        self.assertEqual(stop.exception.code, 2)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


class ProvenanceTests(Fixture):
    """_installed_identity with a synthetic installed distribution (importlib.metadata mocked)."""

    COMMIT = "1" * 40
    URL = "https://github.com/example/feature-extractor"
    CONTENT = b"x = 1\n"

    def dist(self, direct, content=CONTENT, recorded=None):
        site = self.root / "site"
        (site / "feature_extractor").mkdir(parents=True, exist_ok=True)
        (site / "feature_extractor" / "core.py").write_bytes(content)
        file = importlib.metadata.PackagePath("feature_extractor/core.py")
        file.hash = importlib.metadata.FileHash(recorded or f"sha256={b64(self.CONTENT)}")
        compiled = importlib.metadata.PackagePath("feature_extractor/core.pyc")
        compiled.hash = None
        return mock.Mock(
            files=[file, compiled],
            locate_file=lambda f: site / f,
            read_text=lambda name: None if direct is None else json.dumps(direct),
        )

    def identity(self, direct, pins=None, **kwargs):
        pins = pins or [f"feature-extractor @ git+{self.URL}@{self.COMMIT} ; extra == \"extract\""]
        with (
            mock.patch("importlib.metadata.distribution", return_value=self.dist(direct, **kwargs)),
            mock.patch("importlib.metadata.requires", return_value=pins),
        ):
            return _installed_identity()

    def test_only_the_pinned_git_commit_unchanged_is_verified(self):
        good = {"url": self.URL, "vcs_info": {"vcs": "git", "commit_id": self.COMMIT}}
        identity = self.identity(good)
        self.assertEqual((identity["commit"], identity["url"]), (self.COMMIT, self.URL))
        for label, direct, kwargs in (
            ("editable", {"url": "file:///x", "dir_info": {"editable": True}}, {}),
            ("local folder", {"url": "file:///x", "dir_info": {}}, {}),
            ("no direct_url.json", None, {}),
            ("other commit", {**good, "vcs_info": {"vcs": "git", "commit_id": "2" * 40}}, {}),
            ("other url", {**good, "url": "https://evil.test/feature-extractor"}, {}),
            ("changed after install", good, {"content": b"x = 2\n"}),
            ("other recorded hash", good, {"recorded": "sha256=x"}),
            ("not sha256", good, {"recorded": f"md5={b64(self.CONTENT)}"}),
        ):
            with self.subTest(label):
                self.assertIsNone(self.identity(direct, **kwargs))
        self.assertIsNone(self.identity(good, pins=["lightgbm<5"]))
        with mock.patch("importlib.metadata.distribution",
                        side_effect=importlib.metadata.PackageNotFoundError):  # fmt: skip
            self.assertIsNone(_installed_identity())
