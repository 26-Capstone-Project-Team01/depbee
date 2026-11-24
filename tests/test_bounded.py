"""The per-change time budget and its child processes (analysis.bounded), with real children.

Each child job (bounded_jobs.py) blocks network connections and uses its own synthetic I/O in
the child; nothing reaches a registry. Slow jobs write heartbeats, so the tests can see that the
killed child's work and I/O stopped, not only that the caller got an error.
"""

import contextlib
import functools
import importlib.util
import json
import subprocess
import time
import unittest
from pathlib import Path
from unittest import mock

import bounded_jobs
from test_cache import EXTRACTOR, CacheFixture, Model
from test_extract import FakeBackend, packument
from test_registry import package_tgz, sri, tarball_url, tgz
from test_workflow import Fixture, package

from depbee.analysis import bounded, cache
from depbee.analysis.extractor import FeatureExtractorBackend
from depbee.service import check_package, scan_project

REAL_POPEN = subprocess.Popen


class BoundedTests(Fixture):
    bounded_in_process = False  # real child processes

    def setUp(self):
        super().setUp()
        self.children = []

        def popen(*args, **kwargs):
            self.children.append(REAL_POPEN(*args, **kwargs))
            return self.children[-1]

        patcher = mock.patch("depbee.analysis.bounded.subprocess.Popen", side_effect=popen)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.heartbeat = self.root / "heartbeat.txt"

    def limit(self, seconds):
        return mock.patch.object(bounded, "ANALYSIS_SECONDS", seconds)

    def assert_stopped(self):
        """Every child has exited, and the killed work no longer advances."""
        self.assertTrue(self.children)
        self.assertTrue(all(child.poll() is not None for child in self.children))
        before = self.heartbeat.read_bytes()  # the job was working when it was killed
        self.assertTrue(before)
        time.sleep(0.4)  # a live job beats every 0.05 s
        self.assertEqual(self.heartbeat.read_bytes(), before)

    def test_results_and_errors_cross_the_boundary(self):
        self.assertEqual(bounded.run(bounded_jobs.sleep_then, (0, {"a": [1, None, 1.5]})),
                         {"a": [1, None, 1.5]})  # fmt: skip
        self.assertEqual(bounded.run(bounded_jobs.sleep_then, (0, b"\x00raw")), b"\x00raw")
        with self.assertRaisesRegex(bounded.StepError, r"\Asynthetic failure\Z"):
            bounded.run(bounded_jobs.fail, ("synthetic failure",))
        with self.assertRaisesRegex(bounded.StepError, r"ended without a result \(exit 3\)"):
            bounded.run(bounded_jobs.crash, (3,))
        self.assertEqual(len(self.children), 4)
        self.assertTrue(all(child.poll() is not None for child in self.children))

    def test_stuck_download_is_killed_with_its_connection(self):
        for label, opening in (("opening, headers or redirects", True), ("trickling body", False)):
            with self.subTest(label), self.limit(1.0):
                self.heartbeat.write_bytes(b"")
                began = time.monotonic()
                with self.assertRaisesRegex(bounded.TimeLimitError, "within 1.0 s"):
                    bounded.run(bounded_jobs.stuck_download, (str(self.heartbeat), opening))
                self.assertLess(time.monotonic() - began, 5)
                self.assert_stopped()

    def test_slow_unpacking_is_killed(self):
        target = self.root / "unpack"
        target.mkdir()
        data = package_tgz("example", "1.0.0")
        with self.limit(1.0), self.assertRaises(bounded.TimeLimitError):
            bounded.run(bounded_jobs.slow_unpack, (str(self.heartbeat), data, str(target)))
        self.assert_stopped()
        self.assertEqual(list(target.iterdir()), [])  # it never got to write a file

    def stand_in(self, row):
        """The real FeatureExtractorBackend.extract and _extract_here; only depbee-analyzer's
        build_snapshot and build_row are stand-ins (module functions, so they cross by pickle)."""
        backend = FeatureExtractorBackend.__new__(FeatureExtractorBackend)
        backend.errors = (bounded.StepError, bounded.TimeLimitError)
        backend.version, backend.identity, backend.ruleset_version = "stand-in", None, None
        backend._build_snapshot, backend._build_row = bounded_jobs.snapshot, row
        backend._extractors, backend._local_source = [], None
        return backend

    def doc(self):
        doc = packument({"1.0.1": "2026-01-02T00:00:00Z", "1.1.0": "2026-01-03T00:00:00Z"})
        doc["versions"]["1.1.0"]["heartbeat"] = str(self.heartbeat)
        return doc

    def test_feature_extraction_is_killed_and_its_work_folder_removed(self):
        backend = self.stand_in(bounded_jobs.slow_row)
        with self.limit(1.0), bounded.budget(), self.assertRaises(bounded.TimeLimitError):
            backend.extract("example", "1.0.1", "1.1.0", self.doc(), None)
        self.assert_stopped()
        self.assertEqual(list(self.root.glob("depbee_src_*")), [])
        # Within the budget the same path returns the child's features.
        quick = self.stand_in(bounded_jobs.quick_row)
        features, new_json, found = quick.extract("example", "1.0.1", "1.1.0", self.doc(), None)
        self.assertEqual(features, {"signal": 0.2, "obfChangedFileCount": 0, "name": "example"})
        self.assertIsNone(found)  # a backend without a ruleset scans no rules
        self.assertEqual(new_json["version"], "1.1.0")

    def test_one_budget_is_shared_by_the_steps_of_a_change(self):
        # Real children and clocks. Whether a step starts once the budget is spent is decided
        # below with a fixed clock: subprocess times the child on time.monotonic, which can end
        # its wait before bounded._clock reaches the deadline (PR #8 CI, Windows, Python 3.11).
        with self.limit(3.0), bounded.budget():
            self.assertEqual(bounded.run(bounded_jobs.sleep_then, (1.5, "first step")),
                             "first step")  # fmt: skip
            began = time.monotonic()
            with self.assertRaises(bounded.TimeLimitError):
                bounded.run(bounded_jobs.stuck_download, (str(self.heartbeat), True))
            self.assertLess(time.monotonic() - began, 2.5)  # what was left, not a fresh 3 s
        self.assertEqual(len(self.children), 2)
        self.assert_stopped()
        # A new budget (the next change) starts afresh.
        with self.limit(3.0), bounded.budget():
            self.assertIsNone(bounded.run(bounded_jobs.sleep_then, (0, None)))

    def test_a_spent_budget_starts_no_child_and_a_nested_budget_keeps_its_deadline(self):
        # bounded._clock is fixed and Popen gives a child that answers at once, so only the
        # deadline decides: run() needs time left (> 0), check() refuses once it has passed.
        now, children = [1000.0], []

        class Child:
            def __init__(self, *args, **kwargs):
                children.append(self)

            def communicate(self, payload=None, timeout=None):
                self.timeout = timeout
                return b'J"done"', b""

            def poll(self):
                return 0

        def run():
            return bounded.run(bounded_jobs.sleep_then, (0, "done"))

        with (
            self.limit(3.0),
            mock.patch.object(bounded, "_clock", lambda: now[0]),
            mock.patch.object(bounded.subprocess, "Popen", Child),
        ):
            with bounded.budget():  # deadline 1003
                with bounded.budget():  # nested: the same deadline, not a fresh 3 s
                    now[0] = 1002.0
                    self.assertEqual(run(), "done")
                    self.assertEqual(children[-1].timeout, 1.0)
                    now[0] = 1003.0  # at the deadline
                    with self.assertRaises(bounded.TimeLimitError):
                        run()
                    bounded.check()
                    now[0] = 1003.5  # past it
                    with self.assertRaises(bounded.TimeLimitError):
                        bounded.check()
                    with self.assertRaises(bounded.TimeLimitError):
                        run()
                with self.assertRaises(bounded.TimeLimitError):  # the outer budget: same
                    run()
            self.assertEqual(len(children), 1)  # nothing started once it was spent
            with bounded.budget():  # the next change: 3 s from now
                self.assertEqual(run(), "done")
            bounded.check()  # outside any budget nothing is checked
            self.assertEqual(run(), "done")  # and run() gets its own 3 s
            self.assertEqual([child.timeout for child in children], [1.0, 3.0, 3.0])
        self.assertEqual(self.children, [])  # no real process

    def test_check_fails_closed_when_its_change_runs_out_of_time(self):
        backend = self.stand_in(bounded_jobs.slow_row)
        backend.fetch_packument = functools.partial(bounded_jobs.give, self.doc())

        def init(new):  # keeps the real class, which pickle looks up by name
            vars(new).update(vars(backend))

        with mock.patch.object(FeatureExtractorBackend, "__init__", init), self.limit(1.5):
            report = check_package("example", "1.1.0", no_cache=True)
        row = report["results"][0]
        self.assertEqual((report["exit_code"], row["status"], row["reason"]),
                         (2, "incomplete", "analysis_failed"))  # fmt: skip
        self.assertIn("did not finish within 1.5 s", row["detail"])
        self.assertGreaterEqual(row["elapsed_seconds"], 1.5)
        self.assert_stopped()

    def slow(self, target, attribute):
        """Patch target.attribute to take 0.7 s (the parent's own step) before doing its work;
        pickle.dumps is slowed only for the call payload, not for sys.path."""
        real = getattr(target, attribute)

        def delayed(*args, **kwargs):
            if attribute != "dumps" or isinstance(args[0], tuple):
                time.sleep(0.7)
            return real(*args, **kwargs)

        return mock.patch.object(target, attribute, side_effect=delayed)

    def test_parent_steps_past_the_deadline_are_refused(self):
        # Sol's review 02 cases: before the fix each returned the child's result after ~0.85 s.
        steps = {
            "pickling the call": (bounded.pickle, "dumps", 0),
            "starting the process": (bounded.subprocess, "Popen", 1),
            "decoding the result": (bounded.json, "loads", 1),
        }
        for label, (target, attribute, started) in steps.items():
            for scoped in (True, False):  # a run() outside budget() keeps its own deadline
                with self.subTest(label, scoped=scoped), self.limit(0.4):
                    before = len(self.children)
                    scope = bounded.budget() if scoped else contextlib.nullcontext()
                    with scope, self.slow(target, attribute):
                        with self.assertRaises(bounded.TimeLimitError):
                            bounded.run(bounded_jobs.sleep_then, (0, "too late"))
                    self.assertEqual(len(self.children) - before, started)
                    self.assertTrue(all(child.poll() is not None for child in self.children))
        # Within the budget the same calls still succeed.
        with self.limit(5.0):
            self.assertEqual(bounded.run(bounded_jobs.sleep_then, (0, [1, 2])), [1, 2])

    def test_check_refuses_an_extraction_finished_after_its_budget(self):
        backend = self.stand_in(bounded_jobs.quick_row)
        backend.fetch_packument = functools.partial(bounded_jobs.give, self.doc())

        def init(new):
            vars(new).update(vars(backend))

        with (
            mock.patch.object(FeatureExtractorBackend, "__init__", init),
            mock.patch("depbee.service.LightGBMPredictor", return_value=Model()),
            self.limit(0.4),
            self.slow(bounded.pickle, "dumps"),
        ):
            report = check_package("example", "1.1.0", model_dir=Path("m"), no_cache=True)
        row = report["results"][0]
        # Before the fix: status passed, exit code 0 (service_deadline.json).
        self.assertEqual((report["exit_code"], row.get("reason")), (2, "analysis_failed"))
        self.assertIn("did not finish within 0.4 s", row["detail"])
        self.assertTrue(all(child.poll() is not None for child in self.children))

    def test_a_cache_hit_after_the_budget_is_refused_and_not_stored(self):
        # The metadata step uses up the budget in the parent (as parsing a large document would);
        # a cache hit needs no further child step, so only the analyzer's check can refuse it.
        doc = packument({"1.0.0": "2026-01-01T00:00:00Z", "1.0.1": "2026-01-02T00:00:00Z",
                         "1.1.0": "2026-01-03T00:00:00Z"})  # fmt: skip
        backend = FakeBackend(doc, features={"signal": 0.2, "obfChangedFileCount": 2})
        backend.identity = dict(EXTRACTOR)
        late = {"seconds": 0.0}

        def fetch(name):
            fetched = bounded.run(bounded_jobs.sleep_then, (0, doc))  # starts the budget
            time.sleep(late["seconds"])
            return fetched

        backend.fetch_packument = fetch
        cache_dir = self.root / "cache"
        options = {"extract": True, "model_dir": Path("m"), "cache_dir": cache_dir}
        with (
            mock.patch("depbee.analysis.extractor.FeatureExtractorBackend", return_value=backend),
            mock.patch("depbee.service.LightGBMPredictor", return_value=Model()),
            self.limit(1.0),
        ):
            cold = scan_project(self.project, self.base, **options)["results"][0]
            warm = scan_project(self.project, self.base, **options)["results"][0]
            entry = next(cache_dir.glob("*.json")).read_bytes()
            late["seconds"] = 1.3
            expired = scan_project(self.project, self.base, **options)
        self.assertEqual([cold["cache_hit"], warm["cache_hit"]], [False, True])
        row = expired["results"][0]
        self.assertEqual((expired["exit_code"], row.get("reason")), (2, "analysis_failed"))
        self.assertIn("did not finish within 1.0 s", row["detail"])
        self.assertEqual(len(backend.calls), 1)  # extracted once, on the cold run
        self.assertEqual(next(cache_dir.glob("*.json")).read_bytes(), entry)

    def test_a_repeated_package_second_location_has_its_own_deadline(self):
        # Review 03 B with a real child for the metadata: the second location reuses the
        # metadata and hits the cache, so before the fix its budget had no deadline at all.
        for location in ("node_modules/example", "node_modules/a/node_modules/example"):
            self.old["packages"][location] = package()
            self.new["packages"][location] = package("1.1.0")
        self.save_locks()
        doc = packument({"1.0.0": "2026-01-01T00:00:00Z", "1.0.1": "2026-01-02T00:00:00Z",
                         "1.1.0": "2026-01-03T00:00:00Z"})  # fmt: skip
        backend = FakeBackend(doc, features={"signal": 0.2, "obfChangedFileCount": 2})
        backend.identity = dict(EXTRACTOR)
        backend.fetch_packument = lambda name: bounded.run(bounded_jobs.sleep_then, (0, doc))
        real_load, loads = cache.load, []

        def load(*args):
            loads.append(1)
            if len(loads) == 2:  # the second location's cache read
                time.sleep(1.3)
            return real_load(*args)

        options = {"extract": True, "model_dir": Path("m"), "cache_dir": self.root / "cache"}
        with (
            mock.patch("depbee.analysis.extractor.FeatureExtractorBackend", return_value=backend),
            mock.patch("depbee.service.LightGBMPredictor", return_value=Model()),
            mock.patch.object(cache, "load", side_effect=load),
            self.limit(1.0),
        ):
            rows = scan_project(self.project, self.base, **options)["results"]
        self.assertEqual([r["location"] for r in rows],
                         ["node_modules/a/node_modules/example", "node_modules/example"])  # fmt: skip
        self.assertEqual((rows[0]["status"], rows[0]["cache_hit"]), ("not_flagged", False))
        self.assertEqual((rows[1]["status"], rows[1].get("reason")), ("incomplete", "analysis_failed"))
        self.assertEqual((len(self.children), len(backend.calls)), (1, 1))  # one metadata child
        self.assertTrue(all(child.poll() is not None for child in self.children))

    @unittest.skipUnless(
        importlib.util.find_spec("depbee_analyzer"), "Install .[extract] for the pinned loader"
    )
    def test_pinned_extraction_runs_in_a_child(self):
        doc = packument({"1.0.1": "2026-01-02T00:00:00Z", "1.1.0": "2026-01-03T00:00:00Z"})
        doc["versions"]["1.1.0"]["scripts"] = {"postinstall": "node setup.js"}
        files = {}
        for version in ("1.0.1", "1.1.0"):
            data = tgz({"package/package.json": json.dumps({"name": "example",
                                                            "version": version}).encode(),
                        "package/index.js": b"module.exports = 1;\n"})  # fmt: skip
            doc["versions"][version]["dist"]["integrity"] = sri(data)
            files[tarball_url("example", version)] = data
        work = self.root / "work"
        work.mkdir()
        result = bounded.run(bounded_jobs.real_extract,
                             (files, "example", "1.0.1", "1.1.0", doc, str(work)))  # fmt: skip
        self.assertEqual(len(result["features"]), 29)
        self.assertIs(result["features"]["installScriptAdded"], True)  # from the manifest
        self.assertEqual(len(result["unpacked"]), 2)  # both verified tarballs, under work


class ParentBudgetTests(CacheFixture):
    """Review 03: the parent's own cache work is inside each change's budget, child or not.

    Budgets of 1 s and parent delays of 1.3 s on the real clock; no child is needed now that a
    budget starts with its change (the Fixture runs bounded steps in-process).
    """

    def setUp(self):
        super().setUp()
        limit = mock.patch.object(bounded, "ANALYSIS_SECONDS", 1.0)
        limit.start()
        self.addCleanup(limit.stop)

    def late(self, target, attribute, calls=(1,)):
        """target.attribute sleeps 1.3 s on the given calls (1 = first) before its real work."""
        real, seen = getattr(target, attribute), []

        def delayed(*args, **kwargs):
            seen.append(1)
            if len(seen) in calls:
                time.sleep(1.3)
            return real(*args, **kwargs)

        return mock.patch.object(target, attribute, side_effect=delayed)

    def assert_refused(self, row):
        self.assertEqual((row["status"], row.get("reason")), ("incomplete", "analysis_failed"))
        self.assertIn("did not finish within 1.0 s", row["detail"])

    def test_a_late_cache_model_check_writes_and_accepts_nothing(self):
        with self.late(self.model, "encode"):  # the cache's model check on the new features
            self.assert_refused(self.scan()["results"][0])
        self.assertEqual(self.entries(), [])

    def test_a_late_write_is_not_published_and_other_entries_stay(self):
        self.cache_dir.mkdir()
        other = self.cache_dir / ("0" * 64 + ".json")
        other.write_bytes(b'{"unrelated": true}')
        self.scan()
        [entry] = [p for p in self.entries() if p != other]
        entry.write_bytes(b"damaged")  # a miss, so each next run extracts and stores again
        # Every step store() takes before the rename: computing the entry's path (its key
        # digest; load() made the first _path call) and writing the temporary file.
        for label, target, attribute, calls in (("entry path", cache, "_path", (2,)),
                                                ("writing", cache.os, "fdopen", (1,))):  # fmt: skip
            with self.subTest(label):
                with self.late(target, attribute, calls):
                    self.assert_refused(self.scan()["results"][0])
                self.assertEqual(entry.read_bytes(), b"damaged")  # not replaced, not removed
                self.assertEqual(other.read_bytes(), b'{"unrelated": true}')
                names = sorted(p.name for p in self.cache_dir.iterdir())
                self.assertEqual(names, sorted([entry.name, other.name]))  # no temporary file

    def test_a_publish_that_ends_late_is_kept_but_its_result_refused(self):
        # os.replace cannot be stopped once it started in time; its entry holds features that
        # were finished in time, so it stays. This run's result is still refused.
        with self.late(cache.os, "replace"):
            self.assert_refused(self.scan()["results"][0])
        [entry] = self.entries()
        self.assertTrue(json.loads(entry.read_bytes())["features"])
        row = self.scan()["results"][0]
        self.assertEqual((row["status"], row["cache_hit"]), ("not_flagged", True))

    def two_locations(self):
        self.old["packages"]["node_modules/a/node_modules/example"] = package()
        self.new["packages"]["node_modules/a/node_modules/example"] = package("1.1.0")
        self.save_locks()

    def test_every_change_has_its_own_deadline(self):
        # The second location reuses the metadata, and the features too with the cache: no
        # child step at all, yet its own budget applies.
        self.two_locations()
        self.scan()  # warm the cache
        for label, patcher, options in (
            ("cache hit", self.late(cache, "load", calls=(2,)), {}),
            ("no cache", self.late(self.backend, "extract", calls=(2,)), {"no_cache": True}),
        ):
            with self.subTest(label):
                with patcher:
                    rows = self.scan(**options)["results"]
                self.assertEqual(rows[0]["status"], "not_flagged")  # a fresh budget each
                self.assert_refused(rows[1])
        self.assertEqual(self.backend.fetched, ["example"] * 3)  # once per run

    def test_check_shares_one_deadline_from_its_metadata_read(self):
        real_fetch = self.backend.fetch_packument

        def fetch(name):
            time.sleep(0.6)
            return real_fetch(name)

        self.backend.fetch_packument = fetch
        real_extract = self.backend.extract

        def extract(*args):
            time.sleep(0.6)  # each step fits in 1 s, both together do not
            return real_extract(*args)

        self.backend.extract = extract
        report = check_package("example", "1.1.0", model_dir=Path("m"), no_cache=True)
        self.assert_refused(report["results"][0])
        self.assertEqual(report["exit_code"], 2)


if __name__ == "__main__":
    unittest.main()
