"""The per-change time budget and its child processes (analysis.bounded), with real children.

Each child job (bounded_jobs.py) blocks network connections and uses its own synthetic I/O in
the child; nothing reaches a registry. Slow jobs write heartbeats, so the tests can see that the
killed child's work and I/O stopped, not only that the caller got an error.
"""

import functools
import importlib.util
import json
import subprocess
import time
import unittest
from unittest import mock

import bounded_jobs
from test_extract import packument
from test_registry import package_tgz, sri, tarball_url, tgz
from test_workflow import Fixture

from depbee.analysis import bounded
from depbee.analysis.extractor import FeatureExtractorBackend
from depbee.service import check_package

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
        """The real FeatureExtractorBackend.extract and _extract_here; only feature-extractor's
        build_snapshot and build_row are stand-ins (module functions, so they cross by pickle)."""
        backend = FeatureExtractorBackend.__new__(FeatureExtractorBackend)
        backend.errors = (bounded.StepError, bounded.TimeLimitError)
        backend.version, backend.identity = "stand-in", None
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
        features, new_json = quick.extract("example", "1.0.1", "1.1.0", self.doc(), None)
        self.assertEqual(features, {"signal": 0.2, "obfChangedFileCount": 0, "name": "example"})
        self.assertEqual(new_json["version"], "1.1.0")

    def test_one_budget_is_shared_by_the_steps_of_a_change(self):
        with self.limit(3.0), bounded.budget():
            self.assertEqual(bounded.run(bounded_jobs.sleep_then, (1.5, "first step")),
                             "first step")  # fmt: skip
            began = time.monotonic()
            with self.assertRaises(bounded.TimeLimitError):
                bounded.run(bounded_jobs.stuck_download, (str(self.heartbeat), True))
            self.assertLess(time.monotonic() - began, 2.5)  # what was left, not a fresh 3 s
            started = len(self.children)
            with bounded.budget(), self.assertRaises(bounded.TimeLimitError):  # nested: no reset
                bounded.run(bounded_jobs.sleep_then, (0, None))
            self.assertEqual(len(self.children), started)  # nothing starts once it is spent
        self.assert_stopped()
        # A new budget (the next change) starts afresh.
        with self.limit(3.0), bounded.budget():
            self.assertIsNone(bounded.run(bounded_jobs.sleep_then, (0, None)))

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

    @unittest.skipUnless(
        importlib.util.find_spec("feature_extractor"), "Install .[extract] for the pinned loader"
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


if __name__ == "__main__":
    unittest.main()
