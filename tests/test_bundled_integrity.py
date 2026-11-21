"""The assets shipped with depbee are read once, checked against the SHA-256 fixed in code and
only then parsed, from the same bytes: a changed one never reaches LightGBM or a JSON parser.
The model reaches LightGBM as text, so depbee also loads it from an install folder whose path
LightGBM's own file reader cannot open.

Synthetic only: the tiny model and the MAL-EXAMPLE index of test_config.NativeAssets, put in the
shipped assets' place.
"""

import collections
import hashlib
import json
import shutil
import unittest
from pathlib import Path
from unittest import mock

from test_bundled import ship
from test_config import ML, NO_ML, NativeAssets, run_cli

from depbee import bundled, known_malicious
from depbee.contracts import GuardError
from depbee.inference.lightgbm import LightGBMPredictor

LOADERS = {"model_dir": LightGBMPredictor, "known_malicious_dir": known_malicious.load}


@unittest.skipUnless(ML, NO_ML)
class BundledIntegrityTests(NativeAssets):
    def setUp(self):
        super().setUp()
        self.pins = ship(self, self.assets)
        # Every opening of a file under self.assets, by "folder/name": the loaders read through
        # Path.open, and LightGBM (which could read without it) is watched by its Booster.
        self.opened, real = collections.Counter(), Path.open

        def counting(path, *args, **kwargs):
            if self.assets in path.parents:
                self.opened[f"{path.parent.name}/{path.name}"] += 1
            return real(path, *args, **kwargs)

        patcher = mock.patch.object(Path, "open", counting)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_each_file_is_read_once_and_what_is_parsed_is_what_was_checked(self):
        import lightgbm

        with mock.patch.object(lightgbm, "Booster", wraps=lightgbm.Booster) as booster:
            predictor = bundled.load("model_dir", LightGBMPredictor)
        self.assertEqual(self.opened, {"model/manifest.json": 1, "model/model.txt": 1})
        # LightGBM got the text of the bytes that were checked, and no file name to open.
        booster.assert_called_once()
        self.assertEqual((booster.call_args.args, list(booster.call_args.kwargs)),
                         ((), ["model_str"]))  # fmt: skip
        given = booster.call_args.kwargs["model_str"].encode("utf-8")
        self.assertEqual(hashlib.sha256(given).hexdigest(), self.pins["model/model.txt"])
        # The report's provenance is those digests.
        self.assertEqual(predictor.identity, {
            "model_sha256": self.pins["model/model.txt"],
            "manifest_sha256": self.pins["model/manifest.json"]})  # fmt: skip
        self.assertEqual(predictor.model_id, "synthetic-test-only")
        self.opened.clear()
        first = bundled.load("known_malicious_dir", known_malicious.load)
        self.assertEqual(self.opened, {"index/manifest.json": 1, "index/index.json": 1})
        self.assertEqual(first.list_sha256, self.pins["index/index.json"])
        # The next call reuses the checked index only after reading and checking both again.
        self.assertIs(bundled.load("known_malicious_dir", known_malicious.load), first)
        self.assertEqual(self.opened, {"index/manifest.json": 2, "index/index.json": 2})

    def test_a_changed_file_is_refused_before_its_bytes_reach_lightgbm_or_a_parser(self):
        import lightgbm

        released = self.root / "released"
        shutil.copytree(self.assets, released)
        for relative in self.pins:
            with self.subTest(relative):
                shutil.rmtree(self.assets)
                shutil.copytree(released, self.assets)
                folder, _, name = relative.partition("/")
                key = "model_dir" if folder == "model" else "known_malicious_dir"
                # Still the same JSON, still a model LightGBM reads: without the fixed SHA-256
                # a manifest changed like this loads (below).
                changed = (released / relative).read_bytes() + b"\n"
                (self.assets / relative).write_bytes(changed)
                self.opened.clear()
                with mock.patch.object(lightgbm, "Booster", wraps=lightgbm.Booster) as booster, \
                        mock.patch("json.loads", wraps=json.loads) as parser:  # fmt: skip
                    with self.assertRaisesRegex(
                        GuardError, f"shipped with depbee cannot be loaded.*{relative} is not "
                        r"the released file \(SHA-256 mismatch\).*reinstall depbee",
                    ):  # fmt: skip
                        bundled.load(key, LOADERS[key])
                booster.assert_not_called()
                self.assertNotIn(changed.decode("utf-8"), [c.args[0] for c in parser.call_args_list])
                if name == "manifest.json":  # stopped there: its file is not even opened
                    parser.assert_not_called()
                    self.assertEqual(self.opened, {relative: 1})
                    # A folder the caller chose has no fixed SHA-256 and still loads as before.
                    LOADERS[key](self.assets / folder)
                else:
                    self.assertEqual(self.opened, {f"{folder}/manifest.json": 1, relative: 1})

    def test_assets_under_a_path_with_korean_and_an_emoji_load(self):
        """depbee installed under such a folder: on Windows LightGBM's file reader cannot open
        the model there, which stopped every scan with the shipped model."""
        assets = self.root / "한글 설치 경로 \U0001f41d" / "assets"
        shutil.copytree(self.assets, assets)
        pins = ship(self, assets)
        predictor = bundled.load("model_dir", LightGBMPredictor)
        self.assertEqual(predictor.identity["model_sha256"], pins["model/model.txt"])
        self.assertGreaterEqual(predictor.predict({"signal": 0.9}), predictor.threshold)
        index = bundled.load("known_malicious_dir", known_malicious.load)
        self.assertEqual(index.list_sha256, pins["index/index.json"])
        self.adapter()  # and a scan with nothing configured, which uses them
        code, out, err = run_cli("scan", str(self.project), "--base-lock", str(self.base),
                                 "--analysis", str(self.root / "analysis.json"),
                                 "--format", "json")  # fmt: skip
        self.assertEqual((code, err), (1, ""))
        report = json.loads(out)
        self.assertEqual(report["model_id"], "synthetic-test-only")
        self.assertEqual(report["provenance"]["model"]["model_sha256"], pins["model/model.txt"])
        # A model folder of the user's own under such a path loads the same way.
        self.assertEqual(LightGBMPredictor(assets / "model").model_id, "synthetic-test-only")


if __name__ == "__main__":
    unittest.main()
