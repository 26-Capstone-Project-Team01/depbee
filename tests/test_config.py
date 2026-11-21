"""User settings and the one-time asset setup (`depbee setup`): the settings file, the service's
option, variable, saved folder order, the CLI command and the MCP entry point without options.

Synthetic only, inside each test run's folder (Fixture sets DEPBEE_CONFIG_DIR, the user's
settings folder, to a folder there): a tiny LightGBM model of made-up numbers (skipped without
.[ml]), indexes built from MAL-EXAMPLE records, fake analyzer backends. No network; nothing is
downloaded.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import unittest
import venv
from pathlib import Path
from unittest import mock

from test_extract import PackagePredictor
from test_known_malicious import AS_OF
from test_known_malicious_wiring import LISTED, OTHER, IndexMixin, identity
from test_mcp import NO_SDK, SDK, MCPFixture
from test_workflow import Fixture

from depbee import cli, config, history, mcp
from depbee.cli import main
from depbee.contracts import GuardError
from depbee.inference.lightgbm import LightGBMPredictor
from depbee.service import scan_project, setup_assets

ML = importlib.util.find_spec("lightgbm") is not None
NO_ML = "Install .[ml] for the setup tests that load a native model"
SRC = str(Path(__file__).resolve().parents[1] / "src")
# What `depbee setup` prints with nothing saved, in these tests: Fixture leaves depbee's shipped
# assets out, so no asset is in use (test_bundled.py has the shipped ones).
NOTHING = (
    f"{cli.SETUP_NONE}\n  모델: 연결 안 됨\n  기지 악성 색인: 연결 안 됨\n{cli.SETUP_HOW}\n"
)


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def planted_settings(folder, assets):
    """A settings file in folder as depbee setup would write it, naming assets' two folders."""
    settings = {"assets_dir": str(assets), "model_dir": str(assets / "model"),
                "known_malicious_dir": str(assets / "index")}  # fmt: skip
    (folder / "config.json").write_text(json.dumps(settings), "utf-8")


class SettingsFolderTests(Fixture):
    """Where the settings are: the user's folder, whatever the current folder, the project and
    the history file are."""

    def test_the_folder_is_of_the_home_or_the_absolute_one_the_user_named(self):
        self.assertEqual(config.user_dir(), self.root / "user")  # Fixture's DEPBEE_CONFIG_DIR
        self.assertEqual(config.path(), self.root / "user" / "config.json")
        for unset in ("", None):  # empty counts as unset
            with self.subTest(unset=unset), \
                    mock.patch.object(Path, "home", return_value=self.root / "home"):  # fmt: skip
                os.environ.pop("DEPBEE_CONFIG_DIR", None)
                if unset is not None:
                    os.environ["DEPBEE_CONFIG_DIR"] = unset
                self.assertEqual(config.user_dir(), self.root / "home" / ".config" / "depbee")

    def test_the_history_file_does_not_move_it(self):
        with mock.patch.object(Path, "home", return_value=self.root / "home"), \
                contextlib.chdir(self.project):  # fmt: skip
            for variable in ("DEPBEE_CONFIG_DIR", "DEPBEE_HISTORY_DB"):
                os.environ.pop(variable, None)
            default = config.user_dir()
            for history_db in ("history.sqlite3", str(self.project / "history.sqlite3"),
                               str(self.root / "elsewhere" / "history.sqlite3")):  # fmt: skip
                with self.subTest(history_db):
                    os.environ["DEPBEE_HISTORY_DB"] = history_db
                    self.assertEqual(config.user_dir(), default)
                    self.assertNotEqual(config.user_dir(), history.db_path().resolve().parent)

    def test_a_relative_folder_is_refused_not_looked_up_where_depbee_runs(self):
        planted_settings(self.project, self.project)
        relative = [".", "user", os.path.join("..", "user")]
        if os.name == "nt":
            relative += ["\\user", "C:user"]  # no drive, or no root: they depend on where it runs
        for value in relative:
            with self.subTest(value), contextlib.chdir(self.project):
                os.environ["DEPBEE_CONFIG_DIR"] = value
                for call in (config.user_dir, config.load, config.clear,
                             lambda: config.save(self.root, self.root, None),
                             lambda: scan_project(self.project, self.base)):  # fmt: skip
                    with self.assertRaisesRegex(GuardError, "DEPBEE_CONFIG_DIR must be the abs"):
                        call()
                code, out, err = run_cli("setup")
                self.assertEqual((code, out), (2, ""))
                self.assertIn("DEPBEE_CONFIG_DIR", json.loads(err)["error"])

    def test_a_home_that_is_not_absolute_counts_as_no_home(self):
        os.environ.pop("DEPBEE_CONFIG_DIR")
        planted_settings(self.project, self.project)
        with mock.patch.object(Path, "home", return_value=Path(".")), \
                contextlib.chdir(self.project):  # fmt: skip
            with self.assertRaises(RuntimeError):
                config.user_dir()
            self.assertIsNone(config.load())  # not ./.config/depbee of the project


class SettingsFileTests(Fixture):
    def setUp(self):
        super().setUp()
        self.user = Path(os.environ["DEPBEE_CONFIG_DIR"])

    def test_nothing_saved_is_no_settings_and_creates_nothing(self):
        before = sorted(self.root.iterdir())
        self.assertIsNone(config.load())
        self.assertFalse(config.clear())
        self.assertEqual(sorted(self.root.iterdir()), before)  # not even the folder

    def test_save_load_and_clear(self):
        with contextlib.chdir(self.root):
            saved = config.save(Path("assets"), Path("assets/model"), None)
        expected = {"assets_dir": str(self.root / "assets"),
                    "model_dir": str(self.root / "assets" / "model"),
                    "known_malicious_dir": None}  # fmt: skip
        self.assertEqual(saved, {**expected, "path": str(self.user / "config.json")})
        self.assertEqual(json.loads((self.user / "config.json").read_text("utf-8")), expected)
        self.assertEqual(config.load(), expected)
        self.assertEqual([p.name for p in self.user.iterdir()], ["config.json"])  # no leftovers
        if os.name != "nt":  # the folder depbee created and its file are the user's alone
            self.assertEqual(self.user.stat().st_mode & 0o777, 0o700)
            self.assertEqual((self.user / "config.json").stat().st_mode & 0o777, 0o600)
        self.assertFalse(config.open_to_others(self.root / "not-there"))  # nothing to tell
        self.assertTrue(config.clear())
        self.assertIsNone(config.load())

    def test_broken_settings_are_an_error_never_no_settings(self):
        absolute = str(self.root / "m")
        good = {"assets_dir": absolute, "model_dir": absolute, "known_malicious_dir": None}
        broken = {
            "not JSON": b"{",
            "not an object": b"[]",
            "a missing key": json.dumps({"model_dir": absolute}).encode(),
            "a relative folder": json.dumps({**good, "model_dir": "models/m"}).encode(),
            "a folder that is no text": json.dumps({**good, "known_malicious_dir": 3}).encode(),
            "an empty folder": json.dumps({**good, "model_dir": ""}).encode(),
            "too large": json.dumps({**good, "padding": "x" * config.MAX_BYTES}).encode(),
        }
        self.user.mkdir()
        for label, raw in broken.items():
            with self.subTest(label):
                (self.user / "config.json").write_bytes(raw)
                with self.assertRaisesRegex(GuardError, "run depbee setup again"):
                    config.load()
                with self.assertRaises(GuardError):  # so a scan stops instead of dropping it
                    scan_project(self.project, self.base)
        (self.user / "config.json").unlink()
        (self.user / "config.json").mkdir()  # cannot be opened as a file
        with self.assertRaisesRegex(GuardError, "cannot be read"):
            config.load()

    def test_a_failed_write_keeps_the_old_file_and_leaves_no_temporary_file(self):
        target = self.root / "config.json"
        config.write_atomic(target, "old\n")
        with mock.patch("os.replace", side_effect=OSError("synthetic")):
            with self.assertRaises(OSError):
                config.write_atomic(target, "new\n")
        self.assertEqual(target.read_text("utf-8"), "old\n")
        self.assertEqual(sorted(p.name for p in self.root.glob("*config*")), ["config.json"])

    def test_a_replace_refused_while_a_reader_has_the_file_open_is_tried_again(self):
        target, real, calls = self.root / "config.json", os.replace, []

        def busy_twice(source, destination):
            calls.append(destination)
            if len(calls) < 3:
                raise PermissionError("synthetic sharing violation")
            real(source, destination)

        with mock.patch("os.replace", side_effect=busy_twice), mock.patch("time.sleep"):
            config.write_atomic(target, "text\n")
        self.assertEqual((len(calls), target.read_text("utf-8")), (3, "text\n"))
        with mock.patch("os.replace", side_effect=PermissionError("held")), \
                mock.patch("time.sleep"):  # fmt: skip
            with self.assertRaises(PermissionError):  # not forever
                config.write_atomic(target, "never\n")
        self.assertEqual(target.read_text("utf-8"), "text\n")

    def test_without_a_home_folder(self):
        os.environ.pop("DEPBEE_CONFIG_DIR")
        with mock.patch.object(Path, "home", side_effect=RuntimeError("no home")):
            self.assertIsNone(config.load())  # as the feature cache: run without it
            self.assertFalse(config.clear())
            with self.assertRaisesRegex(GuardError, "DEPBEE_CONFIG_DIR"):
                config.save(self.root, self.root, None)
            self.assertEqual(scan_project(self.project, self.base)["exit_code"], 2)


class OrderTests(IndexMixin, MCPFixture):
    """Option, then environment variable, then the saved folder, then depbee's shipped assets:
    none here, where Fixture leaves them out (test_bundled.py has that last step)."""

    def setUp(self):
        super().setUp()
        self.models = []
        patcher = mock.patch("depbee.service.LightGBMPredictor",
                             side_effect=lambda d: self.models.append(d) or PackagePredictor())  # fmt: skip
        patcher.start()
        self.addCleanup(patcher.stop)

    def scan(self, **options):
        return scan_project(self.project, self.base, extract=True, **options)

    def test_model_folder_order(self):
        config.save(self.root, self.root / "saved", None)
        os.environ["DEPBEE_MODEL_DIR"] = str(self.root / "variable")
        self.scan(model_dir=self.root / "option")
        self.scan()
        os.environ["DEPBEE_MODEL_DIR"] = ""  # empty counts as unset
        self.scan()
        os.environ.pop("DEPBEE_MODEL_DIR")
        report = self.scan()
        self.assertEqual(self.models, [self.root / "option", self.root / "variable",
                                       self.root / "saved", self.root / "saved"])  # fmt: skip
        self.assertEqual(report["results"][0]["status"], "not_flagged")
        config.clear()
        report = self.scan()
        self.assertEqual(len(self.models), 4)  # no model is loaded
        self.assertEqual((report["exit_code"], report["results"][0]["reason"]),
                         (2, "model_missing"))  # fmt: skip

    def test_index_folder_order(self):
        (saved, saved_sha), (variable, variable_sha), (option, option_sha) = (
            self.index(LISTED), self.index(OTHER), self.index(OTHER + LISTED))  # fmt: skip
        config.save(self.root, None, saved)
        os.environ["DEPBEE_KNOWN_MALICIOUS_DIR"] = str(variable)
        used = [self.scan(known_malicious_dir=option), self.scan()]
        os.environ["DEPBEE_KNOWN_MALICIOUS_DIR"] = ""
        used.append(self.scan())
        self.assertEqual([r["detectors"]["known_malicious"] for r in used],
                         [identity(option_sha), identity(variable_sha), identity(saved_sha)])  # fmt: skip
        self.assertEqual(used[2]["results"][0]["known_malicious"]["status"], "hit")
        config.clear()
        self.assertIsNone(self.scan()["detectors"]["known_malicious"])

    def test_a_saved_folder_that_is_gone_is_an_error_not_a_missing_asset(self):
        saved, _ = self.index(LISTED)
        config.save(self.root, None, saved)
        shutil.rmtree(saved)
        with self.assertRaisesRegex(GuardError, "cannot be read"):
            self.scan()
        code, out, err = self.cli("scan", str(self.project), "--base-lock", str(self.base),
                                  "--format", "json")  # fmt: skip
        self.assertEqual((code, out), (2, ""))
        self.assertIn("Known malicious index manifest cannot be read", json.loads(err)["error"])

    def test_settings_and_assets_in_a_project_or_beside_the_history_file_are_never_used(self):
        """A repository that brings its own config.json, model/ and index/ (a valid index, so
        that using it would show). Run from inside it, with the history file named by a relative
        path, by a path in the project, and by an absolute one elsewhere: the settings are the
        user's folder's alone, which has none."""
        index, _ = self.index(LISTED)
        elsewhere = self.root / "elsewhere"
        for folder in (self.project, elsewhere):
            shutil.copytree(index, folder / "index")
            (folder / "model").mkdir()
            planted_settings(folder, folder)
        for history_db in ("history.sqlite3", str(self.project / "history.sqlite3"),
                           str(elsewhere / "history.sqlite3")):  # fmt: skip
            with self.subTest(history_db), contextlib.chdir(self.project):
                os.environ["DEPBEE_HISTORY_DB"] = history_db
                self.assertIsNone(config.load())
                report = self.scan()
                self.assertEqual((report["model_id"], report["detectors"]["known_malicious"]),
                                 (None, None))  # fmt: skip
                self.assertEqual(report["results"][0]["reason"], "model_missing")
                self.assertEqual(self.cli("setup"), (0, NOTHING, ""))
                unchecked = mcp.scan_lockfile(str(self.project), str(self.base))
                self.assertIn(mcp.KNOWN_MALICIOUS_NOTICE, unchecked["notices"])
                self.assertEqual(config.path(), self.root / "user" / "config.json")
        self.assertEqual(self.models, [])  # no model folder of the project was ever opened


class NativeAssets(IndexMixin, Fixture):
    """self.assets with a native model in model/ and an index listing example@1.1.0 in index/."""

    def setUp(self):
        super().setUp()
        import lightgbm as lgb
        import numpy as np

        self.assets = self.root / "assets"
        model = self.assets / "model"
        model.mkdir(parents=True)
        # Purely synthetic numbers: serialization and wiring, not detection quality.
        data = lgb.Dataset(np.array([[0.0], [0.1], [0.2], [0.8], [0.9], [1.0]]),
                           label=[0, 0, 0, 1, 1, 1], feature_name=["signal"])  # fmt: skip
        booster = lgb.train({"objective": "binary", "verbosity": -1, "num_threads": 1,
                             "min_data_in_leaf": 1, "min_data_in_bin": 1}, data,
                            num_boost_round=4)  # fmt: skip
        booster.save_model(str(model / "model.txt"))
        self.manifest = {
            "schema_version": 1, "model_id": "synthetic-test-only", "feature_schema": "test-v1",
            "feature_names": ["signal"], "positive_class": "malicious", "objective": "binary",
            "threshold": 0.5,
            "model_sha256": hashlib.sha256((model / "model.txt").read_bytes()).hexdigest(),
        }  # fmt: skip
        self.write(model / "manifest.json", self.manifest)
        folder, self.index_sha = self.index(LISTED)
        folder.rename(self.assets / "index")
        self.settings = Path(os.environ["DEPBEE_CONFIG_DIR"]) / "config.json"

    def scan_without_options(self):
        self.adapter()
        code, out, err = run_cli("scan", str(self.project), "--base-lock", str(self.base),
                                 "--analysis", str(self.root / "analysis.json"),
                                 "--format", "json")  # fmt: skip
        self.assertEqual(err, "")
        return code, json.loads(out)


@unittest.skipUnless(ML, NO_ML)
class SetupTests(NativeAssets):
    def test_one_setup_then_no_path_options(self):
        code, report = self.scan_without_options()
        self.assertEqual(
            (code, report["model_id"], report["detectors"]["known_malicious"]), (2, None, None)
        )  # nothing saved: no model, no index, as before
        with contextlib.chdir(self.root), \
                mock.patch.object(cli, "_installed", return_value=True):  # fmt: skip
            code, out, err = run_cli("setup", "assets")  # a relative folder is saved as absolute
        self.assertEqual((code, err), (0, ""))
        expected = {"assets_dir": str(self.assets), "model_dir": str(self.assets / "model"),
                    "known_malicious_dir": str(self.assets / "index")}  # fmt: skip
        self.assertEqual(json.loads(self.settings.read_text("utf-8")), expected)
        lines = out.splitlines()
        self.assertEqual(lines[0], f"자산 설정을 저장했습니다: {self.settings}")
        self.assertEqual(lines[1:3], [
            f"  모델: {self.assets / 'model'} (모델 ID synthetic-test-only)",
            f"  기지 악성 색인: {self.assets / 'index'} (기준 시점 {AS_OF})"])  # fmt: skip
        registrations = [line for line in lines if " mcp add " in line]
        self.assertEqual(len(registrations), 2)
        for line in registrations:  # nothing after the command but mcp: no path options
            self.assertTrue(line.endswith(" mcp"), line)
            self.assertNotIn("--model-dir", line)
        code, report = self.scan_without_options()
        self.assertEqual((code, report["model_id"]), (1, "synthetic-test-only"))
        self.assertEqual(report["detectors"]["known_malicious"], identity(self.index_sha))
        row = report["results"][0]
        self.assertEqual((row["status"], row["ml"], row["known_malicious"]["status"]),
                         ("flagged", {"status": "hit"}, "hit"))  # fmt: skip

    def test_show_and_clear(self):
        self.assertEqual(run_cli("setup"), (0, NOTHING, ""))
        self.assertFalse(self.settings.parent.exists())  # showing writes nothing
        run_cli("setup", str(self.assets))
        saved = self.settings.read_bytes()
        index = f"  기지 악성 색인: {self.assets / 'index'} (기준 시점 {AS_OF}, 저장된 설정)"
        code, out, err = run_cli("setup")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out.splitlines(), [
            f"저장된 자산 설정: {self.settings}",
            f"  모델: {self.assets / 'model'} (모델 ID synthetic-test-only, 저장된 설정)",
            index])  # fmt: skip
        # The variable is what a scan would use, and its folder does not load: said, and 2 as
        # that scan would be, not passed over for the saved model.
        os.environ["DEPBEE_MODEL_DIR"] = str(self.root / "elsewhere")
        code, out, err = run_cli("setup")
        self.assertEqual((code, err), (2, ""))
        lines = out.splitlines()
        self.assertEqual((lines[0], lines[2], len(lines)),
                         (f"저장된 자산 설정: {self.settings}", index, 3))  # fmt: skip
        self.assertTrue(lines[1].startswith(
            f"  모델: {self.root / 'elsewhere'} (환경 변수 DEPBEE_MODEL_DIR, 읽지 못함: "), lines[1])  # fmt: skip
        self.assertEqual(self.settings.read_bytes(), saved)
        self.assertEqual(run_cli("setup", "--clear"), (0, f"{cli.SETUP_CLEARED}\n", ""))
        self.assertFalse(self.settings.exists())
        self.assertEqual(run_cli("setup", "--clear"), (0, f"{cli.SETUP_NONE}\n", ""))

    def test_a_subfolder_that_does_not_exist_is_not_saved(self):
        """Its asset is then the one shipped with depbee (test_bundled.py); here, where Fixture
        leaves the shipped ones out, none."""
        shutil.rmtree(self.assets / "index")
        code, out, _ = run_cli("setup", str(self.assets))
        self.assertEqual(code, 0)
        self.assertIn(f"  기지 악성 색인: {cli.SETUP_DEFAULT}\n", out)
        self.assertIsNone(json.loads(self.settings.read_text("utf-8"))["known_malicious_dir"])
        code, report = self.scan_without_options()
        self.assertEqual((code, report["model_id"], report["detectors"]["known_malicious"]),
                         (1, "synthetic-test-only", None))  # fmt: skip

    def test_nothing_is_saved_when_an_asset_does_not_load(self):
        run_cli("setup", str(self.assets))
        saved = self.settings.read_bytes()
        broken = self.root / "broken"
        cases = {
            "Model SHA-256 does not match": ("model", "model.txt", b"tree\n"),
            "SHA-256 does not match the manifest's index_sha256": ("index", "index.json", b"{}"),
        }
        for message, (folder, name, content) in cases.items():
            with self.subTest(folder):
                shutil.rmtree(broken, ignore_errors=True)
                shutil.copytree(self.assets, broken)
                (broken / folder / name).write_bytes(content)
                code, out, err = run_cli("setup", str(broken))
                self.assertEqual((code, out), (2, ""))
                self.assertIn(message, json.loads(err)["error"])
                self.assertEqual(self.settings.read_bytes(), saved)  # the earlier setup stays

    def test_a_file_or_broken_link_in_place_of_a_subfolder_is_an_error_not_no_asset(self):
        """Only a name that is not there is "not connected". With a file or a broken link in
        its place, saving would drop the index or the model of the earlier setup without a
        word, and the next scan would pass what it had flagged."""
        run_cli("setup", str(self.assets))
        saved = self.settings.read_bytes()
        broken, target = self.root / "broken", self.root / "not-there"

        def broken_link(path):
            if os.name != "nt":
                path.symlink_to(target, True)
                return
            import _winapi  # CreateJunction needs no privilege, unlike symbolic links

            target.mkdir()
            _winapi.CreateJunction(str(target), str(path))
            target.rmdir()

        plant = {
            "a file": lambda path: path.write_text("synthetic placeholder\n", "utf-8"),
            "a broken link": broken_link,
        }
        for name in ("index", "model"):
            for kind, put in plant.items():
                with self.subTest(name=name, kind=kind):
                    shutil.rmtree(broken, ignore_errors=True)
                    shutil.copytree(self.assets, broken)
                    shutil.rmtree(broken / name)
                    put(broken / name)
                    self.assertTrue(os.path.lexists(broken / name))  # the name is taken,
                    self.assertFalse((broken / name).is_dir())  # by nothing a scan could read
                    code, out, err = run_cli("setup", str(broken))
                    self.assertEqual((code, out), (2, ""))
                    error = json.loads(err)["error"]
                    self.assertIn(f"{broken / name} is not a folder", error)
                    self.assertEqual(self.settings.read_bytes(), saved)
        code, report = self.scan_without_options()  # still the index of the first setup
        self.assertEqual((code, report["detectors"]["known_malicious"]),
                         (1, identity(self.index_sha)))  # fmt: skip
        self.assertEqual(report["results"][0]["known_malicious"]["status"], "hit")

    def test_one_request_uses_the_model_and_the_index_of_one_saved_setup(self):
        """Another setup replaces the settings while a scan is between its model and its index.
        Reading the file once for each of them joined the first setup's model with the second
        setup's index in one report."""
        run_cli("setup", str(self.assets))
        second = self.root / "second"
        shutil.copytree(self.assets / "model", second / "model")
        self.write(second / "model" / "manifest.json",
                   {**self.manifest, "model_id": "synthetic-second"})  # fmt: skip
        other, other_sha = self.index(OTHER)  # does not list example@1.1.0
        other.rename(second / "index")
        loaded = []

        def load_then_set_up_again(directory):
            predictor = LightGBMPredictor(directory)
            if not loaded:
                config.save(second, second / "model", second / "index")
            loaded.append(directory)
            return predictor

        with mock.patch("depbee.service.LightGBMPredictor", side_effect=load_then_set_up_again):
            _, during = self.scan_without_options()
        _, after = self.scan_without_options()  # the next request reads the settings again
        self.assertEqual(loaded, [self.assets / "model"])
        self.assertEqual(
            (during["model_id"], during["detectors"]["known_malicious"],
             during["results"][0]["known_malicious"]["status"]),
            ("synthetic-test-only", identity(self.index_sha), "hit"))  # fmt: skip
        self.assertEqual(
            (after["model_id"], after["detectors"]["known_malicious"],
             after["results"][0]["known_malicious"]["status"]),
            ("synthetic-second", identity(other_sha), "not_hit"))  # fmt: skip

    def test_folders_that_are_not_asset_folders_and_bad_arguments(self):
        empty = self.root / "empty"
        empty.mkdir()
        for folder in (empty, self.root / "missing", self.assets / "model" / "model.txt"):
            with self.subTest(folder.name):
                code, out, err = run_cli("setup", str(folder))
                self.assertEqual((code, out), (2, ""))
                self.assertIn("No model or index folder", json.loads(err)["error"])
        code, _, err = run_cli("setup", str(self.assets), "--clear")
        self.assertEqual((code, json.loads(err)["error"]),
                         (2, "setup takes DIR or --clear, not both"))  # fmt: skip
        self.assertFalse(self.settings.exists())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stop:
            main(["setup", " "])
        self.assertEqual(stop.exception.code, 2)

    def test_setup_assets_returns_what_it_saved(self):
        saved = setup_assets(self.assets)
        self.assertEqual((saved["model_id"], saved["list_as_of"], saved["path"]),
                         ("synthetic-test-only", AS_OF, str(self.settings)))  # fmt: skip

    @unittest.skipUnless(SDK, NO_SDK)
    def test_a_registered_depbee_mcp_without_options_reads_the_saved_assets(self):
        """The real stdio server process, started as an agent starts it with only `mcp`, in a
        project folder that brings a config.json of its own. The settings are those of the
        user's home (no DEPBEE_CONFIG_DIR here). It needs no analyzer: a saved model that no
        longer matches its manifest stops the call, which only a server that read the home's
        settings, and not the project's, can report."""
        import anyio
        from mcp import Client
        from mcp.client.stdio import StdioServerParameters

        home = self.root / "home"
        os.environ.pop("DEPBEE_CONFIG_DIR")
        with mock.patch.object(Path, "home", return_value=home):
            self.assertEqual(run_cli("setup", str(self.assets))[0], 0)
        self.assertTrue((home / ".config" / "depbee" / "config.json").is_file())
        (self.assets / "model" / "model.txt").write_bytes(b"changed after the setup\n")
        planted_settings(self.project, self.root / "not-there")
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "depbee", "mcp"], cwd=str(self.project),
            env={"PYTHONPATH": SRC, "TMP": os.environ.get("TMP", ""),
                 "TEMP": os.environ.get("TEMP", ""), "HOME": str(home),
                 "USERPROFILE": str(home), "DEPBEE_HISTORY_DB": "history.sqlite3"},
        )  # fmt: skip

        async def call():
            async with Client(params) as client:
                return await client.call_tool("scan_lockfile", {
                    "project": str(self.project), "base_lock": str(self.base)})  # fmt: skip

        result = anyio.run(call)
        self.assertTrue(result.is_error)
        self.assertIn("Model SHA-256 does not match the manifest", result.content[0].text)


class RegistrationCommandTests(IndexMixin, Fixture):
    """What `depbee setup DIR` prints for the agents depends on which depbee the Python that
    runs it starts from another folder. A throwaway virtual environment stands for that Python:
    what its site-packages hold is what it imports, whatever this test run's own Python has."""

    def setUp(self):
        super().setUp()
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.index(LISTED)[0].rename(self.assets / "index")
        home = self.root / "venv"
        venv.EnvBuilder(with_pip=False).create(home)
        windows = os.name == "nt"
        scripts = home / ("Scripts" if windows else "bin")
        self.python = scripts / ("python.exe" if windows else "python")
        self.script = scripts / ("depbee.exe" if windows else "depbee")
        (self.site,) = home.glob("Lib/site-packages" if windows else "lib/python*/site-packages")
        patcher = mock.patch.object(sys, "executable", str(self.python))
        patcher.start()
        self.addCleanup(patcher.stop)

    def printed(self):
        code, out, err = run_cli("setup", str(self.assets))
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(config.load()["known_malicious_dir"], str(self.assets / "index"))
        return out

    def test_a_copy_its_python_would_not_start_gets_no_registration_command(self):
        """The reported case: depbee run from a source folder (python -m depbee) in a Python
        that has another depbee installed, with that one's depbee.exe beside it. The command
        printed was that script: an agent would have started the other copy."""
        (self.site / "depbee").mkdir()
        (self.site / "depbee" / "__init__.py").write_text('__version__ = "0"\n', "utf-8")
        self.script.write_bytes(b"")  # the installed copy's console script
        for installed in ("another copy", "none"):
            with self.subTest(installed=installed):
                out = self.printed()
                self.assertNotIn(" mcp add ", out)
                self.assertNotIn(str(self.script), out)
                self.assertTrue(out.endswith(f"{cli.SETUP_SAVED}\n{cli.SETUP_NOT_INSTALLED}\n"))
            shutil.rmtree(self.site / "depbee", ignore_errors=True)  # now: not installed at all

    def test_an_installed_copy_gets_its_console_script_else_its_python(self):
        # As an editable install does it: the folder of this very copy is on the Python's path.
        source = Path(cli.__file__).resolve().parents[1]
        (self.site / "depbee-editable.pth").write_text(f"{source}\n", "utf-8")
        quote = (lambda text: f'"{text}"') if os.name == "nt" else shlex.quote
        for launcher in (f"{quote(str(self.python))} -P -m depbee", quote(str(self.script))):
            with self.subTest(launcher=launcher):
                self.assertEqual(self.printed().splitlines()[-2:], [
                    f"  Claude Code: claude mcp add --scope user depbee -- {launcher} mcp",
                    f"  Codex: codex mcp add depbee -- {launcher} mcp"])  # fmt: skip
            self.script.write_bytes(b"")  # now with the console script of that install


class Terminal(io.StringIO):
    def isatty(self):
        return True


@unittest.skipUnless(os.name == "nt", "Windows access lists")
class SharedFolderTests(Fixture):
    """The settings folder under a folder that the Users group may change, as a folder outside
    the user's profile or on a shared drive is. On Windows a new file gets the access list of
    its folder, so what depbee keeps there is as open as the folder."""

    def setUp(self):
        super().setUp()
        shared = self.root / "shared"
        shared.mkdir()
        # BUILTIN\Users by its SID, so that the name's language does not matter.
        subprocess.run(["icacls", str(shared), "/grant", "*S-1-5-32-545:(OI)(CI)M"],
                       check=True, capture_output=True, timeout=60)  # fmt: skip
        self.user = shared / "depbee"
        os.environ["DEPBEE_CONFIG_DIR"] = str(self.user)

    def on_terminal(self, *argv):
        out, err = io.StringIO(), Terminal()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_a_folder_that_exists_is_used_as_it_is_and_a_person_is_told(self):
        self.user.mkdir()
        config.save(self.root, None, None)
        self.assertTrue(config.open_to_others(self.user))  # depbee does not change its access
        shown = (f"저장된 자산 설정: {self.user / 'config.json'}\n  모델: 연결 안 됨\n"
                 "  기지 악성 색인: 연결 안 됨\n")  # fmt: skip
        notice = cli.SHARED_FOLDER.format(folder=self.user) + "\n"
        self.assertEqual(self.on_terminal("setup"), (0, shown, notice))
        self.assertEqual(run_cli("setup"), (0, shown, ""))  # captured output is as it was
        state = {"url": "http://127.0.0.1:8123/s/" + "s" * 43 + "/"}
        with mock.patch("depbee.dashboard.lifecycle.start", return_value=(state, True)):
            started = (0, f"{state['url']}\n{cli.BACKGROUND_STARTED}\n")
            self.assertEqual(self.on_terminal("dashboard", "--background"), (*started, notice))
            self.assertEqual(run_cli("dashboard", "--background"), (*started, ""))

    @unittest.skipIf(sys.version_info < (3, 12, 4), "this Python ignores mkdir's mode on Windows")
    @unittest.skipIf(config._elevated(), "run as administrator: see the test below")
    def test_a_folder_depbee_creates_is_the_users_alone(self):
        config.save(self.root, self.root, None)
        self.assertFalse(config.open_to_others(self.user))  # not its parent's access list
        self.assertEqual(config.load()["model_dir"], str(self.root))  # and the user reads it
        self.assertEqual(self.on_terminal("setup")[2], "")
        (self.user / "more.txt").write_text("the user can still write here\n", "utf-8")
        self.assertTrue(config.clear())

    def test_a_folder_created_as_administrator_keeps_its_parents_access(self):
        """Owned by Administrators and open to its owner alone, it would be closed to the same
        user in an ordinary terminal."""
        with mock.patch.object(config, "_elevated", return_value=True):
            config.save(self.root, self.root, None)
        self.assertTrue(config.open_to_others(self.user))


class McpWithoutOptionsTests(IndexMixin, MCPFixture):
    def test_tools_use_the_saved_assets_and_say_so_when_there_are_none(self):
        index, sha = self.index(LISTED)
        config.save(self.root, self.root / "model", index)
        report = mcp.scan_lockfile(str(self.project), str(self.base))
        self.assertEqual(report["report"]["detectors"]["known_malicious"], identity(sha))
        self.assertEqual(report["report"]["model_id"], PackagePredictor.model_id)
        self.assertEqual(report["report"]["results"][0]["known_malicious"]["status"], "hit")
        self.assertNotIn(mcp.KNOWN_MALICIOUS_NOTICE, report["notices"])
        config.clear()
        report = mcp.scan_lockfile(str(self.project), str(self.base))
        self.assertEqual((report["report"]["exit_code"], report["report"]["model_id"]),
                         (2, None))  # fmt: skip
        self.assertIn(mcp.KNOWN_MALICIOUS_NOTICE, report["notices"])

    @unittest.skipUnless(SDK, NO_SDK)
    def test_a_server_built_without_folders_serves_the_saved_assets(self):
        import anyio
        from mcp import Client

        index, sha = self.index(LISTED)
        config.save(self.root, self.root / "model", index)

        async def call():
            async with Client(mcp.build_server()) as client:
                return await client.call_tool("scan_lockfile", {
                    "project": str(self.project), "base_lock": str(self.base)})  # fmt: skip

        result = anyio.run(call)
        self.assertFalse(result.is_error)
        report = json.loads(result.content[0].text)["report"]
        self.assertEqual(report["detectors"]["known_malicious"], identity(sha))
        self.assertEqual(report["exit_code"], 1)


if __name__ == "__main__":
    unittest.main()
