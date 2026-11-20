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
import shutil
import sys
import unittest
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
from depbee.service import scan_project, setup_assets

ML = importlib.util.find_spec("lightgbm") is not None
NO_ML = "Install .[ml] for the setup tests that load a native model"
SRC = str(Path(__file__).resolve().parents[1] / "src")


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
        self.assertIsNone(config.saved_dir("model_dir"))
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
        self.assertEqual(config.saved_dir("model_dir"), self.root / "assets" / "model")
        self.assertIsNone(config.saved_dir("known_malicious_dir"))
        self.assertEqual([p.name for p in self.user.iterdir()], ["config.json"])  # no leftovers
        if os.name != "nt":
            self.assertEqual((self.user / "config.json").stat().st_mode & 0o777, 0o600)
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
    """Option, then environment variable, then the saved folder, then none."""

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
                self.assertEqual(self.cli("setup"), (0, f"{cli.SETUP_NONE}\n{cli.SETUP_HOW}\n", ""))
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
        with contextlib.chdir(self.root):  # a relative folder is saved as an absolute one
            code, out, err = run_cli("setup", "assets")
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
        self.assertEqual(run_cli("setup"), (0, f"{cli.SETUP_NONE}\n{cli.SETUP_HOW}\n", ""))
        run_cli("setup", str(self.assets))
        os.environ["DEPBEE_MODEL_DIR"] = str(self.root / "elsewhere")
        code, out, err = run_cli("setup")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out.splitlines(), [
            f"저장된 자산 설정: {self.settings}",
            f"  모델: {self.assets / 'model'}",
            f"  기지 악성 색인: {self.assets / 'index'}",
            cli.SETUP_OVERRIDDEN.format(variable="DEPBEE_MODEL_DIR", name="모델")])  # fmt: skip
        self.assertEqual(run_cli("setup", "--clear"), (0, f"{cli.SETUP_CLEARED}\n", ""))
        self.assertFalse(self.settings.exists())
        self.assertEqual(run_cli("setup", "--clear"), (0, f"{cli.SETUP_NONE}\n", ""))

    def test_a_subfolder_that_does_not_exist_is_saved_as_not_connected(self):
        shutil.rmtree(self.assets / "index")
        code, out, _ = run_cli("setup", str(self.assets))
        self.assertEqual(code, 0)
        self.assertIn("  기지 악성 색인: 연결 안 됨\n", out)
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
