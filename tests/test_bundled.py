"""The model and index shipped with depbee (depbee.bundled), and where a scan takes each asset
from: option, environment variable, saved setup, then the shipped one (service._sources).

The shipped files themselves are only hashed, loaded and named: ShippedDefaultTests makes one
report with them from made-up features and asserts nothing about what they hold beyond what
their manifests say. Everything else uses synthetic stand-ins in each test run's folder: the tiny
model and the MAL-EXAMPLE indexes of test_config.NativeAssets, put in the shipped assets' place.
No network; nothing is downloaded.
"""

import hashlib
import importlib.metadata
import json
import os
import re
import shlex
import shutil
import sys
import tomllib
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

from test_config import ML, NO_ML, NativeAssets, run_cli
from test_known_malicious import AS_OF, record
from test_known_malicious_wiring import OTHER
from test_workflow import Fixture

from depbee import bundled, cli, config
from depbee.service import active_assets

# Taken before any test runs: Fixture leaves the shipped assets out of every other test.
SHIPPED = dict(bundled.DIRS)
REPOSITORY = Path(__file__).resolve().parents[1]
EXTRA = ("NOTICE.md", "LICENSE-Apache-2.0.txt")
# The LICENSE file of github.com/ossf/malicious-packages, the source of the index's records.
OPENSSF_LICENSE = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
THIRD = [record("MAL-EXAMPLE-0003", "example-third", ["1.0.0"])]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifests():
    return (json.loads((SHIPPED[key] / "manifest.json").read_bytes()) for key in config.LAYOUT)


def ship(case, assets):
    """For the rest of the test case, make assets what depbee ships: its model/ and index/, and
    the SHA-256 their four files have now as those of the released files, which it returns."""
    dirs = {key: assets / name for key, name in config.LAYOUT.items()}
    pins = {f"{folder.name}/{file.name}": sha256(file)
            for folder in dirs.values() for file in sorted(folder.iterdir())}  # fmt: skip
    case.assertEqual(sorted(pins), sorted(bundled.SHA256))  # the same four names
    for target, values in ((bundled.DIRS, dirs), (bundled.SHA256, pins)):
        patcher = mock.patch.dict(target, values, clear=True)
        patcher.start()
        case.addCleanup(patcher.stop)
    return pins


class ShippedFilesTests(unittest.TestCase):
    """What is in the package: in a checkout the source folder, in CI the installed wheel."""

    def test_the_four_files_are_the_released_ones_and_nothing_else_is_there(self):
        for relative, expected in bundled.SHA256.items():
            with self.subTest(relative):
                self.assertEqual(sha256(bundled.ROOT / relative), expected)
        found = sorted(p.relative_to(bundled.ROOT).as_posix() for p in bundled.ROOT.rglob("*")
                       if p.is_file())  # fmt: skip
        self.assertEqual(found, sorted([*bundled.SHA256, *EXTRA]))
        self.assertEqual(SHIPPED, {"model_dir": bundled.ROOT / "model",
                                   "known_malicious_dir": bundled.ROOT / "index"})  # fmt: skip

    def test_each_manifest_names_the_file_beside_it(self):
        model, index = manifests()
        self.assertEqual(model["model_sha256"], bundled.SHA256["model/model.txt"])
        self.assertEqual(index["index_sha256"], bundled.SHA256["index/index.json"])

    def test_the_notice_and_the_license_of_the_index_source_are_shipped(self):
        self.assertEqual(sha256(bundled.ROOT / "LICENSE-Apache-2.0.txt"), OPENSSF_LICENSE)
        notice = (bundled.ROOT / "NOTICE.md").read_text("utf-8")
        _, index = manifests()
        # The source and its license, the license text beside it, what was changed (the records
        # were converted) and which snapshot the shipped index was made from.
        for said in ("OpenSSF Malicious Packages", "https://github.com/ossf/malicious-packages",
                     "Apache License 2.0", "LICENSE-Apache-2.0.txt",
                     "depbee.known_malicious.build_index",
                     index["list_as_of"], index["snapshot_sha256"]):  # fmt: skip
            self.assertIn(said, notice)
        self.assertNotIn("—", notice)

    @unittest.skipUnless((REPOSITORY / "pyproject.toml").is_file(), "not run from a source tree")
    def test_the_package_ships_exactly_these_files_and_pins_the_public_analyzer(self):
        project = tomllib.loads((REPOSITORY / "pyproject.toml").read_text("utf-8"))
        shipped = sorted(f"assets/{name}" for name in (*bundled.SHA256, *EXTRA))
        self.assertEqual(sorted(project["tool"]["setuptools"]["package-data"]["depbee"]), shipped)
        listed = (REPOSITORY / "MANIFEST.in").read_text("utf-8").split()
        for name in shipped:  # the sdist
            self.assertIn(f"src/depbee/{name}", listed)
        # The base install scores with the shipped model; only [extract] brings the analyzer,
        # and the older extra names still install.
        base = project["project"]["dependencies"]
        extras = project["project"]["optional-dependencies"]
        self.assertEqual(sorted(d.split(">")[0] for d in base), ["lightgbm", "numpy"])
        analyzer = {name: needs for name, needs in extras.items() if "depbee-analyzer" in str(needs)}
        self.assertEqual(list(analyzer), ["extract"])
        # One pin: the team's public repository over HTTPS at a full commit id. An image build
        # and an action run fetch it without credentials, and the installed identity
        # (extractor._installed_identity) and action.yml's cache key read this exact form.
        (pin,) = analyzer["extract"]
        self.assertRegex(pin, r"^depbee-analyzer @ git\+https://github\.com/"
                              r"26-Capstone-Project-Team01/depbee-analyzer@[0-9a-f]{40}$")  # fmt: skip
        self.assertLessEqual({"ml", "extract", "mcp", "web"}, set(extras))
        attributes = REPOSITORY / ".gitattributes"
        if attributes.is_file():  # not in an sdist
            kept = [line.split()[0] for line in attributes.read_text("utf-8").splitlines()
                    if line.endswith(" -text")]  # fmt: skip
            self.assertEqual(sorted(kept), sorted(f"src/depbee/assets/{n}" for n in bundled.SHA256))

    @unittest.skipUnless((REPOSITORY / ".dockerignore").is_file(), "not run from a checkout")
    def test_the_docker_build_context_admits_every_file_of_the_package_data(self):
        # .dockerignore admits only what it names, and the image installs depbee from that.
        # Package data it does not name is in the wheel of a host install and missing in the
        # image, whose build still succeeds: the dashboard's script once was, and there the
        # pages answered while the script's address alone failed.
        project = tomllib.loads((REPOSITORY / "pyproject.toml").read_text("utf-8"))
        lines = (REPOSITORY / ".dockerignore").read_text("utf-8").splitlines()
        named = [line[1:] for line in lines if line.startswith("!")]
        for package, patterns in project["tool"]["setuptools"]["package-data"].items():
            folder = REPOSITORY / "src" / package.replace(".", "/")
            shipped = [file for pattern in patterns for file in folder.glob(pattern)]
            self.assertTrue(shipped, package)
            for file in shipped:
                path = PurePosixPath(file.relative_to(REPOSITORY).as_posix())
                with self.subTest(str(path)):
                    self.assertTrue(any(path.match(pattern) for pattern in named),
                                    ".dockerignore does not name it")  # fmt: skip

    @unittest.skipUnless((REPOSITORY / "Dockerfile").is_file(), "not run from a checkout")
    def test_the_image_build_can_receive_no_credential(self):
        # The default build installs the pinned public analyzer anonymously. No instruction
        # takes a build argument or mounts a secret, and the default target (the last stage)
        # is the one with the analyzer; core stays a target of its own.
        text = (REPOSITORY / "Dockerfile").read_text("utf-8")
        self.assertNotRegex(text, r"(?m)^\s*(ARG\b|RUN\s+--mount)")
        stages = re.findall(r"(?m)^FROM \S+ AS (\S+)$", text)
        self.assertEqual(stages[-1], "full")
        self.assertIn("core", stages)


class ShippedDefaultTests(Fixture):
    """With no option, variable or saved setup: the real shipped model and index."""

    def setUp(self):
        super().setUp()
        shipped = mock.patch.dict(bundled.DIRS, SHIPPED)
        shipped.start()
        self.addCleanup(shipped.stop)

    def scan(self, form):
        code, out, err = run_cli("scan", str(self.project), "--base-lock", str(self.base),
                                 "--analysis", str(self.root / "analysis.json"),
                                 "--format", form)  # fmt: skip
        self.assertEqual(err, "")
        return code, out

    @unittest.skipUnless(ML, NO_ML)
    def test_a_scan_of_trusted_features_uses_them_and_every_format_names_them(self):
        model, index = manifests()
        categories = model.get("categorical_features", {})

        def made_up(name):
            """A value of the feature's type, to reach the model: no claim about the score."""
            if name in model.get("boolean_features", ()):
                return False
            if name in categories:
                return categories[name][0]
            return None if name in model.get("nullable_features", ()) else 0

        features = {name: made_up(name) for name in model["feature_names"]}
        self.adapter({**self.artifact(features), "feature_schema": model["feature_schema"]})
        code, out = self.scan("json")
        report = json.loads(out)
        self.assertEqual(code, report["exit_code"])
        self.assertIn(code, (0, 1))  # scored: not held for a missing model
        self.assertEqual((report["model_id"], report["threshold"]),
                         (model["model_id"], model["threshold"]))  # fmt: skip
        self.assertEqual(report["provenance"]["model"], {
            "model_sha256": bundled.SHA256["model/model.txt"],
            "manifest_sha256": bundled.SHA256["model/manifest.json"]})  # fmt: skip
        self.assertEqual(report["detectors"]["known_malicious"], {
            "source": index["source"], "list_as_of": index["list_as_of"],
            "list_sha256": bundled.SHA256["index/index.json"]})  # fmt: skip
        row = report["results"][0]
        self.assertIn(row["ml"]["status"], ("hit", "not_hit"))
        self.assertIn(row["known_malicious"]["status"], ("hit", "not_hit"))  # compared
        self.assertTrue(0 <= row["score"] <= 1)
        _, text = self.scan("text")
        self.assertIn(f"모델: {model['model_id']}, 판정 기준 점수 {model['threshold']}\n", text)
        self.assertIn(f"기지 악성 목록: {index['source']}, 기준 시점 {index['list_as_of']}\n", text)
        _, markdown = self.scan("markdown")
        self.assertIn(f"- 모델: ` {model['model_id']} `, 판정 기준 점수 {model['threshold']}\n",
                      markdown)  # fmt: skip
        self.assertIn(f"- 기지 악성 목록: ` {index['source']} `, 기준 시점 ` {index['list_as_of']} `\n",
                      markdown)  # fmt: skip

    @unittest.skipUnless(ML, NO_ML)
    def test_setup_shows_them_with_their_folders_and_writes_nothing(self):
        model, index = manifests()
        code, out, err = run_cli("setup")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out.splitlines(), [
            cli.SETUP_NONE,
            f"  모델: {SHIPPED['model_dir']} (모델 ID {model['model_id']}, depbee 동봉 기본값)",
            f"  기지 악성 색인: {SHIPPED['known_malicious_dir']} "
            f"(기준 시점 {index['list_as_of']}, depbee 동봉 기본값)",
            cli.SETUP_HOW])  # fmt: skip
        self.assertFalse((self.root / "user").exists())  # no settings folder, no settings file


@unittest.skipUnless(ML, NO_ML)
class ResolverTests(NativeAssets):
    """Synthetic assets in the shipped ones' place: self.assets, whose model is
    "synthetic-test-only" and whose index lists the lockfile's new version."""

    def ship(self):
        ship(self, self.assets)

    def another(self, name, records):
        """An asset folder of the user's: the same model under the ID name, and its own index.
        Returns (folder, index.json sha256)."""
        folder = self.root / name
        shutil.copytree(self.assets / "model", folder / "model")
        self.write(folder / "model" / "manifest.json", {**self.manifest, "model_id": name})
        index, index_sha = self.index(records)
        index.rename(folder / "index")
        return folder, index_sha

    def scan(self, *options, form="json"):
        self.adapter()
        return run_cli("scan", str(self.project), "--base-lock", str(self.base), "--analysis",
                       str(self.root / "analysis.json"), "--format", form, *options)  # fmt: skip

    def used(self, *options):
        """(model_id, list_sha256) of the report of a scan with these options."""
        code, out, err = self.scan(*options)
        self.assertEqual(err, "")
        report = json.loads(out)
        return report["model_id"], report["detectors"]["known_malicious"]["list_sha256"]

    def failed(self, *options):
        """The error of a scan that stops with exit code 2 and no report."""
        code, out, err = self.scan(*options)
        self.assertEqual((code, out), (2, ""))
        return json.loads(err)["error"]

    def test_each_asset_is_the_first_of_option_variable_saved_and_shipped(self):
        self.ship()
        shipped = ("synthetic-test-only", self.index_sha)
        saved, saved_sha = self.another("saved", OTHER)
        variable, variable_sha = self.another("variable", THIRD)
        option, option_sha = self.another("option", OTHER + THIRD)
        self.assertEqual(self.used(), shipped)  # nothing configured
        self.assertEqual(run_cli("setup", str(saved))[0], 0)
        self.assertEqual(self.used(), ("saved", saved_sha))
        os.environ["DEPBEE_MODEL_DIR"] = str(variable / "model")
        self.assertEqual(self.used(), ("variable", saved_sha))  # each asset on its own
        os.environ["DEPBEE_KNOWN_MALICIOUS_DIR"] = str(variable / "index")
        self.assertEqual(self.used(), ("variable", variable_sha))
        self.assertEqual(self.used("--model-dir", str(option / "model")),
                         ("option", variable_sha))  # fmt: skip
        self.assertEqual(self.used("--known-malicious-dir", str(option / "index")),
                         ("variable", option_sha))  # fmt: skip
        os.environ["DEPBEE_MODEL_DIR"] = os.environ["DEPBEE_KNOWN_MALICIOUS_DIR"] = ""  # unset
        self.assertEqual(self.used(), ("saved", saved_sha))
        self.assertEqual(run_cli("setup", "--clear"), (0, f"{cli.SETUP_CLEARED}\n", ""))
        self.assertEqual(self.used(), shipped)  # both shipped again

    def test_saved_settings_that_name_one_asset_leave_the_other_to_the_shipped_one(self):
        """Settings of an earlier depbee, saved from a folder with only one of the two: the null
        was "not connected" then. Now it is the shipped asset, and the saved one stays."""
        self.ship()
        saved, saved_sha = self.another("saved", OTHER)
        config.save(saved, None, saved / "index")
        self.assertEqual(self.used(), ("synthetic-test-only", saved_sha))
        config.save(saved, saved / "model", None)
        self.assertEqual(self.used(), ("saved", self.index_sha))
        code, out, err = run_cli("setup")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out.splitlines()[1:], [
            f"  모델: {saved / 'model'} (모델 ID saved, 저장된 설정)",
            f"  기지 악성 색인: {self.assets / 'index'} (기준 시점 {AS_OF}, depbee 동봉 기본값)"])  # fmt: skip
        shutil.rmtree(saved / "index")  # and what depbee setup saves from such a folder now
        code, out, _ = run_cli("setup", str(saved))
        self.assertEqual(code, 0)
        self.assertIn(f"  기지 악성 색인: {cli.SETUP_DEFAULT}\n", out)
        self.assertEqual(self.used(), ("saved", self.index_sha))

    def test_what_a_source_names_is_used_or_is_an_error_never_the_next_source(self):
        """The shipped assets load, and would pass what the user's own index flags: a folder
        that is gone or changed stops the scan instead."""
        self.ship()
        saved, _ = self.another("saved", OTHER)
        self.assertEqual(run_cli("setup", str(saved))[0], 0)
        shutil.rmtree(saved / "model")  # gone after the setup
        self.assertIn(repr(str(saved / "model" / "manifest.json")), self.failed())
        os.environ["DEPBEE_MODEL_DIR"] = str(self.assets / "model")  # so that the index is read
        (saved / "index" / "index.json").write_bytes(b"{}")  # changed after the setup
        self.assertIn("SHA-256 does not match the manifest's index_sha256", self.failed())
        code, out, err = run_cli("setup")  # and setup says which one it is
        self.assertEqual((code, err), (2, ""))
        self.assertIn(f"  기지 악성 색인: {saved / 'index'} (저장된 설정, 읽지 못함: ", out)
        self.assertEqual(run_cli("setup", "--clear")[0], 0)
        gone = self.root / "not-there"
        os.environ["DEPBEE_MODEL_DIR"] = str(gone)
        self.assertIn("not-there", self.failed())
        os.environ.pop("DEPBEE_MODEL_DIR")
        self.assertIn("Known malicious index manifest cannot be read",
                      self.failed("--known-malicious-dir", str(gone)))  # fmt: skip
        self.assertEqual(self.used(), ("synthetic-test-only", self.index_sha))  # still fine

    def test_shipped_files_that_are_not_the_released_ones_are_refused(self):
        """Each change leaves its folder agreeing with itself or is caught by the loader anyway;
        what stops it here is the SHA-256 fixed in code, before the changed bytes are parsed
        (test_bundled_integrity.py has the loaders' side of it)."""
        import lightgbm

        self.ship()
        released = self.root / "released"
        shutil.copytree(self.assets, released)
        model, index = self.assets / "model", self.assets / "index"
        other, _ = self.index(OTHER)
        tree = (model / "model.txt").read_bytes() + b"\n"

        def another_model():
            (model / "model.txt").write_bytes(tree)
            self.write(model / "manifest.json", {
                **self.manifest, "model_sha256": hashlib.sha256(tree).hexdigest()})  # fmt: skip

        # What is changed, by the first file whose bytes are not the released ones: the
        # manifest is read before the file it names.
        changes = {
            # The model's hash in it still right, the threshold one that flags nothing.
            "model/manifest.json": lambda: self.write(
                model / "manifest.json", {**self.manifest, "threshold": 0.999}),
            "model/model.txt": lambda: (model / "model.txt").write_bytes(tree),
            "model/manifest.json and its model": another_model,
            # Another valid index with its own manifest: one that does not list the version.
            "index/manifest.json and its index": lambda: shutil.copytree(
                other, index, dirs_exist_ok=True),
            "index/index.json": lambda: shutil.copy(other / "index.json", index / "index.json"),
            "index/manifest.json": lambda: self.write(
                index / "manifest.json", json.loads((index / "manifest.json").read_bytes())),
        }  # fmt: skip
        for changed, change in changes.items():
            with self.subTest(changed):
                shutil.rmtree(self.assets)
                shutil.copytree(released, self.assets)
                change()
                with mock.patch.object(lightgbm, "Booster", wraps=lightgbm.Booster) as booster:
                    error = self.failed()
                name = changed.split()[0]
                what = "model" if name.startswith("model/") else "known malicious index"
                self.assertIn(f"The {what} shipped with depbee cannot be loaded (", error)
                self.assertIn(f"{name} is not the released file (SHA-256 mismatch)", error)
                self.assertIn("; reinstall depbee: ", error)
                # A changed model is not given to LightGBM; the index is read after the model.
                self.assertEqual(booster.called, what != "model")
                code, out, err = run_cli("setup")
                self.assertEqual((code, err), (2, ""))
                self.assertIn("(depbee 동봉 기본값, 읽지 못함: ", out)
                self.assertFalse(self.settings.exists())  # nothing saved in its place
        shutil.rmtree(self.assets / "index")  # a damaged installation: files missing
        error = self.failed()
        self.assertIn("The known malicious index shipped with depbee cannot be loaded (", error)
        self.assertIn("reinstall depbee", error)

    def test_setup_and_reports_name_the_assets_in_use(self):
        self.ship()
        in_use = {
            "model_dir": {"source": "bundled", "folder": str(self.assets / "model"),
                          "version": "synthetic-test-only", "error": None},
            "known_malicious_dir": {"source": "bundled", "folder": str(self.assets / "index"),
                                    "version": AS_OF, "error": None},
        }  # fmt: skip
        self.assertEqual(active_assets(), in_use)
        code, out, err = run_cli("setup")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out.splitlines(), [
            cli.SETUP_NONE,
            f"  모델: {self.assets / 'model'} (모델 ID synthetic-test-only, depbee 동봉 기본값)",
            f"  기지 악성 색인: {self.assets / 'index'} (기준 시점 {AS_OF}, depbee 동봉 기본값)",
            cli.SETUP_HOW])  # fmt: skip
        self.assertFalse(self.settings.parent.exists())  # showing writes nothing
        code, text, _ = self.scan(form="text")
        self.assertEqual(code, 1)  # the shipped index lists the new version
        self.assertIn("모델: synthetic-test-only, 판정 기준 점수 0.5\n", text)
        self.assertIn(f"기지 악성 목록: OSV npm MAL, 기준 시점 {AS_OF}\n", text)
        _, markdown, _ = self.scan(form="markdown")
        self.assertIn("- 모델: ` synthetic-test-only `, 판정 기준 점수 0.5\n", markdown)
        self.assertIn(f"- 기지 악성 목록: ` OSV npm MAL `, 기준 시점 ` {AS_OF} `\n", markdown)
        # Another model by the variable: the same places name that one, and the option of a
        # caller that has one (the dashboard, the MCP server) comes before both.
        variable, _ = self.another("variable", THIRD)
        os.environ["DEPBEE_MODEL_DIR"] = str(variable / "model")
        self.assertIn("모델: variable, 판정 기준 점수 0.5\n", self.scan(form="text")[1])
        self.assertIn(f"  모델: {variable / 'model'} (모델 ID variable, 환경 변수 DEPBEE_MODEL_DIR)\n",
                      run_cli("setup")[1])  # fmt: skip
        self.assertEqual(active_assets(model_dir=self.assets / "model"), {
            **in_use, "model_dir": {**in_use["model_dir"], "source": "option"}})  # fmt: skip

    def test_without_the_extract_extra_trusted_features_are_scored_and_extraction_says_how(self):
        """The base install: no depbee-analyzer. A trusted analysis file is still scored with
        the shipped model and compared with the shipped index, and an extraction ends with
        advice that works where that depbee runs."""
        self.ship()
        missing = dict.fromkeys(
            ("depbee_analyzer", "depbee_analyzer.core", "depbee_analyzer.core.errors"))
        pin = ("depbee-analyzer @ git+https://github.com/26-Capstone-Project-Team01/"
               "depbee-analyzer@" + "a" * 40)  # fmt: skip

        def advice(requires):
            """The error of scan --extract for a depbee whose metadata requires this."""
            with mock.patch("importlib.metadata.requires", **requires):
                code, out, err = run_cli("scan", str(self.project), "--base-lock",
                                         str(self.base), "--extract", "--format", "json")  # fmt: skip
            self.assertEqual((code, out), (2, ""))
            return json.loads(err)["error"]

        installed = {"return_value": ["numpy>=1.26", f'{pin}; extra == "extract"']}
        unknown = {"side_effect": importlib.metadata.PackageNotFoundError("depbee")}
        # The Python of a virtual environment that is not activated, in a folder with a space
        # and a quote. The shell's own "python" may then be another environment's.
        windows = os.name == "nt"
        python = (r"C:\Users\O'Brien\my env\Scripts\python.exe" if windows
                  else "/home/o'brien/my env/bin/python")  # fmt: skip

        def command(said):
            """The command of an instruction: after its colon, before the import error."""
            return said.partition(": ")[2].rpartition(" (")[0]

        with mock.patch.dict(sys.modules, missing):
            self.assertEqual(self.used(), ("synthetic-test-only", self.index_sha))
            with mock.patch.object(sys, "executable", python):
                pinned, extra = advice(installed), advice(unknown)
            # An installed depbee names the public commit it pins and the Python that runs it:
            # a command for any folder and any PATH. A bare "python" could be another
            # environment's, and the old ".[extract]" meant whatever project the user stood in.
            self.assertTrue(pinned.startswith(
                "depbee-analyzer is missing. Install the commit that this depbee pins into the "
                "Python that runs it"), pinned)  # fmt: skip
            # Run from a source tree, depbee has no metadata to name a commit from.
            self.assertTrue(extra.startswith(
                "depbee-analyzer is missing. In a depbee checkout, install it into the Python "
                "that runs depbee"), extra)  # fmt: skip
            for said, requirement in ((pinned, pin), (extra, ".[extract]")):
                with self.subTest(requirement):
                    if windows:  # PowerShell: & calls a quoted path, '' is a quote inside one
                        self.assertIn(", in PowerShell: & ", said)
                        self.assertEqual(
                            command(said),
                            r"& 'C:\Users\O''Brien\my env\Scripts\python.exe' -m pip install "
                            f"'{requirement}'")  # fmt: skip
                    else:  # what a POSIX shell reads: that interpreter and one requirement
                        self.assertEqual(shlex.split(command(said)),
                                         [python, "-m", "pip", "install", requirement])  # fmt: skip
            # depbee's image has no pip and no source tree: the default image, not an install.
            with mock.patch.dict(os.environ, {"DEPBEE_CONTAINER_PROJECTS": "/projects"}):
                in_image = advice(installed)
            self.assertIn("built with --target core", in_image)
            self.assertIn("docker build -t depbee:local .", in_image)
            self.assertNotIn("pip", in_image)


if __name__ == "__main__":
    unittest.main()
