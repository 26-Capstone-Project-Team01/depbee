"""depbee update (preview): npm is always mocked; no test runs npm, Node.js or the registry."""

import contextlib
import hashlib
import io
import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

from test_workflow import FakePredictor, Fixture

from depbee.cli import main
from depbee.contracts import GuardError
from depbee.inputs import git as git_input
from depbee.inputs import npm_cli
from depbee.service import NPMRC_NOTICE, PREVIEW_NOTICE, preview_update, scan_project

NPMRC_SECRET = "//registry.example.invalid/:_authToken=synthetic-token-not-real"
ERROR_SECRET = b"https://user:synthetic-token@registry.example.invalid/"


def without_times(report):
    report = {k: v for k, v in report.items() if k != "elapsed_seconds"}
    report["results"] = [
        {k: v for k, v in row.items() if k != "elapsed_seconds"} for row in report["results"]
    ]
    return report


class UpdateFixture(Fixture):
    def setUp(self):
        super().setUp()
        # The project to preview: old lock; the fake npm writes the fixture's new lock.
        self.upd = self.root / "upd"
        self.upd.mkdir()
        self.package = {"name": "app", "dependencies": {"example": "^1.0.0"}}
        self.write(self.upd / "package.json", self.package)
        (self.upd / "package-lock.json").write_bytes(self.base.read_bytes())
        # A fake Node.js install; nothing in it is executed because _run is mocked.
        if os.name == "nt":
            self.node = self.root / "nodejs" / "node.exe"
            self.npm_js = self.node.parent / "node_modules" / "npm" / "bin" / "npm-cli.js"
        else:
            self.node = self.root / "nodejs" / "bin" / "node"
            self.npm_js = (
                self.root / "nodejs" / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"
            )
        self.npm_js.parent.mkdir(parents=True)
        self.npm_js.write_text("// never run\n", encoding="utf-8")
        self.which = self.patch("depbee.inputs.npm_cli.shutil.which", return_value=str(self.node))
        self.calls = []
        self.npm_update = self.write_new_lock
        self.run = self.patch("depbee.inputs.npm_cli._run", side_effect=self.fake_run)
        extractor = self.patch("depbee.analysis.extractor.ExtractorAnalyzer")
        extractor.return_value.analyze.side_effect = lambda request: self.artifact()
        extractor.return_value.measurements = {}
        self.patch("depbee.service.LightGBMPredictor", return_value=FakePredictor())

    def patch(self, target, **kwargs):
        patcher = mock.patch(target, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def fake_run(self, argv, cwd, limit, env=None, **kwargs):
        self.calls.append({"argv": argv, "cwd": Path(cwd), "env": env, "kwargs": kwargs})
        # The work folder holds only the copies when npm starts.
        self.work_files = sorted(p.name for p in Path(cwd).iterdir())
        if argv[2:] == ["--version"]:
            return 0, b"11.6.1\n", b""
        return self.npm_update(Path(cwd))

    def write_new_lock(self, work):
        (work / "package-lock.json").write_bytes(self.head.read_bytes())
        return 0, b"changed 1 package\n", b""

    def project_state(self):
        return {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.upd.iterdir()
            if p.is_file()
        }

    def preview(self, packages=None):
        return preview_update(self.upd, packages, model_dir=self.root)

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["update", "--project", str(self.upd), "--model-dir", str(self.root),
                         *args])  # fmt: skip
        return code, out.getvalue(), err.getvalue()


class PreviewTests(UpdateFixture):
    def test_argv_runs_node_with_npm_cli_and_fixed_options_before_double_dash(self):
        self.preview(["example"])
        version, update = (call["argv"] for call in self.calls)
        self.assertEqual(version, [str(self.node), str(self.npm_js), "--version"])
        self.assertEqual(update, [
            str(self.node), str(self.npm_js), "update", "--package-lock-only", "--ignore-scripts",
            "--no-audit", "--no-fund", "--no-update-notifier", "--no-progress", "--color=false",
            "--loglevel=warn", "--", "example",
        ])  # fmt: skip
        self.assertEqual(update.index("--"), len(update) - 2)  # names only after "--"
        for call in self.calls:
            self.assertEqual(call["kwargs"], {"timeout": 120, "stderr_limit": 65536, "name": "npm"})
            self.assertNotEqual(call["cwd"], self.upd)
        self.assertEqual(self.run.call_args.args[2], 1024 * 1024)
        self.assertEqual(self.which.call_args.args[0], "node.exe" if os.name == "nt" else "node")

    def test_no_names_updates_everything(self):
        result = self.preview()
        self.assertEqual(self.calls[1]["argv"][-1], "--")
        self.assertIsNone(result["preview"]["targets"])

    def test_environment_drops_npm_config_and_node_options(self):
        os.environ.update({
            "npm_config_registry": "https://registry.example.invalid/",
            "NPM_CONFIG_USERCONFIG": str(self.root / "other-npmrc"),
            "Npm_Config_Ignore_Scripts": "false",
            "NODE_OPTIONS": "--require ./x.js",
            "DEPBEE_KEEP": "1",
        })  # fmt: skip
        self.preview()
        for call in self.calls:
            env = call["env"]
            self.assertFalse([k for k in env if k.lower().startswith("npm_config_")
                              and k != "npm_config_ignore_scripts"])  # fmt: skip
            self.assertNotIn("NODE_OPTIONS", {k.upper() for k in env})
            self.assertEqual(env["npm_config_ignore_scripts"], "true")
            self.assertEqual(env["DEPBEE_KEEP"], "1")
        self.assertEqual(os.environ["NODE_OPTIONS"], "--require ./x.js")  # parent unchanged

    def test_preview_hashes_and_report_equal_scan_project(self):
        before = self.project_state()
        result = self.preview(["example"])
        preview = result["preview"]
        self.assertEqual(list(result), ["preview", "report"])
        self.assertEqual(preview, {
            "targets": ["example"],
            "npm_version": "11.6.1",
            "package_json_sha256": before["package.json"],
            "package_lock_sha256": before["package-lock.json"],
            "new_package_lock_sha256": hashlib.sha256(self.head.read_bytes()).hexdigest(),
            "package_json_changed": False,
            "changed_count": 1,
            "project_npmrc_ignored": False,
            "notices": [PREVIEW_NOTICE],
        })  # fmt: skip
        expected = scan_project(self.project, self.base, extract=True, model_dir=self.root)
        self.assertEqual(without_times(result["report"]), without_times(expected))
        self.assertEqual(result["report"]["exit_code"], 1)  # FakePredictor scores 0.9
        self.assertEqual(self.project_state(), before)
        self.assertEqual(self.work_files, ["package-lock.json", "package.json"])
        # The temporary folder is removed.
        self.assertFalse([p for p in self.root.iterdir() if p.name.startswith("depbee_preview_")])

    def test_nothing_to_update_exits_0(self):
        self.npm_update = lambda work: (0, b"", b"")
        result = self.preview()
        self.assertEqual(result["report"]["results"], [])
        self.assertEqual(result["report"]["exit_code"], 0)
        self.assertEqual(result["preview"]["changed_count"], 0)
        self.assertEqual(
            result["preview"]["new_package_lock_sha256"], result["preview"]["package_lock_sha256"]
        )
        code, _, err = self.cli("--format", "json")
        self.assertEqual((code, err), (0, ""))

    def test_changed_package_json_is_reported(self):
        def update(work):
            (work / "package.json").write_text('{"name": "changed"}', encoding="utf-8")
            return self.write_new_lock(work)

        self.npm_update = update
        before = self.project_state()
        self.assertTrue(self.preview()["preview"]["package_json_changed"])
        self.assertEqual(self.project_state(), before)

    def test_npmrc_is_not_copied_and_a_notice_is_shown(self):
        (self.upd / ".npmrc").write_text(NPMRC_SECRET + "\n", encoding="utf-8")
        before = self.project_state()
        result = self.preview()
        self.assertNotIn(".npmrc", self.work_files)
        self.assertTrue(result["preview"]["project_npmrc_ignored"])
        self.assertEqual(result["preview"]["notices"], [NPMRC_NOTICE, PREVIEW_NOTICE])
        for fmt in ("text", "markdown", "json"):
            with self.subTest(format=fmt):
                code, out, err = self.cli("--format", fmt)
                self.assertEqual(code, 1)
                self.assertNotIn("synthetic-token", out + err)
                if fmt != "json":
                    self.assertIn(NPMRC_NOTICE, out)
                    self.assertIn(PREVIEW_NOTICE, out)
        self.assertEqual(self.project_state(), before)


class RefusalTests(UpdateFixture):
    def assert_refused(self, *packages, message=None):
        before = self.project_state()
        with self.assertRaisesRegex(GuardError, message or ""):
            self.preview(list(packages))
        self.run.assert_not_called()
        self.assertEqual(self.project_state(), before)

    def test_names_other_than_bare_declared_names_are_refused(self):
        bad = ["--save", "-x", ".hidden", "_private", "@scope/_x", "@-x/y", "lodash é", "é",
               "a b", "a:b", "a\\b", "a%b", "a&b", "a|b", "a^b", "a<b", "a>b", 'a"b', "",
               "x" * 215, "example@1.1.0", "example@^1.0.0", "../example", "example\n"]  # fmt: skip
        for name in bad:
            with self.subTest(name=name):
                self.assert_refused(name, message="names only")
        self.assert_refused("left-pad", message="not a dependency in package.json")

    def test_declared_names_in_each_dependency_field_are_accepted(self):
        self.write(self.upd / "package.json", {
            "dependencies": {"example": "^1.0.0"},
            "devDependencies": {"@types/node": "^20.0.0"},
            "optionalDependencies": {"fsevents": "~2.3.0"},
        })  # fmt: skip
        self.preview(["example", "@types/node", "fsevents"])
        self.assertEqual(self.calls[1]["argv"][-3:], ["example", "@types/node", "fsevents"])

    def test_unsupported_projects_are_refused_before_npm(self):
        lock = json.loads(self.base.read_text(encoding="utf-8"))
        entry = lock["packages"]["node_modules/example"]
        cases = {
            "git": {**entry, "resolved": "git+ssh://git@github.com/x/example.git#abc"},
            "file": {**entry, "resolved": "file:../example"},
            "http": {**entry, "resolved": "http://registry.npmjs.org/example/-/example-1.0.0.tgz"},
            "other registry": {**entry, "resolved": "https://registry.example.invalid/e.tgz"},
            "link": {"resolved": "../example", "link": True},
            "no resolved": {"version": "1.0.0"},
        }
        for name, record in cases.items():
            with self.subTest(lock=name):
                changed = json.loads(json.dumps(lock))
                changed["packages"]["node_modules/example"] = record
                self.write(self.upd / "package-lock.json", changed)
                self.assert_refused(message="lockfile|link or workspace")
        self.write(self.upd / "package-lock.json", lock)
        workspace = json.loads(json.dumps(lock))
        workspace["packages"]["packages/a"] = {"version": "1.0.0"}
        self.write(self.upd / "package-lock.json", workspace)
        self.assert_refused(message="link or workspace")
        self.write(self.upd / "package-lock.json", lock)
        for spec in ("github:x/example", "x/example", "file:../example", "npm:other@1"):
            with self.subTest(spec=spec):
                self.write(self.upd / "package.json", {"dependencies": {"example": spec}})
                self.assert_refused(message="registry ranges")
        self.write(self.upd / "package.json", {**self.package, "workspaces": ["packages/*"]})
        self.assert_refused(message="workspaces")
        self.write(self.upd / "package.json", self.package)
        (self.upd / "npm-shrinkwrap.json").write_text("{}", encoding="utf-8")
        self.assert_refused(message="npm-shrinkwrap.json")
        (self.upd / "npm-shrinkwrap.json").unlink()
        (self.upd / "package.json").unlink()
        self.assert_refused(message="regular file")

    def test_bundled_entries_without_resolved_are_allowed(self):
        lock = json.loads(self.base.read_text(encoding="utf-8"))
        lock["packages"]["node_modules/example/node_modules/inner"] = {
            "version": "1.0.0",
            "inBundle": True,
        }
        self.write(self.upd / "package-lock.json", lock)
        npm_cli.read_project(self.upd)

    def test_cli_refusals_end_with_exit_2(self):
        for args in (["--", "--save"], ["example@1.1.0"], ["left-pad"]):
            with self.subTest(args=args):
                code, out, err = self.cli(*args)
                self.assertEqual((code, out), (2, ""))
                self.assertEqual(json.loads(err)["exit_code"], 2)
        self.run.assert_not_called()


class NpmFailureTests(UpdateFixture):
    def assert_error(self, message):
        before = self.project_state()
        code, out, err = self.cli("--format", "json")
        self.assertEqual((code, out), (2, ""))
        error = json.loads(err)["error"]
        self.assertRegex(error, message)
        self.assertNotIn("synthetic-token", error)
        self.assertEqual(self.project_state(), before)
        self.assertFalse([p for p in self.root.iterdir() if p.name.startswith("depbee_preview_")])

    def test_npm_exit_code_is_an_error_without_npm_output(self):
        self.npm_update = lambda work: (1, ERROR_SECRET, ERROR_SECRET)
        self.assert_error("npm update failed with exit code 1")

    def test_timeout_and_os_errors(self):
        def timeout(work):
            raise GuardError("npm did not finish within 120 seconds")

        self.npm_update = timeout
        self.assert_error("did not finish")

        def missing(work):
            raise FileNotFoundError(2, "No such file or directory", str(ERROR_SECRET))

        self.npm_update = missing
        self.assert_error("Unable to run npm: No such file or directory")

    def test_node_modules_created_is_an_error(self):
        def update(work):
            (work / "node_modules").mkdir()
            return self.write_new_lock(work)

        self.npm_update = update
        self.assert_error("node_modules")

    def test_invalid_new_lockfile_is_an_error(self):
        def update(work):
            (work / "package-lock.json").write_text("{", encoding="utf-8")
            return 0, b"", b""

        self.npm_update = update
        self.assert_error("Invalid JSON")

    def test_bad_npm_version_output_is_an_error(self):
        self.run.side_effect = lambda argv, *a, **k: (0, ERROR_SECRET, b"")
        self.assert_error("Cannot read the npm version")

    def test_node_lookup_refuses_non_exe_relative_and_missing_cli(self):
        cases = [str(self.root / "nodejs" / "node.cmd"), "node.exe"] if os.name == "nt" else []
        cases += [None, "node"]
        for found in cases:
            with self.subTest(found=found):
                self.which.return_value = found
                self.assert_error("not found on PATH")
        self.which.return_value = str(self.node)
        self.npm_js.unlink()
        self.assert_error("npm-cli.js not found")
        self.run.assert_not_called()


class GenericRunTests(unittest.TestCase):
    def test_run_takes_a_timeout_and_a_name(self):
        began = time.monotonic()
        with self.assertRaisesRegex(GuardError, "npm did not finish within 0.5 seconds"):
            git_input._run([sys.executable, "-I", "-c", "import time; time.sleep(60)"],
                           Path.cwd(), 100, timeout=0.5, name="npm")  # fmt: skip
        self.assertLess(time.monotonic() - began, 10)
        code = "import sys; sys.stderr.buffer.write(b'x' * 200)"
        with self.assertRaisesRegex(GuardError, "npm output exceeds 100 bytes \\(stderr 50\\)"):
            git_input._run([sys.executable, "-I", "-c", code], Path.cwd(), 100,
                           stderr_limit=50, name="npm")  # fmt: skip
