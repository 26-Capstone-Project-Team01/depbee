import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from depbee.analysis.artifact import ArtifactAnalyzer
from depbee.cli import _progress, main
from depbee.contracts import MAX_JSON_BYTES, GuardError, finite_number, read_json
from depbee.inference.lightgbm import LightGBMPredictor
from depbee.inputs import git as git_input
from depbee.inputs.npm import build_request
from depbee.pipeline import scan
from depbee.service import plan_project, scan_project


def package(version="1.0.0"):
    return {
        "version": version,
        "resolved": f"https://registry.npmjs.org/example/-/example-{version}.tgz",
        "integrity": "sha512-test-only-not-an-archive-digest",
    }


class Fixture(unittest.TestCase):
    # analysis.bounded runs steps in child processes, which do not see this process's mock
    # patches (a patched registry would be the real one there). Tests run them in-process;
    # test_bounded.py turns this off and gives its child jobs their own synthetic I/O.
    bounded_in_process = True

    def setUp(self):
        # Keep synthetic test outputs inside the workspace, with inherited directory ACLs.
        self.test_runs = Path(__file__).resolve().parents[1] / "artifacts" / "test-runs"
        self.root = self.test_runs / uuid.uuid4().hex
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup_run)
        # Code under test that unpacks tarballs uses tempfile; keep that inside this run too.
        temp = mock.patch("tempfile.tempdir", str(self.root))
        temp.start()
        self.addCleanup(temp.stop)
        if self.bounded_in_process:
            here = mock.patch("depbee.analysis.bounded.run", side_effect=lambda f, args: f(*args))
            here.start()
            self.addCleanup(here.stop)
        # A developer's DEPBEE_MODEL_DIR or DEPBEE_KNOWN_MALICIOUS_DIR must not change service and
        # CLI results.
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("DEPBEE_MODEL_DIR", None)
        os.environ.pop("DEPBEE_KNOWN_MALICIOUS_DIR", None)
        # The local history (depbee.history) stays in this run; the file is not created.
        os.environ["DEPBEE_HISTORY_DB"] = str(self.root / "history.sqlite3")
        self.project = self.root / "project"
        self.project.mkdir()
        self.base = self.root / "base.json"
        self.head = self.project / "package-lock.json"
        self.old = {"lockfileVersion": 3, "packages": {"node_modules/example": package()}}
        self.new = copy.deepcopy(self.old)
        self.new["packages"]["node_modules/example"] = package("1.1.0")
        self.save_locks()

    def cleanup_run(self):
        resolved = self.root.resolve()
        if resolved.parent != self.test_runs.resolve() or self.root.is_symlink():
            raise RuntimeError("Refusing to remove a test directory outside artifacts/test-runs")
        shutil.rmtree(resolved)

    def write(self, path, obj):
        path.write_text(json.dumps(obj), encoding="utf-8")

    def save_locks(self):
        self.write(self.base, self.old)
        self.write(self.head, self.new)

    def request(self):
        return build_request(self.project, self.base)

    def artifact(self, features=None):
        request = self.request()
        return {
            "schema_version": 1,
            "request_id": request["request_id"],
            "feature_schema": "test-v1",
            "analyzer_version": "test-only",
            "results": [{
                "change_id": c["change_id"], "status": "complete",
                "features": features or {"signal": 0.9}, "evidence": ["synthetic evidence"],
            } for c in request["changes"] if c["analyzable"]],
        }

    def adapter(self, artifact=None):
        path = self.root / "analysis.json"
        self.write(path, artifact if artifact is not None else self.artifact())
        return ArtifactAnalyzer(path)


class FakePredictor:
    """Only used to test orchestration, never shipped as a detection backend."""
    feature_schema = "test-v1"
    feature_names = ["signal"]
    threshold = 0.5
    model_id = "unit-test"

    def predict(self, features):
        return features["signal"]


class InputTests(Fixture):
    def test_updates_and_nested_dependencies(self):
        self.old["packages"]["node_modules/a/node_modules/@scope/pkg"] = package()
        self.new["packages"]["node_modules/a/node_modules/@scope/pkg"] = package("2.0.0")
        self.save_locks()
        changes = self.request()["changes"]
        self.assertEqual(len(changes), 2)
        self.assertTrue(all(c["analyzable"] for c in changes))
        self.assertEqual(changes[0]["after"]["name"], "@scope/pkg")

    def test_v1_rejected(self):
        self.new["lockfileVersion"] = 1
        self.save_locks()
        with self.assertRaises(GuardError):
            self.request()

    def test_source_and_integrity_changes_not_ignored(self):
        self.new = copy.deepcopy(self.old)
        self.new["packages"]["node_modules/example"]["integrity"] = "sha512-other"
        self.save_locks()
        self.assertEqual(self.request()["changes"][0]["reason"], "same_version_artifact_changed")

    def test_non_registry_is_incomplete(self):
        self.new["packages"]["node_modules/example"]["resolved"] = "https://evil.test/a.tgz"
        self.save_locks()
        self.assertEqual(scan(self.request(), None, None)["exit_code"], 2)

    def test_added_is_analyzed_not_silently_allowed(self):
        self.new["packages"]["node_modules/new"] = package()
        self.save_locks()
        added = [c for c in self.request()["changes"] if c["kind"] == "added"]
        self.assertTrue(added[0]["analyzable"])
        artifact = self.artifact()
        artifact["results"] = [r for r in artifact["results"] if r["change_id"] != added[0]["change_id"]]
        report = scan(self.request(), self.adapter(artifact), FakePredictor())
        self.assertEqual(report["exit_code"], 2)
        self.assertIn("analysis_missing", [r.get("reason") for r in report["results"]])

    def test_only_installed_version_source_is_checked(self):
        self.old["packages"]["node_modules/example"]["resolved"] = "https://evil.test/a.tgz"
        self.save_locks()
        self.assertTrue(self.request()["changes"][0]["analyzable"])

    def test_removed_and_unchanged_need_no_model(self):
        self.new = copy.deepcopy(self.old)
        self.save_locks()
        self.assertEqual(scan(self.request(), None, None)["exit_code"], 0)
        self.new["packages"] = {}
        self.save_locks()
        self.assertEqual(scan(self.request(), None, None)["results"][0]["status"], "removed")

    def test_duplicate_json_rejected(self):
        self.head.write_text('{"packages":{},"packages":{},"lockfileVersion":3}')
        with self.assertRaises(GuardError):
            self.request()


class PipelineTests(Fixture):
    def test_missing_analysis_is_incomplete(self):
        report = scan(self.request(), None, None)
        self.assertEqual(report["exit_code"], 2)
        self.assertIsNone(report["results"][0]["score"])

    def test_pass_flag_and_threshold_boundary(self):
        for score, expected in ((0.2, 0), (0.5, 1), (0.9, 1)):
            with self.subTest(score=score):
                analyzer = self.adapter(self.artifact({"signal": score}))
                self.assertEqual(scan(self.request(), analyzer, FakePredictor())["exit_code"], expected)

    def test_stale_artifact_rejected(self):
        artifact = self.artifact()
        artifact["request_id"] = "stale"
        with self.assertRaises(GuardError):
            scan(self.request(), self.adapter(artifact), FakePredictor())

    def test_feature_schema_mismatch(self):
        artifact = self.artifact()
        artifact["feature_schema"] = "another-version"
        with self.assertRaises(GuardError):
            scan(self.request(), self.adapter(artifact), FakePredictor())

    def test_duplicate_and_missing_results(self):
        artifact = self.artifact()
        artifact["results"] *= 2
        with self.assertRaises(GuardError):
            self.adapter(artifact).analyze(self.request())
        artifact["results"] = []
        self.assertEqual(scan(self.request(), self.adapter(artifact), FakePredictor())["exit_code"], 2)

    def test_failed_analysis_never_passes(self):
        artifact = self.artifact()
        artifact["results"][0] = {
            "change_id": artifact["results"][0]["change_id"],
            "status": "failed", "error": "parser unsupported",
        }
        self.assertEqual(scan(self.request(), self.adapter(artifact), FakePredictor())["exit_code"], 2)

    def test_invalid_scores_fail_closed(self):
        for score in (float("nan"), float("inf"), -0.1, 1.1, True):
            with self.subTest(score=score):
                artifact = self.artifact({"signal": score})
                self.assertEqual(scan(self.request(), self.adapter(artifact), FakePredictor())["exit_code"], 2)

    def test_cli_json_and_exit_status(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["scan", str(self.project), "--base-lock", str(self.base), "--format", "json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "incomplete")

    def test_cli_does_not_overwrite_input(self):
        original = self.base.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            code = main(["plan", str(self.project), "--base-lock", str(self.base), "--output", str(self.base)])
        self.assertEqual(code, 2)
        self.assertEqual(self.base.read_bytes(), original)

    def test_cli_export_request(self):
        output = self.root / "request.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["plan", str(self.project), "--base-lock", str(self.base), "--output", str(output)])
        self.assertEqual(code, 0)
        self.assertEqual(read_json(output)[0], self.request())


class ServiceTests(Fixture):
    def test_plan_project_is_the_request(self):
        self.assertEqual(plan_project(self.project, self.base), self.request())

    def test_scan_project_without_analysis_or_model(self):
        report = scan_project(self.project, self.base)
        self.assertEqual(report, scan(self.request(), None, None))
        self.assertEqual(report["results"][0]["reason"], "analysis_missing")
        self.adapter()
        report = scan_project(self.project, self.base, analysis=self.root / "analysis.json")
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(report["results"][0]["reason"], "model_missing")

    def test_scan_project_rejects_bad_source_options(self):
        with self.assertRaises(GuardError):
            scan_project(self.project, self.base, analysis=self.base, extract=True)
        with self.assertRaises(GuardError):
            scan_project(self.project, self.base, local_sources=[f"example@1.1.0={self.root}"])

    def test_scan_project_passes_sources_and_progress_to_extractor(self):
        (self.root / "src").mkdir()
        progress = mock.Mock()
        with mock.patch("depbee.analysis.extractor.ExtractorAnalyzer") as extractor:
            extractor.return_value.analyze.return_value = self.artifact()
            extractor.return_value.measurements = {}
            report = scan_project(
                self.project, self.base, extract=True, local_root=self.root,
                local_sources=["example@1.1.0=src"], progress=progress,
            )
        extractor.assert_called_once_with(
            {("example", "1.1.0"): (self.root / "src").resolve()}, progress=progress
        )
        self.assertEqual(report["results"][0]["reason"], "model_missing")

    def test_cli_extract_progress_by_format(self):
        # Real cli.main and scan_project; only the extractor is replaced (nothing is extracted).
        for fmt, progress in (("text", _progress), ("json", None)):
            err = io.StringIO()
            with (
                self.subTest(format=fmt),
                mock.patch("depbee.analysis.extractor.ExtractorAnalyzer") as extractor,
            ):
                extractor.return_value.analyze.return_value = self.artifact()
                extractor.return_value.measurements = {}
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    code = main(["scan", str(self.project), "--base-lock", str(self.base),
                                 "--extract", "--format", fmt])
                extractor.assert_called_once_with({}, progress=progress)
                # model_missing report (exit 2) with an empty stderr, not the error path.
                self.assertEqual((code, err.getvalue()), (2, ""))


class ModelDirEnvTests(Fixture):
    """DEPBEE_MODEL_DIR: explicit model_dir > variable > no model, read on every call."""

    def scan_with(self, env=None, **kwargs):
        if env is not None:
            os.environ["DEPBEE_MODEL_DIR"] = env
        self.adapter()
        with mock.patch("depbee.service.LightGBMPredictor", return_value=FakePredictor()) as model:
            report = scan_project(
                self.project, self.base, analysis=self.root / "analysis.json", **kwargs
            )
        return model, report

    def test_variable_selects_the_model(self):
        model, report = self.scan_with("models/from-env")
        model.assert_called_once_with(Path("models/from-env"))
        self.assertEqual(report["exit_code"], 1)  # scored by that model (signal 0.9)

    def test_explicit_model_dir_wins_and_is_never_retried(self):
        model, _ = self.scan_with("models/from-env", model_dir=Path("models/explicit"))
        model.assert_called_once_with(Path("models/explicit"))
        with (
            mock.patch("depbee.service.LightGBMPredictor", side_effect=GuardError("bad")) as bad,
            self.assertRaises(GuardError),
        ):
            scan_project(self.project, self.base, model_dir=Path("models/explicit"))
        bad.assert_called_once_with(Path("models/explicit"))

    def test_unset_or_empty_means_no_model(self):
        for env in (None, ""):
            with self.subTest(env=env):
                model, report = self.scan_with(env)
                model.assert_not_called()
                self.assertEqual(report["results"][0]["reason"], "model_missing")
        # Unchanged lockfiles still pass without any model.
        self.new = copy.deepcopy(self.old)
        self.save_locks()
        self.assertEqual(scan_project(self.project, self.base)["exit_code"], 0)

    def test_whitespace_or_missing_directory_is_a_path_error(self):
        model, _ = self.scan_with("   ")
        model.assert_called_once_with(Path("   "))  # used as given, not trimmed or skipped
        for env in ("   ", str(self.root / "no-such-model")):
            with self.subTest(env=env):
                os.environ["DEPBEE_MODEL_DIR"] = env
                with self.assertRaises((OSError, GuardError)):
                    scan_project(self.project, self.base)

    def test_variable_is_read_on_every_call(self):
        models = []
        for env in ("models/a", "models/b"):
            model, _ = self.scan_with(env)
            models.append(model.call_args.args[0])
        self.assertEqual(models, [Path("models/a"), Path("models/b")])

    def test_cli_uses_the_variable(self):
        self.adapter()
        os.environ["DEPBEE_MODEL_DIR"] = "models/from-env"
        with (
            mock.patch("depbee.service.LightGBMPredictor", return_value=FakePredictor()) as model,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            code = main(["scan", str(self.project), "--base-lock", str(self.base),
                         "--analysis", str(self.root / "analysis.json"), "--format", "json"])
        model.assert_called_once_with(Path("models/from-env"))
        self.assertEqual(code, 1)


FAKE_GIT = str(Path(__file__).resolve().parent / "fake-git.exe")  # absolute; never executed
COMMIT = "0123456789abcdef0123456789abcdef01234567"
COMMIT_LINE = (0, f"{COMMIT}\n".encode(), b"")
BLOB = f"{COMMIT}:./package-lock.json"
GIT_OPTIONS = [FAKE_GIT, "--no-lazy-fetch", "--no-replace-objects"]
REPOSITORY_VARIABLES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                        "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")


class GitBaseTests(Fixture):
    """Git is always mocked, so no test depends on a real repository or a Git install."""

    def git(self, *steps, which=FAKE_GIT):
        """Mock Git. Each step is (returncode, stdout, stderr) or an exception, in call order."""
        patchers = (
            mock.patch("depbee.inputs.git.shutil.which", return_value=which),
            mock.patch("depbee.inputs.git._run", side_effect=list(steps)),
        )
        mocks = []
        for patcher in patchers:
            mocks.append(patcher.start())
            self.addCleanup(patcher.stop)
        self.which = mocks[0]
        return mocks[1]

    def committed(self, blob):
        return COMMIT_LINE, (0, blob, b"")

    def test_base_lock_file_never_runs_git(self):
        run = self.git()
        self.assertEqual(plan_project(self.project, self.base), self.request())
        run.assert_not_called()

    def test_default_head_matches_file_input(self):
        run = self.git(*self.committed(self.base.read_bytes()))
        # Same bytes as the base file -> exactly the same request, including request_id.
        self.assertEqual(plan_project(self.project), self.request())
        self.assertEqual([c.args[:3] for c in run.call_args_list], [
            ([*GIT_OPTIONS, "rev-parse", "--verify", "--quiet", "--end-of-options",
              "HEAD^{commit}"], self.project, 4096),
            ([*GIT_OPTIONS, "cat-file", "blob", BLOB], self.project, MAX_JSON_BYTES),
        ])

    def test_explicit_ref_in_subdirectory_with_space_and_korean(self):
        project = self.root / "repo" / "하위 폴더 a"
        project.mkdir(parents=True)
        shutil.copyfile(self.head, project / "package-lock.json")
        run = self.git(*self.committed(self.base.read_bytes()))
        request = plan_project(project, base_ref="origin/main")
        self.assertEqual(request["request_id"], self.request()["request_id"])
        self.assertEqual(run.call_args_list[0].args[0][-1], "origin/main^{commit}")
        self.assertEqual(run.call_args_list[1].args[0][-1], BLOB)
        self.assertEqual({c.args[1] for c in run.call_args_list}, {project})

    def test_scan_project_and_cli_read_base_ref(self):
        self.git(*self.committed(self.base.read_bytes()))
        self.assertEqual(scan_project(self.project, base_ref="v1"), scan(self.request(), None, None))
        expected = io.StringIO()
        with contextlib.redirect_stdout(expected):
            main(["plan", str(self.project), "--base-lock", str(self.base)])
        for extra, ref in (([], "HEAD"), (["--base-ref", "HEAD~1"], "HEAD~1")):
            with self.subTest(ref=ref):
                run = self.git(*self.committed(self.base.read_bytes()))
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = main(["plan", str(self.project), *extra])
                self.assertEqual((code, out.getvalue()), (0, expected.getvalue()))
                self.assertEqual(run.call_args_list[0].args[0][-1], f"{ref}^{{commit}}")

    def test_base_lock_and_base_ref_together_rejected(self):
        run = self.git()
        with self.assertRaises(GuardError):
            plan_project(self.project, self.base, base_ref="HEAD")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as stop:
            main(["plan", str(self.project), "--base-lock", str(self.base), "--base-ref", "HEAD"])
        self.assertEqual(stop.exception.code, 2)
        self.assertIn("not allowed with argument", err.getvalue())
        run.assert_not_called()

    def test_option_like_or_empty_ref_rejected_before_git(self):
        run = self.git()
        for ref in ("", "-n", "--output=x"):
            with self.subTest(ref=ref), self.assertRaises(GuardError):
                plan_project(self.project, base_ref=ref)
        run.assert_not_called()

    def test_git_not_found_or_planted_in_current_directory(self):
        expected = "git.exe not found on PATH" if os.name == "nt" else "Git executable not found"
        for which in (None, "git.exe", os.path.join(".", "git.exe")):
            with self.subTest(which=which):
                run = self.git(which=which)
                with self.assertRaisesRegex(GuardError, expected):
                    plan_project(self.project)
                run.assert_not_called()

    def test_git_failures_stop_with_short_errors(self):
        no_repo = b"fatal: not a git repository (or any of the parent directories): .git\n"
        cases = {
            "cannot execute": [FileNotFoundError("git")],
            "not a repository": [(128, b"", no_repo)],
            "unknown ref": [(1, b"", b"")],
            "not a commit id": [(0, b"HEAD\n", b"")],
            # _run raises these itself; BoundedRunTests checks it with a real child.
            "timeout": [GuardError("Git did not finish within 30 seconds")],
            "too large": [COMMIT_LINE, GuardError("Git output exceeds 20971520 bytes")],
            "no base lockfile": [COMMIT_LINE, (128, b"", b"fatal: path does not exist\n")],
            "long stderr": [(128, b"", b"x" * 4096)],
        }
        for name, steps in cases.items():
            with self.subTest(name):
                run = self.git(*steps)
                with self.assertRaises(GuardError) as caught:
                    plan_project(self.project)
                self.assertEqual(run.call_count, len(steps))
                self.assertLess(len(str(caught.exception)), 1000)

    def git_children(self, **parent):
        """Run plan_project through the real _run; each Git child is a harmless Python child.

        Like Git, a child that inherits GIT_DIR or a graft file answers from that other
        repository or history, whose lockfile equals the project's, so a leaked variable would
        hide the real change.
        """
        os.environ.pop("GIT_NO_LAZY_FETCH", None)
        os.environ.update(parent)
        before = dict(os.environ)
        replies = iter((COMMIT_LINE[1], self.base.read_bytes()))
        children = []

        def popen(argv, **kwargs):
            children.append((argv, kwargs["env"]))
            reply = next(replies)
            env = kwargs["env"]
            grafted = env.get("GIT_GRAFT_FILE", os.devnull) != os.devnull
            if ("GIT_DIR" in env or grafted) and reply != COMMIT_LINE[1]:
                reply = self.head.read_bytes()
            code = f"import sys; sys.stdout.buffer.write({reply!r})"
            return REAL_POPEN([sys.executable, "-I", "-c", code], **kwargs)

        with (
            mock.patch("depbee.inputs.git.shutil.which", return_value=FAKE_GIT),
            mock.patch("depbee.inputs.git.subprocess.Popen", side_effect=popen),
        ):
            self.assertEqual(plan_project(self.project), self.request())
        self.assertEqual(dict(os.environ), before)  # the parent environment is not changed
        return children

    def test_lazy_fetch_blocked_in_every_git_child(self):
        # A partial clone would fetch a missing blob from its promisor remote; never go online,
        # whatever GIT_NO_LAZY_FETCH the parent process inherited.
        for parent_env in (None, "0", "false"):
            with self.subTest(parent_env=parent_env):
                parent = {} if parent_env is None else {"GIT_NO_LAZY_FETCH": parent_env}
                children = self.git_children(**parent)
                self.assertEqual(len(children), 2)
                for argv, env in children:
                    self.assertEqual(argv[:3], GIT_OPTIONS)
                    self.assertEqual(env["GIT_NO_LAZY_FETCH"], "1")

    def test_inherited_repository_variables_cannot_redirect_git(self):
        # git_children checks the request still shows the project's real change.
        parent = dict.fromkeys(REPOSITORY_VARIABLES, str(self.root / "other-repo" / ".git"))
        parent["GIT_GRAFT_FILE"] = str(self.root / "grafts")
        parent["LC_ALL"] = "ko_KR.UTF-8"
        children = self.git_children(**parent)
        self.assertEqual(len(children), 2)
        for argv, env in children:
            self.assertEqual(argv[:3], GIT_OPTIONS)
            self.assertFalse(set(REPOSITORY_VARIABLES) & env.keys())
            self.assertEqual(env["GIT_NO_LAZY_FETCH"], "1")
            # An empty graft file also hides .git/info/grafts.
            self.assertEqual(env["GIT_GRAFT_FILE"], os.devnull)
            self.assertEqual(env["LC_ALL"], "C")  # untranslated messages for the 2.45 check
        self.assertEqual(os.environ["GIT_GRAFT_FILE"], parent["GIT_GRAFT_FILE"])
        self.assertEqual(os.environ["LC_ALL"], "ko_KR.UTF-8")

    def test_missing_blob_ends_with_exit_2(self):
        missing = b"fatal: unable to read 89abcdef (missing object, lazy fetch disabled)\n"
        self.git(COMMIT_LINE, (128, b"", missing))
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["plan", str(self.project), "--base-ref", "HEAD~1"])
        self.assertEqual(code, 2)
        self.assertIn("missing object", json.loads(err.getvalue())["error"])

    def test_windows_runs_only_git_exe(self):
        # A git.cmd or git.bat would pass the ref through cmd.exe. POSIX keeps looking up "git".
        self.git(*self.committed(self.base.read_bytes()))
        plan_project(self.project)
        self.assertEqual(self.which.call_args.args[0], "git.exe" if os.name == "nt" else "git")
        if os.name == "nt":
            run = self.git(which=str(self.root / "bin" / "git.exe.cmd"))  # absolute, never run
            with self.assertRaisesRegex(GuardError, "git.exe not found on PATH"):
                plan_project(self.project)
            run.assert_not_called()

    def test_git_older_than_2_45_gets_a_clear_error(self):
        # Git before 2.45 rejects --no-lazy-fetch as an unknown option (exit 129).
        usage = b"unknown option: --no-lazy-fetch\nusage: git [-v | --version] [-h | --help]\n"
        run = self.git((129, b"", usage))
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["plan", str(self.project)])
        self.assertEqual(code, 2)
        self.assertIn("Git 2.45 or later is required", json.loads(err.getvalue())["error"])
        self.assertEqual(run.call_count, 1)

    def test_exit_129_without_unknown_option_keeps_the_git_error(self):
        # 129 is any usage failure; Git 2.45+ also lists --no-lazy-fetch in its usage text.
        usage = b"usage: git [-v | --version] [--no-lazy-fetch] [--no-replace-objects]\n"
        self.git((129, b"", usage))
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["plan", str(self.project)])
        message = json.loads(err.getvalue())["error"]
        self.assertEqual(code, 2)
        self.assertTrue(message.startswith("Git cannot resolve HEAD to a commit"))
        self.assertIn("usage: git", message)
        self.assertNotIn("2.45", message)

    def test_committed_lockfile_gets_the_same_json_checks(self):
        cases = {
            "invalid JSON": b"{",
            "duplicate key": b'{"lockfileVersion": 3, "lockfileVersion": 3, "packages": {}}',
            "lockfileVersion 1": b'{"lockfileVersion": 1, "packages": {}}',
            "not an object": b"[]",
        }
        for name, blob in cases.items():
            with self.subTest(name):
                self.git(*self.committed(blob))
                with self.assertRaises(GuardError):
                    plan_project(self.project)


REAL_POPEN = subprocess.Popen


class BoundedRunTests(unittest.TestCase):
    """The real _run with a real child: this test's own Python printing synthetic bytes."""

    def run_child(self, code, limit=100):
        """Run code in a child Python; keep the Popen object and its arguments for checks."""
        self.started = []

        def popen(*args, **kwargs):
            self.started.append((REAL_POPEN(*args, **kwargs), kwargs))
            return self.started[-1][0]

        began = time.monotonic()
        try:
            with mock.patch("depbee.inputs.git.subprocess.Popen", side_effect=popen):
                return git_input._run([sys.executable, "-I", "-c", code], Path.cwd(), limit)
        finally:
            self.elapsed = time.monotonic() - began
            proc, _ = self.started[0]
            # Cleanup: the child has exited and both pipes are closed, success or not.
            self.assertIsNotNone(proc.poll())
            self.assertTrue(proc.stdout.closed and proc.stderr.closed)

    def test_output_and_exit_code_without_shell(self):
        code = "import sys; sys.stdout.write('ok'); sys.stderr.write('warn'); sys.exit(3)"
        self.assertEqual(self.run_child(code), (3, b"ok", b"warn"))
        kwargs = self.started[0][1]
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertFalse(kwargs.get("shell", False))

    def test_output_at_the_limit_is_kept(self):
        code = "import sys; sys.stdout.buffer.write(b'x' * 100)"
        self.assertEqual(self.run_child(code), (0, b"x" * 100, b""))

    def test_endless_output_is_cut_and_the_child_killed(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                code = f"import sys\nwhile True: sys.{stream}.buffer.write(b'x' * 65536)"
                with self.assertRaisesRegex(GuardError, "exceeds"):
                    self.run_child(code)
                self.assertLess(self.elapsed, 10)  # stopped by the limit, not the timeout

    def test_timeout_kills_a_silent_child(self):
        with mock.patch.object(git_input, "TIMEOUT_SECONDS", 0.5):
            with self.assertRaisesRegex(GuardError, "did not finish"):
                self.run_child("import time; time.sleep(60)")
        self.assertLess(self.elapsed, 10)


@unittest.skipUnless(importlib.util.find_spec("lightgbm"), "Install .[ml] for native integration tests")
class LightGBMTests(Fixture):
    def setUp(self):
        super().setUp()
        import lightgbm as lgb
        import numpy as np

        # Purely synthetic numbers verify serialization and integration, not detection quality.
        data = lgb.Dataset(np.array([[0.0], [0.1], [0.2], [0.8], [0.9], [1.0]]),
                           label=[0, 0, 0, 1, 1, 1], feature_name=["signal"])
        booster = lgb.train({"objective": "binary", "verbosity": -1, "num_threads": 1,
                             "min_data_in_leaf": 1, "min_data_in_bin": 1}, data, num_boost_round=4)
        booster.save_model(str(self.root / "model.txt"))
        self.manifest = {
            "schema_version": 1, "model_id": "synthetic-test-only", "feature_schema": "test-v1",
            "feature_names": ["signal"], "positive_class": "malicious", "objective": "binary",
            "threshold": 0.5,
            "model_sha256": hashlib.sha256((self.root / "model.txt").read_bytes()).hexdigest(),
        }
        self.write(self.root / "manifest.json", self.manifest)

    def test_native_prediction_and_cli(self):
        predictor = LightGBMPredictor(self.root)
        self.assertLess(predictor.predict({"signal": 0.1}), 0.5)
        self.assertGreater(predictor.predict({"signal": 0.9}), 0.5)
        self.adapter()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["scan", str(self.project), "--base-lock", str(self.base),
                         "--analysis", str(self.root / "analysis.json"),
                         "--model-dir", str(self.root), "--format", "json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())["results"][0]["status"], "flagged")

    def test_scan_project_matches_pipeline(self):
        self.adapter()
        analysis = self.root / "analysis.json"
        report = scan_project(self.project, self.base, analysis=analysis, model_dir=self.root)
        expected = scan(self.request(), ArtifactAnalyzer(analysis), LightGBMPredictor(self.root))
        self.assertEqual(report, expected)
        self.assertEqual(report["results"][0]["status"], "flagged")

    def test_identity_is_the_verified_file_hashes(self):
        # The feature cache keys on these (DEV-02e).
        manifest = hashlib.sha256((self.root / "manifest.json").read_bytes()).hexdigest()
        self.assertEqual(LightGBMPredictor(self.root).identity,
                         {"model_sha256": self.manifest["model_sha256"], "manifest_sha256": manifest})

    def test_report_provenance_from_the_native_predictor(self):
        # Review m2 of PR #10: the real LightGBMPredictor path, with this synthetic model.
        self.adapter()
        report = scan_project(self.project, self.base, analysis=self.root / "analysis.json",
                              model_dir=self.root)
        self.assertEqual(report["provenance"],
                         {"model": LightGBMPredictor(self.root).identity, "feature_extractor": None})

    def test_hash_order_and_missing_features(self):
        predictor = LightGBMPredictor(self.root)
        with self.assertRaises(GuardError):
            predictor.predict({"wrong": 1})
        with self.assertRaises(GuardError):
            predictor.predict({"signal": float("nan")})
        self.manifest["feature_names"] = ["wrong"]
        self.write(self.root / "manifest.json", self.manifest)
        with self.assertRaises(GuardError):
            LightGBMPredictor(self.root)
        self.manifest["model_sha256"] = "wrong"
        self.write(self.root / "manifest.json", self.manifest)
        with self.assertRaises(GuardError):
            LightGBMPredictor(self.root)


class NumberTests(unittest.TestCase):
    def test_extreme_number(self):
        with self.assertRaises(GuardError):
            finite_number(10 ** 1000, "test")
