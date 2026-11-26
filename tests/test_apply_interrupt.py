"""Ctrl+C during the npm ci of depbee update --apply install (service.apply_preview).

npm is mocked as in test_apply.py; the tests with real child processes run synthetic Python
stand-ins, never npm or Node.js.
"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from test_apply import PASS, ApplyFixture, sha

from depbee import history
from depbee.contracts import GuardError
from depbee.inputs import git as git_input
from depbee.service import INTERRUPTED, INTERRUPTED_NOTICE, RESTORE_NOTICE

# A synthetic grandchild: it appends to the file in argv[1] until it is killed, until the file
# in argv[2] appears (the test's own cleanup) or for 30 s.
GRANDCHILD = """
import os, sys, time
end = time.monotonic() + 30
while time.monotonic() < end and not os.path.exists(sys.argv[2]):
    open(sys.argv[1], "a").write(".")
    time.sleep(0.05)
"""
# A synthetic child: starts the grandchild on its own pipes and stays as long as it does.
CHILD = """
import subprocess, sys
subprocess.Popen([sys.executable, "-I", "-c", *sys.argv[1:]]).wait()
"""


def interrupted(project):
    raise KeyboardInterrupt  # as _run ends once Ctrl+C came and it has stopped npm


class InterruptedInstallTests(ApplyFixture):
    def setUp(self):
        super().setUp()
        self.verdict([PASS], 0)
        self.npm_ci = interrupted
        self.new_lock = self.head.read_bytes()

    def cli(self, *args):
        try:
            return super().cli("--apply", "install", *args)
        except KeyboardInterrupt:  # uncaught, it would stop unittest itself
            self.fail("Ctrl+C during npm ci ended update --apply without a report")

    def assert_cancelled(self, apply):
        """The apply of an install cancelled after the lockfile was replaced: reported as a
        failed install, with the new lockfile and the backup both left as they are."""
        self.assertEqual(
            (apply["outcome"], apply["reason"], apply["error"]),
            ("failed", "install_failed", INTERRUPTED),
        )
        self.assertEqual((apply["npm_version"], apply["npm_ci_exit_code"]), (None, None))
        self.assertEqual(apply["notices"], [INTERRUPTED_NOTICE, RESTORE_NOTICE])
        self.assertEqual(apply["files"], [{
            "path": "package-lock.json", "sha256": sha(self.original["package-lock.json"]),
            "new_sha256": sha(self.new_lock),
        }])  # fmt: skip
        # Not rolled back: the checked lockfile stays, package.json was never touched.
        self.assertEqual((self.upd / "package-lock.json").read_bytes(), self.new_lock)
        self.assertEqual((self.upd / "package.json").read_bytes(), self.original["package.json"])
        (backup,) = self.backups.iterdir()  # one application: one backup
        self.assertEqual(apply["backup"], str(backup))
        for name, data in self.original.items():
            self.assertEqual((backup / name).read_bytes(), data, name)
        about = json.loads((backup / "backup.json").read_text(encoding="utf-8"))
        self.assertEqual(about["new_package_lock_sha256"], sha(self.new_lock))
        self.assertFalse(list(self.upd.glob(".*.depbee")))
        self.assertFalse(list(self.root.glob("depbee_install_*")))  # scratch folder removed

    def test_the_cli_reports_and_records_the_cancelled_install(self):
        project_id = history.register_project(self.upd)
        code, out, err = self.cli("--format", "json")
        self.assertEqual((code, err), (2, ""))
        output = json.loads(out)
        self.assert_cancelled(output["apply"])
        self.assertEqual(len(self.ci_calls), 1)  # npm ci is not tried again
        (run,) = history.list_runs(project_id)
        (apply,) = history.list_applies(project_id)
        self.assertEqual(apply["apply"], output["apply"])
        self.assertEqual(
            (apply["run_id"], apply["mode"], apply["outcome"], apply["reason"], apply["backup"]),
            (run["id"], "install", "failed", "install_failed", output["apply"]["backup"]),
        )
        self.assertEqual(apply["new_package_lock_sha256"], sha(self.new_lock))

    def test_the_text_output_says_what_was_cancelled_and_what_stays(self):
        code, out, _ = self.cli()
        self.assertEqual(code, 2)
        self.assertIn("depbee 업데이트 반영: 실패", out)
        self.assertIn("이유: npm ci 실패", out)
        self.assertIn(f"오류: {INTERRUPTED}", out)
        self.assertIn("바꾼 파일: package-lock.json", out)
        self.assertIn(f"원본 백업: {next(self.backups.iterdir())}", out)
        self.assertIn(INTERRUPTED_NOTICE, out)
        self.assertIn(RESTORE_NOTICE, out)
        self.assertNotIn("npm ci 종료 코드", out)  # npm ci left none

    def test_a_second_run_that_resolves_the_same_versions_applies_nothing(self):
        # A second run is a new preview. Here npm resolves what the lockfile already has, so
        # nothing is applied or installed: it is not a way to finish the cancelled install.
        self.cli()
        code, out, _ = self.cli()
        self.assertEqual(code, 0)
        self.assertIn("depbee 업데이트 반영: 바뀐 항목 없음", out)
        self.assertEqual(len(self.ci_calls), 1)
        self.assertEqual(len(list(self.backups.iterdir())), 1)

    def test_ctrl_c_at_the_npm_version_check_of_the_install_is_reported_too(self):
        # npm ci has not started, but the lockfile is already replaced.
        real = self.fake_run

        def run(argv, cwd, limit, env=None, **kwargs):
            if argv[2] == "--version" and Path(cwd) == self.upd.absolute():
                raise KeyboardInterrupt
            return real(argv, cwd, limit, env, **kwargs)

        self.run.side_effect = run
        code, out, _ = self.cli("--format", "json")
        self.assertEqual(code, 2)
        self.assert_cancelled(json.loads(out)["apply"])
        self.assertEqual(self.ci_calls, [])

    def test_ctrl_c_before_any_file_is_replaced_stays_a_plain_cancellation(self):
        cases = {
            "npm update of the preview": mock.patch.object(self, "npm_update", interrupted),
            "the scan": mock.patch("depbee.service.scan_project", side_effect=KeyboardInterrupt),
            "the backup": mock.patch("depbee.service._backup", side_effect=KeyboardInterrupt),
        }
        for case, patch in cases.items():
            with self.subTest(case), patch:
                with self.assertRaises(KeyboardInterrupt):
                    self.apply("install")
                self.assert_unchanged()
                self.assertEqual(self.ci_calls, [])


class ChildTreeTests(ApplyFixture):
    """The real _run with a synthetic child and grandchild in place of npm ci. The interrupt is
    raised where a Ctrl+C can surface once the child exists: as the process tree takes the
    child, in the start of the first output reader, or in the wait for the readers."""

    def setUp(self):
        super().setUp()
        self.verdict([PASS], 0)
        self.beat, self.stop, self.child = self.root / "beat", self.root / "stop", None
        self.addCleanup(self.stop_stand_ins)  # before the fixture removes its folder

    def written(self):
        return self.beat.stat().st_size if self.beat.exists() else 0

    def stop_stand_ins(self):
        """End whatever the code under test left running, whether the test passed or not."""
        if self.child is not None and self.child.poll() is None:
            self.child.kill()  # also one left suspended (Windows)
        self.stop.write_bytes(b"")
        size = -1
        while size != self.written():
            size = self.written()
            time.sleep(0.3)

    def interrupt(self, wait=True):
        """Raise the interrupt, with wait once the grandchild runs (never, if it does not)."""
        end = time.monotonic() + 20  # as long as the slowest start test_update allows
        while wait and not self.beat.exists() and time.monotonic() < end:
            time.sleep(0.05)
        if self.beat.exists() or not wait:
            self.interrupted = time.monotonic()
            raise KeyboardInterrupt

    def fake_run(self, argv, cwd, limit, env=None, **kwargs):
        if argv[2] != "ci":
            return super().fake_run(argv, cwd, limit, env, **kwargs)
        self.ci_calls.append(argv)
        at, interrupt, take = self.at, self.interrupt, git_input._ProcessTree.start

        def start(tree, proc):
            self.child = proc
            if at == "before the tree takes the child":  # Windows: the child is still suspended
                interrupt(wait=False)
            take(tree, proc)
            if at == "once the tree has the child":
                interrupt()

        class Reader(threading.Thread):
            def start(self):
                if at == "before the reader runs":
                    interrupt()
                super().start()
                if at == "once the reader runs":
                    interrupt()

            def join(self, timeout=None):
                if at == "in the wait":
                    interrupt()
                return super().join(timeout)

        child = [sys.executable, "-I", "-c", CHILD, GRANDCHILD, str(self.beat), str(self.stop)]
        with (
            mock.patch.object(git_input._ProcessTree, "start", start),
            mock.patch.object(git_input.threading, "Thread", Reader),
        ):
            return git_input._run(child, cwd, limit, **{**kwargs, "timeout": 25})

    def test_the_child_tree_is_stopped_before_the_cancelled_install_is_reported(self):
        for at in ("before the tree takes the child", "once the tree has the child",
                   "before the reader runs", "once the reader runs", "in the wait"):  # fmt: skip
            with self.subTest(at):
                self.at = at
                try:
                    apply = self.apply("install")["apply"]
                except KeyboardInterrupt:  # uncaught, it would stop unittest itself
                    self.fail("Ctrl+C during npm ci ended the apply without a result")
                self.assertEqual((apply["outcome"], apply["error"]), ("failed", INTERRUPTED))
                # Stopped by the interrupt, not ended by itself (30 s) while depbee waited.
                self.assertLess(time.monotonic() - self.interrupted, 12)
                self.assertIsNotNone(self.child.poll())  # the child has ended
                size = self.written()  # nothing writes any more
                time.sleep(0.5)
                self.assertEqual(self.written(), size)
                if at != "before the tree takes the child":
                    self.assertGreater(size, 0)  # the grandchild did run
            self.stop_stand_ins()
            self.beat.unlink(missing_ok=True)
            self.stop.unlink()
            for name, data in self.original.items():
                (self.upd / name).write_bytes(data)


# The Windows calls of _ProcessTree.start() in their order, with what each returns when it fails.
STEPS = {"CreateJobObjectW": None, "SetInformationJobObject": 0, "OpenProcess": None,
         "AssignProcessToJobObject": 0, "NtResumeProcess": 1}  # fmt: skip


class Step:
    """One of those calls or CloseHandle: logged, or interrupted or failed in its place."""

    def __init__(self, log, name, function):
        vars(self).update(log=log, name=name, function=function)

    def __setattr__(self, key, value):  # restype and argtypes are the real function's
        setattr(self.function, key, value)

    def __call__(self, *args):
        if self.name == self.log.at:
            if self.log.error:
                raise self.log.error
            return STEPS[self.name]
        result = self.function(*args)
        self.log.calls.append((self.name, args[0], result))
        return result


class Library:
    """A ctypes library whose calls of interest go through Step."""

    def __init__(self, log, lib):
        vars(self).update(log=log, lib=lib, steps={})

    def __getattr__(self, name):
        if name not in (*STEPS, "CloseHandle"):
            return getattr(self.lib, name)
        if name not in self.steps:
            self.steps[name] = Step(self.log, name, getattr(self.lib, name))
        return self.steps[name]


@unittest.skipUnless(os.name == "nt", "Windows Job Object")
class PartialStartTests(unittest.TestCase):
    """_run with a Ctrl+C or a failure at each step of putting the child, still suspended, into
    its job: the child is ended at once and no job or process handle stays open."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.tmp, self.children = Path(folder.name), []
        self.addCleanup(self.end_children)  # whatever the test found, and before the folder goes
        take = git_input._ProcessTree.start

        def start(tree, proc):
            self.children.append(proc)
            take(tree, proc)

        patcher = mock.patch.object(git_input._ProcessTree, "start", start)
        patcher.start()
        self.addCleanup(patcher.stop)

    def end_children(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()  # also one left suspended
                child.wait(10)

    def run_child(self, at=None, error=None):
        """(result or exception of _run, seconds it took, the file the child writes if it runs)."""
        import ctypes

        self.at, self.error, self.calls = at, error, []
        real, marker = ctypes.WinDLL, self.tmp / "ran"
        marker.unlink(missing_ok=True)
        code = f"open({str(marker)!r}, 'w').close()"
        began = time.monotonic()
        with mock.patch.object(ctypes, "WinDLL", lambda *a, **k: Library(self, real(*a, **k))):
            try:
                result = git_input._run(
                    [sys.executable, "-I", "-c", code], self.tmp, 100, tree=True
                )
            except (KeyboardInterrupt, GuardError) as exc:
                result = exc
        return result, time.monotonic() - began, marker

    def assert_handles_closed(self, opened):
        made = [
            handle for step, _, handle in self.calls if step in ("CreateJobObjectW", "OpenProcess")
        ]
        closed = [handle for step, handle, _ in self.calls if step == "CloseHandle"]
        self.assertEqual((len(made), sorted(closed)), (opened, sorted(made)))

    def test_a_started_child_runs_and_leaves_no_handle(self):
        result, _, marker = self.run_child()
        self.assertEqual(result, (0, b"", b""))
        self.assertTrue(marker.exists())
        self.assert_handles_closed(2)  # the job and the process handle

    def test_an_interrupt_or_a_failure_at_any_step_ends_the_child_and_closes_the_handles(self):
        opened = {"CreateJobObjectW": 0, "SetInformationJobObject": 1, "OpenProcess": 1,
                  "AssignProcessToJobObject": 2, "NtResumeProcess": 2}  # fmt: skip
        for step in STEPS:
            for error in (KeyboardInterrupt(), None):
                with self.subTest(step=step, interrupted=error is not None):
                    result, seconds, marker = self.run_child(step, error)
                    if error:
                        self.assertIs(result, error)
                    else:
                        self.assertIsInstance(result, git_input.ChildNotStarted)
                    # At once, not after the 10 s (STOP_SECONDS) of waiting for a child left over.
                    self.assertLess(seconds, 5)
                    self.assertIsNotNone(self.children[-1].poll())  # ended, and reaped
                    self.assertFalse(marker.exists())  # it never ran
                    self.assert_handles_closed(opened[step])


if __name__ == "__main__":
    unittest.main()
