"""depbee update --apply (service.apply_update): npm is always mocked; no test runs npm or Node.js.

Synthetic projects only, inside each test run's folder; backups go next to the test's
DEPBEE_HISTORY_DB there.
"""

import hashlib
import json
import os
import shutil
from pathlib import Path
from unittest import mock

from test_history import sql
from test_update import ERROR_SECRET, UpdateFixture, sri

from depbee import history, service
from depbee.cli import CONFIRM_OPTION
from depbee.contracts import GuardError
from depbee.service import (
    LOCKFILE_NOTICE,
    NPMRC_INSTALL_NOTICE,
    PREVIEW_NOTICE,
    RESTORE_NOTICE,
    SCRIPTS_NOTICE,
    apply_preview,
    apply_update,
    update_gate,
)

PASS = {"status": "not_flagged", "reason": None, "ml": "not_hit", "known": "not_hit"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ApplyFixture(UpdateFixture):
    def setUp(self):
        super().setUp()
        self.npm_ci = lambda project: (0, b"added 1 package\n", b"")
        self.ci_calls = []
        self.backups = self.root / "backups"  # next to DEPBEE_HISTORY_DB (UpdateFixture)
        self.original = {name: (self.upd / name).read_bytes()
                         for name in ("package.json", "package-lock.json")}  # fmt: skip

    def fake_run(self, argv, cwd, limit, env=None, **kwargs):
        if argv[2] == "ci":
            self.ci_calls.append({"argv": argv, "cwd": Path(cwd), "env": env, "kwargs": kwargs})
            return self.npm_ci(Path(cwd))
        return super().fake_run(argv, cwd, limit, env, **kwargs)

    def verdict(self, rows=None, exit_code=None, during=None):
        """Rewrite the preview's report per item (status, reason, ml, known), as a connected
        known malicious detector would make it; during runs inside the preview."""
        real = service.scan_project

        def scan(*args, **kwargs):
            report = real(*args, **kwargs)
            for row, fields in zip(report["results"], rows or [], strict=False):
                row["status"], row["reason"] = fields["status"], fields["reason"]
                row["ml"] = {"status": fields["ml"]}
                row["known_malicious"] = {**row["known_malicious"], "status": fields["known"]}
            if exit_code is not None:
                report["exit_code"] = exit_code
            if during:
                during()
            return report

        self.patch("depbee.service.scan_project", side_effect=scan)

    def apply(self, mode="lockfile", confirm=False, packages=None):
        return apply_update(self.upd, packages, mode=mode, confirm=confirm, model_dir=self.root)

    def assert_unchanged(self):
        for name, data in self.original.items():
            self.assertEqual((self.upd / name).read_bytes(), data, name)
        self.assertFalse(self.backups.exists())
        extra = [".npmrc"] * (self.upd / ".npmrc").exists()
        self.assertEqual(
            sorted(p.name for p in self.upd.iterdir()), sorted([*self.original, *extra])
        )

    def assert_applied(self, apply):
        self.assertEqual(apply["outcome"], "applied")
        self.assertEqual((self.upd / "package-lock.json").read_bytes(), self.head.read_bytes())
        (backup,) = self.backups.iterdir()
        self.assertEqual(apply["backup"], str(backup))
        self.assertFalse(list(self.upd.glob(".*.depbee")))  # no temporary file left
        return backup


class GateTests(ApplyFixture):
    def test_known_malicious_hit_is_refused_even_with_confirmation(self):
        self.verdict([{"status": "flagged", "reason": None, "ml": "not_hit", "known": "hit"}], 1)
        for confirm in (False, True):
            with self.subTest(confirm=confirm):
                apply = self.apply(confirm=confirm)["apply"]
                self.assertEqual((apply["outcome"], apply["reason"]),
                                 ("refused", "known_malicious_hit"))  # fmt: skip
                self.assertEqual(apply["blocked"][0]["causes"], ["known_malicious_hit"])
                self.assertEqual(apply["confirmation_required"], [])
                self.assert_unchanged()
        self.assertEqual(self.ci_calls, [])

    def test_warnings_need_the_one_confirmation(self):
        cases = {
            "ml hit": ({"status": "flagged", "reason": None, "ml": "hit", "known": "not_hit"},
                       ["ml_hit"]),
            "incomplete": ({"status": "incomplete", "reason": "no_baseline", "ml": "not_run",
                            "known": "not_hit"}, ["incomplete"]),
            "known not_run": ({**PASS, "known": "not_run"}, ["known_malicious_unchecked"]),
            "known failed": ({**PASS, "status": "incomplete", "reason": "detection_failed",
                              "known": "failed"}, ["incomplete", "known_malicious_unchecked"]),
        }  # fmt: skip
        for case, (row, causes) in cases.items():
            with self.subTest(case):
                self.verdict([row], 0)  # the item fields decide, not the report's exit code
                apply = self.apply()["apply"]
                self.assertEqual((apply["outcome"], apply["reason"], apply["confirmed"]),
                                 ("refused", "confirmation_required", False))  # fmt: skip
                (item,) = apply["confirmation_required"]
                self.assertEqual(item["causes"], causes)
                self.assertEqual((item["location"], item["package"], item["after_version"],
                                  item["status"], item["reason"], item["ml_status"],
                                  item["known_malicious_status"]),
                                 ("node_modules/example", "example", "1.1.0", row["status"],
                                  row["reason"], row["ml"], row["known"]))  # fmt: skip
                self.assert_unchanged()
                apply = self.apply(confirm=True)["apply"]
                self.assertTrue(apply["confirmed"])
                backup = self.assert_applied(apply)
                for name, data in self.original.items():  # back to the start for the next case
                    (self.upd / name).write_bytes(data)
                for path in backup.iterdir():
                    path.unlink()
                backup.rmdir()
                self.backups.rmdir()

    def test_passing_items_apply_without_confirmation_whatever_the_exit_code(self):
        self.verdict([PASS], 2)
        result = self.apply()
        self.assertEqual(result["apply"]["confirmation_required"], [])
        self.assert_applied(result["apply"])
        self.assertEqual(result["report"]["exit_code"], 2)  # kept as the report says

    def test_the_gate_reads_item_fields_only(self):
        rows = [
            {"status": "removed", "known_malicious": {"status": "not_run"}, "ml": {}},
            {"status": "not_flagged", "known_malicious": {"status": "not_hit"},
             "ml": {"status": "not_hit"}},
            {"status": "not_flagged", "ml": {"status": "not_hit"}},  # no slot: unchecked
            {"status": "removed", "known_malicious": {"status": "hit"}},
        ]  # fmt: skip
        blocked, confirm = update_gate({"exit_code": 0, "results": rows})
        self.assertEqual([i["causes"] for i in blocked], [["known_malicious_hit"]])
        self.assertEqual([i["causes"] for i in confirm], [["known_malicious_unchecked"]])
        self.assertEqual(update_gate({"exit_code": 2, "results": rows[:2]}), ([], []))

    def test_a_removal_only_apply_needs_no_confirmation(self):
        # Decision 2026-11-16 18:0x: only items that install a new version need confirming.
        def update(work):
            self.write(work / "package-lock.json", {"lockfileVersion": 3, "packages": {}})
            return 0, b"", b""

        self.npm_update = update
        result = self.apply()
        (row,) = result["report"]["results"]
        self.assertEqual((row["status"], row["known_malicious"]["status"]), ("removed", "not_run"))
        self.assertEqual(result["apply"]["confirmation_required"], [])
        self.assertEqual(result["apply"]["outcome"], "applied")

    def test_today_every_item_needs_confirmation(self):
        # No known malicious detector is connected: every installed item is not_run.
        apply = self.apply()["apply"]
        (item,) = apply["confirmation_required"]
        self.assertEqual(item["causes"], ["ml_hit", "known_malicious_unchecked"])
        self.assert_unchanged()


class PreviewFilesTests(ApplyFixture):
    def test_preview_files_returns_the_preview_and_the_new_bytes_for_a_later_apply(self):
        self.verdict([PASS], 0)
        result, new_package, new_lock = service.preview_files(self.upd, ["example"],
                                                              model_dir=self.root)  # fmt: skip
        self.assertEqual(list(result), ["preview", "report"])
        self.assertEqual(result["preview"], self.preview(["example"])["preview"])
        self.assertIn(PREVIEW_NOTICE, result["preview"]["notices"])
        self.assertEqual((new_package, new_lock), (self.original["package.json"],
                                                   self.head.read_bytes()))  # fmt: skip
        self.assertEqual(sha(new_lock), result["preview"]["new_package_lock_sha256"])
        self.assertEqual(self.project_state(), {k: sha(v) for k, v in self.original.items()})
        self.assertFalse(list(self.root.glob("depbee_preview_*")))  # bytes only, no files left
        apply = apply_preview(self.upd, result, new_package, new_lock, mode="lockfile")
        self.assert_applied(apply)


class RecheckTests(ApplyFixture):
    def setUp(self):
        super().setUp()
        self.verdict([PASS], 0)

    def test_project_files_changed_after_the_preview_are_refused(self):
        for name in ("package.json", "package-lock.json"):
            with self.subTest(name):
                path = self.upd / name
                self.verdict([PASS], 0, during=lambda p=path: p.write_bytes(p.read_bytes() + b" "))
                apply = self.apply()["apply"]
                self.assertEqual((apply["outcome"], apply["reason"]),
                                 ("refused", "project_changed"))  # fmt: skip
                self.assertEqual(path.read_bytes(), self.original[name] + b" ")
                self.assertFalse(self.backups.exists())
                path.write_bytes(self.original[name])

    def test_a_project_out_of_scope_after_the_preview_is_refused(self):
        shrinkwrap = self.upd / "npm-shrinkwrap.json"
        self.verdict([PASS], 0, during=lambda: shrinkwrap.write_text("{}", encoding="utf-8"))
        apply = self.apply()["apply"]
        self.assertEqual((apply["outcome"], apply["reason"]), ("refused", "project_unsupported"))
        self.assertIn("npm-shrinkwrap.json", apply["error"])
        self.assertFalse(self.backups.exists())
        self.assertEqual(
            (self.upd / "package-lock.json").read_bytes(), self.original["package-lock.json"]
        )

    def test_a_new_lockfile_other_than_the_checked_one_is_refused(self):
        result = service.preview_update(self.upd, model_dir=self.root)
        apply = apply_preview(self.upd, result, self.original["package.json"],
                              self.head.read_bytes() + b"\n", mode="lockfile")  # fmt: skip
        self.assertEqual((apply["outcome"], apply["reason"]), ("refused", "new_lock_mismatch"))
        self.assert_unchanged()
        with self.assertRaises(GuardError):
            apply_preview(self.upd, result, b"", b"", mode="other")

    def test_new_files_outside_the_supported_range_are_refused_even_when_confirmed(self):
        lock = json.loads(self.head.read_text(encoding="utf-8"))
        entry = lock["packages"]["node_modules/example"]
        entry["resolved"] = "https://codeload.github.com/x/example/tar.gz/" + "a" * 40

        def update(work):
            (work / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            return 0, b"", b""

        self.npm_update = update
        self.verdict([{**PASS, "status": "incomplete", "reason": "unsupported_registry_source"}], 2)
        apply = self.apply("install", confirm=True)["apply"]
        self.assertEqual((apply["outcome"], apply["reason"]), ("refused", "new_files_unsupported"))
        self.assertIn("node_modules/example", apply["error"])
        self.assert_unchanged()
        self.assertEqual(self.ci_calls, [])

    def test_no_change_writes_nothing(self):
        self.npm_update = lambda work: (0, b"", b"")
        for mode in ("lockfile", "install"):
            with self.subTest(mode):
                result = self.apply(mode)
                self.assertEqual(result["apply"]["outcome"], "unchanged")
                self.assert_unchanged()
        self.assertEqual(self.ci_calls, [])


class BackupAndWriteTests(ApplyFixture):
    def setUp(self):
        super().setUp()
        self.verdict([PASS], 0)

    def test_backup_holds_the_original_bytes_and_a_description(self):
        def update(work):
            (work / "package.json").write_text('{"name": "changed"}', encoding="utf-8")
            return self.write_new_lock(work)

        self.npm_update = update
        result = self.apply()
        backup = self.assert_applied(result["apply"])
        self.assertEqual(backup.parent, Path(os.environ["DEPBEE_HISTORY_DB"]).parent / "backups")
        self.assertFalse(backup.is_relative_to(self.upd))
        for name, data in self.original.items():
            self.assertEqual((backup / name).read_bytes(), data)
        about = json.loads((backup / "backup.json").read_text(encoding="utf-8"))
        preview = result["preview"]
        new_package = (self.upd / "package.json").read_bytes()
        self.assertEqual(new_package, b'{"name": "changed"}')
        self.assertEqual(
            {k: v for k, v in about.items() if k not in ("created_at", "depbee_version")},
            {"project": str(self.upd.absolute()), "mode": "lockfile",
             "package_json_sha256": preview["package_json_sha256"],
             "package_lock_sha256": preview["package_lock_sha256"],
             "new_package_json_sha256": sha(new_package),
             "new_package_lock_sha256": preview["new_package_lock_sha256"]},
        )  # fmt: skip
        self.assertTrue(about["created_at"].endswith("Z"))
        self.assertEqual(
            result["apply"]["files"],
            [{"path": "package-lock.json", "sha256": preview["package_lock_sha256"],
              "new_sha256": preview["new_package_lock_sha256"]},
             {"path": "package.json", "sha256": preview["package_json_sha256"],
              "new_sha256": sha(new_package)}],
        )  # fmt: skip
        self.assertEqual(result["apply"]["notices"], [LOCKFILE_NOTICE, RESTORE_NOTICE])
        self.assertNotIn(PREVIEW_NOTICE, result["preview"]["notices"])

    def test_backup_location_comes_from_the_history_location_only(self):
        home = self.root / "home"
        os.environ["DEPBEE_HISTORY_DB"] = ""
        (self.upd / ".env").write_text("DEPBEE_HISTORY_DB=../elsewhere\n", encoding="utf-8")
        with mock.patch("depbee.history.Path.home", return_value=home):
            apply = self.apply()["apply"]
        self.assertEqual(Path(apply["backup"]).parent,
                         home / ".local" / "share" / "depbee" / "backups")  # fmt: skip

    def test_a_backup_that_cannot_be_written_stops_the_apply(self):
        self.backups.write_text("not a folder", encoding="utf-8")
        apply = self.apply()["apply"]
        self.assertEqual((apply["outcome"], apply["reason"]), ("failed", "backup_failed"))
        self.assertEqual(apply["files"], [])
        for name, data in self.original.items():
            self.assertEqual((self.upd / name).read_bytes(), data)
        self.backups.unlink()
        os.environ["DEPBEE_HISTORY_DB"] = ""
        with mock.patch("depbee.history.Path.home", side_effect=RuntimeError("no home")):
            apply = self.apply()["apply"]
        self.assertEqual((apply["outcome"], apply["reason"]), ("failed", "backup_failed"))
        self.assert_unchanged()

    def test_failed_writes_keep_the_originals_and_leave_no_temporary_file(self):
        def update(work):
            (work / "package.json").write_text('{"name": "changed"}', encoding="utf-8")
            return self.write_new_lock(work)

        self.npm_update = update
        real = os.replace
        for fail_at, replaced in ((1, "none"), (2, "package-lock.json")):
            with self.subTest(fail_at=fail_at):

                def replace(src, dst, calls=[], fail_at=fail_at):  # noqa: B006 - one list per case
                    calls.append(dst)
                    if len(calls) == fail_at:
                        raise PermissionError(13, "Permission denied", str(src))
                    return real(src, dst)

                with mock.patch("depbee.service.os.replace", replace):
                    apply = self.apply()["apply"]
                self.assertEqual((apply["outcome"], apply["reason"]), ("failed", "write_failed"))
                self.assertTrue(apply["error"].endswith(f"replaced before the error: {replaced}"))
                self.assertNotIn(".depbee", apply["error"])
                self.assertEqual((self.upd / "package.json").read_bytes(),
                                 self.original["package.json"])  # fmt: skip
                self.assertFalse(list(self.upd.glob(".*.depbee")))
                self.assertIn(RESTORE_NOTICE, apply["notices"])
                for name, data in self.original.items():
                    (self.upd / name).write_bytes(data)
        with mock.patch("depbee.service.shutil.copymode", side_effect=OSError("synthetic")):
            apply = self.apply()["apply"]
        self.assertEqual(apply["reason"], "write_failed")
        self.assertEqual((self.upd / "package-lock.json").read_bytes(),
                         self.original["package-lock.json"])  # fmt: skip
        self.assertFalse(list(self.upd.glob(".*.depbee")))


class InstallTests(ApplyFixture):
    def setUp(self):
        super().setUp()
        self.verdict([PASS], 0)

    def test_npm_ci_argv_environment_and_limits(self):
        os.environ.update({"npm_config_ignore_scripts": "false", "NODE_OPTIONS": "--require x"})
        apply = self.apply("install")["apply"]
        self.assert_applied(apply)
        (ci,) = self.ci_calls
        version = self.calls[-1]  # the npm --version call before ci, in the project
        project = self.upd.absolute()
        scratch = Path(ci["argv"][-2].removeprefix("--git=")).parent.parent
        self.assertTrue(scratch.name.startswith("depbee_install_"))
        self.assertFalse(scratch.is_relative_to(project))
        self.assertFalse(scratch.exists())  # removed afterwards
        pinned = [f"--prefix={project}", "--workspaces=false",
                  f"--git={scratch / 'no-git' / 'git'}",
                  f"--globalconfig={scratch / 'no-globalconfig' / 'npmrc'}"]  # fmt: skip
        self.assertEqual(ci["argv"], [
            str(self.node), str(self.npm_js), "ci", "--ignore-scripts", "--no-audit", "--no-fund",
            "--no-update-notifier", "--no-progress", "--color=false", "--loglevel=warn",
            "--dry-run=false", "--package-lock=true", "--package-lock-only=false", *pinned,
        ])  # fmt: skip
        self.assertEqual(version["argv"], [str(self.node), str(self.npm_js), "--version", *pinned])
        self.assertEqual((ci["cwd"], version["cwd"]), (project, project))
        self.assertEqual(ci["kwargs"], {"timeout": 600, "stderr_limit": 1024 * 1024, "name": "npm",
                                        "tree": True})  # fmt: skip
        for call in (ci, version):
            env = call["env"]
            self.assertEqual(env["npm_config_ignore_scripts"], "true")
            self.assertNotIn("NODE_OPTIONS", env)
        self.assertEqual((apply["npm_version"], apply["npm_ci_exit_code"]), ("11.6.1", 0))
        self.assertEqual(apply["notices"], [SCRIPTS_NOTICE, RESTORE_NOTICE])

    def test_npm_ci_failures_are_errors_with_the_backup(self):
        def timeout(project):
            raise GuardError("npm did not finish within 600 seconds")

        def rewrite(project):
            (project / "package-lock.json").write_text("{}", encoding="utf-8")
            return 0, b"", b""

        def rewrite_package(project):  # package.json was not replaced: still checked
            (project / "package.json").write_text("{}", encoding="utf-8")
            return 0, b"", b""

        cases = {
            "exit code": (lambda project: (1, ERROR_SECRET, ERROR_SECRET),
                          "npm ci failed with exit code 1"),
            "timeout": (timeout, "npm did not finish within 600 seconds"),
            "lockfile changed": (rewrite, "npm ci changed package.json or package-lock.json"),
            "package.json changed": (rewrite_package,
                                     "npm ci changed package.json or package-lock.json"),
        }  # fmt: skip
        for case, (ci, message) in cases.items():
            with self.subTest(case):
                self.npm_ci = ci
                result = self.apply("install")
                apply = result["apply"]
                self.assertEqual(apply["outcome"], "failed")
                self.assertEqual(apply["error"], message)
                self.assertNotIn("synthetic-token", json.dumps(result))
                self.assertTrue(Path(apply["backup"]).is_dir())
                self.assertEqual([f["path"] for f in apply["files"]], ["package-lock.json"])
                self.assertIn(RESTORE_NOTICE, apply["notices"])
                self.assertFalse([p for p in self.root.glob("depbee_install_*")])
                for name, data in self.original.items():
                    (self.upd / name).write_bytes(data)

    def test_a_project_npmrc_refuses_install_but_not_lockfile(self):
        (self.upd / ".npmrc").write_text("; synthetic\n", encoding="utf-8")
        apply = self.apply("install")["apply"]
        self.assertEqual((apply["outcome"], apply["reason"]), ("refused", "project_npmrc"))
        self.assertIn(NPMRC_INSTALL_NOTICE, apply["notices"])
        self.assert_unchanged()
        self.assertEqual(self.ci_calls, [])
        self.assert_applied(self.apply("lockfile")["apply"])

    def test_valid_sri_takes_only_known_algorithms_with_digests_of_their_length(self):
        valid = service.npm_cli.valid_sri
        good = [sri("a"), sri("a", "sha384"), sri("a", "sha256"), sri("a", "sha1"),
                f"{sri('a')} {sri('b')}", f" {sri('a')}\t{sri('a', 'sha1')}\n"]  # fmt: skip
        bad = [None, "", " ", "\t\n", "abc", "sha512", "sha512-", "md5-" + sri("a")[7:],
               "foo-" + sri("a")[7:], "SHA512-" + sri("a")[7:], "sha512-" + sri("a", "sha256")[7:],
               sri("a")[:-2], sri("a").replace("=", ""), sri("a")[:20] + "!" + sri("a")[21:],
               sri("a") + "?opt", f"{sri('a')} abc", f"{sri('a')} md5-abc", "sha512-é" + "A" * 87,
               ["sha512-x"], 5]  # fmt: skip
        self.assertEqual([v for v in good if not valid(v)], [])
        self.assertEqual([v for v in bad if valid(v)], [])

    def test_valid_sri_splits_only_on_ascii_space_tab_lf_cr(self):
        valid = service.npm_cli.valid_sri
        s, t = sri("a"), sri("b", "sha1")
        # A real lockfile value (lodash 4.17.21) and ASCII separators keep working.
        lodash = "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
        good = [lodash, f"{s} {t}", f" {s}\t{t} ", f"{s}\r\n{t}\n", f"\t\t{s}  \r{t}"]
        self.assertEqual([v for v in good if not valid(v)], [])
        # Python whitespace that ECMAScript \s and trim() do not strip (ssri keeps it in the
        # token and drops it), then other characters outside the four separators.
        others = ["\x85", "\x1c", "\x1d", "\x1e", "\x1f", "\x0b", "\x0c", "\xa0", " ",
                  "﻿", "　", "\x00"]  # fmt: skip
        bad = [v for c in others for v in (c + s, s + c, f"{s}{c}{t}", f"{s} {c} {t}")]
        self.assertEqual([v for v in bad if valid(v)], [])

    def test_install_refuses_a_python_only_whitespace_in_front(self):
        for char in ("\x85", "\x1c", "\x1d", "\x1e", "\x1f"):
            with self.subTest(char=hex(ord(char))):
                lock = json.loads(self.head.read_text(encoding="utf-8"))
                entry = lock["packages"]["node_modules/example"]
                entry["integrity"] = char + entry["integrity"]
                self.assert_install_refused_lockfile_applied(
                    lock,
                    "1 lockfile entries have no valid integrity to check: node_modules/example",
                )

    def npm_writes(self, lock):
        """The fake npm update writes lock as the new lockfile; returns its bytes."""
        new_lock = json.dumps(lock).encode("utf-8")

        def update(work):
            (work / "package-lock.json").write_bytes(new_lock)
            return 0, b"", b""

        self.npm_update = update
        return new_lock

    def assert_install_refused_lockfile_applied(self, lock, error):
        """install refuses lock before any change and without npm ci; lockfile writes it."""
        new_lock = self.npm_writes(lock)
        # A bundled entry is a second, unchecked result: confirmed so that the gate passes.
        apply = self.apply("install", confirm=True)["apply"]
        self.assertEqual((apply["outcome"], apply["reason"]), ("refused", "integrity_missing"))
        self.assertEqual(apply["error"], error)
        self.assert_unchanged()
        self.assertEqual(self.ci_calls, [])
        apply = self.apply("lockfile", confirm=True)["apply"]  # the same lockfile, no install
        self.assertEqual(apply["outcome"], "applied")
        self.assertEqual((self.upd / "package-lock.json").read_bytes(), new_lock)
        for name, data in self.original.items():  # back to the start for the next case
            (self.upd / name).write_bytes(data)
        shutil.rmtree(self.backups)

    def test_install_needs_a_valid_integrity_on_every_entry(self):
        self.assertEqual(service.npm_cli.missing_integrity(self.head.read_bytes()), [])
        lock = json.loads(self.head.read_text(encoding="utf-8"))
        lock["packages"]["node_modules/example"]["integrity"] = ""
        self.npm_writes(lock)
        with self.assertRaisesRegex(GuardError, "Invalid integrity"):  # the scan's input check
            self.apply("install", confirm=True)
        self.assert_unchanged()
        self.assertEqual(self.ci_calls, [])
        for value in (None, " ", "abc", "foo-" + sri("a")[7:], sri("a")[:-4], "absent"):
            with self.subTest(integrity=value):
                lock = json.loads(self.head.read_text(encoding="utf-8"))
                entry = lock["packages"]["node_modules/example"]
                if value == "absent":
                    del entry["integrity"]
                else:
                    entry["integrity"] = value
                self.assert_install_refused_lockfile_applied(
                    lock,
                    "1 lockfile entries have no valid integrity to check: node_modules/example",
                )

    def test_install_refuses_bundled_entries_root_and_nested(self):
        bundled = ("; 1 of them bundled (bundleDependencies), which depbee does not install: "
                   "apply the lockfile only and install yourself")  # fmt: skip
        # Root bundleDependencies: npm installs it on its own (arborist node.js 565-570).
        package = {**self.package, "bundleDependencies": ["example"]}
        self.write(self.upd / "package.json", package)
        self.original["package.json"] = (self.upd / "package.json").read_bytes()
        lock = json.loads(self.head.read_text(encoding="utf-8"))
        lock["packages"]["node_modules/example"] = {"version": "1.1.0", "inBundle": True}
        self.assert_install_refused_lockfile_applied(
            lock,
            "1 lockfile entries have no valid integrity to check: node_modules/example" + bundled,
        )
        # Inside a dependency, even with the parent's valid integrity.
        lock = json.loads(self.head.read_text(encoding="utf-8"))
        lock["packages"]["node_modules/example/node_modules/inner"] = {
            "version": "1.0.0", "inBundle": True,
        }  # fmt: skip
        self.assert_install_refused_lockfile_applied(
            lock,
            "1 lockfile entries have no valid integrity to check: "
            "node_modules/example/node_modules/inner" + bundled,
        )

    def test_a_scratch_folder_inside_the_project_is_refused_before_any_change(self):
        inside = self.upd / "tmp"
        inside.mkdir()
        names = [str(inside)]
        if os.name == "nt":
            names.append(str(inside).upper())  # Windows paths compare without case
        link = self.root / "link"
        try:
            if os.name == "nt":
                import _winapi

                _winapi.CreateJunction(str(self.upd), str(link))
            else:
                os.symlink(self.upd, link, target_is_directory=True)
            self.addCleanup(lambda: os.rmdir(link) if os.name == "nt" else os.unlink(link))
            names.append(str(link / "tmp"))  # resolved to the project's own folder
        except OSError:
            pass
        for name in names:
            with self.subTest(tmp=name), mock.patch("tempfile.tempdir", name):
                apply = self.apply("install")["apply"]
                self.assertEqual((apply["outcome"], apply["reason"]),
                                 ("refused", "scratch_in_project"))  # fmt: skip
                self.assertEqual(self.ci_calls, [])
                self.assertFalse(self.backups.exists())
                for file, data in self.original.items():
                    self.assertEqual((self.upd / file).read_bytes(), data)
                self.assertEqual(list(inside.iterdir()), [])  # scratch and preview removed
        self.assertTrue(link.exists() or len(names) < 3)
        self.assertEqual(len(names), 3 if os.name == "nt" else 2, "the link case did not run")

    def test_clean_install_needs_absolute_folders(self):
        with self.assertRaisesRegex(GuardError, "absolute"):
            service.npm_cli.clean_install(Path("relative"), self.root)


class CliTests(ApplyFixture):
    def test_three_formats_and_the_json_entry_point(self):
        self.verdict([PASS], 0)
        code, out, err = self.cli("--apply", "lockfile", "--format", "json")
        self.assertEqual((code, err), (0, ""))
        data = json.loads(out)
        self.assertEqual(list(data), ["preview", "report", "apply"])
        self.assertEqual(data["apply"]["outcome"], "applied")
        for name, data in self.original.items():
            (self.upd / name).write_bytes(data)
        code, out, _ = self.cli("--apply", "lockfile")
        self.assertEqual(code, 0)
        self.assertIn("depbee 업데이트 반영: 반영함", out)
        self.assertIn("원본 백업: ", out)
        self.assertIn(RESTORE_NOTICE, out)
        self.assertNotIn(PREVIEW_NOTICE, out)
        for name, data in self.original.items():
            (self.upd / name).write_bytes(data)
        code, out, _ = self.cli("--apply", "install", "--format", "markdown")
        self.assertEqual(code, 0)
        self.assertIn("## depbee 업데이트 반영: 반영함", out)
        self.assertIn(f"- {SCRIPTS_NOTICE}", out)
        self.assertIn("- npm ` 11.6.1 `, npm ci 종료 코드 0", out)

    def test_confirmation_list_is_shown_and_the_exit_code_rules(self):
        # The fixture's FakePredictor flags the change: report exit code 1.
        code, out, _ = self.cli("--apply", "lockfile")
        self.assertEqual(code, 1)
        self.assertIn("depbee 업데이트 반영: 반영하지 않음", out)
        self.assertIn("확인이 필요한 항목 1개(확인하지 않음):", out)
        self.assertIn("  - [위험] example@1.1.0 (node_modules/example): ML 위험 점수 기준 이상; "
                      "기지 악성 목록 미확인; ML 위험 점수 0.900", out)  # fmt: skip
        self.assertIn(f"{CONFIRM_OPTION}를 함께 줍니다", out)
        code, out, _ = self.cli("--apply", "lockfile", "--format", "markdown")
        self.assertIn("  - [위험] ` example `@` 1.1.0 ` (` node_modules/example `)", out)
        self.verdict([{**PASS, "known": "not_run"}], 0)
        self.assertEqual(self.cli("--apply", "lockfile")[0], 2)  # refused, report 0
        self.assertEqual(self.cli("--apply", "lockfile", CONFIRM_OPTION)[0], 0)
        self.verdict([{**PASS, "ml": "hit", "status": "flagged"}], 1)
        for name, data in self.original.items():
            (self.upd / name).write_bytes(data)
        self.assertEqual(self.cli("--apply", "lockfile", CONFIRM_OPTION)[0], 1)  # applied, 1
        self.verdict([PASS], 0)
        for name, data in self.original.items():
            (self.upd / name).write_bytes(data)
        self.npm_ci = lambda project: (1, b"", b"")
        self.assertEqual(self.cli("--apply", "install")[0], 2)  # failed

    def test_confirmation_without_apply_is_an_error_before_npm(self):
        code, out, err = self.cli(CONFIRM_OPTION)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("needs --apply", json.loads(err)["error"])
        self.assert_npm_not_run()


class HistoryTests(ApplyFixture):
    def test_unregistered_projects_are_not_recorded(self):
        db = Path(os.environ["DEPBEE_HISTORY_DB"])
        self.cli("--apply", "lockfile", CONFIRM_OPTION)
        self.assertFalse(db.exists())
        (self.root / "other").mkdir()
        history.register_project(self.root / "other")
        before = db.read_bytes()
        for name, data in self.original.items():
            (self.upd / name).write_bytes(data)
        self.cli("--apply", "lockfile", CONFIRM_OPTION)
        self.assertEqual(db.read_bytes(), before)

    def test_a_registered_apply_is_recorded_with_its_preview_run(self):
        db = Path(os.environ["DEPBEE_HISTORY_DB"])
        project_id = history.register_project(self.upd)
        code, out, err = self.cli("--apply", "lockfile", CONFIRM_OPTION, "--format", "json")
        self.assertEqual((code, err), (1, ""))
        output = json.loads(out)
        (run,) = history.list_runs(project_id)
        stored = history.get_run(run["id"])
        self.assertEqual(stored["kind"], "update_preview")
        self.assertEqual(
            (stored["preview"], stored["report"]), (output["preview"], output["report"])
        )
        (apply,) = history.list_applies(project_id)
        self.assertEqual(apply["apply"], output["apply"])
        self.assertEqual((apply["run_id"], apply["outcome"], apply["confirmed"], apply["backup"]),
                         (run["id"], "applied", True, output["apply"]["backup"]))  # fmt: skip
        self.assertEqual(apply["apply"]["confirmation_required"][0]["causes"],
                         ["ml_hit", "known_malicious_unchecked"])  # fmt: skip
        self.assertEqual(apply["new_package_lock_sha256"], sha(self.head.read_bytes()))
        # Only hashes, never the new lockfile itself.
        self.assertNotIn(self.head.read_text(encoding="utf-8"), db.read_bytes().decode("latin-1"))
        self.assertEqual(sql(db, "PRAGMA user_version"), [(2,)])
