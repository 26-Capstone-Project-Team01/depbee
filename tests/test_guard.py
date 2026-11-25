"""depbee.guard (the Claude Code PreToolUse hook and its settings) and service.install_checked
(depbee guard ci). Synthetic commands, projects and settings only; npm, Git and the analyzer are
mocked, and no test runs npm, Node.js or Claude Code.
"""

import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

from test_apply import PASS, ApplyFixture
from test_workflow import Fixture

from depbee import guard, service
from depbee.cli import main
from depbee.contracts import GuardError
from depbee.service import GUARD_CHANGED, install_checked

SRC = str(Path(__file__).resolve().parents[1] / "src")
# The hook as Claude Code runs it (-I: no PYTHONPATH, user site or current folder), with this
# checkout's src first: the test Python's own depbee may be another copy.
BOOT = (
    "import runpy, sys; sys.path.insert(0, sys.argv.pop(1)); "
    "runpy.run_module('depbee.guard', run_name='__main__', alter_sys=True)"
)
HOOK = [sys.executable, "-I", "-c", BOOT, SRC, "hook"]


def event(command, tool="Bash", cwd=None, **extra):
    """A PreToolUse event shaped as Claude Code sends it (code.claude.com/docs/en/hooks)."""
    return {
        "session_id": "abc123", "transcript_path": "/tmp/transcript.jsonl",
        "cwd": cwd if cwd is not None else os.getcwd(), "permission_mode": "default",
        "hook_event_name": "PreToolUse", "tool_name": tool,
        "tool_input": {"command": command, "description": "synthetic", "timeout": 120000,
                       "run_in_background": False},
        "tool_use_id": "toolu_01ABC123", **extra,
    }  # fmt: skip


class DecisionTests(Fixture):
    def decide(self, command, tool="Bash", cwd=None):
        return guard.decide(event(command, tool, str(cwd or self.project)))

    def assert_denied(self, commands, tool="Bash", contains=None):
        for command in commands:
            with self.subTest(tool=tool, command=command):
                reason = self.decide(command, tool)
                self.assertIsNotNone(reason, "passed")
                self.assertTrue(reason.startswith(guard.HEADER), reason)
                if contains:
                    self.assertIn(contains, reason)

    def assert_passed(self, commands, tool="Bash"):
        for command in commands:
            with self.subTest(tool=tool, command=command):
                self.assertIsNone(self.decide(command, tool))

    def test_installs_without_the_check_are_refused(self):
        self.assert_denied([
            "npm install lodash", "npm i lodash", "npm add lodash@4.17.21", "npm install",
            "npm update", "npm up lodash", "npm uninstall lodash", "npm rm lodash",
            "npm audit fix", "npm audit fix --force", "npm install -g lodash",
            "/usr/local/bin/npm install lodash", "NPM.CMD install lodash",
            '"C:/Program Files/nodejs/npm.cmd" install lodash',
            'node "C:/Program Files/nodejs/node_modules/npm/bin/npm-cli.js" install lodash',
        ])  # fmt: skip

    def test_clean_installs_point_to_guard_ci(self):
        self.assert_denied(
            ["npm ci", "npm ci --ignore-scripts", "npm clean-install", "npm install-test",
             "npm cit", "timeout 600 npm ci"],
            contains="-m depbee guard ci",
        )  # fmt: skip

    def test_packages_that_run_or_rebuild_are_refused(self):
        self.assert_denied(
            ["npx cowsay", "npx --no eslint .", "npm exec -- cowsay", "npm x cowsay",
             "npm create vite@latest app", "npm init vite", "corepack npx tsc"],
            contains="npx·npm exec",
        )  # fmt: skip
        self.assert_denied(["npm rebuild", "npm rb", "npm link", "npm dedupe", "npm prune"])

    def test_abbreviations_and_other_spellings_npm_accepts_are_refused(self):
        # npm resolves these to install, update or install-test (lib/utils/cmd-list.js deref);
        # the guard passes exact words only.
        self.assert_denied(["npm insta lodash", "npm isntall lodash", "npm upd", "npm installTest",
                            "npm instal lodash --package-lock-only --ignore-scripts"])  # fmt: skip

    def test_a_lockfile_only_change_passes(self):
        self.assert_passed([
            "npm install lodash@4.17.21 --package-lock-only --ignore-scripts",
            "npm i -D @types/node@20.11.0 --ignore-scripts --package-lock-only",
            "npm install --package-lock-only --ignore-scripts",
            "npm install lodash@^4.17.0 left-pad@latest --package-lock-only --ignore-scripts -E",
            "npm i x --package-lock-only=true --ignore-scripts=true --legacy-peer-deps --no-fund",
            "npm update lodash --package-lock-only --ignore-scripts",
            "npm uninstall lodash --package-lock-only --ignore-scripts",
            "npm audit fix --package-lock-only --ignore-scripts",
            "npm install lodash@4.17.21 \\\n  --package-lock-only \\\n  --ignore-scripts",
            "cd sub && npm i x@1.0.0 --package-lock-only --ignore-scripts",
            "npm --prefix sub install x@1.0.0 --package-lock-only --ignore-scripts",
        ])  # fmt: skip
        self.assert_passed(
            ["npm install lodash@4.17.21 --package-lock-only --ignore-scripts"], "PowerShell"
        )

    def test_a_lockfile_only_change_must_really_be_one(self):
        self.assert_denied([
            "npm install lodash --package-lock-only",
            "npm install lodash --ignore-scripts",
            "npm install lodash --package-lock-only --ignore-scripts --package-lock-only=false",
            "npm install lodash --package-lock-only --ignore-scripts --no-ignore-scripts",
            "npm install lodash --package-lock-only --ignore-scripts=false",
            "npm install lodash --package-lock-only --ignore-scripts -g",
            "npm install lodash --package-lock-only --ignore-scripts --force",
            "npm install lodash --package-lock-only --ignore-scripts --git=./x",
            "npm install lodash --package-lock-only --ignore-scripts --userconfig=./x",
            "npm uninstall --package-lock-only --ignore-scripts",
            "npm audit fix extra --package-lock-only --ignore-scripts",
        ])  # fmt: skip

    def test_a_lockfile_only_change_takes_registry_names_only(self):
        for spec in ("github:user/repo", "lodash@git+https://example.invalid/x.git",
                     "file:../local", "./local", "../local", "x@npm:lodash", "x.tgz",
                     "x@./y", "https://example.invalid/x.tgz", "-x"):  # fmt: skip
            with self.subTest(spec=spec):
                reason = self.decide(f"npm install {spec} --package-lock-only --ignore-scripts")
                self.assertIsNotNone(reason)

    def test_a_lockfile_only_change_with_a_prefix_or_wrapper_is_refused(self):
        self.assert_denied([
            "npm_config_git=./x npm install x --package-lock-only --ignore-scripts",
            "sudo npm install x --package-lock-only --ignore-scripts",
            "env npm install x --package-lock-only --ignore-scripts",
        ], contains="환경 변수나 다른 명령")  # fmt: skip

    def test_a_project_npmrc_or_an_unknown_folder_refuses_the_change(self):
        (self.project / ".npmrc").write_text("registry=https://example.invalid/\n", "utf-8")
        self.assert_denied(
            ["npm install x --package-lock-only --ignore-scripts"], contains=".npmrc"
        )
        (self.project / ".npmrc").unlink()
        self.assert_denied(
            ['cd "$DIR" && npm install x --package-lock-only --ignore-scripts'],
            contains="프로젝트 폴더를 판정할 수 없습니다",
        )
        (self.project / "sub").mkdir()
        (self.project / "sub" / ".npmrc").write_text("x=1\n", "utf-8")
        self.assert_denied(["cd sub && npm i x --package-lock-only --ignore-scripts",
                            "npm --prefix sub i x --package-lock-only --ignore-scripts"])  # fmt: skip

    def test_every_segment_is_judged(self):
        self.assert_denied([
            "npm view lodash version && npm install lodash", "npm view x; npm ci",
            "npm view x\nnpm ci", "(cd sub && npm ci)", "if true; then npm ci; fi",
            "true || npm ci", "npm ci &", "npm ls | npm ci", "x=$(npm ci)",
            "cat <(npm ci)", "{ npm ci; }",
        ])  # fmt: skip

    def test_commands_it_cannot_read_are_refused(self):
        self.assert_denied([
            "bash -c 'npm ci'", 'sh -c "npm install x"', "echo 'npm ci' | sh", 'eval "npm ci"',
            "echo `npm bin`", "$NPM install x", "xargs npm install < list.txt",
            "env -u HOME npm ci", "sudo -u root npm ci",
            "node -e \"require('child_process').execSync('npm i x')\"",
            "python -c \"import os; os.system('npm ci')\"", "npm install 'x",
            "npm --unknown value install x", "npm -- install x",
        ], contains="판정할 수 없습니다")  # fmt: skip
        self.assert_denied(
            ["Invoke-Expression 'npm ci'", 'iex "npm i x"', "Start-Process npm -ArgumentList ci",
             "cmd /c npm ci", 'powershell -Command "npm ci"', "& $npm install x"],
            "PowerShell", contains="판정할 수 없습니다",
        )  # fmt: skip

    def test_powershell_forms(self):
        self.assert_denied([
            r"& 'C:\Program Files\nodejs\npm.cmd' install x", "npm.cmd ci", "npm.ps1 install x",
            "$out = npm ci", "foreach ($p in $list) { npm install $p }",
            "Get-ChildItem | ForEach-Object { npm install $_.Name }",
        ], "PowerShell")  # fmt: skip
        self.assert_passed([
            r"& 'C:\Program Files\nodejs\npm.cmd' view lodash", "npm.cmd test",
            "$v = npm view lodash version", "Get-Content package.json | ConvertFrom-Json",
            "Select-String -Pattern 'npm install' -Path README.md",
            "Get-ChildItem | % { $_.Name }; npm -v", r"Set-Location 'C:\x y'; npm ls",
        ], "PowerShell")  # fmt: skip

    def test_reading_and_project_scripts_pass(self):
        self.assert_passed([
            "ls -la", "git status", "cat package.json", "npm", "npm -v", "npm --version",
            "npm help install", "npm view lodash version", "npm info lodash", "npm ls --all",
            "npm outdated", "npm explain lodash", "npm config get registry", "npm pkg get name",
            "npm audit", "npm audit --json", "npm run build", "npm test", "npm run lint -- --fix",
            "npm init -y", "npm --prefix sub run build", "npm -s run test", "npm start",
            "node -v && npm -v", "cd sub && npm ls", "time npm test",
            "nohup npm run dev > out.log 2>&1 &", "command -v npm", "which npx",
        ])  # fmt: skip

    def test_the_word_npm_in_data_passes(self):
        self.assert_passed([
            'grep -rn "npm install" docs', "rg 'npm ci' README.md", "git log --grep=npm",
            'git commit -m "docs: explain npm install guard"', 'echo "run npm install"',
            "cat .npmrc", "ls node_modules/.bin", "pnpm --version",
            "git commit -m \"$(cat <<'EOF'\nchore: npm ci in docs\nEOF\n)\"",
            "cat package.json | grep npm", "Get-Content docs/x.md | Select-String npm",
        ])  # fmt: skip

    def test_agents_cannot_confirm_warnings_or_change_the_guard(self):
        self.assert_denied([
            "depbee update --apply install --confirm-warnings", "depbee update --confirm-w",
            "depbee update lodash --apply lockfile --co",
            "python -m depbee update --apply install --confirm-warnings",
            "python -Im depbee update --apply install --confirm-warnings",
            r"'C:\x\.venv\Scripts\depbee.exe' update --apply install --confirm-warnings",
            "depbee guard disable .claude/settings.local.json",
            "depbee guard enable .claude/settings.local.json",
            "DEPBEE_MODEL_DIR=/tmp/m depbee guard ci .",
            "export DEPBEE_KNOWN_MALICIOUS_DIR=/tmp/i; depbee guard ci .",
        ])  # fmt: skip
        self.assert_denied(["$env:DEPBEE_MODEL_DIR = 'C:\\m'; depbee guard ci ."], "PowerShell")
        self.assert_passed([
            "depbee update --apply install", "depbee guard ci .", "depbee guard status x.json",
            "depbee scan . --extract", "depbee check lodash@4.17.21",
            "python -m depbee guard ci C:/project", "depbee update -- --confirm-warnings",
        ])  # fmt: skip

    def test_the_refusal_names_the_next_commands(self):
        reason = self.decide("npm install lodash@4.17.21")
        self.assertIn("npm install lodash@4.17.21 --package-lock-only --ignore-scripts", reason)
        self.assertIn("scan_lockfile", reason)
        self.assertIn(guard.guard_command(str(self.project), False), reason)
        self.assertIn(guard.CLOSING, reason)
        shell = self.decide("npm ci", "PowerShell")
        self.assertIn(guard.guard_command(str(self.project), True), shell)
        self.assertTrue(guard.guard_command("C:/p", True).startswith("& '"))
        # A cd before npm moves the project the refusal names.
        moved = self.decide("cd sub && npm ci")
        self.assertIn(guard.guard_command(str(self.project / "sub"), False), moved)

    def test_quoting_of_the_guard_command(self):
        self.assertEqual(guard._quote("C:\\it's\u2019 x", True), "'C:\\it''s\u2019\u2019 x'")
        self.assertEqual(guard._quote("/a b/it's", False), "'/a b/it'\"'\"'s'")
        with mock.patch.object(sys, "executable", "/opt/py 3/bin/python"):
            self.assertEqual(guard.guard_command("/p q", False),
                             "'/opt/py 3/bin/python' -I -m depbee guard ci '/p q'")  # fmt: skip
            self.assertIn("<프로젝트 폴더의 절대 경로>", guard.guard_command(None, True))

    def test_other_events_and_tools(self):
        self.assertIsNone(guard.decide({**event("npm ci"), "hook_event_name": "PostToolUse"}))
        self.assertIsNone(guard.decide({**event("x"), "tool_name": "Write", "tool_input": {}}))
        # The Monitor tool's shell commands carry a command too: judged as Bash.
        self.assertIsNotNone(guard.decide({**event("npm ci"), "tool_name": "Monitor"}))
        for broken in ({**event("x"), "tool_input": {}}, {**event("x"), "tool_input": "npm ci"},
                       {**event("x"), "tool_name": "PowerShell", "tool_input": {"command": 1}},
                       [], "npm ci"):  # fmt: skip
            with self.subTest(broken=broken), self.assertRaises(GuardError):
                guard.decide(broken)


class ProtocolTests(Fixture):
    """The hook's answer as Claude Code reads it: exit 0 with one JSON deny object or nothing,
    exit 2 (a block) for every failure, never an allow."""

    def run_hook(self, data):
        stdout, stderr = io.StringIO(), io.StringIO()
        code = guard.hook(io.BytesIO(data), stdout, stderr)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_deny_is_one_ascii_json_object_on_exit_0(self):
        code, out, err = self.run_hook(json.dumps(event("npm install lodash")).encode())
        self.assertEqual((code, err), (0, ""))
        out.encode("ascii")  # any console code page reads it
        decision = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(sorted(decision), ["hookEventName", "permissionDecision",
                                            "permissionDecisionReason"])  # fmt: skip
        self.assertEqual((decision["hookEventName"], decision["permissionDecision"]),
                         ("PreToolUse", "deny"))  # fmt: skip
        self.assertIn("--package-lock-only --ignore-scripts", decision["permissionDecisionReason"])

    def test_no_objection_prints_nothing_and_never_allows(self):
        for command in ("ls", "npm view x", "npm i x --package-lock-only --ignore-scripts"):
            with self.subTest(command=command):
                self.assertEqual(self.run_hook(json.dumps(event(command)).encode()), (0, "", ""))

    def test_every_failure_is_exit_2_with_a_reason_and_no_stdout(self):
        too_big = b'{"x": "' + b"a" * guard.MAX_INPUT_BYTES + b'"}'
        cases = {
            "not json": b"{", "not utf-8": b'{"cwd": "\xff"}', "not an object": b"[]",
            "no command": json.dumps({**event("x"), "tool_input": {}}).encode(),
            "too big": too_big, "empty": b"",
        }  # fmt: skip
        for case, data in cases.items():
            with self.subTest(case):
                code, out, err = self.run_hook(data)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("blocked", err)
                err.encode("ascii")

    def test_unexpected_errors_and_interrupts_block_too(self):
        for error in (RuntimeError("boom"), KeyboardInterrupt(), MemoryError(), SystemExit(0)):
            with self.subTest(error=type(error).__name__):
                with mock.patch("depbee.guard.decide", side_effect=error):
                    code, out, _ = self.run_hook(json.dumps(event("ls")).encode())
                self.assertEqual((code, out), (2, ""))

    def test_main_takes_hook_only(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(guard.main(["other"]), 2)
            self.assertEqual(guard.main([]), 2)


class ProcessTests(Fixture):
    """The hook as a separate process, as Claude Code starts it from settings (exec form)."""

    def spawn(self, data, env=None):
        return subprocess.run(HOOK, input=data, capture_output=True, timeout=60, env=env)

    def test_real_events_from_bash_and_powershell(self):
        folder = self.root / "프로젝트 폴더"  # spaces and non-ASCII in the cwd
        folder.mkdir()
        denied = self.spawn(json.dumps(event("npm install lodash", cwd=str(folder))).encode())
        self.assertEqual(denied.returncode, 0, denied.stderr)
        reason = json.loads(denied.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn(str(folder), reason)
        shell = self.spawn(json.dumps(event("npm.cmd ci", "PowerShell", str(folder))).encode())
        self.assertEqual(json.loads(shell.stdout)["hookSpecificOutput"]["permissionDecision"],
                         "deny")  # fmt: skip
        passed = self.spawn(json.dumps(event("npm view lodash", cwd=str(folder))).encode())
        self.assertEqual((passed.returncode, passed.stdout, passed.stderr), (0, b"", b""))
        broken = self.spawn(b"not json")
        self.assertEqual((broken.returncode, broken.stdout), (2, b""))

    def test_isolated_mode_ignores_a_planted_pythonpath(self):
        planted = self.root / "planted" / "depbee"
        planted.mkdir(parents=True)
        (planted / "__init__.py").write_text("", "utf-8")
        (planted / "guard.py").write_text("print('planted')\n", "utf-8")
        env = {**os.environ, "PYTHONPATH": str(planted.parent)}
        done = self.spawn(json.dumps(event("npm ci")).encode(), env)
        self.assertNotIn(b"planted", done.stdout)
        self.assertEqual(json.loads(done.stdout)["hookSpecificOutput"]["permissionDecision"],
                         "deny")  # fmt: skip

    def test_self_test_runs_the_handler(self):
        entry = {"command": sys.executable, "args": HOOK[1:], "timeout": 60}
        self.assertIsNone(guard.self_test(entry, self.root))
        broken = {**entry, "args": ["-c", "import sys; sys.exit(1)"]}
        self.assertIn("exit 1", guard.self_test(broken, self.root))
        silent = {**entry, "args": ["-c", "pass"]}  # never denies
        self.assertIn("decision None", guard.self_test(silent, self.root))
        missing = {**entry, "command": str(self.root / "missing" / "python.exe")}
        self.assertIn("could not be run", guard.self_test(missing, self.root))
        for edited in ({**entry, "command": None}, {**entry, "args": [1]},
                       {**entry, "timeout": "30"}):  # fmt: skip
            self.assertIn("not of the type", guard.self_test(edited, self.root))
        without_timeout = {key: value for key, value in entry.items() if key != "timeout"}
        self.assertIsNone(guard.self_test(without_timeout, self.root))  # Claude's default


ORCA = {"matcher": "", "hooks": [{"type": "command",
                                  "command": "C:\\Users\\x\\orca\\orca-agent-hook.exe",
                                  "args": ["pre-tool-use"]}]}  # fmt: skip
SETTINGS = {
    "permissions": {"allow": ["Bash(npm run test *)"]},
    "env": {"TMP": "C:\\temp"},
    "hooks": {"PreToolUse": [ORCA], "Stop": [{"hooks": [{"type": "command", "command": "x"}]}]},
    "enabledPlugins": {"example@market": True},
}


class SettingsTests(Fixture):
    def setUp(self):
        super().setUp()
        self.settings = self.root / ".claude" / "settings.local.json"
        self.settings.parent.mkdir()
        self.self_test = mock.patch("depbee.guard.self_test", return_value=None)
        self.self_test.start()
        self.addCleanup(self.self_test.stop)

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["guard", *args])
        return code, out.getvalue(), err.getvalue()

    def write(self, path, obj):
        path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")

    def ours(self):
        return guard.handler(os.path.abspath(sys.executable))

    def backups(self):
        return sorted(self.settings.parent.glob("*.depbee-backup-*"))

    def leftovers(self):
        return sorted(self.settings.parent.glob(".*.depbee"))

    def test_enable_adds_one_group_and_keeps_everything_else(self):
        self.write(self.settings, SETTINGS)
        original = self.settings.read_bytes()
        code, out, _ = self.cli("enable", str(self.settings))
        self.assertEqual(code, 0, out)
        saved = json.loads(self.settings.read_text("utf-8"))
        self.assertEqual({k: v for k, v in saved.items() if k != "hooks"},
                         {k: v for k, v in SETTINGS.items() if k != "hooks"})  # fmt: skip
        self.assertEqual(saved["hooks"]["Stop"], SETTINGS["hooks"]["Stop"])
        self.assertEqual(saved["hooks"]["PreToolUse"],
                         [ORCA, {"matcher": "Bash|PowerShell", "hooks": [self.ours()]}])  # fmt: skip
        handler = saved["hooks"]["PreToolUse"][1]["hooks"][0]
        self.assertEqual((handler["args"], handler["onFailure"], handler["type"]),
                         (["-I", "-m", "depbee.guard", "hook"], "block", "command"))  # fmt: skip
        self.assertTrue(os.path.isabs(handler["command"]))
        (backup,) = self.backups()
        self.assertEqual(backup.read_bytes(), original)
        self.assertEqual(self.leftovers(), [])

    def test_enable_creates_a_missing_file_and_is_idempotent(self):
        self.assertEqual(self.cli("enable", str(self.settings))[0], 0)
        first = self.settings.read_bytes()
        self.assertEqual(json.loads(first), {"hooks": {"PreToolUse": [
            {"matcher": "Bash|PowerShell", "hooks": [self.ours()]}]}})  # fmt: skip
        self.assertEqual(self.backups(), [])  # nothing to back up
        code, out, _ = self.cli("enable", str(self.settings))
        self.assertEqual((code, self.settings.read_bytes(), self.backups()), (0, first, []))
        self.assertIn("바꿀 것이 없습니다", out)

    def test_enable_replaces_an_older_handler_and_disable_removes_only_ours(self):
        old = {**self.ours(), "command": "C:\\old\\python.exe"}
        mixed = {"matcher": "Bash", "hooks": [old, {"type": "command", "command": "other"}]}
        self.write(self.settings, {"hooks": {"PreToolUse": [ORCA, mixed]}})
        self.assertEqual(self.cli("enable", str(self.settings))[0], 0)
        groups = json.loads(self.settings.read_text("utf-8"))["hooks"]["PreToolUse"]
        self.assertEqual(groups, [ORCA, {"matcher": "Bash", "hooks": [mixed["hooks"][1]]},
                                  {"matcher": "Bash|PowerShell", "hooks": [self.ours()]}])  # fmt: skip
        self.assertEqual(self.cli("disable", str(self.settings))[0], 0)
        self.assertEqual(json.loads(self.settings.read_text("utf-8")),
                         {"hooks": {"PreToolUse": [ORCA, groups[1]]}})  # fmt: skip
        before = self.settings.read_bytes()
        code, out, _ = self.cli("disable", str(self.settings))
        self.assertEqual((code, self.settings.read_bytes()), (0, before))
        self.assertIn("바꿀 것이 없습니다", out)

    def test_disable_drops_hooks_it_emptied(self):
        self.cli("enable", str(self.settings))
        self.cli("disable", str(self.settings))
        self.assertEqual(json.loads(self.settings.read_text("utf-8")), {})

    def test_unreadable_settings_are_left_as_they_are(self):
        cases = {
            "invalid json": b"{ \"hooks\": ", "duplicate key": b'{"a": 1, "a": 2}',
            "not an object": b"[]", "hooks not an object": b'{"hooks": []}',
            "PreToolUse not a list": b'{"hooks": {"PreToolUse": {}}}',
        }  # fmt: skip
        for case, data in cases.items():
            for action in ("enable", "disable", "status"):
                with self.subTest(case, action=action):
                    self.settings.write_bytes(data)
                    code, _, err = self.cli(action, str(self.settings))
                    self.assertEqual(code, 2)
                    self.assertIn('"status": "error"', err)
                    self.assertEqual(self.settings.read_bytes(), data)
                    self.assertEqual((self.backups(), self.leftovers()), ([], []))

    def test_a_concurrent_edit_is_kept_and_nothing_is_written(self):
        self.write(self.settings, SETTINGS)
        theirs = json.dumps({**SETTINGS, "model": "theirs"}).encode()

        def other_writer(source, target):  # runs between depbee's read and its replace
            self.settings.write_bytes(theirs)

        with mock.patch("depbee.guard.shutil.copymode", side_effect=other_writer):
            code, _, err = self.cli("enable", str(self.settings))
        self.assertEqual(code, 2)
        self.assertIn("changed while depbee edited it", err)
        self.assertEqual(self.settings.read_bytes(), theirs)
        self.assertEqual((self.backups(), self.leftovers()), ([], []))

    def test_a_failed_replace_keeps_the_original_file(self):
        self.write(self.settings, SETTINGS)
        original = self.settings.read_bytes()
        with mock.patch("depbee.guard.os.replace", side_effect=OSError("disk full")):
            code, _, _ = self.cli("enable", str(self.settings))
        self.assertEqual((code, self.settings.read_bytes(), self.leftovers()), (2, original, []))

    def test_enable_writes_nothing_when_the_self_test_fails(self):
        self.write(self.settings, SETTINGS)
        original = self.settings.read_bytes()
        with mock.patch("depbee.guard.self_test", return_value="exit 1"):
            code, _, err = self.cli("enable", str(self.settings))
        self.assertEqual((code, self.settings.read_bytes(), self.backups()), (2, original, []))
        self.assertIn("nothing was written", err)

    def test_status(self):
        self.assertEqual(self.cli("status", str(self.settings))[0], 2)  # no file, no hook
        self.cli("enable", str(self.settings))
        code, out, _ = self.cli("status", str(self.settings))
        self.assertEqual(code, 0, out)
        self.assertIn("자가 시험 통과", out)
        with mock.patch("depbee.guard.self_test", return_value="exit 1"):
            self.assertEqual(self.cli("status", str(self.settings))[0], 2)
        saved = json.loads(self.settings.read_text("utf-8"))
        saved["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"] = "continue"
        self.write(self.settings, saved)
        code, out, _ = self.cli("status", str(self.settings))
        self.assertEqual(code, 2)
        self.assertIn("onFailure", out)


class InstallCheckedTests(ApplyFixture):
    """depbee guard ci on a project whose lockfile changed from Git HEAD (base.json here)."""

    def setUp(self):
        super().setUp()
        (self.upd / "package-lock.json").write_bytes(self.head.read_bytes())
        self.original = {name: (self.upd / name).read_bytes()
                         for name in ("package.json", "package-lock.json")}  # fmt: skip
        self.bases = None  # successive Git HEAD lockfiles, else base.json every time
        self.patch("depbee.inputs.npm.read_base_lock", side_effect=self.git_head)
        self.at_version = None  # runs when npm --version runs, right before npm ci

    def git_head(self, project, ref, git_dir=None):
        self.assertEqual((Path(project), ref), (self.upd.absolute(), "HEAD"))
        return self.bases.pop(0) if self.bases else self.base.read_bytes()

    def fake_run(self, argv, cwd, limit, env=None, **kwargs):
        if argv[2] == "--version" and self.at_version:
            self.at_version()
        return super().fake_run(argv, cwd, limit, env, **kwargs)

    def assert_not_installed(self):
        self.assertEqual(self.ci_calls, [])
        for name, data in self.original.items():
            self.assertEqual((self.upd / name).read_bytes(), data, name)

    def test_a_passing_change_is_installed_from_the_checked_bytes(self):
        self.verdict([PASS], 0)
        result = install_checked(self.upd)
        self.assertEqual(result["apply"]["outcome"], "applied", result["apply"])
        (ci,) = self.ci_calls
        self.assertIn("ci", ci["argv"])
        self.assertIn("--ignore-scripts", ci["argv"])
        self.assertEqual(ci["cwd"], self.upd.absolute())
        for name, data in self.original.items():  # depbee wrote nothing in the project
            self.assertEqual((self.upd / name).read_bytes(), data, name)
        self.assertEqual(result["apply"]["files"], [])

    def test_no_change_is_not_a_pass(self):
        (self.upd / "package-lock.json").write_bytes(self.base.read_bytes())
        self.original["package-lock.json"] = self.base.read_bytes()
        result = install_checked(self.upd)
        self.assertEqual((result["report"]["results"], result["apply"]["outcome"]),
                         ([], "unchanged"))  # fmt: skip
        self.assert_not_installed()

    def test_risk_hold_and_unchecked_items_are_not_installed(self):
        rows = {
            "ml hit": {"status": "flagged", "reason": None, "ml": "hit", "known": "not_hit"},
            "known hit": {"status": "flagged", "reason": None, "ml": "not_hit", "known": "hit"},
            "incomplete": {"status": "incomplete", "reason": "no_baseline", "ml": "not_run",
                           "known": "not_hit"},
            "index not connected": {**PASS, "known": "not_run"},
        }  # fmt: skip
        for case, row in rows.items():
            with self.subTest(case):
                self.verdict([row])
                apply = install_checked(self.upd)["apply"]
                self.assertEqual(apply["outcome"], "refused")
                self.assert_not_installed()

    def test_a_change_after_the_check_is_not_installed(self):
        self.verdict([PASS], 0, during=lambda: (self.upd / "package.json").write_text(
            '{"name": "app", "dependencies": {"example": "^1.1.0"}}', "utf-8"))  # fmt: skip
        apply = install_checked(self.upd)["apply"]
        self.assertEqual((apply["outcome"], apply["reason"]), ("refused", "project_changed"))
        self.assertEqual(self.ci_calls, [])

    def test_files_or_head_that_change_right_before_npm_ci_stop_it(self):
        self.verdict([PASS], 0)
        changes = {
            "lockfile": lambda: (self.upd / "package-lock.json").write_bytes(
                self.original["package-lock.json"] + b"\n"),
            "npmrc": lambda: (self.upd / ".npmrc").write_text("x=1\n", "utf-8"),
            "head": lambda: self.bases.append(self.head.read_bytes()),
        }  # fmt: skip
        for case, change in changes.items():
            with self.subTest(case):
                self.ci_calls.clear()
                self.bases = [self.base.read_bytes()] * 2  # the plan and the scan
                self.at_version = change
                apply = install_checked(self.upd)["apply"]
                self.assertEqual((apply["outcome"], apply["reason"]), ("failed", "install_failed"))
                self.assertIn("npm ci was not started", apply["error"])
                self.assertEqual(self.ci_calls, [])
                (self.upd / "package-lock.json").write_bytes(self.original["package-lock.json"])
                with contextlib.suppress(FileNotFoundError):
                    (self.upd / ".npmrc").unlink()

    def test_a_lockfile_read_differently_by_the_scan_is_refused(self):
        self.bases = [self.base.read_bytes(), self.head.read_bytes()]  # HEAD moved meanwhile
        with self.assertRaises(GuardError) as caught:
            install_checked(self.upd)
        self.assertEqual(str(caught.exception), GUARD_CHANGED)
        self.assertEqual(self.ci_calls, [])

    def test_refusals_before_the_check(self):
        cases = {
            ".npmrc": lambda: (self.upd / ".npmrc").write_text("x=1\n", "utf-8"),
            "node_modules file": lambda: (self.upd / "node_modules").write_text("", "utf-8"),
            "workspaces": lambda: (self.upd / "package.json").write_text(
                '{"name": "app", "workspaces": ["a"]}', "utf-8"),
        }  # fmt: skip
        for case, make in cases.items():
            with self.subTest(case):
                make()
                with self.assertRaises(GuardError):
                    install_checked(self.upd)
                self.assertEqual(self.ci_calls, [])
                for name in (".npmrc", "node_modules"):
                    with contextlib.suppress(FileNotFoundError):
                        (self.upd / name).unlink()
                (self.upd / "package.json").write_bytes(self.original["package.json"])

    def test_missing_integrity_and_no_base_are_errors(self):
        lock = json.loads(self.original["package-lock.json"])
        lock["packages"]["node_modules/example"].pop("integrity")
        (self.upd / "package-lock.json").write_text(json.dumps(lock), "utf-8")
        with self.assertRaisesRegex(GuardError, "no valid integrity"):
            install_checked(self.upd)
        (self.upd / "package-lock.json").write_bytes(self.original["package-lock.json"])
        with (
            mock.patch("depbee.inputs.npm.read_base_lock", side_effect=GuardError("no HEAD")),
            self.assertRaisesRegex(GuardError, "no HEAD"),
        ):
            install_checked(self.upd)
        self.assertEqual(self.ci_calls, [])

    def test_more_changes_than_the_limit_stop_before_any_analysis(self):
        extractor = self.patch("depbee.analysis.extractor.ExtractorAnalyzer")
        extractor.return_value.measurements = {}

        def analyze(request):
            extractor.call_args.kwargs["progress"](1, service.GUARD_MAX_PACKAGES + 1, {})
            raise AssertionError("analyzed")

        extractor.return_value.analyze.side_effect = analyze
        with self.assertRaisesRegex(GuardError, f"at most {service.GUARD_MAX_PACKAGES}"):
            install_checked(self.upd)
        self.assertEqual(self.ci_calls, [])

    def test_a_second_guard_on_the_same_project_is_refused(self):
        self.verdict([PASS], 0)
        with service._install_lock(self.upd):
            with self.assertRaisesRegex(GuardError, "Another depbee guard ci"):
                install_checked(self.upd)
        self.assertEqual(self.ci_calls, [])
        self.assertEqual(install_checked(self.upd)["apply"]["outcome"], "applied")  # freed

    def test_cli_exit_codes_and_output(self):
        def cli(*args):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["guard", "ci", str(self.upd), *args])
            return code, out.getvalue(), err.getvalue()

        (self.upd / "package-lock.json").write_bytes(self.base.read_bytes())
        code, out, _ = cli()
        self.assertEqual(code, 2)
        self.assertIn("변경 0건은 통과가 아닙니다", out)
        (self.upd / "package-lock.json").write_bytes(self.original["package-lock.json"])
        self.verdict([PASS], 0)
        code, out, _ = cli()
        self.assertEqual(code, 0, out)
        self.assertIn("depbee 검사 후 설치: 설치함", out)
        code, out, _ = cli("--format", "json")
        self.assertEqual((code, sorted(json.loads(out))), (0, ["apply", "report"]))
        self.npm_ci = lambda project: (1, b"", b"")
        code, out, _ = cli()
        self.assertEqual(code, 2)
        self.assertIn("node_modules는 중간 상태일 수 있습니다", out)
        self.npm_ci = lambda project: (0, b"", b"")
        self.verdict([{"status": "flagged", "reason": None, "ml": "hit", "known": "not_hit"}], 1)
        code, out, _ = cli()
        self.assertEqual(code, 1)
        self.assertIn("설치하지 않음", out)
        self.assertNotIn("--confirm-warnings", out)
        (self.upd / ".npmrc").write_text("x=1\n", "utf-8")
        code, _, err = cli()
        self.assertEqual(code, 2)
        self.assertIn('"status": "error"', err)
