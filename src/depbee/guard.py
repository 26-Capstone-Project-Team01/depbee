"""Opt-in Claude Code PreToolUse hook: refuse npm installs that skip depbee's check.

Claude Code runs `<python> -I -m depbee.guard hook` (exec form, matcher Bash|PowerShell) before
each shell command it issues and passes the event as JSON on stdin (docs/claude-guard.md). The
hook never approves anything: it prints a deny decision (exit 0) or nothing (exit 0, the normal
permission flow goes on), and any input or internal error is exit 2, which Claude Code treats
as a block whatever onFailure says. It reads nothing but the event and, for a lockfile-only
command, whether the project has a .npmrc; it starts no process and uses no network.

What it judges is the command text of the npm forms Claude Code issues, not a shell: direct npm
and npx calls at the start of a command segment, with ;, &&, ||, |, &, newlines, (), {} and
<> between segments. npm commands that only read or run the project's own scripts pass, as
does a lockfile-only install, update, uninstall or audit fix (--package-lock-only and
--ignore-scripts, registry names only). The install itself goes through `depbee guard ci`
(service.install_checked), which checks the same bytes again right before npm ci. Anything
else that would install, and npm or npx inside a command it cannot read (another shell, eval,
a wrapper with options, a variable as the command, unbalanced quotes), is refused. A script,
an alias or a package.json script that runs npm itself is not seen.
"""

import contextlib
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from .config import REPLACE_TRIES
from .contracts import GuardError, parse_json
from .inputs.npm_cli import _FILE_SUFFIX, MAX_NAME_LENGTH, UPDATE_NAME, _registry_spec

# The handler Claude Code runs; -I: no PYTHONPATH, user site or current folder on the path.
HOOK_ARGS = ("-I", "-m", "depbee.guard", "hook")
MATCHER = "Bash|PowerShell"
HOOK_SECONDS = 30
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_SETTINGS_BYTES = 4 * 1024 * 1024
SHELL_TOOLS = ("Bash", "PowerShell")

# npm commands that pass: they read the registry or the project, or run the project's own
# scripts, and never install packages into node_modules. Exact words only; npm also accepts
# abbreviations and other aliases (lib/utils/cmd-list.js), which are refused here.
NPM_PASS = frozenset({
    "access", "adduser", "author", "bugs", "c", "cache", "completion", "config", "deprecate",
    "diff", "dist-tag", "docs", "doctor", "explain", "find", "find-dupes", "fund", "get", "help",
    "help-search", "home", "info", "issues", "la", "list", "ll", "login", "logout", "ls", "org",
    "outdated", "owner", "pack", "ping", "pkg", "prefix", "profile", "publish", "query", "repo",
    "restart", "root", "run", "run-script", "s", "sbom", "se", "search", "set", "show", "star",
    "stars", "start", "stop", "t", "team", "test", "token", "tst", "undeprecate", "unpublish",
    "unstar", "v", "version", "view", "whoami", "why",
})  # fmt: skip
# Commands that pass as a lockfile-only change (_prepare); audit only as audit fix.
NPM_PREPARE = {
    "install": "install", "i": "install", "add": "install",
    "update": "update", "up": "update", "upgrade": "update",
    "uninstall": "uninstall", "remove": "uninstall", "rm": "uninstall", "un": "uninstall",
    "audit": "audit",
}  # fmt: skip
# Only for the wording of a refusal; every word not passed above is refused anyway.
NPM_CI = frozenset({"ci", "clean-install", "ic", "install-clean", "it", "install-test", "cit",
                    "install-ci-test", "clean-install-test", "sit"})  # fmt: skip
NPM_EXEC = frozenset({"exec", "x"})
NPM_INIT = frozenset({"init", "create", "innit"})
# Options npm reads before the command: these take the next word as their value.
NPM_VALUE_OPTIONS = frozenset({"--prefix", "-C", "--workspace", "-w", "--loglevel"})
NPM_FLAGS = frozenset({"-s", "--silent", "-q", "--quiet", "--json", "--workspaces", "--ws",
                       "-v", "--version", "-h", "--help", "-y", "--yes"})  # fmt: skip
# Options of a lockfile-only change: boolean ones by name and short alias, and --prefix.
PREPARE_FLAGS = frozenset({
    "package-lock-only", "ignore-scripts", "save", "save-dev", "save-optional", "save-prod",
    "save-exact", "save-peer", "legacy-peer-deps", "strict-peer-deps", "audit", "fund",
})  # fmt: skip
PREPARE_SHORT = {"-S": "save", "-D": "save-dev", "-O": "save-optional", "-P": "save-prod",
                 "-E": "save-exact", "-C": "prefix"}  # fmt: skip
# Commands that run other commands: npm or npx in their arguments cannot be judged.
RUNNERS = frozenset({
    "bash", "busybox", "cmd", "dash", "deno", "eval", "fish", "icm", "iex", "invoke-command",
    "invoke-expression", "ksh", "node", "perl", "powershell", "pwsh", "py", "python",
    "python3", "ruby", "runas", "saps", "sh", "start", "start-process", "su", "wsl", "xargs",
    "zsh",
})  # fmt: skip
# Shells may also read the command from a pipe, so npm anywhere in the text counts for them.
SHELLS = frozenset({"bash", "busybox", "cmd", "dash", "fish", "ksh", "powershell", "pwsh",
                    "sh", "wsl", "zsh"})  # fmt: skip
# Words that run the command after them; their leading options are skipped (timeout: and its
# duration). Shell keywords that start a command are skipped the same way.
WRAPPERS = frozenset({"builtin", "command", "corepack", "doas", "do", "elif", "else", "env",
                      "exec", "if", "nice", "nohup", "stdbuf", "sudo", "then", "time",
                      "timeout", "until", "while", "!"})  # fmt: skip
CHANGE_FOLDER = frozenset({"cd", "chdir", "pushd", "push-location", "set-location", "sl"})
_SEPARATORS = ";&|(){}<>\n"
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_ASSIGN = frozenset({"=", "+=", "-=", "*=", "/=", "%=", "??="})  # PowerShell
_PYTHON = re.compile(r"pythonw?(?:\d+(?:\.\d+)?)?|pyw?")
# npm or npx as a word of the text (npm.cmd, npm-cli.js too), not pnpm, .npmrc or npm_config_.
_NPM_WORD = re.compile(r"(?<![A-Za-z0-9_.-])np[mx](?:-cli\.js|\.cmd|\.exe|\.ps1)?(?![A-Za-z0-9_-])",
                       re.IGNORECASE)  # fmt: skip
_CONFIRM = "--confirm-warnings"

HEADER = "depbee 설치 가드가 이 명령을 실행 전에 막았습니다"
CLOSING = (
    "위험(1)·보류(2)·오류이면 설치하지 말고 판정과 이유를 사용자에게 보여 준 뒤 결정을 기다리세요. "
    "다른 패키지 관리자, 스크립트, 간접 실행으로 우회하지 마세요."
)
STEPS = (
    "1. node_modules 없이 package.json·package-lock.json 변경안만 만듭니다: {prepare}\n"
    "2. (선택) depbee MCP scan_lockfile로 Git HEAD 대비 변경을 검사해 결과를 사용자에게 보여 줍니다.\n"
    "3. 설치는 depbee가 같은 파일을 Git HEAD 기준으로 다시 검사한 뒤 통과할 때만 npm ci --ignore-scripts로 "
    "실행합니다: {guard}\n"
    "Git HEAD에 기준 package-lock.json이 없는 새 프로젝트는 의존성을 넣기 전 상태를 사용자가 먼저 커밋해야 "
    "비교할 수 있습니다."
)
PREPARE_EXAMPLE = "npm install <이름>@<정확한 버전> --package-lock-only --ignore-scripts"


class _Unreadable(Exception):
    """A command whose npm use the guard cannot judge."""


def _quote(text: str, powershell: bool) -> str:
    """text as one literal word: PowerShell single quotes double each quote of their family
    (' and U+2018-U+201B), POSIX ones end and reopen around '."""
    if powershell:
        return "'" + re.sub("(['\u2018-\u201b])", r"\1\1", text) + "'"
    return shlex.quote(text)


def guard_command(project: str | None, powershell: bool) -> str:
    """The `depbee guard ci` command of this Python for the tool's shell."""
    words = [_quote(sys.executable, powershell), "-I", "-m", "depbee", "guard", "ci"]
    words.append(_quote(project, powershell) if project else "<프로젝트 폴더의 절대 경로>")
    return ("& " if powershell else "") + " ".join(words)


def _shown(word: str) -> str:
    """A word of the command as the refusal quotes it: printable and at most 80 characters."""
    text = re.sub(r"[\x00-\x1f\x7f]", "?", word)
    return text if len(text) <= 80 else text[:77] + "..."


def _program(word: str) -> str:
    """The program a command word names: its file name, lowercase, without .exe and the like."""
    name = re.split(r"[\\/]", word)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _segments(command: str, powershell: bool) -> list[tuple[str, list[str]]]:
    """(the separator before it, its words) of each command segment; ValueError for unbalanced
    quotes. A line continuation (backslash or, in PowerShell, backtick before a line break)
    joins its lines first, so every line break left separates commands."""
    escape = "`" if powershell else "\\"
    lexer = shlex.shlex(
        re.sub(re.escape(escape) + r"\r?\n", "", command),
        posix=True, punctuation_chars=_SEPARATORS,
    )  # fmt: skip
    lexer.whitespace_split = True
    lexer.whitespace = " \t\r"  # a newline separates commands
    lexer.commenters = ""  # "#" ends nothing: a missed comment only refuses more
    lexer.escape = escape
    segments, separator, current = [], "", []
    for token in lexer:
        if set(token) <= set(_SEPARATORS):
            if current:
                segments.append((separator, current))
            separator, current = token, []
        else:
            current.append(token)
    return segments + [(separator, current)] * bool(current)


def _unwrap(words: list[str]) -> tuple[list[str], bool, list[str]]:
    """(leading VAR=value words, whether a wrapper came first, the command and its words)."""
    assignments, wrapped, i = [], False, 0
    while i < len(words):
        program = _program(words[i])
        if _ASSIGNMENT.match(words[i]):
            assignments.append(words[i])
        elif program in WRAPPERS:
            wrapped = True
            while i + 1 < len(words) and words[i + 1].startswith("-"):
                i += 1
            if program == "timeout":
                i += 1  # its duration
        else:
            break
        i += 1
    return assignments, wrapped, words[i:]


def _kind(words: list[str]) -> tuple[str | None, list[str]]:
    """("npm", "npx" or "depbee", the arguments) of a command, else (None, words)."""
    program, args = _program(words[0]), words[1:]
    if program in ("npm", "npx", "depbee"):
        return program, args
    if program == "node":
        script = next((i for i, word in enumerate(args) if not word.startswith("-")), None)
        if script is not None and _program(args[script]) in ("npm-cli.js", "npx-cli.js"):
            return _program(args[script])[:3], args[script + 1 :]
    if _PYTHON.fullmatch(program):
        i = 0
        while i < len(args) and args[i].startswith("-") and not args[i].startswith("--"):
            flags = args[i][1:]
            if flags[:1] in ("X", "W"):
                i += 1 if len(flags) > 1 else 2  # -X utf8, -Xutf8
                continue
            if "c" in flags.partition("m")[0]:
                break  # -c: a program text, judged as a runner's arguments
            if "m" in flags:  # -m depbee, -mdepbee, -Im depbee
                inline = flags.partition("m")[2]
                module = inline or (args[i + 1] if i + 1 < len(args) else "")
                rest = args[i + 1 :] if inline else args[i + 2 :]
                return ("depbee", rest) if module == "depbee" else (None, words)
            i += 1
    return None, words


def _folder(current: str | None, target: str) -> str | None:
    """current/target as an absolute path, or None if it cannot be told from the text."""
    if current is None or not target or target == "-" or any(c in target for c in "$%`*?"):
        return None
    target = os.path.expanduser(target)
    msys = re.fullmatch(r"/([A-Za-z])(/.*)?", target) if os.name == "nt" else None
    if msys:  # Git Bash /c/Users/... is C:/Users/...
        target = f"{msys[1]}:{msys[2] or '/'}"
    return os.path.normpath(os.path.join(current, target))


def _option(token: str) -> tuple[str, object] | None:
    """(name, value) of an option of a lockfile-only change, None for any other option."""
    if token in PREPARE_SHORT:
        return PREPARE_SHORT[token], (None if token == "-C" else True)
    if not token.startswith("--"):
        return None
    name, equals, value = token[2:].partition("=")
    if name == "prefix":
        return name, value if equals else None  # None: the next word
    negated = name.startswith("no-") and name[3:] in PREPARE_FLAGS
    name = name[3:] if negated else name
    if name not in PREPARE_FLAGS:
        return None
    if equals:
        return (name, value == "true") if value in ("true", "false") and not negated else None
    return name, not negated


def _registry_package(word: str) -> bool:
    """A registry name with an optional registry version, range or tag (no Git, URL, file,
    alias or link spec)."""
    scope = "@" if word.startswith("@") else ""
    name, at, spec = word[len(scope) :].partition("@")
    name = scope + name
    return (
        len(name) <= MAX_NAME_LENGTH
        and UPDATE_NAME.fullmatch(name) is not None
        and not _FILE_SUFFIX.search(word)  # npm reads x.tgz as a file, with or without a spec
        and (not at or (bool(spec) and _registry_spec(spec)))
    )


class _Check:
    """One shell command of one tool call, judged segment by segment."""

    def __init__(self, command: str, powershell: bool, cwd: object):
        self.command, self.powershell = command, powershell
        self.project = os.path.normpath(cwd) if isinstance(cwd, str) and cwd else None
        self.mentions_npm = _NPM_WORD.search(command) is not None

    def reason(self) -> str | None:
        if not self.mentions_npm and "depbee" not in self.command.lower():
            return None  # the common case: nothing this guard judges
        try:
            if not self.powershell and "`" in self.command:
                raise _Unreadable("백틱 명령 치환")
            try:
                segments = _segments(self.command, self.powershell)
            except ValueError:
                raise _Unreadable("닫히지 않은 따옴표") from None
            for separator, words in segments:
                found = self._segment(separator, words)
                if found:
                    return found
        except _Unreadable as unreadable:
            return self._refuse(
                f"명령 안의 npm 실행을 판정할 수 없습니다({unreadable}). npm을 다른 명령으로 감싸지 말고 "
                "명령의 맨 앞에서 직접 실행하세요."
            )
        return None

    def _segment(self, separator: str, words: list[str]) -> str | None:
        if self.powershell and len(words) > 2 and words[0][:1] == "$" and words[1] in _ASSIGN:
            words = words[2:]  # $out = npm view x: the command after the assignment
        assignments, wrapped, words = _unwrap(words)
        if not words:
            return None
        kind, args = _kind(words)
        program = _program(words[0])
        # A variable as the command: in Bash any $word there; in PowerShell only after the call
        # operator &, since a bare $_.Name there is a value, not a call.
        called = separator.endswith("&") and not separator.endswith("&&")
        variable = words[0][:1] == "$" and (called or not self.powershell)
        if kind is None:
            if program in CHANGE_FOLDER:
                target = next((w for w in words[1:] if not w.startswith("-")), "~")
                self.project = _folder(self.project, target)
            elif self.mentions_npm and (
                program in SHELLS
                or variable
                or ((program in RUNNERS or wrapped) and _NPM_WORD.search(" ".join(words)))
            ):
                raise _Unreadable(f"{_program(words[0])}이(가) 실행하는 명령")
            return None
        if kind == "depbee":
            return self._depbee(args, assignments)
        if kind == "npx":
            return self._refuse(self._exec_text())
        return self._npm(args, bool(assignments) or wrapped)

    def _npm(self, args: list[str], prefixed: bool) -> str | None:
        i = 0
        while i < len(args) and args[i].startswith("-"):
            if args[i] in NPM_VALUE_OPTIONS:
                i += 2
            elif "=" in args[i] or args[i] in NPM_FLAGS or _option(args[i]):
                i += 1
            else:
                raise _Unreadable(f"npm 명령 앞의 옵션 {_shown(args[i])}")
        if i >= len(args):
            return None  # npm alone, npm -v, npm --help
        command, options = args[i], args[:i] + args[i + 1 :]
        if command in NPM_PASS or (command == "audit" and "fix" not in options):
            return None  # npm audit without fix only reports
        if command in NPM_INIT and not any(not word.startswith("-") for word in options):
            return None  # npm init -y writes package.json; an initializer is npm exec
        if command in NPM_PREPARE:
            problem, names = self._prepare(NPM_PREPARE[command], options, prefixed)
            if problem is None:
                return None
            if NPM_PREPARE[command] != "install":
                names = []
            return self._refuse(
                f"npm {_shown(command)}: {problem}. 설치·업데이트는 아래 순서로만 진행합니다.\n"
                + self._steps([name for name in names if _registry_package(name)])
            )
        if command in NPM_CI:
            return self._refuse(
                f"npm {command}은(는) 검사 결과와 묶이지 않은 설치입니다. 설치는 depbee가 같은 lockfile을 다시 "
                f"검사한 뒤 실행합니다: {guard_command(self.project, self.powershell)}\n"
                "변경을 먼저 만들어야 하면 다음 순서를 따릅니다.\n" + self._steps([])
            )
        if command in NPM_EXEC or command in NPM_INIT:
            return self._refuse(self._exec_text())
        return self._refuse(
            f"npm {_shown(command)}은(는) 이 가드가 통과시키는 npm 명령이 아닙니다(조회·스크립트 실행 명령과 "
            "lockfile만 바꾸는 install·update·uninstall·audit fix만 통과, 약어는 판정하지 않음). 설치가 필요하면 "
            "아래 순서를, 그 밖의 작업은 사용자에게 요청하세요.\n" + self._steps([])
        )

    def _prepare(
        self, command: str, options: list[str], prefixed: bool
    ) -> tuple[str | None, list[str]]:
        """(None if this is a lockfile-only change with registry names only, else why not; the
        words that are not options)."""
        values, words, i = {}, [], 0
        while i < len(options):
            token = options[i]
            if token == "--":
                words += options[i + 1 :]
                break
            if not token.startswith("-"):
                words.append(token)
            else:
                found = _option(token)
                if found is None:
                    return f"허용하지 않는 옵션 {_shown(token)}", words
                name, value = found
                if name == "prefix" and value is None:
                    i += 1
                    value = options[i] if i < len(options) else ""
                values[name] = value  # the last one counts, as for npm
            i += 1
        if command == "audit":
            if words != ["fix"]:
                return "audit은 fix 하나만 인자로 둡니다", []
            words = []
        if not (values.get("package-lock-only") is True and values.get("ignore-scripts") is True):
            return "--package-lock-only와 --ignore-scripts가 함께 있어야 합니다", words
        if prefixed:
            return "환경 변수나 다른 명령을 앞에 붙인 npm 실행은 통과시키지 않습니다", words
        valid = _registry_package if command == "install" else UPDATE_NAME.fullmatch
        bad = [word for word in words if not valid(word)]
        if bad:
            return f"registry 패키지 이름이 아닌 인자 {_shown(bad[0])}", words
        if command == "uninstall" and not words:
            return "제거할 패키지 이름이 없습니다", words
        project = self.project
        if "prefix" in values:
            project = _folder(project, values["prefix"])
        if project is None:
            return "명령으로 바꾼 프로젝트 폴더를 판정할 수 없습니다", words
        if os.path.lexists(os.path.join(project, ".npmrc")):
            return (
                "프로젝트에 .npmrc가 있어 에이전트의 npm 실행을 통과시키지 않습니다(설정이 npm 동작을 바꿀 수 "
                "있고 depbee도 이 프로젝트에는 설치하지 않습니다). 사용자가 .npmrc를 검토해야 합니다"
            ), words
        return None, words

    def _depbee(self, args: list[str], assignments: list[str]) -> str | None:
        """An agent's depbee call: no user confirmation flag, no changed depbee settings."""
        before = args[: args.index("--")] if "--" in args else args
        if args[:1] == ["update"] and any(
            len(name) >= 4 and _CONFIRM.startswith(name)
            for name in (word.partition("=")[0] for word in before)
        ):
            return self._refuse(
                f"{_CONFIRM}는 사용자가 경고를 직접 검토하고 확인할 때만 씁니다. 에이전트는 확인이 필요한 항목과 "
                "이유를 사용자에게 보여 주고 결정을 기다립니다."
            )
        if args[:2] in (["guard", "enable"], ["guard", "disable"]):
            return self._refuse(
                "설치 가드를 켜고 끄는 일은 사용자가 Claude Code 밖의 터미널에서 직접 합니다. 필요하면 사용자에게 "
                "요청하세요."
            )
        if args[:2] == ["guard", "ci"] and (assignments or "DEPBEE_" in self.command.upper()):
            return self._refuse(
                "depbee 환경 변수(모델·색인·설정·캐시 위치)를 바꾼 명령에서는 검사 후 설치를 실행하지 않습니다. "
                f"환경 변수 없이 실행하세요: {guard_command(self.project, self.powershell)}"
            )
        return None

    def _steps(self, names: list[str]) -> str:
        prepare = (
            f"npm install {' '.join(names)} --package-lock-only --ignore-scripts"
            if names
            else PREPARE_EXAMPLE
        )
        return STEPS.format(prepare=prepare, guard=guard_command(self.project, self.powershell))

    def _exec_text(self) -> str:
        return (
            "npx·npm exec·npm init <초기화 도구>는 검사하지 않은 패키지를 받아 바로 실행할 수 있습니다. 프로젝트에 이미 "
            "설치된 도구는 npm run <스크립트>나 node_modules/.bin의 실행 파일로 실행하고, 새 도구는 devDependency로 "
            "추가해 아래 순서로 검사·설치한 뒤 쓰세요. 초기화 도구(create-*)는 사용자에게 직접 실행을 요청하세요.\n"
            + self._steps([])
        )

    def _refuse(self, text: str) -> str:
        return f"{HEADER}. {text}\n{CLOSING}"


def decide(event: object) -> str | None:
    """The deny reason for this PreToolUse event, or None (no objection: the normal permission
    flow decides). GuardError for an event this hook cannot read."""
    if not isinstance(event, dict):
        raise GuardError("The hook input is not a JSON object")
    if event.get("hook_event_name") != "PreToolUse":
        return None
    tool_input = event.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        if event.get("tool_name") in SHELL_TOOLS:
            raise GuardError(f"{event['tool_name']} input has no command string")
        return None  # a tool without a shell command (a wider matcher than MATCHER)
    return _Check(command, event.get("tool_name") == "PowerShell", event.get("cwd")).reason()


def hook(stdin=None, stdout=None, stderr=None) -> int:
    """The hook process: the event on stdin, a deny decision or nothing on stdout, exit 0; exit
    2 with a reason on stderr (a block) for any failure, so an error never lets a call through."""
    stdin = stdin or sys.stdin.buffer
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    try:
        raw = stdin.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise GuardError(f"The hook input exceeds {MAX_INPUT_BYTES} bytes")
        reason = decide(json.loads(raw.decode("utf-8")))
        if reason is not None:
            decision = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
            stdout.write(json.dumps(decision, ensure_ascii=True) + "\n")
            stdout.flush()
        return 0
    except BaseException as exc:  # noqa: BLE001 - every failure must block, never allow
        detail = (str(exc) or type(exc).__name__).encode("ascii", "backslashreplace").decode()
        stderr.write(
            f"depbee guard could not judge this command, so it is blocked ({detail}). "
            "To turn the guard off, run `depbee guard disable <settings file>` in a terminal "
            "outside Claude Code (docs/claude-guard.md).\n"
        )
        stderr.flush()
        return 2


# Settings files (depbee guard enable, disable, status): only the file named, only our handler.


def handler(python: str) -> dict:
    """The command hook of this guard for a Python's absolute path (exec form: no shell)."""
    return {
        "type": "command", "command": python, "args": list(HOOK_ARGS),
        "timeout": HOOK_SECONDS, "onFailure": "block",
    }  # fmt: skip


def _ours(entry: object) -> bool:
    args = entry.get("args") if isinstance(entry, dict) else None
    return isinstance(args, list) and args[-3:] == list(HOOK_ARGS[-3:])


def read_settings(path: Path) -> tuple[dict, bytes | None]:
    """(settings, their bytes) of a Claude Code settings file; ({}, None) if it does not exist.
    GuardError for anything else that is not one strict JSON object with object hooks and a
    PreToolUse list: such a file is left as it is."""
    if not os.path.lexists(path):
        return {}, None
    if not path.is_file():
        raise GuardError(f"{path} is not a regular file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_SETTINGS_BYTES + 1)
    if len(raw) > MAX_SETTINGS_BYTES:
        raise GuardError(f"{path} exceeds {MAX_SETTINGS_BYTES} bytes")
    settings, _ = parse_json(raw, path)
    hooks = settings.get("hooks", {})
    if not isinstance(hooks, dict) or not isinstance(hooks.get("PreToolUse", []), list):
        raise GuardError(f"{path}: hooks must be an object and hooks.PreToolUse a list")
    return settings, raw


def installed_handlers(settings: dict) -> list[dict]:
    """This guard's handlers in the settings' PreToolUse groups, with their group's matcher."""
    found = []
    for group in settings.get("hooks", {}).get("PreToolUse", []):
        inner = group.get("hooks") if isinstance(group, dict) else None
        for entry in inner if isinstance(inner, list) else []:
            if _ours(entry):
                found.append({**entry, "matcher": group.get("matcher")})
    return found


def without_guard(settings: dict) -> tuple[dict, int]:
    """A copy of the settings without this guard's handlers, and how many were removed. A group
    left with no handler is dropped, then an empty PreToolUse and an empty hooks."""
    hooks = dict(settings.get("hooks", {}))
    groups, removed = [], 0
    for group in hooks.get("PreToolUse", []):
        inner = group.get("hooks") if isinstance(group, dict) else None
        if not isinstance(inner, list):
            groups.append(group)
            continue
        kept = [entry for entry in inner if not _ours(entry)]
        removed += len(inner) - len(kept)
        if kept or not inner:
            groups.append(group if len(kept) == len(inner) else {**group, "hooks": kept})
    result = dict(settings)
    if groups:
        hooks["PreToolUse"] = groups
    else:
        hooks.pop("PreToolUse", None)
    if hooks:
        result["hooks"] = hooks
    else:
        result.pop("hooks", None)
    return result, removed


def with_guard(settings: dict, python: str) -> dict:
    """The settings with exactly one handler of this guard, for python, in its own group."""
    result, _ = without_guard(settings)
    hooks = dict(result.get("hooks", {}))
    hooks["PreToolUse"] = [
        *hooks.get("PreToolUse", []),
        {"matcher": MATCHER, "hooks": [handler(python)]},
    ]
    return {**result, "hooks": hooks}


def write_settings(path: Path, settings: dict, original: bytes | None) -> Path | None:
    """Replace path with settings, as long as it still holds original (None: no file); return
    the backup of original next to it (None if there was no file).

    The new text goes to a temporary file in the same folder, which takes the old file's mode,
    and os.replace() swaps it in, so a reader sees the old file or the new one, never a part of
    one. Right before the swap the file is read again: if another program (Claude Code, Orca, an
    editor) wrote it meanwhile, nothing is replaced (GuardError) and its edit stays. Another
    write in the instant between that read and the swap is not seen."""
    text = json.dumps(settings, ensure_ascii=False, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".depbee")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        if original is not None:
            shutil.copymode(path, temporary)
        if read_settings(path)[1] != original:
            raise GuardError(
                f"{path} changed while depbee edited it; nothing was written. Run again"
            )
        backup = None
        if original is not None:
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            backup = path.with_name(f"{path.name}.depbee-backup-{stamp}-{secrets.token_hex(3)}")
            with backup.open("xb") as stream:
                stream.write(original)
        for attempt in range(REPLACE_TRIES):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:  # Windows: another process has the file open for an instant
                if attempt == REPLACE_TRIES - 1:
                    raise
                time.sleep(0.05)
        return backup
    finally:
        with contextlib.suppress(OSError):  # gone once replaced
            os.unlink(temporary)


SELF_TEST = (  # (tool, command, whether the hook must deny it)
    ("Bash", "npm install left-pad", True),
    ("PowerShell", "npm ci", True),
    ("Bash", "npm view left-pad version", False),
)


def self_test(entry: dict, cwd: Path) -> str | None:
    """Run the handler as Claude Code would (its command with its args, no shell, the event on
    stdin) on SELF_TEST; None if every answer is right, else what went wrong."""
    argv = [entry.get("command"), *(entry.get("args") or [])]
    timeout = entry.get("timeout", HOOK_SECONDS)
    if not all(isinstance(word, str) for word in argv) or not isinstance(timeout, int | float):
        return "command, args or timeout is not of the type Claude Code reads"
    for tool, command, denied in SELF_TEST:
        event = {"session_id": "depbee-self-test", "hook_event_name": "PreToolUse", "cwd": str(cwd),
                 "tool_name": tool, "tool_input": {"command": command}}  # fmt: skip
        try:
            done = subprocess.run(
                argv, input=json.dumps(event).encode(), capture_output=True, timeout=timeout,
                cwd=cwd,
            )  # fmt: skip
        except (OSError, subprocess.SubprocessError) as exc:
            return f"{argv[0]} could not be run ({type(exc).__name__})"
        try:
            output = json.loads(done.stdout) if done.stdout.strip() else None
            decision = output and output["hookSpecificOutput"]["permissionDecision"]
        except (ValueError, KeyError, TypeError):
            decision = "unreadable output"
        if done.returncode != 0 or decision != ("deny" if denied else None):
            stderr = done.stderr.decode("utf-8", "replace").strip()[:300]
            return f"{tool} {command!r}: exit {done.returncode}, decision {decision!r} {stderr}"
    return None


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments != ["hook"]:
        sys.stderr.write("usage: python -I -m depbee.guard hook (run by Claude Code)\n")
        return 2
    return hook()


if __name__ == "__main__":
    raise SystemExit(main())
