"""What a person at a terminal sees (depbee.terminal): the start screen, the bee mark, colors and
the next steps, and that a pipe, a file, JSON and Markdown get none of them.

Synthetic only: the reports of test_output_formats (fake detectors and predictor). A terminal is
a StringIO whose isatty() says yes; no console is opened here.
"""

import contextlib
import copy
import importlib.util
import io
import json
import os
import re
import unittest
from unittest import mock

from test_detectors import ADVISORY, KnownList
from test_output_formats import EXAMPLE_05_TEXT, EXAMPLES, FormatFixture, capture
from test_workflow import FakePredictor, package

from depbee import __version__, terminal
from depbee.cli import _print_markdown, _print_text, main
from depbee.pipeline import scan

WEB = all(importlib.util.find_spec(name) for name in ("starlette", "jinja2", "uvicorn"))
ANSI = re.compile(r"\x1b\[[0-9;]*m")
PREVIEW = {
    "targets": None, "npm_version": "11.6.1", "package_json_sha256": "0" * 64,
    "package_lock_sha256": "1" * 64, "new_package_lock_sha256": "2" * 64,
    "package_json_changed": False, "changed_count": 1, "project_npmrc_ignored": False,
    "notices": ["미리보기만 했고 프로젝트 파일은 아무것도 바꾸지 않았습니다."],
}  # fmt: skip


class Terminal(io.StringIO):
    def isatty(self):
        return True


def run(argv, stream, colors=True, columns=100):
    """main(argv) with stream as stdout: (exit code, stdout, stderr)."""
    err = io.StringIO()
    size = os.terminal_size((columns, 24))
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(err), \
            mock.patch.object(terminal, "_colors", return_value=colors), \
            mock.patch("shutil.get_terminal_size", return_value=size):  # fmt: skip
        try:
            code = main(argv)
        except SystemExit as stop:  # argparse: --help and usage errors
            code = stop.code
    return code, stream.getvalue(), err.getvalue()


class StartScreenTests(unittest.TestCase):
    def test_no_arguments_show_the_start_screen_and_still_exit_2(self):
        code, out, err = run([], io.StringIO())
        self.assertEqual((code, err), (2, ""))  # nothing was checked: never a pass
        lines = out.splitlines()
        self.assertEqual(lines[:3], [f"depbee {__version__}", *terminal.TAGLINE])
        for command, text in terminal.GUIDE:
            self.assertIn(f"{command}  ", out)
            self.assertIn(text, out)
        self.assertEqual(lines[-3:], list(terminal.GUIDE_END))
        for stamp in terminal.STAMP:  # a pipe or a file gets no bee and no color
            self.assertNotIn(stamp, out)
        self.assertNotIn("\x1b", out)

    def test_an_interactive_terminal_gets_the_stamp_and_colors_only_if_it_takes_them(self):
        code, out, _ = run([], Terminal())
        top, middle, bottom = out.splitlines()[:3]
        self.assertEqual(code, 2)
        self.assertEqual([ANSI.sub("", line) for line in (top, middle, bottom)], [
            terminal.STAMP[0], f"{terminal.STAMP[1]}  depbee {__version__}", terminal.STAMP[2]])  # fmt: skip
        self.assertTrue(top.startswith("\x1b[33m") and top.endswith("\x1b[0m"))
        _, plain, _ = run([], Terminal(), colors=False)
        self.assertEqual(plain, ANSI.sub("", out))  # the same screen without the colors
        self.assertTrue(all(ord(c) < 128 for line in terminal.STAMP for c in line))

    def test_colors_follow_no_color_and_dumb_terminals(self):
        stream = Terminal()
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertIs(terminal.painter(stream), terminal.plain)
        with mock.patch.dict(os.environ, {"TERM": "dumb"}):
            os.environ.pop("NO_COLOR", None)
            self.assertIs(terminal.painter(stream), terminal.plain)
        self.assertIs(terminal.painter(io.StringIO()), terminal.plain)  # not a terminal
        closed = io.StringIO()
        closed.close()  # its isatty() raises
        self.assertFalse(terminal.interactive(closed))
        self.assertFalse(terminal.interactive(object()))

    def test_the_guide_fits_the_width_or_puts_descriptions_under_commands(self):
        for columns, beside in ((80, True), (120, True), (60, False), (30, False)):
            with self.subTest(columns=columns):
                size = os.terminal_size((columns, 24))
                with mock.patch("shutil.get_terminal_size", return_value=size):
                    rows = terminal.guide()[1 : -len(terminal.GUIDE_END) - 1]
                self.assertEqual(len(rows), len(terminal.GUIDE) * (1 if beside else 2))
                if beside or columns >= 60:
                    self.assertLess(max(map(terminal._width, rows)), columns)
        self.assertEqual(terminal._width("가나 ab"), 7)  # a Korean character takes two columns

    def test_help_starts_like_the_start_screen_and_lists_every_command(self):
        code, out, _ = run(["--help"], io.StringIO())
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("usage: depbee "))
        self.assertIn("\n".join([f"depbee {__version__}", *terminal.TAGLINE]), out)
        self.assertIn("{plan,scan,check,update,setup,guard,mcp,dashboard}", out)
        self.assertTrue(out.rstrip("\n").endswith("\n".join(terminal.GUIDE_END)))
        _, stamped, _ = run(["--help"], Terminal(), colors=False)
        self.assertIn("\n".join(terminal.STAMP[:1]), stamped)
        _, dashboard, _ = run(["dashboard", "--help"], io.StringIO())
        for option in ("--background", "--status", "--stop", "--port"):
            self.assertIn(option, dashboard)


class ReportScreenTests(FormatFixture):
    def scan_cli(self, report, stream, *extra, **options):
        with mock.patch("depbee.cli.scan_project", return_value=copy.deepcopy(report)):
            return run(["scan", str(self.project), *extra], stream, **options)

    def test_a_pipe_or_file_gets_the_text_as_it_always_was(self):
        for label, report in self.cases().items():
            with self.subTest(label):
                code, out, err = self.scan_cli(report, io.StringIO())
                self.assertEqual((code, err), (report["exit_code"], ""))
                self.assertEqual(out, capture(_print_text, report))
        example = json.loads((EXAMPLES / "05-detectors-not-configured.json").read_text("utf-8"))
        self.assertEqual(self.scan_cli(example, io.StringIO())[1], EXAMPLE_05_TEXT)

    def test_a_terminal_gets_the_mark_colors_and_next_steps_around_the_same_text(self):
        report = self.cases()["mixed"]
        code, out, _ = self.scan_cli(report, Terminal())
        self.assertEqual(code, report["exit_code"])
        self.assertTrue(out.startswith(f"\x1b[33m{terminal.MARK}\x1b[0m depbee 검사 결과: "))
        self.assertIn("\x1b[1;33m보류(완료하지 못한 항목 있음)\x1b[0m (종료 코드 2)", out)
        self.assertIn("\x1b[1;31m경고: 기지 악성 기록 일치 2개.\x1b[0m 낮은 ML", out)
        self.assertIn("\x1b[1;33m보류 2개.\x1b[0m 검사를 끝내지 못한", out)
        for status, color in (("위험", "1;31"), ("보류", "1;33"), ("통과", "32"), ("삭제", "2")):
            self.assertIn(f"[\x1b[{color}m{status}\x1b[0m] ", out)
        report_text, _, steps = ANSI.sub("", out).partition(f"\n{terminal.NEXT_TITLE}\n")
        # Without the colors, the mark and the last block it is the plain text, to the byte.
        self.assertEqual(report_text.removeprefix(f"{terminal.MARK} "),
                         capture(_print_text, report))  # fmt: skip
        self.assertIn(f"\x1b[1m{terminal.NEXT_TITLE}\x1b[0m\n", out)
        self.assertTrue(steps.startswith("  - 기지 악성 기록과 일치한 2개 항목은 설치하거나"))
        _, plain, _ = self.scan_cli(report, Terminal(), colors=False)
        self.assertEqual(plain, ANSI.sub("", out))  # no color support: the words alone

    def test_json_and_markdown_are_the_same_on_a_terminal(self):
        report = self.cases()["mixed"]
        _, out, _ = self.scan_cli(report, Terminal(), "--format", "json")
        self.assertEqual(json.loads(out), report)
        _, out, _ = self.scan_cli(report, Terminal(), "--format", "markdown")
        self.assertEqual(out, capture(_print_markdown, report))

    def test_plan_keeps_stdout_for_the_json_and_hints_on_stderr_of_a_terminal(self):
        argv = ["plan", str(self.project), "--base-lock", str(self.base)]
        code, piped, err = run(argv, io.StringIO())
        self.assertEqual((code, err), (0, ""))
        code, out, err = run(argv, Terminal())
        self.assertEqual((code, out), (0, piped))
        self.assertEqual(len(json.loads(out)["changes"]), 1)
        self.assertEqual(err, terminal.PLAN_STEP.format(count=1, analyzable=1) + "\n")

    def test_an_update_preview_and_apply_on_a_terminal(self):
        report = self.scan_with(0.1)  # passes; the known malicious list is not connected
        result = {"preview": dict(PREVIEW), "report": report}
        with mock.patch("depbee.cli.preview_update", return_value=copy.deepcopy(result)), \
                mock.patch("depbee.cli._record"):  # fmt: skip
            code, out, _ = run(["update", "--project", str(self.project)], Terminal())
        self.assertEqual(code, 0)
        self.assertTrue(
            out.startswith(f"\x1b[33m{terminal.MARK}\x1b[0m depbee 업데이트 미리보기\n")
        )
        self.assertIn(
            "\ndepbee 검사 결과: \x1b[32m통과\x1b[0m (종료 코드 0)\n", out
        )  # one mark only
        steps = " ".join(ANSI.sub("", out).partition(f"\n{terminal.NEXT_TITLE}\n")[2].split())
        self.assertIn("--apply lockfile", steps)
        self.assertIn("확인이 필요한 항목이 1개 있어", steps)
        self.assertIn("--confirm-warnings", steps)
        applied = {
            "mode": "lockfile", "outcome": "refused", "reason": "confirmation_required",
            "error": None, "blocked": [], "confirmation_required": [], "confirmed": False,
            "files": [], "backup": None, "npm_version": None, "npm_ci_exit_code": None,
            "notices": [],
        }  # fmt: skip
        with mock.patch("depbee.cli.apply_update", return_value={**result, "apply": applied}), \
                mock.patch("depbee.cli._record"):  # fmt: skip
            code, out, _ = run(["update", "--project", str(self.project), "--apply", "lockfile"],
                               Terminal())  # fmt: skip
        self.assertEqual(code, 2)  # refused with a passing report: the apply did not happen
        self.assertIn("depbee 업데이트 반영: \x1b[1;33m반영하지 않음\x1b[0m\n", out)
        self.assertNotIn("--apply lockfile을", ANSI.sub("", out))  # an apply was already asked


class NextStepTests(FormatFixture):
    def steps(self, report, command="scan", apply=None):
        kept = copy.deepcopy(report)
        steps = terminal.next_steps(command, report, apply)
        self.assertEqual(report, kept)  # reads only
        return steps

    def test_steps_follow_the_verdicts_most_urgent_first(self):
        known = self.scan_with(0.1, known_malicious=KnownList((ADVISORY,)))
        self.assertEqual(self.steps(known), [terminal.KNOWN_STEP.format(count=1)])
        self.assertEqual(self.steps(self.scan_with(0.9)),
                         [terminal.ML_STEP.format(count=1), terminal.INDEX_STEP])  # fmt: skip
        passed = self.scan_with(0.1, known_malicious=KnownList())
        self.assertEqual(self.steps(passed), [terminal.PASS_STEP])
        self.assertEqual(self.steps(self.scan_with(0.1)), [terminal.PASS_STEP, terminal.INDEX_STEP])
        empty = {**passed, "results": []}
        self.assertEqual(self.steps(empty), [terminal.NOTHING_CHANGED])
        # Last: mixed() rewrites the fixture's lockfiles.
        self.assertEqual(self.steps(self.mixed()), [terminal.KNOWN_STEP.format(count=2),
                                                    terminal.ML_STEP.format(count=1),
                                                    terminal.PENDING_STEP.format(count=2)])  # fmt: skip

    def test_a_report_that_only_removes_is_not_told_to_install(self):
        """It passes (exit code 0), but there is no version in it to install."""
        self.old["packages"]["node_modules/gone"] = package()
        self.save_locks()
        mixed = self.scan_with(0.1, known_malicious=KnownList())
        self.assertEqual(sorted(row["status"] for row in mixed["results"]),
                         ["not_flagged", "removed"])  # fmt: skip
        self.assertEqual(self.steps(mixed), [terminal.PASS_STEP])  # for the version that stays
        self.new["packages"] = {}
        self.save_locks()
        removed = scan(self.request(), None, FakePredictor(), known_malicious=KnownList())
        self.assertEqual((removed["exit_code"], [row["status"] for row in removed["results"]]),
                         (0, ["removed", "removed"]))  # fmt: skip
        self.assertEqual(self.steps(removed), [])
        self.assertEqual(self.steps(removed, "update"), [terminal.APPLY_STEP])
        # As typed in a terminal: the report, and no step that speaks of installing.
        code, out, err = run(["scan", str(self.project), "--base-lock", str(self.base)],
                             Terminal(), colors=False)  # fmt: skip
        self.assertEqual((code, err), (0, ""))
        self.assertIn("[삭제] example@1.0.0", out)
        self.assertNotIn("설치는 검사한 버전 그대로", " ".join(out.split()))

    def test_unfinished_items_with_a_remedy_name_it(self):
        no_model = scan(self.request(), self.adapter(), None, known_malicious=KnownList())
        self.assertEqual(no_model["results"][0]["reason"], "model_missing")
        self.assertEqual(
            self.steps(no_model), [terminal.REASON_STEPS["model_missing"].format(count=1)]
        )
        self.assertIn("depbee setup DIR", self.steps(no_model)[0])
        not_analyzed = scan(self.request(), None, FakePredictor(), known_malicious=KnownList())
        self.assertEqual(not_analyzed["results"][0]["reason"], "analysis_missing")
        self.assertEqual(self.steps(not_analyzed),
                         [terminal.REASON_STEPS["analysis_missing"].format(count=1)])  # fmt: skip
        # check and update always extract: --extract would be no remedy there.
        self.assertEqual(self.steps(not_analyzed, "check"), [terminal.PENDING_STEP.format(count=1)])

    def test_an_update_preview_says_how_to_apply_and_what_the_gate_will_ask(self):
        listed = KnownList()
        passed = self.scan_with(0.1, known_malicious=listed)
        self.assertEqual(self.steps(passed, "update"), [terminal.APPLY_STEP])
        unchecked = self.scan_with(0.1)  # no list: every new version needs the confirmation
        self.assertEqual(self.steps(unchecked, "update"), [
            terminal.INDEX_STEP, terminal.APPLY_STEP + terminal.CONFIRM_STEP.format(count=1)])  # fmt: skip
        risky = self.scan_with(0.9, known_malicious=listed)
        self.assertEqual(self.steps(risky, "update"), [
            terminal.ML_STEP.format(count=1),
            terminal.APPLY_STEP + terminal.CONFIRM_STEP.format(count=1)])  # fmt: skip
        blocked = self.scan_with(0.1, known_malicious=KnownList((ADVISORY,)))
        self.assertEqual(self.steps(blocked, "update"),
                         [terminal.KNOWN_STEP.format(count=1), terminal.BLOCKED_STEP])  # fmt: skip
        self.assertEqual(self.steps(passed, "update", apply={"outcome": "applied"}), [])

    def test_bullets_break_at_spaces_within_the_terminal_width(self):
        steps = [terminal.INDEX_STEP, terminal.APPLY_STEP + terminal.CONFIRM_STEP.format(count=3),
                 "short"]  # fmt: skip
        for columns in (40, 80, 200):
            with self.subTest(columns=columns):
                size = os.terminal_size((columns, 24))
                with mock.patch("shutil.get_terminal_size", return_value=size):
                    lines = terminal.bullets(steps)
                self.assertLess(max(map(terminal._width, lines)), columns)
                starts = [line for line in lines if line.startswith("  - ")]
                self.assertEqual(len(starts), len(steps))
                self.assertTrue(all(line.startswith(("  - ", "    ")) for line in lines))
                joined = " ".join(line[4:] for line in lines)
                self.assertEqual(joined, " ".join(steps))
        with mock.patch("shutil.get_terminal_size", return_value=os.terminal_size((10, 24))):
            self.assertEqual(terminal.bullets(["x" * 30]), ["  - " + "x" * 30])  # left whole


URL = "http://127.0.0.1:18765/"


def launched(kind, columns=100, colors=True, url=URL, rows=24):
    """terminal.launch() on a terminal of that width: (what it wrote, the waits it made)."""
    stream, waits = Terminal(), []
    size = os.terminal_size((columns, rows))
    with mock.patch.object(terminal, "_colors", return_value=colors), \
            mock.patch("shutil.get_terminal_size", return_value=size):  # fmt: skip
        terminal.launch(stream, kind, url, pause=waits.append)
    return stream.getvalue(), waits


class LaunchTests(unittest.TestCase):
    """The dashboard's start on an interactive terminal (terminal.launch) and who calls it."""

    def test_the_whole_bee_flies_to_the_fixed_address_and_lands_above_the_steps(self):
        moving, waits = launched("foreground")
        still, none = launched("foreground", colors=False)
        self.assertEqual((waits, none), ([terminal.FLIGHT_SECONDS] * 7, []))
        self.assertNotIn("\r", still)
        self.assertNotIn("\x1b", still)
        wings, bee, legs = terminal.STAMP
        self.assertEqual(still.count(URL), 1)  # whole and once
        frames = moving.removeprefix("\n").split("\r\x1b[2A")
        last, after = frames[-1].split("\n\n", 1)
        frames[-1] = last
        distances = (0, 2, 4, 6, 8, 10, 12, len(terminal.TRAIL))
        url_column = still.splitlines()[2].index(URL)
        for offset, frame in zip(distances, frames, strict=True):
            top, middle, bottom = ANSI.sub("", frame).splitlines()
            self.assertEqual(top, " " * (1 + offset) + wings)
            self.assertTrue(middle.startswith(terminal.TRAIL[:offset] + " " + bee))
            self.assertEqual(bottom, " " * (1 + offset) + legs)
            self.assertEqual(middle.index(URL), url_column)
            self.assertIn(f"\x1b[30;43m {URL} \x1b[0m", frame)
        self.assertEqual(ANSI.sub("", f"\n{last}\n\n{after}").replace(f"{URL} ", URL), still)
        self.assertEqual(launched("foreground", rows=2)[1], [])
        # The user's own switches, with nothing patched: the still screen at once.
        for environ in ({"NO_COLOR": "1", "TERM": "xterm"}, {"NO_COLOR": "", "TERM": "dumb"}):
            stream = Terminal()
            with self.subTest(environ=environ), mock.patch.dict(os.environ, environ), \
                    mock.patch("shutil.get_terminal_size",
                               return_value=os.terminal_size((100, 24))):  # fmt: skip
                terminal.launch(stream, "foreground", URL, pause=waits.append)
            self.assertEqual((stream.getvalue(), len(waits)), (still, 7))

    def test_each_start_lists_its_own_steps_in_order_under_the_address_then_what_to_do(self):
        for kind, has, lacks in (
            ("foreground", ("1. 포트 열기  127.0.0.1:18765", "Ctrl+C"), ("--stop", "--status")),
            ("started", ("터미널을 닫아도 계속 실행", "--status", "--stop"), ("Ctrl+C",)),
            ("running", ("이미 백그라운드에서 실행 중", "--stop"), ("Ctrl+C", "--status")),
        ):
            for columns in (100, 52, 40):  # with the trail, without it, steps under their names
                with self.subTest(kind=kind, columns=columns):
                    out, _ = launched(kind, columns=columns, colors=False)
                    steps, notes = terminal.LAUNCH[kind]
                    lines = out.splitlines()
                    self.assertLess(max(map(terminal._width, lines)), columns)
                    # In reading order: the bee, the address, each step as it was done with
                    # what is known of it, then what to do next.
                    host = URL.removeprefix("http://").rstrip("/")
                    parts = [terminal.MARK, URL]
                    for number, (label, detail) in enumerate(steps, 1):
                        parts += [f"\n  {number}. {label}", detail.format(address=host)]
                    rest = out
                    for part in [*parts, "\n\n  - "]:
                        self.assertIn(part, rest)
                        rest = rest.partition(part)[2]
                    told = out.rpartition("\n\n")[2].splitlines()
                    self.assertEqual(" ".join(line[4:] for line in told), " ".join(notes))
                    self.assertEqual(sum(line.startswith("  - ") for line in told), len(notes))
                    if columns == 100:
                        for word in has:
                            self.assertIn(word, out)
                    for word in (*lacks, "PID", chr(0x2014)):  # no process ID, no em dash
                        self.assertNotIn(word, out)
                    # The only numbers are the address and the steps' own: no version, no PID.
                    self.assertEqual(re.findall(r"\d+", out.replace(host, "")),
                                     [str(number + 1) for number in range(len(steps))])  # fmt: skip
                    # ASCII and Korean only: a Korean Windows console's code page takes it all.
                    self.assertTrue(all(ord(c) < 128 or "가" <= c <= "힣" for c in out))
                    out.encode("cp949")
        # The address as it is, whatever the port (--port): shorter here, so the trail still fits.
        out, _ = launched("foreground", columns=51, colors=False, url="http://127.0.0.1:80/")
        self.assertIn(f"{terminal.TRAIL}  {terminal.MARK}     http://127.0.0.1:80/\n", out)
        self.assertIn("  1. 포트 열기  127.0.0.1:80\n", out)

    def test_a_narrow_terminal_gets_the_title_beside_the_bee_and_the_address_under_it(self):
        wings, bee, legs = terminal.STAMP
        wide = len(f" {bee}  {terminal.TRAIL}   {URL} ")
        for columns, trail in ((wide + 1, True), (wide, False), (40, False), (31, False)):
            with self.subTest(columns=columns):
                out, waits = launched("started", columns=columns)
                text = ANSI.sub("", out)
                self.assertEqual((bool(waits), "\r" in out, terminal.TRAIL in text),
                                 (trail, trail, trail))  # fmt: skip
                self.assertEqual(text.count(URL), 8 if trail else 1)
                self.assertIn(f"\x1b[30;43m {URL} \x1b[0m", out)
                for line in text.split("\r\x1b[2A")[-1].splitlines():
                    self.assertLess(terminal._width(line), columns, line)
        stacked = ANSI.sub("", launched("started", columns=40)[0]).splitlines()
        self.assertEqual(stacked[:12], [
            "", f" {wings}", f" {bee}  {terminal.LAUNCH_TITLE}", f" {legs}", f"   {URL} ", "",
            "  1. 실행 여부 확인", "     실행 중인 대시보드 없음",
            "  2. 백그라운드 시작", "     터미널을 닫아도 계속 실행",
            "  3. 응답 확인", "     준비 완료",
        ])  # fmt: skip

    def test_a_background_start_is_drawn_on_a_terminal_and_plain_in_a_pipe(self):
        from depbee import cli
        from depbee.dashboard import lifecycle

        for started, kind, plain in ((True, "started", cli.BACKGROUND_STARTED),
                                     (False, "running", cli.BACKGROUND_RUNNING)):  # fmt: skip
            with self.subTest(started=started), \
                    mock.patch.object(lifecycle, "start", return_value=({"url": URL}, started)), \
                    mock.patch.object(cli, "_warn_shared"), \
                    mock.patch.object(terminal.time, "sleep"):  # fmt: skip
                code, out, err = run(["dashboard", "--background"], Terminal(), colors=False)
                self.assertEqual((code, err, out), (0, "", launched(kind, colors=False)[0]))
                code, out, err = run(["dashboard", "--background"], io.StringIO())
                self.assertEqual((code, out, err), (0, f"{URL}\n{plain}\n", ""))

    @unittest.skipUnless(WEB, "web extra ([web]) not installed; serve() is not tested here")
    def test_a_foreground_start_is_drawn_on_a_terminal_and_ctrl_c_ends_it_in_one_line(self):
        from depbee.dashboard import app

        class Server:
            def __init__(self, config):
                self.port = config.port

            def run(self, sockets):
                raise KeyboardInterrupt

        for stream in (Terminal(), io.StringIO()):
            with self.subTest(stream=type(stream).__name__), \
                    mock.patch.object(app.uvicorn, "Server", Server), \
                    mock.patch.object(app, "build_app"), \
                    mock.patch.object(terminal, "_colors", return_value=False), \
                    mock.patch("shutil.get_terminal_size", return_value=os.terminal_size((100, 24))), \
                    contextlib.redirect_stdout(stream):  # fmt: skip
                app.serve(0)
            out = stream.getvalue()
            url = re.search(r"http://127\.0\.0\.1:\d+/", out)[0]
            if stream.isatty():
                self.assertEqual(
                    out, launched("foreground", colors=False, url=url)[0] + app.STOPPED + "\n"
                )
            else:
                self.assertEqual(out, f"{url}\n{app.STARTED}\n{app.STOPPED}\n")
        # Ctrl+C while the start is being drawn ends the same way.
        with mock.patch.object(app.uvicorn, "Server", Server), mock.patch.object(app, "build_app"), \
                mock.patch.object(terminal, "launch", side_effect=KeyboardInterrupt), \
                contextlib.redirect_stdout(Terminal()) as out:  # fmt: skip
            app.serve(0)
        self.assertEqual(out.getvalue(), app.STOPPED + "\n")


if __name__ == "__main__":
    unittest.main()
