"""GitHub Actions gate for action.yml: decides success or failure from a depbee report.

It only reads what `depbee scan` wrote. Detection and the per-result fields stay in pipeline.scan();
this module never recomputes them. Standard library only: action.yml runs this file directly with
`python -I`, so nothing in the checked-out pull request can shadow its imports.

Exit status 0 means the job step passes (possibly with warnings); 1 means it fails.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath

# Known malicious matches always fail; these can be added with the fail-on input.
FAIL_ON = ("ml-hit", "incomplete")
ROW_STATUSES = {"flagged", "not_flagged", "incomplete", "removed"}
SLOT_STATUSES = {"hit", "not_hit", "not_run", "failed"}
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# Goes into the Release download URL.
MODEL_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
LOCKFILE_NAME = "package-lock.json"
SAFETY_NOTE = "'통과'는 모델의 판정일 뿐 패키지가 안전하다는 보증이 아닙니다."


class ActionError(Exception):
    """A configuration, integrity or report problem: nothing was checked, so the step fails."""


def _clean(value: object) -> str:
    """Escape characters that a package could use to control the log (same rule as the CLI)."""
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in str(value))


def _data(text: str) -> str:
    """Workflow command message escaping (actions/toolkit command.ts escapeData)."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _property(text: str) -> str:
    """Workflow command property escaping (actions/toolkit command.ts escapeProperty)."""
    return _data(text).replace(":", "%3A").replace(",", "%2C")


def command(level: str, message: str, file: str | None = None, line: int | None = None) -> str:
    """An ::error or ::warning workflow command; message is cleaned and escaped here."""
    props = []
    if file is not None:
        props.append(f"file={_property(file)}")
        if line is not None:
            props.append(f"line={line}")
    head = f"::{level} {','.join(props)}" if props else f"::{level}"
    return f"{head}::{_data(_clean(message))}"


def parse_fail_on(text: str) -> set[str]:
    values = {value for value in re.split(r"[\s,]+", text.strip()) if value}
    unknown = sorted(values - set(FAIL_ON))
    if unknown:
        raise ActionError(
            f"fail-on accepts {', '.join(FAIL_ON)} (comma or space separated), "
            f"got: {', '.join(unknown)}"
        )
    return values


def _relative_file(value: str, what: str, workspace: Path) -> Path:
    # The shell steps pass this value unchanged to dirname, which on Linux keeps "\" in a name
    # and reads a leading "-" as an option: check exactly the path the shell will see.
    # $(dirname ...) also drops trailing newlines, turning "app<LF>/..." into "app".
    if any(char < " " or char == "\x7f" for char in value):
        raise ActionError(f"{what} must not contain control characters: {value!r}")
    if "\\" in value:
        raise ActionError(f"{what} must use / as the path separator: {value!r}")
    path = PurePosixPath(value)
    if any(part.startswith("-") for part in path.parts):
        raise ActionError(f"{what} path components must not start with -: {value!r}")
    if not value or path.is_absolute() or ".." in path.parts or re.match(r"[A-Za-z]:", value):
        raise ActionError(f"{what} must be a path inside the workspace: {value!r}")
    full = workspace / path
    if not full.is_file():
        raise ActionError(f"{what} not found in the workspace: {value!r}")
    return full


def check_inputs(env: dict, workspace: Path) -> None:
    """Validate the action inputs before anything is installed or downloaded."""
    lockfile = env.get("LOCKFILE", "")
    _relative_file(lockfile, "lockfile", workspace)
    if PurePosixPath(lockfile).name != LOCKFILE_NAME:
        raise ActionError(f"lockfile must name a {LOCKFILE_NAME} file: {lockfile!r}")
    parse_fail_on(env.get("FAIL_ON", ""))
    if env.get("REPORT"):
        # Self-test mode: no scan, so the model, base commit and change limit are unused.
        _relative_file(env["REPORT"], "report", workspace)
        return
    limit = env.get("MAX_CHANGES", "")
    if not (limit.isascii() and limit.isdigit() and int(limit) > 0):
        raise ActionError(f"max-changes must be a positive integer: {limit!r}")
    if not MODEL_VERSION.fullmatch(env.get("MODEL_VERSION", "")):
        raise ActionError(f"model-version must be a Release tag name: {env.get('MODEL_VERSION')!r}")
    for name in ("MODEL_SHA256", "MANIFEST_SHA256"):
        if not SHA256.fullmatch(env.get(name, "")):
            raise ActionError(f"{name.lower().replace('_', '-')} must be 64 lowercase hex digits")
    if not COMMIT.fullmatch(env.get("BASE_SHA", "")):
        raise ActionError(
            "No pull request base commit: run this action on pull_request events "
            "(github.event.pull_request.base.sha)"
        )


def verify(pairs: list[tuple[Path, str]]) -> None:
    """Each downloaded file must have the expected SHA-256 from the workflow inputs."""
    for path, expected in pairs:
        if not SHA256.fullmatch(expected):
            raise ActionError(f"Expected SHA-256 for {path.name} must be 64 lowercase hex digits")
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected:
            raise ActionError(
                f"SHA-256 mismatch for {path.name}: expected {expected}, got {actual}"
            )


def count_changes(plan: Path, limit: int) -> int:
    """Number of changes in a `depbee plan` request; more than limit is an error."""
    request = json.loads(plan.read_text(encoding="utf-8"))
    changes = request.get("changes") if isinstance(request, dict) else None
    if not isinstance(changes, list):
        raise ActionError("The depbee plan output has no changes list")
    if len(changes) > limit:
        raise ActionError(
            f"{len(changes)} changed lockfile entries exceed max-changes {limit}; "
            "split the update or raise max-changes"
        )
    return len(changes)


def load_report(path: Path) -> list[dict]:
    """The results of a depbee report, checked for the fields this gate reads."""
    report = json.loads(path.read_text(encoding="utf-8"))
    rows = report.get("results") if isinstance(report, dict) else None
    if not isinstance(rows, list):
        raise ActionError("The report has no results list")
    for index, row in enumerate(rows):
        ok = (
            isinstance(row, dict)
            and row.get("status") in ROW_STATUSES
            and isinstance(row.get("package"), str)
            and isinstance(row.get("location"), str)
            and all(
                isinstance(row.get(slot), dict) and row[slot].get("status") in SLOT_STATUSES
                for slot in ("known_malicious", "ml")
            )
        )
        if not ok:
            raise ActionError(
                f"Report result {index} lacks status, package, location, "
                "known_malicious.status or ml.status with a known value"
            )
    return rows


def find_line(lines: list[str], location: str) -> int | None:
    """1-based line of the lockfile `packages` key for location, as npm writes one key a line."""
    key = json.dumps(location, ensure_ascii=False) + ":"
    for number, line in enumerate(lines, 1):
        if line.lstrip().startswith(key):
            return number
    return None


def decide(rows: list[dict], fail_on: set[str], lockfile: str, lines: list[str]):
    """Return (failed, annotations, summary lines) from the per-result fields only.

    The top-level exit_code is not used: 2 (unfinished) would hide 1 (risk).
    """
    annotations, counts = [], {"known": 0, "ml": 0, "pending": 0}
    failed = False
    for row in rows:
        known = row["known_malicious"]["status"] == "hit"
        ml = row["ml"]["status"] == "hit"
        pending = row["status"] == "incomplete"
        if not (known or ml or pending):
            continue
        counts["known"] += known
        counts["ml"] += ml
        counts["pending"] += pending
        reasons = []
        if known:
            matches = row["known_malicious"].get("matches") or []
            ids = ", ".join(str(m.get("advisory_id")) for m in matches if isinstance(m, dict))
            reasons.append("기지 악성 기록 일치" + (f"({ids})" if ids else ""))
        if ml:
            score = row.get("score")
            number = isinstance(score, int | float) and not isinstance(score, bool)
            reasons.append("ML 위험 점수 기준 이상" + (f"({score:.3f})" if number else ""))
        if pending:
            reasons.append(f"보류({row.get('reason') or '이유 없음'}), 통과가 아님")
        fails = known or (ml and "ml-hit" in fail_on) or (pending and "incomplete" in fail_on)
        failed |= fails
        version = row.get("after_version") or row.get("before_version")
        message = f"depbee: {row['package']}@{version} ({row['location']}): " + "; ".join(reasons)
        line = find_line(lines, row["location"])
        annotations.append(command("error" if fails else "warning", message, lockfile, line))
    verdict = "실패" if failed else ("경고" if any(counts.values()) else "통과")
    summary = [
        f"### depbee Actions 판정: {verdict}",
        "",
        f"- 기지 악성 기록 일치 {counts['known']}개: 항상 실패",
        f"- ML 위험 점수 기준 이상 {counts['ml']}개: "
        + ("실패(fail-on ml-hit)" if "ml-hit" in fail_on else "경고"),
        f"- 보류 {counts['pending']}개: "
        + ("실패(fail-on incomplete)" if "incomplete" in fail_on else "경고")
        + ". 보류는 검사를 끝내지 못한 항목이며 통과가 아닙니다.",
        "- 판정은 항목별 `known_malicious.status`, `ml.status`, `status`로 정했고 "
        "최상위 `exit_code`는 쓰지 않았습니다. 전체 보고서는 artifact `depbee-report`의 "
        "`report.json`입니다.",
    ]
    return failed, annotations, summary


def gate(report: Path, lockfile: str, fail_on_text: str, markdown: Path | None, summary) -> int:
    """Print annotations, append the job summary and return the step's exit status."""
    try:
        fail_on = parse_fail_on(fail_on_text)
        rows = load_report(report)
        lockfile = PurePosixPath(lockfile.replace("\\", "/")).as_posix()
        try:
            lines = Path(lockfile).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            lines = []  # annotations fall back to the whole file
        failed, annotations, lines_out = decide(rows, fail_on, lockfile, lines)
        # Written by the depbee CLI from the same report; it already escapes package data.
        cli_markdown = markdown.read_text(encoding="utf-8") if markdown is not None else ""
    except (ActionError, OSError, ValueError, RecursionError) as exc:
        print(command("error", f"depbee 보고서를 판정하지 못했습니다(실패로 처리): {exc}"))
        summary.write(
            "### depbee Actions 판정: 실패\n\n- 보고서를 만들거나 읽지 못했습니다. "
            "검사하지 못한 것을 통과로 두지 않습니다.\n"
        )
        return 1
    for annotation in annotations:
        print(annotation)
    if cli_markdown.strip():
        summary.write(cli_markdown.rstrip("\n") + "\n\n")
    else:  # the CLI Markdown already ends with the note
        lines_out += ["", f"> {SAFETY_NOTE}"]
    summary.write("\n".join(lines_out) + "\n")
    return 1 if failed else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("inputs", help="Validate the inputs passed in the environment")
    check = commands.add_parser("verify", help="Compare FILE SHA256 pairs")
    check.add_argument("pairs", nargs="+", metavar="FILE SHA256")
    count = commands.add_parser("count", help="Limit the changes in a depbee plan output")
    count.add_argument("plan", type=Path)
    count.add_argument("limit", type=int)
    report = commands.add_parser("report", help="Decide from a depbee report")
    report.add_argument("report", type=Path)
    report.add_argument("--lockfile", required=True)
    report.add_argument("--fail-on", default="")
    report.add_argument("--markdown", type=Path, help="depbee --format markdown output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    if args.command == "report":
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if not summary_path:
            return gate(args.report, args.lockfile, args.fail_on, args.markdown, sys.stdout)
        with open(summary_path, "a", encoding="utf-8") as summary:
            return gate(args.report, args.lockfile, args.fail_on, args.markdown, summary)
    try:
        if args.command == "inputs":
            check_inputs(dict(os.environ), Path.cwd())
        elif args.command == "verify":
            if len(args.pairs) % 2:
                raise ActionError("verify needs FILE SHA256 pairs")
            pairs = list(zip(args.pairs[::2], args.pairs[1::2], strict=True))
            verify([(Path(path), expected) for path, expected in pairs])
        else:
            count_changes(args.plan, args.limit)
    except (ActionError, OSError, ValueError, RecursionError) as exc:
        print(command("error", f"depbee action: {exc}"))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
