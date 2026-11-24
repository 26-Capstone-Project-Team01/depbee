"""The pinned depbee-analyzer's static rules (depbee_analyzer.rules.diff_scan) as the report's rule
checks (docs/result-contract-draft.md 3.2), run on the pair the extractor already verified.

scan() runs in the extractor's child process right after feature extraction
(FeatureExtractorBackend._extract_here), on the same two unpacked package roots and in the same
time budget: nothing is downloaded or unpacked again and no package code runs. It reads the roots
with the scanner's own read_root (its size limits) and calls its scan_pair. The scanner's
hit / no_hit / unknown become the contract's hit / not_hit / failed here, and only here:

- hit: the evidence names the rule's strength (review or high_evidence) and the scanner's reason;
  the locations are the package-relative files and lines it gave (a line it did not find is null).
- failed is undetermined (판정 불가), never an error: the scanner's unknown, a no_hit that a missing
  input could have changed, a hit that a file missing from the earlier version could have made
  (the behaviour may not be new), or two package.json files that are not the compared versions.
  Its detail starts with UNDETERMINED. pipeline.scan() holds such an item (D-7).
- An error of the scan itself (an exception, or an answer that is not the six rules of the pinned
  ruleset) is no check: Results.check() raises it, so the slot is failed / detector_failed with
  no checks and a detail that names the error's type only (a message can hold local paths).

Missing inputs come from two places, and both count: analysis.registry.unpack leaves out links,
case-only duplicates and files outside the package root, and the scanner's read_root skips files
over its size limits, links and unreadable files. A missing file changes a rule only if the rule
reads it; READS says which files each rule of RULESET reads besides package.json (diff_scan.py at
the pinned commit). A missing entry that is no plain file may stand for any path, so it counts for
every rule that reads more than package.json, as every entry does for a ruleset READS does not
describe.
"""

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath

from ..contracts import GuardError

# The ruleset of the analyzer that pyproject.toml pins (917ba903), which READS describes.
RULESET = "2026-11-16.1"
CODE_SUFFIXES = (".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx")
INSTALL_HOOKS = ("preinstall", "install", "postinstall")
# Per rule of RULESET: (whether PATH, a package-relative file, is one it reads besides
# package.json, or None if it reads package.json only; whether a file left the same in both
# versions cannot change it).
READS = {
    "R_download_exec": (None, True),
    "R_install_root_wipe": (None, True),
    # node FILE in an install hook of either version, matched as text: a superset of its pattern.
    "R_secret_send": (lambda path, hooks: path in hooks, False),
    "R_ci_secret_send": (lambda path, hooks: path.startswith(".github/workflows/"), True),
    "R_remote_admin_auth_override": (lambda path, hooks: path == "src/index.js", True),
    "R_diff_obfuscation": (lambda path, hooks: path.lower().endswith(CODE_SUFFIXES), True),
}
DISPOSITIONS = {
    "review": "검토용 적중(review)",
    "high_evidence": "강한 정적 근거(high_evidence)",
}
UNDETERMINED = "판정 불가"
KIND_LABELS = {
    "size_limit": "크기 제한",
    "read_error": "읽기 오류",
    "symlink": "링크",
    "link": "하드 링크",
    "case": "대소문자만 다른 이름",
    "outside_root": "패키지 폴더 밖",
}
MAX_LOCATIONS = 10
MAX_TEXT = 300
_SHOWN = 3  # missing files named in a detail


def scan(
    old_root: Path, new_root: Path, missing: dict[str, list[str]], pair: tuple[str, str, str]
) -> dict:
    """{"checks": [...], "cacheable": bool} for the two package roots of pair (name, old, new).

    missing: {"old": [...], "new": [...]}, the "PATH:KIND" entries unpack left out of each root.
    cacheable is false when a file could not be read, which may not happen again. Raises for an
    error of the scan itself (GuardError for an answer that is not the pinned ruleset's)."""
    from depbee_analyzer.rules import diff_scan

    files, lost = {}, {}
    for side, root in (("old", old_root), ("new", new_root)):
        files[side], skipped = diff_scan.read_root(root)
        lost[side] = list(missing.get(side, [])) + list(skipped)
    ruleset = diff_scan.RULESET_VERSION
    expected = {rule_id: disposition for rule_id, disposition, _ in diff_scan.RULES}
    mismatch = _identity_problem(files, pair)
    if mismatch:
        checks = [_failed(rule_id, ruleset, mismatch) for rule_id in expected]
    else:
        found = [
            _finding(f) for f in map(_as_dict, diff_scan.scan_pair(files["old"], files["new"]))
        ]
        if [f["rule_id"] for f in found] != list(expected) or any(
            f["disposition"] != expected[f["rule_id"]] for f in found
        ):
            raise GuardError("The rule scan did not return each rule of its ruleset once")
        hooks = "\n".join(_hooks(files["old"]) + _hooks(files["new"]))
        same = _unchanged(old_root, new_root, lost)
        checks = [convert(f, ruleset, lost, hooks, same) for f in found]
    cacheable = not any(entry.endswith(":read_error") for entry in lost["old"] + lost["new"])
    return {"checks": checks, "cacheable": cacheable}


def _as_dict(finding: object) -> dict:
    return {k: getattr(finding, k) for k in ("rule_id", "status", "disposition", "reason",
                                             "paths", "lines")}  # fmt: skip


def _finding(value: dict) -> dict:
    """A scanner finding checked for the types convert() reads; GuardError otherwise."""
    texts = ("rule_id", "status", "disposition", "reason")
    if not all(isinstance(value[k], str) for k in texts) or not all(
        isinstance(value[k], tuple | list) for k in ("paths", "lines")
    ):
        raise GuardError("The rule scan returned a malformed finding")
    if not all(isinstance(p, str) for p in value["paths"]) or not all(
        type(n) is int for n in value["lines"]
    ):
        raise GuardError("The rule scan returned a malformed location")
    return value


def _manifest(files: dict) -> dict | None:
    try:
        value = json.loads(files["package.json"].decode("utf-8"))
    except (KeyError, UnicodeError, ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _identity_problem(files: dict, pair: tuple[str, str, str]) -> str | None:
    """Why the two package.json files are not name@old and name@new, if they are not. A missing
    or unreadable one is left to the scanner, which answers unknown for every rule."""
    name, old, new = pair
    old_json, new_json = _manifest(files["old"]), _manifest(files["new"])
    if old_json is None or new_json is None:
        return None
    wrong = [
        label
        for label, value, wanted in (
            ("이전 버전의 이름", old_json.get("name"), name),
            ("새 버전의 이름", new_json.get("name"), name),
            ("이전 버전의 version", old_json.get("version"), old),
            ("새 버전의 version", new_json.get("version"), new),
        )
        if value != wanted
    ]
    if not wrong:
        return None
    return f"{UNDETERMINED}: 비교한 package.json의 {', '.join(wrong)}이(가) 이 변경과 다름"


def _hooks(files: dict) -> list[str]:
    scripts = (_manifest(files) or {}).get("scripts")
    if not isinstance(scripts, dict):
        return []
    return [v for k, v in scripts.items() if k in INSTALL_HOOKS and isinstance(v, str)]


def _unchanged(old_root: Path, new_root: Path, lost: dict) -> set[str]:
    """Paths the scanner skipped for size in both versions whose bytes are the same in both."""

    def paths(side: str) -> set[str]:
        return {e.rpartition(":")[0] for e in lost[side] if e.endswith(":size_limit")}

    same = set()
    for path in paths("old") & paths("new"):
        old, new = old_root / path, new_root / path
        try:
            if old.stat().st_size == new.stat().st_size and _sha256(old) == _sha256(new):
                same.add(path)
        except OSError:
            pass  # unreadable now: it stays missing
    return same


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _counts(rule_id: str, entry: str, hooks: str, same: set[str]) -> bool:
    """Whether a missing entry ("PATH:KIND") could change rule_id's result."""
    path, _, kind = entry.rpartition(":")
    if path == "package.json" or rule_id not in READS:
        return True
    reads, same_is_moot = READS[rule_id]
    if reads is None:
        return False  # it reads package.json only
    if kind not in ("size_limit", "read_error"):
        return True  # a link or another entry that is no plain file may stand for any path
    if same_is_moot and path in same:
        return False
    return reads(path, hooks)


def _missing_text(entries: list[str]) -> str:
    shown = []
    for entry in entries[:_SHOWN]:
        path, _, kind = entry.rpartition(":")
        shown.append(f"{path}({KIND_LABELS.get(kind, kind)})")
    more = len(entries) - _SHOWN
    return ", ".join(shown) + (f" 외 {more}개" if more > 0 else "")


def convert(finding: dict, ruleset: str, lost: dict, hooks: str, same: set[str]) -> dict:
    """One scanner finding as a contract check, with the missing inputs that could change it."""
    rule_id, status, reason = finding["rule_id"], finding["status"], finding["reason"]
    old = [e for e in lost["old"] if _counts(rule_id, e, hooks, same)]
    new = [e for e in lost["new"] if _counts(rule_id, e, hooks, same)]
    where = "; ".join(
        f"{label}: {_missing_text(entries)}"
        for label, entries in (("이전 버전", old), ("새 버전", new))
        if entries
    )
    if status == "unknown":
        return _failed(
            rule_id, ruleset, f"{UNDETERMINED}: {reason}" + (f" ({where})" if where else "")
        )
    if status == "hit" and old:
        return _failed(
            rule_id, ruleset,
            f"{UNDETERMINED}: 이전 버전에서 이 규칙이 읽는 파일이 빠져 새로 생긴 것인지 확정할 수 "
            f"없음 ({where}). 스캐너의 적중 근거: {reason}",
        )  # fmt: skip
    if status == "no_hit" and (old or new):
        return _failed(
            rule_id, ruleset,
            f"{UNDETERMINED}: 이 규칙이 읽는 파일이 빠져 미적중을 확정할 수 없음 ({where})",
        )  # fmt: skip
    if status == "hit":
        strength = DISPOSITIONS.get(finding["disposition"], finding["disposition"])
        return {
            "rule_id": rule_id,
            "rule_version": ruleset,
            "status": "hit",
            "evidence": [_cut(f"{strength}: {reason}")],
            "locations": _locations(finding["paths"], finding["lines"]),
            "detail": None,
        }
    if status == "no_hit":
        return {"rule_id": rule_id, "rule_version": ruleset, "status": "not_hit",
                "evidence": [], "locations": [], "detail": None}  # fmt: skip
    return _failed(rule_id, ruleset, f"{UNDETERMINED}: 스캐너의 알 수 없는 상태 {status!r}")


def _failed(rule_id: str, ruleset: str, detail: str) -> dict:
    return {"rule_id": rule_id, "rule_version": ruleset, "status": "failed",
            "evidence": [], "locations": [], "detail": _cut(detail)}  # fmt: skip


def _cut(text: str) -> str:
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT] + "..."


def _locations(paths, lines) -> list[dict]:
    """Package-relative POSIX files only (no absolute, drive, backslash or .. part), each with
    its line if the scanner found one (it gives 0 for none), at most MAX_LOCATIONS."""
    found = []
    for index, path in enumerate(paths):
        parts = PurePosixPath(path).parts
        if not path or "\\" in path or ":" in path or path.startswith("/") or ".." in parts:
            continue
        line = lines[index] if index < len(lines) else 0
        found.append({"file": path, "line": line if line > 0 else None})
    return found[:MAX_LOCATIONS]


def checked(value: object, ruleset: str) -> list[dict] | None:
    """value if it is the checks scan() makes for ruleset (from a child or a cache entry), else
    None: never an empty or partial list that would read as not_hit."""
    if not isinstance(value, list) or not value:
        return None
    fields = {"rule_id", "rule_version", "status", "evidence", "locations", "detail"}
    ids = [c.get("rule_id") if isinstance(c, dict) else None for c in value]
    if len(set(ids)) != len(ids) or (ruleset == RULESET and set(ids) != set(READS)):
        return None
    for check in value:
        if (
            set(check) != fields
            or not isinstance(check["rule_id"], str)
            or check["rule_version"] != ruleset
            or check["status"] not in ("hit", "not_hit", "failed")
            or not isinstance(check["evidence"], list)
            or not all(isinstance(e, str) for e in check["evidence"])
            or not isinstance(check["locations"], list)
            or not all(
                isinstance(x, dict)
                and set(x) == {"file", "line"}
                and isinstance(x["file"], str)
                and (x["line"] is None or type(x["line"]) is int)
                for x in check["locations"]
            )
            or not (check["detail"] is None or isinstance(check["detail"], str))
            or (check["status"] == "failed") != isinstance(check["detail"], str)
        ):
            return None
    return value


class Results:
    """RuleDetector (contracts) over the rule results an ExtractorAnalyzer kept for the changes of
    its latest analyze(): found maps a change_id to {"pair": [name, baseline, new], "checks": [...]}
    or {"pair": ..., "error": text}. A change it has none for, or one of another compared pair, is
    an error, never not_hit."""

    def __init__(self, ruleset_version: str) -> None:
        self.ruleset_version = ruleset_version
        self.found: dict[str, dict] = {}

    def check(self, change: dict, analysis: dict) -> list[dict]:
        kept = self.found.get(change["change_id"])
        pair = [change["after"]["name"], analysis.get("baseline_version"),
                change["after"]["version"]]  # fmt: skip
        if kept is None or kept["pair"] != pair:
            raise GuardError("No rule scan result for this compared pair")
        if "error" in kept:
            raise GuardError(kept["error"])
        return copy.deepcopy(kept["checks"])
