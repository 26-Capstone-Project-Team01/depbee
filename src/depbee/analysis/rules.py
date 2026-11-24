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
  (the behaviour may not be new) or that names in either version spelled two ways make uncertain,
  or two package.json files that are not surely the compared versions. Its detail starts with
  UNDETERMINED. pipeline.scan() holds such an item (D-7) unless a known malicious match flags it.
- An error of the scan itself (an exception, or an answer that is not the six rules of the pinned
  ruleset) is no check: Results.check() raises it, so the slot is failed / detector_failed with
  no checks and a detail that names the error's type only (a message can hold local paths).

Missing inputs come from four places, and all count: analysis.registry.unpack leaves out links
and files outside the package root and reports names spelled in two cases, the files the scanner
finds can differ from the names the archive gave (alias: a folder or name merged on unpacking),
the scanner's read_root skips files over its size limits, links and unreadable files, and an
install hook can name a file the package does not have. A missing file changes a rule only if the
rule reads it; READS says which files each rule of RULESET reads besides package.json (diff_scan.py
at the pinned commit). A missing entry that is no plain file may stand for any path, so it counts
for every rule that reads more than package.json, as every entry does for another ruleset. A file
the scanner skipped is never read again here: whether it changed is not known. Both package.json files
must read as strict JSON objects naming the compared versions, with nothing missing in their
place, or no rule is judged: a manifest decoded or chosen differently than the scanner's would
otherwise decide the six results.
"""

import copy
import re
from pathlib import Path, PurePosixPath

from ..contracts import GuardError, parse_json

# The ruleset of the analyzer that pyproject.toml pins (917ba903), which READS describes.
RULESET = "2026-11-16.1"
CODE_SUFFIXES = (".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx")
INSTALL_HOOKS = ("preinstall", "install", "postinstall")
# The files R_secret_send reads: node FILE in a preinstall, install or postinstall command of
# either version, as the pinned diff_scan.py (_telemetry_upload, _install_scripts) finds them.
NODE_FILE = re.compile(r"\bnode\s+(?:\./)?([\w./-]+\.(?:js|cjs|mjs))\b", re.I)
# Per rule of RULESET only: whether PATH, a package-relative file, is one it reads besides
# package.json, given the NODE_FILE paths of both versions; None if it reads package.json only.
READS = {
    "R_download_exec": None,
    "R_install_root_wipe": None,
    "R_secret_send": lambda path, refs: path in refs,
    "R_ci_secret_send": lambda path, refs: path.startswith(".github/workflows/"),
    "R_remote_admin_auth_override": lambda path, refs: path == "src/index.js",
    "R_diff_obfuscation": lambda path, refs: path.lower().endswith(CODE_SUFFIXES),
}
# Entries whose path may not be the one the scanner read it under, in either version.
AMBIGUOUS = ("case", "alias")
# The rules of RULESET in the scanner's order with their strength (diff_scan.RULES at 917ba903):
# a result for RULESET has them in this order, a hit with its own strength (checked).
PINNED = (
    ("R_download_exec", "review"),
    ("R_secret_send", "high_evidence"),
    ("R_ci_secret_send", "high_evidence"),
    ("R_install_root_wipe", "high_evidence"),
    ("R_remote_admin_auth_override", "review"),
    ("R_diff_obfuscation", "review"),
)
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
    "alias": "보관된 이름과 읽힌 이름이 다름",
    "outside_root": "패키지 폴더 밖",
    "absent": "설치 훅이 가리키지만 패키지에 없음",
}
MAX_LOCATIONS = 10
MAX_PATH = 256  # a location's file, as MCP's package data
MAX_TEXT = 300
_SHOWN = 3  # missing files named in a detail


def scan(
    old_root: Path,
    new_root: Path,
    missing: dict[str, list[str]],
    pair: tuple[str, str, str],
    names: dict[str, list[str] | None] | None = None,
) -> dict:
    """{"checks": [...], "cacheable": bool} for the two package roots of pair (name, old, new).

    missing: {"old": [...], "new": [...]}, the "PATH:KIND" entries unpack left out of each root.
    names: the files the archive named in each root (unpack's written), None for a root that is
    no archive (a local copy). cacheable is false when a file could not be read, which may not
    happen again. Raises for an error of the scan itself (GuardError for an answer that is not
    the pinned ruleset's)."""
    from depbee_analyzer.rules import diff_scan

    files, lost = {}, {}
    for side, root in (("old", old_root), ("new", new_root)):
        files[side], skipped = diff_scan.read_root(root)
        lost[side] = list(missing.get(side, [])) + list(skipped)
        if (names or {}).get(side) is not None:
            lost[side] += _aliases(names[side], files[side], lost[side])
    ruleset = diff_scan.RULESET_VERSION
    expected = {rule_id: disposition for rule_id, disposition, _ in diff_scan.RULES}
    manifests = {side: _manifest(files[side]) for side in files}
    mismatch = _identity_problem(manifests, lost, pair)
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
        refs = {side: _node_files(manifests[side]) for side in files}
        for side in files:  # named by an install hook, not in the package (nor already missing)
            named = {entry.rpartition(":")[0] for entry in lost[side]}
            lost[side] += [f"{path}:absent" for path in sorted(refs[side])
                           if path not in files[side] and path not in named]  # fmt: skip
        checks = [convert(f, ruleset, lost, refs["old"] | refs["new"]) for f in found]
    # An unreadable file may read next time, and a name the scanner did not find where the
    # archive put it (alias) may be a folder its walk could not list then: neither is stored.
    one_off = any(entry.endswith((":read_error", ":alias")) for entry in lost["old"] + lost["new"])
    return {"checks": checks, "cacheable": not one_off}


def _aliases(names: list[str], read: dict, lost: list[str]) -> list[str]:
    """An entry "PATH:alias" for each file the archive named that the scanner neither read nor
    skipped under that name, and for each file it read that the archive did not name: a folder or
    file name the file system merged or changed on unpacking (case, a trailing dot on Windows)."""
    seen = set(read) | {entry.rpartition(":")[0] for entry in lost}
    named = set(names)
    return [f"{path}:alias" for path in sorted((named - seen) | (set(read) - named))]


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
    """The package.json the scanner read, as a strict JSON object (UTF-8, unique keys), or None."""
    raw = files.get("package.json")
    if raw is None:
        return None
    try:
        return parse_json(raw, "package.json")[0]
    except GuardError:
        return None


def _identity_problem(manifests: dict, lost: dict, pair: tuple[str, str, str]) -> str | None:
    """Why the two package.json files are not surely name@old and name@new, if they are not: one
    is missing, cannot be read as a strict JSON object, has an entry left out in its place (its
    size, a link, or a name that differs only in case, on any platform), or names other values."""
    name, old, new = pair
    for side, label in (("old", "이전 버전"), ("new", "새 버전")):
        if any(entry.rpartition(":")[0].casefold() == "package.json" for entry in lost[side]):
            return (f"{UNDETERMINED}: {label}의 package.json이 하나로 정해지지 않음"
                    "(크기 제한, 링크, 대소문자만 다른 이름 등)")  # fmt: skip
        if manifests[side] is None:
            return f"{UNDETERMINED}: {label}의 package.json을 엄격한 UTF-8 JSON 객체로 읽을 수 없음"
    old_json, new_json = manifests["old"], manifests["new"]
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


def _node_files(manifest: dict) -> set[str]:
    """NODE_FILE paths of a manifest's install hooks, as the pinned scanner finds them."""
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict):
        return set()
    return {path for key, script in scripts.items()
            if key in INSTALL_HOOKS and isinstance(script, str)
            for path in NODE_FILE.findall(script)}  # fmt: skip


def _counts(rule_id: str, entry: str, refs: set[str], ruleset: str) -> bool:
    """Whether a missing entry ("PATH:KIND") could change rule_id's result. READS holds for its
    own ruleset only. A missing package.json never gets here (_identity_problem)."""
    path, _, kind = entry.rpartition(":")
    if ruleset != RULESET or rule_id not in READS:
        return True
    if kind == "absent":
        return rule_id == "R_secret_send"  # only it follows an install hook to the file
    reads = READS[rule_id]
    if reads is None:
        return False  # it reads package.json only
    if kind not in ("size_limit", "read_error"):
        return True  # a link or another entry that is no plain file may stand for any path
    return reads(path, refs)


def _missing_text(entries: list[str]) -> str:
    shown = []
    for entry in entries[:_SHOWN]:
        path, _, kind = entry.rpartition(":")
        shown.append(f"{path}({KIND_LABELS.get(kind, kind)})")
    more = len(entries) - _SHOWN
    return ", ".join(shown) + (f" 외 {more}개" if more > 0 else "")


def convert(finding: dict, ruleset: str, lost: dict, refs: set[str]) -> dict:
    """One scanner finding as a contract check, with the missing inputs that could change it.
    refs: the NODE_FILE paths of both versions."""
    rule_id, status, reason = finding["rule_id"], finding["status"], finding["reason"]
    old = [e for e in lost["old"] if _counts(rule_id, e, refs, ruleset)]
    new = [e for e in lost["new"] if _counts(rule_id, e, refs, ruleset)]
    respelled = any(e.rpartition(":")[2] in AMBIGUOUS for e in new)
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
    if status == "hit" and respelled:
        return _failed(
            rule_id, ruleset,
            f"{UNDETERMINED}: 새 버전의 이름이 두 가지로 쓰여 적중한 경로를 확정할 수 없음 "
            f"({where}). 스캐너의 적중 근거: {reason}",
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


def _package_path(path: object) -> bool:
    """A package-relative POSIX file: text of 1 to MAX_PATH characters without an absolute,
    drive, backslash or .. part."""
    if not isinstance(path, str) or not 0 < len(path) <= MAX_PATH or "\\" in path or ":" in path:
        return False
    return not path.startswith("/") and ".." not in PurePosixPath(path).parts


def _locations(paths, lines) -> list[dict]:
    """_package_path files only, each with its line if the scanner found one (it gives 0 for
    none), at most MAX_LOCATIONS."""
    found = []
    for index, path in enumerate(paths):
        if not _package_path(path):
            continue
        line = lines[index] if index < len(lines) else 0
        found.append({"file": path, "line": line if line > 0 else None})
    return found[:MAX_LOCATIONS]


CHECK_FIELDS = {"rule_id", "rule_version", "status", "evidence", "locations", "detail"}


def _text(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_TEXT + 3  # _cut's longest


def _labelled(text: object, label: str | None) -> bool:
    """Whether text is "LABEL: reason" with a reason that is not blank, as convert() and
    _failed() write it; label None: any label (a ruleset whose strengths are not in PINNED)."""
    if not _text(text):
        return False
    head, colon, reason = text.partition(": ")
    return bool(colon) and bool(reason.strip()) and (label is None or head == label)


def _made(check: object, ruleset: str) -> bool:
    """Whether check is one convert() or _failed() can make for ruleset: its fields, and for its
    status the evidence, locations and detail that go with it (a hit: one evidence line naming
    its strength, PINNED's for RULESET, and a reason, with _locations' files and lines; not_hit:
    nothing; failed: an undetermined detail with a reason)."""
    if not isinstance(check, dict) or set(check) != CHECK_FIELDS:
        return False
    rule_id, status = check["rule_id"], check["status"]
    if not isinstance(rule_id, str) or not rule_id or check["rule_version"] != ruleset:
        return False
    evidence, locations, detail = check["evidence"], check["locations"], check["detail"]
    if status == "hit":
        strength = dict(PINNED).get(rule_id) if ruleset == RULESET else None
        label = DISPOSITIONS[strength] if strength else None
        return (
            isinstance(evidence, list) and len(evidence) == 1 and _labelled(evidence[0], label)
            and detail is None and isinstance(locations, list)
            and len(locations) <= MAX_LOCATIONS
            and all(isinstance(x, dict) and set(x) == {"file", "line"}
                    and _package_path(x["file"])
                    and (x["line"] is None or (type(x["line"]) is int and x["line"] > 0))
                    for x in locations)
        )  # fmt: skip
    if status == "not_hit":
        return evidence == [] and locations == [] and detail is None
    if status == "failed":
        return evidence == [] and locations == [] and _labelled(detail, UNDETERMINED)
    return False


def checked(value: object, ruleset: str) -> list[dict] | None:
    """value if it is the checks scan() makes for ruleset (from a child or a cache entry), else
    None: never an empty or partial list that would read as not_hit, and never an exception,
    whatever JSON value it is. Each check is validated before any is compared with another."""
    if not isinstance(value, list) or not value or not all(_made(c, ruleset) for c in value):
        return None
    ids = [check["rule_id"] for check in value]  # all text now
    if len(set(ids)) != len(ids) or (ruleset == RULESET and ids != [i for i, _ in PINNED]):
        return None  # RULESET: its six rules in the scanner's order, as scan() keeps them
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
