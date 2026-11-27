"""CI only: FILE must be a report of the example update (lodash 4.17.20 to 4.17.21) that this
checkout's model, index and pinned analyzer really checked. A held item, another model or index,
or an analyzer that is not the unchanged Git install of pyproject.toml's pin fails here.

    python -I .github/scripts/check_lodash_report.py FILE [ANALYZER_FILES_SHA256]

FILE is a depbee report, or JSON that holds one under "report" (depbee update, the MCP tools,
a dashboard run as history.get_run gives it).
ANALYZER_FILES_SHA256 is the digest that the depbee which made the report gives its own installed
analyzer (files_sha256 of extractor._installed_identity). With it, the report must name it.

    python -I .github/scripts/check_lodash_report.py --compare NAME=FILE NAME=FILE [...]
        [ANALYZER_FILES_SHA256]

Each FILE is checked as above, and the reports of the entry points named must then say the same
about the update in every field: the request and its change, the model, the index, the analyzer
(version, commit and digest of its installed files), the features, the score and its
explanation, every rule's result and evidence, and the verdicts. Values must have the same
type and be equal. Only the floats the model computed (the score, the contributions, their
remaining sum and the base value) may differ, by a relative 1e-12, which is what a math
library can move between hosts. Only what belongs to one run or host is left out: the times,
the cache hit and the Python that ran the analyzer. A difference ends with exit code 1 and one
line per field, which names the field and every source's value.
"""

import hashlib
import json
import math
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "src" / "depbee" / "assets"
# The ruleset and rules of the analyzer that pyproject.toml pins (917ba903, rules/diff_scan.py).
RULESET = "2026-11-16.1"
RULE_IDS = ["R_download_exec", "R_secret_send", "R_ci_secret_send", "R_install_root_wipe",
            "R_remote_admin_auth_override", "R_diff_obfuscation"]  # fmt: skip


def main(file: str, analyzer_files: str | None = None) -> dict:
    data = json.loads(Path(file).read_bytes())
    report = data.get("report", data)
    manifest = (ASSETS / "model" / "manifest.json").read_bytes()
    model, index = json.loads(manifest), json.loads((ASSETS / "index" / "manifest.json").read_bytes())
    project = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))
    (pin,) = project["project"]["optional-dependencies"]["extract"]

    assert (report["status"], report["exit_code"]) == ("passed", 0), report["status"]
    (row,) = report["results"]
    versions = (row["package"], row["before_version"], row["after_version"])
    assert versions == ("lodash", "4.17.20", "4.17.21"), versions
    # Analyzed and scored, not held: the registry's two tarballs, read by the analyzer.
    assert row["compared_version"] == "4.17.20", row["compared_version"]
    states = (row["status"], row["ml"]["status"], row["known_malicious"]["status"])
    assert states == ("not_flagged", "not_hit", "not_hit"), states
    assert 0 <= row["score"] < report["threshold"], row["score"]
    # A report names them only after LightGBM loaded that model and the index was read: the
    # model's bytes and the bytes of its manifest, which holds the threshold and the features.
    assert report["model_id"] == model["model_id"], report["model_id"]
    used = report["provenance"]["model"]
    assert used["model_sha256"] == model["model_sha256"], used["model_sha256"]
    assert used["manifest_sha256"] == hashlib.sha256(manifest).hexdigest(), used["manifest_sha256"]
    known = report["detectors"]["known_malicious"]
    assert (known["list_as_of"], known["list_sha256"]) == (index["list_as_of"],
                                                         index["index_sha256"])  # fmt: skip
    # The pinned analyzer's six static rules ran on the same two tarballs and each one judged:
    # a hit is display only and allowed, undetermined or failed would hold the item. The slot's
    # status is the one its checks give (hit if any is, else not_hit).
    rules = report["detectors"].get("rules") or {}
    assert rules.get("ruleset_version") == RULESET, rules
    checks = row["rules"]["checks"]
    assert [c["rule_id"] for c in checks] == RULE_IDS, checks
    assert all((c["rule_version"], c["status"] in ("hit", "not_hit")) == (RULESET, True)
               for c in checks), checks  # fmt: skip
    expected = "hit" if any(c["status"] == "hit" for c in checks) else "not_hit"
    assert row["rules"]["status"] == expected, row["rules"]
    # The commit and the digest of the installed files are in a report only for the unchanged
    # Git install of that pin (extractor._installed_identity); otherwise this entry is null.
    analyzer = report["provenance"]["feature_extractor"]
    assert analyzer, "the analyzer's install was not verified"
    assert pin.endswith(f"@{analyzer['commit']}"), analyzer["commit"]
    files = analyzer.get("files_sha256")
    assert isinstance(files, str) and re.fullmatch("[0-9a-f]{64}", files), files
    assert analyzer_files in (None, files), f"{files}, not the installed {analyzer_files}"
    print(f"{file}: lodash 4.17.20 to 4.17.21 passed, model {report['model_id']}, "
          f"index {known['list_as_of']}, analyzer {analyzer['commit']} (files {files[:12]})")  # fmt: skip
    return report


def left_out(path: tuple) -> bool:
    """Whether the value at this path belongs to one run or one host and not to the update: the
    times, the cache hit and the Python that ran the analyzer. A path is the keys and list
    positions from the report down to the value, so a feature of the same name is compared."""
    match path:
        case (("elapsed_seconds",) | ("results", int(), "elapsed_seconds" | "cache_hit")
              | ("provenance", "feature_extractor", "python")):  # fmt: skip
            return True
    return False


def computed(path: tuple) -> bool:
    """Whether the model computed the value at this path in floating point: the score, a
    feature's contribution, the sum of the other contributions and the base value."""
    match path:
        case (("results", int(), "score")
              | ("results", int(), "explanation", int(), "contribution")
              | ("results", int(), "explanation_rest", "others_sum" | "base_value")):  # fmt: skip
            return True
    return False


ABSENT = type("Absent", (), {"__repr__": lambda self: "absent"})()


def semantics(report: dict) -> dict:
    """{path: (name, value)} for every value of a report that is not left_out. The name is for
    a message: a list item by its position, a rule check by its rule ID."""
    said = {}

    def walk(value: object, path: tuple, name: str) -> None:
        if isinstance(value, dict) and value:
            for key, inner in value.items():
                if not left_out((*path, key)):
                    walk(inner, (*path, key), f"{name}.{key}" if name else key)
        elif isinstance(value, list) and value:
            for index, inner in enumerate(value):
                item = inner.get("rule_id", index) if isinstance(inner, dict) else index
                walk(inner, (*path, index), f"{name}[{item}]")
        else:
            said[path] = (name, value)

    walk(report, (), "")
    return said


def same(path: tuple, one: object, other: object) -> bool:
    """Whether two sources say the same at a path: the same type and value. Only two floats
    that the model computed may differ, and only as far as the math library under LightGBM
    can move their last digits between supported hosts. Everything else is read from the
    lockfile, the registry or a manifest, or counted, and is the same everywhere."""
    if computed(path) and type(one) is type(other) is float:
        return math.isclose(one, other, rel_tol=1e-12, abs_tol=0.0)
    return type(one) is type(other) and one == other


def compare(*arguments: str) -> None:
    """NAME=FILE of two or more entry points, then optionally ANALYZER_FILES_SHA256 for all."""
    named = [argument.split("=", 1) for argument in arguments if "=" in argument]
    (analyzer_files,) = [argument for argument in arguments if "=" not in argument] or [None]
    names = [name for name, _ in named]
    assert len(set(names)) == len(names) >= 2, f"two or more NAME=FILE, each name once: {names}"
    said = {name: semantics(main(file, analyzer_files)) for name, file in named}
    paths = {}  # each path's name for a message, in the order the sources give them
    for name in names:
        for path, (field, _) in said[name].items():
            paths.setdefault(path, field)

    def value(name: str, path: tuple) -> object:
        return said[name].get(path, (None, ABSENT))[1]

    differences = [
        f"{field} differs: " + ", ".join(f"{name}={value(name, path)!r}" for name in names)
        for path, field in paths.items()
        if not all(same(path, value(names[0], path), value(name, path)) for name in names)
    ]
    if differences:
        raise SystemExit("\n".join(["report parity failed", *differences]))
    print(f"{len(names)} reports say the same ({', '.join(names)}): score "
          f"{value(names[0], ('results', 0, 'score'))!r}, threshold "
          f"{value(names[0], ('threshold',))!r}, exit code {value(names[0], ('exit_code',))}, "
          f"{len(paths)} fields compared")  # fmt: skip


if __name__ == "__main__":
    # Every check here is an assert statement, which python -O would skip.
    if not __debug__:
        raise SystemExit("run without -O: the checks are assert statements")
    if sys.argv[1:2] == ["--compare"]:
        compare(*sys.argv[2:])
    else:
        main(*sys.argv[1:])
