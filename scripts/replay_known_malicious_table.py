"""Replay a fixed KM-01 verdict table against a known malicious index folder, offline.

The table is written apart from depbee, from the OSV records of one all.zip. This script loads
the index (depbee.known_malicious.load) and compares match() of every name@version with the
table: the same hit or not_hit and, for a hit, exactly the same advisory_id and match_kind of
every record. Nothing is fetched and nothing is written.

    python scripts/replay_known_malicious_table.py table.csv src/depbee/assets/index \
        --snapshot-sha256 <SHA-256 of the all.zip the table was written from>

Table: UTF-8 CSV (a BOM is allowed) whose first line is exactly
package,expected,advisory_id,match_kind
- package: name@version, split at the last @ (@scope/name@1.2.3): an npm name as depbee takes
  it (case kept) and a strict SemVer 2.0 version (build metadata allowed, ignored in matching).
- expected hit: advisory_id and match_kind (listed_version or affected_range). A version that
  several records name has one row per record.
- expected not_hit: advisory_id and match_kind are empty, and the package has no other row.

Exit code 0: every case equals the table. 1: a case differs (expected and actual are printed).
2: nothing was compared, because the table is unreadable, malformed, empty or has a duplicate or
conflicting row, the index does not load, or --snapshot-sha256 is not the index's
snapshot_sha256 (the SHA-256 of all.zip, not list_sha256, which is the SHA-256 of index.json).
"""

import argparse
import csv
import io
import re
from pathlib import Path

from depbee.inputs.npm import MAX_NAME_LENGTH, PACKAGE_NAME
from depbee.known_malicious import load, version_key

HEADER = ["package", "expected", "advisory_id", "match_kind"]
KINDS = ("listed_version", "affected_range")
# The table is asked to have 20 to 30 rows; a replay of fewer cases is reported as partial.
MIN_CASES = 20


def read_table(path: Path) -> dict:
    """{(name, version): {advisory_id: match_kind}} in table order, {} for not_hit. ValueError
    for a table that is not exactly the documented form."""
    text = path.read_bytes().decode("utf-8-sig")
    rows = csv.reader(io.StringIO(text, newline=""), strict=True)
    cases: dict[tuple[str, str], dict[str, str]] = {}
    try:
        if next(rows, None) != HEADER:
            raise ValueError(f"the first line must be exactly {','.join(HEADER)}")
        for row in rows:
            if len(row) != len(HEADER) or any(field != field.strip() for field in row):
                raise ValueError(f"expected {len(HEADER)} fields without surrounding spaces")
            package, expected, advisory, kind = row
            name, _, version = package.rpartition("@")
            # A name or version depbee takes from no user has no verdict to compare, and a
            # mistyped one (name@@1.0.0) would pass as not_hit. Build metadata is valid SemVer.
            if len(name) > MAX_NAME_LENGTH or not PACKAGE_NAME.fullmatch(name):
                raise ValueError(f"package is not <npm name>@<version>: {package[:64]!a}")
            version_key(version)
            if not (
                (expected == "hit" and advisory and kind in KINDS)
                or (expected == "not_hit" and not advisory and not kind)
            ):
                raise ValueError(
                    f"expected must be hit with advisory_id and match_kind ({' or '.join(KINDS)})"
                    ", or not_hit with both empty"
                )
            key = (name, version)
            if key in cases and (not advisory or not cases[key] or advisory in cases[key]):
                raise ValueError(f"duplicate or conflicting row for {package[:64]!a}")
            cases.setdefault(key, {})
            if advisory:
                cases[key][advisory] = kind
    except (ValueError, csv.Error) as exc:
        raise ValueError(f"line {rows.line_num}: {exc}") from None
    if not cases:
        raise ValueError("the table has no rows")
    return cases


def shown(found: dict) -> str:
    return "; ".join(f"hit {a} {k}" for a, k in sorted(found.items())) or "not_hit"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("table", type=Path, help="Verdict table (UTF-8 CSV)")
    parser.add_argument("index_dir", type=Path, help="Folder with index.json and manifest.json")
    parser.add_argument(
        "--snapshot-sha256", required=True, help="SHA-256 of the all.zip the table was made from"
    )
    args = parser.parse_args()
    snapshot = args.snapshot_sha256.lower()  # Get-FileHash prints upper case
    try:
        if not re.fullmatch(r"[0-9a-f]{64}", snapshot, re.ASCII):
            raise ValueError("--snapshot-sha256 is not 64 hex digits")
        cases = read_table(args.table)
        index = load(args.index_dir)
        if index.snapshot_sha256 != snapshot:
            raise ValueError(
                f"wrong snapshot: expected (--snapshot-sha256) {snapshot}, "
                f"actual (index snapshot_sha256) {index.snapshot_sha256}"
            )
    except (OSError, ValueError) as exc:  # GuardError and UnicodeDecodeError are ValueErrors
        parser.error(str(exc))
    lines = [
        f"snapshot_sha256 {index.snapshot_sha256} (equals --snapshot-sha256)",
        f"list_sha256 {index.list_sha256}, list_as_of {index.list_as_of}, source {index.source}",
    ]
    differ = 0
    for (name, version), expected in cases.items():
        actual = {m["advisory_id"]: m["match_kind"] for m in index.match(name, version)}
        if actual == expected:
            lines.append(f"OK   {name}@{version}: {shown(expected)}")
        else:
            differ += 1
            lines.append(
                f"DIFF {name}@{version}: expected {shown(expected)} | actual {shown(actual)}"
            )
    partial = f" (partial: fewer than {MIN_CASES} cases)" if len(cases) < MIN_CASES else ""
    if differ:
        lines.append(f"result: {differ} of {len(cases)} cases differ from the table{partial}")
    else:
        lines.append(f"result: all {len(cases)} cases equal the table{partial}")
    for line in lines:
        # Table and index text is printed escaped: no control character, any console encoding.
        print(line.encode("unicode_escape").decode("ascii"))
    return 1 if differ else 0


if __name__ == "__main__":
    raise SystemExit(main())
