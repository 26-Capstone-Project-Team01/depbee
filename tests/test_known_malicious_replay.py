"""Replay of a fixed verdict table (scripts/replay_known_malicious_table.py).

Synthetic only: the made-up records of test_known_malicious (example-*, MAL-EXAMPLE-*), and
expectations written by hand from those records.
"""

import codecs
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_known_malicious import AS_OF, RECORDS, ROOT, snapshot

from depbee.known_malicious import build_index

HEADER = "package,expected,advisory_id,match_kind"
MULTI = [
    "example-multi@2.0.0,hit,MAL-EXAMPLE-0020,listed_version",
    "example-multi@2.0.0,hit,MAL-EXAMPLE-0016,affected_range",
]
ROWS = [
    "example-listed@1.0.1,hit,MAL-EXAMPLE-0001,listed_version",
    "example-listed@1.0.0,not_hit,,",
    "example-range@1.2.4,hit,MAL-EXAMPLE-0002,affected_range",
    "example-range@1.2.5,not_hit,,",
    "example-all@9.9.9,hit,MAL-EXAMPLE-0006,affected_range",
    "example-withdrawn@4.13.3,not_hit,,",
    "example-security@0.0.1-security,not_hit,,",
    "@example/scoped@1.0.0,hit,MAL-EXAMPLE-0013,listed_version",
    "example-pre@1.0.0-beta.2,hit,MAL-EXAMPLE-0004,affected_range",
    "example-ghsa@3.3.6,not_hit,,",
    *MULTI,
]


def table(*rows, header=HEADER):
    return "".join(f"{line}\n" for line in (header, *rows))


class ReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        zipped = snapshot(RECORDS)
        cls.snapshot_sha256 = hashlib.sha256(zipped).hexdigest()
        index, manifest, _ = build_index(zipped, AS_OF)
        cls.list_sha256 = hashlib.sha256(index).hexdigest()
        cls.index = cls.tmp / "km"
        cls.index.mkdir()
        (cls.index / "index.json").write_bytes(index)
        (cls.index / "manifest.json").write_bytes(manifest)

    def run_script(self, text, sha256=None, index=None):
        path = self.tmp / "table.csv"
        path.write_bytes(text if isinstance(text, bytes) else text.encode())
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        script = ROOT / "scripts" / "replay_known_malicious_table.py"
        return subprocess.run(
            [sys.executable, str(script), str(path), str(index or self.index),
             "--snapshot-sha256", sha256 or self.snapshot_sha256],
            capture_output=True, text=True, env=env, timeout=120,
        )  # fmt: skip

    def test_equal_table_passes_and_fewer_cases_are_partial(self):
        done = self.run_script(table(*ROWS))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(f"snapshot_sha256 {self.snapshot_sha256}", done.stdout)
        self.assertIn(f"list_sha256 {self.list_sha256}", done.stdout)
        self.assertIn(
            "OK   example-multi@2.0.0: hit MAL-EXAMPLE-0016 affected_range; "
            "hit MAL-EXAMPLE-0020 listed_version",
            done.stdout,
        )
        self.assertIn("OK   example-listed@1.0.0: not_hit", done.stdout)
        self.assertNotIn("DIFF", done.stdout)
        self.assertTrue(
            done.stdout.endswith(
                "result: all 11 cases equal the table (partial: fewer than 20 cases)\n"
            ),
            done.stdout,
        )

    def test_twenty_cases_are_not_partial(self):
        rows = [f"example-long@1.0.{n},hit,MAL-EXAMPLE-0017,listed_version" for n in range(20)]
        done = self.run_script(table(*rows))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(done.stdout.endswith("result: all 20 cases equal the table\n"), done.stdout)

    def test_accepted_forms(self):
        # A BOM, CRLF, a quoted field, build metadata, exact case and an upper-case SHA-256.
        rows = [
            *ROWS,
            "example-listed@1.0.1+build.7,hit,MAL-EXAMPLE-0001,listed_version",
            "Example-Case@1.0.0,hit,MAL-EXAMPLE-0014,listed_version",
            "example-case@1.0.0,not_hit,,",
        ]
        text = table(*rows).replace("example-ghsa@3.3.6", '"example-ghsa@3.3.6"')
        raw = codecs.BOM_UTF8 + text.replace("\n", "\r\n").encode()
        done = self.run_script(raw, self.snapshot_sha256.upper())
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("result: all 14 cases equal the table (partial", done.stdout)

    def test_any_difference_fails_with_expected_and_actual(self):
        both = "hit MAL-EXAMPLE-0016 affected_range; hit MAL-EXAMPLE-0020 listed_version"
        cases = {
            "expected hit, not hit": (
                ["example-listed@1.0.0,hit,MAL-EXAMPLE-0001,listed_version"],
                "DIFF example-listed@1.0.0: expected hit MAL-EXAMPLE-0001 listed_version"
                " | actual not_hit",
            ),
            "expected not_hit, hit": (
                ["example-listed@1.0.1,not_hit,,"],
                "DIFF example-listed@1.0.1: expected not_hit"
                " | actual hit MAL-EXAMPLE-0001 listed_version",
            ),
            "other advisory": (
                ["example-listed@1.0.1,hit,MAL-EXAMPLE-0002,listed_version"],
                "expected hit MAL-EXAMPLE-0002 listed_version"
                " | actual hit MAL-EXAMPLE-0001 listed_version",
            ),
            "other match_kind": (
                ["example-listed@1.0.1,hit,MAL-EXAMPLE-0001,affected_range"],
                "expected hit MAL-EXAMPLE-0001 affected_range"
                " | actual hit MAL-EXAMPLE-0001 listed_version",
            ),
            "one of two advisories missing": (
                [MULTI[0]],
                f"expected hit MAL-EXAMPLE-0020 listed_version | actual {both}",
            ),
            "one advisory too many": (
                [*MULTI, "example-multi@2.0.0,hit,MAL-EXAMPLE-0099,listed_version"],
                f"expected {both}; hit MAL-EXAMPLE-0099 listed_version | actual {both}",
            ),
            "one kind of two differs": (
                [MULTI[0], MULTI[1].replace("affected_range", "listed_version")],
                "expected hit MAL-EXAMPLE-0016 listed_version; "
                f"hit MAL-EXAMPLE-0020 listed_version | actual {both}",
            ),
        }
        for label, (rows, line) in cases.items():
            with self.subTest(label):
                done = self.run_script(table("example-range@1.2.4,hit,MAL-EXAMPLE-0002,"
                                             "affected_range", *rows))  # fmt: skip
                self.assertEqual(done.returncode, 1, done.stderr)
                self.assertIn(line, done.stdout)
                self.assertIn("OK   example-range@1.2.4", done.stdout)
                self.assertIn("result: 1 of 2 cases differ from the table (partial", done.stdout)

    def test_wrong_snapshot_is_refused_before_comparing(self):
        other = hashlib.sha256(b"another all.zip").hexdigest()
        # list_sha256 is the digest of index.json, not of the snapshot the table names.
        for sha256 in (other, self.list_sha256):
            with self.subTest(sha256):
                done = self.run_script(table(*ROWS), sha256)
                self.assertEqual(done.returncode, 2)
                self.assertIn(f"expected (--snapshot-sha256) {sha256}", done.stderr)
                self.assertIn(f"actual (index snapshot_sha256) {self.snapshot_sha256}", done.stderr)
                self.assertEqual(done.stdout, "")
        for sha256 in ("abc", self.snapshot_sha256 + "0", "g" * 64):
            with self.subTest(sha256):
                done = self.run_script(table(*ROWS), sha256)
                self.assertEqual(done.returncode, 2)
                self.assertIn("not 64 hex digits", done.stderr)

    def test_index_that_does_not_load_is_refused(self):
        done = self.run_script(table(*ROWS), index=self.tmp / "missing")
        self.assertEqual(done.returncode, 2)
        self.assertIn("manifest cannot be read", done.stderr)
        self.assertEqual(done.stdout, "")

    def test_bad_tables_are_refused(self):
        hit = "example-listed@1.0.1,hit,MAL-EXAMPLE-0001,listed_version"
        miss = "example-listed@1.0.0,not_hit,,"
        cases = {
            "empty file": ("", "line 0: the first line must be exactly"),
            "header only": (table(), "the table has no rows"),
            "no header": (table(hit, header=miss), "line 1: the first line must be exactly"),
            "header order": (
                table(hit, header="package,expected,match_kind,advisory_id"),
                "line 1: the first line must be exactly",
            ),
            "header with one more column": (
                table(hit + ",", header=HEADER + ",note"),
                "line 1: the first line must be exactly",
            ),
            "missing field": (table(hit, "example-listed@1.0.0,not_hit,"), "line 3: expected 4"),
            "one field too many": (table(miss + ","), "line 2: expected 4 fields"),
            "blank line": (table(hit, "", miss), "line 3: expected 4 fields"),
            "surrounding space": (table(" " + miss), "line 2: expected 4 fields without"),
            "no version": (table("example-listed,not_hit,,"), "line 2: package is not <npm"),
            "scoped name without version": (
                table("@example/scoped,not_hit,,"),
                "line 2: package is not <npm name>@<version>: '@example/scoped'",
            ),
            # Each would be looked up as a name no record has and pass as not_hit.
            "two @": (table("example-listed@@1.0.1,not_hit,,"), "line 2: package is not <npm"),
            "space in the name": (table("example listed@1.0.1,not_hit,,"), "line 2: package is"),
            "scope without a name": (table("@example@1.0.0,not_hit,,"), "line 2: package is"),
            "name with a leading dot": (table(".example@1.0.0,not_hit,,"), "line 2: package is"),
            "name over 214 characters": (table(f"{'e' * 215}@1.0.0,not_hit,,"), "line 2: package"),
            "empty version": (table("example-listed@,not_hit,,"), "line 2: Not a strict SemVer"),
            "version range": (table("example-listed@^1.0.1,not_hit,,"), "line 2: Not a strict"),
            "build metadata that is not SemVer": (
                table("example-listed@1.0.1+build_7,not_hit,,"),
                "line 2: Not a strict SemVer",
            ),
            "version that is not strict SemVer": (
                table(hit, "example-listed@01.0.0,not_hit,,"),
                "line 3: Not a strict SemVer",
            ),
            "unknown expected": (table("example-listed@1.0.0,miss,,"), "line 2: expected must"),
            "expected in upper case": (table(hit.replace("hit", "HIT")), "line 2: expected must"),
            "hit without advisory_id": (
                table("example-listed@1.0.1,hit,,listed_version"),
                "line 2: expected must be hit with advisory_id and match_kind",
            ),
            "hit without match_kind": (
                table("example-listed@1.0.1,hit,MAL-EXAMPLE-0001,"),
                "line 2: expected must",
            ),
            "unknown match_kind": (
                table("example-listed@1.0.1,hit,MAL-EXAMPLE-0001,listed"),
                "line 2: expected must",
            ),
            "not_hit with advisory_id": (
                table("example-listed@1.0.0,not_hit,MAL-EXAMPLE-0001,"),
                "line 2: expected must",
            ),
            "not_hit with match_kind": (
                table("example-listed@1.0.0,not_hit,,listed_version"),
                "line 2: expected must",
            ),
            "duplicate hit row": (table(hit, miss, hit), "line 4: duplicate or conflicting"),
            "duplicate not_hit row": (table(miss, miss), "line 3: duplicate or conflicting"),
            "same advisory, two kinds": (
                table(hit, hit.replace("listed_version", "affected_range")),
                "line 3: duplicate or conflicting row for 'example-listed@1.0.1'",
            ),
            "hit then not_hit": (
                table(hit, "example-listed@1.0.1,not_hit,,"),
                "line 3: duplicate or conflicting",
            ),
            "not_hit then hit": (
                table(miss, "example-listed@1.0.0,hit,MAL-EXAMPLE-0001,listed_version"),
                "line 3: duplicate or conflicting",
            ),
            "not UTF-8": (table(hit).encode() + "예시\n".encode("cp949"), "codec can't decode"),
            "unclosed quote": (table(hit, '"example-listed@1.0.0,not_hit,,'), "line 3: "),
        }
        for label, (text, message) in cases.items():
            with self.subTest(label):
                done = self.run_script(text)
                self.assertEqual(done.returncode, 2, done.stdout)
                self.assertIn(message, done.stderr)
                self.assertEqual(done.stdout, "")


if __name__ == "__main__":
    unittest.main()
