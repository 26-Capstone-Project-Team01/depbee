"""Known malicious index (KM-01): building from an OSV-shaped zip, loading, SemVer and matching.

Synthetic only: made-up package names (example-*, @example/*) and ids (MAL-EXAMPLE-*), no real
OSV record and no package code.
"""

import copy
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from depbee import known_malicious
from depbee.contracts import GuardError
from depbee.known_malicious import build_index, load, version_key

ROOT = Path(__file__).resolve().parents[1]
AS_OF = "2026-11-01T00:00:00Z"


def semver(*events):
    return {"type": "SEMVER", "events": [{kind: value} for kind, value in events]}


def record(advisory, name, versions=None, ranges=None, ecosystem="npm", **extra):
    affected = {"package": {"ecosystem": ecosystem, "name": name}}
    if versions is not None:
        affected["versions"] = versions
    if ranges is not None:
        affected["ranges"] = ranges
    return {"id": advisory, "affected": [affected], **extra}


def snapshot(records, extra=()):
    """An all.zip-shaped zip: one <id>.json per record, plus (file name, bytes) extras."""
    buffer = io.BytesIO()
    entries = [(f"{value['id']}.json", json.dumps(value)) for value in records] + list(extra)
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries:
            # A fixed time: the same entries give the same zip bytes (and snapshot_sha256).
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return buffer.getvalue()


RECORDS = [
    record("MAL-EXAMPLE-0001", "example-listed", ["1.0.1", "2.0.0"]),
    record("MAL-EXAMPLE-0002", "example-range", ranges=[semver(("introduced", "1.2.0"),
                                                               ("fixed", "1.2.5"))]),  # fmt: skip
    record("MAL-EXAMPLE-0003", "example-last", ranges=[semver(("introduced", "3.0.0"),
                                                              ("last_affected", "3.0.2"))]),  # fmt: skip
    record("MAL-EXAMPLE-0004", "example-pre", ranges=[semver(("introduced", "1.0.0-beta.1"),
                                                             ("last_affected", "1.0.0-beta.3"))]),  # fmt: skip
    # Not in version order: evaluated sorted, as OSV requires.
    record("MAL-EXAMPLE-0005", "example-unsorted", ranges=[semver(("fixed", "8.0.4"),
                                                                  ("introduced", "8.0.1"))]),  # fmt: skip
    record("MAL-EXAMPLE-0006", "example-all", ranges=[semver(("introduced", "0"))]),
    record("MAL-EXAMPLE-0007", "example-open", ranges=[semver(("introduced", "1.2.2"))]),
    # Versions, a bounded range and an all-versions range (the range policy decides).
    record("MAL-EXAMPLE-0008", "example-mixed", ["1.19.1", "1.19.2"], [
        semver(("introduced", "1.19.1"), ("last_affected", "1.19.2")),
        semver(("introduced", "0"))]),  # fmt: skip
    # Versions and an open "X and later" range.
    record("MAL-EXAMPLE-0009", "example-mixed-open", ["99.9.0", "99.9.1"],
           [semver(("introduced", "99.9.1"))]),  # fmt: skip
    record("MAL-EXAMPLE-0010", "example-security", ["0.0.1-security"]),
    record("MAL-EXAMPLE-0011", "example-security-all", ["0.0.1-security", "1.0.0"],
           [semver(("introduced", "0"))]),  # fmt: skip
    record("MAL-EXAMPLE-0012", "example-withdrawn", ["4.13.3"], withdrawn="2026-01-01T00:00:00Z"),
    record("GHSA-example-0001", "example-ghsa", ["3.3.6"]),
    record("MAL-EXAMPLE-0013", "@example/scoped", ["1.0.0"]),
    record("MAL-EXAMPLE-0014", "Example-Case", ["1.0.0"]),
    record("MAL-EXAMPLE-0020", "example-multi", ["2.0.0"]),
    record("MAL-EXAMPLE-0016", "example-multi", ranges=[semver(("introduced", "0"),
                                                               ("fixed", "3.0.0"))]),  # fmt: skip
    record("MAL-EXAMPLE-0017", "example-long", [f"1.0.{n}" for n in range(100)]),
    record("MAL-EXAMPLE-0018", "example-two-ranges", ranges=[semver(
        ("introduced", "1.0.0"), ("fixed", "1.0.2"), ("introduced", "2.0.0"), ("fixed", "2.0.1"))]),
]  # fmt: skip


class IndexDir:
    """Writes index.json and a manifest.json that matches it into a temporary folder."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.index_bytes, self.manifest_bytes, self.header = build_index(snapshot(RECORDS), AS_OF)
        self.dir = self.tmp / "km"
        self.write(self.index_bytes, self.manifest_bytes)
        mock.patch.object(known_malicious, "_last", None).start()
        self.addCleanup(mock.patch.stopall)

    def write(self, index, manifest=None):
        """index.json and, by default, the built manifest with this index's sha256."""
        self.dir.mkdir(exist_ok=True)
        (self.dir / "index.json").write_bytes(index)
        if manifest is None:
            built = json.loads(self.manifest_bytes)
            manifest = json.dumps({**built, "index_sha256": hashlib.sha256(index).hexdigest()})
            manifest = manifest.encode()
        (self.dir / "manifest.json").write_bytes(manifest)

    def body(self):
        return json.loads(self.index_bytes)


class SemverTests(unittest.TestCase):
    def test_spec_precedence_example(self):
        # SemVer 2.0 section 11.
        ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
                   "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]  # fmt: skip
        keys = [version_key(v) for v in ordered]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(set(keys)), len(keys))
        self.assertLess(version_key("1.0.0"), version_key("2.0.0"))
        self.assertLess(version_key("2.0.0"), version_key("2.1.0"))
        self.assertLess(version_key("2.1.0"), version_key("2.1.1"))
        self.assertLess(version_key("1.9.0"), version_key("1.10.0"))  # numeric, not text

    def test_build_metadata_is_ignored(self):
        self.assertEqual(version_key("1.0.0+build.1"), version_key("1.0.0"))
        self.assertEqual(version_key("1.0.0-rc.1+x"), version_key("1.0.0-rc.1"))

    def test_not_strict_semver(self):
        for bad in ("1.0", "01.0.0", "1.0.0-01", "1.0.0-", "1.0.0-a..b", "v1.0.0", "1.0.0+",
                    "١.0.0", "1.0.0 ", "", None, 1):  # fmt: skip
            with self.subTest(version=bad), self.assertRaises(GuardError):
                version_key(bad)


class BuildTests(unittest.TestCase):
    def test_kept_and_skipped_counts(self):
        odd = [
            record("MAL-EXAMPLE-0101", "example-eco", ranges=[{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}]}]),  # fmt: skip
            record("MAL-EXAMPLE-0102", "example-limit", ranges=[semver(("introduced", "0"),
                                                                       ("limit", "2.0.0"))]),  # fmt: skip
            record("MAL-EXAMPLE-0103", "example-badver", ["1.0", "1.0.1"]),
            record("MAL-EXAMPLE-0104", "example-badbound", ranges=[semver(("introduced", "v1.2.3"))]),
            record("MAL-EXAMPLE-0105", "example-noevents", ["1.0.0"], [{"type": "SEMVER", "events": []}]),
            record("MAL-EXAMPLE-0106", "example-unknown", ["1.0.0"], [semver(("introduced", "0"),
                                                                             ("broken", "1.0.0"))]),  # fmt: skip
            record("MAL-EXAMPLE-0107", "example-nointro", ["1.0.0"], [semver(("fixed", "1.0.0"))]),
            record("MAL-EXAMPLE-0108", "example-both", ["1.0.0"], [semver(
                ("introduced", "0"), ("fixed", "1.0.0"), ("last_affected", "2.0.0"))]),  # fmt: skip
            {"id": "MAL-EXAMPLE-0109", "affected": [
                {"package": {"ecosystem": "PyPI", "name": "example-py"}, "versions": ["1.0.0"]},
                {"package": {"ecosystem": "npm", "name": "example-npm"}, "versions": ["1.0.0"]}]},
            {"id": "MAL-EXAMPLE-0110", "affected": [
                {"package": {"ecosystem": "PyPI", "name": "example-py"}, "versions": ["1.0.0"]}]},
            {"id": "MAL-EXAMPLE-0199"},  # no affected
        ]  # fmt: skip
        extra = [("MAL-EXAMPLE-0111.json", b"{not json"),
                 ("MAL-EXAMPLE-0112.json", json.dumps(record("MAL-EXAMPLE-9999", "x", ["1.0.0"]))),
                 ("EXAMPLE-0001.json", b"{}"), ("README.txt", b"x"), ("sub/", b"")]  # fmt: skip
        index, manifest, header = build_index(snapshot(RECORDS + odd, extra), AS_OF)
        counts = header["counts"]
        self.assertEqual(counts["skipped_records"], {
            "withdrawn": 1, "not_mal": 2, "not_record": 2, "record_not_json": 1,
            "record_id_mismatch": 1, "affected_missing": 1, "nothing_to_match": 4,
        })  # fmt: skip
        self.assertEqual(counts["skipped_parts"], {
            "range_not_semver": 1, "range_limit_event": 1, "version_not_semver": 1,
            "range_bound_not_semver": 1, "range_without_events": 1, "range_unknown_event": 1,
            "range_without_introduced": 1, "range_fixed_and_last_affected": 1,
            "affected_not_npm": 2,
        })  # fmt: skip
        # RECORDS less the withdrawn and GHSA ones, plus 0103, 0105-0109 of the odd ones.
        self.assertEqual(counts["records"], len(RECORDS) - 2 + 6)
        body = json.loads(index)
        names = [name for name, _ in body["packages"]]
        self.assertEqual(names, sorted(names))
        self.assertNotIn("example-withdrawn", names)
        self.assertNotIn("example-ghsa", names)
        self.assertNotIn("example-py", names)
        self.assertEqual(counts["names"], len(names))
        packages = dict(body["packages"])
        self.assertEqual(packages["example-badver"], [["MAL-EXAMPLE-0103", ["1.0.1"], []]])
        self.assertEqual(packages["example-unsorted"],
                         [["MAL-EXAMPLE-0005", [], [["8.0.1", "<", "8.0.4"]]]])  # fmt: skip
        self.assertEqual(packages["example-multi"], [["MAL-EXAMPLE-0016", [], [["0", "<", "3.0.0"]]],
                                                     ["MAL-EXAMPLE-0020", ["2.0.0"], []]])  # fmt: skip
        # The 0.0.1-security placeholder stays in the record (it is never matched as a query).
        self.assertEqual(
            packages["example-security"], [["MAL-EXAMPLE-0010", ["0.0.1-security"], []]]
        )
        self.assertEqual(body["counts"], counts)
        man = json.loads(manifest)
        self.assertEqual(man["index_sha256"], hashlib.sha256(index).hexdigest())
        self.assertEqual(man["snapshot_sha256"], header["snapshot_sha256"])
        self.assertEqual((man["source"], man["list_as_of"]), ("OSV npm MAL", AS_OF))

    def test_same_input_same_bytes(self):
        first = build_index(snapshot(RECORDS), AS_OF)
        second = build_index(snapshot(RECORDS), AS_OF)
        self.assertEqual(first[:2], second[:2])
        # Another zip order is another snapshot (its sha256) but the same entries.
        shuffled = build_index(snapshot(list(reversed(RECORDS))), AS_OF)
        self.assertEqual(json.loads(shuffled[0])["packages"], json.loads(first[0])["packages"])
        self.assertTrue(first[0].endswith(b"\n") and b"\r" not in first[0] and first[0].isascii())

    def test_as_of_must_be_utc_z(self):
        for bad in ("2026-11-01T00:00:00", "2026-11-01 00:00:00Z", "2026-13-01T00:00:00Z",
                    "2026-11-01T00:00:00+00:00", "", "2026-11-01"):  # fmt: skip
            with self.subTest(as_of=bad), self.assertRaises(GuardError):
                build_index(snapshot(RECORDS), bad)
        build_index(snapshot(RECORDS), "2026-11-01T00:00:00.123456Z")

    def test_limits_and_not_a_zip(self):
        with self.assertRaises(GuardError):
            build_index(b"not a zip", AS_OF)
        with mock.patch.object(known_malicious, "MAX_RECORD_BYTES", 10), \
                self.assertRaisesRegex(GuardError, "exceeds"):  # fmt: skip
            build_index(snapshot(RECORDS), AS_OF)
        with mock.patch.object(known_malicious, "MAX_SNAPSHOT_ENTRIES", 2), \
                self.assertRaisesRegex(GuardError, "entries"):  # fmt: skip
            build_index(snapshot(RECORDS), AS_OF)
        with mock.patch.object(known_malicious, "MAX_SNAPSHOT_UNPACKED", 10), \
                self.assertRaisesRegex(GuardError, "unpacks"):  # fmt: skip
            build_index(snapshot(RECORDS), AS_OF)

    def test_script_writes_once_and_never_overwrites(self):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        zipped, out = tmp / "all.zip", tmp / "out"
        zipped.write_bytes(snapshot(RECORDS))
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONIOENCODING": "utf-8"}
        script = [sys.executable, str(ROOT / "scripts" / "build_known_malicious_index.py"),
                  str(zipped), str(out)]  # fmt: skip

        def run(*args):
            return subprocess.run([*script, *args], capture_output=True, text=True, env=env,
                                  timeout=120)  # fmt: skip

        bad = run("--as-of", "2026-11-01T00:00:00")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("list_as_of", bad.stderr)
        self.assertFalse(out.exists())
        done = run("--as-of", AS_OF)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["counts"]["records"], len(RECORDS) - 2)
        written = {name: (out / name).read_bytes() for name in ("index.json", "manifest.json")}
        self.assertEqual(written["index.json"], build_index(snapshot(RECORDS), AS_OF)[0])
        with mock.patch.object(known_malicious, "_last", None):
            self.assertEqual(
                load(out).list_sha256, hashlib.sha256(written["index.json"]).hexdigest()
            )
        again = run("--as-of", AS_OF)
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("Refusing to overwrite", again.stderr)
        self.assertEqual({name: (out / name).read_bytes() for name in written}, written)


class LoadTests(IndexDir, unittest.TestCase):
    def test_loads_identity(self):
        index = load(self.dir)
        self.assertEqual(index.source, "OSV npm MAL")
        self.assertEqual(index.list_as_of, AS_OF)
        self.assertEqual(index.list_sha256, hashlib.sha256(self.index_bytes).hexdigest())
        self.assertEqual(index.snapshot_sha256, hashlib.sha256(snapshot(RECORDS)).hexdigest())

    def assert_refused(self, message=""):
        with mock.patch.object(known_malicious, "_last", None), \
                self.assertRaisesRegex(GuardError, message):  # fmt: skip
            load(self.dir)

    def test_missing_folder_or_file(self):
        with self.assertRaisesRegex(GuardError, "manifest cannot be read"):
            load(self.tmp / "none")
        (self.dir / "index.json").unlink()
        self.assert_refused("cannot be read")

    def test_hash_mismatch(self):
        (self.dir / "index.json").write_bytes(self.index_bytes.replace(b"1.0.1", b"1.0.3"))
        self.assert_refused("SHA-256")

    def test_copy_mismatch(self):
        manifest = json.loads(self.manifest_bytes)
        for key, value in (("source", "OTHER"), ("list_as_of", "2026-11-02T00:00:00Z"),
                           ("snapshot_sha256", "0" * 64)):  # fmt: skip
            with self.subTest(key=key):
                self.write(self.index_bytes, json.dumps({**manifest, key: value}).encode())
                self.assert_refused(f"{key} differs")

    def test_duplicate_keys(self):
        raw = self.manifest_bytes.decode()
        self.write(self.index_bytes, raw.replace('{"format"', '{"format":"x","format"', 1).encode())
        self.assert_refused("Duplicate JSON key")
        self.write(self.index_bytes.replace(b'{"counts"', b'{"source":"x","counts"', 1))
        self.assert_refused("Duplicate JSON key")

    def test_format_and_version(self):
        for key, value in (("format", "other"), ("format_version", 2), ("format_version", "1"),
                           ("format_version", True)):  # fmt: skip
            with self.subTest(key=key, value=value):
                self.write(known_malicious._dump({**self.body(), key: value}))
                self.assert_refused("format")
        manifest = json.loads(self.manifest_bytes)
        self.write(self.index_bytes, json.dumps({**manifest, "format_version": 2}).encode())
        self.assert_refused("format_version")
        self.write(self.index_bytes, json.dumps({**manifest, "extra": 1}).encode())
        self.assert_refused("exactly the keys")

    def test_bad_types(self):
        def packages(change):
            body = self.body()
            change(body["packages"])
            return body

        bodies = {
            "not a list": {**self.body(), "packages": {}},
            "pair": packages(lambda p: p[0].append(1)),
            "name": packages(lambda p: p[0].__setitem__(0, 1)),
            "unsorted names": packages(lambda p: p.reverse()),
            "duplicate name": packages(lambda p: p.append(copy.deepcopy(p[-1]))),
            "no records": packages(lambda p: p[0].__setitem__(1, [])),
            "record": packages(lambda p: p[0][1][0].append("x")),
            "versions": packages(lambda p: p[0][1][0].__setitem__(1, "1.0.0")),
            "version": packages(lambda p: p[0][1][0].__setitem__(1, ["1.0"])),
            "range": packages(lambda p: p[0][1][0].__setitem__(2, [["0", "<"]])),
            "upper": packages(lambda p: p[0][1][0].__setitem__(2, [["0", ">", "1.0.0"]])),
            "high": packages(lambda p: p[0][1][0].__setitem__(2, [["0", "<", "0"]])),
            "open": packages(lambda p: p[0][1][0].__setitem__(2, [["0", None, "1.0.0"]])),
            "empty record": packages(lambda p: p[0][1].__setitem__(0, [p[0][1][0][0], [], []])),
            "counts": {**self.body(), "counts": {"records": 1}},
            "count names": {**self.body(), "counts": {**self.body()["counts"], "names": 1}},
        }  # fmt: skip
        for label, body in bodies.items():
            with self.subTest(label=label):
                self.write(known_malicious._dump(body))
                self.assert_refused("Known malicious index")
        self.write(b"[]")
        self.assert_refused("not a JSON object")
        self.write(b"{")
        self.assert_refused("invalid JSON")

    def test_size_limit(self):
        with mock.patch.object(known_malicious, "MAX_INDEX_BYTES", len(self.index_bytes) - 1):
            self.assert_refused("exceeds")

    def test_list_as_of_format(self):
        for bad in ("2026-11-01", "2026-13-01T00:00:00Z", 1):
            with self.subTest(list_as_of=bad):
                self.write(known_malicious._dump({**self.body(), "list_as_of": bad}))
                self.assert_refused("list_as_of")

    def test_checked_index_is_reused_only_for_the_same_files(self):
        first = load(self.dir)
        self.assertIs(load(self.dir), first)
        other = self.tmp / "copy"
        other.mkdir()
        for name in ("index.json", "manifest.json"):
            (other / name).write_bytes((self.dir / name).read_bytes())
        self.assertIsNot(load(other), first)
        self.write(self.index_bytes.replace(b"1.0.1", b"1.0.3"))  # same size, new hash
        self.assertIn("1.0.3", load(self.dir).match("example-listed", "1.0.3")[0]["affected"])
        (self.dir / "index.json").write_bytes(b"{}")
        with self.assertRaisesRegex(GuardError, "SHA-256"):
            load(self.dir)


def hit(advisory, kind, affected):
    return {"advisory_id": advisory, "match_kind": kind, "affected": affected}


class MatchTests(IndexDir, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.index = load(self.dir)

    def ids(self, name, version):
        return [(m["advisory_id"], m["match_kind"]) for m in self.index.match(name, version)]

    def test_listed_versions(self):
        self.assertEqual(self.index.match("example-listed", "1.0.1"),
                         [hit("MAL-EXAMPLE-0001", "listed_version", "1.0.1, 2.0.0")])  # fmt: skip
        self.assertEqual(
            self.ids("example-listed", "2.0.0"), [("MAL-EXAMPLE-0001", "listed_version")]
        )
        for other in ("1.0.0", "1.0.2", "2.0.1", "2.0.0-rc.1"):
            with self.subTest(version=other):
                self.assertEqual(self.index.match("example-listed", other), [])

    def test_bounded_ranges(self):
        range_hit = [hit("MAL-EXAMPLE-0002", "affected_range", ">=1.2.0 <1.2.5")]
        cases = {"1.1.9": [], "1.2.0": range_hit, "1.2.4": range_hit, "1.2.5-rc.1": range_hit,
                 "1.2.5": [], "1.3.0": [], "1.2.0-rc.1": []}  # fmt: skip
        for version, expected in cases.items():
            with self.subTest(version=version):
                self.assertEqual(self.index.match("example-range", version), expected)
        last = [hit("MAL-EXAMPLE-0003", "affected_range", ">=3.0.0 <=3.0.2")]
        for version, expected in {"2.9.9": [], "3.0.0": last, "3.0.2": last, "3.0.3": [],
                                  "3.0.3-alpha": []}.items():  # fmt: skip
            with self.subTest(version=version):
                self.assertEqual(self.index.match("example-last", version), expected)
        two = {"1.0.1": ">=1.0.0 <1.0.2", "1.0.2": None, "2.0.0": ">=2.0.0 <2.0.1", "1.5.0": None}
        for version, affected in two.items():
            with self.subTest(version=version):
                expected = [hit("MAL-EXAMPLE-0018", "affected_range", affected)] if affected else []
                self.assertEqual(self.index.match("example-two-ranges", version), expected)

    def test_prerelease_bounds_and_queries(self):
        pre = [hit("MAL-EXAMPLE-0004", "affected_range", ">=1.0.0-beta.1 <=1.0.0-beta.3")]
        cases = {"1.0.0-alpha.9": [], "1.0.0-beta.1": pre, "1.0.0-beta.2": pre,
                 "1.0.0-beta.3": pre, "1.0.0-beta.11": [], "1.0.0-rc.1": [], "1.0.0": []}  # fmt: skip
        for version, expected in cases.items():
            with self.subTest(version=version):
                self.assertEqual(self.index.match("example-pre", version), expected)

    def test_unsorted_events(self):
        self.assertEqual(self.ids("example-unsorted", "8.0.2"),
                         [("MAL-EXAMPLE-0005", "affected_range")])  # fmt: skip
        self.assertEqual(self.ids("example-unsorted", "8.0.4"), [])

    def test_all_versions_and_open_ranges(self):
        for version in ("0.0.0", "0.0.0-0", "1.0.0", "999.0.0-x"):
            with self.subTest(version=version):
                self.assertEqual(self.index.match("example-all", version),
                                 [hit("MAL-EXAMPLE-0006", "affected_range", ">=0")])  # fmt: skip
        self.assertEqual(self.index.match("example-open", "1.2.1"), [])
        for version in ("1.2.2", "1.3.0", "9.0.0"):
            with self.subTest(version=version):
                self.assertEqual(self.index.match("example-open", version),
                                 [hit("MAL-EXAMPLE-0007", "affected_range", ">=1.2.2")])  # fmt: skip

    # The range policy (known_malicious._match_ranges, decided 2026-11-17; revisit with the fixed
    # verdict table): change this table with the function. Records with versions use those and
    # bounded ranges; unbounded ranges only count for records without versions.
    POLICY = [
        ("example-mixed", "1.19.1", ("MAL-EXAMPLE-0008", "listed_version")),
        ("example-mixed", "1.19.2", ("MAL-EXAMPLE-0008", "listed_version")),
        ("example-mixed", "1.19.0", None),  # all-versions range ignored: the record lists versions
        ("example-mixed", "1.20.0", None),
        ("example-mixed-open", "99.9.1", ("MAL-EXAMPLE-0009", "listed_version")),
        ("example-mixed-open", "99.9.2", None),  # open range ignored: the record lists versions
        ("example-security-all", "1.0.0", ("MAL-EXAMPLE-0011", "listed_version")),
        ("example-security-all", "2.0.0", None),
        ("example-all", "3.0.0", ("MAL-EXAMPLE-0006", "affected_range")),  # no versions listed
        ("example-open", "1.2.3", ("MAL-EXAMPLE-0007", "affected_range")),
    ]

    def test_range_policy_table(self):
        for name, version, expected in self.POLICY:
            with self.subTest(name=name, version=version):
                self.assertEqual(self.ids(name, version), [expected] if expected else [])

    def test_security_placeholder_never_matches(self):
        for name in ("example-security", "example-security-all", "example-all"):
            with self.subTest(name=name):
                self.assertEqual(self.index.match(name, "0.0.1-security"), [])
                self.assertEqual(self.index.match(name, "0.0.1-security+x"), [])
        self.assertEqual(self.ids("example-all", "0.0.1"), [("MAL-EXAMPLE-0006", "affected_range")])

    def test_left_out_records_and_names(self):
        self.assertEqual(self.index.match("example-withdrawn", "4.13.3"), [])
        self.assertEqual(self.index.match("example-ghsa", "3.3.6"), [])
        self.assertEqual(self.index.match("example-unknown-name", "1.0.0"), [])

    def test_exact_names(self):
        self.assertEqual(
            self.ids("@example/scoped", "1.0.0"), [("MAL-EXAMPLE-0013", "listed_version")]
        )
        self.assertEqual(self.index.match("example/scoped", "1.0.0"), [])
        self.assertEqual(
            self.ids("Example-Case", "1.0.0"), [("MAL-EXAMPLE-0014", "listed_version")]
        )
        self.assertEqual(self.index.match("example-case", "1.0.0"), [])
        self.assertEqual(self.index.match("EXAMPLE-LISTED", "1.0.1"), [])

    def test_build_metadata_in_the_query(self):
        self.assertEqual(self.ids("example-listed", "1.0.1+build.5"),
                         [("MAL-EXAMPLE-0001", "listed_version")])  # fmt: skip
        self.assertEqual(
            self.ids("example-range", "1.2.4+x"), [("MAL-EXAMPLE-0002", "affected_range")]
        )

    def test_not_strict_query_versions_raise(self):
        for bad in ("01.0.1", "1.0", "1.0.1-", "1.0.1-a..b", "١.0.1", "v1.0.1", "", None):
            with self.subTest(version=bad), self.assertRaises(GuardError):
                self.index.match("example-listed", bad)
        with self.assertRaises(GuardError):
            self.index.match("example-unknown-name", "1.0")  # even for an unknown name

    def test_several_records_in_id_order(self):
        self.assertEqual(self.index.match("example-multi", "2.0.0"), [
            hit("MAL-EXAMPLE-0016", "affected_range", ">=0 <3.0.0"),
            hit("MAL-EXAMPLE-0020", "listed_version", "2.0.0")])  # fmt: skip
        self.assertEqual(
            self.ids("example-multi", "2.5.0"), [("MAL-EXAMPLE-0016", "affected_range")]
        )

    def test_long_affected_is_cut(self):
        (found,) = self.index.match("example-long", "1.0.5")
        self.assertEqual(len(found["affected"]), 256)
        self.assertTrue(found["affected"].startswith("1.0.0, 1.0.1, "))
        self.assertTrue(found["affected"].endswith("..."))
        full = ", ".join(f"1.0.{n}" for n in range(100))
        self.assertEqual(found["affected"], full[:253] + "...")

    def test_baseline_records(self):
        # D-16: listed versions and bounded ranges only.
        cases = [
            ("example-listed", "2.0.0", ["MAL-EXAMPLE-0001"]),
            ("example-listed", "1.5.0", []),
            ("example-range", "1.2.4", ["MAL-EXAMPLE-0002"]),
            ("example-range", "1.2.5", []),
            ("example-last", "3.0.2", ["MAL-EXAMPLE-0003"]),
            ("example-all", "1.0.0", []),  # all versions: never used here
            ("example-open", "1.3.0", []),  # open range: never used here
            ("example-mixed", "1.19.2", ["MAL-EXAMPLE-0008"]),
            ("example-mixed", "1.18.0", []),
            ("example-multi", "2.0.0", ["MAL-EXAMPLE-0016", "MAL-EXAMPLE-0020"]),
            ("example-withdrawn", "4.13.3", []),
            ("example-ghsa", "3.3.6", []),
        ]
        for name, version, expected in cases:
            with self.subTest(name=name, version=version):
                self.assertEqual(self.index.baseline_records(name, version), expected)


# Past Python's default limit for converting a digit string to int (4300 digits).
LONG = "9" * 5000


def run_build_script(zipped, out, as_of=AS_OF):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONIOENCODING": "utf-8"}
    script = ROOT / "scripts" / "build_known_malicious_index.py"
    return subprocess.run([sys.executable, str(script), str(zipped), str(out), "--as-of", as_of],
                          capture_output=True, text=True, env=env, timeout=120)  # fmt: skip


class MalformedRecordTests(unittest.TestCase):
    """REV-KM01-R1 F1 and F3: unusable version lists and long numbers while building."""

    def load(self, records, extra=()):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        index, manifest, header = build_index(snapshot(records, extra), AS_OF)
        (tmp / "index.json").write_bytes(index)
        (tmp / "manifest.json").write_bytes(manifest)
        with mock.patch.object(known_malicious, "_last", None):
            return load(tmp), header["counts"]

    def test_a_list_without_valid_versions_never_turns_on_unbounded_ranges(self):
        records = [
            record("MAL-EXAMPLE-9001", "example-invalid-list", ["1.0"],
                   [semver(("introduced", "0"))]),
            record("MAL-EXAMPLE-9002", "example-invalid-open", ["01.0.0", "v2.0.0"],
                   [semver(("introduced", "1.0.0"))]),
            record("MAL-EXAMPLE-9003", "example-versions-not-list", "1.0.0",
                   [semver(("introduced", "0"))]),
            record("MAL-EXAMPLE-9004", "example-partly-valid", ["1.0", "1.0.1"],
                   [semver(("introduced", "0"))]),
            record("MAL-EXAMPLE-9005", "example-empty-list", [], [semver(("introduced", "0"))]),
        ]  # fmt: skip
        index, counts = self.load(records)
        for name in ("example-invalid-list", "example-invalid-open", "example-versions-not-list"):
            for version in ("0.0.1", "1.0.0", "9.0.0"):
                with self.subTest(name=name, version=version):
                    self.assertEqual(index.match(name, version), [])
        # One valid version left: still a record with a list (bounded ranges only).
        self.assertEqual([m["match_kind"] for m in index.match("example-partly-valid", "1.0.1")],
                         ["listed_version"])  # fmt: skip
        self.assertEqual(index.match("example-partly-valid", "9.0.0"), [])
        # An empty list lists nothing, as a record without versions.
        self.assertEqual([m["affected"] for m in index.match("example-empty-list", "9.0.0")],
                         [">=0"])  # fmt: skip
        self.assertEqual(counts["skipped_parts"], {
            "version_not_semver": 4, "versions_all_invalid": 2, "versions_not_list": 1})  # fmt: skip
        self.assertEqual(counts["skipped_records"], {"nothing_to_match": 3})
        self.assertEqual(counts["records"], 2)

    def test_long_numbers_in_versions_and_bounds(self):
        seventeen = "12345678901234567"
        records = [
            record("MAL-EXAMPLE-9101", "example-long-version", [f"{seventeen}.0.0", "1.0.0"]),
            record("MAL-EXAMPLE-9102", "example-long-bound",
                   ranges=[semver(("introduced", f"1.0.0-{seventeen}"))]),
            record("MAL-EXAMPLE-9103", "example-huge-version", [f"{LONG}.0.0", "2.0.0"]),
            record("MAL-EXAMPLE-9104", "example-unsafe", ["9007199254740992.0.0", "3.0.0"]),
        ]  # fmt: skip
        index, counts = self.load(records)
        # Only major, minor and patch are limited: the long prerelease bound stays (R2-1).
        self.assertEqual(counts["skipped_parts"], {"version_not_semver": 3})
        self.assertEqual(counts["skipped_records"], {})
        self.assertEqual(counts["records"], 4)
        # As npm semver: at most 16 digits and Number.MAX_SAFE_INTEGER for major, minor, patch.
        for bad in (f"{seventeen}.0.0", f"{LONG}.0.0", "9007199254740992.0.0",
                    f"1.{seventeen}.0", f"1.0.{LONG}"):  # fmt: skip
            with self.subTest(version=bad[:40]):
                with self.assertRaises(GuardError):
                    version_key(bad)
                with self.assertRaises(GuardError):
                    index.match("example-long-version", bad)
        version_key("9007199254740991.0.0")
        self.assertEqual(index.match("example-long-version", "9007199254740991.0.0"), [])
        self.assertEqual(index.match("example-long-bound", f"1.0.0-{LONG}")[0]["advisory_id"],
                         "MAL-EXAMPLE-9102")  # fmt: skip

    def test_long_json_integers_in_a_record(self):
        raw = json.dumps(record("MAL-EXAMPLE-9105", "example-x", ["1.0.0"]))
        raw = raw[:-1] + ', "database_specific": {"n": ' + LONG + "}}"
        _, counts = self.load([record("MAL-EXAMPLE-9106", "example-y", ["1.0.0"])],
                              [("MAL-EXAMPLE-9105.json", raw)])  # fmt: skip
        self.assertEqual(counts["skipped_records"], {"record_not_json": 1})
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        zipped = tmp / "all.zip"
        zipped.write_bytes(snapshot([record("MAL-EXAMPLE-9103", "example-huge", [f"{LONG}.0.0"])],
                                    [("MAL-EXAMPLE-9105.json", raw)]))  # fmt: skip
        done = run_build_script(zipped, tmp / "out")
        self.assertNotIn("Traceback", done.stderr)
        self.assertEqual(done.returncode, 0, done.stderr[-300:])
        counts = json.loads(done.stdout)["counts"]
        self.assertEqual(counts["skipped_records"], {"record_not_json": 1, "nothing_to_match": 1})


SEVENTEEN = "12345678901234567"


class LargePrereleaseTests(unittest.TestCase):
    """REV-KM01-R2 R2-1: as npm semver, a numeric prerelease identifier has no size limit (only
    major, minor and patch do) and compares by value, without int()."""

    load = MalformedRecordTests.load

    def test_order_and_limits(self):
        ordered = ["1.0.0-0", "1.0.0-9", "1.0.0-10", "1.0.0-9007199254740991",
                   "1.0.0-9007199254740992", f"1.0.0-{SEVENTEEN}", "1.0.0-12345678901234568",
                   f"1.0.0-{LONG}", f"1.0.0-1{LONG}", "1.0.0-alpha", "1.0.0-alpha.9",
                   f"1.0.0-alpha.{LONG}", "1.0.0-alpha.beta", "1.0.0"]  # fmt: skip
        keys = [version_key(v) for v in ordered]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(set(keys)), len(keys))
        self.assertEqual(version_key(f"1.0.0-{SEVENTEEN}+b"), version_key(f"1.0.0-{SEVENTEEN}"))
        for bad in (f"{SEVENTEEN}.0.0", "9007199254740992.0.0", f"1.{SEVENTEEN}.0",
                    f"1.0.{LONG}", f"1.0.0-0{SEVENTEEN}"):  # fmt: skip
            with self.subTest(version=bad[:40]), self.assertRaises(GuardError):
                version_key(bad)

    def test_matches(self):
        records = [
            record("MAL-EXAMPLE-9201", "example-large-pre", ranges=[semver(("introduced", "0"))]),
            record("MAL-EXAMPLE-9202", "example-large-listed",
                   [f"1.0.0-{SEVENTEEN}", f"1.0.0-{LONG}"]),
            record("MAL-EXAMPLE-9203", "example-large-range", ranges=[semver(
                ("introduced", "1.0.0-9007199254740992"), ("fixed", "1.0.0-12345678901234568"))]),
        ]  # fmt: skip
        index, counts = self.load(records)
        self.assertEqual((counts["records"], counts["skipped_parts"]), (3, {}))

        def kinds(name, version):
            return [(m["advisory_id"], m["match_kind"]) for m in index.match(name, version)]

        for version in ("1.0.0-9007199254740992", f"1.0.0-{SEVENTEEN}", f"1.0.0-{LONG}"):
            with self.subTest(version=version[:40]):
                self.assertEqual(kinds("example-large-pre", version),
                                 [("MAL-EXAMPLE-9201", "affected_range")])  # fmt: skip
        listed = [("MAL-EXAMPLE-9202", "listed_version")]
        cases = {f"1.0.0-{SEVENTEEN}": listed, f"1.0.0-{SEVENTEEN}+b": listed,
                 f"1.0.0-{LONG}": listed, "1.0.0-12345678901234568": [],
                 f"1.0.0-1{LONG}": [], "1.0.0": []}  # fmt: skip
        for version, expected in cases.items():
            with self.subTest(version=version[:40]):
                self.assertEqual(kinds("example-large-listed", version), expected)
                self.assertEqual(index.baseline_records("example-large-listed", version),
                                 [m[0] for m in expected])  # fmt: skip
        inside = [("MAL-EXAMPLE-9203", "affected_range")]
        cases = {"1.0.0-9007199254740991": [], "1.0.0-9007199254740992": inside,
                 f"1.0.0-{SEVENTEEN}": inside, "1.0.0-12345678901234568": [],
                 f"1.0.0-{LONG}": [], "1.0.0-alpha": []}  # fmt: skip
        for version, expected in cases.items():
            with self.subTest(version=version[:40]):
                self.assertEqual(kinds("example-large-range", version), expected)


class MemoRaceTests(IndexDir, unittest.TestCase):
    """REV-KM01-R1 F2: the checked index A is returned even if another call replaces the memo
    with index B right after A's key was compared (made deterministic with a key whose
    comparison does the replacement)."""

    def test_the_compared_entry_is_the_returned_one(self):
        other = self.tmp / "other"
        other.mkdir()
        index_b, manifest_b, _ = build_index(snapshot(RECORDS[:3]), AS_OF)
        (other / "index.json").write_bytes(index_b)
        (other / "manifest.json").write_bytes(manifest_b)
        first = load(self.dir)
        key_a = known_malicious._last[0]
        second = load(other)
        key_b = known_malicious._last[0]
        self.assertIsNot(first, second)

        class Replaced(tuple):
            """key_a, but comparing it stores B as another thread's load() would."""

            def __eq__(self, other):
                known_malicious._last = (key_b, second)
                return tuple(self) == other

            __hash__ = tuple.__hash__

        known_malicious._last = (Replaced(key_a), first)
        self.assertIs(load(self.dir), first)
        self.assertIs(known_malicious._last[1], second)  # the replacement did happen


def patch_headers(data, offsets):
    """data with {(signature, field offset): (struct format, value)} set in every header of that
    signature (local b"PK\\x03\\x04" or central b"PK\\x01\\x02")."""
    data = bytearray(data)
    for (signature, offset), (fmt, value) in offsets.items():
        start = data.find(signature)
        while start != -1:
            struct.pack_into(fmt, data, start + offset, value)
            start = data.find(signature, start + 4)
    return bytes(data)


def zip64(data, dirsize=None):
    """The same zip with a ZIP64 end record and locator, as large archives (and OSV's) have."""
    end = data.rindex(b"PK\x05\x06")
    _, _, _, this_disk, total, size, offset, _ = struct.unpack("<4s4H2LH", data[end : end + 22])
    record = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, this_disk, total,
                         size if dirsize is None else dirsize, offset)  # fmt: skip
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, end, 1)
    eocd = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    return data[:end] + record + locator + eocd


class ZipBoundaryTests(unittest.TestCase):
    """REV-KM01-R1 F4 and F5: zipfile errors are GuardError, and the central directory is
    checked before zipfile builds an entry for each of its records."""

    def setUp(self):
        self.zipped = snapshot(RECORDS[:3])

    def test_encrypted_unsupported_and_damaged_entries(self):
        cases = {
            "encrypted": patch_headers(self.zipped, {(b"PK\x03\x04", 6): ("<H", 1),
                                                     (b"PK\x01\x02", 8): ("<H", 1)}),
            "unsupported version": patch_headers(self.zipped, {(b"PK\x01\x02", 6): ("<H", 99)}),
            "unsupported method": patch_headers(self.zipped, {(b"PK\x03\x04", 8): ("<H", 99),
                                                              (b"PK\x01\x02", 10): ("<H", 99)}),
        }  # fmt: skip
        damaged = bytearray(self.zipped)
        first = damaged.find(b"PK\x03\x04")
        name_length, extra_length = struct.unpack_from("<2H", damaged, first + 26)
        data_start = first + 30 + name_length + extra_length
        damaged[data_start : data_start + 8] = b"\xff" * 8
        cases["damaged stream"] = bytes(damaged)
        for label, data in cases.items():
            with self.subTest(label), self.assertRaises(GuardError):
                build_index(data, AS_OF)

    def test_script_fails_without_a_traceback(self):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        zipped = tmp / "all.zip"
        zipped.write_bytes(patch_headers(self.zipped, {(b"PK\x03\x04", 6): ("<H", 1),
                                                       (b"PK\x01\x02", 8): ("<H", 1)}))  # fmt: skip
        done = run_build_script(zipped, tmp / "out")
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn("Traceback", done.stderr)
        self.assertIn("encrypted", done.stderr)
        self.assertFalse((tmp / "out").exists())

    def test_zip64_trailer_is_read_as_zipfile_reads_it(self):
        plain = json.loads(build_index(self.zipped, AS_OF)[0])
        wide = json.loads(build_index(zip64(self.zipped), AS_OF)[0])
        self.assertEqual(wide["packages"], plain["packages"])

    def test_central_directory_is_checked_before_zipfile_reads_it(self):
        refuse = mock.patch.object(known_malicious.zipfile, "ZipFile",
                                   side_effect=AssertionError("zipfile was called"))  # fmt: skip
        size = len(self.zipped) - self.zipped.index(b"PK\x01\x02") - 22
        cases = [
            ("central directory bytes", self.zipped, "MAX_CENTRAL_DIRECTORY_BYTES", size - 1),
            ("ZIP64 central directory bytes", zip64(self.zipped, dirsize=2**40),
             "MAX_CENTRAL_DIRECTORY_BYTES", 64 * 1024 * 1024),
            ("declared entries", self.zipped, "MAX_SNAPSHOT_ENTRIES", 2),
            ("ZIP64 declared entries", zip64(self.zipped), "MAX_SNAPSHOT_ENTRIES", 2),
            ("no end record", self.zipped[:-22], "MAX_SNAPSHOT_ENTRIES", 2_000_000),
        ]  # fmt: skip
        for label, data, limit, value in cases:
            with self.subTest(label), refuse, \
                    mock.patch.object(known_malicious, limit, value, create=True), \
                    self.assertRaises(GuardError):  # fmt: skip
                build_index(data, AS_OF)
        with mock.patch.object(known_malicious, "MAX_CENTRAL_DIRECTORY_BYTES", size, create=True):
            build_index(self.zipped, AS_OF)  # exactly at the limit


class LongIntegerLoadTests(IndexDir, unittest.TestCase):
    """REV-KM01-R1 F3: long JSON integers in the index files are GuardError, not ValueError."""

    def test_long_integers(self):
        long = b'"format_version":' + LONG.encode()
        manifest = self.manifest_bytes.replace(b'"format_version":1', long)
        cases = {
            "manifest": (self.index_bytes, manifest),
            "index": (self.index_bytes.replace(b'"format_version":1', long), None),
        }
        for label, (index, manifest) in cases.items():
            with self.subTest(label), mock.patch.object(known_malicious, "_last", None):
                self.write(index, manifest)
                with self.assertRaises(GuardError):
                    load(self.dir)


if __name__ == "__main__":
    unittest.main()
