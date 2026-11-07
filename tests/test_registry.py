"""Registry downloads (PR #7 follow-ups): URLs, redirects, size and time limits, integrity, unpacking.

No network: analysis.registry._open is replaced by FakeRegistry. Tarballs are built here from a
few synthetic bytes; nothing in them is executed.
"""

import base64
import contextlib
import email.message
import gzip
import hashlib
import http.client
import io
import json
import tarfile
import unittest
import urllib.error
import urllib.request
import urllib.response
from unittest import mock

from test_workflow import Fixture

from depbee.analysis import registry
from depbee.analysis.registry import RegistryError

SECRET = "synthetic-secret-3f9c"  # a marker in refused URLs, not a real credential


def tgz(files, *, symlink=None):
    """A deterministic .tgz of {member name: bytes}; symlink=(name, target) adds a link."""
    links = [(symlink[0], tarfile.SYMTYPE, symlink[1])] if symlink else []
    return linked_tgz(*files.items(), *links)


def linked_tgz(*entries):
    """A deterministic .tgz of entries in order, names may repeat: (name, bytes) is a file and
    (name, tarfile.SYMTYPE or tarfile.LNKTYPE, link name) a link."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, *rest in entries:
            info = tarfile.TarInfo(name)
            if len(rest) == 2:
                info.type, info.linkname = rest
                archive.addfile(info)
            else:
                info.size, info.mtime = len(rest[0]), 0
                archive.addfile(info, io.BytesIO(rest[0]))
    return gzip.compress(raw.getvalue(), mtime=0)


def package_tgz(name, version):
    manifest = json.dumps({"name": name, "version": version}).encode()
    return tgz({"package/package.json": manifest, "package/index.js": b"module.exports = 1;\n"})


def sri(data, algorithm="sha512"):
    return f"{algorithm}-{base64.b64encode(hashlib.new(algorithm, data).digest()).decode()}"


def tarball_url(name, version):
    return f"https://registry.npmjs.org/{name}/-/{name.rpartition('/')[2]}-{version}.tgz"


class Response(io.BytesIO):
    def __init__(self, data, url, headers=None):
        super().__init__(data)
        self.url, self.headers = url, headers or {}

    def geturl(self):
        return self.url


class FakeRegistry:
    """Stands in for analysis.registry._open: serves files (bytes, or a prepared Response) by URL
    and records each request."""

    def __init__(self, files=None):
        self.files, self.opened = dict(files or {}), []

    def __call__(self, url):
        self.opened.append(url)
        if url not in self.files:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        served = self.files[url]
        return served if isinstance(served, Response) else Response(served, url)


def https_stand_in(served):
    """Replaces urllib's HTTPS connection (HTTPSHandler.https_open), so that the real opener,
    redirect handler and error processing run without a socket. served maps a URL to bytes (200)
    or to (code, Location) for a redirect; any other URL is a 404."""

    def https_open(handler, request):
        answer = served.get(request.full_url, (404, None))
        code, location = (200, None) if isinstance(answer, bytes) else answer
        headers = email.message.Message()
        if location is not None:
            headers["Location"] = location
        body = io.BytesIO(answer if code == 200 else b"")
        response = urllib.response.addinfourl(body, headers, request.full_url, code)
        response.msg = http.client.responses[code]
        return response

    return mock.patch.object(urllib.request.HTTPSHandler, "https_open", https_open)


def serve_tarballs(doc, name):
    """A FakeRegistry with a synthetic tarball of every version in doc; doc's dist.integrity is
    set to each tarball's real sha512."""
    served = FakeRegistry()
    for version, manifest in doc["versions"].items():
        data = package_tgz(name, version)
        manifest["dist"]["integrity"] = sri(data)
        served.files[tarball_url(name, version)] = data
    return served


class UrlTests(unittest.TestCase):
    def test_only_the_registry_over_https(self):
        good = "https://registry.npmjs.org/example/-/example-1.0.0.tgz"
        self.assertEqual(registry._check_url(good), good)
        for url in ("http://registry.npmjs.org/a", "https://registry.npmjs.org.evil.test/a",
                    "https://evil.test/registry.npmjs.org/a", "https://registry.npmjs.org:444/a",
                    "https://user@registry.npmjs.org/a", "ftp://registry.npmjs.org/a",
                    "//registry.npmjs.org/a", "", None, 5):  # fmt: skip
            with self.subTest(url=url), self.assertRaisesRegex(RegistryError, "outside https"):
                registry._check_url(url)

    def test_tarball_url_must_be_the_registry_path_of_that_version(self):
        data = package_tgz("@scope/pkg", "1.0.0")
        served = FakeRegistry({tarball_url("@scope/pkg", "1.0.0"): data})
        with mock.patch.object(registry, "_open", served):
            dist = {"tarball": tarball_url("@scope/pkg", "1.0.0"), "integrity": sri(data)}
            self.assertEqual(registry.tarball("@scope/pkg", "1.0.0", dist), data)
            for label, url in {
                "other host": "https://evil.test/@scope/pkg/-/pkg-1.0.0.tgz",
                "http": "http://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz",
                "other package": tarball_url("other", "1.0.0"),
                "other version": tarball_url("@scope/pkg", "0.9.0"),
                "query": tarball_url("@scope/pkg", "1.0.0") + "?x=1",
                "not text": ["https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz"],
                "missing": None,
            }.items():
                with self.subTest(label), self.assertRaisesRegex(RegistryError, "URL is not"):
                    registry.tarball("@scope/pkg", "1.0.0", {**dist, "tarball": url})
        self.assertEqual(served.opened, [tarball_url("@scope/pkg", "1.0.0")])  # only the good one

    def test_redirects_must_stay_on_the_registry(self):
        handler = registry._Redirects()
        request = urllib.request.Request("https://registry.npmjs.org/a")
        moved = handler.redirect_request(request, None, 302, "Found", {},
                                         "https://registry.npmjs.org/b")  # fmt: skip
        self.assertEqual(moved.full_url, "https://registry.npmjs.org/b")
        for target in ("https://evil.test/b", "http://registry.npmjs.org/b"):
            with self.subTest(target), self.assertRaisesRegex(RegistryError, "outside https"):
                handler.redirect_request(request, None, 302, "Found", {}, target)
        # The opener really uses this handler, and the final URL is checked again.
        opener = mock.Mock()
        with mock.patch("urllib.request.build_opener", return_value=opener) as build:
            registry._open("https://registry.npmjs.org/a")
        build.assert_called_once_with(registry._Redirects)
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 30})
        with mock.patch.object(registry, "_open",
                               lambda url: Response(b"{}", "https://evil.test/a")):  # fmt: skip
            with self.assertRaisesRegex(RegistryError, "outside https"):
                registry.download("https://registry.npmjs.org/a", 100)

    def test_refused_urls_show_only_their_scheme_and_host(self):
        # Revy minor 2: refusals quoted up to 200 characters of the URL, which then went into the
        # report's detail with credentials, path, query and fragment.
        s, only = SECRET, " (scheme and host only)"
        refused = {
            f"https://user:{s}@evil.test:8443/{s}/a.tgz?token={s}#{s}": "https://evil.test:8443",
            f"https://{s}@registry.npmjs.org/a": "https://registry.npmjs.org",
            f"http://registry.npmjs.org/a?token={s}#{s}": "http://registry.npmjs.org",
            f"ftp://evil.test/{s}": "ftp://evil.test",
        }
        request = urllib.request.Request("https://registry.npmjs.org/a")
        for url, shown in refused.items():
            for label, call in (
                ("check", lambda url=url: registry._check_url(url)),
                ("redirect", lambda url=url: registry._Redirects().redirect_request(
                    request, None, 302, "Found", {}, url)),
            ):  # fmt: skip
                with self.subTest(label, url=url):
                    with self.assertRaises(RegistryError) as error:
                        call()
                    self.assertEqual(str(error.exception),
                                     f"Refusing a URL outside https://registry.npmjs.org: {shown}{only}")  # fmt: skip
        expected = tarball_url("example", "1.0.0")
        not_url = "a value that is not an absolute URL"
        tarballs = [(u, f"{h}{only}") for u, h in refused.items()] + [
            (f"{expected}?token={s}#{s}", f"https://registry.npmjs.org{only}"),
            (f"user:{s}@evil.test/a?{s}", not_url),  # "user" parses as the scheme, no host
            (f"//{s}@evil.test/a", not_url),
            (f"https://[{s}/a", not_url),  # urlsplit raises ValueError
            ([f"https://{s}@evil.test"], not_url),
        ]
        for url, shown in tarballs:
            with self.subTest("tarball", url=url):
                with self.assertRaises(RegistryError) as error:
                    registry.tarball("example", "1.0.0", {"tarball": url})
                self.assertEqual(str(error.exception),
                                 f"example@1.0.0 tarball URL is not {expected}: {shown}")  # fmt: skip

    def test_a_refused_redirect_keeps_its_target_out_of_the_error(self):
        # Through the real opener: urllib refuses other schemes itself, with an HTTPError whose
        # text quotes the whole target; the handler here refuses other hosts.
        s, url = SECRET, "https://registry.npmjs.org/a"
        for target, message in (
            (f"javascript://user:{s}@evil.test/?t={s}",
             f"Cannot download {url}: HTTP 302, redirect not followed"),
            (f"https://user:{s}@evil.test/{s}?t={s}#{s}",
             "Refusing a URL outside https://registry.npmjs.org: https://evil.test (scheme and "
             "host only)"),
        ):  # fmt: skip
            with self.subTest(target=target), https_stand_in({url: (302, target)}):
                with self.assertRaises(RegistryError) as error:
                    registry.download(url, 100)
                self.assertEqual(str(error.exception), message)
        # The same stand-in follows a redirect on the registry; other errors keep urllib's text.
        moved = "https://registry.npmjs.org/b"
        with https_stand_in({url: (302, moved), moved: b"{}"}):
            self.assertEqual(registry.download(url, 100), b"{}")
            with self.assertRaisesRegex(RegistryError, r": HTTP Error 404: Not Found\Z"):
                registry.download("https://registry.npmjs.org/c", 100)


class DownloadTests(unittest.TestCase):
    URL = "https://registry.npmjs.org/a"

    def download(self, response, limit=100):
        with mock.patch.object(registry, "_open", lambda url: response):
            return registry.download(self.URL, limit)

    def test_size_and_time_limits(self):
        self.assertEqual(self.download(Response(b"x" * 100, self.URL)), b"x" * 100)
        with self.assertRaisesRegex(RegistryError, "larger than 100 bytes"):
            self.download(Response(b"x" * 101, self.URL))
        # A declared length over the limit stops before reading.
        reads = []

        class Counted(Response):
            def read1(self, size=-1):
                reads.append(size)
                return super().read1(size)

        with self.assertRaisesRegex(RegistryError, "larger than 100 bytes"):
            self.download(Counted(b"x", self.URL, {"Content-Length": "101"}))
        self.assertEqual(reads, [])

    def test_transport_errors_are_registry_errors(self):
        for error in (urllib.error.HTTPError(self.URL, 404, "Not Found", {}, None),
                      urllib.error.URLError("no route"), TimeoutError("timed out"),
                      http.client.IncompleteRead(b"x", 10)):  # fmt: skip
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(registry, "_open", side_effect=error):
                    with self.assertRaisesRegex(RegistryError, "Cannot download"):
                        registry.download(self.URL, 100)

    def test_packument_is_capped_json(self):
        url = "https://registry.npmjs.org/@scope/pkg"
        served = FakeRegistry({url: b'{"name": "@scope/pkg"}'})
        # The download step runs in-process here (test_bounded.py covers the child process).
        in_process = mock.patch.object(registry.bounded, "run", lambda f, args: f(*args))
        with in_process, mock.patch.object(registry, "_open", served):
            self.assertEqual(registry.packument("@scope/pkg"), {"name": "@scope/pkg"})
            served.files[url] = b"{"
            with self.assertRaisesRegex(RegistryError, "Invalid JSON"):
                registry.packument("@scope/pkg")
            served.files[url] = b"[]" * 10
            with mock.patch.object(registry, "MAX_PACKUMENT_BYTES", 10):
                with self.assertRaisesRegex(RegistryError, "larger than 10 bytes"):
                    registry.packument("@scope/pkg")


class IntegrityTests(unittest.TestCase):
    DATA = b"synthetic tarball bytes"

    def test_strongest_algorithm_decides(self):
        ok = [sri(self.DATA), f"{sri(b'other')} {sri(self.DATA)}", f"{sri(self.DATA)}?opt",
              sri(self.DATA, "sha1"), f"{sri(self.DATA)} {sri(b'other', 'sha1')}",
              sri(self.DATA, "sha256")]  # fmt: skip
        for integrity in ok:
            with self.subTest(integrity=integrity):
                registry.verify(self.DATA, {"integrity": integrity}, "x")
        bad = {
            "sha512 differs": sri(b"other"),
            "sha512 differs, sha1 matches": f"{sri(b'other')} {sri(self.DATA, 'sha1')}",
            "sha384 over sha256": f"{sri(b'other', 'sha384')} {sri(self.DATA, 'sha256')}",
        }
        for label, integrity in bad.items():
            with self.subTest(label), self.assertRaisesRegex(RegistryError, "does not match"):
                registry.verify(self.DATA, {"integrity": integrity}, "x")

    def test_legacy_shasum_and_nothing_to_check(self):
        shasum = hashlib.sha1(self.DATA).hexdigest()
        registry.verify(self.DATA, {"shasum": shasum.upper()}, "x")
        with self.assertRaisesRegex(RegistryError, "does not match its sha1 shasum"):
            registry.verify(self.DATA, {"shasum": hashlib.sha1(b"other").hexdigest()}, "x")
        for dist in ({}, {"integrity": "md5-abc"}, {"integrity": 5}, {"shasum": "short"},
                     {"integrity": ""}):  # fmt: skip
            with self.subTest(dist=dist), self.assertRaisesRegex(RegistryError, "no sha512"):
                registry.verify(self.DATA, dist, "x")

    def test_a_present_integrity_never_falls_back_to_the_shasum(self):
        # Revy minor 1: with a matching shasum each of these passed before the fix.
        shasum = hashlib.sha1(self.DATA).hexdigest()
        for integrity in ("md5-abc", "", " ", "sha3-abc", 5, False, ["sha512-x"], {"a": 1}):
            with self.subTest(integrity=integrity):
                with self.assertRaisesRegex(RegistryError, r"\Ax integrity has no sha512"):
                    registry.verify(self.DATA, {"integrity": integrity, "shasum": shasum}, "x")
        for integrity in ("sha512", f"md5-abc {sri(b'other')}"):  # a supported digest decides
            with self.subTest(integrity=integrity):
                with self.assertRaisesRegex(RegistryError, "does not match its sha512 integrity"):
                    registry.verify(self.DATA, {"integrity": integrity, "shasum": shasum}, "x")
        registry.verify(self.DATA, {"integrity": f"md5-abc {sri(self.DATA)}", "shasum": "0" * 40},
                        "x")  # fmt: skip
        # Missing or null is no integrity: only then the shasum decides.
        for dist in ({"shasum": shasum}, {"integrity": None, "shasum": shasum}):
            registry.verify(self.DATA, dist, "x")
        with self.assertRaisesRegex(RegistryError, "does not match its sha1 shasum"):
            registry.verify(self.DATA, {"integrity": None, "shasum": "0" * 40}, "x")


class UnpackTests(Fixture):
    def unpack(self, data):
        self.target = self.root / f"unpack-{len(list(self.root.iterdir()))}"
        self.target.mkdir()
        return registry.unpack(data, self.target, "x tarball")

    def unpacked(self):
        """{name: size} of every file the last unpack left; no link may be left."""
        paths = list(self.target.rglob("*"))
        self.assertEqual([p for p in paths if p.is_symlink()], [])
        return {p.relative_to(self.target).as_posix(): p.stat().st_size
                for p in paths if p.is_file()}  # fmt: skip

    def test_package_root_like_feature_extractor(self):
        root = self.unpack(package_tgz("example", "1.0.0"))
        self.assertEqual(root.name, "package")
        self.assertEqual(json.loads((root / "package.json").read_bytes())["version"], "1.0.0")
        flat = self.unpack(tgz({"package.json": b"{}"}))
        self.assertEqual(sorted(p.name for p in flat.iterdir()), ["package.json"])
        for files in ({"package/index.js": b""}, {"a/package.json": b"{}", "b/package.json": b"{}"}):
            with self.subTest(files=list(files)), self.assertRaisesRegex(RegistryError, "root"):
                self.unpack(tgz(files))

    def test_limits_and_bad_archives(self):
        members = {f"package/{i}.js": b"" for i in range(4)}
        with mock.patch.object(registry, "MAX_MEMBERS", 3):
            with self.assertRaisesRegex(RegistryError, "more than 3 members"):
                self.unpack(tgz(members))
        zeros = tgz({"package/package.json": b"{}", "package/zeros.bin": bytes(1 << 20)})
        self.assertLess(len(zeros), 4096)  # a small archive that inflates to 1 MiB
        with mock.patch.object(registry, "MAX_UNPACKED_BYTES", 64 * 1024):
            with self.assertRaisesRegex(RegistryError, "unpacks to more than 65536 bytes"):
                self.unpack(zeros)
        # A member may declare far more than the archive holds (as a sparse file can).
        huge = tarfile.TarInfo("package/huge.bin")
        huge.size = 10**12
        declared = gzip.compress(huge.tobuf(tarfile.PAX_FORMAT) + bytes(1024), mtime=0)
        with self.assertRaisesRegex(RegistryError, "unpacks to more than"):
            self.unpack(declared)
        for label, data in {
            "not gzip": b"plain bytes",
            "truncated": package_tgz("example", "1.0.0")[:-8],
            "outside the folder": tgz({"package/package.json": b"{}", "../evil.txt": b"x"}),
            "link outside": tgz({"package/package.json": b"{}"},
                                symlink=("package/link", "../../evil")),
        }.items():  # fmt: skip
            with self.subTest(label), self.assertRaises(RegistryError):
                self.unpack(data)
        self.assertFalse((self.root / "evil.txt").exists())

    def test_symbolic_links_are_not_unpacked(self):
        # Revy major 1: where os.symlink fails (Windows without the privilege) tarfile copied
        # each link's target, which the size limit did not count; npm and feature-extractor's
        # source walk read no symbolic link.
        big, json_ = ("package/big.bin", bytes(64 * 1024)), ("package/package.json", b"{}")
        copies = [(f"package/link{i}", tarfile.SYMTYPE, "big.bin") for i in range(8)]
        cycle = [("package/a", tarfile.SYMTYPE, "b"), ("package/b", tarfile.SYMTYPE, "a")]
        for label, links in (("copies over the limit", copies), ("a cycle", cycle)):
            with (
                self.subTest(label),
                mock.patch.object(registry, "MAX_UNPACKED_BYTES", 128 * 1024),
                mock.patch("os.symlink", side_effect=OSError("no privilege")) as symlink,
            ):
                self.unpack(linked_tgz(json_, big, *links))
                expected = {"package/package.json": 2, "package/big.bin": 65536}
                self.assertEqual(self.unpacked(), expected)
                symlink.assert_not_called()
        with self.assertRaisesRegex(RegistryError, "Cannot unpack"):  # still the "data" filter
            self.unpack(linked_tgz(json_, ("package/up", tarfile.SYMTYPE, "../../evil")))

    def test_hard_links_count_as_the_file_they_copy(self):
        # Revy major 1: a hard link is unpacked (os.link, or a copy of its target where that
        # fails), so it counts as the target: the latest earlier member of that name.
        link = tarfile.LNKTYPE
        json_, f = ("package/package.json", b"{}"), "package/f"
        cap = mock.patch.object(registry, "MAX_UNPACKED_BYTES", 128 * 1024)
        no_link = mock.patch("os.link", side_effect=OSError("no hard links here"))
        refused = {
            "copies over the limit": [(f, bytes(64 * 1024)), *((f"package/c{i}", link, f)
                                                              for i in range(8))],
            "a chain": [(f, bytes(40 * 1024)), ("package/h1", link, f),
                        ("package/h2", link, "package/h1"), ("package/h3", link, "package/h2")],
            "the earlier of two names": [(f, bytes(100 * 1024)), ("package/h", link, f), (f, b"x")],
        }  # fmt: skip
        for label, entries in refused.items():
            with self.subTest(label), cap, no_link:
                with self.assertRaisesRegex(RegistryError, "unpacks to more than 131072 bytes"):
                    self.unpack(linked_tgz(json_, *entries))
                self.assertEqual(self.unpacked(), {})  # refused before anything is written
        within = [(f, bytes(40 * 1024)), ("package/h1", link, f), ("package/h2", link, "package/h1"),
                  (f, b"x"), ("package/h3", link, f)]  # fmt: skip
        for label, patch in (("os.link", contextlib.nullcontext()), ("copies", no_link)):
            with self.subTest(label), cap, patch:
                self.unpack(linked_tgz(json_, *within))
                files = self.unpacked()
                self.assertEqual(files["package/h3"], 1)  # the latest f before it
                self.assertLessEqual(sum(files.values()), 128 * 1024)
        # A hard link to anything but a file is left out, as are its symbolic link targets.
        skipped = [("package/s", tarfile.SYMTYPE, "f"), ("package/d", tarfile.DIRTYPE, ""),
                   ("package/to-link", link, "package/s"), ("package/to-dir", link, "package/d"),
                   ("package/to-nothing", link, "package/none")]  # fmt: skip
        with cap, no_link:
            self.unpack(linked_tgz(json_, (f, bytes(100 * 1024)), *skipped))
        self.assertEqual(self.unpacked(), {"package/package.json": 2, f: 100 * 1024})
        for target in ("../../evil", "/etc/passwd"):  # still the "data" filter
            with self.subTest(target), self.assertRaisesRegex(RegistryError, "Cannot unpack"):
                self.unpack(linked_tgz(json_, ("package/out", link, target)))


if __name__ == "__main__":
    unittest.main()
