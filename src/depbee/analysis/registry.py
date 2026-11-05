"""npm registry downloads for the extractor, with the checks feature-extractor does not make.

The pinned feature-extractor (c24761d, loader.py) fetches with requests and ``timeout=30`` per
socket operation only, follows any redirect, never hashes the tarball, and unpacks it without size
or member limits. depbee therefore downloads packuments and tarballs itself:

- only from https://registry.npmjs.org, also after each redirect; a tarball URL must be the
  registry's own path for that package and version;
- every download stops at a size limit and a wall-clock limit (``download``); unpacking has no
  time limit of its own and is bounded by the size and member limits only;
- tarball bytes must match the version's ``dist.integrity`` before anything is unpacked, using
  the strongest listed algorithm as npm does (``dist.shasum`` if there is no integrity);
- unpacking stops at limits on the unpacked size and member count and uses the tarfile "data"
  filter and package-root rule of feature-extractor's loader, so the source tree is the same.

The limits are constants, not options; docs/validation.md records why each value was chosen.
"""

import base64
import gzip
import hashlib
import http.client
import io
import json
import tarfile
import threading
import time
import urllib.error
import urllib.request
import zlib
from pathlib import Path
from urllib.parse import urlsplit

from .. import __version__
from ..contracts import GuardError

HOST = "registry.npmjs.org"
MAX_PACKUMENT_BYTES = 128 * 1024 * 1024
MAX_TARBALL_BYTES = 128 * 1024 * 1024
MAX_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 20_000
DOWNLOAD_SECONDS = 120
SOCKET_TIMEOUT_SECONDS = 30  # per socket operation, as in feature-extractor
_CHUNK = 1024 * 1024
_ALGORITHMS = ("sha512", "sha384", "sha256", "sha1")  # strongest first, as ssri picks


class RegistryError(GuardError):
    """A registry download that failed or did not pass a check."""


def _check_url(url: object) -> str:
    parts = urlsplit(url) if isinstance(url, str) else None
    if parts is None or parts.scheme != "https" or parts.netloc != HOST:
        raise RegistryError(f"Refusing a URL outside https://{HOST}: {str(url)[:200]!r}")
    return url


class _Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url: str):
    """The HTTP response for url; tests replace this, so no test touches the network."""
    opener = urllib.request.build_opener(_Redirects)
    request = urllib.request.Request(url, headers={"User-Agent": f"depbee/{__version__}"})
    return opener.open(request, timeout=SOCKET_TIMEOUT_SECONDS)


def download(url: str, limit: int) -> bytes:
    """Bytes at url, at most limit of them, within DOWNLOAD_SECONDS of wall-clock time.

    Socket timeouts limit each operation, not a whole request: a server that keeps sending a few
    bytes, slowly, never trips them, while connecting, in the headers, across redirects or in the
    body. So the request runs in a daemon thread that depbee waits for at most DOWNLOAD_SECONDS.
    The thread also checks the clock after every read, at the end of the body too, and stops; one
    that is still blocked in a socket operation when the time is up is abandoned and ends with
    that operation (at most SOCKET_TIMEOUT_SECONDS without data) or with the process.
    """
    _check_url(url)
    deadline = time.monotonic() + DOWNLOAD_SECONDS
    outcome: dict = {}
    finished = threading.Event()

    def work() -> None:
        try:
            outcome["data"] = _read(url, limit, deadline)
        except Exception as exc:  # re-raised in the waiting thread
            outcome["error"] = exc
        finally:
            finished.set()

    threading.Thread(target=work, name="depbee-download", daemon=True).start()
    if not finished.wait(DOWNLOAD_SECONDS):
        raise RegistryError(f"{url} did not download within {DOWNLOAD_SECONDS} s")
    if "error" in outcome:
        raise outcome["error"]
    return outcome["data"]


def _read(url: str, limit: int, deadline: float) -> bytes:
    data = bytearray()
    try:
        with _open(url) as response:
            _check_url(response.geturl())
            length = response.headers.get("Content-Length", "")
            if length.isdigit() and int(length) > limit:
                raise RegistryError(f"{url} is larger than {limit} bytes")
            while True:
                # read1 returns after one socket read; read(n) would wait until n bytes arrive.
                chunk = response.read1(_CHUNK)
                if time.monotonic() > deadline:
                    raise RegistryError(f"{url} did not download within {DOWNLOAD_SECONDS} s")
                if not chunk:
                    return bytes(data)
                data += chunk
                if len(data) > limit:
                    raise RegistryError(f"{url} is larger than {limit} bytes")
    except (OSError, http.client.HTTPException) as exc:  # URLError and HTTPError are OSErrors
        raise RegistryError(f"Cannot download {url}: {exc}") from exc


def packument(name: str) -> dict:
    """Full registry metadata of name, at the URL feature-extractor's fetch_packument uses."""
    raw = download(f"https://{HOST}/{name}", MAX_PACKUMENT_BYTES)
    try:
        return json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise RegistryError(f"Invalid JSON in the npm registry metadata for {name}") from exc


def verify(data: bytes, dist: dict, what: str) -> None:
    """Check data against dist.integrity like npm: the strongest listed algorithm decides, and
    any of its digests may match. Without an integrity, the legacy sha1 dist.shasum is used."""
    integrity = dist.get("integrity")
    digests: dict[str, set[str]] = {}
    for token in integrity.split() if isinstance(integrity, str) else ():
        algorithm, _, value = token.partition("-")
        if algorithm in _ALGORITHMS:
            digests.setdefault(algorithm, set()).add(value.partition("?")[0])
    for algorithm in _ALGORITHMS:
        if algorithm in digests:
            actual = base64.b64encode(hashlib.new(algorithm, data).digest()).decode()
            if actual not in digests[algorithm]:
                raise RegistryError(f"{what} does not match its {algorithm} integrity")
            return
    shasum = dist.get("shasum")
    if not digests and isinstance(shasum, str) and len(shasum) == 40:
        if hashlib.sha1(data).hexdigest() != shasum.lower():
            raise RegistryError(f"{what} does not match its sha1 shasum")
        return
    raise RegistryError(f"{what} has no sha512, sha384, sha256 or sha1 digest to check")


def tarball(name: str, version: str, dist: dict) -> bytes:
    """The checked tarball of name@version: registry URL and path, size, time, integrity."""
    what = f"{name}@{version} tarball"
    expected = f"https://{HOST}/{name}/-/{name.rpartition('/')[2]}-{version}.tgz"
    if dist.get("tarball") != expected:
        raise RegistryError(f"{what} URL is not {expected}: {str(dist.get('tarball'))[:200]!r}")
    data = download(expected, MAX_TARBALL_BYTES)
    verify(data, dist, what)
    return data


def unpack(data: bytes, directory: Path, what: str) -> Path:
    """Unpack a checked .tgz into directory within the limits and return its package root."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            raw = stream.read(MAX_UNPACKED_BYTES + 1)  # never inflates more than this
    except (OSError, EOFError, zlib.error) as exc:
        raise RegistryError(f"{what} is not a complete gzip file") from exc
    if len(raw) > MAX_UNPACKED_BYTES:
        raise RegistryError(f"{what} unpacks to more than {MAX_UNPACKED_BYTES} bytes")
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members, declared = [], 0
            for member in archive:
                members.append(member)
                declared += max(member.size, 0)  # a sparse member can declare more than it holds
                if len(members) > MAX_MEMBERS:
                    raise RegistryError(f"{what} has more than {MAX_MEMBERS} members")
                if declared > MAX_UNPACKED_BYTES:
                    raise RegistryError(f"{what} unpacks to more than {MAX_UNPACKED_BYTES} bytes")
            # The filter feature-extractor uses (loader.py:112-114) against path traversal.
            archive.extractall(directory, members=members, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise RegistryError(f"Cannot unpack {what}: {exc}") from exc
    # feature-extractor's _locate_package_root (loader.py:123-142): the folder or its one child
    # that holds package.json.
    if (directory / "package.json").is_file():
        return directory
    roots = [child for child in sorted(directory.iterdir()) if (child / "package.json").is_file()]
    if len(roots) != 1:
        raise RegistryError(f"{what} has no single package root containing package.json")
    return roots[0]
