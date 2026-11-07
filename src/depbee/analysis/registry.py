"""npm registry downloads for the extractor, with the checks feature-extractor does not make.

The pinned feature-extractor (c24761d, loader.py) fetches with requests and ``timeout=30`` per
socket operation only, follows any redirect, never hashes the tarball, and unpacks it without size
or member limits. depbee therefore downloads packuments and tarballs itself:

- only from https://registry.npmjs.org, also after each redirect; a tarball URL must be the
  registry's own path for that package and version;
- every download stops at a size limit; the time limit is the change's budget in
  analysis.bounded, whose child process (downloads, unpacking, extraction) is killed at the end;
- tarball bytes must match the version's ``dist.integrity`` before anything is unpacked, using
  the strongest listed algorithm as npm does (``dist.shasum`` if there is no integrity);
- unpacking stops at limits on the unpacked size and member count and uses the tarfile "data"
  filter and package-root rule of feature-extractor's loader. Symbolic links are not unpacked
  (npm installs none, feature-extractor reads none) and a hard link counts as the file it copies.

The limits are constants, not options; docs/validation.md records why each value was chosen.
"""

import base64
import gzip
import hashlib
import http.client
import io
import json
import os
import tarfile
import urllib.error
import urllib.request
import zlib
from pathlib import Path
from urllib.parse import urlsplit

from .. import __version__
from ..contracts import GuardError
from . import bounded

HOST = "registry.npmjs.org"
MAX_PACKUMENT_BYTES = 128 * 1024 * 1024
MAX_TARBALL_BYTES = 128 * 1024 * 1024
MAX_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 20_000
SOCKET_TIMEOUT_SECONDS = 30  # per socket operation, as in feature-extractor
_CHUNK = 1024 * 1024
_ALGORITHMS = ("sha512", "sha384", "sha256", "sha1")  # strongest first, as ssri picks


class RegistryError(GuardError):
    """A registry download that failed or did not pass a check."""


def _shown(url: object) -> str:
    """What an error message shows of a refused URL: its scheme and host. User information,
    path, query and fragment are left out, as they can hold credentials or signed tokens."""
    try:
        parts = urlsplit(url) if isinstance(url, str) else None
    except ValueError:  # e.g. an unclosed IPv6 bracket
        parts = None
    if parts is None or not parts.scheme or not parts.netloc:
        return "a value that is not an absolute URL"
    return f"{parts.scheme}://{parts.netloc.rpartition('@')[2]} (scheme and host only)"


def _check_url(url: object) -> str:
    parts = urlsplit(url) if isinstance(url, str) else None
    if parts is None or parts.scheme != "https" or parts.netloc != HOST:
        raise RegistryError(f"Refusing a URL outside https://{HOST}: {_shown(url)}")
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
    """Bytes at url, at most limit of them.

    No time limit here: socket timeouts only limit each operation, and a thread cannot be
    stopped. The extractor runs downloads in a bounded child process (analysis.bounded), whose
    time limit covers connecting, headers, redirects and the body, and which is killed with its
    connection when the time is up.
    """
    _check_url(url)
    data = bytearray()
    try:
        with _open(url) as response:
            _check_url(response.geturl())
            length = response.headers.get("Content-Length", "")
            if length.isdigit() and int(length) > limit:
                raise RegistryError(f"{url} is larger than {limit} bytes")
            while chunk := response.read1(_CHUNK):  # one socket read at a time
                data += chunk
                if len(data) > limit:
                    raise RegistryError(f"{url} is larger than {limit} bytes")
    except urllib.error.HTTPError as exc:
        # urllib's text for a redirect it refused (another scheme) quotes the whole target.
        detail = f"HTTP {exc.code}, redirect not followed" if 300 <= exc.code < 400 else exc
        raise RegistryError(f"Cannot download {url}: {detail}") from exc
    except (OSError, http.client.HTTPException) as exc:  # URLError is an OSError
        raise RegistryError(f"Cannot download {url}: {exc}") from exc
    return bytes(data)


def packument(name: str) -> dict:
    """Full registry metadata of name, at the URL feature-extractor's fetch_packument uses.

    Downloaded in a bounded child process (part of the change's time budget); the bytes, at most
    MAX_PACKUMENT_BYTES, are parsed here.
    """
    raw = bounded.run(download, (f"https://{HOST}/{name}", MAX_PACKUMENT_BYTES))
    try:
        return json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise RegistryError(f"Invalid JSON in the npm registry metadata for {name}") from exc


def verify(data: bytes, dist: dict, what: str) -> None:
    """Check data against dist.integrity like npm: the strongest listed algorithm decides, and
    any of its digests may match. Only without an integrity (missing or null) is the legacy sha1
    dist.shasum used; an integrity that is not text or lists no supported digest fails."""
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
    if integrity is not None:  # present but unusable: never fall back to the weaker shasum
        raise RegistryError(f"{what} integrity has no sha512, sha384, sha256 or sha1 digest")
    shasum = dist.get("shasum")
    if isinstance(shasum, str) and len(shasum) == 40:
        if hashlib.sha1(data).hexdigest() != shasum.lower():
            raise RegistryError(f"{what} does not match its sha1 shasum")
        return
    raise RegistryError(f"{what} has no sha512, sha384, sha256 or sha1 digest to check")


def tarball(name: str, version: str, dist: dict) -> bytes:
    """The checked tarball of name@version: registry URL and path, size, time, integrity."""
    what = f"{name}@{version} tarball"
    expected = f"https://{HOST}/{name}/-/{name.rpartition('/')[2]}-{version}.tgz"
    if dist.get("tarball") != expected:
        raise RegistryError(f"{what} URL is not {expected}: {_shown(dist.get('tarball'))}")
    data = download(expected, MAX_TARBALL_BYTES)
    verify(data, dist, what)
    return data


def _data_without_symlinks(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
    """feature-extractor's "data" filter (loader.py:112-114), which refuses links that leave the
    folder, then leaves out symbolic links. Where os.symlink fails (Windows without the
    privilege) tarfile would copy a link's target instead, bytes the size limit never counted."""
    member = tarfile.data_filter(member, path)
    return None if member.issym() else member


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
            members, declared, files = [], 0, {}  # files: size of each name, None if no file
            for count, member in enumerate(archive, 1):
                if count > MAX_MEMBERS:
                    raise RegistryError(f"{what} has more than {MAX_MEMBERS} members")
                name = os.path.normpath(member.name)
                if member.islnk():
                    # Where os.link fails tarfile copies the latest earlier member of that name
                    # (TarFile._find_link_target): count that file, leave out links to anything else.
                    size = files[name] = files.get(os.path.normpath(member.linkname))
                    if size is None:
                        tarfile.data_filter(member, str(directory))  # links out are still refused
                        continue
                else:
                    size = max(member.size, 0)  # a sparse member can declare more than it holds
                    files[name] = size if member.isreg() else None
                members.append(member)
                declared += size
                if declared > MAX_UNPACKED_BYTES:
                    raise RegistryError(f"{what} unpacks to more than {MAX_UNPACKED_BYTES} bytes")
            archive.extractall(directory, members=members, filter=_data_without_symlinks)
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
