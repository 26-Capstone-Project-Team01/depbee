"""Jobs that tests run in real child processes of analysis.bounded (not a test module itself).

A child process does not inherit the parent's mock patches, so every job first makes network
connections fail and installs its own synthetic registry, inside the child. Slow jobs append to
a heartbeat file while they work, so a test can see that the work stopped once killed.
"""

import gzip
import socket
import time
from pathlib import Path
from types import SimpleNamespace

from depbee.analysis import registry


def offline():
    def refuse(*_args, **_kwargs):
        raise OSError("bounded_jobs: network blocked in the child")

    socket.socket.connect = socket.create_connection = socket.getaddrinfo = refuse


def beat(heartbeat):
    with Path(heartbeat).open("a", encoding="utf-8") as stream:
        stream.write(f"{time.monotonic()}\n")
    time.sleep(0.05)


def sleep_then(seconds, value):
    offline()
    time.sleep(seconds)
    return value


def give(value, _name):
    """fetch_packument stand-in that crosses by pickle (it runs in the parent here)."""
    return value


def fail(message):
    offline()
    raise registry.RegistryError(message)


def crash(code):
    import os

    os._exit(code)


class _Stuck:
    """A response that never finishes: opening (lookup, connect, TLS, headers, redirects) or a
    body that keeps trickling one byte at a time."""

    def __init__(self, heartbeat, opening):
        self.heartbeat, self.opening = heartbeat, opening

    def __call__(self, url):
        while self.opening:
            beat(self.heartbeat)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def geturl(self):
        return "https://registry.npmjs.org/example"

    headers = {}

    def read1(self, _size=-1):
        beat(self.heartbeat)
        return b"x"


def stuck_download(heartbeat, opening):
    offline()
    registry._open = _Stuck(heartbeat, opening)
    return registry.download("https://registry.npmjs.org/example", 10**9)


def slow_unpack(heartbeat, data, target):
    offline()

    class SlowGzip(gzip.GzipFile):
        def read(self, size=-1):
            while True:  # as a decompression or tar walk that takes too long
                beat(heartbeat)

    registry.gzip = SimpleNamespace(GzipFile=SlowGzip)
    return str(registry.unpack(data, Path(target), "slow tarball"))


def snapshot(packument, package, version):
    return SimpleNamespace(package_json=packument["versions"][version])


def slow_row(name, old, new, label, extractors, *, old_source, new_source):
    """build_row stand-in for FeatureExtractorBackend._extract_here: feature extraction that
    never ends. It reads no source, so nothing is downloaded. The heartbeat file is named in
    the new version's manifest, which is all the child receives."""
    offline()
    heartbeat = old_source.get_snapshot(name, new).package_json["heartbeat"]
    while True:
        beat(heartbeat)


def quick_row(name, old, new, label, extractors, *, old_source, new_source):
    offline()
    return SimpleNamespace(features={"signal": 0.2, "obfChangedFileCount": 0, "name": name})


def real_extract(files, name, old, new, packument, work):
    """The installed, pinned depbee-analyzer behind FeatureExtractorBackend._extract_here in
    this child, with tarballs from files ({url: bytes}) instead of the registry."""
    offline()
    from depbee.analysis.extractor import FeatureExtractorBackend

    class Served:
        def __init__(self, url):
            self.data, self.url = files[url], url

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def geturl(self):
            return self.url

        headers = {}

        def read1(self, size=-1):
            data, self.data = self.data, b""
            return data

    registry._open = Served
    features, new_json, found = FeatureExtractorBackend()._extract_here(
        name, old, new, packument, None, Path(work)
    )
    unpacked = sorted(p.relative_to(work).parts[1:] for p in Path(work).rglob("package.json"))
    return {"features": features, "new_json": new_json, "unpacked": unpacked, "rules": found}
