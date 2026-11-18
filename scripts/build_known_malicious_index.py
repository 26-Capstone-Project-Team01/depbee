"""Build a known malicious index folder (index.json + manifest.json) from an OSV npm snapshot.

The rules are depbee.known_malicious.build_index(); this script only reads the zip and writes the
two files, never over existing ones. --as-of is when all.zip was downloaded (UTC, ending in Z).

    python scripts/build_known_malicious_index.py all.zip known-malicious --as-of 2026-10-06T14:00:47Z
"""

import argparse
import json
from pathlib import Path

from depbee.contracts import GuardError
from depbee.known_malicious import MAX_SNAPSHOT_BYTES, build_index


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("snapshot", type=Path, help="OSV npm all.zip")
    parser.add_argument("out_dir", type=Path, help="Folder for index.json and manifest.json")
    parser.add_argument(
        "--as-of", required=True, help="UTC download time, e.g. 2026-10-06T14:00:47Z"
    )
    args = parser.parse_args()

    targets = [args.out_dir / "index.json", args.out_dir / "manifest.json"]
    taken = [str(path) for path in targets if path.exists()]
    if taken:
        raise SystemExit(f"Refusing to overwrite: {', '.join(taken)}")
    with args.snapshot.open("rb") as stream:
        snapshot = stream.read(MAX_SNAPSHOT_BYTES + 1)
    try:
        index, manifest, header = build_index(snapshot, args.as_of)
    except GuardError as exc:
        raise SystemExit(str(exc)) from None
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for path, data in zip(targets, (index, manifest), strict=True):
        with path.open("xb") as stream:
            stream.write(data)
    print(json.dumps(header, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
