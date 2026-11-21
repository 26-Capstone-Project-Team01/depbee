"""The model and the known malicious index shipped inside the depbee package.

A scan uses them for an asset that no option, environment variable or saved setup names
(service._assets). They are the released files, unchanged: assets/model (model.txt,
manifest.json) and assets/index (index.json, manifest.json) beside this module, wherever depbee
is installed. Never the current folder or a project being checked. assets/NOTICE.md names their
sources and licenses.

A manifest only says that the file beside it agrees with it, and whoever can change one can
change both. So the SHA-256 of the four released files are fixed here, in code: a shipped asset
that would load but is not the released one is refused like one that does not load.
"""

from pathlib import Path

from .config import LAYOUT
from .contracts import GuardError

ROOT = Path(__file__).resolve().parent / "assets"
# The shipped folder of each asset, by its settings key.
DIRS = {key: ROOT / name for key, name in LAYOUT.items()}
SHA256 = {
    "model/manifest.json": "24995f63eec3c24f168c8d99bda88badd71738538b62a542e692e76dfa17bdc3",
    "model/model.txt": "4e3bb5a8678ecc1e12ccb39b9cb1f2c23c5a4d04d6aca2832e69ecd2537623a9",
    "index/manifest.json": "1e1d7553cbd99b354a29f8f3949c10968682d15b127cd6d8d851b0e0b19857f9",
    "index/index.json": "a59a627f2870f1f270f8e9a91ea9a0ef3bee6081ee372eaaa2451e1ed58ceb7e",
}
_WHAT = {"model_dir": "model", "known_malicious_dir": "known malicious index"}


def load(key: str, loader):
    """The shipped asset of key ("model_dir" or "known_malicious_dir"), read by the loader of a
    scan: LightGBMPredictor, or known_malicious.load.

    The loader is given the fixed SHA-256 of its two files with the folder. It reads each file
    once and checks those bytes against them before it parses the same bytes, so nothing that is
    not the released file reaches LightGBM or a JSON parser, and no second read can see other
    bytes than the ones checked. Missing files, files that are not the released ones and files
    its own checks refuse are a GuardError that says the installation is damaged: never another
    asset, and never none."""
    folder, prefix = DIRS[key], f"{LAYOUT[key]}/"
    fixed = {name.removeprefix(prefix): sha256 for name, sha256 in SHA256.items()
             if name.startswith(prefix)}  # fmt: skip
    try:
        return loader(folder, fixed)
    except (OSError, ValueError) as exc:  # GuardError is a ValueError
        raise GuardError(
            f"The {_WHAT[key]} shipped with depbee cannot be loaded ({exc}); reinstall depbee: "
            f"{folder}"
        ) from exc
