"""CI only: FILE must be a report of the example update (lodash 4.17.20 to 4.17.21) that this
checkout's model, index and pinned analyzer really checked. A held item, another model or index,
or an analyzer that is not the unchanged Git install of pyproject.toml's pin fails here.

    python -I .github/scripts/check_lodash_report.py FILE [ANALYZER_FILES_SHA256]

FILE is a depbee report, or JSON that holds one under "report" (depbee update, the MCP tools).
ANALYZER_FILES_SHA256 is the digest that the depbee which made the report gives its own installed
analyzer (files_sha256 of extractor._installed_identity). With it, the report must name it.
"""

import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "src" / "depbee" / "assets"


def main(file: str, analyzer_files: str | None = None) -> None:
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


if __name__ == "__main__":
    main(*sys.argv[1:])
