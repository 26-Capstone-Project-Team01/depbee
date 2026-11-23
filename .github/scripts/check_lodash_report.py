"""CI only: FILE must be a report of the example update (lodash 4.17.20 to 4.17.21) that this
checkout's model, index and pinned analyzer really checked. A held item, another model or index,
or an analyzer that is not the unchanged Git install of pyproject.toml's pin fails here.

    python -I .github/scripts/check_lodash_report.py FILE

FILE is a depbee report, or JSON that holds one under "report" (depbee update, the MCP tools).
"""

import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "src" / "depbee" / "assets"


def main(file: str) -> None:
    data = json.loads(Path(file).read_bytes())
    report = data.get("report", data)
    model, index = (json.loads((ASSETS / name / "manifest.json").read_bytes())
                    for name in ("model", "index"))  # fmt: skip
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
    # A report names them only after LightGBM loaded that model and the index was read.
    assert report["model_id"] == model["model_id"], report["model_id"]
    assert report["provenance"]["model"]["model_sha256"] == model["model_sha256"]
    known = report["detectors"]["known_malicious"]
    assert (known["list_as_of"], known["list_sha256"]) == (index["list_as_of"],
                                                         index["index_sha256"])  # fmt: skip
    # The commit is in a report only for the unchanged Git install of that pin
    # (extractor._installed_identity); otherwise feature_extractor is null.
    commit = report["provenance"]["feature_extractor"]["commit"]
    assert pin.endswith(f"@{commit}"), commit
    print(f"{file}: lodash 4.17.20 to 4.17.21 passed, model {report['model_id']}, "
          f"index {known['list_as_of']}, analyzer {commit}")  # fmt: skip


if __name__ == "__main__":
    main(*sys.argv[1:])
