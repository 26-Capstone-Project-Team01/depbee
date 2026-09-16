import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analysis.artifact import ArtifactAnalyzer
from .contracts import GuardError
from .inference.lightgbm import LightGBMPredictor
from .inputs.npm import build_request
from .pipeline import scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze npm updates without installing packages")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("plan", "Export changed version pairs"),
        ("scan", "Join analyzer results with a LightGBM model"),
    ):
        cmd = commands.add_parser(name, help=help_text)
        cmd.add_argument("project", type=Path, help="Directory containing the new package-lock.json")
        cmd.add_argument("--base-lock", required=True, type=Path, help="Previous package-lock.json")
        cmd.add_argument("--output", type=Path, help="Write a NEW JSON file (never overwrite inputs)")
        if name == "scan":
            cmd.add_argument("--analysis", type=Path, help="Trusted analyzer output JSON")
            cmd.add_argument("--model-dir", type=Path, help="Trusted manifest.json + model.txt")
            cmd.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _emit(report: dict, args: argparse.Namespace) -> None:
    # ASCII escapes prevent package-controlled terminal control characters from being interpreted.
    payload = json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
    if args.command == "plan" or args.format == "json":
        print(payload, end="")
        return
    print(f"Status: {report['status']} | exit: {report['exit_code']}")
    print(report["scope"])
    for row in report["results"]:
        label = json.dumps(row["package"], ensure_ascii=True)
        location = json.dumps(row["location"], ensure_ascii=True)
        print(f"- {label} at {location}: {row['status']} (score={row['score']})")
        if row.get("reason"):
            print(f"  reason: {row['reason']}")
        for evidence in row["evidence"]:
            print(f"  evidence: {json.dumps(evidence, ensure_ascii=True)}")
    print("not_flagged is a model decision, not proof that a package is safe.")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        request = build_request(args.project, args.base_lock)
        if args.command == "plan":
            _emit(request, args)
            return 0
        analyzer = ArtifactAnalyzer(args.analysis) if args.analysis else None
        predictor = LightGBMPredictor(args.model_dir) if args.model_dir else None
        report = scan(request, analyzer, predictor)
        _emit(report, args)
        return report["exit_code"]
    except (GuardError, OSError, ValueError, RecursionError) as exc:
        error = {"status": "error", "exit_code": 2, "error": str(exc)}
        print(json.dumps(error, ensure_ascii=True), file=sys.stderr)
        return 2
