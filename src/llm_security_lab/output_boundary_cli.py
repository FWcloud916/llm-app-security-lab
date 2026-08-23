"""Command-line entry point for the Day 23 output-boundary experiment."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
from pathlib import Path

from llm_security_lab.cli import write_raw_evidence
from llm_security_lab.output_boundary import (
    available_output_boundary_experiments,
    run_output_boundary_experiment,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a paired output-boundary experiment.")
    parser.add_argument(
        "--experiment", choices=available_output_boundary_experiments(), required=True
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write raw JSON under ignored evidence/raw/ or results/ instead of stdout.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        evidence = run_output_boundary_experiment(args.experiment)
        if args.output is not None:
            output_path = write_raw_evidence(args.output, evidence)
            print(f"raw evidence written to {output_path}", file=sys.stderr)
        else:
            print(json.dumps(evidence, ensure_ascii=False, indent=2))
    except (
        AssertionError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        urllib.error.URLError,
    ) as error:
        print(f"output-boundary experiment failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
