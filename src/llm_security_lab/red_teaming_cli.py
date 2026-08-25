"""Command-line entry point for the Day 29 red-team experiment."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from llm_security_lab.cli import write_raw_evidence
from llm_security_lab.red_teaming import (
    available_red_team_experiments,
    run_red_team_experiment,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the bounded Day 29 red-team experiment.")
    parser.add_argument("--experiment", choices=available_red_team_experiments(), required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        evidence = run_red_team_experiment(args.experiment, args.runtime_dir)
        if args.output is not None:
            output_path = write_raw_evidence(args.output, evidence)
            print(f"raw evidence written to {output_path}", file=sys.stderr)
        else:
            print(json.dumps(evidence, ensure_ascii=False, indent=2))
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"red-team experiment failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
