"""Command-line entry point for the Day 28 cost-control experiment."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from llm_security_lab.cli import write_raw_evidence
from llm_security_lab.cost_controls import (
    available_cost_control_experiments,
    run_cost_control_experiment,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the synthetic Day 28 cost-control experiment."
    )
    parser.add_argument("--experiment", choices=available_cost_control_experiments(), required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        evidence = run_cost_control_experiment(args.experiment)
        if args.output is not None:
            output_path = write_raw_evidence(args.output, evidence)
            print(f"raw evidence written to {output_path}", file=sys.stderr)
        else:
            print(json.dumps(evidence, ensure_ascii=False, indent=2))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"cost-control experiment failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
