"""Command-line entry point for the deterministic Day 20 supply-chain experiment."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from llm_security_lab.cli import write_raw_evidence
from llm_security_lab.supply_chain import (
    available_supply_chain_experiments,
    run_supply_chain_experiment,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a deterministic synthetic supply-chain intake experiment."
    )
    parser.add_argument("--experiment", choices=available_supply_chain_experiments(), required=True)
    parser.add_argument(
        "--output",
        type=Path,
        help="Write raw JSON under ignored evidence/raw/ or results/ instead of stdout.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        evidence = run_supply_chain_experiment(args.experiment)
        if args.output is not None:
            output_path = write_raw_evidence(args.output, evidence)
            print(f"raw evidence written to {output_path}", file=sys.stderr)
        else:
            print(json.dumps(evidence, ensure_ascii=False, indent=2))
    except (AssertionError, OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"supply-chain experiment failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
