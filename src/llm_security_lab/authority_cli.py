"""Command-line entry point for the deterministic authority experiment."""

from __future__ import annotations

import argparse
import json
import sys

from llm_security_lab.authority import (
    available_authority_experiments,
    run_authority_experiment,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the all-cases authority experiment parser."""
    choices = available_authority_experiments()
    parser = argparse.ArgumentParser(
        description="Run a deterministic synthetic authority-boundary experiment."
    )
    parser.add_argument("--experiment", choices=choices, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        evidence = run_authority_experiment(args.experiment)
    except (AssertionError, OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"authority experiment failed: {error}", file=sys.stderr)
        return 1

    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
