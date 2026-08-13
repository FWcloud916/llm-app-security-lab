"""Command-line entry point for the deterministic Day 18 agency experiment."""

from __future__ import annotations

import argparse
import json
import sys

from llm_security_lab.agency import available_agency_experiments, run_agency_experiment


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a deterministic synthetic agency experiment.")
    parser.add_argument("--experiment", choices=available_agency_experiments(), required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        evidence = run_agency_experiment(args.experiment)
    except (AssertionError, OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"agency experiment failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
