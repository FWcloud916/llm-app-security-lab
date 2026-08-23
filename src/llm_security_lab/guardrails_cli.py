"""Command-line entry point for the Day 24 Guardrails experiment."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import urllib.error
from pathlib import Path

from llm_security_lab.cli import write_raw_evidence
from llm_security_lab.guardrails import (
    available_guardrails_experiments,
    run_guardrails_experiment,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a Day 24 Guardrails comparison batch.")
    parser.add_argument("--experiment", choices=available_guardrails_experiments(), required=True)
    parser.add_argument("--mode", choices=("paired", "end-to-end"), required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        evidence = asyncio.run(run_guardrails_experiment(args.experiment, args.mode))
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
        print(f"guardrails experiment failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
