"""Command-line entry point for the Day 25 sandbox experiment."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
from pathlib import Path

from llm_security_lab.cli import write_raw_evidence
from llm_security_lab.sandboxing import (
    available_sandbox_experiments,
    run_fixed_experiment,
    run_model_experiment,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the Day 25 Agent sandbox experiment.")
    parser.add_argument("--experiment", choices=available_sandbox_experiments(), required=True)
    parser.add_argument("--mode", choices=("fixed", "model"), required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        evidence = (
            run_fixed_experiment(args.experiment)
            if args.mode == "fixed"
            else run_model_experiment(args.experiment)
        )
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
        subprocess.SubprocessError,
        urllib.error.URLError,
    ) as error:
        print(f"sandbox experiment failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
