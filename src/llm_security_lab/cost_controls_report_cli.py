"""Command-line entry point for sanitized Day 28 cost-control reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from llm_security_lab.cost_controls import load_cost_control_batch, render_cost_control_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render a sanitized Day 28 cost-control report.")
    parser.add_argument("raw_json", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = render_cost_control_report(load_cost_control_batch(args.raw_json))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"cost-control report failed: {error}", file=sys.stderr)
        return 1
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
