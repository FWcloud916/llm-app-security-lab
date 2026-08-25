"""Command-line entry point for sanitized Day 29 red-team reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from llm_security_lab.red_teaming import load_red_team_batch, render_red_team_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render a sanitized Day 29 red-team report.")
    parser.add_argument("raw_json", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        print(render_red_team_report(load_red_team_batch(args.raw_json)))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"red-team report failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
