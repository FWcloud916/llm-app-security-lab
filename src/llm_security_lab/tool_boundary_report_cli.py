"""Command-line entry point for sanitized Day 19 tool-boundary reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from llm_security_lab.tool_boundary import load_tool_boundary_batch, render_tool_boundary_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render a sanitized tool-boundary report.")
    parser.add_argument("raw_json", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        batch = load_tool_boundary_batch(args.raw_json)
        report = render_tool_boundary_report(batch)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"tool-boundary report failed: {error}", file=sys.stderr)
        return 1
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
