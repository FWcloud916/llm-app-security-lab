"""Command-line entry point for sanitized Day 18 agency reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from llm_security_lab.agency import load_agency_batch, render_agency_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render a sanitized agency experiment report.")
    parser.add_argument("raw_json", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        batch = load_agency_batch(args.raw_json)
        report = render_agency_report(batch)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"agency report failed: {error}", file=sys.stderr)
        return 1
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
