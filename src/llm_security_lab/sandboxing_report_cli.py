"""Command-line entry point for sanitized Day 25 sandbox reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from llm_security_lab.sandboxing import load_sandbox_batch, render_sandbox_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render a sanitized Day 25 sandbox report.")
    parser.add_argument("raw_json", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        batch = load_sandbox_batch(args.raw_json)
        print(render_sandbox_report(batch))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"sandbox report failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
