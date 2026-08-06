"""Command-line entry point for sanitized authority experiment reports."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from llm_security_lab.authority import load_authority_batch, render_authority_report


def build_parser() -> argparse.ArgumentParser:
    """Build the authority report parser."""
    parser = argparse.ArgumentParser(
        description="Render a sanitized deterministic authority experiment report."
    )
    parser.add_argument("raw_json", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        batch = load_authority_batch(args.raw_json)
        report = render_authority_report(batch)
    except (OSError, TypeError, ValueError, UnicodeDecodeError) as error:
        print(f"authority report failed: {error}", file=sys.stderr)
        return 1
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
