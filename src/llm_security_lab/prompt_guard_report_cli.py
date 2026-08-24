"""Command-line entry point for sanitized Prompt Guard comparison reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from llm_security_lab.prompt_guard import load_prompt_guard_batch, render_prompt_guard_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render a sanitized Prompt Guard report.")
    parser.add_argument("raw_json", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = render_prompt_guard_report(load_prompt_guard_batch(args.raw_json))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"prompt-guard report failed: {error}", file=sys.stderr)
        return 1
    print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
