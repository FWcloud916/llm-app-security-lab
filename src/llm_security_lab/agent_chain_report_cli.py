"""Command-line entry point for sanitized Day 21 Agent attack-chain reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from llm_security_lab.agent_chain import load_agent_chain_batch, render_agent_chain_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render a sanitized Agent attack-chain report.")
    parser.add_argument("raw_json", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        batch = load_agent_chain_batch(args.raw_json)
        report = render_agent_chain_report(batch)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"agent-chain report failed: {error}", file=sys.stderr)
        return 1
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
