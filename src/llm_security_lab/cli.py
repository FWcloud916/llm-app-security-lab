"""Command-line entry point for versioned lab scenarios."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error

from llm_security_lab.lab import load_definition, run


def build_parser() -> argparse.ArgumentParser:
    definition = load_definition()
    parser = argparse.ArgumentParser(
        description="Run a synthetic-data LLM application-security scenario."
    )
    parser.add_argument(
        "--scenario",
        choices=sorted(definition["scenarios"]),
        required=True,
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        evidence = run(args.scenario)
    except (OSError, RuntimeError, TypeError, ValueError, urllib.error.URLError) as error:
        print(f"lab failed: {error}", file=sys.stderr)
        return 1

    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
