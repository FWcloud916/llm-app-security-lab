"""Command-line entry point for versioned lab experiments."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error

from llm_security_lab.lab import (
    DEFAULT_EXPERIMENT,
    available_experiments,
    load_definition,
    run,
    run_planned,
    run_repeated,
)


def positive_int(value: str) -> int:
    """Parse an integer that is safe for a bounded local repetition count."""
    parsed = int(value)
    if parsed < 1 or parsed > 20:
        raise argparse.ArgumentTypeError("repeat must be between 1 and 20")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a synthetic-data LLM application-security experiment."
    )
    parser.add_argument(
        "--experiment",
        choices=available_experiments(),
        default=DEFAULT_EXPERIMENT,
    )
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--scenario")
    selector.add_argument(
        "--run-plan",
        action="store_true",
        help="Execute every schema-v3 planned run exactly once in manifest order.",
    )
    parser.add_argument("--repeat", type=positive_int, default=1)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        definition = load_definition(args.experiment)
        if definition["schema_version"] == 3:
            if not args.run_plan:
                raise ValueError("schema-v3 experiments require --run-plan")
            if args.repeat != 1:
                raise ValueError("--repeat cannot modify a declared run plan")
            evidence = run_planned(args.experiment)
        else:
            if args.run_plan:
                raise ValueError("--run-plan requires a schema-v3 experiment")
            if args.scenario not in definition["scenarios"]:
                choices = ", ".join(sorted(definition["scenarios"]))
                raise ValueError(f"unknown scenario {args.scenario!r}; choose one of: {choices}")
            evidence = (
                run(args.scenario, experiment=args.experiment)
                if args.repeat == 1
                else run_repeated(args.experiment, args.scenario, args.repeat)
            )
    except (OSError, RuntimeError, TypeError, ValueError, urllib.error.URLError) as error:
        print(f"lab failed: {error}", file=sys.stderr)
        return 1

    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
