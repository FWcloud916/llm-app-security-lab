"""Render a compact, sanitized report from a repeated raw evidence batch."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from llm_security_lab.lab import summarize_runs

PREDICATE_LABELS = {
    "canary_in_request": "request",
    "canary_in_model_response": "model response",
    "canary_in_fixture_evidence": "fixture evidence",
    "canary_in_full_stdout": "full stdout",
}


def load_batch(path: Path) -> dict[str, Any]:
    """Load one raw batch and reject incomplete or inconsistent evidence."""
    batch = json.loads(path.read_text(encoding="utf-8"))
    if batch.get("schema_version") != 1:
        raise ValueError("unsupported evidence batch schema version")
    runs = batch.get("runs")
    if not isinstance(runs, list) or len(runs) != batch.get("repeat"):
        raise ValueError("evidence batch is incomplete")

    summary = summarize_runs(runs)
    if summary != batch.get("summary"):
        raise ValueError("stored summary does not match raw runs")
    if summary["experiment_id"] != batch.get("experiment_id"):
        raise ValueError("batch experiment id does not match its runs")
    if summary["scenario"] != batch.get("scenario"):
        raise ValueError("batch scenario does not match its runs")
    return batch


def render_report(batch: dict[str, Any]) -> str:
    """Return a human-readable report without raw fixture or prompt contents."""
    runs = batch["runs"]
    summary = batch["summary"]
    first = runs[0]
    lines = [
        f"Experiment: {summary['experiment_id']}",
        f"Scenario: {summary['scenario']}",
        f"Runs: {summary['runs']}",
        f"Ollama: {first['ollama_version']}",
        f"Model: {first['model']['name']}",
        f"Digest: {summary['model_digest']}",
        "Options: " + json.dumps(first["request"]["options"], sort_keys=True),
        "Tools sent: false",
        "Output sink: stdout",
        "",
        "Fixture hashes:",
    ]
    fixtures = [*first["fixtures"]["notes"], first["fixtures"]["target"]]
    lines.extend(f"  {fixture['path']}: {fixture['sha256']}" for fixture in fixtures)
    lines.extend(["", "Per-run observations:"])
    for index, run in enumerate(runs, start=1):
        observation = run["observations"]
        values = " | ".join(
            f"{label}={'TRUE' if observation[name] else 'FALSE'}"
            for name, label in PREDICATE_LABELS.items()
        )
        lines.append(f"  {index}. {run['recorded_at']} | {values}")
    lines.extend(["", "True counts:"])
    lines.extend(
        f"  {label}: {summary['true_counts'][name]}/{summary['runs']}"
        for name, label in PREDICATE_LABELS.items()
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Summarize a repeated lab evidence batch.")
    parser.add_argument("raw_json", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        batch = load_batch(args.raw_json)
        report = render_report(batch)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"report failed: {error}", file=sys.stderr)
        return 1
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
