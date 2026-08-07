"""Render a compact, sanitized report from a repeated raw evidence batch."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from llm_security_lab.lab import summarize_planned_runs, summarize_runs

PREDICATE_LABELS = {
    "canary_in_request": "request",
    "canary_in_model_response": "model response",
    "canary_in_fixture_evidence": "fixture evidence",
    "canary_in_full_stdout": "full stdout",
    "override_marker_in_model_response": "override marker in model response",
    "target_marker_in_model_response": "target marker in model response",
    "injection_marker_in_model_response": "injection marker in model response",
}


def predicate_label(name: str) -> str:
    """Return a stable public label for one observed predicate."""
    return PREDICATE_LABELS.get(name, name.replace("_", " "))


def load_batch(path: Path) -> dict[str, Any]:
    """Load one raw batch and reject incomplete or inconsistent evidence."""
    batch = json.loads(path.read_text(encoding="utf-8"))
    schema_version = batch.get("schema_version")
    if schema_version not in {1, 2}:
        raise ValueError("unsupported evidence batch schema version")
    runs = batch.get("runs")
    if not isinstance(runs, list):
        raise ValueError("evidence batch is incomplete")
    if schema_version == 1:
        if len(runs) != batch.get("repeat"):
            raise ValueError("evidence batch is incomplete")
        summary = summarize_runs(runs)
    else:
        run_plan = batch.get("run_plan")
        if not isinstance(run_plan, list):
            raise ValueError("planned evidence batch is missing its run plan")
        summary = summarize_planned_runs(runs, run_plan)
    if summary != batch.get("summary"):
        raise ValueError("stored summary does not match raw runs")
    if summary["experiment_id"] != batch.get("experiment_id"):
        raise ValueError("batch experiment id does not match its runs")
    if schema_version == 1 and summary["scenario"] != batch.get("scenario"):
        raise ValueError("batch scenario does not match its runs")
    return batch


def render_report(batch: dict[str, Any]) -> str:
    """Return a human-readable report without raw fixture or prompt contents."""
    if batch["schema_version"] == 2:
        return render_planned_report(batch)

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
    predicate_names = tuple(summary["true_counts"])
    for index, run in enumerate(runs, start=1):
        observation = run["observations"]
        values = " | ".join(
            f"{predicate_label(name)}={'TRUE' if observation[name] else 'FALSE'}"
            for name in predicate_names
        )
        lines.append(f"  {index}. {run['recorded_at']} | {values}")
    lines.extend(["", "True counts:"])
    lines.extend(
        f"  {predicate_label(name)}: {summary['true_counts'][name]}/{summary['runs']}"
        for name in predicate_names
    )
    return "\n".join(lines)


def render_planned_report(batch: dict[str, Any]) -> str:
    """Return a sanitized report for a complete schema-v3 experiment plan."""
    runs = batch["runs"]
    summary = batch["summary"]
    first = runs[0]
    lines = [
        f"Experiment: {summary['experiment_id']}",
        f"Planned runs: {summary['runs']}",
        f"Ollama: {first['ollama_version']}",
        f"Model: {first['model']['name']}",
        f"Digest: {summary['model_digest']}",
        "Tools sent: false",
        "Output sink: stdout",
    ]
    for scenario in summary["scenario_order"]:
        scenario_runs = [run for run in runs if run["scenario"] == scenario]
        scenario_summary = summary["scenarios"][scenario]
        scenario_first = scenario_runs[0]
        lines.extend(["", f"Scenario: {scenario}", f"Runs: {scenario_summary['runs']}"])
        lines.append("Fixture hashes:")
        fixtures = [*scenario_first["fixtures"]["notes"], scenario_first["fixtures"]["target"]]
        lines.extend(f"  {fixture['path']}: {fixture['sha256']}" for fixture in fixtures)
        lines.append("Per-run observations:")
        predicate_names = tuple(scenario_summary["true_counts"])
        for run in scenario_runs:
            observation = run["observations"]
            values = " | ".join(
                f"{predicate_label(name)}={'TRUE' if observation[name] else 'FALSE'}"
                for name in predicate_names
            )
            options = json.dumps(run["request"]["options"], sort_keys=True)
            lines.append(f"  {run['run_id']} | options={options} | {values}")
        lines.append("True counts:")
        lines.extend(
            f"  {predicate_label(name)}: {scenario_summary['true_counts'][name]}/"
            f"{scenario_summary['runs']}"
            for name in predicate_names
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
