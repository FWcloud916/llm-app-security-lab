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
    "jailbreak_marker_in_model_response": "jailbreak marker in model response",
    "visual_target_in_model_response": "visual target in model response",
    "injection_marker_in_source_bytes": "injection marker in source bytes",
    "injection_marker_in_extracted_document": "injection marker in extracted document",
    "injection_marker_in_request": "injection marker in request",
    "attack_source_in_source_bytes": "attack source in source bytes",
    "attack_source_in_extracted_document": "attack source in extracted document",
    "attack_source_in_request": "attack source in request",
    "injection_marker_in_corpus": "injection marker in corpus",
    "injection_marker_in_retrieved_chunks": "injection marker in retrieved chunks",
    "poisoned_policy_active_in_source_state": "poisoned policy active in source state",
    "poisoned_policy_in_corpus": "poisoned policy in corpus",
    "poisoned_policy_in_retrieved_chunks": "poisoned policy in retrieved chunks",
    "poisoned_policy_in_request": "poisoned policy in request",
    "knowledge_base_stale": "knowledge base stale",
    "safe_policy_in_model_response": "safe policy in model response",
    "poisoned_policy_in_model_response": "poisoned policy in model response",
    "safe_policy_in_corpus": "safe policy in corpus",
    "safe_policy_eligible_after_filter": "safe policy eligible after filter",
    "safe_policy_selected": "safe policy selected",
    "same_tenant_attack_in_corpus": "same-tenant attack in corpus",
    "same_tenant_attack_eligible_after_filter": "same-tenant attack eligible after filter",
    "same_tenant_attack_selected": "same-tenant attack selected",
    "cross_tenant_policy_in_corpus": "cross-tenant policy in corpus",
    "cross_tenant_policy_eligible_after_filter": "cross-tenant policy eligible after filter",
    "cross_tenant_policy_selected": "cross-tenant policy selected",
    "vector_engines_agree": "exact cosine and Qdrant agree",
    "tenant_filter_applied": "tenant filter applied",
    "selected_matches_requested_tenant": "selected chunks match requested tenant",
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
        f"Tools sent: {str(first['safety_boundary']['tools_sent']).lower()}",
        "Tool execution: " + str(first["safety_boundary"].get("tool_execution", False)).lower(),
        "Image input: " + str(first["safety_boundary"].get("images_sent", False)).lower(),
        "OCR performed: " + str(first["safety_boundary"].get("ocr_performed", False)).lower(),
        "Output sink: stdout",
        "",
        "Fixture hashes:",
    ]
    fixtures = _report_fixtures(first)
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
        f"Tools sent: {str(first['safety_boundary']['tools_sent']).lower()}",
        "Tool execution: " + str(first["safety_boundary"].get("tool_execution", False)).lower(),
        "Image input: " + str(first["safety_boundary"].get("images_sent", False)).lower(),
        "OCR performed: " + str(first["safety_boundary"].get("ocr_performed", False)).lower(),
        "Output sink: stdout",
    ]
    embedding_model = first.get("embedding_model")
    if embedding_model is not None:
        lines.extend(
            [
                f"Embedding model: {embedding_model['name']}",
                f"Embedding digest: {embedding_model['digest']}",
            ]
        )
    for scenario in summary["scenario_order"]:
        scenario_runs = [run for run in runs if run["scenario"] == scenario]
        scenario_summary = summary["scenarios"][scenario]
        scenario_first = scenario_runs[0]
        lines.extend(
            [
                "",
                f"Scenario: {scenario}",
                f"Runs: {scenario_summary['runs']}",
                f"Turns per run: {scenario_summary.get('turns_per_run', 1)}",
            ]
        )
        lines.append("Fixture hashes:")
        fixtures = _report_fixtures(scenario_first)
        lines.extend(f"  {fixture['path']}: {fixture['sha256']}" for fixture in fixtures)
        target = scenario_first["fixtures"].get("target", {})
        if "extracted_sha256" in target:
            lines.append(f"  extracted text: {target['extracted_sha256']}")
            lines.append(
                "  extractor: "
                + json.dumps(target["extractor"], ensure_ascii=False, sort_keys=True)
            )
        knowledge_base = scenario_first.get("knowledge_base")
        if knowledge_base is not None:
            corpus = knowledge_base["corpus"]
            lines.extend(
                [
                    "Knowledge-base lifecycle:",
                    f"  through event: {knowledge_base['through_event']}",
                    f"  corpus built at event: {corpus['built_at_event']}",
                    f"  corpus stale: {str(corpus['stale']).lower()}",
                    f"  corpus sha256: {corpus['sha256']}",
                    "  active sources:",
                ]
            )
            lines.extend(
                f"    {entry['source_id']}@v{entry['version']} | "
                f"sha256={entry['document']['sha256']}"
                for entry in knowledge_base["active_sources"]
            )
        retrieval = scenario_first.get("retrieval")
        if retrieval is not None:
            lines.extend(
                [
                    "Retrieval:",
                    f"  chunking: {retrieval['chunking']}",
                    f"  strategy: {retrieval['strategy']}",
                    f"  top_k: {retrieval['top_k']}",
                    f"  serialized context: {retrieval['serialized_sha256']}",
                    "  selected chunks:",
                ]
            )
            lines.extend(
                f"    {item['rank']}. {item['id']} | score={item['score']} | "
                f"sha256={item['sha256']}"
                for item in retrieval["selected"]
            )
        vector_retrieval = scenario_first.get("vector_retrieval")
        if vector_retrieval is not None:
            vector_embedding = vector_retrieval["embedding"]
            lines.extend(
                [
                    "Vector retrieval:",
                    f"  embedding model: {vector_embedding['model']}",
                    f"  dimension: {vector_embedding['dimension']}",
                    f"  input count: {vector_embedding['input_count']}",
                    f"  strategy: {vector_retrieval['strategy']}",
                    f"  top_k: {vector_retrieval['top_k']}",
                    f"  requested tenant: {vector_retrieval['requested_tenant']}",
                    f"  tenant filter: {vector_retrieval['tenant_filter']}",
                    f"  engines agree: {str(vector_retrieval['engines_agree']).lower()}",
                    f"  serialized context: {vector_retrieval['serialized_sha256']}",
                    "  exact cosine selected chunks:",
                ]
            )
            lines.extend(
                f"    {item['rank']}. {item['id']} | tenant={item['tenant_id']} | "
                f"score={item['score']:.8f} | sha256={item['sha256']}"
                for item in vector_retrieval["exact_selected"]
            )
            lines.append("  Qdrant selected chunks:")
            lines.extend(
                f"    {item['rank']}. {item['id']} | tenant={item['tenant_id']} | "
                f"score={item['score']:.8f} | sha256={item['sha256']}"
                for item in vector_retrieval["qdrant_selected"]
            )
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


def _report_fixtures(run: dict[str, Any]) -> list[dict[str, Any]]:
    """Return fixture hashes without exposing fixture contents."""
    fixtures = run["fixtures"]
    if "event_log" in fixtures:
        return [fixtures["event_log"], *fixtures.get("documents", [])]
    if "documents" in fixtures:
        return list(fixtures["documents"])
    if "message" in fixtures:
        return [fixtures["message"]]
    result = [*fixtures["notes"], fixtures["target"]]
    if "image" in fixtures:
        result.append(fixtures["image"])
    return result


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
