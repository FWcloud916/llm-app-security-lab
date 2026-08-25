"""Run the deterministic Day 28 abuse and cost-control experiment."""

from __future__ import annotations

import json
import socket
from collections import Counter, defaultdict, deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

from llm_security_lab.lab import (
    EXPERIMENT_ID_PATTERN,
    EXPERIMENTS_ROOT,
    experiment_root,
    read_fixture,
)

COST_CONTROL_RUNNER = "deterministic_cost_controls"
COST_CONTROL_SCHEMA_VERSION = 1
PROFILES = ("unbounded", "layered_controls")
REJECTION_REASONS = (
    "request_rate_limit",
    "input_token_limit",
    "output_token_limit",
    "total_token_limit",
    "concurrency_limit",
    "budget_limit",
)


def available_cost_control_experiments() -> list[str]:
    """Return experiment IDs owned by the Day 28 runner."""
    if not EXPERIMENTS_ROOT.is_dir():
        return []
    names: list[str] = []
    for path in EXPERIMENTS_ROOT.iterdir():
        if not path.is_dir() or EXPERIMENT_ID_PATTERN.fullmatch(path.name) is None:
            continue
        try:
            definition = json.loads((path / "experiment.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if definition.get("runner") == COST_CONTROL_RUNNER:
            names.append(path.name)
    return sorted(names)


def _load_json_fixture(relative_path: str, experiment: str) -> tuple[Any, dict[str, str]]:
    fixture = read_fixture(relative_path, experiment)
    try:
        value = json.loads(fixture["content"])
    except json.JSONDecodeError as error:
        raise ValueError(f"fixture is not valid JSON: {relative_path}") from error
    return value, {"path": fixture["path"], "sha256": fixture["sha256"]}


def load_cost_control_definition(experiment: str) -> dict[str, Any]:
    """Load and validate one Day 28 experiment definition."""
    definition = json.loads(
        (experiment_root(experiment) / "experiment.json").read_text(encoding="utf-8")
    )
    if definition.get("schema_version") != COST_CONTROL_SCHEMA_VERSION:
        raise ValueError("unsupported cost-control experiment schema version")
    if definition.get("id") != experiment:
        raise ValueError("cost-control experiment id does not match its bundle directory")
    if definition.get("runner") != COST_CONTROL_RUNNER:
        raise ValueError("experiment is not a deterministic cost-control experiment")
    if definition.get("profiles") != list(PROFILES):
        raise ValueError("cost-control profiles must match the fixed comparison order")
    for field in ("policy", "cases"):
        if not isinstance(definition.get(field), str):
            raise ValueError(f"cost-control experiment {field} must be a fixture path")
    return definition


def _validate_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("cost-control policy requires schema_version 1")
    integer_fields = (
        "request_window_ms",
        "max_requests_per_subject",
        "max_input_tokens",
        "max_output_tokens",
        "max_total_tokens",
        "max_concurrent_requests_per_subject",
        "budget_window_ms",
        "max_token_budget_per_subject",
    )
    if (
        not isinstance(value.get("version"), str)
        or not value["version"]
        or any(
            not isinstance(value.get(field), int) or value[field] <= 0 for field in integer_fields
        )
        or value["max_total_tokens"] > value["max_input_tokens"] + value["max_output_tokens"]
    ):
        raise ValueError("cost-control policy is incomplete")
    return value


def _validate_expected(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("cost-control case requires expected results")
    reasons = value.get("controlled_rejections")
    if (
        not isinstance(value.get("unbounded_admitted"), int)
        or value["unbounded_admitted"] < 0
        or not isinstance(value.get("controlled_admitted"), int)
        or value["controlled_admitted"] < 0
        or not isinstance(value.get("controlled_peak_concurrency"), int)
        or value["controlled_peak_concurrency"] < 0
        or not isinstance(reasons, dict)
        or any(
            reason not in REJECTION_REASONS or not isinstance(count, int) or count <= 0
            for reason, count in reasons.items()
        )
    ):
        raise ValueError("cost-control expected results are invalid")
    return value


def _validate_cases(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("cost-control cases require schema_version 1")
    cases = value.get("cases")
    if value.get("synthetic_data_only") is not True or not isinstance(cases, list) or not cases:
        raise ValueError("cost-control cases must declare non-empty synthetic cases")
    seen_cases: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("cost-control case must be an object")
        case_id = case.get("id")
        events = case.get("events")
        if (
            not isinstance(case_id, str)
            or not case_id
            or case_id in seen_cases
            or not isinstance(events, list)
            or not events
        ):
            raise ValueError("cost-control case is incomplete")
        seen_cases.add(case_id)
        requests: dict[str, dict[str, Any]] = {}
        last_at = -1
        for event in events:
            if not isinstance(event, dict) or event.get("kind") not in {"request", "complete"}:
                raise ValueError("cost-control event is invalid")
            at_ms = event.get("at_ms")
            request_id = event.get("request_id")
            if (
                not isinstance(at_ms, int)
                or at_ms < last_at
                or not isinstance(request_id, str)
                or not request_id
            ):
                raise ValueError("cost-control event order or request id is invalid")
            last_at = at_ms
            if event["kind"] == "request":
                if request_id in requests:
                    raise ValueError("cost-control request ids must be unique per case")
                if (
                    not isinstance(event.get("subject_id"), str)
                    or not event["subject_id"].startswith("synthetic-")
                    or not isinstance(event.get("input_tokens"), int)
                    or event["input_tokens"] < 0
                    or not isinstance(event.get("max_output_tokens"), int)
                    or event["max_output_tokens"] < 0
                ):
                    raise ValueError("cost-control request event is invalid")
                requests[request_id] = event
            else:
                request = requests.get(request_id)
                if (
                    request is None
                    or not isinstance(event.get("actual_output_tokens"), int)
                    or event["actual_output_tokens"] < 0
                    or event["actual_output_tokens"] > request["max_output_tokens"]
                ):
                    raise ValueError("cost-control completion event is invalid")
        _validate_expected(case.get("expected"))
    return value


def _rejection_reason(
    *,
    event: dict[str, Any],
    policy: dict[str, Any],
    arrivals: deque[int],
    active_count: int,
    committed_budget: int,
) -> str | None:
    if len(arrivals) > policy["max_requests_per_subject"]:
        return "request_rate_limit"
    if event["input_tokens"] > policy["max_input_tokens"]:
        return "input_token_limit"
    if event["max_output_tokens"] > policy["max_output_tokens"]:
        return "output_token_limit"
    requested_tokens = event["input_tokens"] + event["max_output_tokens"]
    if requested_tokens > policy["max_total_tokens"]:
        return "total_token_limit"
    if active_count >= policy["max_concurrent_requests_per_subject"]:
        return "concurrency_limit"
    if committed_budget + requested_tokens > policy["max_token_budget_per_subject"]:
        return "budget_limit"
    return None


def _run_case(case: dict[str, Any], policy: dict[str, Any], profile: str) -> dict[str, Any]:
    arrivals: dict[str, deque[int]] = defaultdict(deque)
    active: dict[str, dict[str, Any]] = {}
    spent: Counter[str] = Counter()
    held: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    outcomes: list[dict[str, Any]] = []
    admitted = 0
    requests_seen = 0
    completions_seen = 0
    ignored_completions = 0
    estimated_tokens_admitted = 0
    peak_concurrency = 0

    for event in case["events"]:
        if event["kind"] == "request":
            requests_seen += 1
            subject = event["subject_id"]
            subject_arrivals = arrivals[subject]
            while (
                subject_arrivals
                and event["at_ms"] - subject_arrivals[0] >= policy["request_window_ms"]
            ):
                subject_arrivals.popleft()
            subject_arrivals.append(event["at_ms"])
            active_count = sum(item["subject_id"] == subject for item in active.values())
            requested_tokens = event["input_tokens"] + event["max_output_tokens"]
            reason = None
            if profile == "layered_controls":
                reason = _rejection_reason(
                    event=event,
                    policy=policy,
                    arrivals=subject_arrivals,
                    active_count=active_count,
                    committed_budget=spent[subject] + held[subject],
                )
            if reason is not None:
                reasons[reason] += 1
                outcomes.append(
                    {
                        "kind": "request",
                        "request_id": event["request_id"],
                        "decision": "reject",
                        "reason": reason,
                    }
                )
                continue
            admitted += 1
            estimated_tokens_admitted += requested_tokens
            held[subject] += requested_tokens
            active[event["request_id"]] = {
                "subject_id": subject,
                "input_tokens": event["input_tokens"],
                "reserved_tokens": requested_tokens,
            }
            peak_concurrency = max(
                peak_concurrency,
                sum(item["subject_id"] == subject for item in active.values()),
            )
            outcomes.append(
                {
                    "kind": "request",
                    "request_id": event["request_id"],
                    "decision": "admit",
                    "reason": "",
                }
            )
            continue

        completions_seen += 1
        admitted_request = active.pop(event["request_id"], None)
        if admitted_request is None:
            ignored_completions += 1
            outcomes.append(
                {
                    "kind": "complete",
                    "request_id": event["request_id"],
                    "decision": "ignored_not_admitted",
                }
            )
            continue
        subject = admitted_request["subject_id"]
        held[subject] -= admitted_request["reserved_tokens"]
        spent[subject] += admitted_request["input_tokens"] + event["actual_output_tokens"]
        outcomes.append(
            {
                "kind": "complete",
                "request_id": event["request_id"],
                "decision": "settled",
            }
        )

    budget_overrun = sum(
        max(0, spent[subject] + held[subject] - policy["max_token_budget_per_subject"])
        for subject in set(spent) | set(held)
    )
    return {
        "profile": profile,
        "requests_seen": requests_seen,
        "admitted_requests": admitted,
        "rejected_requests": requests_seen - admitted,
        "rejection_reasons": dict(sorted(reasons.items())),
        "completion_events": completions_seen,
        "ignored_completions": ignored_completions,
        "peak_concurrency": peak_concurrency,
        "estimated_tokens_admitted": estimated_tokens_admitted,
        "settled_token_units": sum(spent.values()),
        "remaining_reserved_token_units": sum(held.values()),
        "budget_overrun_token_units": budget_overrun,
        "outcomes": outcomes,
    }


def _summary(case_results: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for profile in PROFILES:
        results = [case["profiles"][profile] for case in case_results]
        reasons: Counter[str] = Counter()
        for result in results:
            reasons.update(result["rejection_reasons"])
        summary[profile] = {
            "requests_seen": sum(result["requests_seen"] for result in results),
            "admitted_requests": sum(result["admitted_requests"] for result in results),
            "rejected_requests": sum(result["rejected_requests"] for result in results),
            "rejection_reasons": dict(sorted(reasons.items())),
            "peak_concurrency": max(result["peak_concurrency"] for result in results),
            "estimated_tokens_admitted": sum(
                result["estimated_tokens_admitted"] for result in results
            ),
            "settled_token_units": sum(result["settled_token_units"] for result in results),
            "remaining_reserved_token_units": sum(
                result["remaining_reserved_token_units"] for result in results
            ),
            "budget_overrun_token_units": sum(
                result["budget_overrun_token_units"] for result in results
            ),
        }
    return summary


def _prediction_checks(case_results: list[dict[str, Any]]) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    for case in case_results:
        expected = case["expected"]
        unbounded = case["profiles"]["unbounded"]
        controlled = case["profiles"]["layered_controls"]
        checks[case["id"]] = (
            unbounded["admitted_requests"] == expected["unbounded_admitted"]
            and controlled["admitted_requests"] == expected["controlled_admitted"]
            and controlled["rejection_reasons"] == expected["controlled_rejections"]
            and controlled["peak_concurrency"] == expected["controlled_peak_concurrency"]
        )
    return checks


def run_cost_control_experiment(experiment: str) -> dict[str, Any]:
    """Run the fixed Day 28 unbounded-versus-controlled comparison once."""
    definition = load_cost_control_definition(experiment)
    policy_value, policy_evidence = _load_json_fixture(definition["policy"], experiment)
    cases_value, cases_evidence = _load_json_fixture(definition["cases"], experiment)
    policy = _validate_policy(policy_value)
    cases = _validate_cases(cases_value)
    network_error = RuntimeError("Day 28 forbids network access")
    with (
        patch("socket.create_connection", side_effect=network_error),
        patch.object(socket.socket, "connect", side_effect=network_error),
    ):
        case_results = [
            {
                "id": case["id"],
                "expected": case["expected"],
                "profiles": {profile: _run_case(case, policy, profile) for profile in PROFILES},
            }
            for case in cases["cases"]
        ]
    predictions = _prediction_checks(case_results)
    return {
        "schema_version": 1,
        "experiment": experiment,
        "runner": COST_CONTROL_RUNNER,
        "generated_at": datetime.now(UTC).isoformat(),
        "fixtures": [policy_evidence, cases_evidence],
        "policy": policy,
        "case_results": case_results,
        "summary": _summary(case_results),
        "prediction_checks": predictions,
        "all_predictions_matched": all(predictions.values()),
        "safety_boundary": {
            "synthetic_data_only": True,
            "model_calls": 0,
            "network_calls": 0,
            "external_side_effects": 0,
            "real_billing_events": 0,
        },
    }


def _validated_batch(batch: Any) -> dict[str, Any]:
    if not isinstance(batch, dict) or batch.get("runner") != COST_CONTROL_RUNNER:
        raise ValueError("raw evidence is not a Day 28 cost-control batch")
    experiment = batch.get("experiment")
    if not isinstance(experiment, str):
        raise ValueError("cost-control experiment id is missing")
    definition = load_cost_control_definition(experiment)
    policy_value, _ = _load_json_fixture(definition["policy"], experiment)
    cases_value, _ = _load_json_fixture(definition["cases"], experiment)
    policy = _validate_policy(policy_value)
    cases = _validate_cases(cases_value)
    expected_results = [
        {
            "id": case["id"],
            "expected": case["expected"],
            "profiles": {profile: _run_case(case, policy, profile) for profile in PROFILES},
        }
        for case in cases["cases"]
    ]
    if batch.get("policy") != policy or batch.get("case_results") != expected_results:
        raise ValueError("cost-control evidence does not match committed fixtures")
    expected_summary = _summary(expected_results)
    if batch.get("summary") != expected_summary:
        raise ValueError("cost-control summary does not match case results")
    predictions = _prediction_checks(expected_results)
    if batch.get("prediction_checks") != predictions or batch.get(
        "all_predictions_matched"
    ) is not all(predictions.values()):
        raise ValueError("cost-control prediction summary does not match results")
    if batch.get("all_predictions_matched") is not True:
        raise ValueError("cost-control experiment did not match preregistered predictions")
    expected_safety = {
        "synthetic_data_only": True,
        "model_calls": 0,
        "network_calls": 0,
        "external_side_effects": 0,
        "real_billing_events": 0,
    }
    if batch.get("safety_boundary") != expected_safety:
        raise ValueError("cost-control experiment violated its safety boundary")
    return batch


def load_cost_control_batch(path: Path) -> dict[str, Any]:
    """Load and validate raw Day 28 evidence."""
    return _validated_batch(json.loads(path.read_text(encoding="utf-8")))


def render_cost_control_report(batch: dict[str, Any]) -> str:
    """Render a sanitized report without request or subject identifiers."""
    batch = _validated_batch(batch)
    unbounded = batch["summary"]["unbounded"]
    controlled = batch["summary"]["layered_controls"]
    lines = [
        f"Experiment: {batch['experiment']}",
        f"Generated at: {batch['generated_at']}",
        f"Policy version: {batch['policy']['version']}",
        "",
        "Aggregate profiles:",
        f"- unbounded: requests={unbounded['requests_seen']}, admitted={unbounded['admitted_requests']}, rejected={unbounded['rejected_requests']}, estimated_tokens={unbounded['estimated_tokens_admitted']}, peak_concurrency={unbounded['peak_concurrency']}, budget_overrun={unbounded['budget_overrun_token_units']}",
        f"- layered_controls: requests={controlled['requests_seen']}, admitted={controlled['admitted_requests']}, rejected={controlled['rejected_requests']}, estimated_tokens={controlled['estimated_tokens_admitted']}, peak_concurrency={controlled['peak_concurrency']}, budget_overrun={controlled['budget_overrun_token_units']}",
        f"- controlled_rejection_reasons={json.dumps(controlled['rejection_reasons'], sort_keys=True)}",
        "",
        "Cases:",
    ]
    for case in batch["case_results"]:
        unbounded_case = case["profiles"]["unbounded"]
        controlled_case = case["profiles"]["layered_controls"]
        lines.append(
            f"- {case['id']}: unbounded_admitted={unbounded_case['admitted_requests']}, controlled_admitted={controlled_case['admitted_requests']}, controlled_rejections={json.dumps(controlled_case['rejection_reasons'], sort_keys=True)}, controlled_peak={controlled_case['peak_concurrency']}"
        )
    lines.extend(
        [
            "",
            f"Prediction checks: {json.dumps(batch['prediction_checks'], sort_keys=True)}",
            "Synthetic data only: true",
            "Model calls: 0",
            "Network calls: 0",
            "External side effects: 0",
            "Real billing events: 0",
        ]
    )
    return "\n".join(lines)
