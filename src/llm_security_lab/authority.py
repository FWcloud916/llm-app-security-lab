"""Run the deterministic Day 6 authority-boundary experiment."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from llm_security_lab.lab import (
    EXPERIMENT_ID_PATTERN,
    EXPERIMENTS_ROOT,
    experiment_root,
    read_fixture,
)

AUTHORITY_RUNNER = "deterministic_authority_gate"
AUTHORITY_SCHEMA_VERSION = 1
ALLOWED_PROPOSAL_FIELDS = frozenset({"action", "resource_id"})
GENERIC_DENIAL = {"status": "denied", "message": "request denied"}


def available_authority_experiments() -> list[str]:
    """Return experiment IDs owned by the deterministic authority runner."""
    if not EXPERIMENTS_ROOT.is_dir():
        return []

    names: list[str] = []
    for path in EXPERIMENTS_ROOT.iterdir():
        if not path.is_dir() or not EXPERIMENT_ID_PATTERN.fullmatch(path.name):
            continue
        definition_path = path / "experiment.json"
        try:
            definition = json.loads(definition_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if definition.get("runner") == AUTHORITY_RUNNER:
            names.append(path.name)
    return sorted(names)


def load_authority_definition(experiment: str) -> dict[str, Any]:
    """Load and validate one deterministic authority experiment definition."""
    definition_path = experiment_root(experiment) / "experiment.json"
    definition = json.loads(definition_path.read_text(encoding="utf-8"))
    if definition.get("schema_version") != AUTHORITY_SCHEMA_VERSION:
        raise ValueError("unsupported authority experiment schema version")
    if definition.get("id") != experiment:
        raise ValueError("authority experiment id does not match its bundle directory")
    if definition.get("runner") != AUTHORITY_RUNNER:
        raise ValueError("experiment is not a deterministic authority experiment")
    cases = definition.get("cases")
    if not isinstance(cases, list) or not cases or not all(isinstance(item, str) for item in cases):
        raise ValueError("authority experiment cases must be a non-empty list of paths")
    for field in ("policy", "resources"):
        if not isinstance(definition.get(field), str):
            raise ValueError(f"authority experiment {field} must be a fixture path")
    return definition


def _load_json_fixture(
    relative_path: str, experiment: str
) -> tuple[dict[str, Any], dict[str, str]]:
    """Load one JSON fixture through the bundle-safe fixture boundary."""
    fixture = read_fixture(relative_path, experiment)
    try:
        value = json.loads(fixture["content"])
    except json.JSONDecodeError as error:
        raise ValueError(f"fixture is not valid JSON: {relative_path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"fixture must contain a JSON object: {relative_path}")
    return value, {"path": fixture["path"], "sha256": fixture["sha256"]}


def _load_bundle(
    experiment: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    """Load an authority definition and every fixture owned by its bundle."""
    definition = load_authority_definition(experiment)
    policy, policy_evidence = _load_json_fixture(definition["policy"], experiment)
    resources, resources_evidence = _load_json_fixture(definition["resources"], experiment)
    cases: list[dict[str, Any]] = []
    case_evidence: list[dict[str, str]] = []
    for relative_path in definition["cases"]:
        case, evidence = _load_json_fixture(relative_path, experiment)
        if not isinstance(case.get("id"), str) or not case["id"]:
            raise ValueError(f"authority case id is required: {relative_path}")
        cases.append(case)
        case_evidence.append(evidence)

    fixture_hashes = {
        policy_evidence["path"]: policy_evidence["sha256"],
        resources_evidence["path"]: resources_evidence["sha256"],
        **{item["path"]: item["sha256"] for item in case_evidence},
    }
    return definition, policy, resources, [*cases, {"fixture_hashes": fixture_hashes}]


def _parse_model_output(raw_output: Any) -> tuple[dict[str, Any] | None, str]:
    """Parse a model proposal without assigning any authority to its fields."""
    if not isinstance(raw_output, str):
        return None, "invalid_model_proposal"
    try:
        proposal = json.loads(raw_output)
    except json.JSONDecodeError:
        return None, "invalid_model_proposal"
    if not isinstance(proposal, dict):
        return None, "invalid_model_proposal"
    return proposal, ""


def _valid_identity(identity: Any) -> bool:
    """Accept only an application-established, validated synthetic identity."""
    return (
        isinstance(identity, dict)
        and identity.get("validation_result") == "valid"
        and isinstance(identity.get("subject_ref"), str)
        and bool(identity["subject_ref"])
        and isinstance(identity.get("auth_source"), str)
        and bool(identity["auth_source"])
    )


def _resource_map(resources: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Normalize canonical resource metadata and fail closed on malformed fixtures."""
    entries = resources.get("items")
    if not isinstance(entries, list):
        raise ValueError("resources fixture must contain an items list")
    normalized: dict[str, dict[str, Any]] = {}
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("resource entries must be objects")
        resource_id = item.get("id")
        if not isinstance(resource_id, str) or not resource_id or resource_id in normalized:
            raise ValueError("resource IDs must be unique, non-empty strings")
        normalized[resource_id] = item
    return normalized


def _allowed_tuples(policy: dict[str, Any]) -> set[tuple[str, str, str]]:
    """Load exact subject/action/resource tuples from the integrity-controlled policy fixture."""
    entries = policy.get("allow")
    if not isinstance(entries, list) or not isinstance(policy.get("version"), str):
        raise ValueError("policy fixture must contain version and allow list")
    tuples: set[tuple[str, str, str]] = set()
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("policy entries must be objects")
        values = tuple(item.get(key) for key in ("subject_ref", "action", "resource_id"))
        if not all(isinstance(value, str) and value for value in values):
            raise ValueError("policy entries require subject_ref, action, and resource_id")
        tuples.add(values)  # type: ignore[arg-type]
    return tuples


def _security_event(
    *,
    case: dict[str, Any],
    identity: Any,
    forbidden_fields: list[str],
    action: str | None,
    canonical_resource: str | None,
    policy_version: str,
    decision: str,
    reason_code: str,
) -> dict[str, Any]:
    """Build a minimal event without copying model output or secrets into evidence."""
    return {
        "event_name": "llm_authority_field_ignored",
        "interaction_id": case["interaction_id"],
        "subject_ref": identity.get("subject_ref") if _valid_identity(identity) else None,
        "auth_source": identity.get("auth_source") if isinstance(identity, dict) else None,
        "auth_validation_result": (
            identity.get("validation_result") if isinstance(identity, dict) else "missing"
        ),
        "forbidden_field_names": forbidden_fields,
        "action": action,
        "canonical_resource_reference": canonical_resource,
        "policy_version": policy_version,
        "decision": decision,
        "reason_code": reason_code,
        "severity": "warning",
    }


def evaluate_case(
    case: dict[str, Any],
    policy: dict[str, Any],
    resources: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Evaluate one model proposal against trusted application state and policy."""
    if not isinstance(case.get("interaction_id"), str) or not case["interaction_id"]:
        raise ValueError(f"case {case.get('id', '<unknown>')} requires interaction_id")

    proposal, parse_reason = _parse_model_output(case.get("model_output"))
    forbidden_fields = (
        sorted(set(proposal) - ALLOWED_PROPOSAL_FIELDS) if proposal is not None else []
    )
    action = proposal.get("action") if proposal is not None else None
    resource_id = proposal.get("resource_id") if proposal is not None else None
    identity = case.get("trusted_identity")
    policy_version = policy["version"]
    canonical_resource: str | None = None

    if proposal is None:
        decision = "deny"
        reason_code = parse_reason
    elif (
        not isinstance(action, str)
        or not action
        or not isinstance(resource_id, str)
        or not resource_id
    ):
        decision = "deny"
        reason_code = "invalid_model_proposal"
    elif not _valid_identity(identity):
        decision = "deny"
        reason_code = "missing_trusted_identity"
    elif resource_id not in resources:
        decision = "deny"
        reason_code = "unknown_resource"
    else:
        canonical_resource = resources[resource_id]["id"]
        permitted = (identity["subject_ref"], action, canonical_resource) in _allowed_tuples(policy)
        decision = "allow" if permitted else "deny"
        reason_code = "allowed" if permitted else "policy_denied"

    events = []
    if forbidden_fields:
        events.append(
            _security_event(
                case=case,
                identity=identity,
                forbidden_fields=forbidden_fields,
                action=action if isinstance(action, str) else None,
                canonical_resource=canonical_resource,
                policy_version=policy_version,
                decision=decision,
                reason_code=reason_code,
            )
        )

    return {
        "case_id": case["id"],
        "interaction_id": case["interaction_id"],
        "model_output": case.get("model_output"),
        "trusted_identity": identity,
        "expected": case.get("expected"),
        "observed": {
            "decision": decision,
            "reason_code": reason_code,
            "forbidden_field_names": forbidden_fields,
            "events": events,
            "application_response": (
                {"status": "allowed", "action": action, "resource_id": canonical_resource}
                if decision == "allow"
                else GENERIC_DENIAL.copy()
            ),
        },
    }


def _matches_expected(result: dict[str, Any]) -> bool:
    """Check only the declared public behavior, not timestamps or raw input text."""
    expected = result.get("expected")
    observed = result["observed"]
    if not isinstance(expected, dict):
        return False
    if expected.get("decision") != observed["decision"]:
        return False
    if expected.get("reason_code") != observed["reason_code"]:
        return False
    expected_fields = sorted(expected.get("forbidden_field_names", []))
    if expected_fields != observed["forbidden_field_names"]:
        return False
    return expected.get("event_count") == len(observed["events"])


def summarize_cases(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate deterministic outcomes and reject an incomplete case set."""
    if not results:
        raise ValueError("authority experiment must contain at least one case")
    matched = sum(bool(item.get("matches_expected")) for item in results)
    return {
        "cases": len(results),
        "matched_expected": matched,
        "all_expected": matched == len(results),
        "decisions": {
            "allow": sum(item["observed"]["decision"] == "allow" for item in results),
            "deny": sum(item["observed"]["decision"] == "deny" for item in results),
        },
        "authority_events": sum(len(item["observed"]["events"]) for item in results),
    }


def run_authority_experiment(experiment: str) -> dict[str, Any]:
    """Run every declared authority case exactly once and return raw synthetic evidence."""
    definition, policy, raw_resources, loaded = _load_bundle(experiment)
    fixture_hashes = loaded[-1]["fixture_hashes"]
    cases = loaded[:-1]
    resources = _resource_map(raw_resources)
    _allowed_tuples(policy)
    results = [evaluate_case(case, policy, resources) for case in cases]
    for result in results:
        result["matches_expected"] = _matches_expected(result)
    summary = summarize_cases(results)
    if not summary["all_expected"]:
        raise AssertionError("authority experiment result did not match its declared prediction")
    return {
        "schema_version": AUTHORITY_SCHEMA_VERSION,
        "experiment_id": definition["id"],
        "runner": AUTHORITY_RUNNER,
        "recorded_at": datetime.now(UTC).isoformat(),
        "fixture_hashes": fixture_hashes,
        "cases": results,
        "summary": summary,
    }


def load_authority_batch(path: Path) -> dict[str, Any]:
    """Load and validate raw or sanitized authority evidence."""
    batch = json.loads(path.read_text(encoding="utf-8"))
    if batch.get("schema_version") != AUTHORITY_SCHEMA_VERSION:
        raise ValueError("unsupported authority evidence schema version")
    if batch.get("runner") != AUTHORITY_RUNNER:
        raise ValueError("evidence does not belong to the authority runner")
    cases = batch.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("authority evidence must contain cases")
    if not all(isinstance(item, dict) for item in cases):
        raise ValueError("authority evidence cases must be objects")
    for case in cases:
        if case.get("matches_expected") is not _matches_expected(case):
            raise ValueError("stored authority expectation does not match case")
    expected_summary = summarize_cases(cases)
    if batch.get("summary") != expected_summary:
        raise ValueError("stored authority summary does not match cases")
    return batch


def render_authority_report(batch: dict[str, Any]) -> str:
    """Render a compact report that excludes raw model output and identity fixtures."""
    summary = batch["summary"]
    lines = [
        f"Experiment: {batch['experiment_id']}",
        f"Runner: {batch['runner']}",
        f"Cases: {summary['cases']}",
        f"Expected: {summary['matched_expected']}/{summary['cases']}",
        f"Decisions: allow={summary['decisions']['allow']} | deny={summary['decisions']['deny']}",
        f"Authority events: {summary['authority_events']}",
        "",
        "Per-case results:",
    ]
    for index, result in enumerate(batch["cases"], start=1):
        observed = result["observed"]
        fields = ",".join(observed["forbidden_field_names"]) or "none"
        event_names = ",".join(event["event_name"] for event in observed["events"]) or "none"
        lines.append(
            f"  {index}. {result['case_id']} | decision={observed['decision'].upper()} "
            f"| reason={observed['reason_code']} | ignored={fields} | events={event_names}"
        )
    return "\n".join(lines)


def fixture_hash(content: str) -> str:
    """Expose the hash rule for evidence tests without accepting filesystem paths."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
