"""Run the deterministic Day 18 excessive-agency experiment."""

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

AGENCY_RUNNER = "deterministic_agent_agency"
AGENCY_SCHEMA_VERSION = 1
APPROVAL_MODES = frozenset({"automatic", "manual_exact", "manual_batch"})


def available_agency_experiments() -> list[str]:
    """Return experiment IDs owned by the deterministic agency runner."""
    if not EXPERIMENTS_ROOT.is_dir():
        return []
    names: list[str] = []
    for path in EXPERIMENTS_ROOT.iterdir():
        if not path.is_dir() or not EXPERIMENT_ID_PATTERN.fullmatch(path.name):
            continue
        try:
            definition = json.loads((path / "experiment.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if definition.get("runner") == AGENCY_RUNNER:
            names.append(path.name)
    return sorted(names)


def _load_json_fixture(relative_path: str, experiment: str) -> tuple[Any, dict[str, str]]:
    fixture = read_fixture(relative_path, experiment)
    try:
        value = json.loads(fixture["content"])
    except json.JSONDecodeError as error:
        raise ValueError(f"fixture is not valid JSON: {relative_path}") from error
    return value, {"path": fixture["path"], "sha256": fixture["sha256"]}


def load_agency_definition(experiment: str) -> dict[str, Any]:
    """Load and validate one deterministic agency experiment definition."""
    definition = json.loads(
        (experiment_root(experiment) / "experiment.json").read_text(encoding="utf-8")
    )
    if definition.get("schema_version") != AGENCY_SCHEMA_VERSION:
        raise ValueError("unsupported agency experiment schema version")
    if definition.get("id") != experiment:
        raise ValueError("agency experiment id does not match its bundle directory")
    if definition.get("runner") != AGENCY_RUNNER:
        raise ValueError("experiment is not a deterministic agency experiment")
    for field in ("policy", "risk_rules", "cases"):
        if not isinstance(definition.get(field), str):
            raise ValueError(f"agency experiment {field} must be a fixture path")
    actions = definition.get("approval_required_actions")
    if (
        not isinstance(actions, list)
        or not actions
        or not all(isinstance(item, str) and item for item in actions)
    ):
        raise ValueError("approval_required_actions must be a non-empty string list")
    return definition


def _canonical_envelope(proposal: dict[str, Any]) -> dict[str, Any]:
    """Return exactly the action fields that a user must review."""
    return {
        "action": proposal.get("action"),
        "resource_id": proposal.get("resource_id"),
        "arguments": proposal.get("arguments"),
    }


def envelope_sha256(proposal: dict[str, Any]) -> str:
    """Hash an immutable action envelope using canonical JSON bytes."""
    payload = json.dumps(
        _canonical_envelope(proposal), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [text for item in value for text in _strings(item)]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _strings(item)]
    return []


def _risk_findings(arguments: Any, risk_rules: dict[str, Any]) -> list[str]:
    keywords = risk_rules.get("keywords")
    if not isinstance(keywords, list) or not all(
        isinstance(item, str) and item for item in keywords
    ):
        raise ValueError("risk rules must contain non-empty keyword strings")
    haystack = "\n".join(_strings(arguments)).casefold()
    return sorted(keyword for keyword in keywords if keyword.casefold() in haystack)


def _permission_tuples(policy: dict[str, Any]) -> set[tuple[str, str, str, str]]:
    entries = policy.get("allow")
    if not isinstance(policy.get("version"), str) or not isinstance(entries, list):
        raise ValueError("agency policy requires version and allow list")
    allowed: set[tuple[str, str, str, str]] = set()
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("agency policy entries must be objects")
        values = tuple(
            item.get(field) for field in ("subject_ref", "agent_ref", "action", "resource_id")
        )
        if not all(isinstance(value, str) and value for value in values):
            raise ValueError("agency policy entry contains an invalid field")
        allowed.add(values)  # type: ignore[arg-type]
    return allowed


def _review_hashes(approval: dict[str, Any]) -> set[str]:
    reviewed = approval.get("reviewed_envelopes", [])
    if not isinstance(reviewed, list) or not all(isinstance(item, dict) for item in reviewed):
        raise ValueError("reviewed_envelopes must be a list of action envelopes")
    return {envelope_sha256(item) for item in reviewed}


def _approval_decision(
    *,
    proposal: dict[str, Any],
    findings: list[str],
    approval: dict[str, Any],
) -> tuple[bool, str]:
    mode = approval.get("mode")
    if mode not in APPROVAL_MODES:
        raise ValueError("unsupported approval mode")
    if mode == "automatic":
        return True, "automatic"
    if envelope_sha256(proposal) not in _review_hashes(approval):
        return False, "approval_missing_or_stale"
    if mode == "manual_exact":
        return True, "exact_envelope_approved"
    individual_ids = approval.get("individual_action_ids", [])
    if not isinstance(individual_ids, list) or not all(
        isinstance(item, str) for item in individual_ids
    ):
        raise ValueError("individual_action_ids must be a string list")
    if findings and proposal["id"] not in individual_ids:
        return False, "flagged_requires_individual_review"
    return True, "batch_envelope_approved"


def evaluate_case(
    case: dict[str, Any],
    policy: dict[str, Any],
    risk_rules: dict[str, Any],
    approval_required_actions: set[str],
) -> dict[str, Any]:
    """Evaluate proposals through functionality, permission, risk, and approval gates."""
    case_id = case.get("id")
    subject_ref = case.get("subject_ref")
    agent_ref = case.get("agent_ref")
    available_actions = case.get("available_actions")
    proposals = case.get("proposals")
    approval = case.get("approval")
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("agency case id is required")
    if not isinstance(subject_ref, str) or not isinstance(agent_ref, str):
        raise ValueError(f"agency case {case_id} requires subject_ref and agent_ref")
    if not isinstance(available_actions, list) or not all(
        isinstance(item, str) and item for item in available_actions
    ):
        raise ValueError(f"agency case {case_id} requires available_actions")
    if (
        not isinstance(proposals, list)
        or not proposals
        or not all(isinstance(item, dict) for item in proposals)
    ):
        raise ValueError(f"agency case {case_id} requires proposals")
    if not isinstance(approval, dict):
        raise ValueError(f"agency case {case_id} requires approval")

    permission_tuples = _permission_tuples(policy)
    outcomes: list[dict[str, Any]] = []
    side_effects: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for proposal in proposals:
        proposal_id = proposal.get("id")
        action = proposal.get("action")
        resource_id = proposal.get("resource_id")
        arguments = proposal.get("arguments")
        if (
            not isinstance(proposal_id, str)
            or not proposal_id
            or proposal_id in seen_ids
            or not isinstance(action, str)
            or not action
            or not isinstance(resource_id, str)
            or not resource_id
            or not isinstance(arguments, dict)
        ):
            raise ValueError(f"agency case {case_id} contains an invalid proposal")
        seen_ids.add(proposal_id)
        findings = _risk_findings(arguments, risk_rules)

        if action not in available_actions:
            decision, reason = "block", "function_not_available"
        elif (subject_ref, agent_ref, action, resource_id) not in permission_tuples:
            decision, reason = "block", "permission_denied"
        elif action in approval_required_actions:
            approved, reason = _approval_decision(
                proposal=proposal, findings=findings, approval=approval
            )
            decision = "execute" if approved else "block"
        else:
            decision, reason = "execute", "approval_not_required"

        if decision == "execute":
            side_effects.append({"proposal_id": proposal_id, "action": action})
        outcomes.append(
            {
                "proposal_id": proposal_id,
                "action": action,
                "resource_id": resource_id,
                "envelope_sha256": envelope_sha256(proposal),
                "risk_findings": findings,
                "decision": decision,
                "reason_code": reason,
            }
        )

    result = {
        "case_id": case_id,
        "expected": case.get("expected"),
        "observed": {"outcomes": outcomes, "side_effects": side_effects},
    }
    result["matches_expected"] = _matches_expected(result)
    return result


def _matches_expected(result: dict[str, Any]) -> bool:
    expected = result.get("expected")
    if not isinstance(expected, dict):
        return False
    compact = [
        {
            "proposal_id": item["proposal_id"],
            "decision": item["decision"],
            "reason_code": item["reason_code"],
            "risk_findings": item["risk_findings"],
        }
        for item in result["observed"]["outcomes"]
    ]
    return compact == expected.get("outcomes") and len(
        result["observed"]["side_effects"]
    ) == expected.get("side_effect_count")


def summarize_cases(cases: list[dict[str, Any]]) -> dict[str, Any]:
    if not cases:
        raise ValueError("agency experiment must contain cases")
    outcomes = [item for case in cases for item in case["observed"]["outcomes"]]
    matched = sum(case.get("matches_expected") is True for case in cases)
    return {
        "cases": len(cases),
        "matched_expected": matched,
        "all_expected": matched == len(cases),
        "proposals": len(outcomes),
        "executed": sum(item["decision"] == "execute" for item in outcomes),
        "blocked": sum(item["decision"] == "block" for item in outcomes),
        "flagged": sum(bool(item["risk_findings"]) for item in outcomes),
        "side_effects": sum(len(case["observed"]["side_effects"]) for case in cases),
    }


def run_agency_experiment(experiment: str) -> dict[str, Any]:
    """Run the fixed, offline agency case matrix and return raw synthetic evidence."""
    definition = load_agency_definition(experiment)
    policy, policy_evidence = _load_json_fixture(definition["policy"], experiment)
    risk_rules, risk_evidence = _load_json_fixture(definition["risk_rules"], experiment)
    cases, cases_evidence = _load_json_fixture(definition["cases"], experiment)
    if (
        not isinstance(policy, dict)
        or not isinstance(risk_rules, dict)
        or not isinstance(cases, list)
    ):
        raise ValueError("agency fixtures contain invalid top-level types")
    results = [
        evaluate_case(
            case,
            policy,
            risk_rules,
            set(definition["approval_required_actions"]),
        )
        for case in cases
    ]
    summary = summarize_cases(results)
    if not summary["all_expected"]:
        raise AssertionError("agency experiment result did not match its declared prediction")
    return {
        "schema_version": AGENCY_SCHEMA_VERSION,
        "experiment_id": experiment,
        "runner": AGENCY_RUNNER,
        "recorded_at": datetime.now(UTC).isoformat(),
        "fixture_hashes": {
            item["path"]: item["sha256"]
            for item in (policy_evidence, risk_evidence, cases_evidence)
        },
        "cases": results,
        "summary": summary,
        "safety_boundary": {
            "synthetic_data_only": True,
            "model_called": False,
            "network_access": False,
            "external_side_effects": False,
            "side_effect_store": "in_memory",
        },
    }


def load_agency_batch(path: Path) -> dict[str, Any]:
    batch = json.loads(path.read_text(encoding="utf-8"))
    if batch.get("schema_version") != AGENCY_SCHEMA_VERSION:
        raise ValueError("unsupported agency evidence schema version")
    if batch.get("runner") != AGENCY_RUNNER:
        raise ValueError("evidence does not belong to the agency runner")
    cases = batch.get("cases")
    if (
        not isinstance(cases, list)
        or not cases
        or not all(isinstance(item, dict) for item in cases)
    ):
        raise ValueError("agency evidence must contain cases")
    for case in cases:
        if case.get("matches_expected") is not _matches_expected(case):
            raise ValueError("stored agency expectation does not match case")
    if batch.get("summary") != summarize_cases(cases):
        raise ValueError("stored agency summary does not match cases")
    return batch


def render_agency_report(batch: dict[str, Any]) -> str:
    """Render a report without proposal arguments, identities, or reviewed message content."""
    summary = batch["summary"]
    boundary = batch["safety_boundary"]
    lines = [
        f"Experiment: {batch['experiment_id']}",
        f"Runner: {batch['runner']}",
        f"Cases: {summary['cases']}",
        f"Expected: {summary['matched_expected']}/{summary['cases']}",
        f"Proposals: {summary['proposals']}",
        f"Decisions: execute={summary['executed']} | block={summary['blocked']}",
        f"Flagged: {summary['flagged']}",
        f"Synthetic side effects: {summary['side_effects']}",
        f"Model called: {str(boundary['model_called']).lower()}",
        f"Network access: {str(boundary['network_access']).lower()}",
        f"External side effects: {str(boundary['external_side_effects']).lower()}",
        "",
        "Per-proposal results:",
    ]
    for case in batch["cases"]:
        for outcome in case["observed"]["outcomes"]:
            findings = ",".join(outcome["risk_findings"]) or "none"
            lines.append(
                f"  {case['case_id']}/{outcome['proposal_id']} | "
                f"decision={outcome['decision'].upper()} | reason={outcome['reason_code']} "
                f"| flagged={findings} | envelope={outcome['envelope_sha256']}"
            )
    return "\n".join(lines)
