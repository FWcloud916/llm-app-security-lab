"""Run the deterministic Day 20 supply-chain intake experiment."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from llm_security_lab.lab import (
    EXPERIMENT_ID_PATTERN,
    EXPERIMENTS_ROOT,
    experiment_root,
    read_fixture,
)

SUPPLY_CHAIN_RUNNER = "deterministic_supply_chain_intake"
SUPPLY_CHAIN_SCHEMA_VERSION = 1
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def available_supply_chain_experiments() -> list[str]:
    """Return experiment IDs owned by the deterministic supply-chain runner."""
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
        if definition.get("runner") == SUPPLY_CHAIN_RUNNER:
            names.append(path.name)
    return sorted(names)


def _load_json_fixture(relative_path: str, experiment: str) -> tuple[Any, dict[str, str]]:
    fixture = read_fixture(relative_path, experiment)
    try:
        value = json.loads(fixture["content"])
    except json.JSONDecodeError as error:
        raise ValueError(f"fixture is not valid JSON: {relative_path}") from error
    return value, {"path": fixture["path"], "sha256": fixture["sha256"]}


def load_supply_chain_definition(experiment: str) -> dict[str, Any]:
    """Load and validate one deterministic supply-chain definition."""
    definition = json.loads(
        (experiment_root(experiment) / "experiment.json").read_text(encoding="utf-8")
    )
    if definition.get("schema_version") != SUPPLY_CHAIN_SCHEMA_VERSION:
        raise ValueError("unsupported supply-chain experiment schema version")
    if definition.get("id") != experiment:
        raise ValueError("supply-chain experiment id does not match its bundle directory")
    if definition.get("runner") != SUPPLY_CHAIN_RUNNER:
        raise ValueError("experiment is not a deterministic supply-chain experiment")
    for field in ("repository_audit", "policy", "cases"):
        if not isinstance(definition.get(field), str):
            raise ValueError(f"supply-chain experiment {field} must be a fixture path")
    return definition


def _validated_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("supply-chain policy requires schema_version 1")
    if not isinstance(value.get("version"), str) or not value["version"]:
        raise ValueError("supply-chain policy requires a version")
    allowed_formats = value.get("model", {}).get("allowed_formats")
    required_mcp = value.get("mcp", {}).get("required_capability_fields")
    if (
        not isinstance(allowed_formats, list)
        or not allowed_formats
        or not all(isinstance(item, str) and item for item in allowed_formats)
        or not isinstance(required_mcp, list)
        or not required_mcp
        or not all(isinstance(item, str) and item for item in required_mcp)
    ):
        raise ValueError("supply-chain policy contains invalid allowlists")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _audit_packages(lock_path: Path) -> dict[str, Any]:
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        raise ValueError("repository package lock does not contain packages")
    artifact_hashes: set[str] = set()
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("repository package lock contains an invalid package")
        for field in ("sdist",):
            artifact = package.get(field)
            if isinstance(artifact, dict) and isinstance(artifact.get("hash"), str):
                artifact_hashes.add(artifact["hash"])
        wheels = package.get("wheels", [])
        if isinstance(wheels, list):
            artifact_hashes.update(
                wheel["hash"]
                for wheel in wheels
                if isinstance(wheel, dict) and isinstance(wheel.get("hash"), str)
            )
    return {
        "component": "python_packages",
        "state": "review",
        "reason_code": "package_provenance_not_recorded",
        "lock_file": lock_path.name,
        "lock_sha256": _sha256(lock_path),
        "locked_packages": len(packages),
        "artifact_hashes": len(artifact_hashes),
        "build_provenance_recorded": False,
    }


def _model_references() -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    for path in sorted(EXPERIMENTS_ROOT.glob("*/experiment.json")):
        definition = json.loads(path.read_text(encoding="utf-8"))
        for field in ("model", "embedding_model"):
            model = definition.get(field)
            if not isinstance(model, dict):
                continue
            name = model.get("name")
            digest = model.get("digest")
            if not isinstance(name, str) or not isinstance(digest, str):
                raise ValueError(
                    f"model reference is incomplete: {path.relative_to(REPOSITORY_ROOT)}"
                )
            if SHA256_PATTERN.fullmatch(digest) is None:
                raise ValueError(f"model digest is not a complete sha256: {path.name}/{field}")
            references.append({"name": name, "digest": digest})
    return references


def _audit_models() -> dict[str, Any]:
    references = _model_references()
    if not references:
        raise ValueError("repository audit found no model references")
    unique_pairs = {(item["name"], item["digest"]) for item in references}
    return {
        "component": "model_references",
        "state": "review",
        "reason_code": "model_origin_not_recorded",
        "references": len(references),
        "unique_name_digest_pairs": len(unique_pairs),
        "all_references_have_full_digest": True,
        "artifact_format_recorded": False,
        "signature_or_provenance_recorded": False,
    }


def _validated_audit_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("repository audit fixture requires schema_version 1")
    package_lock = value.get("package_lock")
    mcp_paths = value.get("declared_mcp_config_paths")
    if (
        not isinstance(package_lock, str)
        or not package_lock
        or not isinstance(mcp_paths, list)
        or not mcp_paths
        or not all(isinstance(item, str) and item for item in mcp_paths)
    ):
        raise ValueError("repository audit fixture is incomplete")
    return value


def audit_repository(config: dict[str, Any]) -> dict[str, Any]:
    """Audit only declared version-controlled evidence without executing dependencies."""
    lock_path = (REPOSITORY_ROOT / config["package_lock"]).resolve()
    if lock_path.parent != REPOSITORY_ROOT or not lock_path.is_file() or lock_path.is_symlink():
        raise ValueError("repository audit package lock is invalid")
    present_mcp = []
    for relative in config["declared_mcp_config_paths"]:
        path = (REPOSITORY_ROOT / relative).resolve()
        try:
            path.relative_to(REPOSITORY_ROOT)
        except ValueError as error:
            raise ValueError("repository audit MCP path escapes the repository") from error
        if path.exists():
            present_mcp.append(relative)
    mcp = {
        "component": "mcp_servers",
        "state": "not_configured" if not present_mcp else "review",
        "reason_code": "no_declared_mcp_configuration"
        if not present_mcp
        else "mcp_configuration_requires_review",
        "checked_paths": sorted(config["declared_mcp_config_paths"]),
        "present_paths": sorted(present_mcp),
    }
    return {
        "repository_commit_scope": "day-19-evidence-baseline-plus-day-20-runner",
        "components": [_audit_packages(lock_path), _audit_models(), mcp],
    }


def _missing_common(evidence: dict[str, Any]) -> list[str]:
    required = ("immutable_ref", "sha256", "provenance")
    return [field for field in required if not evidence.get(field)]


def evaluate_case(case: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one synthetic artifact manifest with deterministic fail-closed precedence."""
    case_id = case.get("id")
    component = case.get("component")
    evidence = case.get("evidence")
    expected = case.get("expected")
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("supply-chain case id is required")
    if component not in {"model", "package", "mcp"} or not isinstance(evidence, dict):
        raise ValueError(f"supply-chain case {case_id} is invalid")
    if not isinstance(expected, dict):
        raise ValueError(f"supply-chain case {case_id} requires an expected result")

    missing: list[str] = []
    if evidence.get("hash_matches") is False:
        decision, reason = "block", "artifact_hash_mismatch"
    elif component == "model" and evidence.get("format") not in policy["model"]["allowed_formats"]:
        decision, reason = "block", "unsafe_model_format"
    elif component == "model" and evidence.get("remote_code") is True:
        decision, reason = "block", "remote_code_required"
    elif component == "mcp" and evidence.get("token_passthrough") is True:
        decision, reason = "block", "token_passthrough_forbidden"
    elif component == "mcp" and evidence.get("capability_drift"):
        decision, reason = "block", "mcp_capability_drift"
    else:
        missing = _missing_common(evidence)
        if component == "package" and not evidence.get("exact_version"):
            missing.append("exact_version")
        if component == "model" and "format" not in evidence:
            missing.append("format")
        if component == "mcp":
            missing.extend(
                field
                for field in policy["mcp"]["required_capability_fields"]
                if field not in evidence
            )
        if missing:
            decision = "review"
            reason = (
                "tool_annotations_only"
                if component == "mcp" and evidence.get("tool_annotations")
                else "required_evidence_missing"
            )
        else:
            decision, reason = "allow", "evidence_and_capabilities_accepted"

    observed = {
        "decision": decision,
        "reason_code": reason,
        "missing_evidence": sorted(set(missing)),
    }
    result = {
        "case_id": case_id,
        "component": component,
        "input": evidence,
        "expected": expected,
        "observed": observed,
        "matches_expected": observed == expected,
    }
    return result


def summarize_cases(cases: list[dict[str, Any]]) -> dict[str, Any]:
    if not cases:
        raise ValueError("supply-chain experiment must contain cases")
    matched = sum(case.get("matches_expected") is True for case in cases)
    counts = Counter(case["observed"]["decision"] for case in cases)
    by_component = Counter(case["component"] for case in cases)
    return {
        "cases": len(cases),
        "matched_expected": matched,
        "all_expected": matched == len(cases),
        "allow": counts["allow"],
        "review": counts["review"],
        "block": counts["block"],
        "models": by_component["model"],
        "packages": by_component["package"],
        "mcp_servers": by_component["mcp"],
    }


def run_supply_chain_experiment(experiment: str) -> dict[str, Any]:
    """Run the repository audit and fixed offline intake matrix."""
    definition = load_supply_chain_definition(experiment)
    audit_raw, audit_evidence = _load_json_fixture(definition["repository_audit"], experiment)
    policy_raw, policy_evidence = _load_json_fixture(definition["policy"], experiment)
    cases, cases_evidence = _load_json_fixture(definition["cases"], experiment)
    audit_config = _validated_audit_config(audit_raw)
    policy = _validated_policy(policy_raw)
    if (
        not isinstance(cases, list)
        or not cases
        or not all(isinstance(item, dict) for item in cases)
    ):
        raise ValueError("supply-chain cases fixture must be a non-empty list")
    results = [evaluate_case(case, policy) for case in cases]
    summary = summarize_cases(results)
    if not summary["all_expected"]:
        raise AssertionError("supply-chain result did not match its declared prediction")
    return {
        "schema_version": SUPPLY_CHAIN_SCHEMA_VERSION,
        "experiment_id": experiment,
        "runner": SUPPLY_CHAIN_RUNNER,
        "recorded_at": datetime.now(UTC).isoformat(),
        "fixture_hashes": {
            item["path"]: item["sha256"]
            for item in (audit_evidence, policy_evidence, cases_evidence)
        },
        "repository_audit": audit_repository(audit_config),
        "cases": results,
        "summary": summary,
        "safety_boundary": {
            "synthetic_manifests_only": True,
            "model_calls": 0,
            "network_calls": 0,
            "package_installs": 0,
            "artifact_loads": 0,
            "mcp_server_starts": 0,
            "subprocess_calls": 0,
            "external_side_effects": 0,
        },
    }


def _case_matches(case: dict[str, Any]) -> bool:
    return case.get("observed") == case.get("expected")


def load_supply_chain_batch(path: Path) -> dict[str, Any]:
    batch = json.loads(path.read_text(encoding="utf-8"))
    if batch.get("schema_version") != SUPPLY_CHAIN_SCHEMA_VERSION:
        raise ValueError("unsupported supply-chain evidence schema version")
    if batch.get("runner") != SUPPLY_CHAIN_RUNNER:
        raise ValueError("evidence does not belong to the supply-chain runner")
    cases = batch.get("cases")
    if (
        not isinstance(cases, list)
        or not cases
        or not all(isinstance(item, dict) for item in cases)
    ):
        raise ValueError("supply-chain evidence must contain cases")
    for case in cases:
        if case.get("matches_expected") is not _case_matches(case):
            raise ValueError("stored supply-chain expectation does not match case")
    if batch.get("summary") != summarize_cases(cases):
        raise ValueError("stored supply-chain summary does not match cases")
    boundary = batch.get("safety_boundary")
    zero_fields = (
        "model_calls",
        "network_calls",
        "package_installs",
        "artifact_loads",
        "mcp_server_starts",
        "subprocess_calls",
        "external_side_effects",
    )
    if not isinstance(boundary, dict) or any(boundary.get(field) != 0 for field in zero_fields):
        raise ValueError("supply-chain evidence violates the offline safety boundary")
    return batch


def render_supply_chain_report(batch: dict[str, Any]) -> str:
    """Render a sanitized report without synthetic artifact manifests."""
    summary = batch["summary"]
    boundary = batch["safety_boundary"]
    lines = [
        f"Experiment: {batch['experiment_id']}",
        f"Runner: {batch['runner']}",
        f"Cases: {summary['cases']}",
        f"Expected: {summary['matched_expected']}/{summary['cases']}",
        f"Decisions: allow={summary['allow']} | review={summary['review']} | "
        f"block={summary['block']}",
        f"Components: model={summary['models']} | package={summary['packages']} | "
        f"mcp={summary['mcp_servers']}",
        f"Model / network / installs / loads / MCP starts / subprocess / external: "
        f"{boundary['model_calls']} / {boundary['network_calls']} / "
        f"{boundary['package_installs']} / {boundary['artifact_loads']} / "
        f"{boundary['mcp_server_starts']} / {boundary['subprocess_calls']} / "
        f"{boundary['external_side_effects']}",
        "",
        "Repository audit:",
    ]
    for item in batch["repository_audit"]["components"]:
        lines.append(
            f"  {item['component']} | state={item['state'].upper()} | reason={item['reason_code']}"
        )
    lines.extend(("", "Per-case results:"))
    for case in batch["cases"]:
        outcome = case["observed"]
        lines.append(
            f"  {case['case_id']} | component={case['component']} "
            f"| decision={outcome['decision'].upper()} | reason={outcome['reason_code']} "
            f"| missing={','.join(outcome['missing_evidence']) or '-'}"
        )
    return "\n".join(lines)
