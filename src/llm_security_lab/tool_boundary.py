"""Run the deterministic Day 19 tool-boundary experiment."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from llm_security_lab.lab import (
    EXPERIMENT_ID_PATTERN,
    EXPERIMENTS_ROOT,
    experiment_root,
    read_fixture,
)

TOOL_BOUNDARY_RUNNER = "deterministic_tool_boundary"
TOOL_BOUNDARY_SCHEMA_VERSION = 1


def available_tool_boundary_experiments() -> list[str]:
    """Return experiment IDs owned by the deterministic tool-boundary runner."""
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
        if definition.get("runner") == TOOL_BOUNDARY_RUNNER:
            names.append(path.name)
    return sorted(names)


def _load_json_fixture(relative_path: str, experiment: str) -> tuple[Any, dict[str, str]]:
    fixture = read_fixture(relative_path, experiment)
    try:
        value = json.loads(fixture["content"])
    except json.JSONDecodeError as error:
        raise ValueError(f"fixture is not valid JSON: {relative_path}") from error
    return value, {"path": fixture["path"], "sha256": fixture["sha256"]}


def load_tool_boundary_definition(experiment: str) -> dict[str, Any]:
    """Load and validate one deterministic tool-boundary definition."""
    definition = json.loads(
        (experiment_root(experiment) / "experiment.json").read_text(encoding="utf-8")
    )
    if definition.get("schema_version") != TOOL_BOUNDARY_SCHEMA_VERSION:
        raise ValueError("unsupported tool-boundary experiment schema version")
    if definition.get("id") != experiment:
        raise ValueError("tool-boundary experiment id does not match its bundle directory")
    if definition.get("runner") != TOOL_BOUNDARY_RUNNER:
        raise ValueError("experiment is not a deterministic tool-boundary experiment")
    for field in ("tool_schema", "policy", "cases"):
        if not isinstance(definition.get(field), str):
            raise ValueError(f"tool-boundary experiment {field} must be a fixture path")
    return definition


def _validated_schemas(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("tool schema fixture requires schema_version 1")
    tools = value.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise ValueError("tool schema fixture requires tools")
    validated: dict[str, dict[str, Any]] = {}
    for name, schema in tools.items():
        if not isinstance(name, str) or not name or not isinstance(schema, dict):
            raise ValueError("tool schema contains an invalid tool")
        properties = schema.get("properties")
        required = schema.get("required")
        if (
            not isinstance(properties, dict)
            or not properties
            or not isinstance(required, list)
            or set(required) != set(properties)
            or schema.get("additional_properties") is not False
        ):
            raise ValueError(f"tool schema {name} is not strict")
        for field, rule in properties.items():
            if (
                not isinstance(field, str)
                or not isinstance(rule, dict)
                or rule.get("type") != "string"
            ):
                raise ValueError(f"tool schema {name} supports only declared string fields")
        validated[name] = schema
    return validated


def _validated_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("version"), str):
        raise ValueError("tool policy requires a version")
    allowed_origins = value.get("allowed_origins")
    allowed_templates = value.get("allowed_templates")
    output_pattern = value.get("output_name_pattern")
    if (
        not isinstance(allowed_origins, list)
        or not allowed_origins
        or not all(isinstance(item, str) and item for item in allowed_origins)
        or not isinstance(allowed_templates, list)
        or not allowed_templates
        or not all(isinstance(item, str) and item for item in allowed_templates)
        or not isinstance(output_pattern, str)
        or not output_pattern
    ):
        raise ValueError("tool policy contains invalid allowlists")
    re.compile(output_pattern)
    return value


def _validate_arguments(
    tool_name: str, arguments: Any, schemas: dict[str, dict[str, Any]]
) -> list[str]:
    schema = schemas.get(tool_name)
    if schema is None:
        return ["unknown_tool"]
    if not isinstance(arguments, dict):
        return ["arguments_not_object"]
    properties = schema["properties"]
    errors = [f"missing:{field}" for field in schema["required"] if field not in arguments]
    errors.extend(f"extra:{field}" for field in sorted(set(arguments) - set(properties)))
    errors.extend(
        f"type:{field}"
        for field, value in arguments.items()
        if field in properties and not isinstance(value, str)
    )
    return errors


def _origin(url: str) -> tuple[str | None, str]:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None, "invalid_url"
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None, "invalid_url"
    host = parsed.hostname.lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        destination_class = "hostname"
    else:
        destination_class = (
            "loopback_ip"
            if address.is_loopback
            else "private_ip"
            if address.is_private
            else "public_ip"
        )
    default_port = 443 if parsed.scheme == "https" else 80
    suffix = f":{port}" if port is not None and port != default_port else ""
    return f"{parsed.scheme}://{host}{suffix}", destination_class


def _vulnerable_path(case: dict[str, Any], sink_events: list[dict[str, str]]) -> dict[str, Any]:
    surface = case["surface"]
    if surface == "tool_output":
        return {
            "decision": "expose",
            "reason_code": "tool_output_promoted_to_instruction",
            "schema_valid": None,
            "schema_errors": [],
            "policy_allowed": None,
            "sink_reached": False,
            "sink_kind": None,
            "output_trust": "trusted_instruction",
        }

    tool_name = case["tool_name"]
    sink_kind = "simulated_fetch" if tool_name == "fetch_url" else "would_be_shell_string"
    reason = "unchecked_url_forwarded" if tool_name == "fetch_url" else "shell_string_constructed"
    sink_events.append({"case_id": case["id"], "path": "vulnerable", "kind": sink_kind})
    return {
        "decision": "allow",
        "reason_code": reason,
        "schema_valid": None,
        "schema_errors": [],
        "policy_allowed": None,
        "sink_reached": True,
        "sink_kind": sink_kind,
        "output_trust": "not_applicable",
    }


def _hardened_path(
    case: dict[str, Any],
    schemas: dict[str, dict[str, Any]],
    policy: dict[str, Any],
    sink_events: list[dict[str, str]],
) -> dict[str, Any]:
    if case["surface"] == "tool_output":
        return {
            "decision": "contain",
            "reason_code": "tool_output_kept_untrusted",
            "schema_valid": None,
            "schema_errors": [],
            "policy_allowed": False,
            "sink_reached": False,
            "sink_kind": None,
            "output_trust": "untrusted_data",
        }

    tool_name = case["tool_name"]
    arguments = case["arguments"]
    schema_errors = _validate_arguments(tool_name, arguments, schemas)
    if schema_errors:
        return {
            "decision": "block",
            "reason_code": "schema_rejected",
            "schema_valid": False,
            "schema_errors": schema_errors,
            "policy_allowed": None,
            "sink_reached": False,
            "sink_kind": None,
            "output_trust": "not_applicable",
        }

    if tool_name == "fetch_url":
        origin, destination_class = _origin(arguments["url"])
        if origin not in policy["allowed_origins"]:
            return {
                "decision": "block",
                "reason_code": "destination_not_allowed",
                "schema_valid": True,
                "schema_errors": [],
                "policy_allowed": False,
                "destination_class": destination_class,
                "sink_reached": False,
                "sink_kind": None,
                "output_trust": "not_applicable",
            }
        reason = "destination_allowed"
        sink_kind = "simulated_fetch"
    elif tool_name == "render_report":
        if arguments["template"] not in policy["allowed_templates"]:
            return {
                "decision": "block",
                "reason_code": "template_not_allowed",
                "schema_valid": True,
                "schema_errors": [],
                "policy_allowed": False,
                "sink_reached": False,
                "sink_kind": None,
                "output_trust": "not_applicable",
            }
        if re.fullmatch(policy["output_name_pattern"], arguments["output_name"]) is None:
            return {
                "decision": "block",
                "reason_code": "unsafe_output_name",
                "schema_valid": True,
                "schema_errors": [],
                "policy_allowed": False,
                "sink_reached": False,
                "sink_kind": None,
                "output_trust": "not_applicable",
            }
        reason = "structured_argv"
        sink_kind = "simulated_process"
    else:
        raise ValueError(f"unsupported tool implementation: {tool_name}")

    sink_events.append({"case_id": case["id"], "path": "hardened", "kind": sink_kind})
    return {
        "decision": "allow",
        "reason_code": reason,
        "schema_valid": True,
        "schema_errors": [],
        "policy_allowed": True,
        "sink_reached": True,
        "sink_kind": sink_kind,
        "output_trust": "not_applicable",
    }


def _compact_path(path: dict[str, Any]) -> dict[str, Any]:
    return {
        field: path.get(field)
        for field in (
            "decision",
            "reason_code",
            "schema_valid",
            "policy_allowed",
            "sink_reached",
            "output_trust",
        )
    }


def _matches_expected(result: dict[str, Any]) -> bool:
    expected = result.get("expected")
    if not isinstance(expected, dict):
        return False
    return {
        name: _compact_path(result["observed"][name]) for name in ("vulnerable", "hardened")
    } == expected


def evaluate_case(
    case: dict[str, Any], schemas: dict[str, dict[str, Any]], policy: dict[str, Any]
) -> dict[str, Any]:
    """Evaluate one fixed input through vulnerable and hardened application paths."""
    case_id = case.get("id")
    surface = case.get("surface")
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("tool-boundary case id is required")
    if surface not in {"function_call", "tool_output"}:
        raise ValueError(f"tool-boundary case {case_id} has an invalid surface")
    if surface == "function_call":
        if not isinstance(case.get("tool_name"), str) or not isinstance(
            case.get("arguments"), dict
        ):
            raise ValueError(f"tool-boundary case {case_id} requires a tool and arguments")
    elif not isinstance(case.get("tool_output"), str) or not case["tool_output"]:
        raise ValueError(f"tool-boundary case {case_id} requires synthetic tool output")

    sink_events: list[dict[str, str]] = []
    result = {
        "case_id": case_id,
        "surface": surface,
        "input": {
            "tool_name": case.get("tool_name"),
            "arguments": case.get("arguments"),
            "tool_output": case.get("tool_output"),
        },
        "expected": case.get("expected"),
        "observed": {
            "vulnerable": _vulnerable_path(case, sink_events),
            "hardened": _hardened_path(case, schemas, policy, sink_events),
            "in_memory_sink_events": sink_events,
        },
    }
    result["matches_expected"] = _matches_expected(result)
    return result


def summarize_cases(cases: list[dict[str, Any]]) -> dict[str, Any]:
    if not cases:
        raise ValueError("tool-boundary experiment must contain cases")
    matched = sum(case.get("matches_expected") is True for case in cases)
    vulnerable = [case["observed"]["vulnerable"] for case in cases]
    hardened = [case["observed"]["hardened"] for case in cases]
    return {
        "cases": len(cases),
        "path_evaluations": len(cases) * 2,
        "matched_expected": matched,
        "all_expected": matched == len(cases),
        "vulnerable_sink_reached": sum(item["sink_reached"] is True for item in vulnerable),
        "hardened_sink_reached": sum(item["sink_reached"] is True for item in hardened),
        "hardened_blocks": sum(item["decision"] == "block" for item in hardened),
        "tool_outputs_exposed": sum(item["decision"] == "expose" for item in vulnerable),
        "tool_outputs_contained": sum(item["decision"] == "contain" for item in hardened),
        "in_memory_sink_events": sum(
            len(case["observed"]["in_memory_sink_events"]) for case in cases
        ),
    }


def run_tool_boundary_experiment(experiment: str) -> dict[str, Any]:
    """Run the fixed offline tool-boundary matrix and return raw synthetic evidence."""
    definition = load_tool_boundary_definition(experiment)
    schemas_raw, schemas_evidence = _load_json_fixture(definition["tool_schema"], experiment)
    policy_raw, policy_evidence = _load_json_fixture(definition["policy"], experiment)
    cases, cases_evidence = _load_json_fixture(definition["cases"], experiment)
    schemas = _validated_schemas(schemas_raw)
    policy = _validated_policy(policy_raw)
    if (
        not isinstance(cases, list)
        or not cases
        or not all(isinstance(item, dict) for item in cases)
    ):
        raise ValueError("tool-boundary cases fixture must be a non-empty list")
    results = [evaluate_case(case, schemas, policy) for case in cases]
    summary = summarize_cases(results)
    if not summary["all_expected"]:
        raise AssertionError("tool-boundary result did not match its declared prediction")
    return {
        "schema_version": TOOL_BOUNDARY_SCHEMA_VERSION,
        "experiment_id": experiment,
        "runner": TOOL_BOUNDARY_RUNNER,
        "recorded_at": datetime.now(UTC).isoformat(),
        "fixture_hashes": {
            item["path"]: item["sha256"]
            for item in (schemas_evidence, policy_evidence, cases_evidence)
        },
        "cases": results,
        "summary": summary,
        "safety_boundary": {
            "synthetic_data_only": True,
            "model_calls": 0,
            "network_calls": 0,
            "subprocess_calls": 0,
            "external_side_effects": 0,
            "side_effect_store": "in_memory",
        },
    }


def load_tool_boundary_batch(path: Path) -> dict[str, Any]:
    batch = json.loads(path.read_text(encoding="utf-8"))
    if batch.get("schema_version") != TOOL_BOUNDARY_SCHEMA_VERSION:
        raise ValueError("unsupported tool-boundary evidence schema version")
    if batch.get("runner") != TOOL_BOUNDARY_RUNNER:
        raise ValueError("evidence does not belong to the tool-boundary runner")
    cases = batch.get("cases")
    if (
        not isinstance(cases, list)
        or not cases
        or not all(isinstance(item, dict) for item in cases)
    ):
        raise ValueError("tool-boundary evidence must contain cases")
    for case in cases:
        if case.get("matches_expected") is not _matches_expected(case):
            raise ValueError("stored tool-boundary expectation does not match case")
    if batch.get("summary") != summarize_cases(cases):
        raise ValueError("stored tool-boundary summary does not match cases")
    boundary = batch.get("safety_boundary")
    if not isinstance(boundary, dict) or any(
        boundary.get(field) != 0
        for field in ("model_calls", "network_calls", "subprocess_calls", "external_side_effects")
    ):
        raise ValueError("tool-boundary evidence violates the offline safety boundary")
    return batch


def render_tool_boundary_report(batch: dict[str, Any]) -> str:
    """Render a report without tool arguments or synthetic tool-output text."""
    summary = batch["summary"]
    boundary = batch["safety_boundary"]
    lines = [
        f"Experiment: {batch['experiment_id']}",
        f"Runner: {batch['runner']}",
        f"Cases: {summary['cases']}",
        f"Expected: {summary['matched_expected']}/{summary['cases']}",
        f"Path evaluations: {summary['path_evaluations']}",
        f"Sink reached: vulnerable={summary['vulnerable_sink_reached']} | "
        f"hardened={summary['hardened_sink_reached']}",
        f"Hardened blocks: {summary['hardened_blocks']}",
        f"Tool output: exposed={summary['tool_outputs_exposed']} | "
        f"contained={summary['tool_outputs_contained']}",
        f"In-memory sink events: {summary['in_memory_sink_events']}",
        f"Model / network / subprocess / external side effects: "
        f"{boundary['model_calls']} / {boundary['network_calls']} / "
        f"{boundary['subprocess_calls']} / {boundary['external_side_effects']}",
        "",
        "Per-case results:",
    ]
    for case in batch["cases"]:
        for path_name in ("vulnerable", "hardened"):
            outcome = case["observed"][path_name]
            lines.append(
                f"  {case['case_id']}/{path_name} | decision={outcome['decision'].upper()} "
                f"| reason={outcome['reason_code']} | schema={outcome['schema_valid']} "
                f"| sink={str(outcome['sink_reached']).lower()} "
                f"| output_trust={outcome['output_trust']}"
            )
    return "\n".join(lines)
