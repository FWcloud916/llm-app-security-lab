"""Run the deterministic Day 27 observability and audit-chain experiment."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import socket
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from unittest.mock import patch

from llm_security_lab.lab import (
    EXPERIMENT_ID_PATTERN,
    EXPERIMENTS_ROOT,
    experiment_root,
    read_fixture,
)

OBSERVABILITY_RUNNER = "deterministic_observability_audit"
OBSERVABILITY_SCHEMA_VERSION = 1
PROFILES = ("unsafe_attributes", "safe_attributes")
ZERO_HMAC = "0" * 64


class TraceRuntime(Protocol):
    """The optional OpenTelemetry boundary used by the formal runner."""

    version: str

    def capture(
        self,
        *,
        profile: str,
        request_id: str,
        policy_version: str,
        input_text: str,
        output_text: str,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]: ...


def available_observability_experiments() -> list[str]:
    """Return experiment IDs owned by the Day 27 runner."""
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
        if definition.get("runner") == OBSERVABILITY_RUNNER:
            names.append(path.name)
    return sorted(names)


def _load_json_fixture(relative_path: str, experiment: str) -> tuple[Any, dict[str, str]]:
    fixture = read_fixture(relative_path, experiment)
    try:
        value = json.loads(fixture["content"])
    except json.JSONDecodeError as error:
        raise ValueError(f"fixture is not valid JSON: {relative_path}") from error
    return value, {"path": fixture["path"], "sha256": fixture["sha256"]}


def load_observability_definition(experiment: str) -> dict[str, Any]:
    """Load and validate one Day 27 experiment definition."""
    definition = json.loads(
        (experiment_root(experiment) / "experiment.json").read_text(encoding="utf-8")
    )
    if definition.get("schema_version") != OBSERVABILITY_SCHEMA_VERSION:
        raise ValueError("unsupported observability experiment schema version")
    if definition.get("id") != experiment:
        raise ValueError("observability experiment id does not match its bundle directory")
    if definition.get("runner") != OBSERVABILITY_RUNNER:
        raise ValueError("experiment is not a deterministic observability experiment")
    if definition.get("profiles") != list(PROFILES):
        raise ValueError("observability profiles must match the fixed comparison order")
    for field in ("policy", "events"):
        if not isinstance(definition.get(field), str):
            raise ValueError(f"observability experiment {field} must be a fixture path")
    return definition


def _validate_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("observability policy requires schema_version 1")
    allowed = value.get("safe_attribute_allowlist")
    required = value.get("required_safe_attributes")
    if (
        not isinstance(value.get("version"), str)
        or not isinstance(allowed, list)
        or not allowed
        or not all(isinstance(item, str) and item for item in allowed)
        or len(allowed) != len(set(allowed))
        or not isinstance(required, list)
        or not required
        or not set(required).issubset(allowed)
        or value.get("audit_event_count") != 6
    ):
        raise ValueError("observability policy is incomplete")
    return value


def _validate_events(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("observability events require schema_version 1")
    if value.get("synthetic_data_only") is not True:
        raise ValueError("observability events must declare synthetic_data_only")
    for field in ("request_id", "input_text", "output_text"):
        if not isinstance(value.get(field), str) or not value[field]:
            raise ValueError(f"observability events require {field}")
    markers = value.get("sensitive_markers")
    events = value.get("events")
    if (
        not isinstance(markers, list)
        or len(markers) != 2
        or not all(isinstance(item, str) and item for item in markers)
        or not all(item in value["input_text"] and item in value["output_text"] for item in markers)
        or not isinstance(events, list)
        or len(events) != 6
    ):
        raise ValueError("observability event fixture is incomplete")
    seen: set[str] = set()
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("observability event must be an object")
        name = event.get("name")
        attributes = event.get("attributes")
        if (
            not isinstance(name, str)
            or not name
            or name in seen
            or not isinstance(attributes, dict)
            or not all(
                isinstance(key, str) and isinstance(item, str | int | bool)
                for key, item in attributes.items()
            )
            or event.get("content_source") not in {None, "input", "output"}
        ):
            raise ValueError("observability event is invalid")
        seen.add(name)
    return value


def _content_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _safe_event_attributes(
    event: dict[str, Any], *, input_text: str, output_text: str
) -> dict[str, str | int | bool]:
    attributes = dict(event["attributes"])
    source = event.get("content_source")
    if source == "input":
        attributes["content.sha256"] = _content_sha256(input_text)
    elif source == "output":
        attributes["content.sha256"] = _content_sha256(output_text)
    return attributes


def _marker_summary(spans: list[dict[str, Any]], markers: list[str]) -> dict[str, int]:
    marker_hits = 0
    spans_with_markers = 0
    for span in spans:
        values = [str(value) for value in span["attributes"].values()]
        hits = sum(value.count(marker) for value in values for marker in markers)
        marker_hits += hits
        spans_with_markers += int(hits > 0)
    return {"marker_hits": marker_hits, "spans_with_sensitive_values": spans_with_markers}


def _safe_trace_summary(
    spans: list[dict[str, Any]], policy: dict[str, Any]
) -> dict[str, int | bool]:
    allowlist = set(policy["safe_attribute_allowlist"])
    required = set(policy["required_safe_attributes"])
    violations = sum(len(set(span["attributes"]) - allowlist) for span in spans)
    missing_required = sum(not required.issubset(span["attributes"]) for span in spans)
    trace_ids = {span["trace_id"] for span in spans}
    return {
        "allowlist_violations": violations,
        "spans_missing_required_attributes": missing_required,
        "one_trace_id": len(trace_ids) == 1,
    }


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _event_hmac(key: bytes, payload: dict[str, Any]) -> str:
    return hmac.new(key, _canonical_json(payload), hashlib.sha256).hexdigest()


def build_audit_chain(
    events: list[dict[str, Any]],
    *,
    key: bytes,
    trace_id: str,
    request_id: str,
    policy_version: str,
    generated_at: datetime,
    input_text: str,
    output_text: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build one canonical HMAC-linked event chain and signed terminal checkpoint."""
    if len(key) < 32:
        raise ValueError("audit HMAC key must contain at least 32 bytes")
    records: list[dict[str, Any]] = []
    previous_hmac = ZERO_HMAC
    for sequence, event in enumerate(events, start=1):
        payload = {
            "sequence": sequence,
            "occurred_at": (generated_at + timedelta(milliseconds=sequence)).isoformat(),
            "trace_id": trace_id,
            "request_id": request_id,
            "policy_version": policy_version,
            "event_name": event["name"],
            "attributes": _safe_event_attributes(
                event,
                input_text=input_text,
                output_text=output_text,
            ),
            "previous_hmac": previous_hmac,
        }
        record = {**payload, "hmac": _event_hmac(key, payload)}
        records.append(record)
        previous_hmac = record["hmac"]
    checkpoint_payload = {"event_count": len(records), "final_hmac": previous_hmac}
    checkpoint = {
        **checkpoint_payload,
        "checkpoint_hmac": _event_hmac(key, checkpoint_payload),
    }
    return records, checkpoint


def verify_audit_chain(
    records: list[dict[str, Any]],
    *,
    key: bytes,
    checkpoint: dict[str, Any] | None,
) -> dict[str, str | bool | int]:
    """Verify sequence, links, record HMACs, and an optional terminal checkpoint."""
    previous_hmac = ZERO_HMAC
    for expected_sequence, record in enumerate(records, start=1):
        if record.get("sequence") != expected_sequence:
            return {"valid": False, "failure": "sequence", "checked_records": expected_sequence - 1}
        if record.get("previous_hmac") != previous_hmac:
            return {
                "valid": False,
                "failure": "previous_hmac",
                "checked_records": expected_sequence - 1,
            }
        payload = {key_name: value for key_name, value in record.items() if key_name != "hmac"}
        expected_hmac = _event_hmac(key, payload)
        if not hmac.compare_digest(str(record.get("hmac", "")), expected_hmac):
            return {
                "valid": False,
                "failure": "record_hmac",
                "checked_records": expected_sequence - 1,
            }
        previous_hmac = expected_hmac
    if checkpoint is not None:
        payload = {
            "event_count": checkpoint.get("event_count"),
            "final_hmac": checkpoint.get("final_hmac"),
        }
        if not hmac.compare_digest(
            str(checkpoint.get("checkpoint_hmac", "")), _event_hmac(key, payload)
        ):
            return {"valid": False, "failure": "checkpoint_hmac", "checked_records": len(records)}
        if payload != {"event_count": len(records), "final_hmac": previous_hmac}:
            return {"valid": False, "failure": "checkpoint_value", "checked_records": len(records)}
    return {"valid": True, "failure": "", "checked_records": len(records)}


def _tamper_results(
    records: list[dict[str, Any]], *, key: bytes, checkpoint: dict[str, Any]
) -> dict[str, dict[str, str | bool | int]]:
    mutated = deepcopy(records)
    mutated[1]["attributes"]["decision"] = "deny"
    deleted_middle = deepcopy(records)
    del deleted_middle[2]
    reordered = deepcopy(records)
    reordered[1], reordered[2] = reordered[2], reordered[1]
    inserted = deepcopy(records)
    inserted.insert(2, {**deepcopy(records[2]), "sequence": 3, "event_name": "forged_event"})
    deleted_tail = deepcopy(records[:-1])
    return {
        "mutate_record": verify_audit_chain(mutated, key=key, checkpoint=checkpoint),
        "delete_middle": verify_audit_chain(deleted_middle, key=key, checkpoint=checkpoint),
        "reorder_records": verify_audit_chain(reordered, key=key, checkpoint=checkpoint),
        "insert_forged": verify_audit_chain(inserted, key=key, checkpoint=checkpoint),
        "delete_tail_with_checkpoint": verify_audit_chain(
            deleted_tail, key=key, checkpoint=checkpoint
        ),
        "delete_tail_without_checkpoint": verify_audit_chain(
            deleted_tail, key=key, checkpoint=None
        ),
    }


def run_observability_experiment(
    experiment: str,
    *,
    runtime: TraceRuntime | None = None,
    hmac_key: bytes | None = None,
) -> dict[str, Any]:
    """Run the fixed Day 27 trace and audit-chain comparison once."""
    definition = load_observability_definition(experiment)
    policy_value, policy_evidence = _load_json_fixture(definition["policy"], experiment)
    events_value, events_evidence = _load_json_fixture(definition["events"], experiment)
    policy = _validate_policy(policy_value)
    fixture = _validate_events(events_value)
    runtime = runtime or _load_otel_runtime()
    key = hmac_key or secrets.token_bytes(32)
    generated_at = datetime.now(UTC)
    network_error = RuntimeError("Day 27 forbids network access")
    with (
        patch("socket.create_connection", side_effect=network_error),
        patch.object(socket.socket, "connect", side_effect=network_error),
    ):
        profiles = {
            profile: runtime.capture(
                profile=profile,
                request_id=fixture["request_id"],
                policy_version=policy["version"],
                input_text=fixture["input_text"],
                output_text=fixture["output_text"],
                events=fixture["events"],
            )
            for profile in PROFILES
        }
    unsafe_markers = _marker_summary(profiles["unsafe_attributes"], fixture["sensitive_markers"])
    safe_markers = _marker_summary(profiles["safe_attributes"], fixture["sensitive_markers"])
    safe_trace = _safe_trace_summary(profiles["safe_attributes"], policy)
    trace_id = profiles["safe_attributes"][0]["trace_id"]
    records, checkpoint = build_audit_chain(
        fixture["events"],
        key=key,
        trace_id=trace_id,
        request_id=fixture["request_id"],
        policy_version=policy["version"],
        generated_at=generated_at,
        input_text=fixture["input_text"],
        output_text=fixture["output_text"],
    )
    clean_verification = verify_audit_chain(records, key=key, checkpoint=checkpoint)
    tamper = _tamper_results(records, key=key, checkpoint=checkpoint)
    detected_cases = sum(
        not tamper[name]["valid"]
        for name in (
            "mutate_record",
            "delete_middle",
            "reorder_records",
            "insert_forged",
            "delete_tail_with_checkpoint",
        )
    )
    predictions = {
        "unsafe_trace_contains_every_marker": unsafe_markers["marker_hits"]
        >= len(fixture["sensitive_markers"]),
        "safe_trace_contains_no_marker": safe_markers["marker_hits"] == 0,
        "safe_trace_uses_only_allowlisted_attributes": safe_trace["allowlist_violations"] == 0,
        "safe_trace_has_required_correlation": safe_trace["one_trace_id"]
        and safe_trace["spans_missing_required_attributes"] == 0,
        "clean_audit_chain_verifies": clean_verification["valid"],
        "checkpoint_detects_all_registered_tampering": detected_cases == 5,
        "tail_truncation_requires_checkpoint": not tamper["delete_tail_with_checkpoint"]["valid"]
        and tamper["delete_tail_without_checkpoint"]["valid"],
    }
    return {
        "schema_version": 1,
        "experiment": experiment,
        "runner": OBSERVABILITY_RUNNER,
        "generated_at": generated_at.isoformat(),
        "tooling": {"opentelemetry_sdk": runtime.version, "audit_hmac": "HMAC-SHA-256"},
        "fixtures": [policy_evidence, events_evidence],
        "policy_version": policy["version"],
        "sensitive_markers": fixture["sensitive_markers"],
        "profiles": profiles,
        "profile_summary": {
            "unsafe_attributes": {"spans": len(profiles["unsafe_attributes"]), **unsafe_markers},
            "safe_attributes": {
                "spans": len(profiles["safe_attributes"]),
                **safe_markers,
                **safe_trace,
            },
        },
        "audit": {
            "records": records,
            "checkpoint": checkpoint,
            "clean_verification": clean_verification,
            "tamper_results": tamper,
            "registered_tamper_cases": 5,
            "detected_tamper_cases": detected_cases,
            "key_persisted": False,
        },
        "prediction_checks": predictions,
        "all_predictions_matched": all(predictions.values()),
        "safety_boundary": {
            "synthetic_data_only": True,
            "model_calls": 0,
            "network_calls": 0,
            "external_side_effects": 0,
            "raw_text_in_sanitized_report": False,
        },
    }


def _load_otel_runtime() -> TraceRuntime:
    try:
        from importlib.metadata import version

        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    except ImportError as error:
        raise ValueError(
            "OpenTelemetry SDK is unavailable; run with --extra observability"
        ) from error

    sdk_version = version("opentelemetry-sdk")

    class Runtime:
        version = sdk_version

        def capture(
            self,
            *,
            profile: str,
            request_id: str,
            policy_version: str,
            input_text: str,
            output_text: str,
            events: list[dict[str, Any]],
        ) -> list[dict[str, Any]]:
            exporter = InMemorySpanExporter()
            provider = TracerProvider(
                resource=Resource.create({"service.name": "llm-security-day27"})
            )
            provider.add_span_processor(SimpleSpanProcessor(exporter))
            tracer = provider.get_tracer("llm_security_lab.day27")
            with tracer.start_as_current_span("llm.request") as root:
                root.set_attribute("request.id", request_id)
                root.set_attribute("policy.version", policy_version)
                root.set_attribute("event.name", "llm_request")
                root.set_attribute("content.sha256", _content_sha256(input_text))
                if profile == "unsafe_attributes":
                    root.set_attribute("input.text", input_text)
                for event in events:
                    with tracer.start_as_current_span(event["name"]) as span:
                        span.set_attribute("request.id", request_id)
                        span.set_attribute("policy.version", policy_version)
                        span.set_attribute("event.name", event["name"])
                        for key, value in _safe_event_attributes(
                            event,
                            input_text=input_text,
                            output_text=output_text,
                        ).items():
                            span.set_attribute(key, value)
                        if profile == "unsafe_attributes" and event["name"] == "output_reviewed":
                            span.set_attribute("output.text", output_text)
            provider.force_flush()
            finished = sorted(exporter.get_finished_spans(), key=lambda span: span.start_time)
            serialized = [
                {
                    "name": span.name,
                    "trace_id": f"{span.context.trace_id:032x}",
                    "span_id": f"{span.context.span_id:016x}",
                    "parent_span_id": (
                        f"{span.parent.span_id:016x}" if span.parent is not None else None
                    ),
                    "attributes": dict(span.attributes),
                }
                for span in finished
            ]
            provider.shutdown()
            return serialized

    return Runtime()


def _summary_from_batch(batch: dict[str, Any]) -> dict[str, Any]:
    markers = batch["sensitive_markers"]
    unsafe = batch["profiles"]["unsafe_attributes"]
    safe = batch["profiles"]["safe_attributes"]
    policy = _validate_policy(
        json.loads(
            (experiment_root(batch["experiment"]) / "fixtures" / "policy.json").read_text(
                encoding="utf-8"
            )
        )
    )
    return {
        "unsafe_attributes": {"spans": len(unsafe), **_marker_summary(unsafe, markers)},
        "safe_attributes": {
            "spans": len(safe),
            **_marker_summary(safe, markers),
            **_safe_trace_summary(safe, policy),
        },
    }


def _validated_batch(batch: Any) -> dict[str, Any]:
    if not isinstance(batch, dict) or batch.get("runner") != OBSERVABILITY_RUNNER:
        raise ValueError("raw evidence is not a Day 27 observability batch")
    profiles = batch.get("profiles")
    if not isinstance(profiles, dict) or set(profiles) != set(PROFILES):
        raise ValueError("observability profile evidence is incomplete")
    if batch.get("profile_summary") != _summary_from_batch(batch):
        raise ValueError("observability profile summary does not match spans")
    audit = batch.get("audit")
    if (
        not isinstance(audit, dict)
        or audit.get("registered_tamper_cases") != 5
        or audit.get("detected_tamper_cases") != 5
        or audit.get("key_persisted") is not False
        or audit.get("clean_verification", {}).get("valid") is not True
        or audit.get("tamper_results", {}).get("delete_tail_without_checkpoint", {}).get("valid")
        is not True
    ):
        raise ValueError("observability audit summary is invalid")
    predictions = batch.get("prediction_checks")
    if not isinstance(predictions, dict) or batch.get("all_predictions_matched") is not all(
        predictions.values()
    ):
        raise ValueError("observability prediction summary does not match results")
    if batch.get("all_predictions_matched") is not True:
        raise ValueError("observability experiment did not match preregistered predictions")
    expected_safety = {
        "synthetic_data_only": True,
        "model_calls": 0,
        "network_calls": 0,
        "external_side_effects": 0,
        "raw_text_in_sanitized_report": False,
    }
    if batch.get("safety_boundary") != expected_safety:
        raise ValueError("observability experiment violated its safety boundary")
    return batch


def load_observability_batch(path: Path) -> dict[str, Any]:
    """Load and validate raw Day 27 evidence."""
    return _validated_batch(json.loads(path.read_text(encoding="utf-8")))


def render_observability_report(batch: dict[str, Any]) -> str:
    """Render a sanitized report without trace attributes, audit records, or marker values."""
    batch = _validated_batch(batch)
    unsafe = batch["profile_summary"]["unsafe_attributes"]
    safe = batch["profile_summary"]["safe_attributes"]
    audit = batch["audit"]
    return "\n".join(
        [
            f"Experiment: {batch['experiment']}",
            f"Generated at: {batch['generated_at']}",
            f"OpenTelemetry SDK: {batch['tooling']['opentelemetry_sdk']}",
            "",
            "Trace profiles:",
            f"- unsafe_attributes: spans={unsafe['spans']}, marker_hits={unsafe['marker_hits']}, spans_with_sensitive_values={unsafe['spans_with_sensitive_values']}",
            f"- safe_attributes: spans={safe['spans']}, marker_hits={safe['marker_hits']}, allowlist_violations={safe['allowlist_violations']}, missing_required={safe['spans_missing_required_attributes']}, one_trace_id={str(safe['one_trace_id']).lower()}",
            "",
            "Audit chain:",
            f"- records={len(audit['records'])}, clean_valid={str(audit['clean_verification']['valid']).lower()}",
            f"- registered_tamper_cases={audit['registered_tamper_cases']}, detected={audit['detected_tamper_cases']}",
            f"- tail_without_checkpoint_valid={str(audit['tamper_results']['delete_tail_without_checkpoint']['valid']).lower()}",
            "",
            f"Prediction checks: {json.dumps(batch['prediction_checks'], sort_keys=True)}",
            "Synthetic data only: true",
            "Model calls: 0",
            "Network calls: 0",
            "External side effects: 0",
        ]
    )
