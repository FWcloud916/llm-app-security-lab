from __future__ import annotations

import json
from pathlib import Path

import pytest

from llm_security_lab import observability

DAY_27 = "day-27-observability-audit"


class FakeTraceRuntime:
    version = "test-otel"

    def capture(
        self,
        *,
        profile: str,
        request_id: str,
        policy_version: str,
        input_text: str,
        output_text: str,
        events: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        trace_id = "1" * 32
        spans: list[dict[str, object]] = [
            {
                "name": "llm.request",
                "trace_id": trace_id,
                "span_id": "1" * 16,
                "parent_span_id": None,
                "attributes": {
                    "request.id": request_id,
                    "policy.version": policy_version,
                    "event.name": "llm_request",
                    "content.sha256": observability._content_sha256(input_text),
                },
            }
        ]
        if profile == "unsafe_attributes":
            spans[0]["attributes"]["input.text"] = input_text
        for index, event in enumerate(events, start=2):
            attributes = {
                "request.id": request_id,
                "policy.version": policy_version,
                "event.name": event["name"],
                **observability._safe_event_attributes(
                    event,
                    input_text=input_text,
                    output_text=output_text,
                ),
            }
            if profile == "unsafe_attributes" and event["name"] == "output_reviewed":
                attributes["output.text"] = output_text
            spans.append(
                {
                    "name": event["name"],
                    "trace_id": trace_id,
                    "span_id": f"{index:016x}",
                    "parent_span_id": "1" * 16,
                    "attributes": attributes,
                }
            )
        return spans


def test_observability_bundle_is_discoverable() -> None:
    assert observability.available_observability_experiments() == [DAY_27]


def test_audit_chain_detects_registered_tampering_and_exposes_tail_limit() -> None:
    fixture = json.loads(
        (observability.experiment_root(DAY_27) / "fixtures" / "events.json").read_text(
            encoding="utf-8"
        )
    )
    records, checkpoint = observability.build_audit_chain(
        fixture["events"],
        key=b"k" * 32,
        trace_id="1" * 32,
        request_id=fixture["request_id"],
        policy_version="test-policy",
        generated_at=observability.datetime(2026, 8, 25, tzinfo=observability.UTC),
        input_text=fixture["input_text"],
        output_text=fixture["output_text"],
    )

    assert (
        observability.verify_audit_chain(records, key=b"k" * 32, checkpoint=checkpoint)["valid"]
        is True
    )
    tamper = observability._tamper_results(records, key=b"k" * 32, checkpoint=checkpoint)
    assert all(
        tamper[name]["valid"] is False
        for name in (
            "mutate_record",
            "delete_middle",
            "reorder_records",
            "insert_forged",
            "delete_tail_with_checkpoint",
        )
    )
    assert tamper["delete_tail_without_checkpoint"]["valid"] is True


def test_fixed_observability_matrix_matches_predictions_and_stays_offline() -> None:
    batch = observability.run_observability_experiment(
        DAY_27, runtime=FakeTraceRuntime(), hmac_key=b"k" * 32
    )

    assert batch["profile_summary"]["unsafe_attributes"]["marker_hits"] == 4
    assert batch["profile_summary"]["safe_attributes"]["marker_hits"] == 0
    assert batch["profile_summary"]["safe_attributes"]["allowlist_violations"] == 0
    assert batch["audit"]["detected_tamper_cases"] == 5
    assert batch["all_predictions_matched"] is True
    assert batch["safety_boundary"]["network_calls"] == 0
    assert batch["safety_boundary"]["model_calls"] == 0


def test_actual_otel_runtime_captures_one_safe_trace() -> None:
    pytest.importorskip("opentelemetry.sdk")
    fixture = json.loads(
        (observability.experiment_root(DAY_27) / "fixtures" / "events.json").read_text(
            encoding="utf-8"
        )
    )
    spans = observability._load_otel_runtime().capture(
        profile="safe_attributes",
        request_id=fixture["request_id"],
        policy_version="test-policy",
        input_text=fixture["input_text"],
        output_text=fixture["output_text"],
        events=fixture["events"],
    )

    assert len(spans) == 7
    assert len({span["trace_id"] for span in spans}) == 1
    assert all("input.text" not in span["attributes"] for span in spans)
    assert all("output.text" not in span["attributes"] for span in spans)


def test_report_omits_trace_text_markers_and_audit_records() -> None:
    report = observability.render_observability_report(
        observability.run_observability_experiment(
            DAY_27, runtime=FakeTraceRuntime(), hmac_key=b"k" * 32
        )
    )

    assert "CUST-2701" not in report
    assert "avery.day27@example.test" not in report
    assert "previous_hmac" not in report
    assert "registered_tamper_cases=5, detected=5" in report


def test_report_rejects_tampered_profile_summary(tmp_path: Path) -> None:
    batch = observability.run_observability_experiment(
        DAY_27, runtime=FakeTraceRuntime(), hmac_key=b"k" * 32
    )
    batch["profile_summary"]["safe_attributes"]["marker_hits"] = 99
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="profile summary"):
        observability.load_observability_batch(path)


def test_report_rejects_external_activity(tmp_path: Path) -> None:
    batch = observability.run_observability_experiment(
        DAY_27, runtime=FakeTraceRuntime(), hmac_key=b"k" * 32
    )
    batch["safety_boundary"]["network_calls"] = 1
    path = tmp_path / "unsafe.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="safety boundary"):
        observability.load_observability_batch(path)
