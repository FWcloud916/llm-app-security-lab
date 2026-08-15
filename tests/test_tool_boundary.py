from __future__ import annotations

import json
from pathlib import Path

import pytest

from llm_security_lab import lab, tool_boundary

DAY_19 = "day-19-tool-calling-security"


def _case(batch: dict[str, object], case_id: str) -> dict[str, object]:
    cases = batch["cases"]
    assert isinstance(cases, list)
    return next(item for item in cases if item["case_id"] == case_id)


def test_tool_boundary_bundle_is_discoverable_without_changing_model_choices() -> None:
    assert tool_boundary.available_tool_boundary_experiments() == [DAY_19]
    assert DAY_19 not in lab.available_experiments()


def test_day_19_fixed_matrix_matches_predictions_and_stays_offline() -> None:
    batch = tool_boundary.run_tool_boundary_experiment(DAY_19)

    assert batch["summary"] == {
        "cases": 5,
        "path_evaluations": 10,
        "matched_expected": 5,
        "all_expected": True,
        "vulnerable_sink_reached": 4,
        "hardened_sink_reached": 1,
        "hardened_blocks": 3,
        "tool_outputs_exposed": 1,
        "tool_outputs_contained": 1,
        "in_memory_sink_events": 5,
    }
    assert batch["safety_boundary"] == {
        "synthetic_data_only": True,
        "model_calls": 0,
        "network_calls": 0,
        "subprocess_calls": 0,
        "external_side_effects": 0,
        "side_effect_store": "in_memory",
    }


def test_strict_schema_rejects_forged_authority_field() -> None:
    batch = tool_boundary.run_tool_boundary_experiment(DAY_19)
    case = _case(batch, "forged-authority-field")

    assert case["observed"]["vulnerable"]["sink_reached"] is True
    hardened = case["observed"]["hardened"]
    assert hardened["reason_code"] == "schema_rejected"
    assert hardened["schema_errors"] == ["extra:approved"]


def test_schema_valid_private_url_is_blocked_by_destination_policy() -> None:
    batch = tool_boundary.run_tool_boundary_experiment(DAY_19)
    hardened = _case(batch, "private-url-ssrf")["observed"]["hardened"]

    assert hardened["schema_valid"] is True
    assert hardened["destination_class"] == "loopback_ip"
    assert hardened["reason_code"] == "destination_not_allowed"
    assert hardened["sink_reached"] is False


def test_schema_valid_shell_text_never_starts_a_subprocess() -> None:
    batch = tool_boundary.run_tool_boundary_experiment(DAY_19)
    case = _case(batch, "shell-metacharacter-output-name")

    assert case["observed"]["vulnerable"]["sink_kind"] == "would_be_shell_string"
    assert case["observed"]["hardened"]["reason_code"] == "unsafe_output_name"
    assert batch["safety_boundary"]["subprocess_calls"] == 0


def test_tool_output_remains_untrusted_and_has_no_dispatch_authority() -> None:
    batch = tool_boundary.run_tool_boundary_experiment(DAY_19)
    case = _case(batch, "tool-output-reinjection")

    assert case["observed"]["vulnerable"]["output_trust"] == "trusted_instruction"
    hardened = case["observed"]["hardened"]
    assert hardened["decision"] == "contain"
    assert hardened["output_trust"] == "untrusted_data"
    assert hardened["sink_reached"] is False


def test_report_excludes_raw_arguments_and_tool_output() -> None:
    rendered = tool_boundary.render_tool_boundary_report(
        tool_boundary.run_tool_boundary_experiment(DAY_19)
    )

    assert "127.0.0.1" not in rendered
    assert "/tmp/day19-owned" not in rendered
    assert "attacker@example.test" not in rendered
    assert "private-url-ssrf/hardened" in rendered


def test_report_rejects_tampered_summary(tmp_path: Path) -> None:
    batch = tool_boundary.run_tool_boundary_experiment(DAY_19)
    batch["summary"]["hardened_blocks"] = 99
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="summary does not match"):
        tool_boundary.load_tool_boundary_batch(path)


def test_report_rejects_nonzero_external_activity(tmp_path: Path) -> None:
    batch = tool_boundary.run_tool_boundary_experiment(DAY_19)
    batch["safety_boundary"]["network_calls"] = 1
    path = tmp_path / "unsafe.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="offline safety boundary"):
        tool_boundary.load_tool_boundary_batch(path)
