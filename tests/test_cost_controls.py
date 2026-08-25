from __future__ import annotations

import json
from pathlib import Path

import pytest

from llm_security_lab import cost_controls

DAY_28 = "day-28-dos-token-cost-controls"


def test_cost_control_bundle_is_discoverable() -> None:
    assert cost_controls.available_cost_control_experiments() == [DAY_28]


def test_fixed_matrix_matches_predictions_and_stays_offline() -> None:
    batch = cost_controls.run_cost_control_experiment(DAY_28)

    assert batch["all_predictions_matched"] is True
    assert batch["summary"]["unbounded"]["admitted_requests"] == 19
    assert batch["summary"]["layered_controls"]["admitted_requests"] == 12
    assert batch["summary"]["layered_controls"]["rejected_requests"] == 7
    assert batch["safety_boundary"]["model_calls"] == 0
    assert batch["safety_boundary"]["network_calls"] == 0
    assert batch["safety_boundary"]["external_side_effects"] == 0


def test_every_control_has_an_isolated_rejection_case() -> None:
    batch = cost_controls.run_cost_control_experiment(DAY_28)
    reasons = batch["summary"]["layered_controls"]["rejection_reasons"]

    assert reasons == {
        "budget_limit": 1,
        "concurrency_limit": 1,
        "input_token_limit": 1,
        "output_token_limit": 1,
        "request_rate_limit": 2,
        "total_token_limit": 1,
    }


def test_budget_and_concurrency_limits_bound_the_controlled_path() -> None:
    batch = cost_controls.run_cost_control_experiment(DAY_28)
    cases = {case["id"]: case for case in batch["case_results"]}

    budget = cases["budget_exhaustion"]["profiles"]
    assert budget["unbounded"]["budget_overrun_token_units"] == 100
    assert budget["layered_controls"]["budget_overrun_token_units"] == 0
    concurrency = cases["concurrency_spike"]["profiles"]
    assert concurrency["unbounded"]["peak_concurrency"] == 3
    assert concurrency["layered_controls"]["peak_concurrency"] == 2


def test_report_omits_subject_and_request_identifiers() -> None:
    report = cost_controls.render_cost_control_report(
        cost_controls.run_cost_control_experiment(DAY_28)
    )

    assert "synthetic-budget" not in report
    assert "budget-1" not in report
    assert "requests=19, admitted=19" in report
    assert "requests=19, admitted=12" in report


def test_report_rejects_tampered_results(tmp_path: Path) -> None:
    batch = cost_controls.run_cost_control_experiment(DAY_28)
    batch["summary"]["layered_controls"]["admitted_requests"] = 99
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="summary"):
        cost_controls.load_cost_control_batch(path)


def test_report_rejects_external_activity(tmp_path: Path) -> None:
    batch = cost_controls.run_cost_control_experiment(DAY_28)
    batch["safety_boundary"]["network_calls"] = 1
    path = tmp_path / "unsafe.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="safety boundary"):
        cost_controls.load_cost_control_batch(path)
