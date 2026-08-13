from __future__ import annotations

import json
from pathlib import Path

import pytest

from llm_security_lab import agency, lab

DAY_18 = "day-18-excessive-agency"


def test_agency_bundle_is_discoverable_without_changing_model_choices() -> None:
    assert agency.available_agency_experiments() == [DAY_18]
    assert DAY_18 not in lab.available_experiments()


def test_day_18_fixed_matrix_matches_predictions() -> None:
    batch = agency.run_agency_experiment(DAY_18)

    assert batch["summary"] == {
        "cases": 7,
        "matched_expected": 7,
        "all_expected": True,
        "proposals": 9,
        "executed": 5,
        "blocked": 4,
        "flagged": 5,
        "side_effects": 5,
    }
    assert batch["safety_boundary"] == {
        "synthetic_data_only": True,
        "model_called": False,
        "network_access": False,
        "external_side_effects": False,
        "side_effect_store": "in_memory",
    }


def test_functionality_is_checked_before_permissions_and_approval() -> None:
    batch = agency.run_agency_experiment(DAY_18)
    case = next(item for item in batch["cases"] if item["case_id"] == "function-limited")

    assert case["observed"]["outcomes"][0]["reason_code"] == "function_not_available"
    assert case["observed"]["side_effects"] == []


def test_exact_approval_is_invalid_after_body_mutation() -> None:
    batch = agency.run_agency_experiment(DAY_18)
    approved = next(item for item in batch["cases"] if item["case_id"] == "exact-envelope-approved")
    changed = next(item for item in batch["cases"] if item["case_id"] == "changed-after-approval")

    assert approved["observed"]["outcomes"][0]["decision"] == "execute"
    assert changed["observed"]["outcomes"][0]["decision"] == "block"
    assert (
        approved["observed"]["outcomes"][0]["envelope_sha256"]
        != changed["observed"]["outcomes"][0]["envelope_sha256"]
    )


def test_batch_isolates_flagged_item_but_keyword_paraphrase_passes() -> None:
    batch = agency.run_agency_experiment(DAY_18)
    flagged = next(item for item in batch["cases"] if item["case_id"] == "batch-isolates-flagged")
    paraphrase = next(
        item for item in batch["cases"] if item["case_id"] == "keyword-paraphrase-not-flagged"
    )

    assert [item["decision"] for item in flagged["observed"]["outcomes"]] == [
        "execute",
        "block",
        "execute",
    ]
    assert paraphrase["observed"]["outcomes"][0]["risk_findings"] == []
    assert paraphrase["observed"]["outcomes"][0]["decision"] == "execute"


def test_report_excludes_message_contents_and_identity() -> None:
    rendered = agency.render_agency_report(agency.run_agency_experiment(DAY_18))

    assert "salary table" not in rendered
    assert "subject-user-alice" not in rendered
    assert "attacker@example.test" not in rendered
    assert "function-limited/send-sensitive" in rendered


def test_report_rejects_tampered_summary(tmp_path: Path) -> None:
    batch = agency.run_agency_experiment(DAY_18)
    batch["summary"]["executed"] = 99
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="summary does not match"):
        agency.load_agency_batch(path)
