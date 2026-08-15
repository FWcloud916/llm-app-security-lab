from __future__ import annotations

import json
from pathlib import Path

import pytest

from llm_security_lab import lab, supply_chain

DAY_20 = "day-20-ai-supply-chain-security"


def _case(batch: dict[str, object], case_id: str) -> dict[str, object]:
    cases = batch["cases"]
    assert isinstance(cases, list)
    return next(item for item in cases if item["case_id"] == case_id)


def test_supply_chain_bundle_is_discoverable_without_changing_model_choices() -> None:
    assert supply_chain.available_supply_chain_experiments() == [DAY_20]
    assert DAY_20 not in lab.available_experiments()


def test_day_20_fixed_matrix_matches_predictions_and_stays_offline() -> None:
    batch = supply_chain.run_supply_chain_experiment(DAY_20)

    assert batch["summary"] == {
        "cases": 9,
        "matched_expected": 9,
        "all_expected": True,
        "allow": 3,
        "review": 3,
        "block": 3,
        "models": 3,
        "packages": 3,
        "mcp_servers": 3,
    }
    assert batch["safety_boundary"] == {
        "synthetic_manifests_only": True,
        "model_calls": 0,
        "network_calls": 0,
        "package_installs": 0,
        "artifact_loads": 0,
        "mcp_server_starts": 0,
        "subprocess_calls": 0,
        "external_side_effects": 0,
    }


def test_repository_audit_separates_integrity_from_provenance_and_configuration() -> None:
    components = {
        item["component"]: item
        for item in supply_chain.run_supply_chain_experiment(DAY_20)["repository_audit"][
            "components"
        ]
    }

    packages = components["python_packages"]
    assert packages["state"] == "review"
    assert packages["locked_packages"] > 0
    assert packages["artifact_hashes"] > 0
    assert packages["build_provenance_recorded"] is False
    models = components["model_references"]
    assert models["state"] == "review"
    assert models["all_references_have_full_digest"] is True
    assert models["artifact_format_recorded"] is False
    assert models["signature_or_provenance_recorded"] is False
    assert components["mcp_servers"]["state"] == "not_configured"


def test_signed_pickle_is_blocked_because_origin_is_not_safety() -> None:
    case = _case(supply_chain.run_supply_chain_experiment(DAY_20), "model-signed-pickle")

    assert case["input"]["provenance"] == "signed-publisher-commit"
    assert case["observed"]["decision"] == "block"
    assert case["observed"]["reason_code"] == "unsafe_model_format"


def test_package_hash_mismatch_blocks_even_with_complete_provenance() -> None:
    case = _case(supply_chain.run_supply_chain_experiment(DAY_20), "package-hash-mismatch")

    assert case["observed"]["decision"] == "block"
    assert case["observed"]["reason_code"] == "artifact_hash_mismatch"


def test_mcp_annotations_alone_require_review_and_complete_capability_evidence() -> None:
    case = _case(supply_chain.run_supply_chain_experiment(DAY_20), "mcp-annotations-only")

    assert case["observed"]["decision"] == "review"
    assert case["observed"]["reason_code"] == "tool_annotations_only"
    assert "token_passthrough" in case["observed"]["missing_evidence"]
    assert "tool_snapshot_sha256" in case["observed"]["missing_evidence"]


def test_mcp_capability_drift_blocks_a_previously_complete_declaration() -> None:
    case = _case(supply_chain.run_supply_chain_experiment(DAY_20), "mcp-capability-drift")

    assert case["observed"]["decision"] == "block"
    assert case["observed"]["reason_code"] == "mcp_capability_drift"


def test_report_excludes_raw_artifact_and_capability_values() -> None:
    rendered = supply_chain.render_supply_chain_report(
        supply_chain.run_supply_chain_experiment(DAY_20)
    )

    assert "api.example.test" not in rendered
    assert "/synthetic/private" not in rendered
    assert "SYNTHETIC_API_TOKEN" not in rendered
    assert "mcp-capability-drift" in rendered


def test_report_rejects_tampered_summary(tmp_path: Path) -> None:
    batch = supply_chain.run_supply_chain_experiment(DAY_20)
    batch["summary"]["block"] = 99
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="summary does not match"):
        supply_chain.load_supply_chain_batch(path)


@pytest.mark.parametrize("field", ["network_calls", "package_installs"])
def test_report_rejects_nonzero_external_activity(tmp_path: Path, field: str) -> None:
    batch = supply_chain.run_supply_chain_experiment(DAY_20)
    batch["safety_boundary"][field] = 1
    path = tmp_path / "unsafe.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="offline safety boundary"):
        supply_chain.load_supply_chain_batch(path)
