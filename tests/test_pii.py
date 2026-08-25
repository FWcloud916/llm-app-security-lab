from __future__ import annotations

import json
from pathlib import Path

import pytest

from llm_security_lab import pii

DAY_26 = "day-26-pii-detection-masking"


class FakePresidioRuntime:
    version = "test-presidio"
    nlp_model = "test-model"

    def detect(self, text: str, *, layered: bool, entities: list[str]) -> list[pii.Detection]:
        del entities
        detections: list[pii.Detection] = []
        for entity_type, value in (
            ("EMAIL_ADDRESS", "@example.test"),
            ("PERSON", " Example"),
            ("CREDIT_CARD", "4242 4242 4242 4242"),
            ("CREDIT_CARD", "5555 5555 5555 4444"),
        ):
            if value not in text:
                continue
            if entity_type == "EMAIL_ADDRESS":
                start = text.rfind(" ", 0, text.index(value)) + 1
                end = text.index(value) + len(value)
            elif entity_type == "PERSON":
                end = text.index(value) + len(value)
                start = text.rfind(" ", 0, text.index(value)) + 1
            else:
                start = text.index(value)
                end = start + len(value)
            detections.append(pii.Detection(entity_type, start, end, 0.9))
        if layered:
            policy = pii._validate_policy(
                json.loads(
                    (pii.experiment_root(DAY_26) / "fixtures" / "policy.json").read_text(
                        encoding="utf-8"
                    )
                )
            )
            detections.extend(pii.application_detections(text, policy))
        return pii._normalize_detections(detections)

    def anonymize(self, text: str, detections: list[pii.Detection]) -> str:
        return pii.mask_text(text, detections)


def test_pii_bundle_is_discoverable_without_entering_generic_runner() -> None:
    assert pii.available_pii_experiments() == [DAY_26]


def test_application_rules_validate_luhn_and_avoid_near_matches() -> None:
    policy = pii._validate_policy(
        json.loads(
            (pii.experiment_root(DAY_26) / "fixtures" / "policy.json").read_text(encoding="utf-8")
        )
    )
    detected = pii.application_detections(
        "4242 4242 4242 4242 and 4242 4242 4242 4241 and CUST-2601", policy
    )

    assert [(item.entity_type, item.start, item.end) for item in detected] == [
        ("CREDIT_CARD", 0, 19),
        ("CUSTOMER_ID", 48, 57),
    ]


def test_fixed_matrix_matches_predictions_and_stays_offline() -> None:
    batch = pii.run_pii_experiment(DAY_26, runtime=FakePresidioRuntime())

    assert len(batch["results"]) == 96
    assert batch["profiles"]["raw"]["expected_entities"] == 16
    assert batch["profiles"]["raw"]["unmasked_expected_values"] == 16
    assert batch["profiles"]["application_rules"]["false_negative"] > 0
    assert (
        batch["profiles"]["layered"]["recall"] >= batch["profiles"]["application_rules"]["recall"]
    )
    assert batch["profiles"]["application_rules"]["false_positive"] == 0
    assert batch["all_predictions_matched"] is True
    assert batch["safety_boundary"]["network_calls"] == 0
    assert batch["safety_boundary"]["model_calls"] == 0


def test_report_omits_fixture_text_and_values() -> None:
    report = pii.render_pii_report(pii.run_pii_experiment(DAY_26, runtime=FakePresidioRuntime()))

    assert "avery.day26@example.test" not in report
    assert "0900-000-026" not in report
    assert "4242 4242 4242 4242" not in report
    assert "Synthetic data only: true" in report


def test_report_rejects_tampered_profile_summary(tmp_path: Path) -> None:
    batch = pii.run_pii_experiment(DAY_26, runtime=FakePresidioRuntime())
    batch["profiles"]["raw"]["expected_entities"] = 999
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="summary does not match"):
        pii.load_pii_batch(path)


def test_report_rejects_external_activity(tmp_path: Path) -> None:
    batch = pii.run_pii_experiment(DAY_26, runtime=FakePresidioRuntime())
    batch["safety_boundary"]["network_calls"] = 1
    path = tmp_path / "unsafe.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="safety boundary"):
        pii.load_pii_batch(path)
