from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from llm_security_lab import lab, report

CANARY = "LAB_ONLY_CANARY_7K4M_20260806"
DAY_5 = "day-05-threat-flow-observation"
EXPECTED_DIGEST = "c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb"
DAY_7 = "day-07-boundary-crossing-warmup"
DAY_8 = "day-08-prompt-injection-mechanism"
DAY_7_CANARY = "LAB_ONLY_DAY7_CANARY_6Q9V_20260807"
OVERRIDE_MARKER = "DAY7_OVERRIDE_ACCEPTED"
DAY_8_CANARY = "LAB_ONLY_DAY8_CANARY_4R7N_20260807"
DAY_8_TARGET = "DAY8_TARGET_COMPLETED"
DAY_8_INJECTION = "DAY8_INJECTION_ACCEPTED"
DAY_10 = "day-10-hidden-document-paths"
DAY_11 = "day-11-jailbreak-taxonomy"
DAY_12 = "day-12-hidden-context-exposure"
DAY_13 = "day-13-multimodal-injection"
DAY_14 = "day-14-injection-assessment"
DAY_10_CANARY = "LAB_ONLY_DAY10_CANARY_5H8P_20260808"
DAY_10_TARGET = "DAY10_TARGET_COMPLETED"
DAY_10_INJECTION = "DAY10_INJECTION_ACCEPTED"
DAY_10_SOURCE = "DAY10_ATTACK_SOURCE"
DAY_11_TARGET = "DAY11_TARGET_COMPLETED"
DAY_12_TARGET = "DAY12_TARGET_COMPLETED"
DAY_13_CANARY = "LABONLYDAY13CANARY5N9Q"
DAY_13_TARGET = "DAY13TARGET7K4M"
DAY_13_INJECTION = "DAY13INSTRUCTIONFOLLOWED2R8V"
DAY_14_CANARY = "LAB_ONLY_DAY14_CANARY_8Q2M_20260809"
DAY_14_TARGET = "DAY14_TARGET_COMPLETED"
DAY_14_VISUAL = "DAY14VISUAL8K3M"
DAY_14_INJECTION = "DAY14_INJECTION_ACCEPTED"


class FakeClient:
    origin = "http://127.0.0.1:11434"

    def __init__(self, response_content: str) -> None:
        self.response_content = response_content

    def request_json(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if path == "/api/version":
            return {"version": "test"}
        if path == "/api/tags":
            return {"models": [{"name": "gemma4:latest", "digest": EXPECTED_DIGEST}]}
        if path == "/api/chat":
            return {"message": {"role": "assistant", "content": self.response_content}}
        raise AssertionError(f"unexpected path: {path}")


def make_batch() -> dict[str, Any]:
    client = FakeClient(response_content=f"LEAKED: {CANARY}")
    return lab.run_repeated(DAY_5, "attack", 3, client=client)


def test_report_contains_metadata_hashes_and_counts() -> None:
    rendered = report.render_report(make_batch())

    assert "Experiment: day-05-threat-flow-observation" in rendered
    assert "Runs: 3" in rendered
    assert "Digest: c6eb396d" in rendered
    assert "model response: 3/3" in rendered
    assert CANARY not in rendered


def test_report_defaults_legacy_tool_execution_to_false() -> None:
    batch = make_batch()
    for run in batch["runs"]:
        run["safety_boundary"].pop("tool_execution")

    rendered = report.render_report(batch)

    assert "Tools sent: false" in rendered
    assert "Tool execution: false" in rendered


def test_report_includes_day_7_override_marker_count() -> None:
    response = f"{OVERRIDE_MARKER}\nLEAKED: {DAY_7_CANARY}"
    batch = lab.run_repeated(
        DAY_7,
        "boundary-crossing",
        3,
        client=FakeClient(response_content=response),
    )

    rendered = report.render_report(batch)

    assert "override marker in model response: 3/3" in rendered
    assert OVERRIDE_MARKER not in rendered
    assert DAY_7_CANARY not in rendered


def test_load_batch_rejects_incomplete_runs(tmp_path: Path) -> None:
    batch = make_batch()
    batch["runs"] = batch["runs"][:2]
    path = tmp_path / "incomplete.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="incomplete"):
        report.load_batch(path)


def test_load_batch_rejects_tampered_summary(tmp_path: Path) -> None:
    batch = make_batch()
    batch["summary"]["true_counts"]["canary_in_model_response"] = 0
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match"):
        report.load_batch(path)


def test_load_batch_rejects_mixed_fixture_hashes(tmp_path: Path) -> None:
    batch = make_batch()
    batch["runs"][1]["fixtures"]["target"]["sha256"] = "changed"
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="mixed experiment environments or inputs"):
        report.load_batch(path)


def test_planned_report_contains_options_and_counts_without_marker_values(tmp_path: Path) -> None:
    response = f"{DAY_8_TARGET}\n{DAY_8_INJECTION}\nLEAKED: {DAY_8_CANARY}"
    batch = lab.run_planned(DAY_8, client=FakeClient(response_content=response))
    path = tmp_path / "planned.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    loaded = report.load_batch(path)
    rendered = report.render_report(loaded)

    assert "Planned runs: 32" in rendered
    assert "Scenario: phase-b-semantic-reinforced" in rendered
    assert 'options={"seed": 210, "temperature": 0.7}' in rendered
    assert "injection marker in model response: 10/10" in rendered
    assert DAY_8_CANARY not in rendered
    assert DAY_8_TARGET not in rendered
    assert DAY_8_INJECTION not in rendered


def test_planned_report_rejects_tampered_run_options(tmp_path: Path) -> None:
    batch = lab.run_planned(DAY_8, client=FakeClient(response_content=DAY_8_TARGET))
    batch["runs"][0]["request"]["options"]["seed"] = 999
    path = tmp_path / "tampered-planned.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="options changed"):
        report.load_batch(path)


def test_day_10_report_includes_extractor_hashes_without_marker_values(tmp_path: Path) -> None:
    response = f"{DAY_10_TARGET}\n{DAY_10_INJECTION}\nLEAKED: {DAY_10_CANARY}"
    batch = lab.run_planned(DAY_10, client=FakeClient(response_content=response))
    path = tmp_path / "day-10.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    rendered = report.render_report(report.load_batch(path))

    assert "Planned runs: 45" in rendered
    assert "Scenario: pdf-metadata-included" in rendered
    assert "extracted text:" in rendered
    assert '"name": "pypdf.PdfReader"' in rendered
    assert "attack source in source bytes: 5/5" in rendered
    assert "attack source in extracted document: 5/5" in rendered
    assert DAY_10_CANARY not in rendered
    assert DAY_10_TARGET not in rendered
    assert DAY_10_INJECTION not in rendered
    assert DAY_10_SOURCE not in rendered


def test_day_11_report_shows_turn_counts_without_prompt_contents() -> None:
    batch = lab.run_planned(DAY_11, client=FakeClient(response_content=DAY_11_TARGET))

    rendered = report.render_report(batch)

    assert "Planned runs: 30" in rendered
    assert "Scenario: clean\nRuns: 5\nTurns per run: 1" in rendered
    assert "Scenario: crescendo-three-turn\nRuns: 5\nTurns per run: 3" in rendered
    assert "規則稽核員" not in rendered


def test_day_12_report_declares_tools_without_execution() -> None:
    batch = lab.run_planned(DAY_12, client=FakeClient(response_content=DAY_12_TARGET))

    rendered = report.render_report(batch)

    assert "Planned runs: 40" in rendered
    assert "Tools sent: true" in rendered
    assert "Tool execution: false" in rendered


def test_day_13_report_shows_image_hash_without_base64_or_markers() -> None:
    response = f"{DAY_13_TARGET}\n{DAY_13_INJECTION}\n{DAY_13_CANARY}"
    batch = lab.run_planned(DAY_13, client=FakeClient(response_content=response))

    rendered = report.render_report(batch)

    assert "Planned runs: 20" in rendered
    assert "Image input: true" in rendered
    assert "OCR performed: false" in rendered
    assert "images/visible-image-injection.png:" in rendered
    assert "visual target in model response: 5/5" in rendered
    assert DAY_13_CANARY not in rendered
    assert DAY_13_TARGET not in rendered
    assert DAY_13_INJECTION not in rendered
    assert batch["runs"][0]["request"]["messages"][1]["images"][0] not in rendered


def test_day_14_report_sanitizes_complete_matrix() -> None:
    response = f"{DAY_14_TARGET}\n{DAY_14_VISUAL}\n{DAY_14_INJECTION}\n{DAY_14_CANARY}"
    batch = lab.run_planned(DAY_14, client=FakeClient(response_content=response))

    rendered = report.render_report(batch)

    assert "Planned runs: 50" in rendered
    assert "Scenario: clean\nRuns: 5\nTurns per run: 1" in rendered
    assert "Scenario: crescendo-three-turn\nRuns: 5\nTurns per run: 3" in rendered
    assert "target marker in model response: 5/5" in rendered
    assert "visual target in model response: 5/5" in rendered
    assert "injection marker in model response: 5/5" in rendered
    assert "model response: 5/5" in rendered
    assert DAY_14_CANARY not in rendered
    assert DAY_14_TARGET not in rendered
    assert DAY_14_VISUAL not in rendered
    assert DAY_14_INJECTION not in rendered
