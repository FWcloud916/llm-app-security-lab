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
DAY_10_CANARY = "LAB_ONLY_DAY10_CANARY_5H8P_20260808"
DAY_10_TARGET = "DAY10_TARGET_COMPLETED"
DAY_10_INJECTION = "DAY10_INJECTION_ACCEPTED"
DAY_10_SOURCE = "DAY10_ATTACK_SOURCE"


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
