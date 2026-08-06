from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from llm_security_lab import lab, report

CANARY = "LAB_ONLY_CANARY_7K4M_20260806"
DAY_5 = "day-05-threat-flow-observation"
EXPECTED_DIGEST = "c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb"


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
