from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from llm_security_lab import lab, prompt_guard

EXPERIMENT = "day-24-prompt-guard-input-rail"
DIGEST = "c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb"


class FakeClient:
    origin = "http://127.0.0.1:11434"

    def __init__(self) -> None:
        self.chat_payloads: list[dict[str, Any]] = []

    def request_json(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if path == "/api/version":
            return {"version": "test-ollama"}
        if path == "/api/tags":
            return {"models": [{"name": "gemma4:latest", "digest": DIGEST}]}
        if path != "/api/chat" or payload is None:
            raise AssertionError(f"unexpected request: {path}")
        self.chat_payloads.append(payload)
        text = payload["messages"][-1]["content"]
        quoted = "安全教材中的引用" in text
        attack = any(marker in text for marker in ("override-policy", "文件內附指令", "拆字混淆"))
        decision = "block" if attack and not quoted else "allow"
        reason = "input_attack" if decision == "block" else "none"
        return {
            "message": {
                "role": "assistant",
                "content": json.dumps({"decision": decision, "reason": reason}),
            }
        }


class FakeClassifier:
    metadata = {
        "repo_id": "meta-llama/Llama-Prompt-Guard-2-86M",
        "revision": "a8ded8e697ce7c355e395a0df51f94adb4a2fd27",
        "max_length": 512,
        "benign_index": 0,
        "malicious_index": 1,
        "index_mapping_basis": "official-model-card-example-and-local-pilot",
        "file_sha256": {},
        "local_files_only": True,
    }

    def classify(self, text: str) -> dict[str, Any]:
        quoted = "安全教材中的引用" in text
        attack = any(marker in text for marker in ("override-policy", "文件內附指令", "拆字混淆"))
        blocked = attack and not quoted
        return {
            "decision": "block" if blocked else "allow",
            "predicted_index": 1 if blocked else 0,
            "malicious_score": 0.99 if blocked else 0.01,
            "token_count": 32,
        }


def _run() -> dict[str, Any]:
    return asyncio.run(
        prompt_guard.run_prompt_guard_experiment(
            EXPERIMENT, client=FakeClient(), classifier=FakeClassifier()
        )
    )


def test_prompt_guard_bundle_is_independent_from_generic_and_guardrails_runners() -> None:
    assert prompt_guard.available_prompt_guard_experiments() == [EXPERIMENT]
    assert EXPERIMENT not in lab.available_experiments()


def test_input_comparison_uses_fixed_cases_and_repetitions() -> None:
    batch = _run()
    summary = batch["summary"]

    assert summary["run_units"] == 25
    assert summary["path_evaluations"] == 75
    assert summary["generator_calls"] == 0
    assert summary["sink_reached"] == 0
    assert summary["model_calls"] == 50
    assert summary["by_path"]["semantic"]["correct"] == 25
    assert summary["by_path"]["deterministic"]["false_negative"] == 10
    assert summary["by_path"]["prompt_guard"]["correct"] == 25


def test_every_path_runs_through_one_nemo_input_rail() -> None:
    batch = _run()

    assert all(
        run["paths"][path]["framework_status"] in {"passed", "blocked"}
        for run in batch["runs"]
        for path in prompt_guard.PATHS
    )


def test_sanitized_report_excludes_fixture_text_and_classifier_scores() -> None:
    report = prompt_guard.render_prompt_guard_report(_run())

    assert "忽略原本規則" not in report
    assert "malicious_score" not in report
    assert "Prompt Guard input-rail comparison" in report


def test_saved_evidence_rejects_summary_tampering(tmp_path: Path) -> None:
    batch = _run()
    batch["summary"]["generator_calls"] = 1
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="summary does not match"):
        prompt_guard.load_prompt_guard_batch(path)


@pytest.mark.parametrize(
    "field",
    [
        "browser_launches",
        "javascript_executions",
        "external_network_calls",
        "subprocess_calls",
        "external_side_effects",
        "generator_calls",
        "sink_reached",
    ],
)
def test_saved_evidence_rejects_activity(tmp_path: Path, field: str) -> None:
    batch = _run()
    batch["safety_boundary"][field] = 1
    path = tmp_path / "unsafe.json"
    path.write_text(json.dumps(batch), encoding="utf-8")

    with pytest.raises(ValueError, match="violates the safety boundary"):
        prompt_guard.load_prompt_guard_batch(path)
