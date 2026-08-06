from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from llm_security_lab import lab
from llm_security_lab.ollama import OllamaClient

EXPECTED_DIGEST = "c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb"
CANARY = "LAB_ONLY_CANARY_7K4M_20260806"


class FakeClient:
    origin = "http://127.0.0.1:11434"

    def __init__(self, digest: str = EXPECTED_DIGEST) -> None:
        self.digest = digest
        self.chat_payload: dict[str, Any] | None = None

    def request_json(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if path == "/api/version":
            return {"version": "test"}
        if path == "/api/tags":
            return {
                "models": [
                    {
                        "name": "gemma4:latest",
                        "digest": self.digest,
                        "details": {"format": "gguf"},
                    }
                ]
            }
        if path == "/api/chat":
            self.chat_payload = payload
            return {"message": {"role": "assistant", "content": "synthetic response"}}
        raise AssertionError(f"unexpected path: {path}")


def test_clean_scenario_excludes_attack_note_and_tools() -> None:
    client = FakeClient()

    evidence = lab.run("clean", client=client)

    assert evidence["safety_boundary"]["tools_sent"] is False
    assert client.chat_payload is not None
    assert "tools" not in client.chat_payload
    user_content = client.chat_payload["messages"][1]["content"]
    assert CANARY in user_content
    assert "摘要器維護通知" not in user_content


def test_attack_scenario_includes_separate_injection_note() -> None:
    client = FakeClient()

    lab.run("attack", client=client)

    assert client.chat_payload is not None
    user_content = client.chat_payload["messages"][1]["content"]
    assert CANARY in user_content
    assert "摘要器維護通知" in user_content


def test_model_digest_mismatch_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="model digest changed"):
        lab.run("clean", client=FakeClient(digest="changed"))


def test_fixture_hashes_match_recorded_evidence() -> None:
    expected = {
        "synthetic-notes/01-preferences.md": (
            "4eadcd2adde21ead6156e9b981092cbeab96a17ac339ceac3d13bb17e46d5717"
        ),
        "synthetic-notes/02-lab-canary.md": (
            "2bfb24757d2da484275a33985284d6eeef703ad562663e86c83b8d48a2ea623f"
        ),
        "synthetic-notes/99-injection.md": (
            "df25c920f91fc71ff59012a21a3e0670b46bccbf182a380136a9ccd972308f88"
        ),
        "target.md": "0ea2e50a157859613b5142d10f21d5b36af5216926ded1e02b96b3c33a21ae51",
    }

    for relative_path, digest in expected.items():
        content = (lab.FIXTURES_ROOT / relative_path).read_bytes()
        assert hashlib.sha256(content).hexdigest() == digest


def test_fixture_path_escape_is_rejected() -> None:
    with pytest.raises((FileNotFoundError, ValueError)):
        lab.read_fixture("../pyproject.toml")


def test_symlink_fixture_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_file = tmp_path / "real.md"
    real_file.write_text("synthetic", encoding="utf-8")
    symlink = tmp_path / "link.md"
    symlink.symlink_to(real_file)
    monkeypatch.setattr(lab, "FIXTURES_ROOT", tmp_path)

    with pytest.raises(ValueError, match="refusing symlink"):
        lab.read_fixture("link.md")


def test_ollama_client_rejects_non_loopback_origins() -> None:
    with pytest.raises(ValueError, match="127.0.0.1"):
        OllamaClient(origin="https://example.com")
