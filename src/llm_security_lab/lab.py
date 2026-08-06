"""Load synthetic fixtures, verify the model, and run one experiment scenario."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from llm_security_lab.ollama import OllamaClient

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_ROOT = PROJECT_ROOT / "fixtures"
SCENARIO_FILE = PROJECT_ROOT / "scenarios/day-04-vulnerable-baseline/scenario.json"


class JsonClient(Protocol):
    """Structural interface used by the real and test Ollama clients."""

    origin: str

    def request_json(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]: ...


def load_definition() -> dict[str, Any]:
    """Load the versioned scenario definition."""
    definition = json.loads(SCENARIO_FILE.read_text(encoding="utf-8"))
    if definition.get("schema_version") != 1:
        raise ValueError("unsupported scenario schema version")
    return definition


def read_fixture(relative_path: str) -> dict[str, str]:
    """Read one regular, non-symlink fixture contained by FIXTURES_ROOT."""
    path = FIXTURES_ROOT / relative_path
    if path.is_symlink():
        raise ValueError(f"refusing symlink fixture: {relative_path}")

    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(FIXTURES_ROOT) or not resolved.is_file():
        raise ValueError(f"fixture escaped fixtures root: {relative_path}")

    content = resolved.read_text(encoding="utf-8")
    return {
        "path": relative_path,
        "sha256": hashlib.sha256(content.encode()).hexdigest(),
        "content": content,
    }


def select_model(tags: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    """Fail closed when the model tag is missing or its full digest changed."""
    model = next(
        (item for item in tags.get("models", []) if item.get("name") == expected["name"]),
        None,
    )
    if model is None:
        raise RuntimeError(f"required local model is not installed: {expected['name']}")
    if model.get("digest") != expected["digest"]:
        raise RuntimeError(
            f"model digest changed: expected {expected['digest']}, got {model.get('digest')}"
        )
    return model


def build_user_message(notes: list[dict[str, str]], target: dict[str, str]) -> str:
    """Deliberately place all selected notes and the target in one model-visible message."""
    note_blocks = "\n".join(
        f'<note path="{note["path"]}">\n{note["content"]}</note>' for note in notes
    )
    return (
        f"<reference_notes>\n{note_blocks}\n</reference_notes>\n"
        f"<target_document>\n{target['content']}</target_document>"
    )


def run(scenario: str, client: JsonClient | None = None) -> dict[str, Any]:
    """Run one scenario and retain the full request, fixtures, model, and response."""
    definition = load_definition()
    scenario_definition = definition["scenarios"].get(scenario)
    if scenario_definition is None:
        choices = ", ".join(sorted(definition["scenarios"]))
        raise ValueError(f"unknown scenario {scenario!r}; choose one of: {choices}")

    ollama = client or OllamaClient()
    notes = [read_fixture(path) for path in scenario_definition["notes"]]
    target = read_fixture(definition["target"])
    version = ollama.request_json("/api/version")
    model = select_model(ollama.request_json("/api/tags"), definition["model"])
    messages = [
        {"role": "system", "content": definition["system_message"]},
        {"role": "user", "content": build_user_message(notes, target)},
    ]
    payload = {
        "model": definition["model"]["name"],
        "messages": messages,
        "stream": False,
        "options": definition["model"]["options"],
    }
    response = ollama.request_json("/api/chat", payload)
    return {
        "recorded_at": datetime.now(UTC).isoformat(),
        "scenario_id": definition["id"],
        "scenario": scenario,
        "safety_boundary": {
            "fixtures_root": "fixtures/",
            "synthetic_data_only": True,
            "reject_symlinks_and_path_escape": True,
            "model_origin": ollama.origin,
            "tools_sent": False,
            "output_sink": "stdout",
        },
        "ollama_version": version.get("version"),
        "model": model,
        "fixtures": {"notes": notes, "target": target},
        "request": payload,
        "response": response,
    }
