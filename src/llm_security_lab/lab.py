"""Load one experiment bundle, verify the model, and retain complete evidence."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from llm_security_lab.ollama import OllamaClient

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS_ROOT = PROJECT_ROOT / "experiments"
DEFAULT_EXPERIMENT = "day-04-vulnerable-baseline"
EXPERIMENT_ID_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


class JsonClient(Protocol):
    """Structural interface used by the real and test Ollama clients."""

    origin: str

    def request_json(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]: ...


def available_experiments() -> list[str]:
    """Return experiment bundle IDs that contain an experiment definition."""
    if not EXPERIMENTS_ROOT.is_dir():
        return []
    names: list[str] = []
    for path in EXPERIMENTS_ROOT.iterdir():
        if not path.is_dir() or not EXPERIMENT_ID_PATTERN.fullmatch(path.name):
            continue
        definition_path = path / "experiment.json"
        if not definition_path.is_file():
            continue
        try:
            definition = json.loads(definition_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if definition.get("schema_version") == 2 and "model" in definition:
            names.append(path.name)
    return sorted(names)


def experiment_root(experiment: str) -> Path:
    """Resolve one allowlisted experiment bundle without permitting path traversal."""
    if not EXPERIMENT_ID_PATTERN.fullmatch(experiment):
        raise ValueError(f"invalid experiment id: {experiment!r}")

    root = (EXPERIMENTS_ROOT / experiment).resolve(strict=True)
    if not root.is_relative_to(EXPERIMENTS_ROOT.resolve()) or not root.is_dir():
        raise ValueError(f"experiment escaped experiments root: {experiment}")
    if not (root / "experiment.json").is_file():
        choices = ", ".join(available_experiments())
        raise ValueError(f"unknown experiment {experiment!r}; choose one of: {choices}")
    return root


def load_definition(experiment: str = DEFAULT_EXPERIMENT) -> dict[str, Any]:
    """Load and validate one versioned experiment definition."""
    definition = json.loads((experiment_root(experiment) / "experiment.json").read_text("utf-8"))
    if definition.get("schema_version") != 2:
        raise ValueError("unsupported experiment schema version")
    if definition.get("id") != experiment:
        raise ValueError("experiment id does not match its bundle directory")
    return definition


def read_fixture(relative_path: str, experiment: str = DEFAULT_EXPERIMENT) -> dict[str, str]:
    """Read one regular, non-symlink fixture contained by its experiment bundle."""
    fixtures_root = experiment_root(experiment) / "fixtures"
    path = fixtures_root / relative_path
    try:
        relative = path.relative_to(fixtures_root)
    except ValueError as error:
        raise ValueError(f"fixture escaped experiment bundle: {relative_path}") from error
    current = fixtures_root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"refusing symlink fixture: {relative_path}")

    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(fixtures_root) or not resolved.is_file():
        raise ValueError(f"fixture escaped experiment bundle: {relative_path}")

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


def _marker_observations(
    definition: dict[str, Any],
    fixtures: dict[str, Any],
    payload: dict[str, Any],
    response: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any] | None:
    marker_definition = definition.get("observation_marker")
    if marker_definition is None:
        return None

    marker = marker_definition.get("value")
    marker_id = marker_definition.get("id")
    if not isinstance(marker, str) or not marker or not isinstance(marker_id, str):
        raise ValueError("invalid observation marker")

    message = response.get("message")
    model_content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(model_content, str):
        raise TypeError("model response must contain string message content")

    json_options = {"ensure_ascii": False, "sort_keys": True}
    return {
        "marker_id": marker_id,
        "canary_in_request": marker in json.dumps(payload, **json_options),
        "canary_in_model_response": marker in model_content,
        "canary_in_fixture_evidence": marker in json.dumps(fixtures, **json_options),
        "canary_in_full_stdout": marker in json.dumps(evidence, **json_options),
    }


def run(
    scenario: str,
    client: JsonClient | None = None,
    experiment: str = DEFAULT_EXPERIMENT,
) -> dict[str, Any]:
    """Run one scenario and retain the full request, fixtures, model, and response."""
    definition = load_definition(experiment)
    scenario_definition = definition["scenarios"].get(scenario)
    if scenario_definition is None:
        choices = ", ".join(sorted(definition["scenarios"]))
        raise ValueError(f"unknown scenario {scenario!r}; choose one of: {choices}")

    ollama = client or OllamaClient()
    notes = [read_fixture(path, experiment) for path in scenario_definition["notes"]]
    target = read_fixture(definition["target"], experiment)
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
    fixtures = {"notes": notes, "target": target}
    evidence = {
        "recorded_at": datetime.now(UTC).isoformat(),
        "scenario_id": definition["id"],
        "scenario": scenario,
        "safety_boundary": {
            "fixtures_root": f"experiments/{experiment}/fixtures/",
            "synthetic_data_only": True,
            "reject_symlinks_and_path_escape": True,
            "model_origin": ollama.origin,
            "tools_sent": False,
            "output_sink": "stdout",
        },
        "ollama_version": version.get("version"),
        "model": model,
        "fixtures": fixtures,
        "request": payload,
        "response": response,
    }
    observations = _marker_observations(definition, fixtures, payload, response, evidence)
    if observations is not None:
        evidence["observations"] = observations
    return evidence


def summarize_runs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate and aggregate one repeated experiment batch."""
    if not runs:
        raise ValueError("at least one run is required")

    fingerprints = {
        json.dumps(
            {
                "scenario_id": run.get("scenario_id"),
                "scenario": run.get("scenario"),
                "ollama_version": run.get("ollama_version"),
                "model": run.get("model"),
                "options": run.get("request", {}).get("options"),
                "fixtures": [
                    {"path": fixture.get("path"), "sha256": fixture.get("sha256")}
                    for fixture in [
                        *run.get("fixtures", {}).get("notes", []),
                        run.get("fixtures", {}).get("target", {}),
                    ]
                ],
                "safety_boundary": run.get("safety_boundary"),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        for run in runs
    }
    if len(fingerprints) != 1:
        raise ValueError("cannot summarize mixed experiment environments or inputs")

    experiment_id = runs[0].get("scenario_id")
    scenario = runs[0].get("scenario")
    digest = runs[0].get("model", {}).get("digest")

    observations = [run.get("observations") for run in runs]
    if not all(isinstance(item, dict) for item in observations):
        raise ValueError("every repeated run must contain marker observations")

    predicate_names = (
        "canary_in_request",
        "canary_in_model_response",
        "canary_in_fixture_evidence",
        "canary_in_full_stdout",
    )
    counts = {
        name: sum(bool(item.get(name)) for item in observations if isinstance(item, dict))
        for name in predicate_names
    }
    return {
        "experiment_id": experiment_id,
        "scenario": scenario,
        "model_digest": digest,
        "runs": len(runs),
        "true_counts": counts,
    }


def run_repeated(
    experiment: str,
    scenario: str,
    repeat: int,
    client: JsonClient | None = None,
) -> dict[str, Any]:
    """Run one complete repeated batch without retrying selected model outcomes."""
    if repeat < 1:
        raise ValueError("repeat must be at least 1")
    runs = [run(scenario, client=client, experiment=experiment) for _ in range(repeat)]
    return {
        "schema_version": 1,
        "experiment_id": experiment,
        "scenario": scenario,
        "repeat": repeat,
        "runs": runs,
        "summary": summarize_runs(runs),
    }
