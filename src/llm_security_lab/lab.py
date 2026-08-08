"""Load one experiment bundle, verify the model, and retain complete evidence."""

from __future__ import annotations

import hashlib
import json
import re
from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from llm_security_lab.documents import extract_document, validate_document_spec
from llm_security_lab.ollama import OllamaClient

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS_ROOT = PROJECT_ROOT / "experiments"
DEFAULT_EXPERIMENT = "day-04-vulnerable-baseline"
EXPERIMENT_ID_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
RESPONSE_MARKER_ID_PATTERN = re.compile(r"[a-z][a-z0-9_]*\Z")
RUN_ID_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
CANARY_PREDICATE_NAMES = {
    "canary_in_request",
    "canary_in_model_response",
    "canary_in_fixture_evidence",
    "canary_in_full_stdout",
}


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
        if definition.get("schema_version") in {2, 3} and "model" in definition:
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
    if definition.get("schema_version") not in {2, 3}:
        raise ValueError("unsupported experiment schema version")
    if definition.get("id") != experiment:
        raise ValueError("experiment id does not match its bundle directory")
    markers = response_markers(definition)
    document_marker = definition.get("document_observation_marker")
    if document_marker is not None:
        if not isinstance(document_marker, dict):
            raise ValueError("document observation marker must be an object")
        marker_id = document_marker.get("id")
        marker_value = document_marker.get("value")
        if not isinstance(marker_id, str) or not RESPONSE_MARKER_ID_PATTERN.fullmatch(marker_id):
            raise ValueError("document observation marker id must use lowercase snake_case")
        if not isinstance(marker_value, str) or not marker_value:
            raise ValueError("document observation marker must contain a non-empty value")
        if any(marker["id"] == marker_id for marker in markers):
            raise ValueError("document observation marker must differ from response marker ids")
    if definition["schema_version"] == 3:
        planned_runs(definition)
    return definition


def planned_runs(definition: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate and flatten a schema-v3 run plan in declared execution order."""
    if definition.get("schema_version") != 3:
        raise ValueError("planned runs require experiment schema version 3")
    if "options" in definition.get("model", {}):
        raise ValueError("schema-v3 options must be declared by each planned run")
    if "system_message" in definition:
        raise ValueError("schema-v3 system messages must be declared by each scenario")

    scenarios = definition.get("scenarios")
    if not isinstance(scenarios, dict) or not scenarios:
        raise ValueError("schema-v3 scenarios must be a non-empty object")

    plan: list[dict[str, Any]] = []
    seen_run_ids: set[str] = set()
    planned_chat_calls = 0
    for scenario_name, scenario in scenarios.items():
        if not isinstance(scenario_name, str) or not RUN_ID_PATTERN.fullmatch(scenario_name):
            raise ValueError("planned scenario ids must use lowercase kebab-case")
        if not isinstance(scenario, dict):
            raise ValueError(f"planned scenario {scenario_name} must be an object")
        system_message = scenario.get("system_message")
        if not isinstance(system_message, str) or not system_message:
            raise ValueError(f"planned scenario {scenario_name} needs a system message")
        user_request = scenario.get("user_request")
        if user_request is not None and (
            not isinstance(user_request, str) or not user_request.strip()
        ):
            raise ValueError(
                f"planned scenario {scenario_name} user request must be a non-empty string"
            )
        user_turns = scenario.get("user_turns")
        if user_request is not None and user_turns is not None:
            raise ValueError(
                f"planned scenario {scenario_name} cannot declare both user_request and user_turns"
            )
        if user_turns is not None and (
            not isinstance(user_turns, list)
            or not 2 <= len(user_turns) <= 10
            or not all(isinstance(turn, str) and turn.strip() for turn in user_turns)
        ):
            raise ValueError(
                f"planned scenario {scenario_name} user turns must contain 2 to 10 non-empty strings"
            )
        notes = scenario.get("notes")
        if not isinstance(notes, list) or not notes or not all(isinstance(x, str) for x in notes):
            raise ValueError(f"planned scenario {scenario_name} needs fixture note paths")
        document = scenario.get("document")
        if document is not None:
            validate_document_spec(document)
        runs = scenario.get("runs")
        if not isinstance(runs, list) or not runs or len(runs) > 20:
            raise ValueError(f"planned scenario {scenario_name} needs between 1 and 20 runs")

        for item in runs:
            if not isinstance(item, dict):
                raise ValueError(f"every planned run in {scenario_name} must be an object")
            run_id = item.get("id")
            if not isinstance(run_id, str) or not RUN_ID_PATTERN.fullmatch(run_id):
                raise ValueError("planned run ids must use lowercase kebab-case")
            if run_id in seen_run_ids:
                raise ValueError(f"duplicate planned run id: {run_id}")
            options = item.get("options")
            if not isinstance(options, dict):
                raise ValueError(f"planned run {run_id} needs an options object")
            seed = options.get("seed")
            temperature = options.get("temperature")
            if not isinstance(seed, int) or isinstance(seed, bool):
                raise ValueError(f"planned run {run_id} needs an integer seed")
            if (
                not isinstance(temperature, int | float)
                or isinstance(temperature, bool)
                or temperature < 0
            ):
                raise ValueError(f"planned run {run_id} needs a non-negative temperature")
            seen_run_ids.add(run_id)
            plan.append({"run_id": run_id, "scenario": scenario_name, "options": deepcopy(options)})
            planned_chat_calls += len(user_turns) if user_turns is not None else 1

    if len(plan) > 100:
        raise ValueError("a planned experiment may contain at most 100 runs")
    if planned_chat_calls > 300:
        raise ValueError("a planned experiment may contain at most 300 chat calls")
    return plan


def response_markers(definition: dict[str, Any]) -> list[dict[str, str]]:
    """Validate optional model-response markers and return their normalized definitions."""
    raw_markers = definition.get("response_markers", [])
    if not isinstance(raw_markers, list):
        raise ValueError("response_markers must be a list")

    markers: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for raw_marker in raw_markers:
        if not isinstance(raw_marker, dict):
            raise ValueError("every response marker must be an object")
        marker_id = raw_marker.get("id")
        value = raw_marker.get("value")
        if not isinstance(marker_id, str) or not RESPONSE_MARKER_ID_PATTERN.fullmatch(marker_id):
            raise ValueError("response marker id must use lowercase snake_case")
        if marker_id in seen_ids:
            raise ValueError(f"duplicate response marker id: {marker_id}")
        if not isinstance(value, str) or not value:
            raise ValueError(f"response marker {marker_id} must contain a non-empty value")
        predicate_name = f"{marker_id}_in_model_response"
        if predicate_name in CANARY_PREDICATE_NAMES:
            raise ValueError(f"response marker predicate collides with canary: {predicate_name}")
        seen_ids.add(marker_id)
        markers.append({"id": marker_id, "value": value})
    return markers


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


def read_document_fixture(raw_spec: object, experiment: str = DEFAULT_EXPERIMENT) -> dict[str, Any]:
    """Read and extract one binary-safe document fixture within its experiment bundle."""
    spec = validate_document_spec(raw_spec)
    relative_path = spec["path"]
    fixtures_root = experiment_root(experiment) / "fixtures"
    path = fixtures_root / relative_path
    try:
        relative = path.relative_to(fixtures_root)
    except ValueError as error:
        raise ValueError(f"document escaped experiment bundle: {relative_path}") from error
    current = fixtures_root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"refusing symlink document: {relative_path}")

    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(fixtures_root) or not resolved.is_file():
        raise ValueError(f"document escaped experiment bundle: {relative_path}")

    raw = resolved.read_bytes()
    content, extractor = extract_document(raw, spec)
    return {
        "path": relative_path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "source_base64": b64encode(raw).decode("ascii"),
        "content": content,
        "extracted_sha256": hashlib.sha256(content.encode()).hexdigest(),
        "extractor": extractor,
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


def _fixture_fingerprint(fixture: dict[str, Any]) -> dict[str, Any]:
    """Validate binary document evidence and return its stable input fingerprint."""
    fingerprint = {"path": fixture.get("path"), "sha256": fixture.get("sha256")}
    source_base64 = fixture.get("source_base64")
    if source_base64 is None:
        return fingerprint
    content = fixture.get("content")
    extracted_sha256 = fixture.get("extracted_sha256")
    extractor = fixture.get("extractor")
    if (
        not isinstance(source_base64, str)
        or not isinstance(content, str)
        or not isinstance(extracted_sha256, str)
        or not isinstance(extractor, dict)
    ):
        raise ValueError("document fixture evidence is incomplete")
    try:
        raw = b64decode(source_base64, validate=True)
    except (Base64Error, ValueError) as error:
        raise ValueError("document source base64 is invalid") from error
    if hashlib.sha256(raw).hexdigest() != fixture.get("sha256"):
        raise ValueError("document source hash does not match its bytes")
    if hashlib.sha256(content.encode()).hexdigest() != extracted_sha256:
        raise ValueError("document extracted hash does not match its text")
    fingerprint.update(
        {
            "extracted_sha256": extracted_sha256,
            "extractor": extractor,
        }
    )
    return fingerprint


def build_user_message(
    notes: list[dict[str, str]],
    target: dict[str, str],
    user_request: str | None = None,
) -> str:
    """Deliberately place all selected notes and the target in one model-visible message."""
    note_blocks = "\n".join(
        f'<note path="{note["path"]}">\n{note["content"]}</note>' for note in notes
    )
    request_block = (
        f"<user_request>\n{user_request}\n</user_request>\n" if user_request is not None else ""
    )
    return (
        f"{request_block}<reference_notes>\n{note_blocks}\n</reference_notes>\n"
        f"<target_document>\n{target['content']}</target_document>"
    )


def build_followup_user_message(user_request: str) -> str:
    """Keep later conversation turns explicitly labeled as untrusted user requests."""
    return f"<user_request>\n{user_request}\n</user_request>"


def _response_content(response: dict[str, Any]) -> str:
    """Return one assistant response string or fail closed on an unexpected API shape."""
    message = response.get("message")
    model_content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(model_content, str):
        raise TypeError("model response must contain string message content")
    return model_content


def _marker_observations(
    definition: dict[str, Any],
    fixtures: dict[str, Any],
    payload: dict[str, Any],
    responses: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> dict[str, Any] | None:
    marker_definition = definition.get("observation_marker")
    extra_markers = response_markers(definition)
    if marker_definition is None and not extra_markers:
        return None

    model_contents = [_response_content(response) for response in responses]

    observations: dict[str, Any] = {}
    if marker_definition is not None:
        marker = marker_definition.get("value")
        marker_id = marker_definition.get("id")
        if not isinstance(marker, str) or not marker or not isinstance(marker_id, str):
            raise ValueError("invalid observation marker")
        json_options = {"ensure_ascii": False, "sort_keys": True}
        observations.update(
            {
                "marker_id": marker_id,
                "canary_in_request": marker in json.dumps(payload, **json_options),
                "canary_in_model_response": any(marker in content for content in model_contents),
                "canary_in_fixture_evidence": marker in json.dumps(fixtures, **json_options),
                "canary_in_full_stdout": marker in json.dumps(evidence, **json_options),
            }
        )
    observations.update(
        {
            f"{marker['id']}_in_model_response": any(
                marker["value"] in content for content in model_contents
            )
            for marker in extra_markers
        }
    )
    document_marker = definition.get("document_observation_marker")
    if document_marker is not None:
        target = fixtures.get("target", {})
        source_base64 = target.get("source_base64")
        extracted_content = target.get("content")
        if not isinstance(source_base64, str) or not isinstance(extracted_content, str):
            raise ValueError("document observations require a document target fixture")
        marker_id = document_marker["id"]
        marker_value = document_marker["value"]
        observations.update(
            {
                f"{marker_id}_in_source_bytes": marker_value.encode() in b64decode(source_base64),
                f"{marker_id}_in_extracted_document": marker_value in extracted_content,
                f"{marker_id}_in_request": marker_value
                in json.dumps(payload, ensure_ascii=False, sort_keys=True),
            }
        )
    return observations


def _run_scenario(
    *,
    definition: dict[str, Any],
    scenario: str,
    scenario_definition: dict[str, Any],
    system_message: str,
    options: dict[str, Any],
    ollama: JsonClient,
    experiment: str,
    version: dict[str, Any],
    model: dict[str, Any],
    run_id: str | None = None,
) -> dict[str, Any]:
    """Execute one already validated scenario with preflighted model metadata."""
    notes = [read_fixture(path, experiment) for path in scenario_definition["notes"]]
    document = scenario_definition.get("document")
    target = (
        read_document_fixture(document, experiment)
        if document is not None
        else read_fixture(definition["target"], experiment)
    )
    messages = [
        {"role": "system", "content": system_message},
    ]
    declared_turns = scenario_definition.get("user_turns")
    user_turns = (
        declared_turns if declared_turns is not None else [scenario_definition.get("user_request")]
    )
    responses: list[dict[str, Any]] = []
    conversation: list[dict[str, Any]] = []
    payload: dict[str, Any] = {}
    response: dict[str, Any] = {}
    for turn_number, user_turn in enumerate(user_turns, start=1):
        user_content = (
            build_user_message(notes, target, user_turn)
            if turn_number == 1
            else build_followup_user_message(user_turn)
        )
        messages.append({"role": "user", "content": user_content})
        payload = {
            "model": definition["model"]["name"],
            "messages": deepcopy(messages),
            "stream": False,
            "options": deepcopy(options),
        }
        response = ollama.request_json("/api/chat", payload)
        model_content = _response_content(response)
        responses.append(deepcopy(response))
        conversation.append(
            {
                "turn": turn_number,
                "request": deepcopy(payload),
                "response": deepcopy(response),
            }
        )
        if turn_number < len(user_turns):
            response_message = deepcopy(response["message"])
            response_message["role"] = "assistant"
            response_message["content"] = model_content
            messages.append(response_message)
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
    if len(conversation) > 1:
        evidence["conversation"] = conversation
    observations = _marker_observations(definition, fixtures, payload, responses, evidence)
    if observations is not None:
        evidence["observations"] = observations
    if run_id is not None:
        evidence["run_id"] = run_id
    return evidence


def run(
    scenario: str,
    client: JsonClient | None = None,
    experiment: str = DEFAULT_EXPERIMENT,
) -> dict[str, Any]:
    """Run one schema-v2 scenario and retain full request, fixtures, model, and response."""
    definition = load_definition(experiment)
    if definition["schema_version"] != 2:
        raise ValueError("schema-v3 experiments must execute their complete run plan")
    scenario_definition = definition["scenarios"].get(scenario)
    if scenario_definition is None:
        choices = ", ".join(sorted(definition["scenarios"]))
        raise ValueError(f"unknown scenario {scenario!r}; choose one of: {choices}")

    ollama = client or OllamaClient()
    version = ollama.request_json("/api/version")
    model = select_model(ollama.request_json("/api/tags"), definition["model"])
    return _run_scenario(
        definition=definition,
        scenario=scenario,
        scenario_definition=scenario_definition,
        system_message=definition["system_message"],
        options=definition["model"]["options"],
        ollama=ollama,
        experiment=experiment,
        version=version,
        model=model,
    )


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
                    _fixture_fingerprint(fixture)
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

    predicate_names = tuple(
        name
        for name, value in observations[0].items()
        if name != "marker_id" and isinstance(value, bool)
    )
    if not predicate_names:
        raise ValueError("repeated runs must contain at least one boolean marker predicate")
    expected_names = set(predicate_names)
    for item in observations:
        actual_names = {
            name for name, value in item.items() if name != "marker_id" and isinstance(value, bool)
        }
        if actual_names != expected_names:
            raise ValueError("repeated runs contain inconsistent marker predicates")
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


def summarize_planned_runs(
    runs: list[dict[str, Any]], run_plan: list[dict[str, Any]]
) -> dict[str, Any]:
    """Validate exact planned-run order/options and aggregate every scenario."""
    if not runs or not isinstance(run_plan, list) or len(runs) != len(run_plan):
        raise ValueError("planned evidence is incomplete")

    expected_ids: list[str] = []
    actual_ids: list[str] = []
    for index, (run_evidence, planned) in enumerate(zip(runs, run_plan, strict=True), start=1):
        if not isinstance(planned, dict):
            raise ValueError(f"planned run {index} must be an object")
        run_id = planned.get("run_id")
        scenario = planned.get("scenario")
        options = planned.get("options")
        if (
            not isinstance(run_id, str)
            or not isinstance(scenario, str)
            or not isinstance(options, dict)
        ):
            raise ValueError(f"planned run {index} is malformed")
        expected_ids.append(run_id)
        actual_ids.append(run_evidence.get("run_id"))
        if run_evidence.get("run_id") != run_id:
            raise ValueError("planned evidence run order or id changed")
        if run_evidence.get("scenario") != scenario:
            raise ValueError(f"planned run {run_id} scenario changed")
        if run_evidence.get("request", {}).get("options") != options:
            raise ValueError(f"planned run {run_id} options changed")
        conversation = run_evidence.get("conversation")
        if conversation is not None:
            if not isinstance(conversation, list) or len(conversation) < 2:
                raise ValueError(f"planned run {run_id} conversation is incomplete")
            for turn_number, turn in enumerate(conversation, start=1):
                if not isinstance(turn, dict) or turn.get("turn") != turn_number:
                    raise ValueError(f"planned run {run_id} conversation order changed")
                if turn.get("request", {}).get("options") != options:
                    raise ValueError(f"planned run {run_id} conversation options changed")
                _response_content(turn.get("response", {}))
            if conversation[-1].get("request") != run_evidence.get("request") or conversation[
                -1
            ].get("response") != run_evidence.get("response"):
                raise ValueError(f"planned run {run_id} final conversation turn changed")
    if len(set(expected_ids)) != len(expected_ids) or len(set(actual_ids)) != len(actual_ids):
        raise ValueError("planned evidence contains duplicate run ids")

    common_fingerprints = {
        json.dumps(
            {
                "scenario_id": item.get("scenario_id"),
                "ollama_version": item.get("ollama_version"),
                "model": item.get("model"),
                "safety_boundary": item.get("safety_boundary"),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        for item in runs
    }
    if len(common_fingerprints) != 1:
        raise ValueError("planned runs contain mixed model environments")

    scenario_runs: dict[str, list[dict[str, Any]]] = {}
    for item in runs:
        scenario_runs.setdefault(item["scenario"], []).append(item)

    scenario_summaries: dict[str, Any] = {}
    for scenario, items in scenario_runs.items():
        static_fingerprints = {
            json.dumps(
                {
                    "messages": [
                        message
                        for message in item.get("request", {}).get("messages", [])
                        if message.get("role") in {"system", "user"}
                    ],
                    "fixtures": [
                        _fixture_fingerprint(fixture)
                        for fixture in [
                            *item.get("fixtures", {}).get("notes", []),
                            item.get("fixtures", {}).get("target", {}),
                        ]
                    ],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            for item in items
        }
        if len(static_fingerprints) != 1:
            raise ValueError(f"planned scenario {scenario} changed model-visible inputs")

        turn_counts = {len(item["conversation"]) if "conversation" in item else 1 for item in items}
        if len(turn_counts) != 1:
            raise ValueError(f"planned scenario {scenario} changed conversation length")

        observations = [item.get("observations") for item in items]
        if not all(isinstance(observation, dict) for observation in observations):
            raise ValueError("every planned run must contain marker observations")
        predicate_names = tuple(
            name
            for name, value in observations[0].items()
            if name != "marker_id" and isinstance(value, bool)
        )
        if not predicate_names:
            raise ValueError("planned runs must contain at least one boolean marker predicate")
        expected_names = set(predicate_names)
        for observation in observations:
            actual_names = {
                name
                for name, value in observation.items()
                if name != "marker_id" and isinstance(value, bool)
            }
            if actual_names != expected_names:
                raise ValueError("planned runs contain inconsistent marker predicates")
        scenario_summary = {
            "runs": len(items),
            "true_counts": {
                name: sum(bool(observation[name]) for observation in observations)
                for name in predicate_names
            },
        }
        turns_per_run = turn_counts.pop()
        if turns_per_run > 1:
            scenario_summary["turns_per_run"] = turns_per_run
        scenario_summaries[scenario] = scenario_summary

    return {
        "experiment_id": runs[0].get("scenario_id"),
        "model_digest": runs[0].get("model", {}).get("digest"),
        "runs": len(runs),
        "scenario_order": list(scenario_runs),
        "scenarios": scenario_summaries,
    }


def run_planned(
    experiment: str,
    client: JsonClient | None = None,
) -> dict[str, Any]:
    """Execute one schema-v3 plan exactly once in declared order."""
    definition = load_definition(experiment)
    if definition["schema_version"] != 3:
        raise ValueError("complete run plans require experiment schema version 3")

    plan = planned_runs(definition)
    ollama = client or OllamaClient()
    version = ollama.request_json("/api/version")
    model = select_model(ollama.request_json("/api/tags"), definition["model"])
    runs = []
    for item in plan:
        scenario_definition = definition["scenarios"][item["scenario"]]
        runs.append(
            _run_scenario(
                definition=definition,
                scenario=item["scenario"],
                scenario_definition=scenario_definition,
                system_message=scenario_definition["system_message"],
                options=item["options"],
                ollama=ollama,
                experiment=experiment,
                version=version,
                model=model,
                run_id=item["run_id"],
            )
        )
    return {
        "schema_version": 2,
        "experiment_id": experiment,
        "run_plan": plan,
        "runs": runs,
        "summary": summarize_planned_runs(runs, plan),
    }
