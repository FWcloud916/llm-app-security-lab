"""Run the deterministic Day 26 PII detection and masking experiment."""

from __future__ import annotations

import hashlib
import json
import re
import socket
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from unittest.mock import patch

from llm_security_lab.lab import (
    EXPERIMENT_ID_PATTERN,
    EXPERIMENTS_ROOT,
    experiment_root,
    read_fixture,
)

PII_RUNNER = "deterministic_pii_masking"
PII_SCHEMA_VERSION = 1
PROFILES = ("raw", "application_rules", "presidio_builtin", "layered")


@dataclass(frozen=True)
class Detection:
    """One normalized PII detection span."""

    entity_type: str
    start: int
    end: int
    score: float


class PresidioRuntime(Protocol):
    """The optional Presidio boundary used by the formal runner."""

    version: str
    nlp_model: str

    def detect(self, text: str, *, layered: bool, entities: list[str]) -> list[Detection]: ...

    def anonymize(self, text: str, detections: list[Detection]) -> str: ...


def available_pii_experiments() -> list[str]:
    """Return experiment IDs owned by the Day 26 runner."""
    if not EXPERIMENTS_ROOT.is_dir():
        return []
    names: list[str] = []
    for path in EXPERIMENTS_ROOT.iterdir():
        if not path.is_dir() or EXPERIMENT_ID_PATTERN.fullmatch(path.name) is None:
            continue
        try:
            definition = json.loads((path / "experiment.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if definition.get("runner") == PII_RUNNER:
            names.append(path.name)
    return sorted(names)


def _load_json_fixture(relative_path: str, experiment: str) -> tuple[Any, dict[str, str]]:
    fixture = read_fixture(relative_path, experiment)
    try:
        value = json.loads(fixture["content"])
    except json.JSONDecodeError as error:
        raise ValueError(f"fixture is not valid JSON: {relative_path}") from error
    return value, {"path": fixture["path"], "sha256": fixture["sha256"]}


def load_pii_definition(experiment: str) -> dict[str, Any]:
    """Load and validate one Day 26 experiment definition."""
    definition = json.loads(
        (experiment_root(experiment) / "experiment.json").read_text(encoding="utf-8")
    )
    if definition.get("schema_version") != PII_SCHEMA_VERSION:
        raise ValueError("unsupported PII experiment schema version")
    if definition.get("id") != experiment:
        raise ValueError("PII experiment id does not match its bundle directory")
    if definition.get("runner") != PII_RUNNER:
        raise ValueError("experiment is not a deterministic PII experiment")
    if definition.get("profiles") != list(PROFILES):
        raise ValueError("PII experiment profiles must match the fixed comparison order")
    for field in ("policy", "cases"):
        if not isinstance(definition.get(field), str):
            raise ValueError(f"PII experiment {field} must be a fixture path")
    return definition


def _validate_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("PII policy requires schema_version 1")
    entities = value.get("entities")
    patterns = value.get("application_patterns")
    if (
        not isinstance(value.get("version"), str)
        or not isinstance(entities, list)
        or not entities
        or not all(isinstance(item, str) and item for item in entities)
        or not isinstance(patterns, dict)
        or set(patterns) != {"EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "CUSTOMER_ID"}
        or not all(isinstance(pattern, str) and pattern for pattern in patterns.values())
    ):
        raise ValueError("PII policy is incomplete")
    threshold = value.get("score_threshold")
    if not isinstance(threshold, int | float) or not 0 <= threshold <= 1:
        raise ValueError("PII score threshold must be between zero and one")
    return value


def _validate_cases(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("PII cases require schema_version 1")
    if value.get("synthetic_data_only") is not True:
        raise ValueError("PII cases must declare synthetic_data_only")
    cases = value.get("cases")
    if not isinstance(cases, list) or len(cases) != 24:
        raise ValueError("PII experiment requires exactly 24 cases")
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("PII case must be an object")
        case_id = case.get("id")
        text = case.get("text")
        expected = case.get("expected")
        if (
            not isinstance(case_id, str)
            or not case_id
            or case_id in seen
            or case.get("flow") not in {"input", "output"}
            or not isinstance(text, str)
            or not text
            or not isinstance(expected, list)
        ):
            raise ValueError("PII case is invalid")
        seen.add(case_id)
        for item in expected:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("entity_type"), str)
                or not isinstance(item.get("value"), str)
                or not item["value"]
                or text.count(item["value"]) != 1
            ):
                raise ValueError(f"PII case {case_id} has an invalid expected span")
    return cases


def _luhn_valid(value: str) -> bool:
    digits = [int(character) for character in value if character.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def application_detections(text: str, policy: dict[str, Any]) -> list[Detection]:
    """Apply the experiment-owned deterministic recognizers."""
    detections: list[Detection] = []
    for entity_type, pattern in policy["application_patterns"].items():
        for match in re.finditer(pattern, text):
            if entity_type == "CREDIT_CARD" and not _luhn_valid(match.group(0)):
                continue
            detections.append(
                Detection(entity_type=entity_type, start=match.start(), end=match.end(), score=1.0)
            )
    return _normalize_detections(detections)


def _normalize_detections(detections: list[Detection]) -> list[Detection]:
    unique: dict[tuple[str, int, int], Detection] = {}
    for item in detections:
        if item.start < 0 or item.end <= item.start:
            raise ValueError("PII detector returned an invalid span")
        key = (item.entity_type, item.start, item.end)
        if key not in unique or item.score > unique[key].score:
            unique[key] = item
    return sorted(unique.values(), key=lambda item: (item.start, item.end, item.entity_type))


def mask_text(text: str, detections: list[Detection]) -> str:
    """Deterministically replace non-overlapping detections for test and fallback use."""
    output = text
    cursor = len(text)
    for item in sorted(detections, key=lambda value: (value.start, value.end), reverse=True):
        if item.end > cursor:
            continue
        output = f"{output[: item.start]}<{item.entity_type}>{output[item.end :]}"
        cursor = item.start
    return output


def _expected_spans(case: dict[str, Any]) -> set[tuple[str, int, int]]:
    spans: set[tuple[str, int, int]] = set()
    text = case["text"]
    for item in case["expected"]:
        start = text.index(item["value"])
        spans.add((item["entity_type"], start, start + len(item["value"])))
    return spans


def _evaluate_case(
    case: dict[str, Any],
    profile: str,
    policy: dict[str, Any],
    runtime: PresidioRuntime,
) -> dict[str, Any]:
    text = case["text"]
    if profile == "raw":
        detections: list[Detection] = []
        masked = text
    elif profile == "application_rules":
        detections = application_detections(text, policy)
        masked = runtime.anonymize(text, detections)
    else:
        detections = runtime.detect(
            text,
            layered=profile == "layered",
            entities=policy["entities"],
        )
        detections = [item for item in detections if item.score >= policy["score_threshold"]]
        masked = runtime.anonymize(text, detections)

    expected = _expected_spans(case)
    observed = {(item.entity_type, item.start, item.end) for item in detections}
    true_positive = len(expected & observed)
    false_positive = len(observed - expected)
    false_negative = len(expected - observed)
    leaked = sum(item["value"] in masked for item in case["expected"])
    return {
        "case_id": case["id"],
        "flow": case["flow"],
        "profile": profile,
        "input_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "expected_entities": len(expected),
        "detected_entities": len(observed),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "unmasked_expected_values": leaked,
        "changed_without_expected_pii": bool(not expected and masked != text),
        "detections": [asdict(item) for item in detections],
        "masked_text": masked,
    }


def _profile_summary(results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {}
    for profile in PROFILES:
        rows = [item for item in results if item["profile"] == profile]
        expected = sum(item["expected_entities"] for item in rows)
        detected = sum(item["detected_entities"] for item in rows)
        true_positive = sum(item["true_positive"] for item in rows)
        false_positive = sum(item["false_positive"] for item in rows)
        false_negative = sum(item["false_negative"] for item in rows)
        summary[profile] = {
            "cases": len(rows),
            "expected_entities": expected,
            "detected_entities": detected,
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "precision": round(true_positive / detected, 4) if detected else None,
            "recall": round(true_positive / expected, 4) if expected else None,
            "unmasked_expected_values": sum(item["unmasked_expected_values"] for item in rows),
            "changed_negative_cases": sum(item["changed_without_expected_pii"] for item in rows),
        }
    return summary


def run_pii_experiment(
    experiment: str,
    *,
    runtime: PresidioRuntime | None = None,
) -> dict[str, Any]:
    """Run the fixed Day 26 matrix once."""
    definition = load_pii_definition(experiment)
    policy_value, policy_evidence = _load_json_fixture(definition["policy"], experiment)
    cases_value, cases_evidence = _load_json_fixture(definition["cases"], experiment)
    policy = _validate_policy(policy_value)
    cases = _validate_cases(cases_value)
    network_error = RuntimeError("Day 26 forbids network access")
    with (
        patch("socket.create_connection", side_effect=network_error),
        patch.object(socket.socket, "connect", side_effect=network_error),
    ):
        if runtime is None:
            runtime = _load_presidio_runtime(policy)
        results = [
            _evaluate_case(case, profile, policy, runtime) for case in cases for profile in PROFILES
        ]
    profiles = _profile_summary(results)
    predictions = {
        "raw_leaks_every_expected_value": profiles["raw"]["unmasked_expected_values"]
        == profiles["raw"]["expected_entities"],
        "application_rules_miss_person": profiles["application_rules"]["false_negative"] > 0,
        "application_rules_have_no_false_positives": profiles["application_rules"]["false_positive"]
        == 0,
        "layered_recall_not_lower_than_either_detector": profiles["layered"]["recall"]
        >= max(
            profiles["application_rules"]["recall"],
            profiles["presidio_builtin"]["recall"],
        ),
    }
    return {
        "schema_version": 1,
        "experiment": experiment,
        "runner": PII_RUNNER,
        "generated_at": datetime.now(UTC).isoformat(),
        "tooling": {
            "presidio_analyzer": runtime.version,
            "presidio_anonymizer": runtime.version,
            "nlp_model": runtime.nlp_model,
        },
        "fixtures": [policy_evidence, cases_evidence],
        "policy_version": policy["version"],
        "profiles": profiles,
        "prediction_checks": predictions,
        "all_predictions_matched": all(predictions.values()),
        "results": results,
        "safety_boundary": {
            "synthetic_data_only": True,
            "model_calls": 0,
            "network_calls": 0,
            "external_side_effects": 0,
            "raw_values_in_sanitized_report": False,
        },
    }


def _load_presidio_runtime(policy: dict[str, Any]) -> PresidioRuntime:
    try:
        from importlib.metadata import version

        from presidio_analyzer import (
            AnalyzerEngine,
            Pattern,
            PatternRecognizer,
            RecognizerRegistry,
        )
        from presidio_analyzer.nlp_engine import SpacyNlpEngine
        from presidio_anonymizer import AnonymizerEngine
        from presidio_anonymizer.entities import OperatorConfig
    except ImportError as error:
        raise ValueError("Presidio is unavailable; run with --extra pii") from error

    nlp_engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": "en_core_web_sm"}])
    nlp_engine.load()

    def engine(layered: bool) -> Any:
        registry = RecognizerRegistry(supported_languages=["en"])
        registry.load_predefined_recognizers(languages=["en"], nlp_engine=nlp_engine)
        if layered:
            for entity_type in (
                "EMAIL_ADDRESS",
                "PHONE_NUMBER",
                "CREDIT_CARD",
                "CUSTOMER_ID",
            ):
                registry.add_recognizer(
                    PatternRecognizer(
                        supported_entity=entity_type,
                        supported_language="en",
                        patterns=[
                            Pattern(
                                name=f"day26_{entity_type.lower()}",
                                regex=policy["application_patterns"][entity_type],
                                score=1.0,
                            )
                        ],
                    )
                )
        return AnalyzerEngine(
            registry=registry,
            nlp_engine=nlp_engine,
            supported_languages=["en"],
            default_score_threshold=policy["score_threshold"],
        )

    presidio_version = version("presidio-analyzer")
    nlp_model_identity = f"en_core_web_sm=={version('en-core-web-sm')}"

    class Runtime:
        version = presidio_version
        nlp_model = nlp_model_identity

        def __init__(self) -> None:
            self._builtin = engine(False)
            self._layered = engine(True)
            self._anonymizer = AnonymizerEngine()

        def detect(self, text: str, *, layered: bool, entities: list[str]) -> list[Detection]:
            analyzer = self._layered if layered else self._builtin
            return _normalize_detections(
                [
                    Detection(
                        entity_type=item.entity_type,
                        start=item.start,
                        end=item.end,
                        score=float(item.score),
                    )
                    for item in analyzer.analyze(text=text, language="en", entities=entities)
                ]
            )

        def anonymize(self, text: str, detections: list[Detection]) -> str:
            from presidio_analyzer import RecognizerResult

            results = [
                RecognizerResult(
                    entity_type=item.entity_type,
                    start=item.start,
                    end=item.end,
                    score=item.score,
                )
                for item in detections
            ]
            operators = {
                entity: OperatorConfig("replace", {"new_value": f"<{entity}>"})
                for entity in policy["entities"]
            }
            return self._anonymizer.anonymize(
                text=text,
                analyzer_results=results,
                operators=operators,
            ).text

    return Runtime()


def _validated_batch(batch: Any) -> dict[str, Any]:
    if not isinstance(batch, dict) or batch.get("runner") != PII_RUNNER:
        raise ValueError("raw evidence is not a Day 26 PII batch")
    results = batch.get("results")
    if not isinstance(results, list) or len(results) != 24 * len(PROFILES):
        raise ValueError("PII result matrix is incomplete")
    if batch.get("profiles") != _profile_summary(results):
        raise ValueError("PII profile summary does not match results")
    predictions = batch.get("prediction_checks")
    if not isinstance(predictions, dict) or batch.get("all_predictions_matched") is not all(
        predictions.values()
    ):
        raise ValueError("PII prediction summary does not match results")
    if batch.get("all_predictions_matched") is not True:
        raise ValueError("PII experiment did not match preregistered predictions")
    expected_safety = {
        "synthetic_data_only": True,
        "model_calls": 0,
        "network_calls": 0,
        "external_side_effects": 0,
        "raw_values_in_sanitized_report": False,
    }
    if batch.get("safety_boundary") != expected_safety:
        raise ValueError("PII experiment violated its safety boundary")
    return batch


def load_pii_batch(path: Path) -> dict[str, Any]:
    """Load and validate raw Day 26 evidence."""
    return _validated_batch(json.loads(path.read_text(encoding="utf-8")))


def render_pii_report(batch: dict[str, Any]) -> str:
    """Render a sanitized report without fixture text or detected values."""
    batch = _validated_batch(batch)
    lines = [
        f"Experiment: {batch['experiment']}",
        f"Generated at: {batch['generated_at']}",
        f"Presidio: {batch['tooling']['presidio_analyzer']}",
        f"NLP model: {batch['tooling']['nlp_model']}",
        "",
        "Profile results:",
    ]
    for profile in PROFILES:
        item = batch["profiles"][profile]
        lines.append(
            f"- {profile}: tp={item['true_positive']}, fp={item['false_positive']}, "
            f"fn={item['false_negative']}, precision={item['precision']}, "
            f"recall={item['recall']}, unmasked={item['unmasked_expected_values']}, "
            f"changed_negatives={item['changed_negative_cases']}"
        )
    lines.extend(
        [
            "",
            "Flows:",
        ]
    )
    flow_counts = Counter(item["flow"] for item in batch["results"])
    lines.extend(f"- {flow}: {flow_counts[flow]} evaluations" for flow in sorted(flow_counts))
    lines.extend(
        [
            "",
            f"Prediction checks: {json.dumps(batch['prediction_checks'], sort_keys=True)}",
            "Synthetic data only: true",
            "Model calls: 0",
            "Network calls: 0",
            "External side effects: 0",
        ]
    )
    return "\n".join(lines)
