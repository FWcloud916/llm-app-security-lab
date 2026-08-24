"""Compare three NeMo input rails with a revision-pinned local Prompt Guard model."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

os.environ["NEMO_GUARDRAILS_NO_USAGE_STATS"] = "1"
os.environ["DO_NOT_TRACK"] = "1"
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"

from llm_security_lab.guardrails import DECISION_SCHEMA, _semantic_prompt
from llm_security_lab.ollama import OllamaClient

PROMPT_GUARD_RUNNER = "prompt_guard_input_comparison"
PROMPT_GUARD_SCHEMA_VERSION = 1
PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS_ROOT = PROJECT_ROOT / "experiments"
EXPERIMENT_ID_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
PATHS = ("semantic", "deterministic", "prompt_guard")


class JsonClient(Protocol):
    origin: str

    def request_json(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]: ...


class Classifier(Protocol):
    metadata: dict[str, Any]

    def classify(self, text: str) -> dict[str, Any]: ...


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode())


def _experiment_root(experiment: str) -> Path:
    if not EXPERIMENT_ID_PATTERN.fullmatch(experiment):
        raise ValueError("invalid experiment id")
    root = (EXPERIMENTS_ROOT / experiment).resolve(strict=True)
    if not root.is_relative_to(EXPERIMENTS_ROOT.resolve()) or not root.is_dir():
        raise ValueError("prompt-guard experiment escaped experiments root")
    return root


def available_prompt_guard_experiments() -> list[str]:
    """Return experiment IDs owned by the Prompt Guard input runner."""
    if not EXPERIMENTS_ROOT.is_dir():
        return []
    names: list[str] = []
    for path in EXPERIMENTS_ROOT.iterdir():
        if not path.is_dir() or not EXPERIMENT_ID_PATTERN.fullmatch(path.name):
            continue
        try:
            definition = json.loads((path / "experiment.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if definition.get("runner") == PROMPT_GUARD_RUNNER:
            names.append(path.name)
    return sorted(names)


def load_prompt_guard_definition(experiment: str) -> dict[str, Any]:
    """Load and validate one fixed Prompt Guard input-rail comparison."""
    definition = json.loads(
        (_experiment_root(experiment) / "experiment.json").read_text(encoding="utf-8")
    )
    required = {
        "schema_version",
        "id",
        "runner",
        "guard_model",
        "semantic_guard",
        "prompt_guard",
        "repetitions",
        "cases",
        "rails",
    }
    if not isinstance(definition, dict) or set(definition) != required:
        raise ValueError("prompt-guard definition fields do not match schema version 1")
    if (
        definition["schema_version"] != PROMPT_GUARD_SCHEMA_VERSION
        or definition["id"] != experiment
        or definition["runner"] != PROMPT_GUARD_RUNNER
    ):
        raise ValueError("prompt-guard experiment identity is invalid")
    guard_model = definition["guard_model"]
    if (
        not isinstance(guard_model, dict)
        or set(guard_model) != {"name", "digest"}
        or not all(isinstance(value, str) and value for value in guard_model.values())
        or len(guard_model["digest"]) != 64
    ):
        raise ValueError("guard_model requires a name and full digest")
    if definition["semantic_guard"] != {"temperature": 0, "seed": 2400}:
        raise ValueError("semantic guard contract changed")
    prompt_guard = definition["prompt_guard"]
    prompt_guard_fields = {
        "repo_id",
        "revision",
        "max_length",
        "benign_index",
        "malicious_index",
        "index_mapping_basis",
        "file_sha256",
    }
    if not isinstance(prompt_guard, dict) or set(prompt_guard) != prompt_guard_fields:
        raise ValueError("prompt_guard model contract is invalid")
    if (
        prompt_guard["repo_id"] != "meta-llama/Llama-Prompt-Guard-2-86M"
        or not isinstance(prompt_guard["revision"], str)
        or len(prompt_guard["revision"]) != 40
        or prompt_guard["max_length"] != 512
        or prompt_guard["benign_index"] != 0
        or prompt_guard["malicious_index"] != 1
        or prompt_guard["index_mapping_basis"] != "official-model-card-example-and-local-pilot"
    ):
        raise ValueError("prompt_guard identity or label mapping changed")
    file_hashes = prompt_guard["file_sha256"]
    required_files = {
        "config.json",
        "model.safetensors",
        "special_tokens_map.json",
        "tokenizer.json",
        "tokenizer_config.json",
    }
    if (
        not isinstance(file_hashes, dict)
        or set(file_hashes) != required_files
        or not all(
            isinstance(name, str) and isinstance(digest, str) and len(digest) == 64
            for name, digest in file_hashes.items()
        )
    ):
        raise ValueError("prompt_guard file hashes are incomplete")
    if definition["repetitions"] != [2411, 2412, 2413, 2414, 2415]:
        raise ValueError("prompt-guard repetitions changed")
    if not isinstance(definition["cases"], str) or not definition["cases"]:
        raise ValueError("prompt-guard cases fixture is missing")
    rails = definition["rails"]
    if not isinstance(rails, dict) or set(rails) != set(PATHS):
        raise ValueError("prompt-guard rail paths are incomplete")
    for relative_path in rails.values():
        root = (_experiment_root(experiment) / relative_path).resolve()
        if not root.is_relative_to(_experiment_root(experiment).resolve()):
            raise ValueError("prompt-guard rail config escapes the bundle")
        if not root.is_dir() or root.is_symlink():
            raise ValueError("prompt-guard rail config directory is invalid")
    return definition


def _read_cases(experiment: str, path: str) -> tuple[list[dict[str, str]], dict[str, str]]:
    from llm_security_lab.lab import read_fixture

    fixture = read_fixture(path, experiment)
    try:
        raw = json.loads(fixture["content"])
    except json.JSONDecodeError as error:
        raise ValueError("prompt-guard cases fixture is not valid JSON") from error
    required = {"id", "route", "expected", "request", "source"}
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "cases"}:
        raise ValueError("prompt-guard cases fixture is invalid")
    cases = raw["cases"]
    if raw["schema_version"] != 1 or not isinstance(cases, list) or len(cases) != 5:
        raise ValueError("prompt-guard comparison requires exactly five input cases")
    seen: set[str] = set()
    for case in cases:
        if (
            not isinstance(case, dict)
            or set(case) != required
            or not all(isinstance(value, str) and value for value in case.values())
            or not EXPERIMENT_ID_PATTERN.fullmatch(case["id"])
            or case["id"] in seen
            or case["expected"] not in {"allow", "block"}
        ):
            raise ValueError("prompt-guard input case is invalid")
        seen.add(case["id"])
    return cases, {"path": fixture["path"], "sha256": fixture["sha256"]}


def _canonical_input(case: dict[str, str]) -> str:
    return json.dumps(
        {"route": case["route"], "request": case["request"], "source": case["source"]},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


class LocalPromptGuard:
    """Load Prompt Guard from a verified local Hugging Face snapshot only."""

    def __init__(self, config: dict[str, Any]) -> None:
        try:
            import torch
            import transformers
            from huggingface_hub import snapshot_download
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as error:
            raise RuntimeError(
                "Prompt Guard dependencies are missing; run with --extra prompt-guard"
            ) from error
        snapshot = Path(
            snapshot_download(
                repo_id=config["repo_id"],
                revision=config["revision"],
                local_files_only=True,
            )
        )
        verified: dict[str, str] = {}
        for name, expected in config["file_sha256"].items():
            path = snapshot / name
            if not path.is_file():
                raise RuntimeError(f"Prompt Guard local snapshot is missing {name}")
            observed = _sha256_bytes(path.read_bytes())
            if observed != expected:
                raise RuntimeError(f"Prompt Guard local file hash changed: {name}")
            verified[name] = observed
        self._torch = torch
        self._tokenizer = AutoTokenizer.from_pretrained(
            snapshot, local_files_only=True, trust_remote_code=False
        )
        self._model = AutoModelForSequenceClassification.from_pretrained(
            snapshot, local_files_only=True, trust_remote_code=False
        )
        self._model.eval()
        if self._model.config.num_labels != 2:
            raise RuntimeError("Prompt Guard model no longer has two output classes")
        self._max_length = config["max_length"]
        self._benign_index = config["benign_index"]
        self._malicious_index = config["malicious_index"]
        self.metadata = {
            "repo_id": config["repo_id"],
            "revision": config["revision"],
            "max_length": self._max_length,
            "benign_index": self._benign_index,
            "malicious_index": self._malicious_index,
            "index_mapping_basis": config["index_mapping_basis"],
            "file_sha256": verified,
            "transformers_version": transformers.__version__,
            "torch_version": torch.__version__,
            "local_files_only": True,
        }

    def classify(self, text: str) -> dict[str, Any]:
        encoded = self._tokenizer(text, return_tensors="pt", truncation=False)
        token_count = int(encoded["input_ids"].shape[-1])
        if token_count > self._max_length:
            raise ValueError("Prompt Guard input exceeds the fixed 512-token experiment contract")
        with self._torch.inference_mode():
            logits = self._model(**encoded).logits
            probabilities = self._torch.softmax(logits, dim=-1)[0]
        predicted_index = int(logits.argmax(dim=-1).item())
        if predicted_index not in {self._benign_index, self._malicious_index}:
            raise RuntimeError("Prompt Guard returned an unknown class index")
        return {
            "decision": "block" if predicted_index == self._malicious_index else "allow",
            "predicted_index": predicted_index,
            "malicious_score": float(probabilities[self._malicious_index].item()),
            "token_count": token_count,
        }


class _InputGuardAction:
    def __init__(
        self,
        *,
        kind: str,
        client: JsonClient,
        guard_model: dict[str, Any],
        guard_options: dict[str, Any],
        classifier: Classifier,
    ) -> None:
        self.kind = kind
        self.client = client
        self.guard_model = guard_model
        self.guard_options = guard_options
        self.classifier = classifier
        self.traces: list[dict[str, Any]] = []

    async def __call__(self, text: str) -> bool:
        if not isinstance(text, str):
            raise ValueError("input rail received non-text content")
        if self.kind == "semantic":
            trace = self._semantic(text)
        elif self.kind == "deterministic":
            trace = self._deterministic(text)
        else:
            trace = self._prompt_guard(text)
        self.traces.append(trace)
        return trace["decision"] == "allow"

    def _semantic(self, text: str) -> dict[str, Any]:
        payload = {
            "model": self.guard_model["name"],
            "messages": _semantic_prompt("input", text),
            "format": DECISION_SCHEMA,
            "stream": False,
            "options": {
                "seed": self.guard_options["seed"],
                "temperature": self.guard_options["temperature"],
            },
        }
        response = self.client.request_json("/api/chat", payload)
        raw_content = response.get("message", {}).get("content")
        decision = "block"
        reason = "parser_error"
        parser_valid = False
        if isinstance(raw_content, str):
            try:
                parsed = json.loads(raw_content)
            except json.JSONDecodeError:
                parsed = None
            if (
                isinstance(parsed, dict)
                and set(parsed) == {"decision", "reason"}
                and parsed["decision"] in {"allow", "block"}
                and parsed["reason"] in {"none", "input_attack"}
                and ((parsed["decision"] == "allow") == (parsed["reason"] == "none"))
            ):
                decision = parsed["decision"]
                reason = parsed["reason"]
                parser_valid = True
        return {
            "kind": self.kind,
            "decision": decision,
            "reason": reason,
            "parser_valid": parser_valid,
            "model_call": True,
            "model_runtime": "loopback_ollama",
            "request": payload,
            "response": response,
            "input_sha256": _sha256_text(text),
        }

    def _deterministic(self, text: str) -> dict[str, Any]:
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            value = None
        blocked = not isinstance(value, dict) or value.get("route") == "override-policy"
        return {
            "kind": self.kind,
            "decision": "block" if blocked else "allow",
            "reason": "input_contract" if blocked else "none",
            "parser_valid": True,
            "model_call": False,
            "model_runtime": "none",
            "input_sha256": _sha256_text(text),
        }

    def _prompt_guard(self, text: str) -> dict[str, Any]:
        result = self.classifier.classify(text)
        if (
            not isinstance(result, dict)
            or set(result) != {"decision", "predicted_index", "malicious_score", "token_count"}
            or result["decision"] not in {"allow", "block"}
            or not isinstance(result["predicted_index"], int)
            or not isinstance(result["malicious_score"], float)
            or not 0 <= result["malicious_score"] <= 1
            or not isinstance(result["token_count"], int)
            or result["token_count"] < 1
        ):
            raise RuntimeError("Prompt Guard classifier returned invalid evidence")
        return {
            "kind": self.kind,
            "decision": result["decision"],
            "reason": "prompt_attack" if result["decision"] == "block" else "none",
            "parser_valid": True,
            "model_call": True,
            "model_runtime": "local_prompt_guard",
            "predicted_index": result["predicted_index"],
            "malicious_score": result["malicious_score"],
            "token_count": result["token_count"],
            "input_sha256": _sha256_text(text),
        }


class _NemoInputExecutor:
    def __init__(
        self,
        *,
        definition: dict[str, Any],
        experiment: str,
        client: JsonClient,
        guard_model: dict[str, Any],
        classifier: Classifier,
    ) -> None:
        from nemoguardrails import LLMRails, RailsConfig

        self._apps: dict[str, Any] = {}
        self._actions: dict[str, _InputGuardAction] = {}
        for kind, relative_path in definition["rails"].items():
            action = _InputGuardAction(
                kind=kind,
                client=client,
                guard_model=guard_model,
                guard_options=definition["semantic_guard"],
                classifier=classifier,
            )
            app = LLMRails(RailsConfig.from_path(str(_experiment_root(experiment) / relative_path)))

            async def run_action(text: str, *, _action: _InputGuardAction = action) -> bool:
                return await _action(text)

            app.register_action(run_action, name="day24_input_guard")
            self._apps[kind] = app
            self._actions[kind] = action

    async def check(self, kind: str, text: str) -> dict[str, Any]:
        from nemoguardrails.rails.llm.options import RailStatus, RailType

        action = self._actions[kind]
        action.traces.clear()
        result = await self._apps[kind].check_async(
            [{"role": "user", "content": text}], rail_types=[RailType.INPUT]
        )
        if len(action.traces) != 1:
            raise RuntimeError(f"NeMo input rail {kind} did not execute exactly once")
        trace = action.traces[0]
        statuses = {
            RailStatus.PASSED: "passed",
            RailStatus.MODIFIED: "modified",
            RailStatus.BLOCKED: "blocked",
        }
        status = statuses.get(result.status)
        if status == "modified":
            trace["decision"] = "block"
            trace["reason"] = "unexpected_modification"
        expected_status = "passed" if trace["decision"] == "allow" else "blocked"
        if status != expected_status:
            raise RuntimeError(f"NeMo input rail {kind} status disagrees with its action")
        trace["framework_status"] = status
        trace["blocking_rail"] = result.rail
        return trace


def summarize_prompt_guard(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the deterministic summary checked again by the reporter."""
    by_path: dict[str, Any] = {}
    for path in PATHS:
        traces = [run["paths"][path] for run in runs]
        by_path[path] = {
            "evaluated": len(traces),
            "allowed": sum(trace["decision"] == "allow" for trace in traces),
            "blocked": sum(trace["decision"] == "block" for trace in traces),
            "correct": sum(
                trace["decision"] == run["expected"]
                for run, trace in zip(runs, traces, strict=True)
            ),
            "false_positive": sum(
                run["expected"] == "allow" and trace["decision"] == "block"
                for run, trace in zip(runs, traces, strict=True)
            ),
            "false_negative": sum(
                run["expected"] == "block" and trace["decision"] == "allow"
                for run, trace in zip(runs, traces, strict=True)
            ),
            "model_calls": sum(trace["model_call"] is True for trace in traces),
            "parser_failures": sum(trace["parser_valid"] is False for trace in traces),
        }
    case_ids = list(dict.fromkeys(run["case_id"] for run in runs))
    by_case: dict[str, Any] = {}
    for case_id in case_ids:
        case_runs = [run for run in runs if run["case_id"] == case_id]
        by_case[case_id] = {
            "expected": case_runs[0]["expected"],
            "evaluated": len(case_runs),
            "blocked_by_path": {
                path: sum(run["paths"][path]["decision"] == "block" for run in case_runs)
                for path in PATHS
            },
        }
    return {
        "run_units": len(runs),
        "path_evaluations": len(runs) * len(PATHS),
        "cases": len(case_ids),
        "repetitions": sorted({run["repetition"] for run in runs}),
        "model_calls": sum(item["model_calls"] for item in by_path.values()),
        "generator_calls": 0,
        "sink_reached": 0,
        "by_path": by_path,
        "by_case": by_case,
    }


async def run_prompt_guard_experiment(
    experiment: str,
    *,
    client: JsonClient | None = None,
    classifier: Classifier | None = None,
) -> dict[str, Any]:
    """Run the complete input-only comparison through three NeMo rails."""
    from llm_security_lab.lab import select_model

    definition = load_prompt_guard_definition(experiment)
    cases, cases_evidence = _read_cases(experiment, definition["cases"])
    ollama = client or OllamaClient()
    version = ollama.request_json("/api/version")
    tags = ollama.request_json("/api/tags")
    guard_model = select_model(tags, definition["guard_model"])
    local_classifier = classifier or LocalPromptGuard(definition["prompt_guard"])
    executor = _NemoInputExecutor(
        definition=definition,
        experiment=experiment,
        client=ollama,
        guard_model=guard_model,
        classifier=local_classifier,
    )
    runs: list[dict[str, Any]] = []
    for case in cases:
        text = _canonical_input(case)
        for repetition in definition["repetitions"]:
            paths = {path: await executor.check(path, text) for path in PATHS}
            runs.append(
                {
                    "run_id": f"{case['id']}-{repetition}",
                    "case_id": case["id"],
                    "repetition": repetition,
                    "expected": case["expected"],
                    "input_sha256": _sha256_text(text),
                    "paths": paths,
                }
            )
    summary = summarize_prompt_guard(runs)
    import nemoguardrails

    return {
        "schema_version": PROMPT_GUARD_SCHEMA_VERSION,
        "experiment_id": experiment,
        "runner": PROMPT_GUARD_RUNNER,
        "recorded_at": datetime.now(UTC).isoformat(),
        "framework": {"name": "nemoguardrails", "version": nemoguardrails.__version__},
        "telemetry": {
            "nemo_usage_stats_disabled": True,
            "do_not_track": True,
            "hugging_face_telemetry_disabled": True,
        },
        "ollama_version": version.get("version"),
        "guard_model": guard_model,
        "prompt_guard": local_classifier.metadata,
        "fixture_hashes": {cases_evidence["path"]: cases_evidence["sha256"]},
        "runs": runs,
        "summary": summary,
        "safety_boundary": {
            "synthetic_data_only": True,
            "ollama_origin": ollama.origin,
            "prompt_guard_local_files_only": True,
            "browser_launches": 0,
            "javascript_executions": 0,
            "external_network_calls": 0,
            "subprocess_calls": 0,
            "external_side_effects": 0,
            "generator_calls": 0,
            "sink_reached": 0,
        },
    }


def load_prompt_guard_batch(path: Path) -> dict[str, Any]:
    """Load raw evidence and reject summary, telemetry, or boundary tampering."""
    batch = json.loads(path.read_text(encoding="utf-8"))
    if (
        batch.get("schema_version") != PROMPT_GUARD_SCHEMA_VERSION
        or batch.get("runner") != PROMPT_GUARD_RUNNER
        or not isinstance(batch.get("runs"), list)
    ):
        raise ValueError("prompt-guard evidence is invalid")
    if batch.get("summary") != summarize_prompt_guard(batch["runs"]):
        raise ValueError("stored prompt-guard summary does not match its evidence")
    boundary = batch.get("safety_boundary")
    zero_fields = (
        "browser_launches",
        "javascript_executions",
        "external_network_calls",
        "subprocess_calls",
        "external_side_effects",
        "generator_calls",
        "sink_reached",
    )
    if (
        not isinstance(boundary, dict)
        or boundary.get("prompt_guard_local_files_only") is not True
        or any(boundary.get(field) != 0 for field in zero_fields)
    ):
        raise ValueError("prompt-guard evidence violates the safety boundary")
    expected_telemetry = {
        "nemo_usage_stats_disabled": True,
        "do_not_track": True,
        "hugging_face_telemetry_disabled": True,
    }
    if batch.get("telemetry") != expected_telemetry:
        raise ValueError("prompt-guard evidence did not disable telemetry")
    return batch


def render_prompt_guard_report(batch: dict[str, Any]) -> str:
    """Render a sanitized report without fixture text or classifier requests."""
    summary = batch["summary"]
    model = batch["prompt_guard"]
    lines = [
        "## Prompt Guard input-rail comparison",
        "",
        f"- Recorded at: `{batch['recorded_at']}`",
        f"- Framework: `nemoguardrails {batch['framework']['version']}`",
        f"- Prompt Guard: `{model['repo_id']}`",
        f"- Revision: `{model['revision']}`",
        f"- Transformers / PyTorch: `{model.get('transformers_version', 'test')} / {model.get('torch_version', 'test')}`",
        f"- Run units / path evaluations: `{summary['run_units']} / {summary['path_evaluations']}`",
        f"- Generator calls / sink reached: `{summary['generator_calls']} / {summary['sink_reached']}`",
        "- Browser / JavaScript / external network / subprocess / external side effects: `0 / 0 / 0 / 0 / 0`",
        "",
        "| Path | Allowed | Blocked | Correct | False positive | False negative | Model calls | Parser failures |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for path in PATHS:
        item = summary["by_path"][path]
        lines.append(
            f"| {path} | {item['allowed']} | {item['blocked']} | {item['correct']} | "
            f"{item['false_positive']} | {item['false_negative']} | {item['model_calls']} | "
            f"{item['parser_failures']} |"
        )
    lines.extend(
        [
            "",
            "### Blocked repetitions by case",
            "",
            "| Case | Expected | Semantic | Deterministic | Prompt Guard |",
            "|---|---|---:|---:|---:|",
        ]
    )
    for case_id, item in summary["by_case"].items():
        blocked = item["blocked_by_path"]
        lines.append(
            f"| {case_id} | {item['expected']} | {blocked['semantic']} / {item['evaluated']} | "
            f"{blocked['deterministic']} / {item['evaluated']} | "
            f"{blocked['prompt_guard']} / {item['evaluated']} |"
        )
    lines.extend(["", "### Input fingerprints", ""])
    for run in batch["runs"]:
        lines.append(f"- `{run['run_id']}`: `{run['input_sha256']}`")
    return "\n".join(lines) + "\n"
