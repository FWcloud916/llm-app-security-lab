from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from llm_security_lab import lab
from llm_security_lab.ollama import OllamaClient

EXPECTED_DIGEST = "c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb"
CANARY = "LAB_ONLY_CANARY_7K4M_20260806"
DAY_5 = "day-05-threat-flow-observation"
DAY_7 = "day-07-boundary-crossing-warmup"
DAY_8 = "day-08-prompt-injection-mechanism"
DAY_9 = "day-09-direct-vs-indirect-injection"
DAY_10 = "day-10-hidden-document-paths"
DAY_7_CANARY = "LAB_ONLY_DAY7_CANARY_6Q9V_20260807"
OVERRIDE_MARKER = "DAY7_OVERRIDE_ACCEPTED"
DAY_8_CANARY = "LAB_ONLY_DAY8_CANARY_4R7N_20260807"
DAY_8_TARGET = "DAY8_TARGET_COMPLETED"
DAY_8_INJECTION = "DAY8_INJECTION_ACCEPTED"
DAY_9_CANARY = "LAB_ONLY_DAY9_CANARY_8M2T_20260807"
DAY_9_TARGET = "DAY9_TARGET_COMPLETED"
DAY_9_INJECTION = "DAY9_INJECTION_ACCEPTED"
DAY_10_CANARY = "LAB_ONLY_DAY10_CANARY_5H8P_20260808"
DAY_10_TARGET = "DAY10_TARGET_COMPLETED"
DAY_10_INJECTION = "DAY10_INJECTION_ACCEPTED"


class FakeClient:
    origin = "http://127.0.0.1:11434"

    def __init__(
        self,
        digest: str = EXPECTED_DIGEST,
        response_content: str = "synthetic response",
    ) -> None:
        self.digest = digest
        self.response_content = response_content
        self.chat_payload: dict[str, Any] | None = None
        self.chat_payloads: list[dict[str, Any]] = []
        self.chat_calls = 0
        self.version_calls = 0
        self.tags_calls = 0

    def request_json(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if path == "/api/version":
            self.version_calls += 1
            return {"version": "test"}
        if path == "/api/tags":
            self.tags_calls += 1
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
            self.chat_calls += 1
            self.chat_payload = payload
            assert payload is not None
            self.chat_payloads.append(payload)
            return {"message": {"role": "assistant", "content": self.response_content}}
        raise AssertionError(f"unexpected path: {path}")


def test_experiment_bundles_are_discoverable() -> None:
    assert lab.available_experiments() == [
        "day-04-vulnerable-baseline",
        DAY_5,
        DAY_7,
        DAY_8,
        DAY_9,
        DAY_10,
    ]


def test_clean_scenario_excludes_attack_note_and_tools() -> None:
    client = FakeClient()

    evidence = lab.run("clean", client=client)

    assert evidence["scenario_id"] == "day-04-vulnerable-baseline"
    assert evidence["safety_boundary"]["tools_sent"] is False
    assert evidence["observations"] == {
        "marker_id": "lab_canary",
        "canary_in_request": True,
        "canary_in_model_response": False,
        "canary_in_fixture_evidence": True,
        "canary_in_full_stdout": True,
    }
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


@pytest.mark.parametrize(
    ("response", "expected"),
    [("safe summary", False), (f"LEAKED: {CANARY}", True)],
)
def test_day_5_observes_canary_at_each_sink(response: str, expected: bool) -> None:
    evidence = lab.run("clean", client=FakeClient(response_content=response), experiment=DAY_5)

    assert evidence["safety_boundary"]["fixtures_root"] == (
        "experiments/day-05-threat-flow-observation/fixtures/"
    )
    assert evidence["observations"] == {
        "marker_id": "lab_canary",
        "canary_in_request": True,
        "canary_in_model_response": expected,
        "canary_in_fixture_evidence": True,
        "canary_in_full_stdout": True,
    }


def test_repeated_batch_retains_all_runs_and_counts() -> None:
    client = FakeClient(response_content=f"LEAKED: {CANARY}")

    batch = lab.run_repeated(DAY_5, "attack", 3, client=client)

    assert client.chat_calls == 3
    assert len(batch["runs"]) == 3
    assert batch["summary"]["true_counts"] == {
        "canary_in_request": 3,
        "canary_in_model_response": 3,
        "canary_in_fixture_evidence": 3,
        "canary_in_full_stdout": 3,
    }


@pytest.mark.parametrize(
    ("response", "expected_override", "expected_canary"),
    [
        ("safe summary", False, False),
        (OVERRIDE_MARKER, True, False),
        (f"{OVERRIDE_MARKER}\nLEAKED: {DAY_7_CANARY}", True, True),
    ],
)
def test_day_7_distinguishes_behavior_change_from_boundary_crossing(
    response: str,
    expected_override: bool,
    expected_canary: bool,
) -> None:
    evidence = lab.run(
        "clean",
        client=FakeClient(response_content=response),
        experiment=DAY_7,
    )

    assert evidence["observations"] == {
        "marker_id": "lab_canary",
        "canary_in_request": True,
        "canary_in_model_response": expected_canary,
        "canary_in_fixture_evidence": True,
        "canary_in_full_stdout": True,
        "override_marker_in_model_response": expected_override,
    }


def test_day_7_repeated_batch_counts_every_marker() -> None:
    response = f"{OVERRIDE_MARKER}\nLEAKED: {DAY_7_CANARY}"

    batch = lab.run_repeated(
        DAY_7,
        "boundary-crossing",
        3,
        client=FakeClient(response_content=response),
    )

    assert batch["summary"]["true_counts"] == {
        "canary_in_request": 3,
        "canary_in_model_response": 3,
        "canary_in_fixture_evidence": 3,
        "canary_in_full_stdout": 3,
        "override_marker_in_model_response": 3,
    }


def test_day_7_scenarios_add_only_the_declared_attack_note() -> None:
    expected_notes = {
        "clean": {
            "synthetic-notes/01-preferences.md",
            "synthetic-notes/02-lab-canary.md",
        },
        "behavior-only": {
            "synthetic-notes/01-preferences.md",
            "synthetic-notes/02-lab-canary.md",
            "synthetic-notes/98-behavior-only.md",
        },
        "boundary-crossing": {
            "synthetic-notes/01-preferences.md",
            "synthetic-notes/02-lab-canary.md",
            "synthetic-notes/99-boundary-crossing.md",
        },
    }

    for scenario, expected in expected_notes.items():
        client = FakeClient()
        evidence = lab.run(scenario, client=client, experiment=DAY_7)

        assert {fixture["path"] for fixture in evidence["fixtures"]["notes"]} == expected
        assert client.chat_payload is not None
        assert "tools" not in client.chat_payload


def test_day_8_plan_is_fixed_before_execution() -> None:
    definition = lab.load_definition(DAY_8)
    plan = lab.planned_runs(definition)

    assert len(plan) == 32
    assert [item["run_id"] for item in plan[:3]] == [
        "a-clean-01",
        "a-clean-02",
        "a-clean-03",
    ]
    assert [item["options"]["seed"] for item in plan[12:22]] == list(range(201, 211))
    assert [item["options"]["seed"] for item in plan[22:32]] == list(range(201, 211))
    assert {item["options"]["temperature"] for item in plan[:12]} == {0}
    assert {item["options"]["temperature"] for item in plan[12:]} == {0.7}


def test_day_9_plan_is_fixed_before_execution() -> None:
    definition = lab.load_definition(DAY_9)
    plan = lab.planned_runs(definition)

    assert len(plan) == 30
    assert [item["scenario"] for item in plan] == [
        *(["clean"] * 10),
        *(["direct"] * 10),
        *(["indirect"] * 10),
    ]
    for offset in (0, 10, 20):
        assert [item["options"]["seed"] for item in plan[offset : offset + 10]] == list(
            range(301, 311)
        )
    assert {item["options"]["temperature"] for item in plan} == {0.7}


def test_day_10_plan_is_fixed_before_execution() -> None:
    definition = lab.load_definition(DAY_10)
    plan = lab.planned_runs(definition)

    assert len(plan) == 45
    assert [item["scenario"] for item in plan[::5]] == [
        "clean-html",
        "html-white-text",
        "html-comment",
        "pdf-white-text",
        "pdf-metadata-body-only",
        "pdf-metadata-included",
        "email-hidden-html",
        "email-filename-body-only",
        "email-filename-included",
    ]
    for offset in range(0, 45, 5):
        assert [item["options"]["seed"] for item in plan[offset : offset + 5]] == list(
            range(401, 406)
        )
    assert {item["options"]["temperature"] for item in plan} == {0.7}


def test_day_10_observes_source_extraction_request_and_model_separately() -> None:
    response = f"{DAY_10_TARGET}\n{DAY_10_INJECTION}\nLEAKED: {DAY_10_CANARY}"
    batch = lab.run_planned(DAY_10, client=FakeClient(response_content=response))
    first_by_scenario = {
        run["scenario"]: run for run in batch["runs"] if run["run_id"].endswith("401")
    }

    expected_paths = {
        "clean-html": (False, False, False),
        "html-white-text": (True, True, True),
        "html-comment": (True, False, False),
        "pdf-white-text": (True, True, True),
        "pdf-metadata-body-only": (True, False, False),
        "pdf-metadata-included": (True, True, True),
        "email-hidden-html": (True, True, True),
        "email-filename-body-only": (True, False, False),
        "email-filename-included": (True, True, True),
    }
    for scenario, expected in expected_paths.items():
        observation = first_by_scenario[scenario]["observations"]
        assert (
            observation["injection_marker_in_source_bytes"],
            observation["injection_marker_in_extracted_document"],
            observation["injection_marker_in_request"],
        ) == expected
        assert observation["injection_marker_in_model_response"] is True

    assert batch["summary"]["scenarios"]["html-comment"]["true_counts"] == {
        "canary_in_request": 5,
        "canary_in_model_response": 5,
        "canary_in_fixture_evidence": 5,
        "canary_in_full_stdout": 5,
        "target_marker_in_model_response": 5,
        "injection_marker_in_model_response": 5,
        "injection_marker_in_source_bytes": 5,
        "injection_marker_in_extracted_document": 0,
        "injection_marker_in_request": 0,
    }


def test_day_10_summary_rejects_tampered_document_evidence() -> None:
    batch = lab.run_planned(DAY_10, client=FakeClient(response_content=DAY_10_TARGET))

    changed_source = deepcopy(batch["runs"])
    changed_source[0]["fixtures"]["target"]["source_base64"] = "dGFtcGVyZWQ="
    with pytest.raises(ValueError, match="source hash does not match"):
        lab.summarize_planned_runs(changed_source, batch["run_plan"])

    changed_extractor = deepcopy(batch["runs"])
    changed_extractor[1]["fixtures"]["target"]["extractor"]["version"] = "changed"
    with pytest.raises(ValueError, match="changed model-visible inputs"):
        lab.summarize_planned_runs(changed_extractor, batch["run_plan"])


def test_day_10_document_spec_rejects_format_suffix_mismatch() -> None:
    definition = deepcopy(lab.load_definition(DAY_10))
    definition["scenarios"]["clean-html"]["document"]["format"] = "pdf"

    with pytest.raises(ValueError, match="suffix does not match"):
        lab.planned_runs(definition)


def test_planned_user_request_must_be_non_empty_when_declared() -> None:
    definition = deepcopy(lab.load_definition(DAY_8))
    definition["scenarios"]["phase-a-clean"]["user_request"] = "  "

    with pytest.raises(ValueError, match="user request must be a non-empty string"):
        lab.planned_runs(definition)


def test_day_9_delivers_the_same_payload_through_distinct_sources() -> None:
    definition = lab.load_definition(DAY_9)
    indirect_payload = lab.read_fixture("synthetic-notes/99-indirect-injection.md", DAY_9)[
        "content"
    ]

    assert indirect_payload in definition["scenarios"]["direct"]["user_request"]
    assert indirect_payload not in definition["scenarios"]["indirect"]["user_request"]

    response = f"{DAY_9_TARGET}\n{DAY_9_INJECTION}\nLEAKED: {DAY_9_CANARY}"
    batch = lab.run_planned(DAY_9, client=FakeClient(response_content=response))
    direct = batch["runs"][10]
    indirect = batch["runs"][20]
    direct_message = direct["request"]["messages"][1]["content"]
    indirect_message = indirect["request"]["messages"][1]["content"]

    assert direct_message.startswith("<user_request>\n")
    assert indirect_message.startswith("<user_request>\n")
    assert direct_message.index(indirect_payload) < direct_message.index("<reference_notes>")
    assert indirect_message.index(indirect_payload) > indirect_message.index("<reference_notes>")
    assert {fixture["path"] for fixture in direct["fixtures"]["notes"]} == {
        "synthetic-notes/01-preferences.md",
        "synthetic-notes/02-lab-canary.md",
    }
    assert {fixture["path"] for fixture in indirect["fixtures"]["notes"]} == {
        "synthetic-notes/01-preferences.md",
        "synthetic-notes/02-lab-canary.md",
        "synthetic-notes/99-indirect-injection.md",
    }
    assert direct["request"]["messages"][0] == indirect["request"]["messages"][0]
    assert "tools" not in direct["request"]
    assert "tools" not in indirect["request"]


def test_day_8_executes_complete_plan_with_one_model_preflight() -> None:
    response = f"{DAY_8_TARGET}\n{DAY_8_INJECTION}\nLEAKED: {DAY_8_CANARY}"
    client = FakeClient(response_content=response)

    batch = lab.run_planned(DAY_8, client=client)

    assert batch["schema_version"] == 2
    assert client.version_calls == 1
    assert client.tags_calls == 1
    assert client.chat_calls == 32
    assert [run["run_id"] for run in batch["runs"]] == [
        item["run_id"] for item in batch["run_plan"]
    ]
    assert batch["summary"]["scenario_order"] == [
        "phase-a-clean",
        "phase-a-semantic",
        "phase-a-reinforced",
        "phase-a-delimiter-break",
        "phase-b-semantic-baseline",
        "phase-b-semantic-reinforced",
    ]
    assert batch["summary"]["scenarios"]["phase-a-semantic"]["true_counts"] == {
        "canary_in_request": 3,
        "canary_in_model_response": 3,
        "canary_in_fixture_evidence": 3,
        "canary_in_full_stdout": 3,
        "target_marker_in_model_response": 3,
        "injection_marker_in_model_response": 3,
    }

    semantic = batch["runs"][3]
    reinforced = batch["runs"][6]
    assert semantic["request"]["messages"][1] == reinforced["request"]["messages"][1]
    assert "<user_request>" not in semantic["request"]["messages"][1]["content"]
    assert semantic["request"]["messages"][0] != reinforced["request"]["messages"][0]


def test_planned_summary_rejects_reordered_and_unplanned_options() -> None:
    client = FakeClient(response_content=DAY_8_TARGET)
    batch = lab.run_planned(DAY_8, client=client)
    reordered = deepcopy(batch["runs"])
    reordered[0], reordered[1] = reordered[1], reordered[0]

    with pytest.raises(ValueError, match="order or id changed"):
        lab.summarize_planned_runs(reordered, batch["run_plan"])

    changed = deepcopy(batch["runs"])
    changed[0]["request"]["options"]["seed"] = 999
    with pytest.raises(ValueError, match="options changed"):
        lab.summarize_planned_runs(changed, batch["run_plan"])


def test_planned_summary_rejects_duplicate_run_ids() -> None:
    client = FakeClient(response_content=DAY_8_TARGET)
    batch = lab.run_planned(DAY_8, client=client)
    duplicated_plan = deepcopy(batch["run_plan"])
    duplicated_runs = deepcopy(batch["runs"])
    duplicated_plan[1]["run_id"] = duplicated_plan[0]["run_id"]
    duplicated_runs[1]["run_id"] = duplicated_runs[0]["run_id"]

    with pytest.raises(ValueError, match="duplicate run ids"):
        lab.summarize_planned_runs(duplicated_runs, duplicated_plan)


@pytest.mark.parametrize(
    ("markers", "message"),
    [
        ({"id": "override_marker", "value": "x"}, "must be a list"),
        ([{"id": "bad-id", "value": "x"}], "lowercase snake_case"),
        ([{"id": "override_marker", "value": ""}], "non-empty value"),
        (
            [
                {"id": "override_marker", "value": "x"},
                {"id": "override_marker", "value": "y"},
            ],
            "duplicate response marker",
        ),
        ([{"id": "canary", "value": "x"}], "collides with canary"),
    ],
)
def test_response_marker_definition_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    markers: object,
    message: str,
) -> None:
    bundle = tmp_path / "test-bundle"
    bundle.mkdir()
    (bundle / "experiment.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "id": "test-bundle",
                "model": {"name": "synthetic", "digest": "synthetic", "options": {}},
                "response_markers": markers,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(lab, "EXPERIMENTS_ROOT", tmp_path)

    with pytest.raises(ValueError, match=message):
        lab.load_definition("test-bundle")


def test_summarize_runs_rejects_mixed_scenarios() -> None:
    client = FakeClient()
    clean = lab.run("clean", client=client, experiment=DAY_5)
    attack = lab.run("attack", client=client, experiment=DAY_5)

    with pytest.raises(ValueError, match="mixed experiment environments or inputs"):
        lab.summarize_runs([clean, attack])


def test_model_digest_mismatch_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="model digest changed"):
        lab.run("clean", client=FakeClient(digest="changed"))


def test_day_4_and_day_5_fixture_hashes_match_without_sharing_paths() -> None:
    paths = (
        "synthetic-notes/01-preferences.md",
        "synthetic-notes/02-lab-canary.md",
        "synthetic-notes/99-injection.md",
        "target.md",
    )

    for relative_path in paths:
        day_4 = lab.read_fixture(relative_path, "day-04-vulnerable-baseline")
        day_5 = lab.read_fixture(relative_path, DAY_5)
        assert day_4["sha256"] == day_5["sha256"]
        assert day_4["content"] == day_5["content"]


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

    for experiment in ("day-04-vulnerable-baseline", DAY_5):
        fixtures_root = lab.experiment_root(experiment) / "fixtures"
        for relative_path, digest in expected.items():
            content = (fixtures_root / relative_path).read_bytes()
            assert hashlib.sha256(content).hexdigest() == digest


def test_fixture_path_escape_is_rejected() -> None:
    with pytest.raises((FileNotFoundError, ValueError)):
        lab.read_fixture("../../day-04-vulnerable-baseline/fixtures/target.md", DAY_5)


def test_experiment_path_escape_is_rejected() -> None:
    with pytest.raises(ValueError, match="invalid experiment id"):
        lab.experiment_root("../day-04-vulnerable-baseline")


def test_symlink_fixture_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = tmp_path / "test-bundle"
    fixtures = bundle / "fixtures"
    fixtures.mkdir(parents=True)
    (bundle / "experiment.json").write_text(
        json.dumps({"schema_version": 2, "id": "test-bundle"}), encoding="utf-8"
    )
    real_file = fixtures / "real.md"
    real_file.write_text("synthetic", encoding="utf-8")
    (fixtures / "link.md").symlink_to(real_file)
    monkeypatch.setattr(lab, "EXPERIMENTS_ROOT", tmp_path)

    with pytest.raises(ValueError, match="refusing symlink"):
        lab.read_fixture("link.md", "test-bundle")


def test_ollama_client_rejects_non_loopback_origins() -> None:
    with pytest.raises(ValueError, match="127.0.0.1"):
        OllamaClient(origin="https://example.com")
