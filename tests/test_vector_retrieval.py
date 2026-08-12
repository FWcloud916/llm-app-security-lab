from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any

import pytest

from llm_security_lab import lab, report
from llm_security_lab.vector_retrieval import (
    retrieve_vectors,
    validate_vector_retrieval_spec,
    vector_retrieval_fingerprint,
)

DAY_17 = "day-17-vector-embedding-security"
CHAT_DIGEST = "c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb"
EMBED_DIGEST = "85462619ee721b466c5927d109d4cb765861907d5417b9109caebc4e614679f1"
SAFE = "DAY17_SAFE_POLICY_30_DAYS"
SAME_TENANT = "DAY17_SAME_TENANT_ATTACK_180_DAYS"
CROSS_TENANT = "DAY17_CROSS_TENANT_POLICY_365_DAYS"


def _document(path: str, tenant_id: str, content: str) -> dict[str, str]:
    return {
        "path": path,
        "tenant_id": tenant_id,
        "content": content,
        "sha256": hashlib.sha256(content.encode()).hexdigest(),
    }


def _spec(*documents: dict[str, str], tenant_filter: str | None) -> dict[str, Any]:
    return {
        "documents": [
            {"path": document["path"], "tenant_id": document["tenant_id"]} for document in documents
        ],
        "chunking": "paragraph-v1",
        "strategy": "ollama-embedding-cosine-v1",
        "top_k": 1,
        "requested_tenant": "tenant-alpha",
        "tenant_filter": tenant_filter,
        "engines": ["exact-cosine-v1", "qdrant-local-v1"],
    }


def test_exact_cosine_and_qdrant_apply_the_same_tenant_filter() -> None:
    safe = _document("safe.md", "tenant-alpha", f"safe policy {SAFE}")
    cross = _document("cross.md", "tenant-beta", f"cross tenant policy {CROSS_TENANT}")
    spec = _spec(safe, cross, tenant_filter="tenant-alpha")
    response = {
        "model": "embeddinggemma:latest",
        "embeddings": [[1.0, 0.0], [0.8, 0.6], [0.999, 0.001]],
    }

    trace = retrieve_vectors(
        "refund window",
        [safe, cross],
        spec,
        response,
        "embeddinggemma:latest",
    )

    assert trace["eligible_chunk_ids"] == ["safe.md#p01"]
    assert [item["id"] for item in trace["exact_selected"]] == ["safe.md#p01"]
    assert [item["id"] for item in trace["qdrant_selected"]] == ["safe.md#p01"]
    assert trace["engines_agree"] is True
    assert trace["qdrant_selected"][0]["tenant_id"] == "tenant-alpha"


def test_vector_retrieval_fingerprint_rejects_tampered_vector() -> None:
    safe = _document("safe.md", "tenant-alpha", f"safe policy {SAFE}")
    trace = retrieve_vectors(
        "refund window",
        [safe],
        _spec(safe, tenant_filter="tenant-alpha"),
        {"model": "embeddinggemma:latest", "embeddings": [[1.0, 0.0], [0.8, 0.6]]},
        "embeddinggemma:latest",
    )
    trace["chunks"][0]["embedding"][0] = 0.1

    with pytest.raises(ValueError, match="embedding hash"):
        vector_retrieval_fingerprint(trace)


def test_vector_retrieval_fingerprint_rejects_rehashed_non_numeric_vector() -> None:
    safe = _document("safe.md", "tenant-alpha", f"safe policy {SAFE}")
    trace = retrieve_vectors(
        "refund window",
        [safe],
        _spec(safe, tenant_filter="tenant-alpha"),
        {"model": "embeddinggemma:latest", "embeddings": [[1.0, 0.0], [0.8, 0.6]]},
        "embeddinggemma:latest",
    )
    trace["chunks"][0]["embedding"] = ["not-a-number", 0.6]
    encoded = json.dumps(trace["chunks"][0]["embedding"], separators=(",", ":")).encode()
    trace["chunks"][0]["embedding_sha256"] = hashlib.sha256(encoded).hexdigest()

    with pytest.raises(ValueError, match="embedding hash"):
        vector_retrieval_fingerprint(trace)


@pytest.mark.parametrize(
    "change,match",
    [
        ({"engines": ["qdrant-local-v1", "exact-cosine-v1"]}, "engines"),
        ({"tenant_filter": ""}, "tenant_filter"),
        ({"top_k": 0}, "top_k"),
    ],
)
def test_vector_retrieval_spec_fails_closed(change: dict[str, Any], match: str) -> None:
    safe = _document("safe.md", "tenant-alpha", "safe")
    spec = _spec(safe, tenant_filter="tenant-alpha")
    spec.update(change)

    with pytest.raises(ValueError, match=match):
        validate_vector_retrieval_spec(spec)


class FakeVectorClient:
    origin = "http://127.0.0.1:11434"

    def __init__(self) -> None:
        self.chat_calls = 0
        self.embed_calls = 0

    def request_json(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if path == "/api/version":
            return {"version": "test"}
        if path == "/api/tags":
            return {
                "models": [
                    {"name": "gemma4:latest", "digest": CHAT_DIGEST},
                    {"name": "embeddinggemma:latest", "digest": EMBED_DIGEST},
                ]
            }
        if path == "/api/embed":
            self.embed_calls += 1
            assert payload is not None
            vectors = []
            for text in payload["input"]:
                if text == "What is the Enterprise Plus refund request window in days?":
                    vectors.append([1.0, 0.0, 0.0])
                elif SAME_TENANT in text:
                    vectors.append([0.999, 0.001, 0.0])
                elif CROSS_TENANT in text:
                    vectors.append([0.998, 0.002, 0.0])
                elif SAFE in text:
                    vectors.append([0.8, 0.6, 0.0])
                else:
                    raise AssertionError(f"unexpected embedding input: {text}")
            return {"model": "embeddinggemma:latest", "embeddings": vectors}
        if path == "/api/chat":
            self.chat_calls += 1
            assert payload is not None
            content = payload["messages"][1]["content"]
            marker = next(
                marker for marker in (SAFE, SAME_TENANT, CROSS_TENANT) if marker in content
            )
            return {"message": {"role": "assistant", "content": marker}}
        raise AssertionError(f"unexpected path: {path}")


def test_day_17_embedding_digest_mismatch_fails_before_inference() -> None:
    client = FakeVectorClient()
    original = client.request_json

    def changed_tags(path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        result = original(path, payload)
        if path == "/api/tags":
            result["models"][1]["digest"] = "changed"
        return result

    client.request_json = changed_tags  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="model digest changed"):
        lab.run_planned(DAY_17, client=client)
    assert client.embed_calls == 0
    assert client.chat_calls == 0


def test_day_17_plan_keeps_geometry_and_authorization_as_separate_gates() -> None:
    client = FakeVectorClient()
    batch = lab.run_planned(DAY_17, client=client)

    assert len(batch["runs"]) == 20
    assert client.embed_calls == 20
    assert client.chat_calls == 20
    assert batch["summary"]["embedding_model_digest"] == EMBED_DIGEST
    first_by_scenario = {run["scenario"]: run for run in batch["runs"][::5]}
    assert first_by_scenario["clean-filtered"]["observations"]["safe_policy_selected"] is True
    assert (
        first_by_scenario["same-tenant-ranking-attack"]["observations"][
            "same_tenant_attack_selected"
        ]
        is True
    )
    assert (
        first_by_scenario["cross-tenant-unfiltered"]["observations"]["cross_tenant_policy_selected"]
        is True
    )
    assert (
        first_by_scenario["cross-tenant-unfiltered"]["observations"][
            "selected_matches_requested_tenant"
        ]
        is False
    )
    filtered = first_by_scenario["cross-tenant-filtered"]
    assert filtered["observations"]["cross_tenant_policy_in_corpus"] is True
    assert filtered["observations"]["cross_tenant_policy_eligible_after_filter"] is False
    assert filtered["observations"]["cross_tenant_policy_selected"] is False
    assert filtered["observations"]["safe_policy_selected"] is True
    for run in batch["runs"]:
        assert run["safety_boundary"]["embedding_api_called"] is True
        assert run["safety_boundary"]["vector_store_used"] is True
        assert run["safety_boundary"]["retrieval_persistent"] is False
        assert run["safety_boundary"]["tools_sent"] is False
        assert run["observations"]["vector_engines_agree"] is True


def test_day_17_summary_rejects_tampered_embedding_evidence() -> None:
    batch = lab.run_planned(DAY_17, client=FakeVectorClient())
    changed = deepcopy(batch["runs"])
    changed[0]["vector_retrieval"]["chunks"][0]["embedding"][0] = 0.25

    with pytest.raises(ValueError, match="embedding hash"):
        lab.summarize_planned_runs(changed, batch["run_plan"])


def test_day_17_report_excludes_vectors_and_marker_values() -> None:
    batch = lab.run_planned(DAY_17, client=FakeVectorClient())
    rendered = report.render_report(batch)

    assert "Embedding model: embeddinggemma:latest" in rendered
    assert "Vector retrieval:" in rendered
    assert "exact cosine selected chunks:" in rendered
    assert "Qdrant selected chunks:" in rendered
    assert "exact cosine and Qdrant agree: 5/5" in rendered
    assert "[1.0, 0.0, 0.0]" not in rendered
    assert SAFE not in rendered
    assert SAME_TENANT not in rendered
    assert CROSS_TENANT not in rendered
