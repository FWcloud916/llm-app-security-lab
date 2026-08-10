from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest

from llm_security_lab.knowledge_base import (
    knowledge_base_fingerprint,
    replay_knowledge_base,
    validate_knowledge_base_spec,
)


def _document(path: str, content: str) -> dict[str, str]:
    return {
        "path": path,
        "sha256": hashlib.sha256(content.encode()).hexdigest(),
        "content": content,
    }


def _event_fixture(events: list[dict[str, object]]) -> dict[str, str]:
    content = json.dumps({"schema_version": 1, "events": events}, ensure_ascii=False)
    return {
        "path": "knowledge-base/events.json",
        "sha256": hashlib.sha256(content.encode()).hexdigest(),
        "content": content,
    }


EVENTS = [
    {
        "id": 1,
        "type": "publish",
        "source_id": "policy",
        "version": 1,
        "document": "v1.md",
        "actor": "owner",
        "review_status": "approved",
    },
    {"id": 2, "type": "rebuild"},
    {
        "id": 3,
        "type": "publish",
        "source_id": "policy",
        "version": 2,
        "document": "v2.md",
        "actor": "editor",
        "review_status": "unreviewed",
    },
    {"id": 4, "type": "rebuild"},
    {"id": 5, "type": "revoke", "source_id": "policy", "version": 2, "actor": "reviewer"},
    {"id": 6, "type": "rebuild"},
]


def test_validate_knowledge_base_spec_keeps_retrieval_bounded() -> None:
    spec = validate_knowledge_base_spec(
        {
            "events": "knowledge-base/events.json",
            "through_event": 5,
            "retrieval": {
                "chunking": "paragraph-v1",
                "strategy": "ascii-token-overlap-v1",
                "top_k": 1,
            },
        }
    )

    assert spec["through_event"] == 5
    assert spec["retrieval"]["top_k"] == 1


def test_replay_preserves_stale_corpus_until_rebuild() -> None:
    documents = {"v1.md": _document("v1.md", "safe"), "v2.md": _document("v2.md", "poison")}
    fixture = _event_fixture(EVENTS)

    clean = replay_knowledge_base(fixture, 2, documents.__getitem__)
    poisoned = replay_knowledge_base(fixture, 4, documents.__getitem__)
    stale = replay_knowledge_base(fixture, 5, documents.__getitem__)
    rebuilt = replay_knowledge_base(fixture, 6, documents.__getitem__)

    assert clean["active_sources"][0]["version"] == 1
    assert poisoned["active_sources"][0]["version"] == 2
    assert stale["active_sources"][0]["version"] == 1
    assert stale["corpus"]["entries"][0]["version"] == 2
    assert stale["corpus"]["stale"] is True
    assert rebuilt["active_sources"][0]["version"] == 1
    assert rebuilt["corpus"]["entries"][0]["version"] == 1
    assert rebuilt["corpus"]["stale"] is False


def test_replay_rejects_missing_rebuild_and_unknown_event() -> None:
    documents = {"v1.md": _document("v1.md", "safe")}
    with pytest.raises(ValueError, match="include a rebuild"):
        replay_knowledge_base(_event_fixture(EVENTS[:1]), 1, documents.__getitem__)

    changed = deepcopy(EVENTS)
    changed[0]["type"] = "overwrite"
    with pytest.raises(ValueError, match="event type"):
        replay_knowledge_base(_event_fixture(changed), 1, documents.__getitem__)


def test_knowledge_base_fingerprint_rejects_tampered_corpus() -> None:
    documents = {"v1.md": _document("v1.md", "safe"), "v2.md": _document("v2.md", "poison")}
    trace = replay_knowledge_base(_event_fixture(EVENTS), 5, documents.__getitem__)
    assert knowledge_base_fingerprint(trace)["corpus"]["stale"] is True

    trace["corpus"]["entries"][0]["version"] = 99
    with pytest.raises(ValueError, match="corpus hash"):
        knowledge_base_fingerprint(trace)
