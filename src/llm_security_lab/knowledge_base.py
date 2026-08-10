"""Deterministic knowledge-base lifecycle replay for the synthetic Day 16 experiment."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from copy import deepcopy
from typing import Any

from llm_security_lab.retrieval import CHUNKING_STRATEGY, RETRIEVAL_STRATEGY

DocumentLoader = Callable[[str], dict[str, str]]
EVENT_TYPES = {"publish", "rebuild", "revoke"}


def validate_knowledge_base_spec(raw_spec: object) -> dict[str, Any]:
    """Validate one bounded lifecycle replay and retrieval declaration."""
    if not isinstance(raw_spec, dict):
        raise ValueError("knowledge_base must be an object")
    if set(raw_spec) != {"events", "through_event", "retrieval"}:
        raise ValueError("knowledge_base requires only events, through_event, and retrieval")
    events = raw_spec.get("events")
    if not isinstance(events, str) or not events.strip():
        raise ValueError("knowledge_base events must be a non-empty fixture path")
    through_event = raw_spec.get("through_event")
    if (
        not isinstance(through_event, int)
        or isinstance(through_event, bool)
        or not 1 <= through_event <= 100
    ):
        raise ValueError("knowledge_base through_event must be an integer between 1 and 100")
    retrieval = raw_spec.get("retrieval")
    if not isinstance(retrieval, dict) or set(retrieval) != {"chunking", "strategy", "top_k"}:
        raise ValueError("knowledge_base retrieval requires chunking, strategy, and top_k")
    if retrieval.get("chunking") != CHUNKING_STRATEGY:
        raise ValueError(f"knowledge_base chunking must be {CHUNKING_STRATEGY}")
    if retrieval.get("strategy") != RETRIEVAL_STRATEGY:
        raise ValueError(f"knowledge_base strategy must be {RETRIEVAL_STRATEGY}")
    top_k = retrieval.get("top_k")
    if not isinstance(top_k, int) or isinstance(top_k, bool) or not 1 <= top_k <= 20:
        raise ValueError("knowledge_base top_k must be an integer between 1 and 20")
    return {
        "events": events,
        "through_event": through_event,
        "retrieval": {
            "chunking": CHUNKING_STRATEGY,
            "strategy": RETRIEVAL_STRATEGY,
            "top_k": top_k,
        },
    }


def _validate_event_log(event_fixture: dict[str, str]) -> list[dict[str, Any]]:
    try:
        raw_log = json.loads(event_fixture["content"])
    except (KeyError, json.JSONDecodeError) as error:
        raise ValueError("knowledge-base event log must contain valid JSON") from error
    if not isinstance(raw_log, dict) or raw_log.get("schema_version") != 1:
        raise ValueError("knowledge-base event log must use schema version 1")
    events = raw_log.get("events")
    if not isinstance(events, list) or not events or len(events) > 100:
        raise ValueError("knowledge-base event log must contain 1 to 100 events")

    validated: list[dict[str, Any]] = []
    published: set[tuple[str, int]] = set()
    revoked: set[tuple[str, int]] = set()
    for expected_id, event in enumerate(events, start=1):
        if not isinstance(event, dict) or event.get("id") != expected_id:
            raise ValueError("knowledge-base event ids must be consecutive from 1")
        event_type = event.get("type")
        if event_type not in EVENT_TYPES:
            raise ValueError("knowledge-base event type must be publish, revoke, or rebuild")
        if event_type == "rebuild":
            if set(event) != {"id", "type"}:
                raise ValueError("knowledge-base rebuild events may contain only id and type")
        else:
            source_id = event.get("source_id")
            version = event.get("version")
            actor = event.get("actor")
            if not isinstance(source_id, str) or not source_id.strip():
                raise ValueError("knowledge-base source_id must be a non-empty string")
            if not isinstance(version, int) or isinstance(version, bool) or version < 1:
                raise ValueError("knowledge-base version must be a positive integer")
            if not isinstance(actor, str) or not actor.strip():
                raise ValueError("knowledge-base actor must be a non-empty string")
            key = (source_id, version)
            if event_type == "publish":
                if set(event) != {
                    "id",
                    "type",
                    "source_id",
                    "version",
                    "document",
                    "actor",
                    "review_status",
                }:
                    raise ValueError("knowledge-base publish event fields are invalid")
                document = event.get("document")
                review_status = event.get("review_status")
                if not isinstance(document, str) or not document.strip():
                    raise ValueError("knowledge-base publish document must be a fixture path")
                if review_status not in {"approved", "unreviewed"}:
                    raise ValueError("knowledge-base review_status must be approved or unreviewed")
                if key in published:
                    raise ValueError("knowledge-base source versions must be unique")
                published.add(key)
            else:
                if set(event) != {"id", "type", "source_id", "version", "actor"}:
                    raise ValueError("knowledge-base revoke event fields are invalid")
                if key not in published:
                    raise ValueError("knowledge-base revoke must reference a published version")
                if key in revoked:
                    raise ValueError("knowledge-base source version may be revoked only once")
                revoked.add(key)
        validated.append(deepcopy(event))
    return validated


def _corpus_sha256(entries: list[dict[str, Any]]) -> str:
    canonical = [
        {
            "source_id": entry["source_id"],
            "version": entry["version"],
            "path": entry["document"]["path"],
            "sha256": entry["document"]["sha256"],
        }
        for entry in entries
    ]
    return hashlib.sha256(
        json.dumps(canonical, ensure_ascii=False, sort_keys=True).encode()
    ).hexdigest()


def replay_knowledge_base(
    event_fixture: dict[str, str],
    through_event: int,
    load_document: DocumentLoader,
) -> dict[str, Any]:
    """Replay source changes through one event and return source and derived-corpus state."""
    events = _validate_event_log(event_fixture)
    if through_event > len(events):
        raise ValueError("knowledge_base through_event does not exist in the event log")

    versions: dict[tuple[str, int], dict[str, Any]] = {}
    corpus_entries: list[dict[str, Any]] | None = None
    last_rebuild_event: int | None = None
    latest_source_change = 0
    applied_events = events[:through_event]
    for event in applied_events:
        event_type = event["type"]
        if event_type == "publish":
            key = (event["source_id"], event["version"])
            versions[key] = {
                "source_id": event["source_id"],
                "version": event["version"],
                "actor": event["actor"],
                "review_status": event["review_status"],
                "published_at_event": event["id"],
                "revoked_at_event": None,
                "document": load_document(event["document"]),
            }
            latest_source_change = event["id"]
        elif event_type == "revoke":
            versions[(event["source_id"], event["version"])]["revoked_at_event"] = event["id"]
            latest_source_change = event["id"]
        else:
            active_by_source: dict[str, dict[str, Any]] = {}
            for entry in versions.values():
                if entry["revoked_at_event"] is not None:
                    continue
                current = active_by_source.get(entry["source_id"])
                if current is None or entry["version"] > current["version"]:
                    active_by_source[entry["source_id"]] = entry
            corpus_entries = [deepcopy(active_by_source[key]) for key in sorted(active_by_source)]
            last_rebuild_event = event["id"]

    if corpus_entries is None or last_rebuild_event is None:
        raise ValueError("knowledge-base lifecycle must include a rebuild before inference")
    active_by_source = {}
    for entry in versions.values():
        if entry["revoked_at_event"] is not None:
            continue
        current = active_by_source.get(entry["source_id"])
        if current is None or entry["version"] > current["version"]:
            active_by_source[entry["source_id"]] = entry
    active_entries = [deepcopy(active_by_source[key]) for key in sorted(active_by_source)]
    source_documents = [deepcopy(entry["document"]) for entry in versions.values()]
    corpus_documents = [deepcopy(entry["document"]) for entry in corpus_entries]
    return {
        "event_log": deepcopy(event_fixture),
        "through_event": through_event,
        "applied_events": deepcopy(applied_events),
        "source_versions": list(versions.values()),
        "active_sources": active_entries,
        "source_documents": source_documents,
        "corpus": {
            "built_at_event": last_rebuild_event,
            "stale": latest_source_change > last_rebuild_event,
            "sha256": _corpus_sha256(corpus_entries),
            "entries": corpus_entries,
            "documents": corpus_documents,
        },
    }


def knowledge_base_fingerprint(trace: dict[str, Any]) -> dict[str, Any]:
    """Validate lifecycle evidence and return fields safe for fixed-input comparison."""
    event_log = trace.get("event_log")
    if not isinstance(event_log, dict) or not isinstance(event_log.get("content"), str):
        raise ValueError("knowledge-base evidence is missing its event log")
    if hashlib.sha256(event_log["content"].encode()).hexdigest() != event_log.get("sha256"):
        raise ValueError("knowledge-base event-log hash does not match its content")
    through_event = trace.get("through_event")
    applied_events = trace.get("applied_events")
    if (
        not isinstance(through_event, int)
        or not isinstance(applied_events, list)
        or len(applied_events) != through_event
    ):
        raise ValueError("knowledge-base applied event evidence is incomplete")
    source_documents = trace.get("source_documents")
    if not isinstance(source_documents, list) or not source_documents:
        raise ValueError("knowledge-base evidence is missing source documents")
    documents_by_path: dict[str, dict[str, str]] = {}
    for document in source_documents:
        if (
            not isinstance(document, dict)
            or not isinstance(document.get("path"), str)
            or not isinstance(document.get("content"), str)
            or hashlib.sha256(document["content"].encode()).hexdigest() != document.get("sha256")
            or document["path"] in documents_by_path
        ):
            raise ValueError("knowledge-base source document evidence is invalid")
        documents_by_path[document["path"]] = document
    corpus = trace.get("corpus")
    active_sources = trace.get("active_sources")
    if not isinstance(corpus, dict) or not isinstance(active_sources, list):
        raise ValueError("knowledge-base source or corpus evidence is incomplete")
    entries = corpus.get("entries")
    if not isinstance(entries, list) or _corpus_sha256(entries) != corpus.get("sha256"):
        raise ValueError("knowledge-base corpus hash does not match its entries")
    latest_source_change = max(
        (event["id"] for event in applied_events if event["type"] in {"publish", "revoke"}),
        default=0,
    )
    expected_stale = latest_source_change > corpus.get("built_at_event", 0)
    if corpus.get("stale") is not expected_stale:
        raise ValueError("knowledge-base stale flag does not match lifecycle events")
    expected_trace = replay_knowledge_base(
        event_log, through_event, lambda path: documents_by_path[path]
    )
    if trace != expected_trace:
        raise ValueError("knowledge-base evidence does not match deterministic event replay")
    return {
        "event_log": {"path": event_log.get("path"), "sha256": event_log.get("sha256")},
        "through_event": through_event,
        "applied_event_ids": [event.get("id") for event in applied_events],
        "active_sources": [
            {
                "source_id": entry.get("source_id"),
                "version": entry.get("version"),
                "document_sha256": entry.get("document", {}).get("sha256"),
            }
            for entry in active_sources
        ],
        "corpus": {
            "built_at_event": corpus.get("built_at_event"),
            "stale": corpus.get("stale"),
            "sha256": corpus.get("sha256"),
            "entries": [
                {
                    "source_id": entry.get("source_id"),
                    "version": entry.get("version"),
                    "document_sha256": entry.get("document", {}).get("sha256"),
                }
                for entry in entries
            ],
        },
    }
