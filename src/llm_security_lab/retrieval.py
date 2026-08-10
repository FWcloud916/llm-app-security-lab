"""Deterministic in-memory retrieval for the synthetic Day 15 RAG experiment."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Any

TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
CHUNKING_STRATEGY = "paragraph-v1"
RETRIEVAL_STRATEGY = "ascii-token-overlap-v1"


def validate_retrieval_spec(raw_spec: object) -> dict[str, Any]:
    """Validate one bounded, dependency-free retrieval declaration."""
    if not isinstance(raw_spec, dict):
        raise ValueError("retrieval must be an object")
    documents = raw_spec.get("documents")
    if (
        not isinstance(documents, list)
        or not 1 <= len(documents) <= 20
        or not all(isinstance(path, str) and path.strip() for path in documents)
    ):
        raise ValueError("retrieval documents must contain 1 to 20 fixture paths")
    if len(set(documents)) != len(documents):
        raise ValueError("retrieval documents must not contain duplicates")
    if raw_spec.get("chunking") != CHUNKING_STRATEGY:
        raise ValueError(f"retrieval chunking must be {CHUNKING_STRATEGY}")
    if raw_spec.get("strategy") != RETRIEVAL_STRATEGY:
        raise ValueError(f"retrieval strategy must be {RETRIEVAL_STRATEGY}")
    top_k = raw_spec.get("top_k")
    if not isinstance(top_k, int) or isinstance(top_k, bool) or not 1 <= top_k <= 20:
        raise ValueError("retrieval top_k must be an integer between 1 and 20")
    return {
        "documents": list(documents),
        "chunking": CHUNKING_STRATEGY,
        "strategy": RETRIEVAL_STRATEGY,
        "top_k": top_k,
    }


def tokenize(text: str) -> list[str]:
    """Return stable unique ASCII tokens in first-seen order."""
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return list(dict.fromkeys(TOKEN_PATTERN.findall(normalized)))


def chunk_documents(documents: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Split fixture documents on blank lines and retain source provenance."""
    chunks: list[dict[str, Any]] = []
    for document_order, document in enumerate(documents):
        paragraphs = [part.strip() for part in re.split(r"\n\s*\n", document["content"])]
        paragraphs = [part for part in paragraphs if part]
        if not paragraphs:
            raise ValueError(f"retrieval document is empty: {document['path']}")
        if len(paragraphs) > 100:
            raise ValueError(f"retrieval document has too many paragraphs: {document['path']}")
        for paragraph_number, content in enumerate(paragraphs, start=1):
            chunks.append(
                {
                    "id": f"{document['path']}#p{paragraph_number:02d}",
                    "source_path": document["path"],
                    "source_sha256": document["sha256"],
                    "document_order": document_order,
                    "paragraph_number": paragraph_number,
                    "sha256": hashlib.sha256(content.encode()).hexdigest(),
                    "content": content,
                    "tokens": tokenize(content),
                }
            )
    return chunks


def serialize_selected(selected: list[dict[str, Any]]) -> str:
    """Serialize selected chunks into the exact model-visible context block."""
    blocks = [
        f'<chunk rank="{item["rank"]}" id="{item["id"]}" score="{item["score"]}">\n'
        f"{item['content']}\n</chunk>"
        for item in selected
    ]
    return "<retrieved_context>\n" + "\n".join(blocks) + "\n</retrieved_context>"


def retrieve(
    query: str,
    documents: list[dict[str, str]],
    raw_spec: object,
) -> dict[str, Any]:
    """Rank every paragraph by unique token overlap and serialize the selected context."""
    spec = validate_retrieval_spec(raw_spec)
    query_tokens = tokenize(query)
    if not query_tokens:
        raise ValueError("retrieval query needs at least one ASCII alphanumeric token")
    chunks = chunk_documents(documents)
    if spec["top_k"] > len(chunks):
        raise ValueError("retrieval top_k exceeds the available chunk count")

    query_token_set = set(query_tokens)
    ranked = []
    for chunk in chunks:
        score = len(query_token_set.intersection(chunk["tokens"]))
        ranked.append({**chunk, "score": score})
    ranked.sort(key=lambda item: (-item["score"], item["document_order"], item["paragraph_number"]))

    selected = []
    for rank, chunk in enumerate(ranked[: spec["top_k"]], start=1):
        selected.append(
            {
                "rank": rank,
                "id": chunk["id"],
                "source_path": chunk["source_path"],
                "sha256": chunk["sha256"],
                "score": chunk["score"],
                "content": chunk["content"],
            }
        )
    serialized_context = serialize_selected(selected)
    return {
        "query_tokens": query_tokens,
        "chunking": spec["chunking"],
        "strategy": spec["strategy"],
        "top_k": spec["top_k"],
        "chunks": ranked,
        "selected": selected,
        "serialized_context": serialized_context,
        "serialized_sha256": hashlib.sha256(serialized_context.encode()).hexdigest(),
    }


def retrieval_fingerprint(trace: dict[str, Any]) -> dict[str, Any]:
    """Validate a retrieval trace and return the fields safe for fixed-input comparison."""
    serialized_context = trace.get("serialized_context")
    serialized_sha256 = trace.get("serialized_sha256")
    if (
        not isinstance(serialized_context, str)
        or hashlib.sha256(serialized_context.encode()).hexdigest() != serialized_sha256
    ):
        raise ValueError("retrieval serialized context hash does not match its text")
    selected = trace.get("selected")
    chunks = trace.get("chunks")
    if not isinstance(selected, list) or not isinstance(chunks, list):
        raise ValueError("retrieval evidence is incomplete")
    for chunk in chunks:
        if (
            not isinstance(chunk, dict)
            or not isinstance(chunk.get("content"), str)
            or hashlib.sha256(chunk["content"].encode()).hexdigest() != chunk.get("sha256")
            or tokenize(chunk["content"]) != chunk.get("tokens")
            or not isinstance(chunk.get("score"), int)
        ):
            raise ValueError("retrieval ranked chunk evidence is invalid")
    by_id = {chunk.get("id"): chunk for chunk in chunks if isinstance(chunk, dict)}
    for expected_rank, item in enumerate(selected, start=1):
        source = by_id.get(item.get("id")) if isinstance(item, dict) else None
        if (
            source is None
            or any(
                item.get(key) != source.get(key)
                for key in ("source_path", "sha256", "score", "content")
            )
            or item.get("rank") != expected_rank
        ):
            raise ValueError("retrieval selected chunk does not match ranked evidence")
        if hashlib.sha256(item["content"].encode()).hexdigest() != item["sha256"]:
            raise ValueError("retrieval selected chunk hash does not match its text")
    if serialize_selected(selected) != serialized_context:
        raise ValueError("retrieval serialized context does not match selected chunks")
    return {
        "query_tokens": trace.get("query_tokens"),
        "chunking": trace.get("chunking"),
        "strategy": trace.get("strategy"),
        "top_k": trace.get("top_k"),
        "chunks": [
            {
                "id": chunk.get("id"),
                "source_path": chunk.get("source_path"),
                "source_sha256": chunk.get("source_sha256"),
                "sha256": chunk.get("sha256"),
                "score": chunk.get("score"),
            }
            for chunk in chunks
        ],
        "selected": [
            {
                "rank": item.get("rank"),
                "id": item.get("id"),
                "source_path": item.get("source_path"),
                "sha256": item.get("sha256"),
                "score": item.get("score"),
            }
            for item in selected
        ],
        "serialized_sha256": serialized_sha256,
    }
