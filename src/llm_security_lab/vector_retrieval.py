"""Embedding-backed retrieval with exact cosine and local Qdrant parity."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from qdrant_client import QdrantClient, models

from llm_security_lab.retrieval import CHUNKING_STRATEGY, chunk_documents

VECTOR_RETRIEVAL_STRATEGY = "ollama-embedding-cosine-v1"
VECTOR_ENGINES = ["exact-cosine-v1", "qdrant-local-v1"]
SCORE_TOLERANCE = 1e-5


def validate_vector_retrieval_spec(raw_spec: object) -> dict[str, Any]:
    """Validate one bounded vector-retrieval declaration."""
    if not isinstance(raw_spec, dict):
        raise ValueError("vector_retrieval must be an object")
    expected_keys = {
        "documents",
        "chunking",
        "strategy",
        "top_k",
        "requested_tenant",
        "tenant_filter",
        "engines",
    }
    if set(raw_spec) != expected_keys:
        raise ValueError("vector_retrieval fields do not match the supported schema")

    raw_documents = raw_spec.get("documents")
    if not isinstance(raw_documents, list) or not 1 <= len(raw_documents) <= 20:
        raise ValueError("vector_retrieval documents must contain 1 to 20 entries")
    documents: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for raw_document in raw_documents:
        if not isinstance(raw_document, dict) or set(raw_document) != {"path", "tenant_id"}:
            raise ValueError("vector_retrieval documents require only path and tenant_id")
        path = raw_document.get("path")
        tenant_id = raw_document.get("tenant_id")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("vector_retrieval document path must be a non-empty string")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("vector_retrieval tenant_id must be a non-empty string")
        if path in seen_paths:
            raise ValueError("vector_retrieval document paths must be unique")
        seen_paths.add(path)
        documents.append({"path": path, "tenant_id": tenant_id})

    if raw_spec.get("chunking") != CHUNKING_STRATEGY:
        raise ValueError(f"vector_retrieval chunking must be {CHUNKING_STRATEGY}")
    if raw_spec.get("strategy") != VECTOR_RETRIEVAL_STRATEGY:
        raise ValueError(f"vector_retrieval strategy must be {VECTOR_RETRIEVAL_STRATEGY}")
    top_k = raw_spec.get("top_k")
    if not isinstance(top_k, int) or isinstance(top_k, bool) or not 1 <= top_k <= 20:
        raise ValueError("vector_retrieval top_k must be an integer between 1 and 20")
    requested_tenant = raw_spec.get("requested_tenant")
    if not isinstance(requested_tenant, str) or not requested_tenant.strip():
        raise ValueError("vector_retrieval requested_tenant must be a non-empty string")
    tenant_filter = raw_spec.get("tenant_filter")
    if tenant_filter is not None and (
        not isinstance(tenant_filter, str) or not tenant_filter.strip()
    ):
        raise ValueError("vector_retrieval tenant_filter must be null or a non-empty string")
    if raw_spec.get("engines") != VECTOR_ENGINES:
        raise ValueError("vector_retrieval engines must contain exact cosine then Qdrant local")
    return {
        "documents": documents,
        "chunking": CHUNKING_STRATEGY,
        "strategy": VECTOR_RETRIEVAL_STRATEGY,
        "top_k": top_k,
        "requested_tenant": requested_tenant,
        "tenant_filter": tenant_filter,
        "engines": list(VECTOR_ENGINES),
    }


def embedding_inputs(query: str, documents: list[dict[str, str]]) -> list[str]:
    """Return query followed by paragraph chunks in stable corpus order."""
    if not isinstance(query, str) or not query.strip():
        raise ValueError("vector retrieval query must be a non-empty string")
    return [query, *(chunk["content"] for chunk in _chunks_with_tenants(documents))]


def _chunks_with_tenants(documents: list[dict[str, str]]) -> list[dict[str, Any]]:
    chunks = chunk_documents(documents)
    tenant_by_path = {document["path"]: document["tenant_id"] for document in documents}
    return [{**chunk, "tenant_id": tenant_by_path[chunk["source_path"]]} for chunk in chunks]


def _validate_embeddings(
    response: object,
    *,
    expected_model: str,
    expected_count: int,
) -> list[list[float]]:
    if not isinstance(response, dict) or response.get("model") != expected_model:
        raise ValueError("embedding response model does not match the requested model")
    raw_embeddings = response.get("embeddings")
    if not isinstance(raw_embeddings, list) or len(raw_embeddings) != expected_count:
        raise ValueError("embedding response count does not match the submitted inputs")
    embeddings: list[list[float]] = []
    dimension: int | None = None
    for raw_vector in raw_embeddings:
        if not isinstance(raw_vector, list) or not raw_vector:
            raise ValueError("every embedding must be a non-empty vector")
        vector: list[float] = []
        for raw_value in raw_vector:
            if (
                not isinstance(raw_value, int | float)
                or isinstance(raw_value, bool)
                or not math.isfinite(raw_value)
            ):
                raise ValueError("embedding values must be finite numbers")
            vector.append(float(raw_value))
        if dimension is None:
            dimension = len(vector)
        elif len(vector) != dimension:
            raise ValueError("embedding vectors must all use the same dimension")
        embeddings.append(vector)
    if dimension is None or not 1 <= dimension <= 8192:
        raise ValueError("embedding dimension is outside the supported range")
    return embeddings


def _cosine(left: list[float], right: list[float]) -> float:
    numerator = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0 or right_norm == 0:
        raise ValueError("zero-length embedding cannot be ranked with cosine similarity")
    return numerator / (left_norm * right_norm)


def _selected_entry(chunk: dict[str, Any], score: float, rank: int) -> dict[str, Any]:
    return {
        "rank": rank,
        "id": chunk["id"],
        "source_path": chunk["source_path"],
        "tenant_id": chunk["tenant_id"],
        "sha256": chunk["sha256"],
        "score": float(score),
        "content": chunk["content"],
    }


def _serialize_selected(selected: list[dict[str, Any]]) -> str:
    blocks = [
        f'<chunk rank="{item["rank"]}" id="{item["id"]}" '
        f'tenant_id="{item["tenant_id"]}" score="{item["score"]:.8f}">\n'
        f"{item['content']}\n</chunk>"
        for item in selected
    ]
    return "<retrieved_context>\n" + "\n".join(blocks) + "\n</retrieved_context>"


def _vector_sha256(vector: list[float]) -> str:
    encoded = json.dumps(vector, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _validate_stored_vector(raw_vector: object, *, dimension: int | None = None) -> list[float]:
    if not isinstance(raw_vector, list) or not raw_vector:
        raise ValueError("stored embedding must be a non-empty vector")
    vector: list[float] = []
    for raw_value in raw_vector:
        if (
            not isinstance(raw_value, int | float)
            or isinstance(raw_value, bool)
            or not math.isfinite(raw_value)
        ):
            raise ValueError("stored embedding values must be finite numbers")
        vector.append(float(raw_value))
    if dimension is not None and len(vector) != dimension:
        raise ValueError("stored embedding dimension changed")
    return vector


def retrieve_vectors(
    query: str,
    documents: list[dict[str, str]],
    raw_spec: object,
    embedding_response: object,
    embedding_model: str,
) -> dict[str, Any]:
    """Rank the same vectors with exact cosine and local Qdrant, then require parity."""
    spec = validate_vector_retrieval_spec(raw_spec)
    chunks = _chunks_with_tenants(documents)
    inputs = [query, *(chunk["content"] for chunk in chunks)]
    embeddings = _validate_embeddings(
        embedding_response,
        expected_model=embedding_model,
        expected_count=len(inputs),
    )
    query_vector = embeddings[0]
    for chunk, vector in zip(chunks, embeddings[1:], strict=True):
        chunk["embedding"] = vector
        chunk["embedding_sha256"] = _vector_sha256(vector)

    eligible = [
        chunk
        for chunk in chunks
        if spec["tenant_filter"] is None or chunk["tenant_id"] == spec["tenant_filter"]
    ]
    if spec["top_k"] > len(eligible):
        raise ValueError("vector_retrieval top_k exceeds the eligible chunk count")

    exact_ranked = [
        {**chunk, "score": _cosine(query_vector, chunk["embedding"])} for chunk in eligible
    ]
    exact_ranked.sort(
        key=lambda item: (-item["score"], item["document_order"], item["paragraph_number"])
    )
    exact_selected = [
        _selected_entry(chunk, chunk["score"], rank)
        for rank, chunk in enumerate(exact_ranked[: spec["top_k"]], start=1)
    ]

    client = QdrantClient(":memory:")
    client.create_collection(
        collection_name="day17",
        vectors_config=models.VectorParams(size=len(query_vector), distance=models.Distance.COSINE),
    )
    client.upsert(
        collection_name="day17",
        wait=True,
        points=[
            models.PointStruct(
                id=index,
                vector=chunk["embedding"],
                payload={"chunk_id": chunk["id"], "tenant_id": chunk["tenant_id"]},
            )
            for index, chunk in enumerate(chunks, start=1)
        ],
    )
    query_filter = None
    if spec["tenant_filter"] is not None:
        query_filter = models.Filter(
            must=[
                models.FieldCondition(
                    key="tenant_id",
                    match=models.MatchValue(value=spec["tenant_filter"]),
                )
            ]
        )
    qdrant_points = client.query_points(
        collection_name="day17",
        query=query_vector,
        query_filter=query_filter,
        limit=spec["top_k"],
    ).points
    chunks_by_id = {chunk["id"]: chunk for chunk in chunks}
    qdrant_selected = []
    for rank, point in enumerate(qdrant_points, start=1):
        payload = point.payload or {}
        chunk = chunks_by_id.get(payload.get("chunk_id"))
        if chunk is None:
            raise ValueError("Qdrant returned an unknown chunk id")
        qdrant_selected.append(_selected_entry(chunk, point.score, rank))

    exact_ids = [item["id"] for item in exact_selected]
    qdrant_ids = [item["id"] for item in qdrant_selected]
    if exact_ids != qdrant_ids:
        raise ValueError("exact cosine and Qdrant selected different chunks")
    for exact_item, qdrant_item in zip(exact_selected, qdrant_selected, strict=True):
        if abs(exact_item["score"] - qdrant_item["score"]) > SCORE_TOLERANCE:
            raise ValueError("exact cosine and Qdrant scores exceeded tolerance")

    serialized_context = _serialize_selected(qdrant_selected)
    return {
        "embedding": {
            "model": embedding_model,
            "dimension": len(query_vector),
            "input_count": len(inputs),
            "input_sha256": [hashlib.sha256(item.encode()).hexdigest() for item in inputs],
            "query_vector": query_vector,
            "query_vector_sha256": _vector_sha256(query_vector),
        },
        "chunking": spec["chunking"],
        "strategy": spec["strategy"],
        "engines": spec["engines"],
        "top_k": spec["top_k"],
        "requested_tenant": spec["requested_tenant"],
        "tenant_filter": spec["tenant_filter"],
        "chunks": chunks,
        "eligible_chunk_ids": [chunk["id"] for chunk in eligible],
        "exact_selected": exact_selected,
        "qdrant_selected": qdrant_selected,
        "engines_agree": True,
        "score_tolerance": SCORE_TOLERANCE,
        "serialized_context": serialized_context,
        "serialized_sha256": hashlib.sha256(serialized_context.encode()).hexdigest(),
    }


def vector_retrieval_fingerprint(trace: dict[str, Any]) -> dict[str, Any]:
    """Validate raw vector evidence and return a text/vector-safe stable fingerprint."""
    embedding = trace.get("embedding")
    chunks = trace.get("chunks")
    if not isinstance(embedding, dict) or not isinstance(chunks, list):
        raise ValueError("vector retrieval evidence is incomplete")
    dimension = embedding.get("dimension")
    if not isinstance(dimension, int) or isinstance(dimension, bool) or not 1 <= dimension <= 8192:
        raise ValueError("vector retrieval embedding dimension is invalid")
    try:
        query_vector = _validate_stored_vector(embedding.get("query_vector"), dimension=dimension)
    except ValueError as error:
        raise ValueError("query embedding evidence is invalid") from error
    if _vector_sha256(query_vector) != embedding.get("query_vector_sha256"):
        raise ValueError("query embedding hash does not match its vector")
    for chunk in chunks:
        if not isinstance(chunk, dict) or not isinstance(chunk.get("content"), str):
            raise ValueError("vector retrieval chunk embedding hash or text evidence is invalid")
        try:
            chunk_vector = _validate_stored_vector(chunk.get("embedding"), dimension=dimension)
        except ValueError as error:
            raise ValueError(
                "vector retrieval chunk embedding hash or text evidence is invalid"
            ) from error
        if hashlib.sha256(chunk["content"].encode()).hexdigest() != chunk.get(
            "sha256"
        ) or _vector_sha256(chunk_vector) != chunk.get("embedding_sha256"):
            raise ValueError("vector retrieval chunk embedding hash or text evidence is invalid")
    exact_selected = trace.get("exact_selected")
    qdrant_selected = trace.get("qdrant_selected")
    if not isinstance(exact_selected, list) or not isinstance(qdrant_selected, list):
        raise ValueError("vector retrieval selections are incomplete")
    if [item.get("id") for item in exact_selected] != [item.get("id") for item in qdrant_selected]:
        raise ValueError("vector retrieval engines no longer agree")
    if trace.get("engines_agree") is not True:
        raise ValueError("vector retrieval parity flag is false")
    serialized_context = trace.get("serialized_context")
    if (
        not isinstance(serialized_context, str)
        or hashlib.sha256(serialized_context.encode()).hexdigest() != trace.get("serialized_sha256")
        or _serialize_selected(qdrant_selected) != serialized_context
    ):
        raise ValueError("vector retrieval serialized context is invalid")
    return {
        "embedding": {
            "model": embedding.get("model"),
            "dimension": embedding.get("dimension"),
            "input_count": embedding.get("input_count"),
            "input_sha256": embedding.get("input_sha256"),
            "query_vector_sha256": embedding.get("query_vector_sha256"),
        },
        "chunking": trace.get("chunking"),
        "strategy": trace.get("strategy"),
        "engines": trace.get("engines"),
        "top_k": trace.get("top_k"),
        "requested_tenant": trace.get("requested_tenant"),
        "tenant_filter": trace.get("tenant_filter"),
        "chunks": [
            {
                "id": chunk.get("id"),
                "source_path": chunk.get("source_path"),
                "source_sha256": chunk.get("source_sha256"),
                "tenant_id": chunk.get("tenant_id"),
                "sha256": chunk.get("sha256"),
                "embedding_sha256": chunk.get("embedding_sha256"),
            }
            for chunk in chunks
        ],
        "eligible_chunk_ids": trace.get("eligible_chunk_ids"),
        "exact_selected": [
            {key: item.get(key) for key in ("rank", "id", "tenant_id", "sha256", "score")}
            for item in exact_selected
        ],
        "qdrant_selected": [
            {key: item.get(key) for key in ("rank", "id", "tenant_id", "sha256", "score")}
            for item in qdrant_selected
        ],
        "engines_agree": True,
        "score_tolerance": trace.get("score_tolerance"),
        "serialized_sha256": trace.get("serialized_sha256"),
    }
