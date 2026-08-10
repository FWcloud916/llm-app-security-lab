from __future__ import annotations

import pytest

from llm_security_lab.retrieval import chunk_documents, retrieve, tokenize


def _document(path: str, content: str) -> dict[str, str]:
    return {"path": path, "sha256": f"hash-{path}", "content": content}


def test_tokenize_normalizes_case_width_and_duplicates() -> None:
    assert tokenize("ＲＡＧ rag Policy-42 policy") == ["rag", "policy", "42"]


def test_paragraph_chunks_keep_stable_provenance() -> None:
    chunks = chunk_documents([_document("a.md", "first\n\nsecond")])

    assert [chunk["id"] for chunk in chunks] == ["a.md#p01", "a.md#p02"]
    assert [chunk["paragraph_number"] for chunk in chunks] == [1, 2]
    assert all(chunk["source_sha256"] == "hash-a.md" for chunk in chunks)


def test_retrieval_scores_unique_overlap_and_breaks_ties_by_source_order() -> None:
    documents = [
        _document("first.md", "refund policy window"),
        _document("second.md", "refund policy"),
        _document("third.md", "refund policy"),
    ]
    trace = retrieve(
        "refund policy window",
        documents,
        {
            "documents": ["first.md", "second.md", "third.md"],
            "chunking": "paragraph-v1",
            "strategy": "ascii-token-overlap-v1",
            "top_k": 3,
        },
    )

    assert [(item["source_path"], item["score"]) for item in trace["selected"]] == [
        ("first.md", 3),
        ("second.md", 2),
        ("third.md", 2),
    ]
    assert trace["serialized_context"].count("<chunk ") == 3


def test_retrieval_rejects_top_k_beyond_chunk_count() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        retrieve(
            "refund",
            [_document("first.md", "refund")],
            {
                "documents": ["first.md"],
                "chunking": "paragraph-v1",
                "strategy": "ascii-token-overlap-v1",
                "top_k": 2,
            },
        )
