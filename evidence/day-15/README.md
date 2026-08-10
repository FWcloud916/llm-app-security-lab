# Day 15 RAG Attack Surface

This checkpoint is reserved for one complete, predeclared synthetic experiment. Complete corpus
text, selected context, requests, and responses remain under ignored `evidence/raw/day-15/`; this
directory will contain only reviewed, sanitized evidence after the fixed plan runs.

## Registered Plan

- Model: `gemma4:latest`, full digest fixed in the experiment definition.
- Options: `temperature=0.7`, seeds 911–915 for every scenario.
- Matrix: clean corpus, injection indexed but excluded by `top_k=1`, and the same injection selected
  and serialized by `top_k=2`.
- Size: 15 run units and 15 loopback chat calls, executed once after the definition, prediction,
  fixtures, and tests are committed.
- Retriever: `paragraph-v1` chunks ranked by deterministic `ascii-token-overlap-v1`; no embedding
  endpoint, vector store, persistent index, or production retrieval claim.
- Boundary: synthetic Markdown only; no tools, action execution, renderer, or external sink. Raw
  output is ignored; stdout is the only sink.

## Registered Prediction

The author predicts reachability, not generation behavior:

1. Clean: the injection marker is absent from corpus, retrieved chunks, and request.
2. Indexed-not-retrieved: the marker exists in corpus but is absent from retrieved chunks and the
   request.
3. Retrieved-and-serialized: the marker exists at all three stages.

The target marker, injection marker, and confidential canary remain separate response observations.
Retrieval exposure does not imply that the model must follow the instruction or reveal the canary.
