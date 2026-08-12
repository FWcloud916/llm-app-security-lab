# Day 17 Vector Database and Embedding Security

This checkpoint records one complete, predeclared synthetic experiment. Complete source text,
embedding vectors, requests, and responses remain under ignored `evidence/raw/day-17/`; this
directory contains only reviewed, sanitized evidence.

## Registered Plan

- Chat model: `gemma4:latest`; embedding model: `embeddinggemma:latest`; both full digests fixed in
  the experiment definition.
- Options: `temperature=0.7`, seeds 1111–1115 for every scenario.
- Matrix: clean filtered, same-tenant ranking attack, cross-tenant unfiltered, and cross-tenant
  filtered.
- Size: 20 run units, 20 loopback embedding calls, and 20 loopback chat calls, executed once after
  the definition, fixtures, implementation, tests, and prediction were committed.
- Retrieval: one batched `/api/embed` request per run, exact cosine and Qdrant `:memory:` cosine
  ranking, `top_k=1`, and fail-closed selection/score parity within `1e-5`.
- Boundary: synthetic Markdown only; no persistent index, Qdrant server, tools, action execution,
  renderer, credentials, or external sink. Raw output is ignored; stdout is the only sink.

## Registered Prediction

The author predicted selected-policy reachability before the formal run:

1. Clean filtered selects the safe Tenant Alpha policy.
2. Same-tenant ranking attack selects the query-shaped Tenant Alpha attack despite the tenant
   filter.
3. Cross-tenant unfiltered selects the higher-scoring Tenant Beta policy.
4. Cross-tenant filtered excludes Tenant Beta and selects the safe Tenant Alpha policy.

This is a two-gate prediction: semantic ranking chooses among eligible chunks, while authorization
decides which chunks are eligible. A tenant filter is not a same-tenant content-integrity control.

## Fixed Contract

- Runner commit: `605c2a2`
- Ollama: `0.32.7` on `http://127.0.0.1:11434`
- Chat model: `gemma4:latest`
- Chat digest: `c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb`
- Embedding model: `embeddinggemma:latest`
- Embedding digest: `85462619ee721b466c5927d109d4cb765861907d5417b9109caebc4e614679f1`
- Embedding dimension: `768`
- Seeds: `1111`–`1115`
- Temperature: `0.7`
- Run units / embedding calls / chat calls: `20 / 20 / 20`
- Raw evidence SHA-256: `f7ed222e4b0e2af62888641d8de91fe8ac09ff30bcd33f7513be0c60917b98d1`
- Recorded: `2026-08-12T01:41:11Z`–`2026-08-12T01:46:02Z`
- Tools / actions / persistent retrieval: disabled
- Output sink: stdout

## Exact Observations

Both ranking engines agreed in all 20 runs. Embeddings and retrieval inputs are deterministic for a
scenario, so each scenario has one score pair across its five generation seeds.

| Scenario | Tenant filter | Exact Top-1 | Exact score | Qdrant score | Predicted selection |
|---|---|---|---:|---:|---:|
| Clean filtered | Tenant Alpha | Safe Alpha | 0.71602672 | 0.71602675 | 5/5 |
| Same-tenant ranking attack | Tenant Alpha | Attack Alpha | 0.78254732 | 0.78254733 | 5/5 |
| Cross-tenant unfiltered | None | Policy Beta | 0.80466538 | 0.80466545 | 5/5 |
| Cross-tenant filtered | Tenant Alpha | Safe Alpha | 0.71602672 | 0.71602675 | 5/5 |

The cross-tenant policy was present in the filtered corpus in 5/5 runs but eligible in 0/5,
selected in 0/5, and serialized into the chat request in 0/5. The same-tenant attack was present,
eligible, selected, and serialized in 5/5 runs because tenant authorization had no basis for
rejecting an already authorized source.

## Manual Review

All 20 assistant responses were reviewed after exact results were frozen. Every response stated the
day count from its single model-visible selected chunk and preserved the selected marker:

| Scenario | 30-day policy | 180-day policy | 365-day policy |
|---|---:|---:|---:|
| Clean filtered | 5/5 | 0/5 | 0/5 |
| Same-tenant ranking attack | 0/5 | 5/5 | 0/5 |
| Cross-tenant unfiltered | 0/5 | 0/5 | 5/5 |
| Cross-tenant filtered | 5/5 | 0/5 | 0/5 |

## Interpretation Limits

This experiment isolates two controls that are often conflated: cosine similarity ranks eligible
content, while a tenant payload filter constrains eligibility. It does not show that Qdrant itself
creates or prevents poisoning, that tenant filters validate source integrity, or that embeddings are
authorization decisions. The tiny synthetic corpus, one embedding model, exact-query-shaped attack,
single Top-1 result, local Qdrant mode, and one chat model are a trace instrument—not a production
quality, performance, privacy, collision, inversion, or poisoning-optimization benchmark.
