# LLM Application Security Lab — Agent Guide

This project owns versioned, synthetic-data experiments for the 30-day LLM application-security series.

## Hard constraints

- MUST use only synthetic fixtures and MUST NOT commit real notes, credentials, personal data, or production exports (source: `SECURITY.md`).
- MUST keep the Day 4 model endpoint on `http://127.0.0.1:11434` (source: `SECURITY.md`, `src/llm_security_lab/ollama.py`).
- MUST verify the configured full model digest before inference and fail closed on a mismatch (source: `experiments/<experiment-id>/experiment.json`, `src/llm_security_lab/lab.py`).
- MUST NOT add tools, external rendering, automatic actions, or outbound communication to the Day 4,
  Day 5, Day 7, Day 8, Day 9, Day 10, or Day 11 model experiments (source: `SECURITY.md`).
- Day 12 MAY send synthetic function schemas to Ollama, but MUST NOT provide implementations,
  execute returned tool calls, or add an outbound sink (source: `SECURITY.md`).
- Day 13 MAY send experiment-owned synthetic PNG fixtures to Ollama, but MUST NOT run OCR, add
  tools, execute downstream actions, or add an outbound sink (source: `SECURITY.md`).
- Day 14 MAY combine experiment-owned synthetic PNGs, user requests, multi-turn history, encoded
  text, and reference notes, but MUST NOT run OCR, add tools, execute downstream actions, or add an
  outbound sink (source: `SECURITY.md`).
- Day 15 MAY run deterministic in-memory paragraph retrieval over experiment-owned synthetic
  Markdown fixtures, but MUST NOT call an embedding API, use a vector store, persist an index, add
  tools, execute downstream actions, or add an outbound sink (source: `SECURITY.md`).
- Day 16 MAY replay an experiment-owned synthetic publish/rebuild/revoke event log and retrieve from
  its materialized in-memory corpus, but MUST NOT use a database, embedding API, vector store,
  tools, downstream actions, or an outbound sink (source: `SECURITY.md`).
- Day 17 MAY call Ollama `/api/embed` for experiment-owned synthetic text and compare exact cosine
  ranking with an in-memory Qdrant collection. It MUST verify both model digests, apply any declared
  tenant filter inside each retrieval engine, and MUST NOT persist the collection, add tools,
  execute downstream actions, or add an outbound sink (source: `SECURITY.md`).
- Day 18 MUST run offline with fixed synthetic proposals, identities, policy, review envelopes, and
  an in-memory side-effect ledger. It MUST NOT call a model, access the network, connect to a real
  mailbox or payment system, or execute an external side effect (source: `SECURITY.md`).
- Day 19 MUST run offline with fixed synthetic function calls, tool output, strict schemas, and
  in-memory sink events. It MUST NOT call a model, access the network, start a subprocess or shell,
  or execute an external side effect (source: `SECURITY.md`).
- Day 20 MUST run offline with fixed synthetic artifact manifests and a read-only audit of committed
  lock and experiment metadata. It MUST NOT load a model artifact, install a package, start an MCP
  Server, access the network, start a subprocess, or execute an external side effect (source:
  `SECURITY.md`).
- Day 21 MAY combine deterministic in-memory retrieval, loopback Ollama native tool calls, and two
  experiment-owned synthetic tools. It MUST reject parallel or unknown calls, use only `.test`
  recipients, keep every tool effect in memory, and MUST NOT access an external network, start a
  subprocess, or execute an external side effect (source: `SECURITY.md`).
- Day 22 MAY compare the complete Day 14 matrix through baseline and validated canonical-JSON
  input paths. It MUST keep task identity application-owned, use only bundle-owned synthetic
  fixtures, keep Ollama on loopback, and MUST NOT add OCR, tools, downstream actions, or an external
  sink (source: `SECURITY.md`).
- Day 23 MAY send bundle-owned synthetic text to digest-pinned loopback Ollama, then evaluate the
  same candidate through intentionally unescaped and defended HTML-text paths. It MUST use only an
  inert parser oracle, MUST NOT launch a browser or execute JavaScript, and MUST NOT make an
  external request or side effect (source: `SECURITY.md`).
- Day 24 MAY use NeMo Guardrails to orchestrate bundle-owned semantic and deterministic input,
  topic, and output rails around digest-pinned loopback Ollama. It MUST disable NeMo usage
  telemetry, keep every model call on loopback, preserve the Day 23 output contract and safe sink,
  and MUST NOT launch a browser, execute JavaScript, access an external network, start a subprocess,
  or create an external side effect (source: `SECURITY.md`).
- The Day 24 Prompt Guard extension MAY load the gated 86M classifier only from a revision-pinned,
  hash-verified local Hugging Face snapshot. It MUST use bundle-owned synthetic input, set
  Hugging Face and Transformers offline modes before import, reject inputs beyond its fixed
  512-token contract, and MUST NOT download during a run, generate a response, reach a sink, launch
  a browser, execute JavaScript, access an external network, start a subprocess, or create an
  external side effect (source: `SECURITY.md`).
- Day 25 MAY start only the digest-pinned Alpine image with exact Docker argument vectors and the
  bundle-owned fixed workload. It MUST keep proposals as data, use only temporary synthetic mounts,
  enforce the hardened container profile for every full-control path, and MUST NOT interpret
  model-authored commands, make a network request, or create an external side effect (source:
  `SECURITY.md`).
- Day 26 MUST use only the bundle-owned labeled synthetic PII cases. It MAY load the locked
  Presidio and `en_core_web_sm` packages from the local environment, but MUST NOT download during a
  run, call a model, access the network, use real personal data, or create an external side effect
  (source: `SECURITY.md`).
- Day 27 MUST use only the bundle-owned synthetic request and six fixed audit events. It MAY load
  the locked OpenTelemetry SDK and create in-memory spans and an ephemeral HMAC key. It MUST NOT
  export telemetry, persist the HMAC key, call a model, access the network, use real personal data,
  or create an external side effect (source: `SECURITY.md`).
- MUST preserve the model, runtime, options, fixture hashes, full request, and observed response for every claimed result (source: `README.md`, `src/llm_security_lab/lab.py`).
- MUST pass `uv run pytest`, `uv run ruff check .`, and `uv run ruff format --check .` before declaring code changes complete (source: `pyproject.toml`).

## Read before you work

| Task | Read first |
|---|---|
| Architecture, execution flow, directory layout, integrations | [docs/project-overview.md](docs/project-overview.md) |
| Style, lint rules, error handling, and layering | [docs/coding-style.md](docs/coding-style.md) |
| Adding fixtures, attacks, sinks, tools, or model-visible data | [SECURITY.md](SECURITY.md) |

## Commands

```bash
uv sync
uv run llm-security-lab --scenario clean
uv run llm-security-lab --scenario attack
uv run llm-security-lab --experiment day-05-threat-flow-observation --scenario clean --repeat 3
uv run llm-security-lab --experiment day-11-jailbreak-taxonomy --run-plan
uv run llm-security-lab --experiment day-12-hidden-context-exposure --run-plan
uv run llm-security-lab --experiment day-13-multimodal-injection --run-plan
uv run llm-security-lab --experiment day-14-injection-assessment --run-plan
uv run llm-security-lab --experiment day-15-rag-attack-surface --run-plan
uv run llm-security-lab --experiment day-16-data-poisoning --run-plan
uv run llm-security-lab --experiment day-17-vector-embedding-security --run-plan
uv run llm-security-lab --experiment day-22-input-defense-isolation-validation --run-plan
uv run llm-security-report evidence/raw/day-05/clean.json
uv run llm-security-authority --experiment day-06-authority-boundary
uv run llm-security-authority-report evidence/raw/day-06/results.json
uv run llm-security-agency --experiment day-18-excessive-agency
uv run llm-security-agency-report evidence/raw/day-18/results.json
uv run llm-security-tool-boundary --experiment day-19-tool-calling-security --output evidence/raw/day-19/results.json
uv run llm-security-tool-boundary-report evidence/raw/day-19/results.json
uv run llm-security-supply-chain --experiment day-20-ai-supply-chain-security --output evidence/raw/day-20/results.json
uv run llm-security-supply-chain-report evidence/raw/day-20/results.json
uv run llm-security-agent-chain --experiment day-21-end-to-end-agent-attack-chain --output evidence/raw/day-21/results.json
uv run llm-security-agent-chain-report evidence/raw/day-21/results.json
uv run llm-security-output-boundary --experiment day-23-output-defense-safe-rendering --output evidence/raw/day-23/results.json
uv run llm-security-output-boundary-report evidence/raw/day-23/results.json
uv run llm-security-guardrails --experiment day-24-guardrails-in-practice --mode paired --output evidence/raw/day-24/paired.json
uv run llm-security-guardrails --experiment day-24-guardrails-in-practice --mode end-to-end --output evidence/raw/day-24/end-to-end.json
uv run llm-security-guardrails-report evidence/raw/day-24/paired.json
uv run --extra prompt-guard --python 3.13 llm-security-prompt-guard --experiment day-24-prompt-guard-input-rail --output evidence/raw/day-24/prompt-guard.json
uv run --extra prompt-guard --python 3.13 llm-security-prompt-guard-report evidence/raw/day-24/prompt-guard.json
uv run llm-security-sandbox --experiment day-25-least-privilege-agent-sandboxing --mode fixed --output evidence/raw/day-25/fixed.json
uv run llm-security-sandbox --experiment day-25-least-privilege-agent-sandboxing --mode model --output evidence/raw/day-25/model.json
uv run llm-security-sandbox-report evidence/raw/day-25/fixed.json
uv run --extra pii llm-security-pii --experiment day-26-pii-detection-masking --output evidence/raw/day-26/results.json
uv run --extra pii llm-security-pii-report evidence/raw/day-26/results.json
uv run --extra observability llm-security-observability --experiment day-27-observability-audit --output evidence/raw/day-27/results.json
uv run --extra observability llm-security-observability-report evidence/raw/day-27/results.json
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

## Conventions

- Keep each experiment's definition and synthetic fixtures together under
  `experiments/<experiment-id>/`; bundles MUST NOT reference another experiment's fixture paths.
- Treat a model or digest change as a new result and preserve the earlier evidence.
- Keep raw output under ignored paths; commit only reviewed, sanitized evidence summaries.

## Docs maintenance

When modifying any file under `docs/`, update its `> **Last updated:** YYYY-MM-DD` frontmatter to today's date. Requirement keywords (MUST, SHOULD, MAY) follow RFC 2119.
