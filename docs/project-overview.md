# LLM Application Security Lab — Project Overview

> **Type:** Explanation
> **Audience:** Developers, AI assistants, and any tooling that needs project context
> **Last updated:** 2026-08-08
>
> A versioned, synthetic-data lab whose independent experiment bundles support the 30-day LLM
> application-security series.

---

## 1. Purpose

### 1.1 Core Responsibilities

The repository owns a generic runner, independent experiment bundles, offline tests, and sanitized
result checkpoints. Each article can cite one immutable Git commit or tag.

### 1.2 Relationship with Other Systems

The CLI calls one Ollama server over IPv4 loopback. The separate `brag-talker` repository owns the
articles, author notes, publication state, and social distribution; this repository owns only lab
artifacts and their verification.

### 1.3 Deprecated / Retired or Not-Yet-Enabled Features

- Cloud model adapters are not enabled.
- Tools, browser rendering, OCR, automated sinks, and external communication are intentionally absent
  from the Day 4, Day 5, Day 7, Day 8, Day 9, Day 10, and Day 11 model bundles.
- The model artifact is not distributed through this repository.

## 2. Tech Stack

| Component | Choice | Rationale |
|---|---|---|
| Language | Python 3.11+ | Standard-library HTTP and filesystem APIs are sufficient for the baseline. |
| Environment | uv with `uv.lock` | Locks development dependencies and provides one command surface. |
| Runtime dependencies | Python standard library + pypdf 6.x | Keeps HTTP and HTML/email parsing in the standard library; pins one PDF text/metadata extractor. |
| Test | pytest | Supports offline fake clients, temporary paths, and explicit failure assertions. |
| Lint and format | Ruff | Provides one configured check and format gate. |
| Model runtime | Ollama on `127.0.0.1` | Preserves the local-only Day 4 safety boundary. |

The project uses a modular CLI package instead of a notebook because hidden notebook state makes
inputs and execution order harder to audit. A web UI was rejected because Day 4 deliberately avoids
adding a renderer or another output sink.

## 3. Architecture Overview

```text
CLI argument
    │
    ▼
versioned experiment bundle
    │
    ├─► synthetic fixture loader ──► path and symlink checks ──► optional document extractor
    │                                                       └─► raw/extracted SHA-256 evidence
    │
    └─► Ollama preflight ──► version + full model digest check
                                  │
                                  ▼
                            POST /api/chat
                                  │
                                  ▼
                    complete JSON evidence on stdout
```

### Key Principles

- Experiment bundles own model, prompt, option, fixture, and fixture-order decisions.
- Bundles MUST NOT read fixtures from another experiment.
- Fixture loading MUST fail closed on symlinks and paths outside the selected bundle.
- The Ollama client MUST reject non-loopback origins.
- A model tag is not identity; the full digest is checked before inference.
- Model responses remain untrusted evidence and do not trigger automatic actions.

## 4. Directory Structure

```text
.
├── src/llm_security_lab/
│   ├── cli.py                 # Experiment selection, repetition or fixed plans, and raw JSON output
│   ├── lab.py                 # Bundle, fixture, digest, request, and evidence flow
│   ├── report.py              # Sanitized repeated-run summary
│   └── ollama.py              # Loopback-only JSON client
├── experiments/
│   └── <experiment-id>/       # Definition plus experiment-owned synthetic fixtures
├── evidence/                  # Reviewed, sanitized checkpoints
├── tests/                     # Offline unit tests with fake clients
├── docs/                      # Architecture and coding references
├── SECURITY.md                # Deliberately vulnerable lab boundary
└── pyproject.toml             # Package, pytest, and Ruff configuration
```

## 5. Domain Models (High-Level)

### Core Entity Relationships

N/A — the project has no database entities. An experiment definition selects a model configuration,
one target fixture, and an ordered list of note fixtures; one run produces an evidence document.

### Model Details

N/A — the dictionaries returned by `src/llm_security_lab/lab.py` are serialized directly to JSON
and are not persistent domain models.

## 6. API / Interface Structure

The public runner and reporter interfaces are:

```text
llm-security-lab --scenario {clean,attack}
llm-security-lab --experiment <experiment-id> --scenario <name> [--repeat N]
llm-security-lab --experiment <schema-v3-experiment-id> --run-plan
llm-security-lab --experiment <schema-v3-experiment-id> --run-plan --output evidence/raw/<id>.json
llm-security-report <raw-json>
llm-security-authority --experiment day-06-authority-boundary
llm-security-authority-report <raw-json>
```

The legacy command defaults to `day-04-vulnerable-baseline`. A schema-v2 experiment selects one
scenario and optionally repeats identical options. A schema-v3 experiment uses `--run-plan` to
execute every declared run once in manifest order; each scenario owns its system message, optional
current user request or mutually exclusive `user_turns`, notes, run IDs, seeds, and temperatures. A
declared user request is serialized before the reference notes; omitting it preserves the earlier
message shape. A `user_turns` list contains 2–10 requests. Its first request carries the selected
fixtures, later requests carry an explicit `<user_request>` label, and every API call receives the
complete preceding user/assistant history. The raw schema-v2
planned batch retains every request and response.
Its reporter rejects missing, duplicated, reordered, or unplanned options before printing a
sanitized summary. Invalid bundles, scenarios, fixtures, model digest mismatches, mixed batches, and
Ollama failures return exit status 1. The authority runner executes the complete fixed case matrix
once, evaluates proposals against synthetic trusted application state and policy, and its reporter
verifies expected decisions and event counts without printing raw model output or identity fixtures.

## 7. Background Jobs & Scheduled Tasks

N/A — the project has no worker, queue, scheduler, daemon, or recurring task.

## 8. External Service Integrations

| Integration | Client | Boundary |
|---|---|---|
| Ollama API | `src/llm_security_lab/ollama.py` | Plain HTTP to `127.0.0.1`; only `/api/*` paths accepted for Day 4/5 |
| Day 6 authority runner | `src/llm_security_lab/authority.py` | Offline deterministic evaluator; no network or model |

The Day 4, Day 5, Day 7, Day 8, Day 9, Day 10, and Day 11 bundles call `GET /api/version`,
`GET /api/tags`, and `POST /api/chat`. No cloud API, credential, tool schema, browser, or downstream
action is configured.
Day 7 adds an optional `response_markers` list to its schema-v2 definition; every marker produces one
`<id>_in_model_response` boolean observation while older bundle evidence remains unchanged. Day 8
uses schema v3 to predeclare a complete multi-scenario option sequence without CLI overrides. Day 9
adds an optional scenario-level user request while retaining the same fixed-plan and evidence rules.
Day 10 adds scenario-level synthetic HTML, PDF, and email extraction. Raw source bytes, source hash,
extractor identity and policy, extracted text hash, serialized request, and model response remain
separate evidence. PDF metadata and email attachment filenames enter context only when the scenario
explicitly enables those application fields.
Day 11 adds a backwards-compatible scenario-level multi-turn request list. Evidence stores each
request/response pair in `conversation`, retains the final request/response at their existing
top-level keys, evaluates response markers across every assistant turn, and excludes variable
assistant text when comparing fixed scenario inputs across seeds. The fixed 30-run plan contains
40 loopback chat calls because its Crescendo proxy uses three turns per run.

## 9. Database / Data Stores

N/A — the project owns no database, cache, object store, vector store, or persistent runtime state.
Git stores scenario definitions, synthetic fixtures, and sanitized evidence summaries.

## 10. Environments & Deployment

### Environments

- **Local development and experiment execution:** Python, uv, and a loopback Ollama server.
- **Offline test:** pytest uses fake clients and temporary fixture paths; no model or network call.

### Deployment Pipeline

N/A — the project is a local CLI lab and has no deployed service or automated release pipeline.

### Configuration Hierarchy

1. The selected experiment bundle defines the model, digest, options, prompt, target, and note order.
2. The CLI selects one schema-v2 scenario or executes one complete schema-v3 run plan.
3. `OllamaClient` fixes the default origin and rejects non-loopback alternatives.

The project intentionally has no `.env` configuration for the Day 4 baseline.
