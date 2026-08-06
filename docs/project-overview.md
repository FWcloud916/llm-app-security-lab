# LLM Application Security Lab — Project Overview

> **Type:** Explanation
> **Audience:** Developers, AI assistants, and any tooling that needs project context
> **Last updated:** 2026-08-06
>
> A versioned, synthetic-data lab for the experiments in the 30-day LLM application-security series.

---

## 1. Purpose

### 1.1 Core Responsibilities

The repository owns runnable experiment code, synthetic fixtures, versioned scenarios, offline
tests, and sanitized result checkpoints. Each article can cite one immutable Git commit or tag.

### 1.2 Relationship with Other Systems

The CLI calls one Ollama server over IPv4 loopback. The separate `brag-talker` repository owns the
articles, author notes, publication state, and social distribution; this repository owns only lab
artifacts and their verification.

### 1.3 Deprecated / Retired or Not-Yet-Enabled Features

- Cloud model adapters are not enabled.
- Tools, browser rendering, automated sinks, and external communication are intentionally absent
  from the Day 4 baseline.
- The model artifact is not distributed through this repository.

## 2. Tech Stack

| Component | Choice | Rationale |
|---|---|---|
| Language | Python 3.11+ | Standard-library HTTP and filesystem APIs are sufficient for the baseline. |
| Environment | uv with `uv.lock` | Locks development dependencies and provides one command surface. |
| Runtime dependencies | Python standard library | Keeps the experiment wrapper independent of an Ollama SDK. |
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
versioned scenario.json
    │
    ├─► synthetic fixture loader ──► path and symlink checks ──► SHA-256 evidence
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

- Scenario files own model, prompt, option, and fixture-order decisions.
- Fixture loading MUST fail closed on symlinks and paths outside `fixtures/`.
- The Ollama client MUST reject non-loopback origins.
- A model tag is not identity; the full digest is checked before inference.
- Model responses remain untrusted evidence and do not trigger automatic actions.

## 4. Directory Structure

```text
.
├── src/llm_security_lab/
│   ├── cli.py                 # CLI parsing and JSON output
│   ├── lab.py                 # Scenario, fixture, digest, request, and evidence flow
│   └── ollama.py              # Loopback-only JSON client
├── fixtures/                  # Synthetic model-visible data
├── scenarios/                 # Immutable experiment definitions by milestone
├── evidence/                  # Reviewed, sanitized checkpoints
├── tests/                     # Offline unit tests with fake clients
├── docs/                      # Architecture and coding references
├── SECURITY.md                # Deliberately vulnerable lab boundary
└── pyproject.toml             # Package, pytest, and Ruff configuration
```

## 5. Domain Models (High-Level)

### Core Entity Relationships

N/A — the project has no database entities. A scenario definition selects a model configuration,
one target fixture, and an ordered list of note fixtures; one run produces an evidence document.

### Model Details

N/A — the dictionaries returned by `src/llm_security_lab/lab.py` are serialized directly to JSON
and are not persistent domain models.

## 6. API / Interface Structure

The public interface is one CLI command:

```text
llm-security-lab --scenario {clean,attack}
```

The command loads `scenarios/day-04-vulnerable-baseline/scenario.json`, runs the selected fixture
set, and writes complete JSON evidence to stdout. Invalid scenarios, missing fixtures, model digest
mismatches, and Ollama failures return exit status 1.

## 7. Background Jobs & Scheduled Tasks

N/A — the project has no worker, queue, scheduler, daemon, or recurring task.

## 8. External Service Integrations

| Integration | Client | Boundary |
|---|---|---|
| Ollama API | `src/llm_security_lab/ollama.py` | Plain HTTP to `127.0.0.1`; only `/api/*` paths accepted |

The Day 4 baseline calls `GET /api/version`, `GET /api/tags`, and `POST /api/chat`. No cloud API,
credential, tool schema, browser, or downstream action is configured.

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

1. The versioned scenario JSON selects the model, digest, options, prompt, target, and note order.
2. The CLI selects one named scenario only.
3. `OllamaClient` fixes the default origin and rejects non-loopback alternatives.

The project intentionally has no `.env` configuration for the Day 4 baseline.
