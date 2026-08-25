# LLM Application Security Lab — Project Overview

> **Type:** Explanation
> **Audience:** Developers, AI assistants, and any tooling that needs project context
> **Last updated:** 2026-08-25
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
- Day 12 sends inert synthetic function definitions but has no implementation, dispatch loop,
  tool-result message, or external sink.
- Day 13 sends one experiment-owned synthetic PNG through Ollama's native vision input. The runner
  performs no OCR, tool call, downstream action, or external communication.
- Day 18 does not call a model. It evaluates fixed synthetic proposals through functionality,
  downstream permission, advisory risk, exact approval, and in-memory side-effect gates.
- Day 19 does not call a model. It compares fixed synthetic function calls and tool output through
  vulnerable and hardened schema, policy, sink-adapter, and output-trust paths.
- Day 20 does not call a model or execute candidate components. It audits committed lock and model
  metadata, then evaluates fixed synthetic model, package, and MCP Server manifests.
- Day 21 is an intentionally vulnerable hybrid orchestration experiment. It performs deterministic
  retrieval, sends two strict native tool definitions to digest-pinned loopback Ollama, and records
  both tool effects in memory without external communication.
- Day 22 pairs the complete Day 14 matrix across the legacy serializer and a strict task-specific
  input contract with canonical JSON. Both paths remain loopback-only and have no OCR, tools,
  actions, or external sink.
- Day 23 generates one structured candidate per loopback model call, then sends the same bytes to
  an intentionally unescaped HTML path and a strict schema, review, authorization, and HTML-text
  path. An inert parser records would-be active markup without launching a browser or making a
  request.
- Day 24 uses NeMo Guardrails 0.23.x to orchestrate separate semantic and deterministic input,
  topic, and output rails. Paired runs share one candidate; independent runs short-circuit before
  generation or before the sink. The Day 23 application boundary remains mandatory.
- A separate Day 24 extension compares three input rails: the existing semantic classifier, the
  deterministic route rule, and Llama Prompt Guard 2 86M loaded from a revision-pinned,
  hash-verified local snapshot. It has no generator or sink.
- Day 25 combines strict model proposals with deterministic action, resource, and exact-approval
  checks before an exact Docker adapter. Its fixed ablation removes one control at a time; the
  model plan keeps every executable path on the hardened container profile.
- Day 26 compares application rules, Presidio built-in recognizers, and a layered registry over one
  fixed labeled synthetic corpus. It performs no model or network call.
- Model artifacts are not distributed through this repository.

## 2. Tech Stack

| Component | Choice | Rationale |
|---|---|---|
| Language | Python 3.11+ | Standard-library HTTP and filesystem APIs are sufficient for the baseline. |
| Environment | uv with `uv.lock` | Locks development dependencies and provides one command surface. |
| Runtime dependencies | Python standard library + pypdf 6.x + qdrant-client 1.19.x; optional Transformers/PyTorch or Presidio/SpaCy | Keeps large or experiment-specific runtimes behind explicit extras. |
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
    │                         └─► optional PNG ──► base64 + source SHA-256 evidence
    │
    └─► Ollama preflight ──► version + full model digest check
                                  │
                    optional lifecycle replay
                    (publish + revoke + rebuild)
                                  │
                    optional deterministic retrieval
                    (paragraph chunks + token overlap)
                                  │
                    optional vector retrieval
                    (/api/embed + exact cosine + in-memory Qdrant)
                                  │
                                  ▼
                            POST /api/chat
                                  │
                                  ▼
                    complete JSON evidence on stdout

Day 18 fixed synthetic proposal
    │
    ├─► available-function gate
    ├─► subject + dedicated-Agent permission gate
    ├─► advisory keyword annotation
    ├─► exact or batch approval-envelope gate
    └─► in-memory synthetic side-effect ledger

Day 19 fixed synthetic function call or tool output
    │
    ├─► strict schema gate
    ├─► destination and semantic policy
    ├─► sink-safe adapter
    ├─► tool-output trust classification
    └─► in-memory sink-event ledger

Day 20 committed metadata + fixed synthetic manifests
    │
    ├─► read-only package-lock and model-reference audit
    ├─► immutable identity + hash + provenance gates
    ├─► model format and remote-code gate
    ├─► MCP capability and token-passthrough gate
    └─► ALLOW / REVIEW / BLOCK evidence

Day 21 synthetic RAG context + loopback Ollama
    │
    ├─► deterministic Top-1 retrieval
    ├─► native read_case_record proposal ──► synthetic record in memory
    ├─► native send_case_summary proposal ──► in-memory sink ledger
    └─► source / retrieval / tool / destination control matrix

Day 25 fixed or model proposal
    │
    ├─► action allowlist
    ├─► subject + Agent + resource grant, expiry, and revocation
    ├─► exact reviewed-envelope binding
    └─► exact Docker adapter ──► hardened fixed workload ──► containment evidence

Day 26 fixed labeled synthetic text
    │
    ├─► raw path
    ├─► application-owned deterministic recognizers
    ├─► Presidio built-in recognizers
    └─► layered Presidio registry ──► fixed masking ──► span and leakage metrics
```

### Key Principles

- Experiment bundles own model, prompt, option, fixture, and fixture-order decisions.
- Bundles MUST NOT read fixtures from another experiment.
- Fixture loading MUST fail closed on symlinks and paths outside the selected bundle.
- The Ollama client MUST reject non-loopback origins.
- A model tag is not identity; the full digest is checked before inference.
- Model responses remain untrusted evidence and do not trigger automatic actions.
- Day 15 retrieval is in-memory and vectorless: it records corpus, chunk, rank, selection, and
  serialization evidence without an embedding endpoint or persistent index.
- Day 16 lifecycle replay is in-memory and deterministic: it records source versions, revocation,
  derived-corpus rebuilds, staleness, and corpus hashes without a database.
- Day 17 treats ranking and authorization as independent gates: both exact cosine and Qdrant apply
  the declared tenant filter before Top-k, and the runner fails closed unless their IDs and scores
  agree within the recorded tolerance.
- Day 18 treats Agent proposals as already compromised input. Keyword findings never grant
  authority; only available functions, deterministic policy, exact review binding, and the action's
  approval mode determine whether an in-memory synthetic side effect occurs.
- Day 19 treats schema-valid strings and tool output as untrusted. Structural validation never
  grants destination authority or sink safety, and tool output never gains dispatch authority.
- Day 20 treats a familiar name, signature, or tool annotation as incomplete evidence. Identity,
  integrity, provenance, executable format, and runtime capability are evaluated separately.
- Day 21 preserves model variability and deterministic controls as separate evidence. Native tool
  calls are executed only by exact experiment-owned in-memory adapters; parallel, repeated,
  unknown, malformed, or over-limit calls fail closed.
- Day 25 never turns model text into a command line. The proposal selects one declared operation;
  deterministic policy controls decide whether an exact Docker argument vector may run it. Runtime
  containment remains a separate boundary after authorization.
- Day 26 treats PII detection as evidence, not authorization. A detector profile returns spans;
  application policy still decides which entities to block, replace, retain, or route for review.

## 4. Directory Structure

```text
.
├── src/llm_security_lab/
│   ├── cli.py                 # Experiment selection, repetition or fixed plans, and raw JSON output
│   ├── agency.py              # Offline Excessive Agency control-flow matrix and report
│   ├── tool_boundary.py       # Offline function-call and tool-output boundary matrix and report
│   ├── supply_chain.py        # Offline artifact-intake matrix and repository metadata audit
│   ├── agent_chain.py         # Hybrid Agent tool loop and deterministic cut-point matrix
│   ├── sandboxing.py          # Day 25 policy ablation and exact Docker adapter
│   ├── pii.py                 # Day 26 fixed PII detection and masking matrix
│   ├── lab.py                 # Bundle, fixture, digest, request, and evidence flow
│   ├── knowledge_base.py      # Synthetic publish/revoke/rebuild lifecycle replay
│   ├── report.py              # Sanitized repeated-run summary
│   ├── retrieval.py           # Deterministic paragraph chunking and sparse retrieval trace
│   ├── vector_retrieval.py    # Embedding validation, exact cosine, and local Qdrant parity
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

N/A — the project has no database entities. An experiment definition selects a model configuration
and either direct fixtures or an in-memory retrieval corpus; one run produces an evidence document.

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
llm-security-agency --experiment day-18-excessive-agency
llm-security-agency-report <raw-json>
llm-security-tool-boundary --experiment day-19-tool-calling-security [--output <raw-json>]
llm-security-tool-boundary-report <raw-json>
llm-security-supply-chain --experiment day-20-ai-supply-chain-security [--output <raw-json>]
llm-security-supply-chain-report <raw-json>
llm-security-agent-chain --experiment day-21-end-to-end-agent-attack-chain [--output <raw-json>]
llm-security-agent-chain-report <raw-json>
llm-security-output-boundary --experiment day-23-output-defense-safe-rendering [--output <raw-json>]
llm-security-output-boundary-report <raw-json>
llm-security-guardrails --experiment day-24-guardrails-in-practice --mode {paired,end-to-end} [--output <raw-json>]
llm-security-guardrails-report <raw-json>
llm-security-prompt-guard --experiment day-24-prompt-guard-input-rail [--output <raw-json>]
llm-security-prompt-guard-report <raw-json>
llm-security-sandbox --experiment day-25-least-privilege-agent-sandboxing --mode {fixed,model} [--output <raw-json>]
llm-security-sandbox-report <raw-json>
llm-security-pii --experiment day-26-pii-detection-masking [--output <raw-json>]
llm-security-pii-report <raw-json>
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
Schema-v3 scenarios may also declare validated Ollama function definitions. They are preserved as
model-visible request evidence; the runner never executes returned calls. The reporter rejects
missing, duplicated, reordered, or unplanned options before printing a sanitized summary. Invalid
bundles, scenarios, fixtures, model digest mismatches, mixed batches, and Ollama failures return
exit status 1. The authority runner executes the complete fixed case matrix
once, evaluates proposals against synthetic trusted application state and policy, and its reporter
verifies expected decisions and event counts without printing raw model output or identity fixtures.
The tool-boundary runner executes one fixed vulnerable/hardened matrix, records only in-memory sink
events, and its reporter omits raw arguments and synthetic tool-output text. The supply-chain runner
performs a read-only repository metadata audit and evaluates one fixed nine-case manifest matrix;
its reporter omits raw artifact identifiers and declared capability values.
The Agent-chain runner executes ten digest-pinned model runs across clean and poisoned retrieval,
permits only one native tool call per turn, and evaluates one five-case deterministic cut-point
matrix. Its reporter omits retrieved text, model responses, synthetic records, tool arguments, and
recipient values.

Day 15 adds a mutually exclusive scenario-level `retrieval` object. A retrieval scenario declares
one `user_request`, 1–20 synthetic Markdown documents, `paragraph-v1` chunking,
`ascii-token-overlap-v1` scoring, and a bounded `top_k`. The runner fingerprints the corpus, ranks
every paragraph deterministically, serializes only selected chunks, and records stage markers for
corpus, retrieved context, request, and response. Retrieval scenarios cannot add notes, binary
documents, images, tools, or multi-turn history.

Day 16 adds a mutually exclusive scenario-level `knowledge_base` object. It declares one synthetic
JSON event log, the final event to replay, and vectorless retrieval options. Event IDs are
consecutive; publish events own a versioned Markdown fixture and review status; revoke events
reference a published version; rebuild events materialize the latest non-revoked version per
source. Evidence and the sanitized report keep active source state, corpus state, retrieval, and
model response as separate layers.

Day 17 adds a mutually exclusive scenario-level `vector_retrieval` object and a top-level pinned
`embedding_model`. A scenario declares synthetic Markdown documents with tenant IDs, a requested
tenant, an optional tenant filter, `paragraph-v1`, `ollama-embedding-cosine-v1`, bounded `top_k`, and
the fixed exact-cosine/Qdrant engine order. The runner sends the query and chunks in one batch to
loopback `/api/embed`, validates vector count, dimension, finiteness, and model name, applies the
filter inside each engine, and refuses to call chat unless selected IDs and scores agree. Raw
evidence retains vectors; the sanitized fingerprint and report retain only hashes and audit fields.

## 7. Background Jobs & Scheduled Tasks

N/A — the project has no worker, queue, scheduler, daemon, or recurring task.

## 8. External Service Integrations

| Integration | Client | Boundary |
|---|---|---|
| Ollama API | `src/llm_security_lab/ollama.py` | Plain HTTP to `127.0.0.1`; only `/api/*` paths accepted for Day 4/5 |
| Day 6 authority runner | `src/llm_security_lab/authority.py` | Offline deterministic evaluator; no network or model |
| Day 18 agency runner | `src/llm_security_lab/agency.py` | Offline deterministic evaluator; synthetic in-memory side effects only |
| Day 19 tool-boundary runner | `src/llm_security_lab/tool_boundary.py` | Offline deterministic evaluator; no model, network, subprocess, shell, or external side effect |
| Day 20 supply-chain runner | `src/llm_security_lab/supply_chain.py` | Offline deterministic evaluator and read-only metadata audit; no artifact load, install, MCP start, network, subprocess, or external side effect |
| Day 21 Agent-chain runner | `src/llm_security_lab/agent_chain.py` | Loopback Ollama plus deterministic retrieval and two strict in-memory synthetic tool adapters; no external network, subprocess, email, or external side effect |
| Qdrant local mode | `src/llm_security_lab/vector_retrieval.py` | Process-local `:memory:` collection; no server, persistence, or outbound call |

The Day 4, Day 5, Day 7, Day 8, Day 9, Day 10, Day 11, Day 12, Day 13, Day 14, Day 15, Day 16, and Day 17
bundles call
`GET /api/version`, `GET /api/tags`, and `POST /api/chat`. No cloud API, credential, browser, or
downstream action is configured. Day 4–11 send no tool schema. Day 12 sends synthetic tool schemas
only; no function implementation or downstream action exists. Day 13 and Day 14 send one base64
PNG in the native `images` message field and no tools.
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
Day 12 adds backwards-compatible scenario-level inert function schemas. Evidence records whether
schemas were sent and that tool execution remained disabled; fixed-input validation fingerprints
the complete schema so a changed description or parameter definition invalidates the batch.
Day 13 adds a backwards-compatible scenario-level PNG path. The runner attaches the base64 bytes to
the first user message, fingerprints the source hash and size, retains the complete request only in
raw evidence, and declares that OCR and downstream execution remained disabled.
Day 14 composes those existing schema-v3 capabilities without adding a new runner interface. Ten
scenarios hold one task, one synthetic confidential reference, one model digest, and five seeds
constant while changing direct, indirect, delimiter, hypothetical, multi-turn, encoded, many-shot,
or image-based delivery. The fixed 50-run plan contains 60 loopback calls.
Day 15 keeps the same loopback-only chat interface while adding a vectorless retrieval trace. It
uses no embedding API or vector store; raw evidence separates corpus membership, chunk ranking,
selected context, serialized request, and response.
Day 16 materializes a corpus from an experiment-owned event log before invoking that same retriever.
It uses no database or persistent index; raw evidence separates accepted source versions, revoked
versions, the last rebuild, corpus staleness, selected context, serialized request, and response.
Day 17 additionally calls loopback `POST /api/embed` for synthetic inputs, creates one ephemeral
Qdrant local collection per run, and compares its filtered cosine result with an exact calculation.
The chat and embedding tags are each checked against their configured full digest before inference.
Day 19 has no external integration. The vulnerable path records unchecked destinations and
would-be shell strings as in-memory event metadata; the hardened path applies strict field checks,
exact origin and template allowlists, output-name validation, and untrusted tool-output labeling.
Day 21 calls the same loopback `/api/version`, `/api/tags`, and `/api/chat` endpoints. The model may
propose `read_case_record` and `send_case_summary`; exact adapters return one experiment-owned JSON
record or append one process-local ledger event. No socket, mailbox, subprocess, file output, or
external service backs either tool.
Day 22 adds an optional scenario-level `input_boundary` version 1 to the normal schema-v3
note/target/image path. The runner validates application-owned task identity, bounded text and PNG
metadata, serializes provenance-labeled content as canonical JSON, and binds each admission decision
to the exact user-message SHA-256. Baseline and defended pairs own identical fixture bytes and
sampling options; JSON labels reduce structural ambiguity but do not enforce model obedience.
Day 23 uses a dedicated runner. Ollama structured output supplies one candidate JSON string per
run; application validation still checks exact keys, string types, lengths, and task markers. The
candidate hash is shared by the vulnerable and defended paths. The defended path separately records
content review, authorization for the `html_text` sink, and context-specific escaping. Its HTML
oracle parses strings in memory and cannot execute scripts, load resources, or contact a network.
Day 24 uses a dedicated asynchronous runner. Six small NeMo configurations invoke registered custom
actions through `check_async()`: three use the digest-pinned loopback model as a strict semantic
classifier, and three apply application-owned deterministic rules. Invalid classifier JSON fails
closed. NeMo has no configured remote model and usage telemetry is disabled before initialization.
The Prompt Guard extension has a separate bundle and runner. Three NeMo input configurations apply
the existing loopback semantic classifier, the deterministic route rule, and a local Prompt Guard
classifier to the exact same canonical JSON bytes. The local loader resolves one fixed Hugging Face
revision from cache, verifies required file hashes, disables telemetry and online lookup before
import, and rejects inputs beyond 512 tokens. The fixed plan contains 25 run units and 75 path
evaluations, with no generation or sink.

## 9. Database / Data Stores

N/A — the project owns no persistent database, cache, object store, vector store, or runtime state.
Day 16 replays persistent-state semantics entirely in memory from a versioned synthetic event log.
Day 17 creates and discards a Qdrant `:memory:` collection inside each run; it is an experiment
engine, not repository-owned persistence.
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
