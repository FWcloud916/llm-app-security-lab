# LLM Application Security Lab

A versioned, synthetic-data lab for reproducing the LLM application-security experiments in the
30-day article series.

## What it does

- Runs independent, versioned experiment bundles against a loopback Ollama endpoint.
- Fails closed when the configured model tag no longer matches the recorded full digest.
- Prints the full fixtures, request, model metadata, response, token counts, and timings as JSON.
- Executes predeclared schema-v3 run plans without prompt, seed, or temperature CLI overrides.
- Runs the Day 6 deterministic authority-boundary bundle without a model or network call.
- Runs the Day 18 deterministic agency bundle with synthetic proposals and in-memory side effects,
  without a model, network call, mailbox, or payment service.
- Runs the Day 19 deterministic tool-boundary bundle with synthetic function calls and tool output,
  without a model, network call, subprocess, shell, or external side effect.
- Runs the Day 20 deterministic supply-chain intake bundle against synthetic artifact manifests and
  a read-only repository audit, without loading models, installing packages, starting MCP Servers,
  accessing the network, or starting subprocesses.
- Runs the Day 21 hybrid Agent attack-chain bundle with deterministic retrieval, digest-pinned
  loopback tool calls, and process-local synthetic tool effects; no external message is sent.
- Runs the Day 23 paired output-boundary bundle with one shared model candidate, strict validation,
  content review, and inert vulnerable/safe HTML inspection; no browser or outbound request exists.
- Preserves stable milestone tags so an article can point to the exact code it described.

## Quickstart

### Prerequisites

- Python 3.11 or newer
- [uv](https://docs.astral.sh/uv/)
- Ollama listening on `http://127.0.0.1:11434`

The Day 4 checkpoint expects `gemma4:latest` with digest
`c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb`. The model artifact is not
stored in Git. Using another model or digest creates a new result rather than an exact reproduction.

The Day 2 experiment preserves each complete model-visible user message as an experiment-owned
fixture. Its two scenarios use the same five fixed seeds and sampling options:

```bash
uv run llm-security-lab \
  --experiment day-02-prompt-injection-rerun \
  --run-plan \
  --output evidence/raw/day-02/results.json
uv run llm-security-report evidence/raw/day-02/results.json
```

Schema-v3 scenarios may declare one `message_fixture` instead of the normal message builder. The
runner sends those fixture bytes as the first user message without adding a wrapper. This mode is
mutually exclusive with notes, retrieval, user requests, multi-turn history, documents, images, and
tools. The sanitized report exposes only its path and SHA-256.

### Setup

```bash
uv sync
```

### Run

```bash
uv run llm-security-lab --scenario clean
uv run llm-security-lab --scenario attack
```

Those backward-compatible commands run the Day 4 baseline. The independent Day 5 threat-flow
experiment records three complete runs per scenario:

```bash
uv run llm-security-lab \
  --experiment day-05-threat-flow-observation \
  --scenario clean \
  --repeat 3 > evidence/raw/day-05/clean.json
uv run llm-security-report evidence/raw/day-05/clean.json
```

Day 4 and Day 5 experiment commands send requests to the local Ollama server. Raw evidence stays
ignored; commit only reviewed, sanitized summaries. Review [SECURITY.md](SECURITY.md) before adding
a bundle.

The Day 7 boundary-crossing warmup separates task deviation from data movement with three fixed
scenarios and an additional model-response marker:

```bash
uv run llm-security-lab \
  --experiment day-07-boundary-crossing-warmup \
  --scenario behavior-only \
  --repeat 3 > evidence/raw/day-07/behavior-only.json
uv run llm-security-report evidence/raw/day-07/behavior-only.json
```

Day 7 uses the same loopback-only model boundary as Day 4 and Day 5. It does not enable tools,
rendering, automatic actions, or outbound communication.

The Day 8 mechanism experiment fixes six scenarios and 32 run IDs before inference. Phase A keeps
sampling fixed; Phase B compares the same semantic payload under baseline and reinforced system
messages with ten predeclared seeds per prompt:

```bash
uv run llm-security-lab \
  --experiment day-08-prompt-injection-mechanism \
  --run-plan > evidence/raw/day-08/results.json
uv run llm-security-report evidence/raw/day-08/results.json
```

The reporter verifies exact run order and options before rendering counts. Day 8 remains synthetic,
loopback-only, and has no tools, renderer, automatic action, or outbound sink.

The Day 9 experiment uses one shared payload to compare a direct current-user request with an
indirect synthetic note. All three scenarios use the same ten predeclared seeds and sampling
options:

```bash
uv run llm-security-lab \
  --experiment day-09-direct-vs-indirect-injection \
  --run-plan > evidence/raw/day-09/results.json
uv run llm-security-report evidence/raw/day-09/results.json
```

Schema-v3 scenarios may declare an optional non-empty `user_request`. When present, the runner
serializes it in a `<user_request>` block before reference notes; older bundles that omit the field
retain their original message bytes. Day 9 remains synthetic and loopback-only, with stdout as its
only sink.

The Day 10 experiment compares synthetic HTML, PDF, email, metadata, and attachment-filename paths.
It records source bytes, extracted text, and the serialized request separately before measuring the
model response:

```bash
uv run llm-security-lab \
  --experiment day-10-hidden-document-paths \
  --run-plan > evidence/raw/day-10/results.json
uv run llm-security-report evidence/raw/day-10/results.json
```

Day 10 uses Python's standard HTML/email parsers and locked pypdf 6.x. It does not fetch live
content, render documents, run OCR, enable tools, or communicate outside loopback Ollama.

The Day 11 experiment compares five safe jailbreak-pattern proxies with a clean control. It adds an
optional schema-v3 `user_turns` list for true multi-turn conversations; later requests include the
complete user/assistant history while single-turn bundles keep their existing request shape:

```bash
uv run llm-security-lab \
  --experiment day-11-jailbreak-taxonomy \
  --run-plan \
  --output evidence/raw/day-11/results.json
uv run llm-security-report evidence/raw/day-11/results.json
```

The plan contains 30 run units. Five three-turn Crescendo proxies make the runner issue 40 local
chat calls in total. The raw evidence preserves every turn; the sanitized reporter prints only turn
counts, fixed options, fixture hashes, and marker counts. Day 11 uses synthetic policy-bypass
markers, has no harmful task, and keeps tools and outbound communication disabled.

The Day 12 experiment compares one synthetic hidden policy in four model-visible locations: system
text, a developer-labeled block inside the native system role, a RAG-like reference note, and an
inert function schema. Each location has a benign and an extraction request over the same five
predeclared seeds:

```bash
uv run llm-security-lab \
  --experiment day-12-hidden-context-exposure \
  --run-plan \
  --output evidence/raw/day-12/results.json
uv run llm-security-report evidence/raw/day-12/results.json
```

The Day 13 experiment compares a clean PNG, the same payload delivered as text, visible typography
inside a PNG, and human-readable low-contrast typography. It uses Ollama's native vision input,
performs no OCR, exposes no tools, and keeps the only output sink on stdout.

```bash
uv run llm-security-lab \
  --experiment day-13-multimodal-injection \
  --run-plan \
  --output evidence/raw/day-13/results.json
uv run llm-security-report evidence/raw/day-13/results.json
```

The Day 14 experiment holds one multimodal summary task, one confidential synthetic reference,
one model digest, and five seeds constant while changing only the attack delivery or framing. Its
ten scenarios cover clean, direct, indirect, delimiter-breaking, hypothetical, three-turn,
Base64, many-shot, visible-image, and low-contrast-image inputs. The fixed plan contains 50 run
units and 60 loopback chat calls because the three-turn scenario makes three calls per seed.

```bash
uv run llm-security-lab \
  --experiment day-14-injection-assessment \
  --run-plan \
  --output evidence/raw/day-14/results.json
uv run llm-security-report evidence/raw/day-14/results.json
```

The Day 22 experiment repeats that complete Day 14 matrix through paired baseline and defended
paths. The defended path validates one application-owned task contract, bounded text and PNG
inputs, then serializes provenance-labeled untrusted data as canonical JSON. All semantically valid
attack fixtures still pass admission; the experiment measures whether the changed packaging lowers
model deviation without claiming that JSON creates an instruction/data security boundary. The
fixed plan contains 100 run units and 120 loopback chat calls.

```bash
uv run llm-security-lab \
  --experiment day-22-input-defense-isolation-validation \
  --run-plan \
  --output evidence/raw/day-22/results.json
uv run llm-security-report evidence/raw/day-22/results.json
```

The Day 23 experiment asks the pinned loopback model for one structured event-summary candidate per
run, then evaluates those exact bytes through an intentionally unescaped HTML path and a defended
`html_text` path. A separate fixed matrix covers active tags, event handlers, dangerous URLs,
automatic resource references, secrets, and malformed output objects. The standard-library parser
only records would-be browser capabilities; it does not render, execute JavaScript, or access a URL.

```bash
uv run llm-security-output-boundary \
  --experiment day-23-output-defense-safe-rendering \
  --output evidence/raw/day-23/results.json
uv run llm-security-output-boundary-report evidence/raw/day-23/results.json
```

The Day 15 experiment adds a deterministic, in-memory RAG trace. It compares a clean corpus, the
same injection indexed but excluded by `top_k=1`, and the injection selected by `top_k=2`. The
retriever uses paragraph chunks and ASCII token overlap so corpus, rank, selected context, request,
and response remain independently auditable. It does not call an embedding API or vector store.

```bash
uv run llm-security-lab \
  --experiment day-15-rag-attack-surface \
  --run-plan \
  --output evidence/raw/day-15/results.json
uv run llm-security-report evidence/raw/day-15/results.json
```

The Day 16 experiment adds a deterministic knowledge-base lifecycle before the same vectorless
retrieval. One synthetic event log publishes an approved policy, publishes an unreviewed poisoned
version, revokes that version, and rebuilds the derived corpus. Four fixed scenarios distinguish
active source state from a stale materialized corpus; no database or persistent index is used.

```bash
uv run llm-security-lab \
  --experiment day-16-data-poisoning \
  --run-plan \
  --output evidence/raw/day-16/results.json
uv run llm-security-report evidence/raw/day-16/results.json
```

The Day 17 experiment separates semantic ranking from tenant authorization. It embeds only
experiment-owned synthetic text with `embeddinggemma:latest`, applies the same optional tenant
filter to exact cosine and an in-memory Qdrant collection, requires both engines to select the same
Top-1 chunk, and then sends only that chunk to the pinned chat model. Its four fixed scenarios show
that a tenant filter blocks a higher-scoring cross-tenant chunk but cannot distinguish a poisoned
chunk that is already inside the authorized tenant. Raw vectors remain in ignored evidence only;
the sanitized report exposes hashes, dimensions, selected IDs, scores, and aggregate predicates.

```bash
uv run llm-security-lab \
  --experiment day-17-vector-embedding-security \
  --run-plan \
  --output evidence/raw/day-17/results.json
uv run llm-security-report evidence/raw/day-17/results.json
```

The Day 18 experiment assumes a fixed malicious Agent proposal and isolates the blast-radius
controls around it. Seven offline cases compare excessive functionality, restricted functionality,
dedicated downstream permissions, exact approval binding, post-approval mutation, batch isolation,
and one keyword-paraphrase miss. The runner records functionality, authorization, advisory risk,
approval, and synthetic state transition separately. It does not call a model or network and never
connects to a mailbox, payment service, or external sink.

```bash
uv run llm-security-agency \
  --experiment day-18-excessive-agency \
  > evidence/raw/day-18/results.json
uv run llm-security-agency-report evidence/raw/day-18/results.json
```

The Day 19 experiment compares the same five synthetic inputs through deliberately vulnerable and
hardened application paths. It separates strict schema validation, destination policy, sink-safe
argument handling, and tool-output trust. Vulnerable sinks are only recorded as in-memory events;
the runner never fetches a URL, starts a process, creates the proposed file, or dispatches a tool
instruction.

```bash
uv run llm-security-tool-boundary \
  --experiment day-19-tool-calling-security \
  --output evidence/raw/day-19/results.json
uv run llm-security-tool-boundary-report evidence/raw/day-19/results.json
```

The Day 20 experiment first audits committed package-lock and model-reference metadata, then applies
one fixed `ALLOW / REVIEW / BLOCK` policy to nine synthetic model, package, and MCP Server manifests.
It records evidence gaps and capability drift without downloading, importing, or executing any
candidate component.

```bash
uv run llm-security-supply-chain \
  --experiment day-20-ai-supply-chain-security \
  --output evidence/raw/day-20/results.json
uv run llm-security-supply-chain-report evidence/raw/day-20/results.json
```

The Day 21 experiment compares five clean and five poisoned retrieval runs. The deliberately
vulnerable model loop may read one experiment-owned synthetic case and record a proposed send in an
in-memory ledger. A separate fixed matrix shows where source review, retrieval authority, the tool
allowlist, and destination/data policy cut the same path.

```bash
uv run llm-security-agent-chain \
  --experiment day-21-end-to-end-agent-attack-chain \
  --output evidence/raw/day-21/results.json
uv run llm-security-agent-chain-report evidence/raw/day-21/results.json
```

Schema-v3 scenarios may declare an optional `tools` array containing Ollama function definitions.
The runner records those definitions in the request and evidence but has no function dispatcher: it
never executes a returned tool call or sends a tool-result message. Ollama's native chat roles do not
include a separate developer role, so the developer arm is explicitly a labeled block inside the
system message rather than a claim about an independent API channel.

Schema-v3 scenarios may instead declare a `retrieval` object with one fixed `user_request`,
experiment-owned Markdown documents, `paragraph-v1` chunking, `ascii-token-overlap-v1` scoring,
and bounded `top_k`. Retrieval is mutually exclusive with direct notes, binary documents, images,
tools, and multi-turn history.

Schema-v3 scenarios may instead declare a `knowledge_base` object with one event-log fixture,
`through_event`, and the same bounded vectorless retrieval options. Publish events load
experiment-owned Markdown; revoke events deactivate one version; rebuild events atomically
materialize the latest non-revoked version of every source. The runner records active source state,
corpus staleness, corpus hash, retrieval, request, and response separately.

Schema-v3 scenarios may instead declare a `vector_retrieval` object with experiment-owned Markdown
documents and tenant IDs, `paragraph-v1` chunking, `ollama-embedding-cosine-v1` scoring, bounded
`top_k`, an optional tenant filter, and the fixed exact-cosine/Qdrant engine pair. This mode requires
a pinned `embedding_model`, is mutually exclusive with all other context modes, and fails closed if
embedding shapes, hashes, model identity, selected IDs, or engine scores disagree.

Schema-v3 scenarios that use the normal note/target/image path may declare `input_boundary` version
1. The policy owns one server-selected task ID and strict character, source-count, media-type, and
byte limits. Accepted content is serialized as canonical `input-envelope-v1` JSON with provenance
and `untrusted` labels; raw fixture bytes remain in the same evidence surfaces. The mode is mutually
exclusive with documents, retrieval modes, message fixtures, and tools.

The Day 6 authority experiment runs all four synthetic cases without Ollama, network access,
resource-content reads, or downstream actions:

```bash
uv run llm-security-authority \
  --experiment day-06-authority-boundary \
  > evidence/raw/day-06/results.json
uv run llm-security-authority-report evidence/raw/day-06/results.json
```

### Test

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

The test suite does not call a model or the network.

## Project structure

```text
src/          Generic runner, deterministic authority/agency/tool-boundary runners, reporters, and CLIs
experiments/  Independent definitions and synthetic fixture bundles
evidence/     Sanitized experiment checkpoints; raw runs stay ignored
tests/        Offline unit tests
docs/         Architecture and coding references
```

## Documentation

| Doc | What it covers |
|---|---|
| [SECURITY.md](SECURITY.md) | Safety boundary for deliberately vulnerable experiments |
| [docs/project-overview.md](docs/project-overview.md) | Architecture, directory map, interface, and integrations |
| [docs/coding-style.md](docs/coding-style.md) | Ruff rules, code conventions, and verification commands |

## License

Original source code and project materials in this repository are licensed under the MIT License;
see [LICENSE](LICENSE). Third-party dependencies, model artifacts, and externally supplied materials
remain under their respective licenses.
