# LLM Application Security Lab

A versioned, synthetic-data lab for reproducing the LLM application-security experiments in the
30-day article series.

## What it does

- Runs independent, versioned experiment bundles against a loopback Ollama endpoint.
- Fails closed when the configured model tag no longer matches the recorded full digest.
- Prints the full fixtures, request, model metadata, response, token counts, and timings as JSON.
- Executes predeclared schema-v3 run plans without prompt, seed, or temperature CLI overrides.
- Runs the Day 6 deterministic authority-boundary bundle without a model or network call.
- Preserves stable milestone tags so an article can point to the exact code it described.

## Quickstart

### Prerequisites

- Python 3.11 or newer
- [uv](https://docs.astral.sh/uv/)
- Ollama listening on `http://127.0.0.1:11434`

The Day 4 checkpoint expects `gemma4:latest` with digest
`c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb`. The model artifact is not
stored in Git. Using another model or digest creates a new result rather than an exact reproduction.

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
src/          Generic runner, deterministic authority runner, reporters, Ollama client, and CLIs
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
