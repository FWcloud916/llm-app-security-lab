# LLM Application Security Lab

A versioned, synthetic-data lab for reproducing the LLM application-security experiments in the
30-day article series.

## What it does

- Runs clean and indirect Prompt Injection scenarios against a loopback Ollama endpoint.
- Fails closed when the configured model tag no longer matches the recorded full digest.
- Prints the full fixtures, request, model metadata, response, token counts, and timings as JSON.
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

Both commands send the request to the local Ollama server. Review [SECURITY.md](SECURITY.md) before
adding a scenario or fixture.

### Test

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

The test suite does not call a model or the network.

## Project structure

```text
src/          Python package and CLI
fixtures/     Synthetic notes and target documents only
scenarios/    Versioned model, prompt, and fixture selections
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
