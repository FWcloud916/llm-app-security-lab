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
uv run llm-security-report evidence/raw/day-05/clean.json
uv run llm-security-authority --experiment day-06-authority-boundary
uv run llm-security-authority-report evidence/raw/day-06/results.json
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
