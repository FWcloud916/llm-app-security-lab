# LLM Application Security Lab — Agent Guide

This project owns versioned, synthetic-data experiments for the 30-day LLM application-security series.

## Hard constraints

- MUST use only synthetic fixtures and MUST NOT commit real notes, credentials, personal data, or production exports (source: `SECURITY.md`).
- MUST keep the Day 4 model endpoint on `http://127.0.0.1:11434` (source: `SECURITY.md`, `src/llm_security_lab/ollama.py`).
- MUST verify the configured full model digest before inference and fail closed on a mismatch (source: `scenarios/day-04-vulnerable-baseline/scenario.json`, `src/llm_security_lab/lab.py`).
- MUST NOT add tools, external rendering, automatic actions, or outbound communication to the Day 4 baseline (source: `SECURITY.md`).
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
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

## Conventions

- Keep scenario definitions versioned under `scenarios/<milestone>/`; do not hide experiment inputs in code.
- Treat a model or digest change as a new result and preserve the earlier evidence.
- Keep raw output under ignored paths; commit only reviewed, sanitized evidence summaries.

## Docs maintenance

When modifying any file under `docs/`, update its `> **Last updated:** YYYY-MM-DD` frontmatter to today's date. Requirement keywords (MUST, SHOULD, MAY) follow RFC 2119.
