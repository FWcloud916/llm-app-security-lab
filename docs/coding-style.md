# LLM Application Security Lab — Coding Style Guide

> **Type:** Reference / How-to
> **Audience:** Developers, AI assistants, code reviewers
> **Last updated:** 2026-08-25
>
> This document describes the coding style conventions for LLM Application Security Lab.
> It covers both **linter-enforced rules** and **team conventions** that cannot be auto-checked.
>
> Configuration source: `pyproject.toml`
>
> **Terminology:** This document uses RFC 2119 keywords —
> **MUST** (mandatory), **SHOULD** (recommended), **MAY** (optional).

---

## 1. Linter Overview

Ruff targets Python 3.11 with a 100-character line length. Ruff checks the package, tests, and
configuration examples; no source directory is excluded. Pytest discovers tests under `tests/`.

## 2. Linter Rules Summary

| Rule group | Configured value |
|---|---|
| Python target | `py311` |
| Line length | `100` |
| Pycodestyle | `E4`, `E7`, `E9` |
| Pyflakes | `F` |
| Import sorting | `I` |
| Pyupgrade | `UP` |
| Bugbear | `B` |

## 3. Project-Specific Code Examples

`src/llm_security_lab/ollama.py` validates the complete origin in `__post_init__` before any request.
`src/llm_security_lab/lab.py` resolves each fixture and then checks containment before reading it.
Both boundaries raise explicit exceptions instead of silently falling back.

## 4. Team Conventions (Not Enforced by the Linter)

### 4.1 Preserve experiment identity

Code that changes the model, digest, prompt, fixture order, or inference options MUST create a new
experiment bundle rather than rewriting earlier evidence. A bundle MUST own its fixtures and MUST
NOT reference fixture paths from another experiment.

### 4.2 Keep model-visible data declarative

Each `experiments/<experiment-id>/experiment.json` and adjacent `fixtures/` directory SHOULD contain
all model-visible inputs. Python code SHOULD implement the execution mechanism without hiding
payload text or experiment-specific fixture order.

### 4.3 Fail closed at safety boundaries

Unexpected model identity, non-loopback origins, path escape, symlinks, and unknown scenario schema
versions MUST stop execution. Code MUST NOT replace a failed check with an implicit default.

## 5. Architecture Conventions

- `cli.py` owns argument parsing and human-facing errors.
- `lab.py` owns scenario loading, fixture validation, model preflight, and evidence assembly.
- `ollama.py` owns HTTP transport and the loopback restriction.
- `guardrails.py` owns Day 24 rail orchestration, strict classifier parsing, short-circuit behavior,
  and sanitized comparison evidence.
- `prompt_guard.py` owns the independent Day 24 input-only comparison, verified local model loading,
  fixed 512-token contract, and sanitized evidence.
- `sandboxing.py` owns Day 25 strict proposals, deterministic authorization, exact Docker argument
  construction, containment evidence, and sanitized reports. Model-authored text MUST NOT enter a
  shell command or Docker option.
- `pii.py` owns Day 26 labeled synthetic cases, deterministic patterns, optional Presidio loading,
  normalized spans, masking metrics, and sanitized reports. Presidio results MUST NOT become an
  authorization decision.
- Tests MUST use fake clients; the default unit-test gate MUST NOT call a model or the network.
- Secrets MUST NOT enter source, fixtures, snapshots, logs, or committed evidence.

## 6. Running the Linter (Pre-merge)

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

## 7. References

- [Project overview](project-overview.md)
- [Repository safety policy](../SECURITY.md)
- [Ruff configuration](../pyproject.toml)
