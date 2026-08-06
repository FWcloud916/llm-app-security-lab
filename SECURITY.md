# Security Policy

This repository contains deliberately vulnerable LLM application-security experiments.

## Safety boundary

- MUST use only the committed synthetic fixtures.
- MUST NOT add real notes, credentials, personal data, production exports, or private prompts.
- MUST keep the default Ollama endpoint on `http://127.0.0.1:11434`.
- MUST NOT add tools, browser rendering, automatic downstream actions, or outbound communication to
  the Day 4 or Day 5 experiment bundles.
- MUST keep raw evidence under `evidence/raw/` or `results/`; both paths are ignored by Git.

The Day 4 and Day 5 experiments reduce the blast radius but are not an operating-system or
container sandbox.
Run experiments on a machine and account that contain no data the selected model should not see.

## Reporting a problem

Do not place sensitive details in a public issue. Use GitHub's private vulnerability reporting when
it is enabled for this repository, or contact the repository owner through their GitHub profile.
