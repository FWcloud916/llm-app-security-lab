# Security Policy

This repository contains deliberately vulnerable LLM application-security experiments.

## Safety boundary

- MUST use only the committed synthetic fixtures.
- MUST NOT add real notes, credentials, personal data, production exports, or private prompts.
- MUST keep the default Ollama endpoint on `http://127.0.0.1:11434`.
- The Day 2 rerun MAY send complete experiment-owned synthetic user-message fixtures without adding
  a wrapper. It MUST NOT add notes, retrieval, documents, images, tools, actions, or an external
  sink.
- MUST NOT add tools, browser rendering, OCR, automatic downstream actions, or outbound communication
  to the Day 4, Day 5, Day 7, Day 8, Day 9, Day 10, or Day 11 model experiment bundles.
- The Day 12 bundle MAY send synthetic function schemas to Ollama. It MUST NOT provide a function
  implementation, execute a returned tool call, add a tool-result message, or communicate with an
  external sink.
- The Day 13 bundle MAY send experiment-owned synthetic PNG fixtures to Ollama's native vision
  input. It MUST NOT run OCR, add tools, execute a downstream action, or communicate with an
  external sink.
- The Day 14 bundle MAY combine experiment-owned synthetic PNGs, direct and indirect text,
  multi-turn history, and encoded instructions in one fixed assessment. It MUST NOT run OCR, add
  tools, execute a downstream action, or communicate with an external sink.
- The Day 15 bundle MAY run deterministic in-memory paragraph retrieval over experiment-owned
  synthetic Markdown fixtures and serialize selected chunks into one Ollama chat request. It MUST
  NOT call an embedding API, use a vector database, persist an index, add tools, execute a
  downstream action, or communicate with an external sink.
- The Day 6 authority bundle MUST use only structured synthetic fixtures and MUST NOT call Ollama,
  access the network, read resource content, or execute a downstream action.
- MUST keep raw evidence under `evidence/raw/` or `results/`; both paths are ignored by Git.

The Day 2, Day 4, Day 5, Day 7, Day 8, Day 9, Day 10, Day 11, Day 12, Day 13, Day 14, and Day 15
experiments reduce the blast radius
but are not an operating-system or container sandbox. The Day 6 evaluator is an offline policy
prototype, not a production authentication or authorization service.
Run experiments on a machine and account that contain no data the selected model should not see.

## Reporting a problem

Do not place sensitive details in a public issue. Use GitHub's private vulnerability reporting when
it is enabled for this repository, or contact the repository owner through their GitHub profile.
