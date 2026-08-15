# Security Policy

This repository contains deliberately vulnerable LLM application-security experiments.

## Safety boundary

- MUST use only the committed synthetic fixtures.
- MUST NOT add real notes, credentials, personal data, production exports, or private prompts.
- MUST keep the default Ollama endpoint on `http://127.0.0.1:11434`.
- The Day 2 experiment MAY send complete experiment-owned synthetic user-message fixtures without adding
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
- The Day 16 bundle MAY replay an experiment-owned synthetic publish/rebuild/revoke event log,
  materialize its corpus in memory, and serialize one selected synthetic policy into an Ollama chat
  request. It MUST NOT use a database, call an embedding API, use a vector store, add tools, execute
  a downstream action, or communicate with an external sink.
- The Day 17 bundle MAY send only experiment-owned synthetic text to Ollama's loopback `/api/embed`
  endpoint, compare exact cosine ranking with a local in-memory Qdrant collection, and serialize the
  agreed selected chunk into one Ollama chat request. It MUST verify the full chat and embedding
  model digests, apply a declared tenant filter inside both ranking engines, keep all vectors and
  collections ephemeral, and MUST NOT add tools, execute a downstream action, or communicate with
  an external sink.
- The Day 18 agency bundle MUST use only fixed synthetic proposals, identities, policies, approval
  envelopes, mail addresses under `.test`, and an in-memory side-effect ledger. It MUST NOT call a
  model, access the network, connect to a real mailbox or payment system, or execute an external
  side effect. Its keyword findings are advisory experiment signals, not authorization decisions.
- The Day 19 tool-boundary bundle MUST use only fixed synthetic function calls, strict schemas,
  URL and output-name policies, tool output, and in-memory sink events. Its vulnerable path MAY
  record an unchecked destination or would-be shell string, but MUST NOT call a model, access the
  network, start a subprocess or shell, create the proposed file, dispatch a returned instruction,
  or execute an external side effect.
- The Day 6 authority bundle MUST use only structured synthetic fixtures and MUST NOT call Ollama,
  access the network, read resource content, or execute a downstream action.
- MUST keep raw evidence under `evidence/raw/` or `results/`; both paths are ignored by Git.

The Day 2, Day 4, Day 5, Day 7, Day 8, Day 9, Day 10, Day 11, Day 12, Day 13, Day 14, Day 15,
Day 16, and Day 17 experiments reduce the blast radius
but are not an operating-system or container sandbox. The Day 6 evaluator is an offline policy
prototype, not a production authentication or authorization service. The Day 18 evaluator is an
offline control-flow prototype, not a production mail, approval, or policy service. The Day 19
evaluator is an offline data-flow prototype, not a production URL fetcher, process runner, tool
dispatcher, or SSRF defense.
Run experiments on a machine and account that contain no data the selected model should not see.

## Reporting a problem

Do not place sensitive details in a public issue. Use GitHub's private vulnerability reporting when
it is enabled for this repository, or contact the repository owner through their GitHub profile.
