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
- The Day 20 supply-chain bundle MUST use only fixed synthetic artifact manifests and read-only
  inspection of committed `uv.lock` and experiment definitions. It MAY record hashes, counts, and
  declared paths, but MUST NOT load a model artifact, install or import a candidate package, start
  an MCP Server, access the network, start a subprocess, read credentials, or execute an external
  side effect.
- The Day 21 Agent attack-chain bundle MAY retrieve experiment-owned synthetic Markdown, send two
  strict function schemas to the digest-pinned loopback Ollama model, return one experiment-owned
  synthetic case record, and record a proposed send operation in a process-local ledger. It MUST
  reject parallel calls, unknown tools, undeclared cases, repeated calls, invalid arguments, and
  calls beyond the fixed turn limit. Every recipient MUST use the reserved `.test` suffix. It MUST
  NOT access an external network, send email, start a subprocess, read real data, or execute an
  external side effect.
- The Day 6 authority bundle MUST use only structured synthetic fixtures and MUST NOT call Ollama,
  access the network, read resource content, or execute a downstream action.
- The Day 22 input-defense bundle MAY repeat the complete Day 14 synthetic matrix through paired
  baseline and defended paths. The defended path MAY validate task-specific text, source-count,
  PNG media, and size limits before serializing an application-owned task ID plus provenance-labeled
  untrusted inputs as canonical JSON. The bundle MUST NOT treat valid JSON or labels as an
  authorization boundary, run OCR, add tools, execute downstream actions, or communicate with an
  external sink.
- The Day 23 output-defense bundle MAY send only bundle-owned synthetic text to digest-pinned
  loopback Ollama and feed each resulting candidate into paired unescaped and defended HTML-text
  paths. The vulnerable path MAY retain would-be active HTML and external-resource references as
  raw evidence. Both paths MUST use only the standard-library inert HTML parser oracle; they MUST
  NOT launch a browser, execute JavaScript, resolve a URL, open a socket beyond loopback Ollama,
  start a subprocess, or create an external side effect.
- The Day 24 Guardrails bundle MAY use NeMo Guardrails to orchestrate bundle-owned semantic and
  deterministic input, topic, and output checks around digest-pinned loopback Ollama. It MAY retain
  complete synthetic requests and responses only in ignored raw evidence. It MUST disable NeMo
  usage telemetry, MUST keep model traffic on `127.0.0.1`, MUST retain the Day 23 schema, content
  review, sink authorization, and HTML-text escaping boundary, and MUST NOT launch a browser,
  execute JavaScript, resolve or fetch an external URL, start a subprocess, or create an external
  side effect.
- The Day 24 Prompt Guard extension MAY compare the semantic and deterministic input rails with
  `meta-llama/Llama-Prompt-Guard-2-86M` using only bundle-owned synthetic input. The Prompt Guard
  artifact MUST already exist in the local Hugging Face cache, match the bundle's exact revision
  and file hashes, and load with offline and `local_files_only` controls. The runner MUST reject
  input beyond its fixed 512-token contract. It MUST NOT download or update a model during a run,
  call a generator, reach an output sink, launch a browser, execute JavaScript, access an external
  network, start a subprocess, or create an external side effect. Loopback Ollama MAY be used only
  by the comparison's digest-pinned semantic input rail.
- The Day 25 sandbox bundle MAY ask the digest-pinned loopback model for strict synthetic action
  proposals and MAY start the digest-pinned Alpine image through exact Docker argument vectors.
  The hardened profile MUST use a non-root user, a read-only root filesystem, no network, no Linux
  capabilities, no-new-privileges, bounded memory, CPU, and process counts, a read-only public
  fixture, and an ephemeral writable directory. The intentionally vulnerable comparison MAY mount
  only temporary copies of the bundle-owned public and private fixtures. The workload MUST be the
  committed fixed script, MUST NOT interpret model-authored commands, URLs, paths, or shell text,
  and MUST NOT make a network request or create an external side effect.
- The Day 26 PII bundle MUST use only its 24 labeled synthetic cases and fixed policy. It MAY load
  the uv-locked Presidio packages and `en_core_web_sm` model already installed in the local
  environment. It MUST NOT download or update a package or model during a run, call an LLM, access
  the network, read real personal data, persist an index, or create an external side effect. Raw
  synthetic values MAY appear only in ignored raw evidence; the sanitized report MUST expose only
  counts, versions, and fixture hashes.
- The Day 27 observability bundle MUST use only its fixed synthetic request, safe attribute policy,
  and six declared audit events. It MAY compare intentionally unsafe in-memory span attributes with
  an allowlisted metadata-only trace and MAY create an ephemeral HMAC-SHA-256 audit key. It MUST
  NOT export telemetry, persist or print the HMAC key, call an LLM, access the network, read real
  personal data, or create an external side effect. Raw synthetic text and complete audit records
  MAY appear only in ignored raw evidence; sanitized reports MUST expose only counts, versions,
  verification outcomes, and fixture hashes.
- The Day 28 cost-control bundle MUST use only its fixed synthetic request and completion events,
  synthetic subject identifiers, token counts, and rate, token, concurrency, and budget policy. It
  MAY compare an intentionally unbounded in-memory path with the complete deterministic control
  path. It MUST NOT call a model, access the network, contact a billing provider, use real identity
  or payment data, or create an external side effect. Complete request and subject identifiers MAY
  appear only in ignored raw evidence; sanitized reports MUST expose only case IDs, counts,
  rejection reasons, fixture hashes, and resource totals.
- MUST keep raw evidence under `evidence/raw/` or `results/`; both paths are ignored by Git.

The Day 2, Day 4, Day 5, Day 7, Day 8, Day 9, Day 10, Day 11, Day 12, Day 13, Day 14, Day 15,
Day 16, Day 17, Day 22, Day 23, and Day 24 experiments reduce the blast radius
but are not an operating-system or container sandbox. The Day 6 evaluator is an offline policy
prototype, not a production authentication or authorization service. The Day 18 evaluator is an
offline control-flow prototype, not a production mail, approval, or policy service. The Day 19
evaluator is an offline data-flow prototype, not a production URL fetcher, process runner, tool
dispatcher, or SSRF defense. The Day 20 evaluator is an offline intake-policy prototype, not a
malware scanner, signature verifier, package installer, model loader, MCP client, or sandbox. The
Day 21 runner is an intentionally vulnerable orchestration prototype; it is not an email client,
data connector, authorization service, or production Agent framework. The Day 22 input boundary is
a task-specific validation and serialization prototype, not a prompt-injection firewall or an
instruction/data parser boundary. The Day 23 output boundary is a text-only renderer prototype,
not a browser, rich-HTML sanitizer, content-classification service, or general XSS scanner.
The Day 24 runner is a comparison harness, not a production policy service, prompt-injection
firewall, or proof that an LLM classifier is independent from the model it judges. The Prompt
Guard extension tests one binary prompt-attack classifier on five synthetic Chinese inputs; it is
not a topic classifier, output classifier, multilingual benchmark, or production deployment claim.
The Day 25 runner is a bounded least-privilege experiment, not a production authorization service,
general-purpose command sandbox, container escape assessment, or proof that Docker alone makes an
Agent safe.
The Day 26 runner is a small English-language synthetic benchmark, not a production PII inventory,
Taiwan privacy-law compliance assessment, multilingual benchmark, or proof that masking repairs an
authorization failure.
The Day 27 runner is an offline trace-and-integrity prototype, not a production telemetry backend,
SIEM, key-management system, append-only storage service, or proof that HMAC prevents authorized
deletion. Tail truncation requires an independently retained terminal checkpoint.
The Day 28 runner is an offline admission-control simulator, not a production gateway, distributed
rate limiter, tokenizer, queue, billing ledger, or proof that one subject identifier prevents
distributed abuse. Its token counts and budget units are fixed synthetic fixture values.
Run experiments on a machine and account that contain no data the selected model should not see.

## Reporting a problem

Do not place sensitive details in a public issue. Use GitHub's private vulnerability reporting when
it is enabled for this repository, or contact the repository owner through their GitHub profile.
