# Day 27 — Observability and Audit

This checkpoint records one predeclared offline comparison over a fixed synthetic request. Raw
trace attributes, complete audit records, and synthetic marker values remain under ignored
`evidence/raw/day-27/`; this directory contains only reviewed counts, versions, hashes, and
interpretation limits.

## Registered question

The experiment asks whether an OpenTelemetry trace can preserve request correlation and security
decisions without copying synthetic input or output text, and which audit-log changes an
HMAC-linked chain can detect. It compares intentionally unsafe span attributes with one fixed safe
attribute allowlist. The safe trace also supplies six canonical events to an HMAC-SHA-256 chain.

## Fixed contract

- Runner commit: `e1caf53`
- OpenTelemetry SDK: `1.44.0`
- Audit algorithm: `HMAC-SHA-256`
- Trace profiles: `2`
- Spans per profile: `7`
- Audit records: `6`
- Registered tamper cases with checkpoint: `5`
- Raw SHA-256: `a9ab1815fa4de7b8f22afe8812e6dd17049c5913bbf403ecf9bdb19bf971b1ed`
- Policy SHA-256: `737f3f1a37aa33cf1c195537f3dc106fdbf2cddbcd3883ffa927f63e1767cd07`
- Events SHA-256: `8297becfa2928cf40a5f7eb96fae83d16de9b95d5423f0aae195ddb67d901a7c`
- Recorded: `2026-08-25T07:04:40.030981Z`

The raw file and ephemeral HMAC key are intentionally not committed. The key was not persisted in
raw or sanitized evidence.

## Trace results

| Profile | Spans | Marker hits | Spans with marker values | Allowlist violations | Missing required attributes | One trace ID |
|---|---:|---:|---:|---:|---:|---:|
| Unsafe attributes | 7 | 4 | 2 | N/A | N/A | N/A |
| Safe attributes | 7 | 0 | 0 | 0 | 0 | Yes |

The unsafe root span retained the synthetic input and the output-review span retained the
synthetic output. The safe profile retained the request ID, policy version, event name, content
hashes, decisions, reason codes, PII count, and result status under one trace ID. It did not retain
either registered marker value.

## Audit results

| Check | Result |
|---|---:|
| Clean six-record chain | Verified |
| Mutated record | Detected |
| Deleted middle record | Detected |
| Reordered records | Detected |
| Inserted forged record | Detected |
| Deleted tail with terminal checkpoint | Detected |
| Deleted tail without terminal checkpoint | Valid prefix |

All five registered tamper cases were detected when the verifier received the signed terminal
checkpoint. Removing the last record without supplying that checkpoint left a valid shorter
prefix. The experiment therefore treats an independently retained checkpoint as a separate
control, not as an automatic property of the HMAC chain.

## Interpretation limits

This is one synthetic request, two in-memory traces, one attribute policy, six events, and one
ephemeral key. It does not assess an OpenTelemetry Collector, backend storage, sampling, export,
retention, access control, SIEM correlation, key rotation, clock trust, concurrency, multi-service
propagation, or production incident response.

An HMAC chain detects changes only for a verifier that has the secret key and the expected terminal
checkpoint. It does not make storage append-only, stop an authorized operator from deleting both
events and checkpoints, provide public verification, or prove that the event contents were true
when recorded. The runner used only committed synthetic fixtures and made `0` model calls, `0`
network calls, and `0` external side effects.
