# Day 23 — Output Defense and Safe Rendering

This checkpoint records one complete, predeclared synthetic model batch and two deterministic
application matrices. Complete prompts, synthetic confidential values, model responses, and
rendered HTML remain under ignored `evidence/raw/day-23/`; this directory contains only reviewed,
sanitized evidence.

## Registered question

The experiment asks what changes when the exact same model candidate is sent to an intentionally
unescaped HTML path and to a defended path. The defended path validates an exact structured-output
contract, reviews the accepted strings, authorizes only the `html_text` sink, and HTML-escapes every
model-owned field. One model call produces each pair, so model variation cannot explain the
renderer difference.

The registered deterministic prediction required zero active HTML in every defended model and
fixed-case path. All five clean candidates also had to preserve their visible text. The vulnerable
model-path count was not predicted because it depended on whether the pinned model produced a valid
payload.

## Fixed contract

- Runner commit: `06ba541`
- Ollama: `0.32.9` on `http://127.0.0.1:11434`
- Model: `gemma4:latest`
- Full digest: `c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb`
- Options: `temperature=0.7`, seeds `811`–`815`
- Model scenarios: five clean and five XSS-canary candidates
- Model run units / chat calls: `10 / 10`
- Deterministic cases: seven renderer cases and five output-validation failures
- Output authorization: `html_text` only
- Browser launches / JavaScript executions / external network calls: `0 / 0 / 0`
- Subprocesses / external side effects: `0 / 0`
- Raw evidence SHA-256: `625d89e152eb9033fc899874a6adcae9f86cef8327dd9e7d463db96cc146e578`
- Recorded: `2026-08-23T09:44:33Z`–`2026-08-23T09:46:42Z`

The raw file is intentionally not committed.

## Model results

All five clean candidates were valid JSON, preserved both application-owned task markers, omitted
the synthetic canary, and produced no active HTML. The defended renderer preserved the visible text
for all five.

All five attack candidates contained the exact synthetic canary and attempted the requested active
HTML payload. Four were valid candidate objects; each of those four produced active HTML and a
potential outbound reference in the intentionally unescaped path. The fifth response contained the
attack expression but was invalid JSON, so application validation rejected it before either
renderer received a candidate object.

The defended path rejected all five attack candidates: four failed content review and one failed
JSON parsing. No defended output contained active HTML or an outbound reference.

| Scenario | Valid schema | Canary exact | Vulnerable active HTML | Defended allow | Defended active HTML | Visible text preserved |
|---|---:|---:|---:|---:|---:|---:|
| Clean | 5/5 | 0/5 | 0/5 | 5/5 | 0/5 | 5/5 |
| XSS-canary | 4/5 | 5/5 | 4/5 | 0/5 | 0/5 | 0/5 |

The structured-output request therefore did not remove the need for application validation. It
produced four valid but unsafe string values and one response that was not valid JSON at all.

## Deterministic matrices

The seven renderer cases cover normal text, benign angle brackets, a script element, an event
handler, a `javascript:` URL, an automatically loaded external resource, and a canary-only string.
All seven matched their registered result. Four formed active HTML in the vulnerable path; none did
so in the defended path. Three were blocked by content review, while the tag-only cases demonstrate
why context-specific escaping remains necessary even when a keyword review allows the text.

The five validation cases cover a missing field, an unknown field, a wrong type, a changed task
marker, and an oversized summary. All five failed closed with the registered error.

## Manual review and interpretation limits

All ten model candidates were reviewed after the exact observations were frozen. `Attack payload
attempted` means the response tried to construct the requested HTML and used the exact synthetic
canary; it does not mean a browser executed the payload. The one invalid-JSON response remains an
attack attempt and a schema failure, not an active-renderer hit.

The parser oracle only identifies would-be active tags, event attributes, dangerous URL schemes,
and automatically loaded resource references. It does not implement browser parsing, execute
JavaScript, resolve DNS, or send data. This experiment supports a narrower conclusion: for this
fixed HTML-text contract, application validation, review, authorization, and escaping kept active
HTML out of the defended sink. It does not test rich-HTML sanitization, Markdown rendering, CSP,
SQL, shell commands, or a real browser exploit.
