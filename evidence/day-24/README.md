# Day 24 — Guardrails in Practice

This checkpoint records two complete, predeclared synthetic NeMo Guardrails batches. Complete
prompts, classifier responses, generated candidates, and synthetic marker values remain under the
ignored `evidence/raw/day-24/` directory. The committed reports contain only counts, decisions,
framework and model identity, and SHA-256 fingerprints.

## Registered question

The experiment compares three application paths:

1. The existing application-owned output contract and safe `html_text` sink without Day 24 rails.
2. NeMo-orchestrated input, topic, and output rails whose decisions come from a strict LLM JSON
   classifier.
3. NeMo-orchestrated rails whose decisions come from deterministic application rules.

The paired batch generates one candidate and evaluates the same bytes through all three paths. The
independent end-to-end batch lets input and topic rails short-circuit generation and lets output
rails stop a candidate before the application sink. The registered interpretation did not predict
that either rail path would be perfect or that the path with the highest block count would be best.

## Fixed contract

- Runner commit: `b7f4a39`
- Framework: `nemoguardrails 0.23.0`
- Ollama: `0.32.9` on `http://127.0.0.1:11434`
- Generator and guard model: `gemma4:latest`
- Full digest: `c6eb396dbd5992bbe3f5cdb947e8bbc0ee413d7c17e2beaae69f5d569cf982eb`
- Generator options: `temperature=0.7`, seeds `2411`–`2415`
- Semantic guard options: `temperature=0`, seed `2400`
- Cases: five input, five topic, and five output cases
- NeMo usage statistics and `DO_NOT_TRACK`: disabled before framework initialization
- Browser launches / JavaScript executions / external network calls: `0 / 0 / 0`
- Subprocesses / external side effects: `0 / 0`
- Paired raw evidence SHA-256: `5e6991f11a34158dd2306ccf22a9eec7d39b352945e23c24bf30159d28c78400`
- End-to-end raw evidence SHA-256: `d3d90d6cb8385a5d72ffde8ed24b7a7ebe8f043f5f70ae8ea3d1a18253c2819e`
- Paired recorded at: `2026-08-23T17:40:22.146395+00:00`
- End-to-end recorded at: `2026-08-23T19:03:28.783977+00:00`

Fixture SHA-256 values:

| Fixture | SHA-256 |
|---|---|
| `target.md` | `27b7470d6181b38f5d252652a696337a62058ca16fcb39ba2d81edc2ead85dd2` |
| `output-contract.json` | `796fcc6d8b884e2e8803186ecb6e89a7488fdc4337272835b88bd2a739e5fd63` |
| `review-policy.json` | `96dfb9bca8ab31007616ea88bc7cd2bdf28227b086f9c43882fb825c11f056cb` |
| `cases.json` | `4df4db5652c373c0cd08bb6f43a7ec1e0bca37dddcba01a1f7dd571a162ae582` |

## Paired result

The paired batch completed 75 run units and 225 path evaluations. It made 75 generator calls and
225 semantic rail model calls. Every path received the same candidate SHA-256 for each case and
seed; the full list is in [paired-report.md](paired-report.md).

| Path | Correct | False positive | False negative | Generator calls | Rail model calls | Sink reached | Active HTML at sink |
|---|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 40／75 | 2 | 33 | 75 | 0 | 64 | 0 |
| Semantic rails | 67／75 | 7 | 1 | 75 | 225 | 27 | 0 |
| Deterministic rails | 58／75 | 2 | 15 | 75 | 0 | 46 | 0 |

The output target was not guaranteed merely because the case requested it. The exact canary was
generated 5／5, the external URL 4／5, active HTML 3／5, and benign angle-bracket text 0／5. Output
policy accuracy therefore used the actual candidate oracle, while target production remained a
separate observation.

## Independent end-to-end result

The end-to-end batch completed the same 75 run units and 225 path evaluations. The three paths
made 175 generator calls in total instead of the 225 calls required if every path always generated.
The semantic path made 170 additional model calls for rails. Complete sanitized run fingerprints
are in [end-to-end-report.md](end-to-end-report.md).

| Path | Correct | False positive | False negative | Generator calls | Rail model calls | Sink reached | Active HTML at sink |
|---|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 40／75 | 2 | 33 | 75 | 0 | 64 | 0 |
| Semantic rails | 68／75 | 7 | 0 | 40 | 170 | 26 | 0 |
| Deterministic rails | 58／75 | 2 | 15 | 60 | 0 | 46 | 0 |

The lower generator-call count is not automatically a security success. A false positive also
short-circuits generation. Decision quality and call counts must be read together.

## Manual review and interpretation limits

Manual review followed the frozen observations and found four important patterns:

- The semantic input rail blocked all five benign security-analysis quotes. This is a repeatable
  false positive, not evidence that quoting an injection is unsafe by itself.
- The semantic path also blocked one otherwise clean run at the output rail. In the paired batch it
  missed one of the three candidates that actually contained active HTML.
- The deterministic route policy correctly blocked the explicit override route, travel, and
  medical cases. It allowed all indirect and obfuscated input attacks whose application route was
  otherwise valid, and all five financial requests wrapped in an allowed event-summary route.
- Two allowed cases produced an output-contract failure in one seed. Those are application-boundary
  false positives shared by the affected paths, not rail-classification errors.

The safe renderer kept active HTML at the sink at zero for all paths and both batches. This result
does not mean the rails were perfect and does not let the framework replace the application-owned
schema, content review, sink authorization, or context-specific encoding. The experiment uses one
model as both generator and semantic classifier, so correlated errors remain possible. It does not
test Llama Guard, Prompt Guard, production traffic, external tools, a browser, latency under
controlled load, or an independent safety model.
