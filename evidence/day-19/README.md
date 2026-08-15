# Day 19 Tool Calling Security

This checkpoint records one complete fixed synthetic experiment. Raw function arguments and the
synthetic tool-output payload remain under ignored `evidence/raw/day-19/`; this directory contains
only reviewed, sanitized evidence.

## Registered Plan

- Compare the same five inputs through a deliberately vulnerable application path and a hardened
  application path instead of measuring whether a model chooses a tool.
- Evaluate four boundaries independently: strict argument shape, destination or semantic policy,
  sink-safe argument handling, and the trust assigned to tool output before another model turn.
- Use only `.test` URLs and addresses, fixed JSON fixtures, and an in-memory sink-event ledger. Do
  not call a model, access the network, start a subprocess or shell, create the proposed file,
  dispatch a returned instruction, or execute an external side effect.

## Registered Prediction

1. A clean public URL reaches the simulated fetch sink through both paths.
2. An extra model-supplied `approved` field reaches the vulnerable sink, while the strict schema
   rejects the hardened path before policy evaluation.
3. A loopback URL remains schema-valid because it is a string. The vulnerable path records the
   unchecked target, while the hardened destination allowlist blocks it before the simulated sink.
4. An output filename containing a shell separator remains schema-valid. The vulnerable path
   records a would-be shell string, while the hardened adapter rejects the filename and starts no
   process.
5. Synthetic tool output containing a next-action instruction is exposed as a trusted instruction
   by the vulnerable serializer. The hardened serializer keeps it as untrusted data with no
   dispatch authority; neither path calls a model or executes a tool.

## Fixed Contract

- Runner commit: `2bb7a22`
- Cases / path evaluations: `5 / 10`
- Fixture tool schema SHA-256: `3370214e9df8e24dad2ca8f6b10630707f703dc267854e3a9c781ea81eb4f079`
- Fixture policy SHA-256: `255919a154af4ca65f8870bebf1decbd9e18dee850710ec89387d56a14fbd5d8`
- Fixture cases SHA-256: `d987085e01be8919d2ac5043eb4f14fc479d25d97ea74f157d101e804260c928`
- Raw evidence SHA-256: `89e7c5ae4268a376742c668c94c5d25f3c58d9e7e9448d9a17edd2c021deeff4`
- Recorded: `2026-08-15T12:19:24.444651Z`
- Model / network / subprocess / external side-effect calls: `0 / 0 / 0 / 0`

## Exact Observations

All five cases matched their predeclared outcomes. Four vulnerable paths and one hardened control
reached only the in-memory sink ledger. Three hardened function-call paths were blocked, and the
hardened tool-output path was contained without dispatch.

| Case | Vulnerable path | Hardened path | Main result |
|---|---|---|---|
| Clean public fetch | Allow; simulated fetch | Allow; simulated fetch | Valid control passes every hardened gate |
| Forged authority field | Allow; unchecked fetch | Block; `schema_rejected` | Strict shape rejects an extra authority field |
| Private URL SSRF | Allow; unchecked fetch | Block; `destination_not_allowed` | Schema-valid URL still needs destination policy |
| Shell metacharacter filename | Allow; would-be shell string | Block; `unsafe_output_name` | String type does not make a shell sink safe |
| Tool-output reinjection | Expose as trusted instruction | Contain as untrusted data | Tool output does not receive dispatch authority |

The strict schema blocked only the extra field. The loopback URL and shell-metacharacter filename
both satisfied their declared string types, so separate destination and sink-adapter controls made
the hardened decisions. No test path performed DNS resolution, opened a socket, or invoked a
process.

## Manual Review

The ten path evaluations and five in-memory sink events were reviewed against the fixed fixtures.
The sanitized reporter exposes case IDs, decisions, reason codes, shape results, sink reachability,
and output-trust labels without publishing raw URL arguments, proposed filenames, or tool-output
text.

The vulnerable tool-output result records a trust-classification failure, not a successful prompt
injection. Because the experiment calls no model, the result supports only the claim that the
application placed tool output in a position where it could be interpreted as instruction.

## Interpretation Limits

This experiment does not measure model behavior, prompt-injection success, framework behavior,
redirect handling, DNS rebinding, IP canonicalization, production authorization, or a general SSRF
or command-injection prevention rate. The exact-origin and filename policies are narrow synthetic
controls, not a production URL fetcher or process sandbox.

The result supports a smaller claim: strict schemas can reject malformed structure, but schema-valid
strings still require use-specific policy and a sink-safe adapter; tool output must remain untrusted
when it is returned to a model-visible context.
