# Day 28 — Abuse and Cost Controls

This checkpoint records one predeclared offline comparison over seven fixed synthetic event
sequences. Complete request and subject identifiers remain under ignored `evidence/raw/day-28/`;
this directory contains only reviewed counts, rejection reasons, hashes, and interpretation limits.

## Registered question

The experiment asks how separate request-rate, input-token, output-token, total-token, concurrency,
and budget controls change admission and reserved resource exposure. It compares an intentionally
unbounded path with the complete layered-control path. Each control has an isolated case so an
earlier gate does not hide the result of a later gate.

## Fixed contract

- Runner commit: `85bc250`
- Policy version: `day28-cost-control-policy-v1`
- Profiles: `2`
- Isolated cases: `7`
- Request attempts: `19`
- Raw SHA-256: `904e979a69e6372e55eca761b02ed78da29ed80a6762a405686a81948afeb72a`
- Policy SHA-256: `94cf5b59965607500040451f5862f77d11bca99246c2f55f09e6b79bff5a2d43`
- Cases SHA-256: `606a382a19d7f894b504fab0aca53578059111e79a9a4b0cac996dc81e883274`
- Recorded: `2026-08-25T08:46:10.753541Z`

The raw file is intentionally not committed. Token counts and budget units are fixed fixture
values; they are not measurements from a tokenizer, model provider, or billing system.

## Aggregate results

| Profile | Attempts | Admitted | Rejected | Estimated tokens admitted | Peak concurrency | Budget overrun |
|---|---:|---:|---:|---:|---:|---:|
| Unbounded | 19 | 19 | 0 | 1,132 | 3 | 100 |
| Layered controls | 19 | 12 | 7 | 590 | 2 | 0 |

The layered path rejected two requests at the request-rate gate and one request at each input-token,
output-token, total-token, concurrency, and budget gate. Both clean requests were admitted.

## Case results

| Case | Unbounded admitted | Controlled admitted | Controlled result |
|---|---:|---:|---|
| Clean sequential | 2 | 2 | No rejection |
| Request-rate burst | 7 | 5 | 2 request-rate rejections |
| Input-token exhaustion | 1 | 0 | 1 input-token rejection |
| Output-token reservation | 1 | 0 | 1 output-token rejection |
| Total-token exhaustion | 1 | 0 | 1 total-token rejection |
| Concurrency spike | 3 | 2 | 1 concurrency rejection |
| Budget exhaustion | 4 | 3 | 1 budget rejection |

All seven registered predictions matched the formal run.

## Interpretation limits

This is an in-memory simulator over seven isolated event sequences and one fixed policy. It does
not use a production tokenizer, stream responses, cancel work, test queues, distribute counters,
share limits across credentials, enforce IP or device limits, contact a billing provider, or model
provider-specific pricing. Each case starts with empty state and remains inside one fixed budget
window; rollover and concurrent ledger updates are not tested.

The result does not prove that the selected limits fit a production workload or prevent distributed
abuse. An attacker may rotate subject identifiers, consume downstream resources before the gate,
or target a dependency outside this simulator. The runner used only committed synthetic fixtures
and made `0` model calls, `0` network calls, `0` external side effects, and `0` real billing events.
