# Day 29 — Bounded AI Red Teaming

This checkpoint records one bounded integration run of garak 0.16.0 and PyRIT 1.0.1 against the
same deterministic loopback application. Complete prompts and responses remain under ignored raw
evidence. This directory contains only reviewed hashes, counts, fixed case identifiers, and
interpretation limits.

## Registered question

The experiment asks whether two current red-team tools can drive one local application endpoint
under a fixed request budget and preserve independently auditable results. The endpoint contains
intentional marker-returning branches so the run tests orchestration, request transport, result
collection, and reporting rather than model quality.

## Fixed contract

- Runner commit: 18d28c7
- Endpoint: http://127.0.0.1:18029/generate
- garak: 0.16.0, four requests
- PyRIT: 1.0.1, four attack cases plus one control
- Total request cap: 9
- Raw SHA-256: 5345c0942e055b73e660d462a72d4f9230cc1aea56881eaa4246b9658d819297
- garak lock SHA-256: 2ce39dd139076a01ef4bbb2cd3d0601f9879c46e6ddf28b5173aa6617bd4ccd3
- PyRIT lock SHA-256: 18d02971d3e54bb35fd7485672e15457566a8f73a1ee76cd060527e03eee2985
- PyRIT case SHA-256: 415aa8e7ad9dfe41268f94b800b07df0c2a81c1f33fdb791e18f76e5e8b5f41d
- Recorded: 2026-08-25T11:06:39.985312Z

The two tools use separate Python 3.12 locks. garak 0.16.0 requires datasets below version 4, while
PyRIT 1.0.1 requires datasets 4.8 or newer; forcing both into one environment would make the
dependency set unsatisfiable.

## Results

| Tool | Requests | Attack findings | Control findings |
|---|---:|---:|---:|
| garak 0.16.0 | 4 | 4 | Not included |
| PyRIT 1.0.1 | 5 | 4 | 0 |

garak ran the bounded PromptInject HijackHateHumans probe and its own rogue-string detector. PyRIT
sent four fixed attack objectives and one benign control through HTTPTarget; the Lab runner
evaluated whether the deterministic response contained each registered synthetic marker. All
three registered predictions matched.

## Interpretation limits

The garak and PyRIT numbers are not a comparative benchmark. They use different prompt sources and
result evaluators, so four findings from one tool do not imply equal coverage or severity in the
other. The endpoint is an intentionally vulnerable deterministic test double and does not contain
an LLM, retrieval system, tool implementation, content filter, or production data.

This run demonstrates a bounded, reproducible tool integration. It does not show that either tool
can discover unknown weaknesses in a real model application, and it does not measure false
negatives outside the five fixed PyRIT cases and one bounded garak probe. The run made 0 model
calls, 9 loopback requests, 0 external network calls, and 0 external side effects.
