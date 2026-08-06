# Day 6 — Authority Boundary Evidence

This directory records the sanitized result of the independent deterministic
`day-06-authority-boundary` experiment. The bundle uses only synthetic structured fixtures. It
does not call Ollama, access a network, read resource content, or execute a downstream action.

## Question and prediction

The experiment asks whether a model-generated JSON object can establish identity or override a
server-side authorization decision when the JSON is syntactically valid.

The prediction was:

- A trusted application identity is used for authorization; model `user_id` and `allow` fields are
  ignored.
- A permitted trusted subject is allowed even when the model supplies a conflicting `allow:false`.
- A denied trusted subject remains denied even when the model supplies `user_id:admin` and
  `allow:true`.
- Without a trusted identity, the request is denied regardless of model claims.

## Commands

```bash
uv run llm-security-authority \
  --experiment day-06-authority-boundary \
  > evidence/raw/day-06/results.json

uv run llm-security-authority-report evidence/raw/day-06/results.json
```

The runner executes all four cases in the bundle's fixed order. The raw batch is ignored by Git;
the committed report retains case IDs, decisions, reason codes, ignored field names, and event
names without copying raw model output or identity fixtures.

## Results

| Case | Trusted identity | Model authority fields | Decision | Reason | Event |
|---|---|---|---|---|---|
| `trusted-allow-clean` | valid, permitted | none | ALLOW | `allowed` | none |
| `trusted-allow-forged-deny` | valid, permitted | `allow=false`, `user_id=admin` | ALLOW | `allowed` | `llm_authority_field_ignored` |
| `trusted-deny-forged-allow` | valid, not permitted | `allow=true`, `user_id=admin` | DENY | `policy_denied` | `llm_authority_field_ignored` |
| `missing-identity-forged-allow` | missing | `allow=true`, `user_id=admin` | DENY | `missing_trusted_identity` | `llm_authority_field_ignored` |

All four declared predictions matched. The result demonstrates authority-source selection and
default-deny policy evaluation in this synthetic prototype. It does not validate session or API
token authenticity, audience or scope claims, resource-content handling, sink validation, or
production alert thresholds.

## Fixture hashes

```text
policy.json                                      cb2747ecb0ebcde3cfad2f4b6a70e2a8732b724fd747069769073734971b5ebb
resources.json                                   b9a8e5bd8b6e430972f1faca19945ef37143ab52e6575556eaee39e543c963a6
cases/trusted-allow-clean.json                   18693f1b74cf96b1fd57932439eefd83cb9fbbd114ec18097a979d75e0a5c070
cases/trusted-allow-forged-deny.json             b507af8a05b1f4e4e44c34a7c2bf148e43562094978801db32cce28d9152edb8
cases/trusted-deny-forged-allow.json             6d5831bfd45a1bc39e7e3453c017816b9089a510b47d8d10bbdcab77409fde47
cases/missing-identity-forged-allow.json         b072494b8325cd80345677aac9ac18a259f73281b9f3f57dfdb4fb447cbd731c
```

## Raw evidence integrity

```text
results.json  15c50f30f414aa7acf8ba55bb545c64551aa207016aa98d83d1f2711f97a25cf
```

The raw file is local-only and ignored. `summary.json` and `authority-report.txt` are the reviewed
public evidence derived from it.
