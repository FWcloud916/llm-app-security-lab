# Day 20 AI Supply Chain Security

This checkpoint records one complete fixed synthetic experiment plus a read-only audit of committed
repository metadata. Raw artifact manifests remain under ignored `evidence/raw/day-20/`; this
directory contains only reviewed, sanitized evidence.

## Registered Plan

- Audit the repository's committed Python lock metadata, model references, and declared MCP Server
  configuration without importing, loading, installing, or starting any candidate component.
- Apply one deterministic `ALLOW / REVIEW / BLOCK` policy to nine fixed synthetic manifests: three
  models, three packages, and three MCP Servers.
- Evaluate identity, integrity, provenance, executable format, and runtime capability separately.
- Make no model or network call, install no package, load no artifact, start no MCP Server or
  subprocess, and execute no external side effect.

## Registered Prediction

1. Each component class has one complete synthetic evidence set that is allowed.
2. A mutable model reference without a digest, a package without provenance, and MCP tool
   annotations without a capability declaration require review.
3. A signed pickle model, a package whose hash mismatches, and an MCP Server whose capabilities
   drift from the reviewed declaration are blocked.
4. The repository audit records existing hashes and digests without treating them as proof of
   origin or runtime safety.

## Fixed Contract

- Runner commit: `04800e0`
- Cases: `9` (`3` model / `3` package / `3` MCP Server)
- Repository-audit fixture SHA-256: `485c65fdff695b4c1ea959d4495f4335b3112699bfe061274a203a39e44976a2`
- Policy fixture SHA-256: `89d65cde51b4fec1ef65a2eec2e39713f7e64f189f692c7f4f11b9a44627e0ef`
- Cases fixture SHA-256: `53ca2afc2de7291eb20bd54ebef3c00c45945df4cb6c86b61bbf6848796c5ffa`
- Raw evidence SHA-256: `74b7ace3cc9802d0acd73d30382667fc35158924662517589b035f98b55c4c40`
- Recorded: `2026-08-15T15:41:33.375598Z`
- Model / network / install / artifact-load / MCP-start / subprocess / external calls:
  `0 / 0 / 0 / 0 / 0 / 0 / 0`

## Repository Audit

| Component | State | Recorded evidence | Missing evidence |
|---|---|---|---|
| Python packages | `REVIEW` | `uv.lock`: 32 packages, 436 distinct artifact hashes | Build provenance is not recorded |
| Model references | `REVIEW` | 15 references; all have full SHA-256 digests; 2 unique name/digest pairs | Artifact format and signature or provenance are not recorded |
| MCP Servers | `NOT_CONFIGURED` | Three declared config paths checked; none present | No server or capability declaration to assess |

The lock file itself had SHA-256
`7a38da2bf0ec0fdc4b3d9d373eb0ea5f0bb43641146a84be1c0a637ce0ab681f` during the run.

## Exact Observations

All nine cases matched their predeclared outcomes: three `ALLOW`, three `REVIEW`, and three `BLOCK`.

| Case | Component | Decision | Main reason |
|---|---|---|---|
| Complete model evidence | Model | `ALLOW` | Identity, digest, provenance, allowed format, and policy matched |
| Mutable model without digest | Model | `REVIEW` | Immutable reference and SHA-256 were missing |
| Signed pickle | Model | `BLOCK` | Signed origin did not make the executable format safe |
| Complete package evidence | Package | `ALLOW` | Exact version, digest, provenance, and policy matched |
| Package without provenance | Package | `REVIEW` | Integrity metadata did not explain how the artifact was produced |
| Package hash mismatch | Package | `BLOCK` | Observed artifact integrity did not match the reviewed evidence |
| Complete MCP declaration | MCP Server | `ALLOW` | Tool snapshot and runtime capabilities matched the reviewed declaration |
| Tool annotations only | MCP Server | `REVIEW` | Annotations did not establish identity, provenance, scopes, hosts, secrets, or token handling |
| MCP capability drift | MCP Server | `BLOCK` | Filesystem and outbound-host capabilities changed after review |

## Manual Review

The nine decisions, missing-evidence lists, repository counts, fixture hashes, and zero-activity
safety boundary were reviewed against the fixed fixtures and raw evidence. The sanitized reporter
exposes case IDs, decisions, reason codes, and evidence-field names without publishing synthetic
artifact identifiers, host values, filesystem roots, or secret names.

The repository audit is intentionally conservative. A lock hash or model digest supports integrity
and repeatability, but does not by itself establish the publisher, build process, artifact format,
or runtime authority. An absent MCP configuration means only that the declared paths contained no
configuration at this commit; it is not proof that no external MCP Server exists elsewhere.

## Interpretation Limits

This experiment does not scan for malware, verify a real signature, reproduce a build, install a
package, deserialize a model, inspect model behavior, connect to a registry, start an MCP Server,
or test a production sandbox. The policy fields and three-way decisions are an intake prototype,
not a certification system.

The result supports a smaller claim: supply-chain intake needs an evidence chain that distinguishes
what an artifact is, whether its bytes match, where it came from, what can execute, and which
runtime capabilities it receives. A name, signature, hash, or annotation answers only part of that
chain.
