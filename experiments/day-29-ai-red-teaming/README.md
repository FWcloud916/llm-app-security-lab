# Day 29 — Bounded AI Red Teaming

This bundle runs garak 0.16.0 and PyRIT 1.0.1 against the same synthetic loopback application.
Each tool has an independent uv lock because their current datasets requirements conflict.

The run is capped at four garak requests and five PyRIT requests. The endpoint is a deterministic
test double with intentionally vulnerable branches. It does not call a model, execute tools, use
real data, or contact an external service.
