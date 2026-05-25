# Roadmap

This is a living document. Concrete tracking happens in GitHub Issues and Projects.

## 0.1.x — Foundation (current)

- Decision pipeline with classifiers, DLP, identity, and policy engine.
- Rust execution-ring engine with PyO3 bindings.
- Fail-closed degradation and local policy cache.
- Bearer-auth HTTP control plane with per-tenant rate limits.
- Prometheus metrics, structured JSON logs, NDJSON / HTTP SIEM exporters.
- Default OWASP Agentic AI Top 10 policy bundle.
- Reference adapters for Kong, Envoy, and AWS API Gateway.
- Red-team harness covering every OWASP category.

## 0.2.x — Hardening

- OPA / Rego policy backend (in addition to the native matcher).
- gRPC control-plane surface alongside HTTP.
- WebAssembly classifier sandbox for user-supplied detectors.
- Per-tenant audit-log signing keys.
- Pluggable approval backends (Slack, Linear, PagerDuty).

## 0.3.x — Scale

- Postgres-backed identity store with logical replication.
- Multi-region active-active control plane.
- Streaming red-team harness driven by production traffic shadows.
- SOC-2-ready evidence pack auto-generation.

## 1.0.0 — GA

- Long-term API stability guarantees on `/v1/*`.
- Two-year LTS branch.
- Certified compatibility with at least three managed MCP runtimes.

Have a use case that doesn't fit here? Open an issue using the feature template.
