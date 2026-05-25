# OWASP Agentic AI Top 10 — Coverage Mapping

This document maps each OWASP Agentic AI Top 10 risk to the sentinel control(s) that mitigate it. It is also surfaced as the default rule set in `config/policies/default.yaml`.

| OWASP ID | Risk | Sentinel control(s) |
| --- | --- | --- |
| AGENT-01 | Goal hijacking | `classifiers.intent_classifier`, policy rules `goal-hijack-*`, trust-score decay on detected intent mismatch. |
| AGENT-02 | Memory poisoning | `verification.cmvk` signed memory receipts, `classifiers.injection_detector` on `memory_write` actions, policy rules `mem-poison-*`. |
| AGENT-03 | Tool misuse | `classifiers.tool_validator` capability check + JSON-schema arg validation, ring downgrade on repeat violations. |
| AGENT-04 | Identity / authorization abuse | `identity.resolver` DID resolution, `identity.signing` action signatures, `identity.trust_scorer` tier gating. |
| AGENT-05 | Rogue agents | Behavioral anomaly detector, trust-tier gating, IATP sender verification. |
| AGENT-06 | Supply-chain risks | Signed policy bundles, pinned dependencies + lockfile, Dependabot, CodeQL, secret scanning, image signing on release. |
| AGENT-07 | Code-execution abuse | `gateway.sandbox` ring isolation (R0–R3), `sentinel-engine` per-ring policy, `code_exec` actions default to ESCALATE. |
| AGENT-08 | Insecure communications | `comms.iatp` signed envelopes with monotonic nonces, mTLS recommended at the transport layer. |
| AGENT-09 | Cascading failures | `core.circuit_breaker` per-dependency breakers, fail-closed degradation, local policy cache. |
| AGENT-10 | Human-agent trust exploitation | `core.approval` workflow, structured `explanation` field on every DENY / ESCALATE, audit-log signing for downstream verification. |

For every control, the corresponding rule IDs are documented inline in the default policy bundle. The red-team harness exercises one scenario per OWASP category on every CI run, and failures block the build.
