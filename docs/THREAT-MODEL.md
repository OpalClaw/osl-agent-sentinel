# Threat Model

Aligns with STRIDE for the control plane and with the OWASP Agentic AI Top 10 for the agent runtime surface.

## Assets

1. **Policy bundles** — authoritative rule set. Compromise enables silent allow-by-default.
2. **Identity registry** — DIDs, public keys, capability grants, trust scores.
3. **Audit log** — append-only, hash-chained, signed.
4. **Secrets** — API tokens, signing keys, SIEM credentials.
5. **Agent action stream** — sensitive payloads (PII, credentials in args, model prompts).

## Trust boundaries

| Boundary | From | To | Authn / Authz |
| --- | --- | --- | --- |
| Agent ↔ Sentinel | agent runtime | control plane | DID + Ed25519 signature (optional) and tenant-scoped bearer token (required). |
| Sentinel ↔ Policy source | control plane | bundle store | Signature verification on every load. |
| Sentinel ↔ SIEM | control plane | log sink | Bearer / mTLS depending on backend. |
| Operator ↔ Sentinel | human reviewer | approval workflow | Bearer + per-tenant scope. |

## STRIDE

| Threat | Surface | Mitigation |
| --- | --- | --- |
| Spoofing | Action submission | DID resolution + Ed25519 signature verification; constant-time bearer compare. |
| Tampering | Policy bundles, audit log | Ed25519 signatures; SHA-256 hash chain across audit records. |
| Repudiation | Decision provenance | Signed audit records; every DENY/ESCALATE carries triggered-rule IDs, risk factors, and rationale. |
| Information disclosure | Action payloads, logs | DLP scanner on inbound payloads; redaction in structured logs; secrets never logged. |
| Denial of service | API surface, classifier hot path | Per-tenant rate limiting; circuit breakers on dependencies; bounded classifier CPU budgets. |
| Elevation of privilege | Tool capability set, trust tiers | Tool validator capability check; trust-score decay; ring downgrade on repeat violations. |

## Out of scope

- Physical security of the underlying host.
- Side-channel attacks on the cryptographic primitives (we use vetted libraries).
- Supply-chain compromise of language ecosystems (Python / Rust) — mitigated only by pinning, lockfile, and Dependabot.

## Residual risks

- A compromised operator with a valid bearer token and tenant scope can publish a permissive policy bundle. Mitigation: bundle-signing key custody is separate from the API token, and bundle signature verification is enforced in production.
- A determined adversary in control of the agent runtime can submit signed actions matching policy. Mitigation: trust-score decay, anomaly detection, and behavioral baselines surface drift even when individual actions look benign.
