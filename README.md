<div align="center">

![OpalSageLabs · osl-agent-sentinel](assets/banner.png)

# osl-agent-sentinel

**Autonomous AI agent runtime security layer.**
Intercepts, validates, and governs every agent action before execution.
Built end-to-end against the OWASP Agentic AI Top 10.

[![CI](https://github.com/OpalClaw/osl-agent-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/OpalClaw/osl-agent-sentinel/actions/workflows/ci.yml)
[![Security](https://github.com/OpalClaw/osl-agent-sentinel/actions/workflows/security.yml/badge.svg)](https://github.com/OpalClaw/osl-agent-sentinel/actions/workflows/security.yml)
[![Coverage](https://img.shields.io/badge/coverage-meaningful-1f6feb)](docs/TESTING.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-1f6feb.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-1f6feb)](pyproject.toml)
[![Rust stable](https://img.shields.io/badge/rust-stable-orange)](sentinel-engine/Cargo.toml)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP-Agentic%20AI%20Top%2010-critical)](docs/OWASP-MAPPING.md)

</div>

---

## Overview

`osl-agent-sentinel` is a production-grade runtime security layer for autonomous AI agents. It sits between an agent (LangChain, LangGraph, AutoGen, CrewAI, custom runtimes, MCP clients) and the tools, APIs, models, files, and external systems the agent attempts to touch. Every proposed action  tool call, file write, HTTP request, code execution, memory mutation, sub-agent spawn is intercepted, classified, scored, policy-checked, signed, and either allowed, denied, escalated to human approval, or rate-limited.

It is designed for the operational reality of agentic systems in production: opaque LLM intent, ambient prompt injection, compromised tool outputs, drifting policies, multi-tenant blast radius, and the absence of meaningful default guardrails in modern agent frameworks.

The result is a single, observable, policy-driven enforcement point with cryptographic provenance, behavioral trust scoring, and SIEM-grade telemetry — engineered to be the security control plane your SOC and compliance team will actually accept.

## Why it exists

Modern agent stacks are functionally powerful and architecturally exposed. The frameworks were built for capability, not containment. In practice this means:

- Tools are invoked based on natural-language LLM output, with no structural enforcement of which tool may be called, with what arguments, under what context, by which identity.
- Agent memory and retrieved context are treated as trusted inputs even though they are externally writable.
- Sub-agents are spawned without bounded authority, lineage tracking, or cost ceilings.
- Outbound communications, file writes, and code execution proceed without policy adjudication.
- Failures and anomalies cascade silently across agents, tools, and tenants.
- Observability is shaped for debugging, not for detection-and-response.

`osl-agent-sentinel` exists to close that gap. It is the runtime control plane that agent frameworks do not ship with, packaged so that a single team can integrate it in a day and operate it for years.

## Threat coverage — OWASP Agentic AI Top 10

| # | Risk | Sentinel control |
|---|------|------------------|
| AAI-01 | Goal hijacking | Intent classifier + prompt-injection detector + signed task objectives |
| AAI-02 | Memory poisoning | Memory write policy + provenance tags + retrieval integrity checks |
| AAI-03 | Tool misuse | Per-tool schemas, argument validators, capability scopes, execution rings |
| AAI-04 | Identity abuse | DID-based agent identity, mTLS, scoped tokens, lineage tracking |
| AAI-05 | Rogue agents | Behavioral trust scoring, circuit breaker, kill-switch, isolation |
| AAI-06 | Supply chain risk | Tool registry signing, SBOM, dependency pinning, CodeQL + Semgrep |
| AAI-07 | Code execution abuse | Sandboxed execution rings (R0–R3), syscall allowlists, resource caps |
| AAI-08 | Insecure communications | IATP — signed agent-to-agent transport, replay protection, audit |
| AAI-09 | Cascading failures | Circuit breakers, blast-radius caps, anomaly spike detection, fail-closed |
| AAI-10 | Human-agent trust exploitation | Explainable denials, structured approval workflows, audit immutability |

Full control mapping in [`docs/OWASP-MAPPING.md`](docs/OWASP-MAPPING.md).

## Architecture

```
                ┌───────────────────────────────────────────────────────────┐
                │                       Agent Runtime                       │
                │       (LangGraph / AutoGen / CrewAI / MCP / custom)       │
                └──────────────────────────┬────────────────────────────────┘
                                           │  proposed action (tool call,
                                           │   file write, HTTP, code exec,
                                           │   memory write, sub-agent spawn)
                                           ▼
   ┌────────────────────────────────────────────────────────────────────────────┐
   │                          osl-agent-sentinel                                │
   │                                                                            │
   │   Interceptor ──► Identity & Lineage ──► Intent Classifier ──► Injection   │
   │       │                                       │                  Detector  │
   │       ▼                                       ▼                            │
   │   Tool Validator ──► Policy Engine (PaC) ──► Trust Scorer ──► DLP Scanner  │
   │       │                                                                    │
   │       ▼                                                                    │
   │   Approval Workflow ──► Circuit Breaker ──► Execution Rings ──► Audit Log  │
   │                                              (Rust engine)        (signed) │
   │                                                                            │
   │   Observability: OTel · Prometheus · SIEM exporter · Explainable denials   │
   └────────────────────────────────────────────────────────────────────────────┘
                                           │
                                           ▼
                              Allow · Deny · Escalate · Throttle
```

Detailed component descriptions, sequence diagrams, threat model, and data-flow diagrams live in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Key capabilities

- **Pre-execution interception** for tool calls, file writes, HTTP requests, code execution, memory writes, and sub-agent spawns.
- **Policy-as-code** evaluation with hot-reload, signed policy bundles, and version pinning. Rego- and YAML-driven rule packs.
- **Behavioral trust scoring** per agent DID. Trust degrades on policy violations, anomalies, and failed verifications, and gates the autonomy tier the agent is permitted to operate in.
- **Execution rings (R0–R3)** implemented in a Rust core for syscall-allowlisted, resource-capped, network-scoped tool execution.
- **Cryptographic provenance** — every decision and every executed action is signed and recorded in an append-only audit log.
- **Explainable denials** — every deny or escalate returns a structured `explanation` with rule ID, risk factors, recommended remediation, and human-readable rationale.
- **Prompt-injection detection** as a first-class control distinct from intent classification.
- **DLP scanning** on agent outputs and outbound payloads to catch data exfiltration by compromised agents.
- **Multi-tenancy** — tenant isolation at the policy, identity, audit, and execution layers.
- **Fail-closed local cache** — sentinel continues to enforce a signed policy snapshot when the control plane is unreachable.
- **SIEM-grade observability** — OpenTelemetry traces and metrics, Prometheus endpoints, structured JSON logs, and direct exporters for Splunk, Elastic, Datadog, and Sentinel-compatible SIEMs.
- **API gateway adapters** for Kong, Envoy, and AWS API Gateway when sentinel runs in inline-proxy mode.
- **Red-team harness** — adversarial test suite for prompt injection, tool abuse, goal hijacking, and trust-score evasion.

## Quickstart

```bash
# 1. Install (Python 3.11+)
pip install osl-agent-sentinel

# 2. Pull the signed default policy pack
sentinel policy pull --pack opalsagelabs/baseline

# 3. Start the sentinel control plane
sentinel serve --config config/sentinel.yaml
```

Wire an agent into the sentinel in three lines:

```python
from sentinel.client import Sentinel

sentinel = Sentinel(endpoint="http://localhost:8787", agent_did="did:osl:agent:demo-001")

decision = sentinel.evaluate(
    action_type="tool_call",
    tool="http_request",
    arguments={"method": "POST", "url": "https://api.example.com/orders", "body": {...}},
    context={"task_id": "task-42", "objective_signature": "..."},
)

if decision.allowed:
    result = run_tool(...)
    sentinel.record_result(decision.id, result)
else:
    raise PermissionError(decision.explanation.human_readable)
```

A full integration walkthrough is in [`docs/QUICKSTART.md`](docs/QUICKSTART.md) and end-to-end examples live in [`examples/`](examples/).

## Installation

### From PyPI

```bash
pip install osl-agent-sentinel
```

### From source

```bash
git clone https://github.com/OpalClaw/osl-agent-sentinel.git
cd osl-agent-sentinel
make install
make build-engine     # builds the Rust execution-ring core
make test
```

### Docker

```bash
docker compose -f docker/docker-compose.yml up -d
```

System requirements, supported runtimes, and hardware sizing guidance are documented in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Configuration

All configuration is environment-variable driven with a layered YAML override. Every option is documented in [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) and a complete annotated example lives in [`.env.example`](.env.example).

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — full system architecture, components, data flows, threat model.
- [`docs/API.md`](docs/API.md) — control-plane and data-plane API reference.
- [`docs/openapi.yaml`](docs/openapi.yaml) — OpenAPI 3.1 specification.
- [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) — every configuration option, environment variable, and feature flag.
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — infrastructure requirements and deployment patterns.
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — local development, tooling, workflow.
- [`docs/TESTING.md`](docs/TESTING.md) — testing strategy, coverage requirements, red-team harness.
- [`docs/OWASP-MAPPING.md`](docs/OWASP-MAPPING.md) — control-to-risk mapping for the OWASP Agentic AI Top 10.
- [`docs/POLICY-AUTHORING.md`](docs/POLICY-AUTHORING.md) — writing, signing, and shipping policy packs.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — planned features and known limitations.

## Repository layout

```
osl-agent-sentinel/
├── src/sentinel/             # Python control plane & SDK
├── sentinel-engine/          # Rust execution-ring core (PyO3 bindings)
├── tests/                    # unit / integration / e2e / chaos / fuzz
├── docs/                     # architecture, API, deployment, OWASP mapping
├── docker/                   # Dockerfiles & compose stacks
├── scripts/                  # setup, build, release, policy-pack utilities
├── examples/                 # framework integrations & reference deployments
├── benchmarks/               # latency & throughput benchmarks
├── config/                   # default policy packs & tooling config
└── .github/                  # workflows, issue/PR templates, CODEOWNERS
```

## Security

`osl-agent-sentinel` is itself a security product, so the supply chain, build, and disclosure processes are first-class concerns. See [`SECURITY.md`](SECURITY.md) for the threat model, supported versions, vulnerability disclosure policy, and a complete description of the security controls baked into the product itself.

## Contributing

Contributions, audits, and red-team findings are welcome. The contribution model, coding standards, and required checks are documented in [`CONTRIBUTING.md`](CONTRIBUTING.md). All participants are expected to follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Roadmap

The roadmap for `osl-agent-sentinel` is published in [`docs/ROADMAP.md`](docs/ROADMAP.md) and tracked on the GitHub Project board attached to this repository.

## License

Released under the [MIT License](LICENSE). © OpalSageLabs.

---

<div align="center">

**OpalSageLabs** · production-grade autonomous AI systems engineering.
[GitHub](https://github.com/OpalClaw) · [opalsagelabs.click](https://opalsagelabs.click)

</div>
