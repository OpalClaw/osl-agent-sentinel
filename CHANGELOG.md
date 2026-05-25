# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial public release of `osl-agent-sentinel`.
- Core interceptor, policy engine, and decision pipeline (Python control plane).
- Rust execution-ring engine (`sentinel-engine`) with R0–R3 isolation tiers and PyO3 bindings.
- Intent classifier, prompt-injection detector, tool validator, and anomaly detector.
- DID-based agent identity management, capability-bound credentials, behavioral trust scoring.
- MCP gateway with tool allow-listing, schema validation, and per-tool circuit breakers.
- Cryptographic Memory Verification Kernel (CMVK) with Merkle-anchored memory commitments.
- Inter-Agent Trust Protocol (IATP) for signed agent-to-agent messaging.
- Cryptographic, hash-chained audit log with optional WORM sink adapters.
- Fail-closed degradation mode with local signed policy cache.
- DLP scanner for outbound action payloads.
- Multi-tenant policy isolation with per-tenant rate limits and quotas.
- OpenTelemetry traces and metrics, Prometheus exporter, SIEM CEF/LEEF exporters.
- API gateway adapters: Kong, Envoy, AWS API Gateway.
- Red-team test harness with continuously updated prompt-injection corpus.
- Production-grade CI/CD: lint, type-check, test, security scan, container build, SBOM, signing.
- Helm chart and Terraform module for AWS EKS reference deployment.

### Security
- All artifacts signed with Sigstore Cosign.
- SBOMs published as build artifacts (CycloneDX and SPDX).
- Secret scanning, CodeQL, and Dependabot enabled on the repository.

[Unreleased]: https://github.com/OpalClaw/osl-agent-sentinel/compare/main...HEAD
