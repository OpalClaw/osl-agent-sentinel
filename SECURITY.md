# Security Policy

`osl-agent-sentinel` is itself a security control. The supply chain, build pipeline, runtime defaults, and disclosure process are treated as first-class engineering concerns.

## Supported versions

| Version | Status | Security updates |
| --- | --- | --- |
| `0.x` (pre-1.0) | active development | latest minor only |
| `>= 1.0.0` | will be GA-supported | last two minor versions |

Once `1.0.0` ships, the supported window will expand to the latest two minor versions. Prior versions receive critical-severity fixes only.

## Reporting a vulnerability

Please do not open a public GitHub issue for security findings.

Send reports to `security@opalsagelabs.click` with:

1. A description of the issue and the affected component (module, file, function).
2. Steps to reproduce. A minimal proof-of-concept is appreciated.
3. The version, commit SHA, deployment shape (library, container, Kubernetes, etc.), and environment.
4. Any suggested remediation.

We will acknowledge receipt within two business days, provide an initial triage assessment within five business days, and aim to ship a fix or mitigation within thirty days for high-severity issues. We coordinate public disclosure with the reporter and will credit reporters who request it.

## Threat model

The project's threat model is documented in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). At a high level we assume:

- The agent runtime is partially trusted. It may be compromised by prompt injection, memory poisoning, or a rogue tool, and sentinel must continue to enforce policy.
- The network between the agent and the control plane is hostile. All communication is mutually authenticated, encrypted in transit, and replay-protected.
- The control plane is the trust root. Its operators are trusted, its keys are protected by an HSM or KMS, and its audit log is append-only.
- Policy bundles are signed. Unsigned or tamper-evidence-failing bundles are refused.
- Telemetry sinks may be unavailable. Sentinel degrades closed when it cannot reach its policy source.

## Security controls in this repository

- Dependabot is enabled for `pip`, `cargo`, `npm` (docs), `docker`, and `github-actions`.
- Secret scanning and push protection are enabled.
- CodeQL analysis runs on every push and pull request (`python`, `rust` via custom workflow).
- `bandit`, `ruff`, `mypy --strict`, `cargo audit`, and `cargo clippy -- -D warnings` are required CI gates.
- The `main` branch is protected: pull request review required, all status checks required, no direct pushes, no force pushes, signed commits encouraged.
- All container images are built with multi-stage Dockerfiles and pinned base images. The runtime image runs as a non-root user with a read-only root filesystem.
- The release pipeline produces SBOMs (CycloneDX and SPDX) and signs artifacts with Sigstore Cosign.

## Out of scope

- Issues that require physical access to the host running sentinel.
- Issues in third-party dependencies that have already been reported upstream. Please link the upstream advisory in your report.
- Social engineering of OpalSageLabs personnel.

## Hall of fame

Reporters who responsibly disclose qualifying issues are listed in [`docs/SECURITY-HALL-OF-FAME.md`](docs/SECURITY-HALL-OF-FAME.md) with their consent.
