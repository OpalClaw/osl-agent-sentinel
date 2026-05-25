# Testing Strategy

Five test tiers, each with a specific intent. The CI runs all five on every PR.

## 1. Unit (`tests/unit/`)

Fast, in-process, no I/O. Cover the core algorithms: policy matching, intent classification, trust scoring, anomaly detection, signing primitives.

Run: `pytest tests/unit -q`.

## 2. Integration (`tests/integration/`)

Exercise multiple modules together against the in-memory backends. Cover the full decision pipeline end-to-end and the FastAPI app with `httpx.AsyncClient`.

Run: `pytest tests/integration -q`.

## 3. End-to-end (`tests/e2e/`)

Spin up the control plane and the embedded SDK in the same process and replay scripted agent sessions. Cover the MCP gateway, approval workflow, and SIEM emission.

Run: `pytest tests/e2e -q`.

## 4. Chaos (`tests/chaos/`)

Force every dependency to fail in turn and assert the pipeline degrades fail-closed: dropped policy source, broken identity resolver, broken SIEM. The cache path is exercised.

Run: `pytest tests/chaos -q`.

## 5. Fuzz (`tests/fuzz/`)

Property-based tests with Hypothesis cover the canonical encoder, signing round-trips, and the policy matcher. Run a longer fuzz cycle nightly.

Run: `pytest tests/fuzz -q`.

## Coverage

We target meaningful coverage on **security-critical paths** rather than a single global percentage:

- Policy engine and pipeline orchestration: `>= 95%`.
- Classifiers and DLP scanner: `>= 90%`.
- Identity and signing: `>= 95%`.
- Adapters and observability glue: `>= 80%`.

The `make test` target prints a per-module coverage breakdown.

## Rust tests

`cargo test` runs the Rust unit and property tests. `cargo bench` runs the Criterion benchmarks under `sentinel-engine/benches/`.
