# sentinel-engine

Rust execution-ring engine for [`osl-agent-sentinel`](../README.md). Provides
the isolation tiers (R0 trusted host, R1 namespaced, R2 microVM-class, R3
network-only) and the cryptographic primitives that back the Python control
plane. Compiled as both an `rlib` (for Rust embedders) and a `cdylib` with
PyO3 bindings (for the Python wheel).

## Why Rust

The decision hot-path runs on every action. The Rust core enforces:

- Bounded execution time and memory per ring.
- Deterministic, panic-free policy matching.
- Constant-time signature verification.

It deliberately exposes a small, audit-friendly surface; richer orchestration
remains in the Python control plane.

## Build

```bash
cargo build --release
cargo test
cargo bench
```

For the Python wheel:

```bash
maturin build --release --features pyo3
```
