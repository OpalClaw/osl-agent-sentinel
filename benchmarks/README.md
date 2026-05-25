# Benchmarks

| Suite | Tool | Path |
| --- | --- | --- |
| Engine hot path | Criterion (Rust) | `sentinel-engine/benches/decision.rs` |
| Pipeline throughput | pytest-benchmark | `benchmarks/test_pipeline_bench.py` |

Run Rust benchmarks:

```bash
cargo bench --manifest-path sentinel-engine/Cargo.toml
```

Run Python benchmarks:

```bash
pytest benchmarks/ --benchmark-only
```

The control plane targets **sub-millisecond** policy evaluation on a single
core and **single-digit-millisecond** end-to-end decision latency under
typical classifier load.
