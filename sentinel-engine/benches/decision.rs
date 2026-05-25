//! Benchmarks for the engine decision hot path.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinel_engine::{Engine, Ring};

fn bench_evaluate(c: &mut Criterion) {
    let engine = Engine::default();
    c.bench_function("engine_evaluate_r1_network", |b| {
        b.iter(|| {
            let _ = engine.evaluate(black_box(Ring::R1Namespaced), black_box("network"));
        });
    });
    c.bench_function("engine_evaluate_r3_filesystem_write_denied", |b| {
        b.iter(|| {
            let _ = engine.evaluate(
                black_box(Ring::R3NetworkOnly),
                black_box("filesystem_write"),
            );
        });
    });
}

criterion_group!(benches, bench_evaluate);
criterion_main!(benches);
