//! sentinel-engine — Rust core for osl-agent-sentinel.
//!
//! Exposes execution-ring isolation, signing primitives, and a deterministic
//! policy-rule matcher to both Rust embedders and the Python control plane
//! (via the `pyo3` feature).

#![forbid(unsafe_code)]
#![warn(
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    missing_docs,
    rust_2018_idioms
)]
#![allow(clippy::module_name_repetitions, clippy::multiple_crate_versions)]

pub mod engine;
pub mod errors;
pub mod rings;
pub mod signing;

pub use engine::{Engine, EngineConfig};
pub use errors::EngineError;
pub use rings::{Ring, RingPolicy};
pub use signing::{verify_ed25519, KeyPair};

#[cfg(feature = "pyo3")]
mod py;
