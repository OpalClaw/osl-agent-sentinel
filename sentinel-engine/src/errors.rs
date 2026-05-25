//! Engine error types.

use thiserror::Error;

/// Errors emitted by the engine.
#[derive(Debug, Error)]
pub enum EngineError {
    /// The requested ring does not permit the action class.
    #[error("ring {ring} denies action class {class}")]
    RingDenied {
        /// Ring identifier.
        ring: &'static str,
        /// Action class denied.
        class: String,
    },
    /// The action exceeded its time budget.
    #[error("execution exceeded budget ({budget_ms} ms)")]
    Timeout {
        /// Configured budget in milliseconds.
        budget_ms: u64,
    },
    /// Signature verification failed.
    #[error("signature verification failed")]
    InvalidSignature,
    /// Generic policy violation surfaced from caller-supplied data.
    #[error("policy violation: {0}")]
    Policy(String),
    /// Underlying I/O or serialization failure.
    #[error("internal error: {0}")]
    Internal(String),
}
