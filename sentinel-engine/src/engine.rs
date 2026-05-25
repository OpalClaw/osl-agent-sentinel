//! Engine entry points.
//!
//! The engine owns ring policies and applies them to a normalized action
//! payload before the runtime executes it.

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::errors::EngineError;
use crate::rings::{Ring, RingPolicy};

/// Engine configuration: per-ring policy overrides.
#[derive(Debug, Clone, Default)]
pub struct EngineConfig {
    overrides: HashMap<Ring, RingPolicy>,
}

impl EngineConfig {
    /// Override the default policy for a ring.
    #[must_use]
    pub fn with_ring(mut self, ring: Ring, policy: RingPolicy) -> Self {
        self.overrides.insert(ring, policy);
        self
    }

    /// Resolve the effective policy for `ring`.
    #[must_use]
    pub fn policy_for(&self, ring: Ring) -> RingPolicy {
        self.overrides
            .get(&ring)
            .cloned()
            .unwrap_or_else(|| RingPolicy::defaults_for(ring))
    }
}

/// Result of an engine action evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResult {
    /// Whether the action passed all ring checks.
    pub allowed: bool,
    /// Ring the action was evaluated against.
    pub ring: String,
    /// Elapsed time in microseconds for the evaluation.
    pub elapsed_us: u128,
    /// Diagnostic reason, if denied.
    pub reason: Option<String>,
}

/// The engine itself.
#[derive(Debug, Clone, Default)]
pub struct Engine {
    config: EngineConfig,
}

impl Engine {
    /// Create a new engine from a configuration.
    #[must_use]
    pub const fn new(config: EngineConfig) -> Self {
        Self { config }
    }

    /// Evaluate an action class against a ring's policy.
    ///
    /// `action_class` is a short identifier describing the action category
    /// (`network`, `filesystem_write`, `subprocess`, `pure_compute`). The
    /// engine returns whether the ring permits that class.
    ///
    /// # Errors
    /// Returns `EngineError::RingDenied` when the action class is not
    /// permitted by the resolved ring policy.
    pub fn evaluate(&self, ring: Ring, action_class: &str) -> Result<EngineResult, EngineError> {
        let started = Instant::now();
        let policy = self.config.policy_for(ring);
        let allowed = match action_class {
            "network" => policy.allow_network,
            "filesystem_write" => policy.allow_filesystem_write,
            "subprocess" => policy.allow_subprocess,
            "pure_compute" => true,
            _ => false,
        };
        let elapsed_us = started.elapsed().as_micros();
        if !allowed {
            debug!(ring = ring.id(), action_class, "ring denied action class");
            return Err(EngineError::RingDenied {
                ring: ring.id(),
                class: action_class.to_string(),
            });
        }
        Ok(EngineResult {
            allowed,
            ring: ring.id().to_string(),
            elapsed_us,
            reason: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r3_denies_filesystem_write() {
        let engine = Engine::default();
        let err = engine.evaluate(Ring::R3NetworkOnly, "filesystem_write").unwrap_err();
        assert!(matches!(err, EngineError::RingDenied { .. }));
    }

    #[test]
    fn r0_allows_subprocess() {
        let engine = Engine::default();
        let result = engine.evaluate(Ring::R0Trusted, "subprocess").unwrap();
        assert!(result.allowed);
        assert_eq!(result.ring, "R0");
    }

    #[test]
    fn unknown_action_class_is_denied() {
        let engine = Engine::default();
        let err = engine.evaluate(Ring::R0Trusted, "exfiltrate").unwrap_err();
        assert!(matches!(err, EngineError::RingDenied { .. }));
    }
}
