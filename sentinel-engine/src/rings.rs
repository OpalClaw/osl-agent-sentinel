//! Execution rings: isolation tiers an action may run in.

use serde::{Deserialize, Serialize};

/// The four isolation tiers, in increasing order of restriction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ring {
    /// Trusted host — agent runs in the same process as the orchestrator.
    R0Trusted,
    /// Namespaced — separate process, restricted filesystem and network.
    R1Namespaced,
    /// MicroVM-class — kernel-level isolation, no host filesystem.
    R2MicroVm,
    /// Network-only — ephemeral container with no persistent state.
    R3NetworkOnly,
}

impl Ring {
    /// Human-readable identifier for the ring.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::R0Trusted => "R0",
            Self::R1Namespaced => "R1",
            Self::R2MicroVm => "R2",
            Self::R3NetworkOnly => "R3",
        }
    }
}

/// Declarative policy controlling what each ring may do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingPolicy {
    /// Maximum wall-clock time per action, in milliseconds.
    pub max_wallclock_ms: u64,
    /// Maximum memory the action may allocate, in megabytes.
    pub max_memory_mb: u64,
    /// Allow network access (egress) from the ring.
    pub allow_network: bool,
    /// Allow filesystem writes from the ring.
    pub allow_filesystem_write: bool,
    /// Allow subprocess spawn from the ring.
    pub allow_subprocess: bool,
}

impl RingPolicy {
    /// Returns the default policy for the given ring.
    #[must_use]
    pub const fn defaults_for(ring: Ring) -> Self {
        match ring {
            Ring::R0Trusted => Self {
                max_wallclock_ms: 30_000,
                max_memory_mb: 2_048,
                allow_network: true,
                allow_filesystem_write: true,
                allow_subprocess: true,
            },
            Ring::R1Namespaced => Self {
                max_wallclock_ms: 10_000,
                max_memory_mb: 512,
                allow_network: true,
                allow_filesystem_write: true,
                allow_subprocess: false,
            },
            Ring::R2MicroVm => Self {
                max_wallclock_ms: 5_000,
                max_memory_mb: 256,
                allow_network: true,
                allow_filesystem_write: false,
                allow_subprocess: false,
            },
            Ring::R3NetworkOnly => Self {
                max_wallclock_ms: 2_000,
                max_memory_mb: 128,
                allow_network: true,
                allow_filesystem_write: false,
                allow_subprocess: false,
            },
        }
    }
}
