#![doc = include_str!("../README.md")]
// Clippy configuration for release
#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::field_reassign_with_default)]

// Public modules
pub mod config;
pub mod error;
pub mod light_client;
pub mod types;

// Private implementation modules
mod consensus;

// Test utilities (unstable, not part of public API)
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

// Re-export main types at crate root for convenience
pub use crate::config::{ChainSpec, ChainSpecConfig};
pub use crate::error::{Error, Result};
pub use crate::light_client::{LightClient, UpdateOutcome};
pub use crate::types::{
    consensus::{
        BeaconBlockHeader, LightClientBootstrap, LightClientUpdate, SyncAggregate, SyncCommittee,
    },
    primitives::{Root, Slot},
};

/// Contains the recommended set of types needed for most light client usage.
/// For additional types (e.g. [`SyncAggregate`]), import them from the crate root
/// (or from [`crate::types`] if you prefer the module path).
pub mod prelude {
    pub use crate::config::ChainSpec;
    pub use crate::error::{Error, Result};
    pub use crate::light_client::{LightClient, UpdateOutcome};
    pub use crate::types::{
        consensus::{BeaconBlockHeader, LightClientBootstrap, LightClientUpdate, SyncCommittee},
        primitives::{Root, Slot},
    };
}
