#![doc = include_str!("../README.md")]

pub mod config;
pub mod error;
pub mod light_client;
pub mod types;

mod consensus;

/// Unstable: not part of the public API.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

// Crate root = the prelude plus the two power-user types it omits.
pub use crate::config::ChainSpecConfig;
pub use crate::prelude::*;
pub use crate::types::consensus::SyncAggregate;

/// The types most light-client usage needs. Omits [`ChainSpecConfig`] (custom
/// networks) and [`SyncAggregate`]; import those from the crate root.
pub mod prelude {
    pub use crate::config::{ChainSpec, Fork};
    pub use crate::error::{Error, Result};
    pub use crate::light_client::{LightClient, UpdateOutcome};
    pub use crate::types::{
        consensus::{
            BeaconBlockHeader, LightClientBootstrap, LightClientHeader, LightClientUpdate,
            SyncCommittee,
        },
        primitives::{Root, Slot},
    };
}
