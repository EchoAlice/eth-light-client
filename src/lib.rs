#![doc = include_str!("../README.md")]

pub mod chain_spec;
pub mod error;
pub mod light_client;
pub mod types;

mod consensus;

/// Unstable: not part of the public API.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

// Crate root = the prelude plus the two power-user types it omits.
pub use crate::chain_spec::ChainSpecConfig;
pub use crate::prelude::*;
pub use crate::types::consensus::SyncAggregate;

/// The types most light-client usage needs. Omits [`ChainSpecConfig`] (custom
/// networks) and [`SyncAggregate`]; import those from the crate root.
pub mod prelude {
    pub use crate::chain_spec::{ChainSpec, Fork};
    pub use crate::consensus::processor::UpdateChanges;
    pub use crate::error::{Error, Result};
    pub use crate::light_client::LightClient;
    pub use crate::types::{
        consensus::{
            BeaconBlockHeader, LightClientBootstrap, LightClientHeader, LightClientUpdate,
            SyncCommittee,
        },
        primitives::{Root, Slot},
    };
}
