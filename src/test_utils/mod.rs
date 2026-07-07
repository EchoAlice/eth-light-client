//! # Test Utilities (Unstable)
//!
//! **Warning:** This module is not part of the stable public API.
//! It may change or be removed without notice in any version.
//!
//! Provides helpers for loading Ethereum consensus-spec test fixtures,
//! useful for integration testing and downstream library testing.
//!
//! Enable with the `test-utils` feature:
//! ```toml
//! [dev-dependencies]
//! eth-light-client = { version = "0.1", features = ["test-utils"] }
//! ```

mod loader;
mod raw_ssz;
mod steps;

pub use loader::{BootstrapData, SpecTestLoader};
pub use steps::{
    hex_to_root, ForceUpdateStep, HeaderCheck, ProcessUpdateStep, StateChecks, TestMeta, TestStep,
};

/// Fork tag used by the fixture loader to wrap deserialized headers
/// into the correct [`LightClientHeader`](crate::types::consensus::LightClientHeader) variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestFork {
    Altair,
    Bellatrix,
    Capella,
}

impl TestFork {
    /// Return a `ChainSpec` whose fork schedule matches the spec-test fixtures
    /// for this fork.
    pub fn chain_spec(&self) -> crate::config::ChainSpec {
        use crate::config::{ChainSpec, ChainSpecConfig};

        let mut config = ChainSpecConfig {
            genesis_time: 1578009600,
            seconds_per_slot: 6,
            slots_per_epoch: 8,
            epochs_per_sync_committee_period: 8,
            sync_committee_size: 32,
            altair_fork_version: [0x01, 0x00, 0x00, 0x01],
            altair_fork_epoch: 0,
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x01],
            bellatrix_fork_epoch: u64::MAX,
            capella_fork_version: [0x03, 0x00, 0x00, 0x01],
            capella_fork_epoch: u64::MAX,
            deneb_fork_version: [0x04, 0x00, 0x00, 0x01],
            deneb_fork_epoch: u64::MAX,
            electra_fork_version: [0x05, 0x00, 0x00, 0x01],
            electra_fork_epoch: u64::MAX,
        };

        match self {
            TestFork::Altair => {} // defaults are correct
            TestFork::Bellatrix => {
                config.bellatrix_fork_epoch = 0;
            }
            TestFork::Capella => {
                config.bellatrix_fork_epoch = 0;
                config.capella_fork_epoch = 0;
            }
        }

        ChainSpec::try_from_config(config).expect("minimal fixture config is valid")
    }
}
