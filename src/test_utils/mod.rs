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
pub use steps::{ForceUpdateStep, HeaderCheck, ProcessUpdateStep, StateChecks, TestMeta, TestStep};

use crate::types::consensus::{BeaconBlockHeader, LightClientHeader as PubLightClientHeader};
use crate::types::primitives::Root;

/// Fork tag used by the fixture loader to wrap deserialized headers
/// into the correct [`LightClientHeader`](PubLightClientHeader) variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestFork {
    Altair,
    Bellatrix,
    Capella,
}

impl TestFork {
    /// Only valid for Altair/Bellatrix; Capella headers carry an execution payload (panics).
    fn wrap_header(&self, beacon: BeaconBlockHeader) -> PubLightClientHeader {
        match self {
            TestFork::Altair => PubLightClientHeader::altair(beacon),
            TestFork::Bellatrix => PubLightClientHeader::bellatrix(beacon),
            TestFork::Capella => {
                panic!("Capella headers require execution payload; use Capella-specific load path")
            }
        }
    }

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

/// Convert a hex string (with or without 0x prefix) to a 32-byte root.
pub fn hex_to_root(hex: &str) -> Result<Root, Box<dyn std::error::Error>> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex)?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()).into());
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    Ok(root)
}
