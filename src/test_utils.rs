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

use crate::types::consensus::{
    BeaconBlockHeader, LightClientBootstrap, LightClientUpdate, SyncAggregate, SyncCommittee,
};
use crate::types::primitives::Root;
use ssz_rs::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

// ============================================================================
// SSZ Deserialization Types (internal)
// ============================================================================

#[derive(Debug, Clone, Default, SimpleSerialize)]
struct RawBeaconBlockHeader {
    slot: u64,
    proposer_index: u64,
    parent_root: Node,
    state_root: Node,
    body_root: Node,
}

impl RawBeaconBlockHeader {
    fn into_beacon_block_header(self) -> BeaconBlockHeader {
        let mut parent_root = [0u8; 32];
        parent_root.copy_from_slice(self.parent_root.as_ref());
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(self.state_root.as_ref());
        let mut body_root = [0u8; 32];
        body_root.copy_from_slice(self.body_root.as_ref());

        BeaconBlockHeader::new(
            self.slot,
            self.proposer_index,
            parent_root,
            state_root,
            body_root,
        )
    }
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
struct LightClientHeader {
    beacon: RawBeaconBlockHeader,
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
struct RawLightClientBootstrap {
    header: LightClientHeader,
    current_sync_committee: RawSyncCommittee,
    current_sync_committee_branch: Vector<Node, 5>,
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
struct RawSyncCommittee {
    pubkeys: Vector<Vector<u8, 48>, 32>,
    aggregate_pubkey: Vector<u8, 48>,
}

impl RawSyncCommittee {
    fn to_sync_committee(&self) -> Result<SyncCommittee, String> {
        if self.pubkeys.len() != 32 {
            return Err(format!(
                "Expected 32 pubkeys (minimal preset), got {}",
                self.pubkeys.len()
            ));
        }

        let mut pubkeys_array = Box::new([[0u8; 48]; 512]);
        for (i, pk) in self.pubkeys.iter().enumerate() {
            let mut key = [0u8; 48];
            key.copy_from_slice(pk.as_ref());
            pubkeys_array[i] = key;
        }

        let mut aggregate = [0u8; 48];
        aggregate.copy_from_slice(self.aggregate_pubkey.as_ref());

        Ok(SyncCommittee::new(pubkeys_array, aggregate))
    }
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
struct RawSyncAggregate {
    sync_committee_bits: Bitvector<32>,
    sync_committee_signature: Vector<u8, 96>,
}

impl RawSyncAggregate {
    fn into_sync_aggregate(self) -> Result<SyncAggregate, String> {
        let mut bits_array = Box::new([false; 512]);
        for (i, bit) in self.sync_committee_bits.iter().enumerate() {
            bits_array[i] = *bit;
        }

        let mut signature = [0u8; 96];
        signature.copy_from_slice(self.sync_committee_signature.as_ref());

        Ok(SyncAggregate::new(bits_array, signature))
    }
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
struct RawLightClientUpdate {
    attested_header: LightClientHeader,
    next_sync_committee: RawSyncCommittee,
    next_sync_committee_branch: Vector<Node, 5>,
    finalized_header: LightClientHeader,
    finality_branch: Vector<Node, 6>,
    sync_aggregate: RawSyncAggregate,
    signature_slot: u64,
}

impl RawLightClientUpdate {
    fn into_light_client_update(self) -> Result<LightClientUpdate, String> {
        let sync_committee = self.next_sync_committee.to_sync_committee()?;
        let sync_aggregate = self.sync_aggregate.into_sync_aggregate()?;

        let has_sync_committee = !sync_committee
            .pubkeys
            .iter()
            .all(|pk| pk.iter().all(|&b| b == 0));

        let finality_branch: Vec<Root> = self
            .finality_branch
            .iter()
            .map(|node| {
                let mut root = [0u8; 32];
                root.copy_from_slice(node.as_ref());
                root
            })
            .collect();

        let next_sync_committee_branch: Vec<Root> = self
            .next_sync_committee_branch
            .iter()
            .map(|node| {
                let mut root = [0u8; 32];
                root.copy_from_slice(node.as_ref());
                root
            })
            .collect();

        Ok(LightClientUpdate {
            attested_header: self.attested_header.beacon.into_beacon_block_header(),
            finalized_header: Some(self.finalized_header.beacon.into_beacon_block_header()),
            finality_branch,
            next_sync_committee: if has_sync_committee {
                Some(sync_committee)
            } else {
                None
            },
            next_sync_committee_branch: if has_sync_committee {
                next_sync_committee_branch
            } else {
                Vec::new()
            },
            sync_aggregate,
            signature_slot: self.signature_slot,
        })
    }
}

// ============================================================================
// Test Metadata Types (YAML)
// ============================================================================

/// Metadata from a spec test's meta.yaml file.
#[derive(Debug, serde::Deserialize)]
pub struct TestMeta {
    /// Genesis validators root as hex string (0x-prefixed).
    pub genesis_validators_root: String,
    #[allow(dead_code)]
    trusted_block_root: String,
    #[allow(dead_code)]
    bootstrap_fork_digest: String,
    #[allow(dead_code)]
    store_fork_digest: String,
}

/// Expected state after a test step.
#[derive(Debug, serde::Deserialize)]
pub struct StateChecks {
    /// Expected finalized header state.
    pub finalized_header: Option<HeaderCheck>,
    /// Expected optimistic header state.
    pub optimistic_header: Option<HeaderCheck>,
}

/// Expected header values.
#[derive(Debug, serde::Deserialize)]
pub struct HeaderCheck {
    /// Expected slot.
    pub slot: u64,
    /// Expected beacon block root as hex string.
    pub beacon_root: String,
}

/// A single test step from steps.yaml.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
pub enum TestStep {
    /// Process a light client update.
    ProcessUpdate {
        /// The process_update step data.
        process_update: ProcessUpdateStep,
    },
    /// Force update (safety timeout mechanism).
    ForceUpdate {
        /// The force_update step data.
        force_update: ForceUpdateStep,
    },
}

/// Data for a process_update test step.
#[derive(Debug, serde::Deserialize)]
pub struct ProcessUpdateStep {
    #[allow(dead_code)]
    update_fork_digest: String,
    /// Update file name (without .ssz_snappy extension).
    pub update: String,
    /// Current slot when processing the update.
    pub current_slot: u64,
    /// Expected state after processing.
    pub checks: StateChecks,
}

/// Data for a force_update test step.
#[derive(Debug, serde::Deserialize)]
pub struct ForceUpdateStep {
    /// Current slot when forcing update.
    pub current_slot: u64,
    /// Expected state after forcing.
    pub checks: StateChecks,
}

// ============================================================================
// Public API
// ============================================================================

/// Bootstrap data loaded from spec test fixtures.
#[derive(Debug, Clone)]
pub struct BootstrapData {
    /// The trusted beacon block header.
    pub header: BeaconBlockHeader,
    /// The current sync committee.
    pub sync_committee: SyncCommittee,
    /// Merkle branch proving sync committee in state.
    pub branch: Vec<Root>,
    /// Genesis validators root for signature domain.
    pub genesis_validators_root: Root,
}

impl BootstrapData {
    /// Convert to the public [`LightClientBootstrap`] type.
    pub fn into_bootstrap(self) -> LightClientBootstrap {
        LightClientBootstrap::new(
            self.header,
            self.sync_committee,
            self.branch,
            self.genesis_validators_root,
        )
    }
}

/// Loads spec test fixtures from a directory.
///
/// **Unstable:** This API may change without notice.
pub struct SpecTestLoader {
    test_dir: PathBuf,
}

impl SpecTestLoader {
    /// Create a loader for the default minimal/altair sync test.
    ///
    /// Looks for fixtures at `tests/fixtures/minimal/altair/light_client/sync/light_client_sync`
    /// relative to `CARGO_MANIFEST_DIR`.
    pub fn minimal_altair_sync() -> Self {
        let test_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/minimal/altair/light_client/sync/light_client_sync");
        Self { test_dir }
    }

    /// Create a loader for a custom test directory.
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self {
            test_dir: path.into(),
        }
    }

    /// Load bootstrap data from the test fixtures.
    pub fn load_bootstrap(&self) -> Result<BootstrapData, Box<dyn std::error::Error>> {
        let meta = self.load_meta()?;
        let bootstrap_path = self.test_dir.join("bootstrap.ssz_snappy");
        let bootstrap: RawLightClientBootstrap = load_ssz_snappy(&bootstrap_path)?;

        let sync_committee = bootstrap.current_sync_committee.to_sync_committee()?;

        let branch: Vec<Root> = bootstrap
            .current_sync_committee_branch
            .iter()
            .map(|node| {
                let mut root = [0u8; 32];
                root.copy_from_slice(node.as_ref());
                root
            })
            .collect();

        let genesis_validators_root = hex_to_root(&meta.genesis_validators_root)?;

        Ok(BootstrapData {
            header: bootstrap.header.beacon.into_beacon_block_header(),
            sync_committee,
            branch,
            genesis_validators_root,
        })
    }

    /// Load a specific update by name.
    ///
    /// The name should not include the `.ssz_snappy` extension.
    pub fn load_update(&self, name: &str) -> Result<LightClientUpdate, Box<dyn std::error::Error>> {
        let update_path = self.test_dir.join(format!("{}.ssz_snappy", name));
        let raw_update: RawLightClientUpdate = load_ssz_snappy(&update_path)?;
        raw_update.into_light_client_update().map_err(|e| e.into())
    }

    /// Load test metadata from meta.yaml.
    pub fn load_meta(&self) -> Result<TestMeta, Box<dyn std::error::Error>> {
        let meta_path = self.test_dir.join("meta.yaml");
        let meta_contents = fs::read_to_string(&meta_path)?;
        let meta: TestMeta = serde_yaml::from_str(&meta_contents)?;
        Ok(meta)
    }

    /// Load test steps from steps.yaml.
    pub fn load_steps(&self) -> Result<Vec<TestStep>, Box<dyn std::error::Error>> {
        let steps_path = self.test_dir.join("steps.yaml");
        let steps_contents = fs::read_to_string(&steps_path)?;
        let steps: Vec<TestStep> = serde_yaml::from_str(&steps_contents)?;
        Ok(steps)
    }
}

// ============================================================================
// Internal Helpers
// ============================================================================

fn load_ssz_snappy<T>(file_path: &Path) -> Result<T, Box<dyn std::error::Error>>
where
    T: Deserialize,
{
    let compressed = fs::read(file_path)?;
    let mut decoder = snap::raw::Decoder::new();
    let decompressed = decoder.decompress_vec(&compressed)?;
    let decoded =
        T::deserialize(&decompressed).map_err(|e| format!("SSZ decode error: {:?}", e))?;
    Ok(decoded)
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
