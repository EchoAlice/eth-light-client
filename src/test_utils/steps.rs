//! YAML metadata and step types deserialized from spec test fixtures.

use super::TestUtilsResult;
use crate::types::consensus::BeaconBlockHeader;
use crate::types::primitives::Root;

/// Metadata from a spec test's meta.yaml file.
///
/// The fork-digest keys are unmodeled; serde ignores them (fork comes from the
/// `SpecTestLoader` constructor).
#[derive(Debug, serde::Deserialize)]
pub(crate) struct TestMeta {
    pub(crate) genesis_validators_root: String,
    /// Parsed but not yet enforced; see issue #55.
    #[allow(dead_code)]
    trusted_block_root: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct StateChecks {
    pub finalized_header: Option<HeaderCheck>,
    pub optimistic_header: Option<HeaderCheck>,
}

#[derive(Debug, serde::Deserialize)]
pub struct HeaderCheck {
    pub slot: u64,
    pub beacon_root: String,
    /// Present only for Capella+ (absent for Altair/Bellatrix).
    #[serde(default)]
    pub execution_root: Option<String>,
}

/// A single test step from steps.yaml.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
pub enum TestStep {
    ProcessUpdate { process_update: ProcessUpdateStep },
    ForceUpdate { force_update: serde::de::IgnoredAny },
}

#[derive(Debug, serde::Deserialize)]
pub struct ProcessUpdateStep {
    /// Update file name (without .ssz_snappy extension).
    pub update: String,
    pub current_slot: u64,
    pub checks: StateChecks,
}

/// Convert a hex string (with or without 0x prefix) to a 32-byte root.
pub(crate) fn hex_to_root(hex: &str) -> TestUtilsResult<Root> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex)?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()).into());
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    Ok(root)
}

/// Whether a beacon header matches a fixture `HeaderCheck` (slot + beacon root).
///
/// Covers only the beacon check — the part both the internal processor and the
/// public `LightClient` expose as a `BeaconBlockHeader`. The Capella+
/// `execution_root` is not checked here, since only the processor exposes the
/// full light client header.
pub fn beacon_header_matches(check: &HeaderCheck, header: &BeaconBlockHeader) -> bool {
    let expected_root = hex_to_root(&check.beacon_root).expect("invalid beacon_root hex");
    let actual_root = header.hash_tree_root().expect("hash_tree_root");
    header.slot == check.slot && actual_root == expected_root
}
