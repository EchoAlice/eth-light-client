//! YAML metadata and step types deserialized from spec test fixtures.

use super::TestUtilsResult;
use crate::types::consensus::BeaconBlockHeader;
use crate::types::primitives::Root;
use serde::Deserialize;

/// Metadata from a spec test's meta.yaml file.
///
/// `store_fork_digest` stays unmodeled: it names the fork the *store* should be
/// typed as, which only matters for implementations with per-fork store types.
/// Our store is fork-agnostic (see `consensus/store.rs`), so there is nothing
/// to key off it.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct TestMeta {
    #[serde(deserialize_with = "de_root")]
    pub(crate) genesis_validators_root: Root,
    /// Parsed but not yet enforced; see issue #55.
    #[allow(dead_code)]
    #[serde(deserialize_with = "de_root")]
    trusted_block_root: Root,
    /// Fork the bootstrap is serialized under; drives bootstrap decode.
    #[serde(deserialize_with = "de_fork_digest")]
    pub(crate) bootstrap_fork_digest: [u8; 4],
}

#[derive(Debug, serde::Deserialize)]
pub struct StateChecks {
    pub finalized_header: Option<HeaderCheck>,
    pub optimistic_header: Option<HeaderCheck>,
}

#[derive(Debug, serde::Deserialize)]
pub struct HeaderCheck {
    pub slot: u64,
    #[serde(deserialize_with = "de_root")]
    pub beacon_root: Root,
    /// Present only for Capella+ (absent for Altair/Bellatrix).
    #[serde(default, deserialize_with = "de_root_opt")]
    pub execution_root: Option<Root>,
}

/// A single test step from steps.yaml.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
pub enum TestStep {
    ProcessUpdate { process_update: ProcessUpdateStep },
    UpgradeStore { upgrade_store: UpgradeStoreStep },
    ForceUpdate { force_update: serde::de::IgnoredAny },
}

#[derive(Debug, serde::Deserialize)]
pub struct ProcessUpdateStep {
    /// Fork the update is serialized under; drives per-update decode. In
    /// cross-fork sequences this differs from the bootstrap fork (and pre-fork
    /// updates keep arriving after the chain forks), so it must come from the
    /// step, not the test.
    #[serde(deserialize_with = "de_fork_digest")]
    pub update_fork_digest: [u8; 4],
    /// Update file name (without .ssz_snappy extension).
    pub update: String,
    pub current_slot: u64,
    pub checks: StateChecks,
}

/// pyspec's store-migration step (re-type the store, pad retained branches).
/// Our store is fork-agnostic and retains no branches, so the step mutates
/// nothing here — the driver only asserts `checks` as a checkpoint.
#[derive(Debug, serde::Deserialize)]
pub struct UpgradeStoreStep {
    /// Fork the store upgrades to. Unused beyond documentation: with no
    /// per-fork store typing there is nothing to key off it.
    #[allow(dead_code)]
    #[serde(deserialize_with = "de_fork_digest")]
    pub store_fork_digest: [u8; 4],
    pub checks: StateChecks,
}

/// Whether a beacon header matches a fixture `HeaderCheck` (slot + beacon root).
///
/// Covers only the beacon check — the part both the internal processor and the
/// public `LightClient` expose as a `BeaconBlockHeader`. The Capella+
/// `execution_root` is not checked here, since only the processor exposes the
/// full light client header.
pub fn beacon_header_matches(check: &HeaderCheck, header: &BeaconBlockHeader) -> bool {
    let actual_root = header.hash_tree_root().expect("hash_tree_root");
    header.slot == check.slot && actual_root == check.beacon_root
}

/// Deserialize a hex root string (`meta.yaml` / `steps.yaml`) into a `Root`,
/// so malformed hex fails at load time rather than at assertion time.
fn de_root<'de, D>(deserializer: D) -> Result<Root, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    hex_to_root(&s).map_err(serde::de::Error::custom)
}

/// Deserialize a hex fork-digest string (`0x0cbce901`) into its 4 bytes.
fn de_fork_digest<'de, D>(deserializer: D) -> Result<[u8; 4], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let hex = s.strip_prefix("0x").unwrap_or(&s);
    let bytes = hex::decode(hex).map_err(serde::de::Error::custom)?;
    bytes.try_into().map_err(|b: Vec<u8>| {
        serde::de::Error::custom(format!("expected 4 bytes, got {}", b.len()))
    })
}

fn de_root_opt<'de, D>(deserializer: D) -> Result<Option<Root>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|s| hex_to_root(&s))
        .transpose()
        .map_err(serde::de::Error::custom)
}

/// Convert a hex string (with or without 0x prefix) to a 32-byte root.
fn hex_to_root(hex: &str) -> TestUtilsResult<Root> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex)?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| format!("expected 32 bytes, got {}", b.len()).into())
}
