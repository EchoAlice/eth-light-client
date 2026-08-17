use super::TestUtilsResult;
use crate::types::consensus::BeaconBlockHeader;
use crate::types::primitives::{Root, Slot};
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct TestMeta {
    #[serde(deserialize_with = "de_root")]
    pub(crate) genesis_validators_root: Root,
    #[serde(deserialize_with = "de_root")]
    pub(crate) trusted_block_root: Root,
    #[serde(deserialize_with = "de_fork_digest")]
    pub(crate) bootstrap_fork_digest: [u8; 4],
}

#[derive(Deserialize)]
pub struct HeaderCheck {
    pub slot: Slot,
    #[serde(deserialize_with = "de_root")]
    pub beacon_root: Root,
    #[serde(default, deserialize_with = "de_root_opt")]
    pub execution_root: Option<Root>,
}

impl HeaderCheck {
    pub fn matches(&self, header: &BeaconBlockHeader) -> bool {
        let actual_root = header.hash_tree_root();
        header.slot == self.slot && actual_root == self.beacon_root
    }
}

#[derive(Deserialize)]
pub struct StateChecks {
    pub finalized_header: Option<HeaderCheck>,
    pub optimistic_header: Option<HeaderCheck>,
}

#[derive(Deserialize)]
pub struct ProcessUpdateStep {
    #[serde(deserialize_with = "de_fork_digest")]
    pub update_fork_digest: [u8; 4],
    pub update: String, // Update file name (without .ssz_snappy extension).
    pub current_slot: Slot,
    pub checks: StateChecks,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestStep {
    ProcessUpdate(ProcessUpdateStep),
    UpgradeStore { checks: StateChecks },
    ForceUpdate(serde::de::IgnoredAny),
}

fn de_root<'de, D>(deserializer: D) -> Result<Root, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    hex_to_array(&s).map_err(serde::de::Error::custom)
}

fn de_fork_digest<'de, D>(deserializer: D) -> Result<[u8; 4], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    hex_to_array(&s).map_err(serde::de::Error::custom)
}

fn de_root_opt<'de, D>(deserializer: D) -> Result<Option<Root>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|s| hex_to_array(&s))
        .transpose()
        .map_err(serde::de::Error::custom)
}

fn hex_to_array<const N: usize>(hex: &str) -> TestUtilsResult<[u8; N]> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex)?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| format!("expected {N} bytes, got {}", b.len()).into())
}
