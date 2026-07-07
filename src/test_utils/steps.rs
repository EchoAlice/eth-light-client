//! YAML metadata and step types deserialized from spec test fixtures.

/// Metadata from a spec test's meta.yaml file.
#[derive(Debug, serde::Deserialize)]
pub struct TestMeta {
    pub genesis_validators_root: String,
    #[allow(dead_code)]
    trusted_block_root: String,
    #[allow(dead_code)]
    bootstrap_fork_digest: String,
    #[allow(dead_code)]
    store_fork_digest: String,
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
    ProcessUpdate {
        process_update: ProcessUpdateStep,
    },
    /// Force update (safety timeout mechanism).
    ForceUpdate {
        force_update: ForceUpdateStep,
    },
}

#[derive(Debug, serde::Deserialize)]
pub struct ProcessUpdateStep {
    #[allow(dead_code)]
    update_fork_digest: String,
    /// Update file name (without .ssz_snappy extension).
    pub update: String,
    pub current_slot: u64,
    pub checks: StateChecks,
}

#[derive(Debug, serde::Deserialize)]
pub struct ForceUpdateStep {
    pub current_slot: u64,
    pub checks: StateChecks,
}
