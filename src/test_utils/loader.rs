//! Fixture loader: reads spec test files and builds production light client types.

use super::raw_ssz::{
    nodes_to_roots, raw_beacon_only_header_to_pub, raw_beacon_only_update_to_pub,
    raw_capella_header_to_pub, raw_capella_update_to_pub, RawCapellaLightClientBootstrap,
    RawCapellaLightClientUpdate, RawLightClientBootstrap, RawLightClientUpdate,
};
use super::steps::{TestMeta, TestStep};
use super::{MinimalPresetFork, TestUtilsResult};
use crate::types::consensus::{LightClientBootstrap, LightClientUpdate};
use ssz_rs::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

/// One fork's minimal light-client-sync spec test: its `ChainSpec` plus the
/// bootstrap / updates / steps loaded from the fixture directory.
///
/// **Unstable:** This API may change without notice.
pub struct LightClientSyncTest {
    test_dir: PathBuf,
    fork: MinimalPresetFork,
}

impl LightClientSyncTest {
    fn new(fork: MinimalPresetFork) -> Self {
        let dir = fork.name();
        let test_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "tests/fixtures/minimal/{dir}/light_client/sync/light_client_sync"
        ));
        Self { test_dir, fork }
    }

    pub fn minimal_altair() -> Self {
        Self::new(MinimalPresetFork::Altair)
    }

    pub fn minimal_bellatrix() -> Self {
        Self::new(MinimalPresetFork::Bellatrix)
    }

    pub fn minimal_capella() -> Self {
        Self::new(MinimalPresetFork::Capella)
    }

    pub fn chain_spec(&self) -> crate::config::ChainSpec {
        self.fork.chain_spec()
    }

    pub fn load_bootstrap(&self) -> TestUtilsResult<LightClientBootstrap> {
        let meta = self.load_meta()?;
        let genesis_validators_root = meta.genesis_validators_root;
        let bootstrap_path = self.test_dir.join("bootstrap.ssz_snappy");

        match self.fork {
            MinimalPresetFork::Altair | MinimalPresetFork::Bellatrix => {
                let bootstrap: RawLightClientBootstrap = load_ssz_snappy(&bootstrap_path)?;
                let sync_committee = bootstrap.current_sync_committee.into_sync_committee();
                let branch = nodes_to_roots(&bootstrap.current_sync_committee_branch);
                let header = raw_beacon_only_header_to_pub(self.fork, bootstrap.header);

                Ok(LightClientBootstrap::from_header(
                    header,
                    sync_committee,
                    branch,
                    genesis_validators_root,
                ))
            }
            MinimalPresetFork::Capella => {
                let bootstrap: RawCapellaLightClientBootstrap = load_ssz_snappy(&bootstrap_path)?;
                let sync_committee = bootstrap.current_sync_committee.into_sync_committee();
                let branch = nodes_to_roots(&bootstrap.current_sync_committee_branch);
                let header = raw_capella_header_to_pub(bootstrap.header)?;

                Ok(LightClientBootstrap::from_header(
                    header,
                    sync_committee,
                    branch,
                    genesis_validators_root,
                ))
            }
        }
    }

    /// `name` must not include the `.ssz_snappy` extension.
    pub fn load_update(&self, name: &str) -> TestUtilsResult<LightClientUpdate> {
        let update_path = self.test_dir.join(format!("{}.ssz_snappy", name));

        match self.fork {
            MinimalPresetFork::Altair | MinimalPresetFork::Bellatrix => {
                let raw: RawLightClientUpdate = load_ssz_snappy(&update_path)?;
                Ok(raw_beacon_only_update_to_pub(self.fork, raw))
            }
            MinimalPresetFork::Capella => {
                let raw: RawCapellaLightClientUpdate = load_ssz_snappy(&update_path)?;
                raw_capella_update_to_pub(raw)
            }
        }
    }

    pub(crate) fn load_meta(&self) -> TestUtilsResult<TestMeta> {
        let meta_path = self.test_dir.join("meta.yaml");
        let meta_contents = fs::read_to_string(&meta_path)?;
        let meta: TestMeta = serde_yaml::from_str(&meta_contents)?;
        Ok(meta)
    }

    pub fn load_steps(&self) -> TestUtilsResult<Vec<TestStep>> {
        let steps_path = self.test_dir.join("steps.yaml");
        let steps_contents = fs::read_to_string(&steps_path)?;
        let steps: Vec<TestStep> = serde_yaml::from_str(&steps_contents)?;
        Ok(steps)
    }
}

/// Load a minimal Altair bootstrap — a convenience for tests that only need a
/// valid bootstrap for setup.
#[cfg(test)]
pub(crate) fn load_altair_bootstrap() -> LightClientBootstrap {
    LightClientSyncTest::minimal_altair()
        .load_bootstrap()
        .expect("Failed to load bootstrap")
}

fn load_ssz_snappy<T>(file_path: &Path) -> TestUtilsResult<T>
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
