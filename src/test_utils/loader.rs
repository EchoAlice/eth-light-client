//! Fixture loader: reads spec test files and builds production light client types.

use super::steps::{TestMeta, TestStep};
use super::{MinimalPresetFork, TestUtilsResult};
use crate::types::consensus::{LightClientBootstrap, LightClientUpdate};
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
        let bytes = snappy_decompress(&self.test_dir.join("bootstrap.ssz_snappy"))?;
        // Drive the public decode path (dogfoods `from_ssz`); snappy framing is
        // a fixture concern, so it stays here — the beacon API serves raw SSZ.
        Ok(LightClientBootstrap::from_ssz(
            &bytes,
            self.fork.into(),
            meta.genesis_validators_root,
        )?)
    }

    /// `name` must not include the `.ssz_snappy` extension.
    pub fn load_update(&self, name: &str) -> TestUtilsResult<LightClientUpdate> {
        let bytes = snappy_decompress(&self.test_dir.join(format!("{name}.ssz_snappy")))?;
        Ok(LightClientUpdate::from_ssz(&bytes, self.fork.into())?)
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

/// Decompress a `.ssz_snappy` fixture into raw SSZ bytes. Snappy framing is a
/// fixture/gossip detail; the public `from_ssz` decoders take raw SSZ.
fn snappy_decompress(file_path: &Path) -> TestUtilsResult<Vec<u8>> {
    let compressed = fs::read(file_path)?;
    let mut decoder = snap::raw::Decoder::new();
    Ok(decoder.decompress_vec(&compressed)?)
}
