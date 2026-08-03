use super::fork::{deneb_electra_fork_config, fork_for_digest};
use super::steps::{TestMeta, TestStep};
use super::{MinimalPresetFork, TestUtilsResult};
use crate::config::{ChainSpecConfig, Fork};
use crate::types::consensus::{LightClientBootstrap, LightClientUpdate};
use std::fs;
use std::path::{Path, PathBuf};

pub struct LightClientSyncTest {
    test_dir: PathBuf,
    config: ChainSpecConfig,
}

impl LightClientSyncTest {
    fn new(fork: MinimalPresetFork) -> Self {
        Self::with_case(fork.name(), "light_client_sync", fork.config())
    }

    fn with_case(dir: &str, case: &str, config: ChainSpecConfig) -> Self {
        let test_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "tests/fixtures/minimal/{dir}/light_client/sync/{case}"
        ));
        Self { test_dir, config }
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

    pub fn minimal_deneb() -> Self {
        Self::new(MinimalPresetFork::Deneb)
    }

    pub fn minimal_electra() -> Self {
        Self::new(MinimalPresetFork::Electra)
    }

    /// The cross-fork `electra_fork` spec test: Deneb bootstrap, chain forks
    /// to Electra at epoch 3, with Deneb- and Electra-format updates
    /// interleaved (see the fixture's steps.yaml).
    pub fn minimal_deneb_electra_fork() -> Self {
        Self::with_case("deneb", "electra_fork", deneb_electra_fork_config())
    }

    pub fn chain_spec(&self) -> crate::config::ChainSpec {
        crate::config::ChainSpec::try_from_config(self.config)
            .expect("minimal fixture config is valid")
    }

    /// Resolve a fixture fork digest against this test's chain schedule.
    fn resolve_fork(
        &self,
        digest: [u8; 4],
        genesis_validators_root: crate::types::primitives::Root,
    ) -> TestUtilsResult<Fork> {
        fork_for_digest(digest, &self.config, genesis_validators_root).ok_or_else(|| {
            format!(
                "no active fork in this test's schedule matches digest 0x{}",
                hex::encode(digest)
            )
            .into()
        })
    }

    pub fn load_bootstrap(&self) -> TestUtilsResult<LightClientBootstrap> {
        let meta = self.load_meta()?;
        let fork = self.resolve_fork(meta.bootstrap_fork_digest, meta.genesis_validators_root)?;
        let bytes = snappy_decompress(&self.test_dir.join("bootstrap.ssz_snappy"))?;
        // Drive the public decode path (dogfoods `from_ssz`); snappy framing is
        // a fixture concern, so it stays here — the beacon API serves raw SSZ.
        Ok(LightClientBootstrap::from_ssz(
            &bytes,
            fork,
            self.chain_spec().sync_committee_size(),
            meta.genesis_validators_root,
        )?)
    }

    /// `name` must not include the `.ssz_snappy` extension. `fork_digest` is
    /// the step's `update_fork_digest` — updates decode under their own fork,
    /// which in cross-fork sequences differs per update.
    pub fn load_update(
        &self,
        name: &str,
        fork_digest: [u8; 4],
    ) -> TestUtilsResult<LightClientUpdate> {
        let meta = self.load_meta()?;
        let fork = self.resolve_fork(fork_digest, meta.genesis_validators_root)?;
        let bytes = snappy_decompress(&self.test_dir.join(format!("{name}.ssz_snappy")))?;
        Ok(LightClientUpdate::from_ssz(
            &bytes,
            fork,
            self.chain_spec().sync_committee_size(),
        )?)
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
        // The fixture encodes each step as a single-key map (`- process_update:`),
        // which serde_yaml 0.9 only maps onto an externally-tagged enum through
        // its singleton_map adapter (plain from_str would expect `!` YAML tags).
        let steps: Vec<TestStep> = serde_yaml::with::singleton_map_recursive::deserialize(
            serde_yaml::Deserializer::from_str(&steps_contents),
        )?;
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
