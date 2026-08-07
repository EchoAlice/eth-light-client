use super::fork::{deneb_electra_fork_config, fixture_dir, fork_for_digest, single_fork_config};
use super::steps::{TestMeta, TestStep};
use super::TestUtilsResult;
use crate::config::{ChainSpec, ChainSpecConfig, Fork};
use crate::types::consensus::{LightClientBootstrap, LightClientUpdate};
use std::fs;
use std::path::{Path, PathBuf};

/// One case of the official `light_client/sync` suite, loaded: its fixture
/// directory plus everything derived from it at construction (parsed meta,
/// validated chain spec). Construction panics on a broken fixture — the
/// harness-wide policy.
pub struct SyncTestCase {
    test_dir: PathBuf,
    config: ChainSpecConfig,
    meta: TestMeta,
    spec: ChainSpec,
}

impl SyncTestCase {
    /// The single-fork `light_client_sync` case for `fork`: one `Fork` value
    /// determines both the fixture directory and the toy-chain calendar.
    /// (A *case* is one pyspec test-scenario directory; see the README.)
    pub fn new(fork: Fork) -> Self {
        Self::with_case(
            fixture_dir(fork),
            "light_client_sync",
            single_fork_config(fork),
        )
    }

    fn with_case(dir: &str, case: &str, config: ChainSpecConfig) -> Self {
        let test_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "tests/fixtures/minimal/{dir}/light_client/sync/{case}"
        ));
        let meta_contents =
            fs::read_to_string(test_dir.join("meta.yaml")).expect("read case meta.yaml");
        let meta: TestMeta = serde_yaml::from_str(&meta_contents).expect("parse case meta.yaml");
        let spec = ChainSpec::try_from_config(config).expect("case chain schedule is valid");
        Self {
            test_dir,
            config,
            meta,
            spec,
        }
    }

    /// The cross-fork `electra_fork` spec test: Deneb bootstrap, chain forks
    /// to Electra at epoch 3, with Deneb- and Electra-format updates
    /// interleaved (see the fixture's steps.yaml).
    pub fn deneb_electra_fork() -> Self {
        Self::with_case("deneb", "electra_fork", deneb_electra_fork_config())
    }

    pub fn chain_spec(&self) -> &ChainSpec {
        &self.spec
    }

    /// Resolve a fixture fork digest against this test's chain schedule.
    fn resolve_fork(&self, digest: [u8; 4]) -> TestUtilsResult<Fork> {
        fork_for_digest(digest, &self.config, self.meta.genesis_validators_root).ok_or_else(|| {
            format!(
                "no active fork in this case's schedule matches digest 0x{}",
                hex::encode(digest)
            )
            .into()
        })
    }

    pub fn load_bootstrap(&self) -> TestUtilsResult<LightClientBootstrap> {
        let fork = self.resolve_fork(self.meta.bootstrap_fork_digest)?;
        let bytes = snappy_decompress(&self.test_dir.join("bootstrap.ssz_snappy"))?;
        // Drive the public decode path (dogfoods `from_ssz`); snappy framing is
        // a fixture concern, so it stays here — the beacon API serves raw SSZ.
        Ok(LightClientBootstrap::from_ssz(
            &bytes,
            fork,
            self.spec.sync_committee_size(),
            self.meta.genesis_validators_root,
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
        let fork = self.resolve_fork(fork_digest)?;
        let bytes = snappy_decompress(&self.test_dir.join(format!("{name}.ssz_snappy")))?;
        Ok(LightClientUpdate::from_ssz(
            &bytes,
            fork,
            self.spec.sync_committee_size(),
        )?)
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
    SyncTestCase::new(Fork::Altair)
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
