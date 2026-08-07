use super::fork::{case_path, fork_dir, fork_for_digest, single_fork_config};
use super::steps::{TestMeta, TestStep};
use super::TestUtilsResult;
use crate::config::{ChainSpec, ChainSpecConfig, Fork};
use crate::types::consensus::{LightClientBootstrap, LightClientUpdate};
use std::fs;
use std::path::{Path, PathBuf};

pub struct SyncTestCase {
    case_dir: PathBuf,
    config: ChainSpecConfig,
    meta: TestMeta,
    spec: ChainSpec,
}

impl SyncTestCase {
    pub fn light_client_sync(fork: Fork) -> Self {
        let fork_dir = fork_dir(fork);
        Self::open(
            case_path(fork_dir, "light_client_sync"),
            single_fork_config(fork),
        )
    }

    // TODO(#112): implement — schedule from `transition_config(from, to)`,
    // case dir from `{fork_dir(to)}_fork` under `fork_dir(from)`.
    pub fn fork_transition(_from: Fork, _to: Fork) -> Self {
        todo!()
    }

    fn open(case_dir: PathBuf, config: ChainSpecConfig) -> Self {
        let meta_contents =
            fs::read_to_string(case_dir.join("meta.yaml")).expect("read case meta.yaml");
        let meta: TestMeta = serde_yaml::from_str(&meta_contents).expect("parse case meta.yaml");
        let spec = ChainSpec::try_from_config(config).expect("case chain schedule is valid");
        Self {
            case_dir,
            config,
            meta,
            spec,
        }
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
        let bytes = snappy_decompress(&self.case_dir.join("bootstrap.ssz_snappy"))?;
        // Drive the public decode path (dogfoods `from_ssz`); snappy framing is
        // a fixture concern, so it stays here — the beacon API serves raw SSZ.
        Ok(LightClientBootstrap::from_ssz(
            &bytes,
            fork,
            self.spec.sync_committee_size(),
            self.meta.genesis_validators_root,
        )?)
    }

    pub fn load_update(
        &self,
        name: &str,
        fork_digest: [u8; 4],
    ) -> TestUtilsResult<LightClientUpdate> {
        let fork = self.resolve_fork(fork_digest)?;
        let bytes = snappy_decompress(&self.case_dir.join(format!("{name}.ssz_snappy")))?;
        Ok(LightClientUpdate::from_ssz(
            &bytes,
            fork,
            self.spec.sync_committee_size(),
        )?)
    }

    pub fn load_steps(&self) -> TestUtilsResult<Vec<TestStep>> {
        let steps_path = self.case_dir.join("steps.yaml");
        let steps_contents = fs::read_to_string(&steps_path)?;
        let steps: Vec<TestStep> = serde_yaml::with::singleton_map_recursive::deserialize(
            serde_yaml::Deserializer::from_str(&steps_contents),
        )?;
        Ok(steps)
    }
}

fn snappy_decompress(file_path: &Path) -> TestUtilsResult<Vec<u8>> {
    let compressed = fs::read(file_path)?;
    let mut decoder = snap::raw::Decoder::new();
    Ok(decoder.decompress_vec(&compressed)?)
}
