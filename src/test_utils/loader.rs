use super::fork::{case_path, fork_dir, single_fork_config, transition_config};
use super::steps::{TestMeta, TestStep};
use super::TestUtilsResult;
use crate::config::{ChainSpec, ChainSpecConfig, Fork};
use crate::types::consensus::{LightClientBootstrap, LightClientUpdate};
use std::fs;
use std::path::{Path, PathBuf};

pub struct SyncTestCase {
    case_dir: PathBuf,
    meta: TestMeta,
    spec: ChainSpec,
}

/// Public constructors exist for each type of test case supported.
impl SyncTestCase {
    pub fn light_client_sync(fork: Fork) -> Self {
        let fork_dir = fork_dir(fork);
        Self::open(
            case_path(fork_dir, "light_client_sync"),
            single_fork_config(fork),
        )
    }

    pub fn fork_transition(from: Fork, to: Fork) -> Self {
        let from_dir = fork_dir(from);
        let to_dir = fork_dir(to);
        Self::open(
            case_path(from_dir, &format!("{to_dir}_fork")),
            transition_config(from, to),
        )
    }

    fn open(case_dir: PathBuf, config: ChainSpecConfig) -> Self {
        let meta_contents =
            fs::read_to_string(case_dir.join("meta.yaml")).expect("read case meta.yaml");
        let meta: TestMeta = serde_yaml::from_str(&meta_contents).expect("parse case meta.yaml");
        let spec = ChainSpec::try_from_config(config).expect("case chain schedule is valid");
        Self {
            case_dir,
            meta,
            spec,
        }
    }

    pub fn load_steps(&self) -> TestUtilsResult<Vec<TestStep>> {
        let steps_path = self.case_dir.join("steps.yaml");
        let steps_contents = fs::read_to_string(&steps_path)?;
        let steps: Vec<TestStep> = serde_yaml::with::singleton_map_recursive::deserialize(
            serde_yaml::Deserializer::from_str(&steps_contents),
        )?;
        Ok(steps)
    }

    pub fn load_bootstrap(&self) -> TestUtilsResult<LightClientBootstrap> {
        let fork = Self::resolve_fork(self.meta.bootstrap_fork_digest)?;
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
        let fork = Self::resolve_fork(fork_digest)?;
        let bytes = snappy_decompress(&self.case_dir.join(format!("{name}.ssz_snappy")))?;
        Ok(LightClientUpdate::from_ssz(
            &bytes,
            fork,
            self.spec.sync_committee_size(),
        )?)
    }

    fn resolve_fork(digest: [u8; 4]) -> TestUtilsResult<Fork> {
        match digest {
            [0x15, 0xcf, 0xa0, 0xa7] => Ok(Fork::Altair),
            [0x79, 0x0e, 0x5b, 0x44] => Ok(Fork::Bellatrix),
            [0x85, 0x68, 0x42, 0xbe] => Ok(Fork::Capella),
            [0x0c, 0xbc, 0xe9, 0x01] => Ok(Fork::Deneb),
            [0x9a, 0xcb, 0x23, 0x0d] => Ok(Fork::Electra),
            _ => Err(format!(
                "no known minimal-preset fork digest matches 0x{}",
                hex::encode(digest)
            )
            .into()),
        }
    }

    pub fn chain_spec(&self) -> &ChainSpec {
        &self.spec
    }
}

fn snappy_decompress(file_path: &Path) -> TestUtilsResult<Vec<u8>> {
    let compressed = fs::read(file_path)?;
    let mut decoder = snap::raw::Decoder::new();
    Ok(decoder.decompress_vec(&compressed)?)
}
