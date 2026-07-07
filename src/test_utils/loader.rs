//! Fixture loader: reads spec test files and builds production light client types.

use super::raw_ssz::{
    raw_beacon_only_header_to_pub, raw_beacon_only_update_to_pub, raw_capella_header_to_pub,
    raw_capella_update_to_pub, RawCapellaLightClientBootstrap, RawCapellaLightClientUpdate,
    RawLightClientBootstrap, RawLightClientUpdate,
};
use super::steps::{TestMeta, TestStep};
use super::{hex_to_root, TestFork};
use crate::types::consensus::{
    LightClientBootstrap, LightClientHeader, LightClientUpdate, SyncCommittee,
};
use crate::types::primitives::Root;
use ssz_rs::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct BootstrapData {
    pub header: LightClientHeader,
    pub sync_committee: SyncCommittee,
    pub branch: Vec<Root>,
    pub genesis_validators_root: Root,
}

impl BootstrapData {
    pub fn into_bootstrap(self) -> LightClientBootstrap {
        LightClientBootstrap::from_header(
            self.header,
            self.sync_committee,
            self.branch,
            self.genesis_validators_root,
        )
    }
}

/// Loads spec test fixtures from a directory.
///
/// **Unstable:** This API may change without notice.
pub struct SpecTestLoader {
    test_dir: PathBuf,
    fork: TestFork,
}

impl SpecTestLoader {
    /// Loader for the minimal Altair light-client sync fixtures.
    pub fn minimal_altair_sync() -> Self {
        let test_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/minimal/altair/light_client/sync/light_client_sync");
        Self {
            test_dir,
            fork: TestFork::Altair,
        }
    }

    /// Loader for the minimal Bellatrix light-client sync fixtures.
    pub fn minimal_bellatrix_sync() -> Self {
        let test_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/minimal/bellatrix/light_client/sync/light_client_sync");
        Self {
            test_dir,
            fork: TestFork::Bellatrix,
        }
    }

    /// Loader for the minimal Capella light-client sync fixtures.
    pub fn minimal_capella_sync() -> Self {
        let test_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/minimal/capella/light_client/sync/light_client_sync");
        Self {
            test_dir,
            fork: TestFork::Capella,
        }
    }

    pub fn from_path(path: impl Into<PathBuf>, fork: TestFork) -> Self {
        Self {
            test_dir: path.into(),
            fork,
        }
    }

    pub fn chain_spec(&self) -> crate::config::ChainSpec {
        self.fork.chain_spec()
    }

    pub fn load_bootstrap(&self) -> Result<BootstrapData, Box<dyn std::error::Error>> {
        let meta = self.load_meta()?;
        let genesis_validators_root = hex_to_root(&meta.genesis_validators_root)?;
        let bootstrap_path = self.test_dir.join("bootstrap.ssz_snappy");

        match self.fork {
            TestFork::Altair | TestFork::Bellatrix => {
                let bootstrap: RawLightClientBootstrap = load_ssz_snappy(&bootstrap_path)?;
                let sync_committee = bootstrap.current_sync_committee.to_sync_committee()?;
                let branch = nodes_to_roots(&bootstrap.current_sync_committee_branch);

                Ok(BootstrapData {
                    header: raw_beacon_only_header_to_pub(self.fork, bootstrap.header),
                    sync_committee,
                    branch,
                    genesis_validators_root,
                })
            }
            TestFork::Capella => {
                let bootstrap: RawCapellaLightClientBootstrap = load_ssz_snappy(&bootstrap_path)?;
                let sync_committee = bootstrap.current_sync_committee.to_sync_committee()?;
                let branch = nodes_to_roots(&bootstrap.current_sync_committee_branch);
                let header = raw_capella_header_to_pub(bootstrap.header)?;

                Ok(BootstrapData {
                    header,
                    sync_committee,
                    branch,
                    genesis_validators_root,
                })
            }
        }
    }

    /// `name` must not include the `.ssz_snappy` extension.
    pub fn load_update(&self, name: &str) -> Result<LightClientUpdate, Box<dyn std::error::Error>> {
        let update_path = self.test_dir.join(format!("{}.ssz_snappy", name));

        match self.fork {
            TestFork::Altair | TestFork::Bellatrix => {
                let raw: RawLightClientUpdate = load_ssz_snappy(&update_path)?;
                raw_beacon_only_update_to_pub(self.fork, raw).map_err(|e| e.into())
            }
            TestFork::Capella => {
                let raw: RawCapellaLightClientUpdate = load_ssz_snappy(&update_path)?;
                raw_capella_update_to_pub(raw).map_err(|e| e.into())
            }
        }
    }

    pub fn load_meta(&self) -> Result<TestMeta, Box<dyn std::error::Error>> {
        let meta_path = self.test_dir.join("meta.yaml");
        let meta_contents = fs::read_to_string(&meta_path)?;
        let meta: TestMeta = serde_yaml::from_str(&meta_contents)?;
        Ok(meta)
    }

    pub fn load_steps(&self) -> Result<Vec<TestStep>, Box<dyn std::error::Error>> {
        let steps_path = self.test_dir.join("steps.yaml");
        let steps_contents = fs::read_to_string(&steps_path)?;
        let steps: Vec<TestStep> = serde_yaml::from_str(&steps_contents)?;
        Ok(steps)
    }
}

fn nodes_to_roots(nodes: &[Node]) -> Vec<Root> {
    nodes
        .iter()
        .map(|node| {
            let mut root = [0u8; 32];
            root.copy_from_slice(node.as_ref());
            root
        })
        .collect()
}

fn load_ssz_snappy<T>(file_path: &Path) -> Result<T, Box<dyn std::error::Error>>
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
