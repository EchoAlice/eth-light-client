use crate::config::{ChainSpecConfig, Fork};
use std::path::{Path, PathBuf};

pub(crate) fn fork_dir(fork: Fork) -> &'static str {
    match fork {
        Fork::Altair => "altair",
        Fork::Bellatrix => "bellatrix",
        Fork::Capella => "capella",
        Fork::Deneb => "deneb",
        Fork::Electra => "electra",
    }
}

pub(crate) fn single_fork_config(fork: Fork) -> ChainSpecConfig {
    // Altair active at genesis: the LC floor
    let mut config = ChainSpecConfig::minimal();

    if fork >= Fork::Bellatrix {
        config.bellatrix_fork_epoch = 0;
    }
    if fork >= Fork::Capella {
        config.capella_fork_epoch = 0;
    }
    if fork >= Fork::Deneb {
        config.deneb_fork_epoch = 0;
    }
    if fork >= Fork::Electra {
        config.electra_fork_epoch = 0;
    }

    config
}

pub(crate) fn transition_config(from: Fork, to: Fork) -> ChainSpecConfig {
    let mut config = single_fork_config(from);
    let epoch = 3; // Epoch transitions are hardcoded in fixtures

    match to {
        Fork::Altair => config.altair_fork_epoch = epoch,
        Fork::Bellatrix => config.bellatrix_fork_epoch = epoch,
        Fork::Capella => config.capella_fork_epoch = epoch,
        Fork::Deneb => config.deneb_fork_epoch = epoch,
        Fork::Electra => config.electra_fork_epoch = epoch,
    }

    config
}

pub(crate) fn case_path(fork_dir: &str, case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "tests/fixtures/minimal/{fork_dir}/light_client/sync/{case}"
    ))
}
