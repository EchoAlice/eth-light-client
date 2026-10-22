use eth_light_client::chain_spec::{ChainSpecConfig, Fork};
use std::path::{Path, PathBuf};

pub fn fork_dir(fork: Fork) -> &'static str {
    match fork {
        Fork::Altair => "altair",
        Fork::Bellatrix => "bellatrix",
        Fork::Capella => "capella",
        Fork::Deneb => "deneb",
        Fork::Electra => "electra",
        Fork::Fulu => "fulu",
    }
}

pub fn single_fork_config(fork: Fork) -> ChainSpecConfig {
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
    if fork >= Fork::Fulu {
        config.fulu_fork_epoch = 0;
    }

    config
}

/// The forks a transition case crosses: strictly after `from`, through `to`.
pub fn forks_crossed(from: Fork, to: Fork) -> Vec<Fork> {
    let all = [
        Fork::Altair,
        Fork::Bellatrix,
        Fork::Capella,
        Fork::Deneb,
        Fork::Electra,
        Fork::Fulu,
    ];
    all.into_iter().filter(|f| from < *f && *f <= to).collect()
}

pub fn transition_config(from: Fork, to: Fork) -> ChainSpecConfig {
    let mut config = single_fork_config(from);

    // Every fork after `from` through `to` activates at epochs 3, 4, 5, …
    for (i, fork) in forks_crossed(from, to).into_iter().enumerate() {
        let epoch = 3 + i as u64;
        match fork {
            Fork::Altair => config.altair_fork_epoch = epoch,
            Fork::Bellatrix => config.bellatrix_fork_epoch = epoch,
            Fork::Capella => config.capella_fork_epoch = epoch,
            Fork::Deneb => config.deneb_fork_epoch = epoch,
            Fork::Electra => config.electra_fork_epoch = epoch,
            Fork::Fulu => config.fulu_fork_epoch = epoch,
        }
    }

    config
}

pub fn case_path(fork_dir: &str, case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "tests/fixtures/minimal/{fork_dir}/light_client/sync/{case}"
    ))
}
