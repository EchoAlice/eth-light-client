use crate::config::{ChainSpecConfig, Fork};
use crate::types::primitives::Root;
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

pub(crate) fn case_path(fork_dir: &str, case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "tests/fixtures/minimal/{fork_dir}/light_client/sync/{case}"
    ))
}

fn _set_fork_epoch() {
    todo!()
}

/// Fork-activation epochs are overridden so `fork` and its ancestors
/// are active from genesis — the chain the single-fork fixtures were
/// generated on.
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

/// Resolve a fixture fork digest (`fork_data_root[..4]`, per the consensus
/// spec's `compute_fork_digest`) to the fork it identifies, by computing the
/// digest of every fork active in `config` and matching.
pub(crate) fn fork_for_digest(
    digest: [u8; 4],
    config: &ChainSpecConfig,
    genesis_validators_root: Root,
) -> Option<Fork> {
    let candidates = [
        (
            Fork::Altair,
            config.altair_fork_version,
            config.altair_fork_epoch,
        ),
        (
            Fork::Bellatrix,
            config.bellatrix_fork_version,
            config.bellatrix_fork_epoch,
        ),
        (
            Fork::Capella,
            config.capella_fork_version,
            config.capella_fork_epoch,
        ),
        (
            Fork::Deneb,
            config.deneb_fork_version,
            config.deneb_fork_epoch,
        ),
        (
            Fork::Electra,
            config.electra_fork_version,
            config.electra_fork_epoch,
        ),
    ];
    candidates
        .into_iter()
        .filter(|(_, _, epoch)| *epoch != u64::MAX) // inactive forks have no digest on this chain
        .find(|(_, version, _)| {
            let root = crate::consensus::sync_committee::compute_fork_data_root(
                *version,
                genesis_validators_root,
            );
            root[0..4] == digest
        })
        .map(|(fork, _, _)| fork)
}

#[cfg(test)]
mod tests {
    use super::{fork_dir, single_fork_config};
    use crate::config::Fork;

    /// Config.yaml keys we check. `Option` since earlier forks omit later-fork
    /// keys; versions are hex strings under YAML 1.2.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    struct ConfigYaml {
        preset_base: String,
        seconds_per_slot: u64,
        altair_fork_version: Option<String>,
        altair_fork_epoch: Option<u64>,
        bellatrix_fork_version: Option<String>,
        bellatrix_fork_epoch: Option<u64>,
        capella_fork_version: Option<String>,
        capella_fork_epoch: Option<u64>,
        deneb_fork_version: Option<String>,
        deneb_fork_epoch: Option<u64>,
        electra_fork_version: Option<String>,
        electra_fork_epoch: Option<u64>,
    }

    fn load_case_config_yaml(dir: &str, case: &str) -> ConfigYaml {
        let path = super::case_path(dir, case).join("config.yaml");
        let contents = std::fs::read_to_string(&path).expect("read config.yaml");
        serde_yaml::from_str(&contents).expect("parse config.yaml")
    }

    fn version_bytes(hex: &str) -> [u8; 4] {
        let h = hex.strip_prefix("0x").unwrap_or(hex);
        hex::decode(h)
            .expect("fork version hex")
            .try_into()
            .expect("fork version is 4 bytes")
    }

    /// Field-by-field comparison of a hardcoded schedule against a fixture's
    /// config.yaml, asserting whichever fork keys the yaml actually provides.
    fn assert_schedule_matches(
        label: &str,
        cfg: &crate::config::ChainSpecConfig,
        yaml: &ConfigYaml,
    ) {
        assert_eq!(yaml.preset_base, "minimal", "{label}: PRESET_BASE");
        assert_eq!(
            yaml.seconds_per_slot, cfg.seconds_per_slot,
            "{label}: SECONDS_PER_SLOT"
        );

        let check_v = |field: &str, y: &Option<String>, hardcoded: [u8; 4]| {
            if let Some(v) = y {
                assert_eq!(version_bytes(v), hardcoded, "{label}: {field}");
            }
        };
        let check_e = |field: &str, y: Option<u64>, hardcoded: u64| {
            if let Some(e) = y {
                assert_eq!(e, hardcoded, "{label}: {field}");
            }
        };

        check_v(
            "ALTAIR_FORK_VERSION",
            &yaml.altair_fork_version,
            cfg.altair_fork_version,
        );
        check_e(
            "ALTAIR_FORK_EPOCH",
            yaml.altair_fork_epoch,
            cfg.altair_fork_epoch,
        );
        check_v(
            "BELLATRIX_FORK_VERSION",
            &yaml.bellatrix_fork_version,
            cfg.bellatrix_fork_version,
        );
        check_e(
            "BELLATRIX_FORK_EPOCH",
            yaml.bellatrix_fork_epoch,
            cfg.bellatrix_fork_epoch,
        );
        check_v(
            "CAPELLA_FORK_VERSION",
            &yaml.capella_fork_version,
            cfg.capella_fork_version,
        );
        check_e(
            "CAPELLA_FORK_EPOCH",
            yaml.capella_fork_epoch,
            cfg.capella_fork_epoch,
        );
        check_v(
            "DENEB_FORK_VERSION",
            &yaml.deneb_fork_version,
            cfg.deneb_fork_version,
        );
        check_e(
            "DENEB_FORK_EPOCH",
            yaml.deneb_fork_epoch,
            cfg.deneb_fork_epoch,
        );
        check_v(
            "ELECTRA_FORK_VERSION",
            &yaml.electra_fork_version,
            cfg.electra_fork_version,
        );
        check_e(
            "ELECTRA_FORK_EPOCH",
            yaml.electra_fork_epoch,
            cfg.electra_fork_epoch,
        );
    }

    /// Guards the hardcoded minimal schedules against drift from the fixtures.
    /// config.yaml holds only the config half; the preset half isn't vendored,
    /// so for that we assert only `PRESET_BASE == minimal`.
    #[test]
    fn hardcoded_schedule_matches_vendored_config_yaml() {
        for fork in [
            Fork::Altair,
            Fork::Bellatrix,
            Fork::Capella,
            Fork::Deneb,
            Fork::Electra,
        ] {
            let cfg = single_fork_config(fork);
            let yaml = load_case_config_yaml(fork_dir(fork), "light_client_sync");
            assert_schedule_matches(fork_dir(fork), &cfg, &yaml);
        }
    }
}
