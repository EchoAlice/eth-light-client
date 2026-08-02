/// The fork whose minimal-preset spec-test fixtures are being loaded; selects
/// both the fixture set and the matching minimal-preset chain configuration.
#[derive(Clone, Copy)]
pub(crate) enum MinimalPresetFork {
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
}

impl MinimalPresetFork {
    /// Spec name / fixture directory for this fork.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            MinimalPresetFork::Altair => "altair",
            MinimalPresetFork::Bellatrix => "bellatrix",
            MinimalPresetFork::Capella => "capella",
            MinimalPresetFork::Deneb => "deneb",
            MinimalPresetFork::Electra => "electra",
        }
    }

    /// [`ChainSpecConfig::minimal`] with the fork-activation epochs overridden
    /// per fork — which forks are active, i.e. which signing-domain version applies.
    pub(crate) fn config(&self) -> crate::config::ChainSpecConfig {
        let mut config = crate::config::ChainSpecConfig::minimal();

        match self {
            MinimalPresetFork::Altair => {} // later forks stay inactive (MAX)
            MinimalPresetFork::Bellatrix => {
                config.bellatrix_fork_epoch = 0;
            }
            MinimalPresetFork::Capella => {
                config.bellatrix_fork_epoch = 0;
                config.capella_fork_epoch = 0;
            }
            MinimalPresetFork::Deneb => {
                config.bellatrix_fork_epoch = 0;
                config.capella_fork_epoch = 0;
                config.deneb_fork_epoch = 0;
            }
            MinimalPresetFork::Electra => {
                config.bellatrix_fork_epoch = 0;
                config.capella_fork_epoch = 0;
                config.deneb_fork_epoch = 0;
                config.electra_fork_epoch = 0;
            }
        }

        config
    }
}

/// Chain schedule for the cross-fork `electra_fork` spec test: the store
/// bootstraps under Deneb (epoch 0) and the chain forks to Electra at epoch 3,
/// matching the vendored fixture's config.yaml (drift-guarded below).
pub(crate) fn deneb_electra_fork_config() -> crate::config::ChainSpecConfig {
    let mut config = MinimalPresetFork::Deneb.config();
    config.electra_fork_epoch = 3;
    config
}

/// Resolve a fixture fork digest (`fork_data_root[..4]`, per the consensus
/// spec's `compute_fork_digest`) to the fork it identifies, by computing the
/// digest of every fork active in `config` and matching.
pub(crate) fn fork_for_digest(
    digest: [u8; 4],
    config: &crate::config::ChainSpecConfig,
    genesis_validators_root: crate::types::primitives::Root,
) -> Option<crate::config::Fork> {
    use crate::config::Fork;
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
    use super::MinimalPresetFork;
    use std::path::Path;

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
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "tests/fixtures/minimal/{dir}/light_client/sync/{case}/config.yaml"
        ));
        let contents = std::fs::read_to_string(&path).expect("read config.yaml");
        serde_yaml::from_str(&contents).expect("parse config.yaml")
    }

    fn load_config_yaml(fork: MinimalPresetFork) -> ConfigYaml {
        load_case_config_yaml(fork.name(), "light_client_sync")
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

    /// Guards the hardcoded minimal schedule against drift from the fixtures.
    /// config.yaml holds only the config half; the preset half isn't vendored,
    /// so for that we assert only `PRESET_BASE == minimal`.
    #[test]
    fn hardcoded_schedule_matches_vendored_config_yaml() {
        for fork in [
            MinimalPresetFork::Altair,
            MinimalPresetFork::Bellatrix,
            MinimalPresetFork::Capella,
            MinimalPresetFork::Deneb,
            MinimalPresetFork::Electra,
        ] {
            let cfg = fork.config();
            let yaml = load_config_yaml(fork);
            assert_schedule_matches(fork.name(), &cfg, &yaml);
        }
    }

    /// Same drift guard for the cross-fork `electra_fork` schedule (Deneb at
    /// epoch 0, Electra at epoch 3).
    #[test]
    fn cross_fork_schedule_matches_vendored_config_yaml() {
        let cfg = super::deneb_electra_fork_config();
        let yaml = load_case_config_yaml("deneb", "electra_fork");
        assert_schedule_matches("deneb/electra_fork", &cfg, &yaml);
    }
}
