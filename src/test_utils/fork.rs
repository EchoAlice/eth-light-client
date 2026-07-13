//! The fork tag identifying which spec-test fixtures to load and how to
//! configure the chain for them.

/// The fork whose minimal-preset spec-test fixtures are being loaded; selects
/// both the fixture set and the matching minimal-preset chain configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MinimalPresetFork {
    Altair,
    Bellatrix,
    Capella,
}

impl From<MinimalPresetFork> for crate::config::Fork {
    fn from(fork: MinimalPresetFork) -> Self {
        match fork {
            MinimalPresetFork::Altair => crate::config::Fork::Altair,
            MinimalPresetFork::Bellatrix => crate::config::Fork::Bellatrix,
            MinimalPresetFork::Capella => crate::config::Fork::Capella,
        }
    }
}

impl MinimalPresetFork {
    /// Spec name / fixture directory for this fork.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            MinimalPresetFork::Altair => "altair",
            MinimalPresetFork::Bellatrix => "bellatrix",
            MinimalPresetFork::Capella => "capella",
        }
    }

    /// Return a `ChainSpec` whose fork schedule matches the spec-test fixtures
    /// for this fork.
    pub(crate) fn chain_spec(&self) -> crate::config::ChainSpec {
        crate::config::ChainSpec::try_from_config(self.config())
            .expect("minimal fixture config is valid")
    }

    /// [`ChainSpecConfig::minimal`] with the fork-activation epochs overridden
    /// per fork — which forks are active, i.e. which signing-domain version applies.
    fn config(&self) -> crate::config::ChainSpecConfig {
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
        }

        config
    }
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
    }

    fn load_config_yaml(fork: MinimalPresetFork) -> ConfigYaml {
        let dir = fork.name();
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "tests/fixtures/minimal/{dir}/light_client/sync/light_client_sync/config.yaml"
        ));
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

    /// Guards the hardcoded minimal schedule against drift from the fixtures.
    /// config.yaml holds only the config half; the preset half isn't vendored,
    /// so for that we assert only `PRESET_BASE == minimal`.
    #[test]
    fn hardcoded_schedule_matches_vendored_config_yaml() {
        for fork in [
            MinimalPresetFork::Altair,
            MinimalPresetFork::Bellatrix,
            MinimalPresetFork::Capella,
        ] {
            let cfg = fork.config();
            let yaml = load_config_yaml(fork);

            assert_eq!(yaml.preset_base, "minimal", "{:?}: PRESET_BASE", fork);
            assert_eq!(
                yaml.seconds_per_slot, cfg.seconds_per_slot,
                "{:?}: SECONDS_PER_SLOT",
                fork
            );

            // Assert whichever fork keys this fork's config.yaml actually provides.
            let check_v = |field: &str, y: &Option<String>, hardcoded: [u8; 4]| {
                if let Some(v) = y {
                    assert_eq!(version_bytes(v), hardcoded, "{:?}: {}", fork, field);
                }
            };
            let check_e = |field: &str, y: Option<u64>, hardcoded: u64| {
                if let Some(e) = y {
                    assert_eq!(e, hardcoded, "{:?}: {}", fork, field);
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
        }
    }
}
