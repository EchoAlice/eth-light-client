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

impl MinimalPresetFork {
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
