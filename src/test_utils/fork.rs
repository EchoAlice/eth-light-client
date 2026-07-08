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
        use crate::config::{ChainSpec, ChainSpecConfig};

        let mut config = ChainSpecConfig {
            genesis_time: 1578009600,
            seconds_per_slot: 6,
            slots_per_epoch: 8,
            epochs_per_sync_committee_period: 8,
            sync_committee_size: 32,
            altair_fork_version: [0x01, 0x00, 0x00, 0x01],
            altair_fork_epoch: 0,
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x01],
            bellatrix_fork_epoch: u64::MAX,
            capella_fork_version: [0x03, 0x00, 0x00, 0x01],
            capella_fork_epoch: u64::MAX,
            deneb_fork_version: [0x04, 0x00, 0x00, 0x01],
            deneb_fork_epoch: u64::MAX,
            electra_fork_version: [0x05, 0x00, 0x00, 0x01],
            electra_fork_epoch: u64::MAX,
        };

        match self {
            MinimalPresetFork::Altair => {} // defaults are correct
            MinimalPresetFork::Bellatrix => {
                config.bellatrix_fork_epoch = 0;
            }
            MinimalPresetFork::Capella => {
                config.bellatrix_fork_epoch = 0;
                config.capella_fork_epoch = 0;
            }
        }

        ChainSpec::try_from_config(config).expect("minimal fixture config is valid")
    }
}
