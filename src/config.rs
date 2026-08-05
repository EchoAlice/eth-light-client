use crate::error::{Error, Result};
use crate::types::primitives::Slot;

/// Identifies a consensus fork, selecting the light client wire layout / rules
/// that apply. Used by [`ChainSpec`] internally and by the public
/// `LightClient{Update,Bootstrap}::from_ssz` decoders to pick the wire format.
/// For what each fork changed light-client-wise, see `src/README.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Fork {
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
}

/// Defines network-specific constants. Includes fork schedule and fork-specific constants.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ChainSpec {
    genesis_time: u64,
    seconds_per_slot: u64,
    slots_per_epoch: u64,
    epochs_per_sync_committee_period: u64,
    sync_committee_size: usize,
    fork_schedule: ForkSchedule,
}

impl ChainSpec {
    pub const fn mainnet() -> Self {
        Self::from_config(ChainSpecConfig::mainnet())
    }

    pub const fn minimal() -> Self {
        Self::from_config(ChainSpecConfig::minimal())
    }

    pub fn try_from_config(config: ChainSpecConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self::from_config(config))
    }

    /// The one place the config -> spec mapping lives; callers own validation.
    const fn from_config(config: ChainSpecConfig) -> Self {
        Self {
            genesis_time: config.genesis_time,
            seconds_per_slot: config.seconds_per_slot,
            slots_per_epoch: config.slots_per_epoch,
            epochs_per_sync_committee_period: config.epochs_per_sync_committee_period,
            sync_committee_size: config.sync_committee_size,
            fork_schedule: ForkSchedule::new(
                ForkParams::new(config.altair_fork_version, config.altair_fork_epoch),
                ForkParams::new(config.bellatrix_fork_version, config.bellatrix_fork_epoch),
                ForkParams::new(config.capella_fork_version, config.capella_fork_epoch),
                ForkParams::new(config.deneb_fork_version, config.deneb_fork_epoch),
                ForkParams::new(config.electra_fork_version, config.electra_fork_epoch),
            ),
        }
    }

    pub const fn slots_per_epoch(&self) -> u64 {
        self.slots_per_epoch
    }

    pub const fn sync_committee_size(&self) -> usize {
        self.sync_committee_size
    }

    pub const fn slots_per_sync_committee_period(&self) -> u64 {
        self.slots_per_epoch * self.epochs_per_sync_committee_period
    }

    pub(crate) const fn slot_to_epoch(&self, slot: u64) -> u64 {
        slot / self.slots_per_epoch
    }

    pub(crate) const fn slot_to_sync_committee_period(&self, slot: u64) -> u64 {
        self.slot_to_epoch(slot) / self.epochs_per_sync_committee_period
    }

    /// Current slot from a Unix timestamp.
    ///
    /// Pre-genesis timestamps map to slot 0 — fail-closed: a wrong/early clock
    /// lowers `current_slot`, and validation rejects updates with
    /// `signature_slot > current_slot`, so a bad clock rejects more, never
    /// accepts more.
    pub(crate) fn timestamp_to_slot(&self, timestamp_secs: u64) -> u64 {
        if timestamp_secs >= self.genesis_time {
            (timestamp_secs - self.genesis_time) / self.seconds_per_slot
        } else {
            0
        }
    }

    const fn fork_at_epoch(&self, epoch: u64) -> Fork {
        self.fork_schedule.fork_at_epoch(epoch)
    }

    /// Determine which fork is active at a given slot.
    const fn fork_at_slot(&self, slot: Slot) -> Fork {
        self.fork_at_epoch(slot / self.slots_per_epoch)
    }

    /// Get the fork version for a given epoch.
    ///
    /// Used for computing signature domains.
    pub(crate) const fn fork_version_at_epoch(&self, epoch: u64) -> [u8; 4] {
        self.fork_schedule.version_at_epoch(epoch)
    }

    #[inline]
    pub(crate) const fn current_sync_committee_gindex(&self, slot: Slot) -> u64 {
        match self.fork_at_slot(slot) {
            Fork::Electra => 86,
            _ => 54,
        }
    }

    #[inline]
    pub(crate) const fn next_sync_committee_gindex(&self, slot: Slot) -> u64 {
        match self.fork_at_slot(slot) {
            Fork::Electra => 87,
            _ => 55,
        }
    }

    #[inline]
    pub(crate) const fn finalized_root_gindex(&self, slot: Slot) -> u64 {
        match self.fork_at_slot(slot) {
            Fork::Electra => 169,
            _ => 105,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForkSchedule {
    altair: ForkParams,
    bellatrix: ForkParams,
    capella: ForkParams,
    deneb: ForkParams,
    electra: ForkParams,
}

impl ForkSchedule {
    pub(crate) const fn new(
        altair: ForkParams,
        bellatrix: ForkParams,
        capella: ForkParams,
        deneb: ForkParams,
        electra: ForkParams,
    ) -> Self {
        Self {
            altair,
            bellatrix,
            capella,
            deneb,
            electra,
        }
    }

    pub(crate) const fn fork_at_epoch(&self, epoch: u64) -> Fork {
        if epoch >= self.electra.epoch() {
            Fork::Electra
        } else if epoch >= self.deneb.epoch() {
            Fork::Deneb
        } else if epoch >= self.capella.epoch() {
            Fork::Capella
        } else if epoch >= self.bellatrix.epoch() {
            Fork::Bellatrix
        } else {
            Fork::Altair
        }
    }

    pub(crate) const fn version_at_epoch(&self, epoch: u64) -> [u8; 4] {
        match self.fork_at_epoch(epoch) {
            Fork::Altair => self.altair.version(),
            Fork::Bellatrix => self.bellatrix.version(),
            Fork::Capella => self.capella.version(),
            Fork::Deneb => self.deneb.version(),
            Fork::Electra => self.electra.version(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForkParams {
    version: [u8; 4],
    epoch: u64,
}

impl ForkParams {
    pub(crate) const fn new(version: [u8; 4], epoch: u64) -> Self {
        Self { version, epoch }
    }

    pub(crate) const fn version(&self) -> [u8; 4] {
        self.version
    }

    pub(crate) const fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Configurations for creating a [`ChainSpec`].
///
/// For mainnet, use [`ChainSpec::mainnet()`].
/// For spec tests / minimal preset parameters, use [`ChainSpec::minimal()`].
/// For other networks, build a custom spec with [`ChainSpec::try_from_config`].
///
/// # Example
///
/// Start from a preset and override what differs; [`ChainSpec::try_from_config`]
/// validates the result (e.g. fork-epoch ordering):
///
/// ```
/// use eth_light_client::{ChainSpec, ChainSpecConfig};
///
/// let config = ChainSpecConfig {
///     genesis_time: 1700000000,
///     bellatrix_fork_epoch: 10,
///     capella_fork_epoch: 20,
///     ..ChainSpecConfig::minimal()
/// };
///
/// let spec = ChainSpec::try_from_config(config).unwrap();
/// assert_eq!(spec.slots_per_epoch(), 8); // minimal-preset value carried through
/// ```

#[derive(Debug, Clone, Copy)]
pub struct ChainSpecConfig {
    pub genesis_time: u64,
    pub seconds_per_slot: u64,
    pub slots_per_epoch: u64,
    pub epochs_per_sync_committee_period: u64,
    pub sync_committee_size: usize,

    pub altair_fork_version: [u8; 4],
    pub bellatrix_fork_version: [u8; 4],
    pub capella_fork_version: [u8; 4],
    pub deneb_fork_version: [u8; 4],
    pub electra_fork_version: [u8; 4],

    pub altair_fork_epoch: u64,
    pub bellatrix_fork_epoch: u64,
    pub capella_fork_epoch: u64,
    pub deneb_fork_epoch: u64,
    pub electra_fork_epoch: u64,
}

impl ChainSpecConfig {
    pub const fn mainnet() -> Self {
        Self {
            genesis_time: 1606824023,
            seconds_per_slot: 12,
            slots_per_epoch: 32,
            epochs_per_sync_committee_period: 256,
            sync_committee_size: 512,
            altair_fork_version: [0x01, 0x00, 0x00, 0x00],
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
            capella_fork_version: [0x03, 0x00, 0x00, 0x00],
            deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
            electra_fork_version: [0x05, 0x00, 0x00, 0x00],
            altair_fork_epoch: 74240,
            bellatrix_fork_epoch: 144896,
            capella_fork_epoch: 194048,
            deneb_fork_epoch: 269568,
            electra_fork_epoch: 364544,
        }
    }

    pub const fn minimal() -> Self {
        Self {
            genesis_time: 1578009600,
            seconds_per_slot: 6,
            slots_per_epoch: 8,
            epochs_per_sync_committee_period: 8,
            sync_committee_size: 32,
            altair_fork_version: [0x01, 0x00, 0x00, 0x01],
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x01],
            capella_fork_version: [0x03, 0x00, 0x00, 0x01],
            deneb_fork_version: [0x04, 0x00, 0x00, 0x01],
            electra_fork_version: [0x05, 0x00, 0x00, 0x01],
            altair_fork_epoch: 0,
            bellatrix_fork_epoch: u64::MAX,
            capella_fork_epoch: u64::MAX,
            deneb_fork_epoch: u64::MAX,
            electra_fork_epoch: u64::MAX,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.seconds_per_slot == 0 {
            return Err(Error::InvalidInput(
                "seconds_per_slot must be > 0".to_string(),
            ));
        }
        if self.slots_per_epoch == 0 {
            return Err(Error::InvalidInput(
                "slots_per_epoch must be > 0".to_string(),
            ));
        }
        if self.epochs_per_sync_committee_period == 0 {
            return Err(Error::InvalidInput(
                "epochs_per_sync_committee_period must be > 0".to_string(),
            ));
        }

        // TODO: Figure out *why* these are the only two permitted sync committee sizes... this seems unnecessary, and at the very least, unnecessarily opaque.
        if self.sync_committee_size != 32 && self.sync_committee_size != 512 {
            return Err(Error::InvalidInput(
                "sync_committee_size must be 32 or 512".to_string(),
            ));
        }

        // Fork epochs are monotonically non-decreasing, anchored at Altair.
        if self.bellatrix_fork_epoch < self.altair_fork_epoch {
            return Err(Error::InvalidInput(
                "bellatrix_fork_epoch must be >= altair_fork_epoch".to_string(),
            ));
        }
        if self.capella_fork_epoch < self.bellatrix_fork_epoch {
            return Err(Error::InvalidInput(
                "capella_fork_epoch must be >= bellatrix_fork_epoch".to_string(),
            ));
        }
        if self.deneb_fork_epoch < self.capella_fork_epoch {
            return Err(Error::InvalidInput(
                "deneb_fork_epoch must be >= capella_fork_epoch".to_string(),
            ));
        }
        if self.electra_fork_epoch < self.deneb_fork_epoch {
            return Err(Error::InvalidInput(
                "electra_fork_epoch must be >= deneb_fork_epoch".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
