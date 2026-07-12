use crate::error::{Error, Result};
use crate::types::primitives::Slot;

/// Each fork may change the BeaconState structure, affecting generalized indices and the LightClientHeader format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Fork {
    Altair,    // Light client protocol introduced (Oct 2021)
    Bellatrix, // The Merge (Sep 2022). No LC header changes.
    Capella,   // Withdrawals (Apr 2023). LC header gains execution payload.
    Deneb,     // Blobs/4844 (Mar 2024). LC header adds blob fields.
    Electra,   // Pectra upgrade (2025). BeaconState restructured, gindice change.
}

/// Complete fork schedule for a network.
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

    /// Determine which fork is active at a given epoch.
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

    /// Get the fork version for a given epoch.
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

/// Fork version and activation epoch for a single fork.
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
/// ```
/// use eth_light_client::{ChainSpec, ChainSpecConfig};
///
/// let config = ChainSpecConfig {
///     genesis_time: 1700000000,
///     seconds_per_slot: 12,
///     slots_per_epoch: 32,
///     epochs_per_sync_committee_period: 256,
///     sync_committee_size: 512,
///     altair_fork_version: [0x01, 0x00, 0x00, 0x00],
///     bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
///     capella_fork_version: [0x03, 0x00, 0x00, 0x00],
///     deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
///     electra_fork_version: [0x05, 0x00, 0x00, 0x00],
///     altair_fork_epoch: 0,
///     bellatrix_fork_epoch: 10,
///     capella_fork_epoch: 20,
///     deneb_fork_epoch: 30,
///     electra_fork_epoch: 40,
/// };
///
/// let spec = ChainSpec::try_from_config(config).unwrap();
/// assert_eq!(spec.genesis_time(), 1700000000);
/// ```

#[derive(Debug, Clone, Copy)]
pub struct ChainSpecConfig {
    pub genesis_time: u64,
    pub seconds_per_slot: u64,
    pub slots_per_epoch: u64,
    pub epochs_per_sync_committee_period: u64,
    /// Must be 32 (minimal) or 512 (mainnet).
    pub sync_committee_size: usize,

    pub altair_fork_version: [u8; 4],
    pub bellatrix_fork_version: [u8; 4],
    pub capella_fork_version: [u8; 4],
    pub deneb_fork_version: [u8; 4],
    pub electra_fork_version: [u8; 4],

    /// Altair activation epoch; the monotonic floor of the fork schedule
    /// (may be nonzero, e.g. mainnet's 74240).
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

        // Strict validation: only 32 or 512 are valid sync committee sizes
        if self.sync_committee_size != 32 && self.sync_committee_size != 512 {
            return Err(Error::InvalidInput(
                "sync_committee_size must be 32 or 512".to_string(),
            ));
        }

        // Fork epochs must be monotonically non-decreasing, anchored at Altair. The light client operates from Altair onward via its trusted bootstrap, so Altair may activate at any epoch (e.g. mainnet at 74240), not only genesis — it just cannot come after a later fork.
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

/// Defines network-specific constants for mainnet and minimal (test) presets.
/// Includes fork schedule and fork-specific constants.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ChainSpec {
    preset_name: &'static str,
    genesis_time: u64,
    seconds_per_slot: u64,
    slots_per_epoch: u64,
    epochs_per_sync_committee_period: u64,
    sync_committee_size: usize,
    fork_schedule: ForkSchedule,
}

impl ChainSpec {
    pub const fn mainnet() -> Self {
        Self::from_config(ChainSpecConfig::mainnet(), "mainnet")
    }

    pub const fn minimal() -> Self {
        Self::from_config(ChainSpecConfig::minimal(), "minimal")
    }

    /// Use this for local testnets or devnets with non-standard parameters.
    pub fn try_from_config(config: ChainSpecConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self::from_config(config, "custom"))
    }

    /// The one place the config -> spec mapping lives; callers own validation.
    const fn from_config(config: ChainSpecConfig, preset_name: &'static str) -> Self {
        Self {
            preset_name,
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

    /// Test constructor for creating custom specs (e.g., fork boundary tests).
    #[cfg(test)]
    pub(crate) fn for_test(
        slots_per_epoch: u64,
        altair_fork_version: [u8; 4],
        bellatrix_fork_version: [u8; 4],
        altair_fork_epoch: u64,
        bellatrix_fork_epoch: u64,
    ) -> Self {
        // Later forks are pinned past reach (u64::MAX), so their versions are
        // never active; values are placeholders. from_config keeps this on the
        // single config->spec mapping.
        Self::from_config(
            ChainSpecConfig {
                genesis_time: 0,
                seconds_per_slot: 12,
                slots_per_epoch,
                epochs_per_sync_committee_period: 8,
                sync_committee_size: 32,
                altair_fork_version,
                bellatrix_fork_version,
                capella_fork_version: [0x03, 0x00, 0x00, 0x00],
                deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
                electra_fork_version: [0x05, 0x00, 0x00, 0x00],
                altair_fork_epoch,
                bellatrix_fork_epoch,
                capella_fork_epoch: u64::MAX,
                deneb_fork_epoch: u64::MAX,
                electra_fork_epoch: u64::MAX,
            },
            "test",
        )
    }

    pub const fn preset_name(&self) -> &'static str {
        self.preset_name
    }

    pub const fn genesis_time(&self) -> u64 {
        self.genesis_time
    }

    pub const fn seconds_per_slot(&self) -> u64 {
        self.seconds_per_slot
    }

    pub const fn slots_per_epoch(&self) -> u64 {
        self.slots_per_epoch
    }

    pub const fn epochs_per_sync_committee_period(&self) -> u64 {
        self.epochs_per_sync_committee_period
    }

    pub const fn sync_committee_size(&self) -> usize {
        self.sync_committee_size
    }

    /// Calculate total slots per sync committee period
    pub const fn slots_per_sync_committee_period(&self) -> u64 {
        self.slots_per_epoch * self.epochs_per_sync_committee_period
    }

    /// Convert slot to epoch
    pub(crate) const fn slot_to_epoch(&self, slot: u64) -> u64 {
        slot / self.slots_per_epoch
    }

    /// Convert slot to sync committee period
    pub(crate) const fn slot_to_sync_committee_period(&self, slot: u64) -> u64 {
        self.slot_to_epoch(slot) / self.epochs_per_sync_committee_period
    }

    /// Get start slot of a sync committee period
    pub const fn sync_committee_period_start_slot(&self, period: u64) -> u64 {
        period * self.slots_per_sync_committee_period()
    }

    /// Get end slot of a sync committee period (inclusive)
    pub const fn sync_committee_period_end_slot(&self, period: u64) -> u64 {
        self.sync_committee_period_start_slot(period + 1) - 1
    }

    /// Calculate current slot from Unix timestamp
    ///
    /// Returns 0 if the timestamp is before genesis (e.g., system clock is wrong)
    pub(crate) fn timestamp_to_slot(&self, timestamp_secs: u64) -> u64 {
        if timestamp_secs >= self.genesis_time {
            (timestamp_secs - self.genesis_time) / self.seconds_per_slot
        } else {
            0
        }
    }

    /// Determine which fork is active at a given epoch.
    ///
    /// Returns the highest fork whose activation epoch is <= the given epoch.
    pub(crate) const fn fork_at_epoch(&self, epoch: u64) -> Fork {
        self.fork_schedule.fork_at_epoch(epoch)
    }

    /// Determine which fork is active at a given slot.
    pub(crate) const fn fork_at_slot(&self, slot: Slot) -> Fork {
        self.fork_at_epoch(slot / self.slots_per_epoch)
    }

    /// Get the fork version for a given epoch.
    ///
    /// Used for computing signature domains.
    pub(crate) const fn fork_version_at_epoch(&self, epoch: u64) -> [u8; 4] {
        self.fork_schedule.version_at_epoch(epoch)
    }

    // Beacon State Generalized Indices
    //
    // These return the SSZ generalized index for various beacon state fields.
    // Indices changed in Electra due to BeaconState restructuring.
    //
    // Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md
    #[inline]
    pub(crate) const fn current_sync_committee_gindex(&self, slot: Slot) -> u64 {
        match self.fork_at_slot(slot) {
            Fork::Electra => 86,
            _ => 54,
        }
    }

    /// Get the generalized index for `BeaconState.next_sync_committee` at a given slot.
    #[inline]
    pub(crate) const fn next_sync_committee_gindex(&self, slot: Slot) -> u64 {
        match self.fork_at_slot(slot) {
            Fork::Electra => 87,
            _ => 55,
        }
    }

    /// Get the generalized index for `BeaconState.finalized_checkpoint.root` at a given slot.
    #[inline]
    pub(crate) const fn finalized_root_gindex(&self, slot: Slot) -> u64 {
        match self.fork_at_slot(slot) {
            Fork::Electra => 169,
            _ => 105,
        }
    }
}

#[cfg(test)]
mod tests;
