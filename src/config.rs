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

impl Fork {
    /// Returns the fork name as used in spec test paths.
    #[allow(dead_code)] // Will be used when loading fork-specific test fixtures
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Fork::Altair => "altair",
            Fork::Bellatrix => "bellatrix",
            Fork::Capella => "capella",
            Fork::Deneb => "deneb",
            Fork::Electra => "electra",
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

    pub(crate) const fn altair_version(&self) -> [u8; 4] {
        self.altair.version()
    }
}

/// Configuration for creating a custom [`ChainSpec`].
///
/// Use this to configure a light client for local testnets or devnets.
/// For mainnet or standard test networks, use [`ChainSpec::mainnet()`] or [`ChainSpec::minimal()`].
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

    /// Must be 0 (light client protocol requires Altair from genesis).
    pub altair_fork_epoch: u64,
    pub bellatrix_fork_epoch: u64,
    pub capella_fork_epoch: u64,
    pub deneb_fork_epoch: u64,
    pub electra_fork_epoch: u64,
}

impl ChainSpecConfig {
    /// Validate the configuration.
    ///
    /// Returns an error if any values are invalid or inconsistent.
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

        // Light client protocol requires Altair from genesis
        if self.altair_fork_epoch != 0 {
            return Err(Error::InvalidInput(
                "altair_fork_epoch must be 0 (light client requires Altair from genesis)"
                    .to_string(),
            ));
        }

        // Fork epochs must be monotonically non-decreasing
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
    /// Ethereum mainnet specification
    pub const fn mainnet() -> Self {
        Self {
            preset_name: "mainnet",
            genesis_time: 1606824023,
            seconds_per_slot: 12,
            slots_per_epoch: 32,
            epochs_per_sync_committee_period: 256,
            sync_committee_size: 512,
            fork_schedule: ForkSchedule::new(
                ForkParams::new([0x01, 0x00, 0x00, 0x00], 74240),
                ForkParams::new([0x02, 0x00, 0x00, 0x00], 144896),
                ForkParams::new([0x03, 0x00, 0x00, 0x00], 194048),
                ForkParams::new([0x04, 0x00, 0x00, 0x00], 269568),
                ForkParams::new([0x05, 0x00, 0x00, 0x00], 364544),
            ),
        }
    }

    /// Minimal test specification
    pub const fn minimal() -> Self {
        Self {
            preset_name: "minimal",
            genesis_time: 1578009600,
            seconds_per_slot: 6,
            slots_per_epoch: 8,
            epochs_per_sync_committee_period: 8,
            sync_committee_size: 32,
            fork_schedule: ForkSchedule::new(
                ForkParams::new([0x01, 0x00, 0x00, 0x01], 0),
                ForkParams::new([0x02, 0x00, 0x00, 0x01], u64::MAX),
                ForkParams::new([0x03, 0x00, 0x00, 0x01], u64::MAX),
                ForkParams::new([0x04, 0x00, 0x00, 0x01], u64::MAX),
                ForkParams::new([0x05, 0x00, 0x00, 0x01], u64::MAX),
            ),
        }
    }

    /// Create a ChainSpec from a custom configuration.
    ///
    /// Use this for local testnets or devnets with non-standard parameters.
    /// The configuration is validated before the ChainSpec is created.
    pub fn try_from_config(config: ChainSpecConfig) -> Result<Self> {
        config.validate()?;

        Ok(Self {
            preset_name: "custom",
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
        })
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
        Self {
            preset_name: "test",
            genesis_time: 0,
            seconds_per_slot: 12,
            slots_per_epoch,
            epochs_per_sync_committee_period: 8,
            sync_committee_size: 32,
            fork_schedule: ForkSchedule::new(
                ForkParams::new(altair_fork_version, altair_fork_epoch),
                ForkParams::new(bellatrix_fork_version, bellatrix_fork_epoch),
                ForkParams::new([0x02, 0x00, 0x00, 0x00], u64::MAX),
                ForkParams::new([0x03, 0x00, 0x00, 0x00], u64::MAX),
                ForkParams::new([0x04, 0x00, 0x00, 0x00], u64::MAX),
            ),
        }
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

    pub(crate) const fn altair_fork_version(&self) -> [u8; 4] {
        self.fork_schedule.altair_version()
    }

    /// Calculate total slots per sync committee period
    pub const fn slots_per_sync_committee_period(&self) -> u64 {
        self.slots_per_epoch * self.epochs_per_sync_committee_period
    }

    /// Convert slot to epoch
    pub const fn slot_to_epoch(&self, slot: u64) -> u64 {
        slot / self.slots_per_epoch
    }

    /// Convert slot to sync committee period
    pub const fn slot_to_sync_committee_period(&self, slot: u64) -> u64 {
        self.slot_to_epoch(slot) / self.epochs_per_sync_committee_period
    }

    /// Convert epoch to sync committee period
    pub const fn epoch_to_sync_committee_period(&self, epoch: u64) -> u64 {
        epoch / self.epochs_per_sync_committee_period
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
    pub fn timestamp_to_slot(&self, timestamp_secs: u64) -> u64 {
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

    /// Get the fork version for a given slot.
    #[allow(dead_code)] // Will be used in future fork-aware update processing
    pub(crate) const fn fork_version_at_slot(&self, slot: Slot) -> [u8; 4] {
        self.fork_version_at_epoch(slot / self.slots_per_epoch)
    }

    // Beacon State Generalized Indices
    //
    // These return the SSZ generalized index for various beacon state fields.
    // Indices changed in Electra due to BeaconState restructuring.
    //
    // Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md
    #[inline]
    pub const fn current_sync_committee_gindex(&self, slot: Slot) -> u64 {
        match self.fork_at_slot(slot) {
            Fork::Electra => 86,
            _ => 54,
        }
    }

    /// Get the generalized index for `BeaconState.next_sync_committee` at a given slot.
    #[inline]
    pub const fn next_sync_committee_gindex(&self, slot: Slot) -> u64 {
        match self.fork_at_slot(slot) {
            Fork::Electra => 87,
            _ => 55,
        }
    }

    /// Get the generalized index for `BeaconState.finalized_checkpoint.root` at a given slot.
    #[inline]
    pub const fn finalized_root_gindex(&self, slot: Slot) -> u64 {
        match self.fork_at_slot(slot) {
            Fork::Electra => 169,
            _ => 105,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_spec() {
        let spec = ChainSpec::mainnet();
        assert_eq!(spec.preset_name(), "mainnet");
        assert_eq!(spec.slots_per_epoch(), 32);
        assert_eq!(spec.epochs_per_sync_committee_period(), 256);
        assert_eq!(spec.sync_committee_size(), 512);
        assert_eq!(spec.slots_per_sync_committee_period(), 8192);
        assert_eq!(spec.altair_fork_version(), [0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_minimal_spec() {
        let spec = ChainSpec::minimal();
        assert_eq!(spec.preset_name(), "minimal");
        assert_eq!(spec.slots_per_epoch(), 8);
        assert_eq!(spec.epochs_per_sync_committee_period(), 8);
        assert_eq!(spec.sync_committee_size(), 32);
        assert_eq!(spec.slots_per_sync_committee_period(), 64);
        assert_eq!(spec.altair_fork_version(), [0x01, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn test_slot_to_period_mainnet() {
        let spec = ChainSpec::mainnet();
        assert_eq!(spec.slot_to_sync_committee_period(0), 0);
        assert_eq!(spec.slot_to_sync_committee_period(8191), 0);
        assert_eq!(spec.slot_to_sync_committee_period(8192), 1);
        assert_eq!(spec.slot_to_sync_committee_period(16383), 1);
        assert_eq!(spec.slot_to_sync_committee_period(16384), 2);
    }

    #[test]
    fn test_slot_to_period_minimal() {
        let spec = ChainSpec::minimal();
        assert_eq!(spec.slot_to_sync_committee_period(0), 0);
        assert_eq!(spec.slot_to_sync_committee_period(63), 0);
        assert_eq!(spec.slot_to_sync_committee_period(64), 1);
        assert_eq!(spec.slot_to_sync_committee_period(127), 1);
        assert_eq!(spec.slot_to_sync_committee_period(128), 2);
    }

    #[test]
    fn test_period_boundaries() {
        let spec = ChainSpec::minimal();
        assert_eq!(spec.sync_committee_period_start_slot(0), 0);
        assert_eq!(spec.sync_committee_period_end_slot(0), 63);
        assert_eq!(spec.sync_committee_period_start_slot(1), 64);
        assert_eq!(spec.sync_committee_period_end_slot(1), 127);
    }

    #[test]
    fn test_timestamp_to_slot_mainnet() {
        let spec = ChainSpec::mainnet();
        // Mainnet genesis: Dec 1, 2020, 12:00:23 UTC
        // 12 seconds per slot
        assert_eq!(spec.timestamp_to_slot(1606824023), 0); // Genesis
        assert_eq!(spec.timestamp_to_slot(1606824023 + 12), 1); // 1 slot later
        assert_eq!(spec.timestamp_to_slot(1606824023 + 120), 10); // 10 slots later
        assert_eq!(spec.timestamp_to_slot(1606824023 - 100), 0); // Before genesis
    }

    #[test]
    fn test_timestamp_to_slot_minimal() {
        let spec = ChainSpec::minimal();
        // Minimal: 6 seconds per slot
        assert_eq!(spec.timestamp_to_slot(1578009600), 0); // Genesis
        assert_eq!(spec.timestamp_to_slot(1578009600 + 6), 1); // 1 slot later
        assert_eq!(spec.timestamp_to_slot(1578009600 + 60), 10); // 10 slots later
        assert_eq!(spec.timestamp_to_slot(1578009600 - 100), 0); // Before genesis
    }

    // Fork Detection Tests
    #[test]
    fn test_fork_at_epoch_mainnet() {
        let spec = ChainSpec::mainnet();

        // Before Altair (shouldn't happen in practice, but returns Altair)
        assert_eq!(spec.fork_at_epoch(0), Fork::Altair);

        // Altair epoch boundary
        assert_eq!(spec.fork_at_epoch(74239), Fork::Altair);
        assert_eq!(spec.fork_at_epoch(74240), Fork::Altair); // Altair activates

        // Bellatrix epoch boundary
        assert_eq!(spec.fork_at_epoch(144895), Fork::Altair);
        assert_eq!(spec.fork_at_epoch(144896), Fork::Bellatrix);

        // Capella epoch boundary
        assert_eq!(spec.fork_at_epoch(194047), Fork::Bellatrix);
        assert_eq!(spec.fork_at_epoch(194048), Fork::Capella);

        // Deneb epoch boundary
        assert_eq!(spec.fork_at_epoch(269567), Fork::Capella);
        assert_eq!(spec.fork_at_epoch(269568), Fork::Deneb);

        // Electra epoch boundary
        assert_eq!(spec.fork_at_epoch(364543), Fork::Deneb);
        assert_eq!(spec.fork_at_epoch(364544), Fork::Electra);

        // Far future
        assert_eq!(spec.fork_at_epoch(1_000_000), Fork::Electra);
    }

    #[test]
    fn test_fork_at_slot_mainnet() {
        let spec = ChainSpec::mainnet();

        // Bellatrix boundary: epoch 144896 * 32 slots = slot 4636672
        let bellatrix_start_slot = 144896 * 32;
        assert_eq!(spec.fork_at_slot(bellatrix_start_slot - 1), Fork::Altair);
        assert_eq!(spec.fork_at_slot(bellatrix_start_slot), Fork::Bellatrix);

        // Electra boundary: epoch 364544 * 32 slots = slot 11665408
        let electra_start_slot = 364544 * 32;
        assert_eq!(spec.fork_at_slot(electra_start_slot - 1), Fork::Deneb);
        assert_eq!(spec.fork_at_slot(electra_start_slot), Fork::Electra);
    }

    #[test]
    fn test_fork_version_at_epoch_mainnet() {
        let spec = ChainSpec::mainnet();

        assert_eq!(spec.fork_version_at_epoch(74240), [0x01, 0x00, 0x00, 0x00]); // Altair
        assert_eq!(spec.fork_version_at_epoch(144896), [0x02, 0x00, 0x00, 0x00]); // Bellatrix
        assert_eq!(spec.fork_version_at_epoch(194048), [0x03, 0x00, 0x00, 0x00]); // Capella
        assert_eq!(spec.fork_version_at_epoch(269568), [0x04, 0x00, 0x00, 0x00]); // Deneb
        assert_eq!(spec.fork_version_at_epoch(364544), [0x05, 0x00, 0x00, 0x00]);
        // Electra
    }

    #[test]
    fn test_fork_minimal_preset() {
        let spec = ChainSpec::minimal();

        // Minimal has only Altair active; all later forks at u64::MAX
        assert_eq!(spec.fork_at_epoch(0), Fork::Altair);
        assert_eq!(spec.fork_at_epoch(1000), Fork::Altair);
        assert_eq!(spec.fork_at_epoch(u64::MAX - 1), Fork::Altair);
        // Note: u64::MAX would match all fork epochs set to MAX, but since
        // we check in reverse order, it would return Electra. However, this
        // is an edge case that doesn't occur in practice.
    }

    #[test]
    fn test_fork_ordering() {
        // Ensure Fork enum ordering is correct for comparisons
        assert!(Fork::Altair < Fork::Bellatrix);
        assert!(Fork::Bellatrix < Fork::Capella);
        assert!(Fork::Capella < Fork::Deneb);
        assert!(Fork::Deneb < Fork::Electra);
    }

    #[test]
    fn test_fork_name() {
        assert_eq!(Fork::Altair.name(), "altair");
        assert_eq!(Fork::Bellatrix.name(), "bellatrix");
        assert_eq!(Fork::Capella.name(), "capella");
        assert_eq!(Fork::Deneb.name(), "deneb");
        assert_eq!(Fork::Electra.name(), "electra");
    }

    // Generalized Index Tests
    #[test]
    fn test_gindex_altair_through_deneb() {
        let spec = ChainSpec::mainnet();

        // Test slots in Altair through Deneb (all should use same gindices)
        let altair_slot = 74240 * 32; // First Altair slot
        let deneb_slot = 269568 * 32; // First Deneb slot

        // Altair
        assert_eq!(spec.current_sync_committee_gindex(altair_slot), 54);
        assert_eq!(spec.next_sync_committee_gindex(altair_slot), 55);
        assert_eq!(spec.finalized_root_gindex(altair_slot), 105);

        // Deneb (same gindices)
        assert_eq!(spec.current_sync_committee_gindex(deneb_slot), 54);
        assert_eq!(spec.next_sync_committee_gindex(deneb_slot), 55);
        assert_eq!(spec.finalized_root_gindex(deneb_slot), 105);
    }

    #[test]
    fn test_gindex_electra() {
        let spec = ChainSpec::mainnet();

        // Electra changes gindices due to BeaconState restructuring
        let electra_slot = 364544 * 32; // First Electra slot

        assert_eq!(spec.current_sync_committee_gindex(electra_slot), 86);
        assert_eq!(spec.next_sync_committee_gindex(electra_slot), 87);
        assert_eq!(spec.finalized_root_gindex(electra_slot), 169);
    }

    #[test]
    fn test_gindex_boundary() {
        let spec = ChainSpec::mainnet();

        // Test right at the Electra boundary
        let pre_electra_slot = 364544 * 32 - 1;
        let electra_slot = 364544 * 32;

        // Pre-Electra (Deneb)
        assert_eq!(spec.current_sync_committee_gindex(pre_electra_slot), 54);
        assert_eq!(spec.next_sync_committee_gindex(pre_electra_slot), 55);
        assert_eq!(spec.finalized_root_gindex(pre_electra_slot), 105);

        // Electra
        assert_eq!(spec.current_sync_committee_gindex(electra_slot), 86);
        assert_eq!(spec.next_sync_committee_gindex(electra_slot), 87);
        assert_eq!(spec.finalized_root_gindex(electra_slot), 169);
    }

    #[test]
    fn test_gindex_minimal_preset() {
        let spec = ChainSpec::minimal();

        // Minimal has Electra at u64::MAX, so all practical slots use pre-Electra gindices
        assert_eq!(spec.current_sync_committee_gindex(0), 54);
        assert_eq!(spec.next_sync_committee_gindex(0), 55);
        assert_eq!(spec.finalized_root_gindex(0), 105);

        assert_eq!(spec.current_sync_committee_gindex(1_000_000), 54);
        assert_eq!(spec.next_sync_committee_gindex(1_000_000), 55);
        assert_eq!(spec.finalized_root_gindex(1_000_000), 105);
    }

    // ChainSpecConfig Tests

    fn valid_config() -> ChainSpecConfig {
        ChainSpecConfig {
            genesis_time: 1700000000,
            seconds_per_slot: 12,
            slots_per_epoch: 32,
            epochs_per_sync_committee_period: 256,
            sync_committee_size: 512,
            altair_fork_version: [0x01, 0x00, 0x00, 0x00],
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
            capella_fork_version: [0x03, 0x00, 0x00, 0x00],
            deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
            electra_fork_version: [0x05, 0x00, 0x00, 0x00],
            altair_fork_epoch: 0,
            bellatrix_fork_epoch: 0,
            capella_fork_epoch: 0,
            deneb_fork_epoch: 0,
            electra_fork_epoch: 10,
        }
    }

    #[test]
    fn test_chainspec_config_valid() {
        let config = valid_config();
        assert!(config.validate().is_ok());

        let spec = ChainSpec::try_from_config(config).unwrap();
        assert_eq!(spec.preset_name(), "custom");
        assert_eq!(spec.genesis_time(), 1700000000);
        assert_eq!(spec.seconds_per_slot(), 12);
        assert_eq!(spec.slots_per_epoch(), 32);
        assert_eq!(spec.epochs_per_sync_committee_period(), 256);
        assert_eq!(spec.sync_committee_size(), 512);
    }

    #[test]
    fn test_chainspec_config_custom_timing() {
        let config = ChainSpecConfig {
            genesis_time: 1234567890,
            seconds_per_slot: 6,
            slots_per_epoch: 8,
            epochs_per_sync_committee_period: 8,
            sync_committee_size: 32,
            altair_fork_version: [0xAA, 0xBB, 0xCC, 0xDD],
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
            capella_fork_version: [0x03, 0x00, 0x00, 0x00],
            deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
            electra_fork_version: [0x05, 0x00, 0x00, 0x00],
            altair_fork_epoch: 0,
            bellatrix_fork_epoch: 100,
            capella_fork_epoch: 200,
            deneb_fork_epoch: 300,
            electra_fork_epoch: 400,
        };

        let spec = ChainSpec::try_from_config(config).unwrap();

        // Test slot_to_epoch with custom slots_per_epoch=8
        assert_eq!(spec.slot_to_epoch(0), 0);
        assert_eq!(spec.slot_to_epoch(7), 0);
        assert_eq!(spec.slot_to_epoch(8), 1);
        assert_eq!(spec.slot_to_epoch(16), 2);

        // Test fork_at_epoch with custom fork schedule
        assert_eq!(spec.fork_at_epoch(0), Fork::Altair);
        assert_eq!(spec.fork_at_epoch(99), Fork::Altair);
        assert_eq!(spec.fork_at_epoch(100), Fork::Bellatrix);
        assert_eq!(spec.fork_at_epoch(199), Fork::Bellatrix);
        assert_eq!(spec.fork_at_epoch(200), Fork::Capella);
        assert_eq!(spec.fork_at_epoch(300), Fork::Deneb);
        assert_eq!(spec.fork_at_epoch(400), Fork::Electra);

        // Test fork_version_at_epoch with custom fork version
        assert_eq!(spec.fork_version_at_epoch(0), [0xAA, 0xBB, 0xCC, 0xDD]);

        // Test fork_at_slot (slot 800 = epoch 100 = Bellatrix)
        assert_eq!(spec.fork_at_slot(800), Fork::Bellatrix);
    }

    #[test]
    fn test_chainspec_config_validation_seconds_per_slot() {
        let mut config = valid_config();
        config.seconds_per_slot = 0;
        assert!(config.validate().is_err());
        assert!(ChainSpec::try_from_config(config).is_err());
    }

    #[test]
    fn test_chainspec_config_validation_slots_per_epoch() {
        let mut config = valid_config();
        config.slots_per_epoch = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_chainspec_config_validation_epochs_per_period() {
        let mut config = valid_config();
        config.epochs_per_sync_committee_period = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_chainspec_config_validation_sync_committee_size() {
        // Valid sizes: 32 and 512
        let mut config = valid_config();
        config.sync_committee_size = 32;
        assert!(config.validate().is_ok());

        config.sync_committee_size = 512;
        assert!(config.validate().is_ok());

        // Invalid sizes
        config.sync_committee_size = 0;
        assert!(config.validate().is_err());

        config.sync_committee_size = 64;
        assert!(config.validate().is_err());

        config.sync_committee_size = 256;
        assert!(config.validate().is_err());

        config.sync_committee_size = 1024;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_chainspec_config_validation_altair_epoch() {
        let mut config = valid_config();
        config.altair_fork_epoch = 1; // Must be 0
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_chainspec_config_validation_fork_ordering() {
        // bellatrix < altair
        let mut config = valid_config();
        config.altair_fork_epoch = 0;
        config.bellatrix_fork_epoch = 0; // Equal is OK
        assert!(config.validate().is_ok());

        // capella < bellatrix
        let mut config = valid_config();
        config.bellatrix_fork_epoch = 100;
        config.capella_fork_epoch = 50;
        assert!(config.validate().is_err());

        // deneb < capella
        let mut config = valid_config();
        config.capella_fork_epoch = 100;
        config.deneb_fork_epoch = 50;
        assert!(config.validate().is_err());

        // electra < deneb
        let mut config = valid_config();
        config.deneb_fork_epoch = 100;
        config.electra_fork_epoch = 50;
        assert!(config.validate().is_err());
    }
}
