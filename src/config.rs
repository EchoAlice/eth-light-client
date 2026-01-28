use crate::types::primitives::Slot;

// =============================================================================
// Fork Enum
// =============================================================================

/// Ethereum consensus layer forks (post-merge light client relevant).
///
/// Each fork may change the BeaconState structure, affecting generalized indices
/// and the LightClientHeader format.
///
/// Internal to the crate - not part of the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Fork {
    /// Altair - Light client protocol introduced (Oct 2021)
    Altair,
    /// Bellatrix - The Merge (Sep 2022). No LC header changes.
    Bellatrix,
    /// Capella - Withdrawals (Apr 2023). LC header gains execution payload.
    Capella,
    /// Deneb - Blobs/4844 (Mar 2024). LC header adds blob fields.
    Deneb,
    /// Electra - Pectra upgrade (2025). BeaconState restructured, gindices change.
    Electra,
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

// =============================================================================
// ChainSpec
// =============================================================================

/// Ethereum consensus layer chain specification
///
/// Defines network-specific constants for mainnet and minimal (test) presets.
/// Includes fork schedule and fork-specific constants.
#[derive(Debug, Clone, Copy)]
pub struct ChainSpec {
    /// Preset name ("mainnet" or "minimal")
    pub preset_name: &'static str,

    /// Number of slots per epoch
    /// - Mainnet: 32
    /// - Minimal: 8
    pub slots_per_epoch: u64,

    /// Number of epochs per sync committee period
    /// - Mainnet: 256 (8192 slots/period)
    /// - Minimal: 8 (64 slots/period)
    pub epochs_per_sync_committee_period: u64,

    /// Sync committee size
    /// - Mainnet: 512
    /// - Minimal: 32
    pub sync_committee_size: usize,

    // =========================================================================
    // Fork Versions
    // =========================================================================
    pub altair_fork_version: [u8; 4],
    pub bellatrix_fork_version: [u8; 4],
    pub capella_fork_version: [u8; 4],
    pub deneb_fork_version: [u8; 4],
    pub electra_fork_version: [u8; 4],

    // =========================================================================
    // Fork Epochs (when each fork activates)
    // =========================================================================
    pub altair_fork_epoch: u64,
    pub bellatrix_fork_epoch: u64,
    pub capella_fork_epoch: u64,
    pub deneb_fork_epoch: u64,
    pub electra_fork_epoch: u64,

    // =========================================================================
    // Time
    // =========================================================================
    /// Genesis time (Unix timestamp)
    /// - Mainnet: 1606824023 (Dec 1, 2020, 12:00:23 UTC)
    /// - Minimal: 1578009600 (test preset, Jan 3, 2020)
    pub genesis_time: u64,

    /// Seconds per slot
    /// - Mainnet: 12
    /// - Minimal: 6 (faster for testing)
    pub seconds_per_slot: u64,
}

impl ChainSpec {
    /// Ethereum mainnet specification
    pub const fn mainnet() -> Self {
        Self {
            preset_name: "mainnet",
            slots_per_epoch: 32,
            epochs_per_sync_committee_period: 256,
            sync_committee_size: 512,

            // Fork versions (mainnet)
            altair_fork_version: [0x01, 0x00, 0x00, 0x00],
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
            capella_fork_version: [0x03, 0x00, 0x00, 0x00],
            deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
            electra_fork_version: [0x05, 0x00, 0x00, 0x00],

            // Fork epochs (mainnet)
            altair_fork_epoch: 74240,     // Oct 27, 2021
            bellatrix_fork_epoch: 144896, // Sep 6, 2022
            capella_fork_epoch: 194048,   // Apr 12, 2023
            deneb_fork_epoch: 269568,     // Mar 13, 2024
            electra_fork_epoch: 364544,   // May 7, 2025

            genesis_time: 1606824023, // Dec 1, 2020, 12:00:23 UTC
            seconds_per_slot: 12,
        }
    }

    /// Minimal test specification
    pub const fn minimal() -> Self {
        Self {
            preset_name: "minimal",
            slots_per_epoch: 8,
            epochs_per_sync_committee_period: 8,
            sync_committee_size: 32,

            // Fork versions (minimal preset)
            altair_fork_version: [0x01, 0x00, 0x00, 0x01],
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x01],
            capella_fork_version: [0x03, 0x00, 0x00, 0x01],
            deneb_fork_version: [0x04, 0x00, 0x00, 0x01],
            electra_fork_version: [0x05, 0x00, 0x00, 0x01],

            // Fork epochs (minimal preset for Altair tests)
            // Only Altair is active; later forks not yet activated
            altair_fork_epoch: 0,
            bellatrix_fork_epoch: u64::MAX,
            capella_fork_epoch: u64::MAX,
            deneb_fork_epoch: u64::MAX,
            electra_fork_epoch: u64::MAX,

            genesis_time: 1578009600, // Jan 3, 2020 (test value)
            seconds_per_slot: 6,      // Faster slots for testing
        }
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

    // =========================================================================
    // Fork Detection
    // =========================================================================

    /// Determine which fork is active at a given epoch.
    ///
    /// Returns the highest fork whose activation epoch is <= the given epoch.
    pub(crate) const fn fork_at_epoch(&self, epoch: u64) -> Fork {
        if epoch >= self.electra_fork_epoch {
            Fork::Electra
        } else if epoch >= self.deneb_fork_epoch {
            Fork::Deneb
        } else if epoch >= self.capella_fork_epoch {
            Fork::Capella
        } else if epoch >= self.bellatrix_fork_epoch {
            Fork::Bellatrix
        } else {
            Fork::Altair
        }
    }

    /// Determine which fork is active at a given slot.
    pub(crate) const fn fork_at_slot(&self, slot: Slot) -> Fork {
        self.fork_at_epoch(slot / self.slots_per_epoch)
    }

    /// Get the fork version for a given epoch.
    ///
    /// Used for computing signature domains.
    pub(crate) const fn fork_version_at_epoch(&self, epoch: u64) -> [u8; 4] {
        match self.fork_at_epoch(epoch) {
            Fork::Altair => self.altair_fork_version,
            Fork::Bellatrix => self.bellatrix_fork_version,
            Fork::Capella => self.capella_fork_version,
            Fork::Deneb => self.deneb_fork_version,
            Fork::Electra => self.electra_fork_version,
        }
    }

    /// Get the fork version for a given slot.
    #[allow(dead_code)] // Will be used in future fork-aware update processing
    pub(crate) const fn fork_version_at_slot(&self, slot: Slot) -> [u8; 4] {
        self.fork_version_at_epoch(slot / self.slots_per_epoch)
    }

    // =========================================================================
    // Beacon State Generalized Indices
    // =========================================================================
    //
    // These return the SSZ generalized index for various beacon state fields.
    // Indices changed in Electra due to BeaconState restructuring.
    //
    // Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md

    /// Get the generalized index for `BeaconState.current_sync_committee` at a given slot.
    ///
    /// - Altair through Deneb: 54
    /// - Electra onwards: 86
    #[inline]
    pub const fn current_sync_committee_gindex(&self, slot: Slot) -> u64 {
        match self.fork_at_slot(slot) {
            Fork::Electra => 86,
            _ => 54,
        }
    }

    /// Get the generalized index for `BeaconState.next_sync_committee` at a given slot.
    ///
    /// - Altair through Deneb: 55
    /// - Electra onwards: 87
    #[inline]
    pub const fn next_sync_committee_gindex(&self, slot: Slot) -> u64 {
        match self.fork_at_slot(slot) {
            Fork::Electra => 87,
            _ => 55,
        }
    }

    /// Get the generalized index for `BeaconState.finalized_checkpoint.root` at a given slot.
    ///
    /// - Altair through Deneb: 105
    /// - Electra onwards: 169
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
        assert_eq!(spec.preset_name, "mainnet");
        assert_eq!(spec.slots_per_epoch, 32);
        assert_eq!(spec.epochs_per_sync_committee_period, 256);
        assert_eq!(spec.sync_committee_size, 512);
        assert_eq!(spec.slots_per_sync_committee_period(), 8192);
        assert_eq!(spec.altair_fork_version, [0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_minimal_spec() {
        let spec = ChainSpec::minimal();
        assert_eq!(spec.preset_name, "minimal");
        assert_eq!(spec.slots_per_epoch, 8);
        assert_eq!(spec.epochs_per_sync_committee_period, 8);
        assert_eq!(spec.sync_committee_size, 32);
        assert_eq!(spec.slots_per_sync_committee_period(), 64);
        assert_eq!(spec.altair_fork_version, [0x01, 0x00, 0x00, 0x01]);
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

    // =========================================================================
    // Fork Detection Tests
    // =========================================================================

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

    // =========================================================================
    // Generalized Index Tests
    // =========================================================================

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
}
