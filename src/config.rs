use crate::types::primitives::Slot;

/// Ethereum consensus layer chain specification
///
/// Defines network-specific constants for mainnet and minimal (test) presets.
/// Currently supports Altair fork only.
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

    /// Altair fork version
    /// - Mainnet: [0x01, 0x00, 0x00, 0x00]
    /// - Minimal: [0x01, 0x00, 0x00, 0x01]
    pub altair_fork_version: [u8; 4],

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
            altair_fork_version: [0x01, 0x00, 0x00, 0x00],
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
            altair_fork_version: [0x01, 0x00, 0x00, 0x01],
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
    // Beacon State Generalized Indices
    // =========================================================================
    //
    // These return the SSZ generalized index for various beacon state fields.
    // Currently Altair-only. Future forks (Electra) will branch on slot/epoch.
    //
    // Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md

    /// Get the generalized index for `BeaconState.current_sync_committee` at a given slot.
    ///
    /// Altair: 54
    #[inline]
    pub const fn current_sync_committee_gindex(&self, _slot: Slot) -> u64 {
        54 // Altair gindex (future: branch on slot for Electra → 86)
    }

    /// Get the generalized index for `BeaconState.next_sync_committee` at a given slot.
    ///
    /// Altair: 55
    #[inline]
    pub const fn next_sync_committee_gindex(&self, _slot: Slot) -> u64 {
        55 // Altair gindex (future: branch on slot for Electra → 87)
    }

    /// Get the generalized index for `BeaconState.finalized_checkpoint.root` at a given slot.
    ///
    /// Altair: 105
    #[inline]
    pub const fn finalized_root_gindex(&self, _slot: Slot) -> u64 {
        105 // Altair gindex (future: branch on slot for Electra → 169)
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
}
