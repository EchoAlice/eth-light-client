/// Minimal light client state - stores only what's necessary for consensus verification.
///
/// Light clients should NOT store full beacon blocks. They only need:
/// - Finalized and optimistic headers (~112 bytes each)
/// - Current and next sync committees (~24KB each)
/// - Merkle proofs for verification
pub(crate) struct BeaconConsensus {
    /// Light client processor for handling updates
    light_client: LightClientProcessor,
    /// Current sync status
    is_synced: bool,
    /// Last update timestamp
    last_update_time: std::time::SystemTime,
}

impl BeaconConsensus {
    /// Create new beacon consensus with verified bootstrap.
    ///
    /// The `current_sync_committee_branch` proves that `current_sync_committee` is
    /// correctly embedded in `trusted_header.state_root`. Verification happens in
    /// `LightClientProcessor::new`.
    ///
    /// # Arguments
    ///
    /// * `chain_spec` - Network configuration (mainnet/minimal)
    /// * `trusted_header` - A finalized beacon block header (from trusted source)
    /// * `current_sync_committee` - The sync committee (may be from untrusted source)
    /// * `current_sync_committee_branch` - Merkle proof for the sync committee
    /// * `genesis_validators_root` - For signature domain computation
    ///
    /// # Errors
    ///
    /// Returns an error if the sync committee branch proof fails verification.
    pub fn new(
        chain_spec: ChainSpec,
        trusted_header: BeaconBlockHeader,
        current_sync_committee: SyncCommittee,
        current_sync_committee_branch: &[Root],
        genesis_validators_root: Root,
    ) -> Result<Self> {
        let fork_version = chain_spec.altair_fork_version;

        let light_client = LightClientProcessor::new(
            chain_spec,
            trusted_header,
            current_sync_committee,
            current_sync_committee_branch,
            genesis_validators_root,
            fork_version,
        )?;

        Ok(Self {
            light_client,
            is_synced: false,
            last_update_time: std::time::SystemTime::now(),
        })
    }

    /// Process a light client update from the network using wall-clock time.
    ///
    /// This is a convenience wrapper that computes `current_slot` from system time.
    /// For spec-testable behavior, use `process_update_at_slot`.
    pub(crate) fn process_update(&mut self, update: LightClientUpdate) -> Result<bool> {
        let state_changed = self.light_client.process_light_client_update(update)?;

        if state_changed {
            self.last_update_time = std::time::SystemTime::now();
            self.is_synced = self.light_client.is_synced();
        }

        Ok(state_changed)
    }

    /// Process a light client update with an explicit current slot.
    ///
    /// This allows spec tests to inject the fixture's `current_slot` so that
    /// time-based validation is properly exercised.
    pub(crate) fn process_update_at_slot(
        &mut self,
        update: LightClientUpdate,
        current_slot: Slot,
    ) -> Result<bool> {
        let state_changed = self
            .light_client
            .process_light_client_update_at_slot(update, current_slot)?;

        if state_changed {
            self.last_update_time = std::time::SystemTime::now();
            self.is_synced = self.light_client.is_synced();
        }

        Ok(state_changed)
    }

    /// Get current finalized beacon block header
    pub(crate) fn get_finalized_header(&self) -> &BeaconBlockHeader {
        self.light_client.get_finalized_header()
    }

    /// Get current optimistic beacon block header
    pub(crate) fn get_optimistic_header(&self) -> &BeaconBlockHeader {
        self.light_client.get_optimistic_header()
    }

    /// Check if we're currently synced to the beacon chain
    pub(crate) fn is_synced(&self) -> bool {
        self.is_synced
    }

    /// Get current sync committee period
    pub(crate) fn get_current_period(&self) -> u64 {
        self.light_client.get_current_period()
    }

    /// Get the chain specification
    pub(crate) fn get_chain_spec(&self) -> &ChainSpec {
        self.light_client.get_chain_spec()
    }

    /// Get the current sync committee
    pub(crate) fn get_current_sync_committee(&self) -> &SyncCommittee {
        self.light_client.get_current_sync_committee()
    }

    /// Get the next sync committee if known
    pub(crate) fn get_next_sync_committee(&self) -> Option<&SyncCommittee> {
        self.light_client.get_next_sync_committee()
    }

    /// Check if a beacon header is from a trusted source (finalized or recent)
    #[cfg(test)]
    pub fn is_beacon_header_trusted(&self, beacon_header: &BeaconBlockHeader) -> bool {
        let finalized_header = self.get_finalized_header();
        let optimistic_header = self.get_optimistic_header();

        // Trust finalized headers
        if beacon_header.slot <= finalized_header.slot {
            return true;
        }

        // Trust recent headers (within a reasonable range of optimistic head)
        const MAX_SLOT_DISTANCE: u64 = 64; // About 12.8 minutes
        beacon_header.slot <= optimistic_header.slot + MAX_SLOT_DISTANCE
    }

    /// Compute the expected timestamp for a beacon slot
    #[cfg(test)]
    pub fn compute_beacon_timestamp(&self, slot: Slot) -> u64 {
        // In Ethereum, slot 0 corresponds to genesis time
        // Each slot is 12 seconds apart
        const SECONDS_PER_SLOT: u64 = 12;
        // Mainnet genesis timestamp
        const GENESIS_TIMESTAMP: u64 = 1606824000;

        GENESIS_TIMESTAMP + (slot * SECONDS_PER_SLOT)
    }
}

use super::light_client::LightClientProcessor;
use crate::config::ChainSpec;
use crate::error::Result;
use crate::types::consensus::{BeaconBlockHeader, LightClientUpdate, SyncCommittee};
use crate::types::primitives::{Root, Slot};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::light_client_spec_tests::load_bootstrap_fixture;

    fn create_test_beacon_header(slot: u64) -> BeaconBlockHeader {
        BeaconBlockHeader::new(
            slot, 42,        // proposer_index
            [1u8; 32], // parent_root
            [2u8; 32], // state_root
            [3u8; 32], // body_root
        )
    }

    #[test]
    fn test_beacon_consensus_creation() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = ChainSpec::minimal();
        let expected_slot = bootstrap.header.slot;

        let consensus = BeaconConsensus::new(
            chain_spec,
            bootstrap.header,
            bootstrap.current_sync_committee,
            &bootstrap.current_sync_committee_branch,
            bootstrap.genesis_validators_root,
        )
        .unwrap();

        assert_eq!(consensus.get_finalized_header().slot, expected_slot);
        assert_eq!(consensus.get_optimistic_header().slot, expected_slot);
        assert!(!consensus.is_synced()); // Should start unsynced
    }

    #[test]
    fn test_beacon_timestamp_computation() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = ChainSpec::minimal();

        let consensus = BeaconConsensus::new(
            chain_spec,
            bootstrap.header,
            bootstrap.current_sync_committee,
            &bootstrap.current_sync_committee_branch,
            bootstrap.genesis_validators_root,
        )
        .unwrap();

        // Test timestamp computation
        let timestamp_0 = consensus.compute_beacon_timestamp(0);
        let timestamp_1 = consensus.compute_beacon_timestamp(1);

        // Should be 12 seconds apart (slot time)
        assert_eq!(timestamp_1 - timestamp_0, 12);

        // Test with slot 1000
        let timestamp_1000 = consensus.compute_beacon_timestamp(1000);
        assert_eq!(timestamp_1000 - timestamp_0, 1000 * 12);
    }

    #[test]
    fn test_beacon_header_trusted() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = ChainSpec::minimal();
        let bootstrap_slot = bootstrap.header.slot;

        let consensus = BeaconConsensus::new(
            chain_spec,
            bootstrap.header,
            bootstrap.current_sync_committee,
            &bootstrap.current_sync_committee_branch,
            bootstrap.genesis_validators_root,
        )
        .unwrap();

        // Headers at or before finalized slot should be trusted
        let old_header = create_test_beacon_header(0);
        assert!(consensus.is_beacon_header_trusted(&old_header));

        // Header at finalized slot should be trusted
        let finalized_slot_header = create_test_beacon_header(bootstrap_slot);
        assert!(consensus.is_beacon_header_trusted(&finalized_slot_header));

        // Recent headers (within 64 slots) should be trusted
        let recent_header = create_test_beacon_header(bootstrap_slot + 50);
        assert!(consensus.is_beacon_header_trusted(&recent_header));

        // Far future headers should not be trusted
        let future_header = create_test_beacon_header(bootstrap_slot + 1000);
        assert!(!consensus.is_beacon_header_trusted(&future_header));
    }
}
