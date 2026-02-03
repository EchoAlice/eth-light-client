use crate::config::ChainSpec;
use crate::consensus::merkle::{verify_bootstrap_sync_committee, verify_finality_branch};
use crate::consensus::sync_committee::SyncCommitteeTracker;
use crate::error::{Error, Result};
use crate::types::consensus::{
    BeaconBlockHeader, LightClientStore, LightClientUpdate, SyncCommittee,
};
use crate::types::primitives::Root;
use crate::types::primitives::Slot;
use std::time::{SystemTime, UNIX_EPOCH};

/// Light client processor for handling beacon chain updates.
/// Internal to the crate - not part of the public API.
#[derive(Debug)]
pub(crate) struct LightClientProcessor {
    /// Chain specification (mainnet or minimal)
    chain_spec: ChainSpec,
    /// Current trusted state
    store: LightClientStore,
    /// Sync committee tracker
    sync_committee_tracker: SyncCommitteeTracker,
}

impl LightClientProcessor {
    /// Create a new light client processor with verified bootstrap.
    ///
    /// The `current_sync_committee_branch` proves that `current_sync_committee` is
    /// correctly embedded in `trusted_header.state_root`. This verification is
    /// mandatory - there is no unverified constructor path.
    ///
    /// # Arguments
    ///
    /// * `chain_spec` - Network configuration
    /// * `trusted_header` - A finalized beacon block header (from trusted source)
    /// * `current_sync_committee` - The sync committee (may be from untrusted source)
    /// * `current_sync_committee_branch` - Merkle proof for the sync committee
    /// * `genesis_validators_root` - For signature domain computation
    /// * `fork_version` - Current fork version for signatures
    ///
    /// # Errors
    ///
    /// Returns an error if the sync committee branch proof fails verification.
    pub(crate) fn new(
        chain_spec: ChainSpec,
        trusted_header: BeaconBlockHeader,
        current_sync_committee: SyncCommittee,
        current_sync_committee_branch: &[Root],
        genesis_validators_root: Root,
        fork_version: [u8; 4],
    ) -> Result<Self> {
        // Verify that the sync committee is properly embedded in the trusted state
        verify_bootstrap_sync_committee(
            &current_sync_committee,
            current_sync_committee_branch,
            trusted_header.slot,
            &trusted_header.state_root,
            &chain_spec,
        )?;

        // Verification passed - create the light client processor
        let store = LightClientStore::new(
            trusted_header.clone(),
            current_sync_committee.clone(),
            genesis_validators_root,
        );
        let initial_period = chain_spec.slot_to_sync_committee_period(trusted_header.slot);

        let sync_committee_tracker =
            SyncCommitteeTracker::new(current_sync_committee, initial_period, fork_version)?;

        Ok(Self {
            chain_spec,
            store,
            sync_committee_tracker,
        })
    }

    /// Process a light client update using wall-clock time for slot validation.
    ///
    /// This is a convenience wrapper that computes `current_slot` from system time.
    /// For spec-testable behavior, use `process_light_client_update_at_slot`.
    pub(crate) fn process_light_client_update(
        &mut self,
        update: LightClientUpdate,
    ) -> Result<bool> {
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Internal("Failed to get current time".to_string()))?
            .as_secs();
        let current_slot = self.chain_spec.timestamp_to_slot(current_timestamp);

        self.process_light_client_update_at_slot(update, current_slot)
    }

    /// Process a light client update with an explicit current slot.
    ///
    /// This allows spec tests to inject the fixture's `current_slot` so that
    /// time-based validation is properly exercised.
    pub(crate) fn process_light_client_update_at_slot(
        &mut self,
        update: LightClientUpdate,
        current_slot: Slot,
    ) -> Result<bool> {
        // Validate basic update properties: fail fast principle
        self.validate_light_client_update(&update, current_slot)?;

        // Verify sync committee signature
        self.verify_update_signature(&update)?;

        // Apply the update to our store
        self.apply_light_client_update(update)
    }

    /// Validate light client update structure and timing.
    ///
    /// Takes `current_slot` as an explicit parameter for testability.
    fn validate_light_client_update(
        &self,
        update: &LightClientUpdate,
        current_slot: Slot,
    ) -> Result<()> {
        // Basic validation: signature_slot > attested_header.slot, supermajority participation
        update.validate_basic(&self.store.current_sync_committee)?;

        // Spec: current_slot >= signature_slot (strict, no tolerance)
        if update.signature_slot > current_slot {
            return Err(Error::InvalidInput(
                "Update signature slot is in the future".to_string(),
            ));
        }

        // Attested header should be newer than our current finalized header (with some tolerance)
        // Allow updates from the same slot if they have sync committee updates
        let has_sync_committee = update.has_sync_committee_update();
        let is_slot_acceptable = if has_sync_committee {
            // Allow equal slots if update contains sync committee (useful for bootstrapping)
            update.attested_header.slot >= self.store.finalized_header.slot
        } else {
            // Regular updates must be strictly newer
            update.attested_header.slot > self.store.finalized_header.slot
        };

        if !is_slot_acceptable {
            return Err(Error::InvalidInput(
                "Attested header is not newer than finalized header".to_string(),
            ));
        }

        Ok(())
    }

    /// Verify BLS signature on the light client update
    fn verify_update_signature(&mut self, update: &LightClientUpdate) -> Result<()> {
        // Get attested header root for signature verification
        let attested_header_root = update.attested_header.hash_tree_root()?;

        // CRITICAL FIX: Use signature_slot for committee lookup, not attested_header.slot
        // The sync committee signs at signature_slot, so we need the committee for that slot
        let is_valid = self.sync_committee_tracker.verify_sync_aggregate(
            update.signature_slot,
            attested_header_root,
            update.sync_aggregate.sync_committee_bits.as_ref(),
            &update.sync_aggregate.sync_committee_signature,
            self.store.genesis_validators_root,
            &self.chain_spec,
        )?;

        if !is_valid {
            return Err(Error::InvalidInput(
                "Invalid sync committee signature".to_string(),
            ));
        }

        Ok(())
    }

    /// Apply verified light client update to our state
    fn apply_light_client_update(&mut self, update: LightClientUpdate) -> Result<bool> {
        let mut state_changed = false;

        // IMPORTANT: Advance period FIRST, before loading new sync committees
        // This ensures newly loaded committees stay as next_committee
        let should_advance = self
            .sync_committee_tracker
            .should_advance_period(update.attested_header.slot, &self.chain_spec);
        if should_advance {
            self.sync_committee_tracker.advance_to_next_period()?;
            // Update the store's committees to match the tracker
            if let Some(next_committee) = self.store.next_sync_committee.take() {
                self.store.current_sync_committee = next_committee;
            }
            state_changed = true;
        }

        // Process sync committee updates AFTER advancing
        if update.has_sync_committee_update()
            && self
                .sync_committee_tracker
                .process_sync_committee_update(&update, &self.chain_spec)?
        {
            // Also update the store's next_sync_committee to keep it in sync
            self.store.next_sync_committee = update.next_sync_committee.clone();
            state_changed = true;
        }

        // Update optimistic header if this is better
        if update.attested_header.slot > self.store.optimistic_header.slot {
            self.store.optimistic_header = update.attested_header.clone();
            state_changed = true;
        }

        // Update finalized header if we have finality information
        if let Some(ref finalized_header) = update.finalized_header {
            if finalized_header.slot > self.store.finalized_header.slot {
                // Verify finality branch proof: the finalized_header.hash_tree_root()
                // must be proven to exist at finalized_checkpoint.root in the attested state
                let finalized_header_root = finalized_header.hash_tree_root()?;
                verify_finality_branch(
                    &finalized_header_root,
                    &update.finality_branch,
                    update.attested_header.slot,
                    &update.attested_header.state_root,
                    &self.chain_spec,
                )?;

                self.store.finalized_header = finalized_header.clone();
                state_changed = true;
            }
        }

        // Update participation tracking
        let participation = update.sync_aggregate.participation_count() as u64;
        self.store.current_max_active_participants = self
            .store
            .current_max_active_participants
            .max(participation);

        Ok(state_changed)
    }

    /// Get current finalized header
    pub(crate) fn get_finalized_header(&self) -> &BeaconBlockHeader {
        &self.store.finalized_header
    }

    /// Get current optimistic header (may be ahead of finalized)
    pub(crate) fn get_optimistic_header(&self) -> &BeaconBlockHeader {
        &self.store.optimistic_header
    }

    /// Get current sync committee
    pub(crate) fn get_current_sync_committee(&self) -> &SyncCommittee {
        &self.store.current_sync_committee
    }

    /// Get next sync committee if available
    pub(crate) fn get_next_sync_committee(&self) -> Option<&SyncCommittee> {
        self.store.next_sync_committee.as_ref()
    }

    /// Check if we're currently synced (optimistic head is recent)
    pub(crate) fn is_synced(&self) -> bool {
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Use ChainSpec to compute current slot from wall clock
        let current_slot = self.chain_spec.timestamp_to_slot(current_timestamp);
        let head_slot = self.store.optimistic_header.slot;

        // Consider synced if head is within 64 slots of current
        // (mainnet: ~12.8 minutes, minimal: ~6.4 minutes)
        current_slot.saturating_sub(head_slot) <= 64
    }

    /// Get current sync committee period
    pub(crate) fn get_current_period(&self) -> u64 {
        self.sync_committee_tracker.current_period()
    }

    /// Get the chain specification
    pub(crate) fn get_chain_spec(&self) -> &ChainSpec {
        &self.chain_spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::light_client_spec_tests::load_bootstrap_fixture;
    use crate::types::consensus::SyncAggregate;

    fn create_test_beacon_header(slot: Slot) -> BeaconBlockHeader {
        BeaconBlockHeader::new(
            slot, 42,        // proposer_index
            [1u8; 32], // parent_root
            [2u8; 32], // state_root
            [3u8; 32], // body_root
        )
    }

    fn create_test_sync_aggregate() -> SyncAggregate {
        let sync_committee_bits = Box::new([true; 512]); // Full participation
        let sync_committee_signature = [1u8; 96];
        SyncAggregate::new(sync_committee_bits, sync_committee_signature)
    }

    #[test]
    fn test_light_client_processor_creation() {
        // Use real spec test fixtures for valid bootstrap data
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = crate::config::ChainSpec::minimal();
        let expected_slot = bootstrap.header.slot;

        let fork_version = chain_spec.altair_fork_version();
        let processor = LightClientProcessor::new(
            chain_spec,
            bootstrap.header,
            bootstrap.current_sync_committee,
            &bootstrap.current_sync_committee_branch,
            bootstrap.genesis_validators_root,
            fork_version,
        )
        .unwrap();

        assert_eq!(processor.get_finalized_header().slot, expected_slot);
        assert_eq!(processor.get_optimistic_header().slot, expected_slot);
    }

    #[test]
    fn test_light_client_processor_rejects_invalid_branch() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = crate::config::ChainSpec::minimal();

        // Empty branch should fail verification
        let empty_branch: Vec<Root> = vec![];

        let fork_version = chain_spec.altair_fork_version();
        let result = LightClientProcessor::new(
            chain_spec,
            bootstrap.header,
            bootstrap.current_sync_committee,
            &empty_branch,
            bootstrap.genesis_validators_root,
            fork_version,
        );

        assert!(result.is_err(), "Should reject invalid branch proof");
    }

    #[test]
    fn test_light_client_update_validation() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = crate::config::ChainSpec::minimal();
        let bootstrap_slot = bootstrap.header.slot;

        let fork_version = chain_spec.altair_fork_version();
        let processor = LightClientProcessor::new(
            chain_spec,
            bootstrap.header,
            bootstrap.current_sync_committee,
            &bootstrap.current_sync_committee_branch,
            bootstrap.genesis_validators_root,
            fork_version,
        )
        .unwrap();

        // Test update with older header (should fail)
        let old_header = create_test_beacon_header(0);
        let sync_aggregate = create_test_sync_aggregate();
        let old_update = LightClientUpdate::new(old_header, sync_aggregate, 1);

        // Use a current_slot well ahead of the update's signature_slot
        let current_slot = bootstrap_slot + 1000;
        assert!(processor
            .validate_light_client_update(&old_update, current_slot)
            .is_err());

        // Test update with newer header (should pass basic validation)
        let new_header = create_test_beacon_header(bootstrap_slot + 1000);
        let sync_aggregate = create_test_sync_aggregate();
        let new_update = LightClientUpdate::new(new_header, sync_aggregate, bootstrap_slot + 1001);

        // Use a current_slot that allows the update (signature_slot <= current_slot)
        let current_slot_for_new = bootstrap_slot + 1001;
        // Basic validation should pass (signature verification tested separately)
        assert!(processor
            .validate_light_client_update(&new_update, current_slot_for_new)
            .is_ok());
    }
}
