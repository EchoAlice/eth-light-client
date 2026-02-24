use crate::config::ChainSpec;
use crate::consensus::merkle::{verify_bootstrap_sync_committee, verify_finality_branch};
use crate::consensus::sync_committee;
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
}

impl LightClientProcessor {
    /// Create a new light client processor with verified bootstrap.
    ///
    /// The `current_sync_committee_branch` proves that `current_sync_committee` is
    /// correctly embedded in `trusted_header.state_root`. This verification is
    /// mandatory - there is no unverified constructor path.
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
    ) -> Result<Self> {
        // Verify that the sync committee is properly embedded in the trusted state
        verify_bootstrap_sync_committee(
            &current_sync_committee,
            current_sync_committee_branch,
            trusted_header.slot,
            &trusted_header.state_root,
            &chain_spec,
        )?;

        let store = LightClientStore::new(
            trusted_header,
            current_sync_committee,
            genesis_validators_root,
        );

        Ok(Self { chain_spec, store })
    }

    /// Process a light client update using wall-clock time for slot validation.
    ///
    /// This is a convenience wrapper that computes `current_slot` from system time.
    /// For spec-testable behavior, use `process_update_at_slot`.
    pub(crate) fn process_update(&mut self, update: LightClientUpdate) -> Result<bool> {
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Internal("Failed to get current time".to_string()))?
            .as_secs();
        let current_slot = self.chain_spec.timestamp_to_slot(current_timestamp);

        self.process_update_at_slot(update, current_slot)
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
    fn verify_update_signature(&self, update: &LightClientUpdate) -> Result<()> {
        let attested_header_root = update.attested_header.hash_tree_root()?;

        // Look up the committee for the signature slot from the store
        let committee = sync_committee::committee_for_slot(
            update.signature_slot,
            self.store.finalized_header.slot,
            &self.store.current_sync_committee,
            self.store.next_sync_committee.as_ref(),
            &self.chain_spec,
        )?;

        let is_valid = sync_committee::verify_sync_aggregate(
            committee,
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

        // Capture store period BEFORE any finalized-header mutation.
        let store_period = self.store.finalized_sync_committee_period(&self.chain_spec);

        // Update finalized header (verify finality proof first)
        if let Some(ref finalized_header) = update.finalized_header {
            if finalized_header.slot > self.store.finalized_header.slot {
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

        // Rotate when the update's finalized period == store_period + 1
        // and next committee is known.
        if let Some(ref finalized_header) = update.finalized_header {
            let update_finalized_period = self
                .chain_spec
                .slot_to_sync_committee_period(finalized_header.slot);

            if update_finalized_period == store_period + 1
                && self.store.next_sync_committee.is_some()
            {
                self.store.current_sync_committee = self
                    .store
                    .next_sync_committee
                    .take()
                    .expect("checked is_some above");
                state_changed = true;
            }
        }

        // Process sync committee updates AFTER finalized-header update and rotation.
        // We derive the period from the store's (now-updated) finalized header so
        // that:
        //   - if finality advances but rotation can't happen (next unknown), we
        //     learn next relative to the new finalized period;
        //   - if rotation happened, we begin learning the subsequent period's
        //     committee.
        let finalized_period = self.store.finalized_sync_committee_period(&self.chain_spec);
        if let Some(verified) = sync_committee::process_sync_committee_update(
            &update,
            finalized_period,
            self.store.next_sync_committee.is_some(),
            &self.chain_spec,
        )? {
            self.store.next_sync_committee = Some(verified);
            state_changed = true;
        }

        // Update optimistic header if this is better
        if update.attested_header.slot > self.store.optimistic_header.slot {
            self.store.optimistic_header = update.attested_header.clone();
            state_changed = true;
        }

        // Update participation tracking
        let participation = update.sync_aggregate.participation_count() as u64;
        self.store.current_max_active_participants = self
            .store
            .current_max_active_participants
            .max(participation);

        Ok(state_changed)
    }

    /// Current finalized header
    pub(crate) fn finalized_header(&self) -> &BeaconBlockHeader {
        &self.store.finalized_header
    }

    /// Current optimistic header (may be ahead of finalized)
    pub(crate) fn optimistic_header(&self) -> &BeaconBlockHeader {
        &self.store.optimistic_header
    }

    /// Current sync committee
    pub(crate) fn current_sync_committee(&self) -> &SyncCommittee {
        &self.store.current_sync_committee
    }

    /// Next sync committee if available
    pub(crate) fn next_sync_committee(&self) -> Option<&SyncCommittee> {
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

    /// Current sync committee period (derived from finalized header).
    pub(crate) fn current_period(&self) -> u64 {
        self.store.finalized_sync_committee_period(&self.chain_spec)
    }

    /// Chain specification
    pub(crate) fn chain_spec(&self) -> &ChainSpec {
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
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = crate::config::ChainSpec::minimal();
        let expected_slot = bootstrap.header.slot;

        let processor = LightClientProcessor::new(
            chain_spec,
            bootstrap.header,
            bootstrap.current_sync_committee,
            &bootstrap.current_sync_committee_branch,
            bootstrap.genesis_validators_root,
        )
        .unwrap();

        assert_eq!(processor.finalized_header().slot, expected_slot);
        assert_eq!(processor.optimistic_header().slot, expected_slot);
    }

    #[test]
    fn test_light_client_processor_rejects_invalid_branch() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = crate::config::ChainSpec::minimal();

        let empty_branch: Vec<Root> = vec![];

        let result = LightClientProcessor::new(
            chain_spec,
            bootstrap.header,
            bootstrap.current_sync_committee,
            &empty_branch,
            bootstrap.genesis_validators_root,
        );

        assert!(result.is_err(), "Should reject invalid branch proof");
    }

    #[test]
    fn test_light_client_update_validation() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = crate::config::ChainSpec::minimal();
        let bootstrap_slot = bootstrap.header.slot;

        let processor = LightClientProcessor::new(
            chain_spec,
            bootstrap.header,
            bootstrap.current_sync_committee,
            &bootstrap.current_sync_committee_branch,
            bootstrap.genesis_validators_root,
        )
        .unwrap();

        // Test update with older header (should fail)
        let old_header = create_test_beacon_header(0);
        let sync_aggregate = create_test_sync_aggregate();
        let old_update = LightClientUpdate::new(old_header, sync_aggregate, 1);

        let current_slot = bootstrap_slot + 1000;
        assert!(processor
            .validate_light_client_update(&old_update, current_slot)
            .is_err());

        // Test update with newer header (should pass basic validation)
        let new_header = create_test_beacon_header(bootstrap_slot + 1000);
        let sync_aggregate = create_test_sync_aggregate();
        let new_update = LightClientUpdate::new(new_header, sync_aggregate, bootstrap_slot + 1001);

        let current_slot_for_new = bootstrap_slot + 1001;
        assert!(processor
            .validate_light_client_update(&new_update, current_slot_for_new)
            .is_ok());
    }

    /// Drift-prevention regression test.
    ///
    /// Verifies that after a simulated rotation:
    ///   1. The store's current committee is what was previously next.
    ///   2. The store's next committee is consumed (None).
    ///   3. The processor's period (store-derived) matches the expected
    ///      post-rotation period.
    ///
    /// Because there is no separate tracker, committee period is always
    /// derived from `store.finalized_header.slot` — drift is structurally
    /// impossible.
    #[test]
    fn test_store_period_correct_after_rotation() {
        use crate::types::consensus::SyncCommittee;

        let bootstrap = load_bootstrap_fixture();
        let chain_spec = crate::config::ChainSpec::minimal();
        let bootstrap_slot = bootstrap.header.slot;

        let mut processor = LightClientProcessor::new(
            chain_spec.clone(),
            bootstrap.header,
            bootstrap.current_sync_committee.clone(),
            &bootstrap.current_sync_committee_branch,
            bootstrap.genesis_validators_root,
        )
        .unwrap();

        let initial_period = chain_spec.slot_to_sync_committee_period(bootstrap_slot);
        assert_eq!(processor.current_period(), initial_period);
        assert!(processor.store.next_sync_committee.is_none());

        // Inject a distinguishable "next" committee directly on the store
        let next = SyncCommittee::new(Box::new([[0xAA; 48]; 512]), [0xBB; 48]);
        processor.store.next_sync_committee = Some(next.clone());

        // Store period is still initial_period (finalized header not yet updated)
        let store_period = processor.store.finalized_sync_committee_period(&chain_spec);
        assert_eq!(store_period, initial_period);

        // Simulate an update whose finalized_header crosses into period+1
        let next_period_slot = (initial_period + 1) * chain_spec.slots_per_sync_committee_period();
        let finalized = create_test_beacon_header(next_period_slot);

        // Exercise rotation directly (can't do full process_update because
        // BLS/merkle proofs would fail with synthetic data).
        let update_fin_period = chain_spec.slot_to_sync_committee_period(finalized.slot);
        if update_fin_period == store_period + 1 && processor.store.next_sync_committee.is_some() {
            processor.store.current_sync_committee = processor
                .store
                .next_sync_committee
                .take()
                .expect("checked is_some");
            // Advance finalized header to match (as apply_light_client_update does)
            processor.store.finalized_header = finalized;
        }

        // Assertions: store state is correct after rotation
        assert_eq!(
            processor.store.current_sync_committee.aggregate_pubkey, [0xBB; 48],
            "store current committee should be what was next"
        );
        assert!(
            processor.store.next_sync_committee.is_none(),
            "store next committee should be consumed"
        );
        // Period is derived from finalized header — automatically correct
        assert_eq!(
            processor.current_period(),
            initial_period + 1,
            "period should reflect the new finalized header"
        );
    }
}
