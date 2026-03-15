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
/// Internal to the crate — not part of the public API.
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
    /// correctly embedded in `trusted_header.state_root`.
    pub(crate) fn new(
        chain_spec: ChainSpec,
        trusted_header: BeaconBlockHeader,
        current_sync_committee: SyncCommittee,
        current_sync_committee_branch: &[Root],
        genesis_validators_root: Root,
    ) -> Result<Self> {
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
    pub(crate) fn process_update(&mut self, update: LightClientUpdate) -> Result<bool> {
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Internal("Failed to get current time".to_string()))?
            .as_secs();
        let current_slot = self.chain_spec.timestamp_to_slot(current_timestamp);

        self.process_update_at_slot(update, current_slot)
    }

    /// Process a light client update with an explicit current slot.
    pub(crate) fn process_update_at_slot(
        &mut self,
        update: LightClientUpdate,
        current_slot: Slot,
    ) -> Result<bool> {
        self.validate_light_client_update(&update, current_slot)?;
        self.verify_update_signature(&update)?;
        self.apply_light_client_update(update)
    }

    /// Validate light client update structure and timing.
    fn validate_light_client_update(
        &self,
        update: &LightClientUpdate,
        current_slot: Slot,
    ) -> Result<()> {
        update.validate_basic(&self.store.current_sync_committee)?;

        // Spec: current_slot >= signature_slot
        if update.signature_slot > current_slot {
            return Err(Error::InvalidInput(
                "Update signature slot is in the future".to_string(),
            ));
        }

        // Attested header should be newer than current finalized header
        let has_sync_committee = update.has_sync_committee_update();
        let is_slot_acceptable = if has_sync_committee {
            update.attested_header.slot >= self.store.finalized_header.slot
        } else {
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

        // Learn next sync committee AFTER finalized-header update and rotation.
        let finalized_period = self.store.finalized_sync_committee_period(&self.chain_spec);
        if let Some(verified) = sync_committee::learn_next_sync_committee_from_update(
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

    pub(crate) fn finalized_header(&self) -> &BeaconBlockHeader {
        &self.store.finalized_header
    }

    pub(crate) fn optimistic_header(&self) -> &BeaconBlockHeader {
        &self.store.optimistic_header
    }

    pub(crate) fn current_sync_committee(&self) -> &SyncCommittee {
        &self.store.current_sync_committee
    }

    pub(crate) fn next_sync_committee(&self) -> Option<&SyncCommittee> {
        self.store.next_sync_committee.as_ref()
    }

    /// Current sync committee period (derived from finalized header).
    pub(crate) fn current_period(&self) -> u64 {
        self.store.finalized_sync_committee_period(&self.chain_spec)
    }

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
        BeaconBlockHeader::new(slot, 42, [1u8; 32], [2u8; 32], [3u8; 32])
    }

    fn create_test_sync_aggregate() -> SyncAggregate {
        let sync_committee_bits = Box::new([true; SyncCommittee::SYNC_COMMITTEE_SIZE]);
        SyncAggregate::new(sync_committee_bits, [1u8; 96])
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

        // Update with older header should fail
        let old_header = create_test_beacon_header(0);
        let sync_aggregate = create_test_sync_aggregate();
        let old_update = LightClientUpdate::new(old_header, sync_aggregate, 1);

        let current_slot = bootstrap_slot + 1000;
        assert!(processor
            .validate_light_client_update(&old_update, current_slot)
            .is_err());

        // Update with newer header should pass basic validation
        let new_header = create_test_beacon_header(bootstrap_slot + 1000);
        let sync_aggregate = create_test_sync_aggregate();
        let new_update = LightClientUpdate::new(new_header, sync_aggregate, bootstrap_slot + 1001);

        let current_slot_for_new = bootstrap_slot + 1001;
        assert!(processor
            .validate_light_client_update(&new_update, current_slot_for_new)
            .is_ok());
    }

    #[test]
    fn test_store_period_correct_after_rotation() {
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

        // Inject a distinguishable "next" committee
        let next = SyncCommittee::new(
            Box::new([[0xAA; 48]; SyncCommittee::SYNC_COMMITTEE_SIZE]),
            [0xBB; 48],
        );
        processor.store.next_sync_committee = Some(next.clone());

        let store_period = processor.store.finalized_sync_committee_period(&chain_spec);
        assert_eq!(store_period, initial_period);

        // Simulate rotation
        let next_period_slot = (initial_period + 1) * chain_spec.slots_per_sync_committee_period();
        let finalized = create_test_beacon_header(next_period_slot);

        let update_fin_period = chain_spec.slot_to_sync_committee_period(finalized.slot);
        if update_fin_period == store_period + 1 && processor.store.next_sync_committee.is_some() {
            processor.store.current_sync_committee = processor
                .store
                .next_sync_committee
                .take()
                .expect("checked is_some");
            processor.store.finalized_header = finalized;
        }

        assert_eq!(
            processor.store.current_sync_committee.aggregate_pubkey, [0xBB; 48],
            "store current committee should be what was next"
        );
        assert!(
            processor.store.next_sync_committee.is_none(),
            "store next committee should be consumed"
        );
        assert_eq!(
            processor.current_period(),
            initial_period + 1,
            "period should reflect the new finalized header"
        );
    }
}
