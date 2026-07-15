use crate::config::ChainSpec;
use crate::consensus::merkle::{
    validate_light_client_header, verify_bootstrap_sync_committee, verify_finality_branch,
};
use crate::consensus::sync_committee;
use crate::error::{Error, Result};
use crate::types::consensus::{
    BeaconBlockHeader, LightClientHeader, LightClientStore, LightClientUpdate, SyncCommittee,
};
use crate::types::primitives::Root;
use crate::types::primitives::Slot;

#[derive(Debug)]
pub(crate) struct LightClientProcessor {
    chain_spec: ChainSpec,
    store: LightClientStore,
}

/// What a processed update changed in the store. The engine reports this
/// directly; the `LightClient` facade maps it to the public `UpdateOutcome`.
#[derive(Default)]
pub(crate) struct UpdateChanges {
    pub finalized_updated: bool,
    pub optimistic_updated: bool,
    pub rotated: bool,
    pub next_committee_learned: bool,
}

impl LightClientProcessor {
    pub(crate) fn new(
        chain_spec: ChainSpec,
        trusted_header: LightClientHeader,
        current_sync_committee: SyncCommittee,
        current_sync_committee_branch: &[Root],
        genesis_validators_root: Root,
    ) -> Result<Self> {
        verify_bootstrap_sync_committee(
            &current_sync_committee,
            current_sync_committee_branch,
            trusted_header.slot(),
            trusted_header.state_root(),
            &chain_spec,
        )?;

        let store = LightClientStore::new(
            trusted_header,
            current_sync_committee,
            genesis_validators_root,
        );

        Ok(Self { chain_spec, store })
    }

    /// The engine is time-injectable
    pub(crate) fn process_update_at_slot(
        &mut self,
        update: LightClientUpdate,
        current_slot: Slot,
    ) -> Result<UpdateChanges> {
        // Validate basic update properties: fail fast principle
        self.validate_light_client_update(&update, current_slot)?;

        // Verify sync committee signature
        self.verify_update_signature(&update)?;

        // Apply the update to our store
        self.apply_light_client_update(update)
    }

    /// Takes `current_slot` as an explicit parameter for testability.
    fn validate_light_client_update(
        &self,
        update: &LightClientUpdate,
        current_slot: Slot,
    ) -> Result<()> {
        // Basic validation: signature_slot > attested_header.slot, supermajority participation
        update.validate_basic(&self.store.current_sync_committee)?;

        // Validate header-local consistency (execution branch for Capella+).
        validate_light_client_header(&update.attested_header)?;
        if let Some(ref finalized) = update.finalized_header {
            validate_light_client_header(finalized)?;
        }

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
            update.attested_header.slot() >= self.store.finalized_header.slot()
        } else {
            // Regular updates must be strictly newer
            update.attested_header.slot() > self.store.finalized_header.slot()
        };

        if !is_slot_acceptable {
            return Err(Error::InvalidInput(
                "Attested header is not newer than finalized header".to_string(),
            ));
        }

        Ok(())
    }

    /// The sync committee signs `hash_tree_root(attested_header.beacon)` — the
    /// beacon block root, not the full `LightClientHeader` root (which includes
    /// execution payload fields starting at Capella).
    fn verify_update_signature(&self, update: &LightClientUpdate) -> Result<()> {
        let attested_header_root = update.attested_header.beacon().hash_tree_root()?;

        // Look up the committee for the signature slot from the store
        let committee = sync_committee::committee_for_slot(
            update.signature_slot,
            self.store.finalized_header.slot(),
            &self.store.current_sync_committee,
            self.store.next_sync_committee.as_ref(),
            &self.chain_spec,
        )?;

        let is_valid = sync_committee::verify_sync_aggregate(
            committee,
            update.signature_slot,
            attested_header_root,
            &update.sync_aggregate.sync_committee_bits,
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

    fn apply_light_client_update(&mut self, update: LightClientUpdate) -> Result<UpdateChanges> {
        let mut changes = UpdateChanges::default();

        // Capture store period BEFORE any finalized-header mutation.
        let store_period = self.store.finalized_sync_committee_period(&self.chain_spec);

        if let Some(ref finalized_header) = update.finalized_header {
            if finalized_header.slot() > self.store.finalized_header.slot() {
                // The finality branch proves that beacon.hash_tree_root() matches
                // finalized_checkpoint.root in the attested state — use the beacon
                // root, not the full LightClientHeader root.
                let finalized_header_root = finalized_header.beacon().hash_tree_root()?;
                verify_finality_branch(
                    &finalized_header_root,
                    &update.finality_branch,
                    update.attested_header.slot(),
                    update.attested_header.state_root(),
                    &self.chain_spec,
                )?;

                self.store.finalized_header = finalized_header.clone();
                changes.finalized_updated = true;
            }

            // Rotate when the update's finalized period == store_period + 1 and the
            // next committee is known (invariant I-2, via `should_rotate`).
            if sync_committee::should_rotate(
                finalized_header.slot(),
                store_period,
                self.store.next_sync_committee.is_some(),
                &self.chain_spec,
            ) {
                self.store.current_sync_committee = self
                    .store
                    .next_sync_committee
                    .take()
                    .expect("should_rotate checked next is_some");
                changes.rotated = true;
            }
        }

        // Learn next sync committee AFTER finalized-header update and rotation.
        // We derive the period from the store's (now-updated) finalized header so
        // that:
        //   - if finality advances but rotation can't happen (next unknown), we
        //     learn next relative to the new finalized period;
        //   - if rotation happened, we begin learning the subsequent period's
        //     committee.
        let finalized_period = self.store.finalized_sync_committee_period(&self.chain_spec);
        if let Some(verified) = sync_committee::learn_next_sync_committee_from_update(
            &update,
            finalized_period,
            self.store.next_sync_committee.is_some(),
            &self.chain_spec,
        )? {
            self.store.next_sync_committee = Some(verified);
            changes.next_committee_learned = true;
        }

        if update.attested_header.slot() > self.store.optimistic_header.slot() {
            self.store.optimistic_header = update.attested_header.clone();
            changes.optimistic_updated = true;
        }

        let participation = update.sync_aggregate.participation_count() as u64;
        self.store.current_max_active_participants = self
            .store
            .current_max_active_participants
            .max(participation);

        Ok(changes)
    }

    pub(crate) fn finalized_header(&self) -> &BeaconBlockHeader {
        self.store.finalized_header.beacon()
    }

    /// Full fork-aware finalized header (for fork-specific checks in tests).
    #[cfg(test)]
    pub(crate) fn finalized_light_client_header(&self) -> &LightClientHeader {
        &self.store.finalized_header
    }

    /// Current optimistic header (may be ahead of finalized).
    pub(crate) fn optimistic_header(&self) -> &BeaconBlockHeader {
        self.store.optimistic_header.beacon()
    }

    /// Full fork-aware optimistic header (for fork-specific checks in tests).
    #[cfg(test)]
    pub(crate) fn optimistic_light_client_header(&self) -> &LightClientHeader {
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
    use crate::test_utils::load_altair_bootstrap;
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
        SyncAggregate::new(vec![true; 32], [1u8; 96])
    }

    #[test]
    fn test_light_client_processor_creation() {
        let bootstrap = load_altair_bootstrap();
        let chain_spec = crate::config::ChainSpec::minimal();
        let expected_slot = bootstrap.header.slot();

        let processor = LightClientProcessor::new(
            chain_spec,
            bootstrap.header.clone(),
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
        let bootstrap = load_altair_bootstrap();
        let chain_spec = crate::config::ChainSpec::minimal();

        let empty_branch: Vec<Root> = vec![];

        let result = LightClientProcessor::new(
            chain_spec,
            bootstrap.header.clone(),
            bootstrap.current_sync_committee,
            &empty_branch,
            bootstrap.genesis_validators_root,
        );

        assert!(result.is_err(), "Should reject invalid branch proof");
    }

    #[test]
    fn test_light_client_update_validation() {
        let bootstrap = load_altair_bootstrap();
        let chain_spec = crate::config::ChainSpec::minimal();
        let bootstrap_slot = bootstrap.header.slot();

        let processor = LightClientProcessor::new(
            chain_spec,
            bootstrap.header.clone(),
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
        let bootstrap = load_altair_bootstrap();
        let chain_spec = crate::config::ChainSpec::minimal();
        let bootstrap_slot = bootstrap.header.slot();

        let mut processor = LightClientProcessor::new(
            chain_spec,
            bootstrap.header.clone(),
            bootstrap.current_sync_committee.clone(),
            &bootstrap.current_sync_committee_branch,
            bootstrap.genesis_validators_root,
        )
        .unwrap();

        let initial_period = chain_spec.slot_to_sync_committee_period(bootstrap_slot);
        assert_eq!(processor.current_period(), initial_period);
        assert!(processor.store.next_sync_committee.is_none());

        // Inject a distinguishable "next" committee directly on the store
        let next = SyncCommittee::from_parts(vec![[0xAA; 48]; 32], [0xBB; 48]).unwrap();
        processor.store.next_sync_committee = Some(next.clone());

        // Store period is still initial_period (finalized header not yet updated)
        let store_period = processor.store.finalized_sync_committee_period(&chain_spec);
        assert_eq!(store_period, initial_period);

        // Simulate an update whose finalized_header crosses into period+1
        let next_period_slot = (initial_period + 1) * chain_spec.slots_per_sync_committee_period();
        let finalized = create_test_beacon_header(next_period_slot);

        // Exercise rotation directly (can't do full process_update because
        // BLS/merkle proofs would fail with synthetic data). Uses the same
        // `should_rotate` predicate as production.
        if sync_committee::should_rotate(
            finalized.slot,
            store_period,
            processor.store.next_sync_committee.is_some(),
            &chain_spec,
        ) {
            processor.store.current_sync_committee = processor
                .store
                .next_sync_committee
                .take()
                .expect("should_rotate checked next is_some");
            // Advance finalized header to match (as apply_light_client_update does)
            processor.store.finalized_header = LightClientHeader::altair(finalized);
        }

        // Assertions: store state is correct after rotation
        assert_eq!(
            processor
                .store
                .current_sync_committee
                .aggregate_pubkey()
                .as_ref(),
            &[0xBB; 48],
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
