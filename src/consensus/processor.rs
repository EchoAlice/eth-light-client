use crate::chain_spec::ChainSpec;
use crate::consensus::merkle::{verify_light_client_header, verify_merkle_proof};
use crate::consensus::store::LightClientStore;
use crate::consensus::sync_committee;
use crate::error::{Error, Result};
use crate::types::consensus::{
    BeaconBlockHeader, LightClientHeader, LightClientUpdate, SyncCommittee,
};
use crate::types::primitives::Root;
use crate::types::primitives::Slot;

#[derive(Default)]
pub(crate) struct UpdateChanges {
    pub finalized_updated: bool,
    pub optimistic_updated: bool,
    pub rotated: bool,
    pub next_committee_learned: bool,
}

#[derive(Debug)]
pub(crate) struct LightClientProcessor {
    chain_spec: ChainSpec,
    store: LightClientStore,
}

impl LightClientProcessor {
    // TODO: Rename to bootstrap_sync_committee_* / trusted_sync_committee_*
    pub(crate) fn new(
        chain_spec: ChainSpec,
        trusted_header: LightClientHeader,
        current_sync_committee: SyncCommittee,
        current_sync_committee_branch: &[Root],
        genesis_validators_root: Root,
    ) -> Result<Self> {
        // TODO: verify_light_client_header(&trusted_header)? — the spec's
        // initialize_light_client_store asserts is_valid_light_client_header
        // on the bootstrap header; we never check its execution payload
        // consistency. See #128.
        verify_merkle_proof(
            &current_sync_committee.hash_tree_root(),
            current_sync_committee_branch,
            chain_spec.current_sync_committee_gindex(trusted_header.slot()),
            trusted_header.state_root(),
        )?;

        let store = LightClientStore::new(
            trusted_header,
            current_sync_committee,
            genesis_validators_root,
        );

        Ok(Self { chain_spec, store })
    }

    pub(crate) fn process_update_at_slot(
        &mut self,
        update: LightClientUpdate,
        current_slot: Slot,
    ) -> Result<UpdateChanges> {
        self.validate_light_client_update(&update, current_slot)?;

        self.verify_update_signature(&update)?;

        self.apply_light_client_update(update)
    }

    /// Validate basic update properties: fail fast principle
    fn validate_light_client_update(
        &self,
        update: &LightClientUpdate,
        current_slot: Slot,
    ) -> Result<()> {
        if update.signature_slot <= update.attested_header.slot() {
            return Err(Error::InvalidInput(
                "Signature slot must be after attested header slot".to_string(),
            ));
        }
        if !update
            .sync_aggregate
            .has_supermajority(&self.store.current_sync_committee)
        {
            return Err(Error::InvalidInput(
                "Insufficient sync committee participation".to_string(),
            ));
        }

        // Validate header-local consistency (execution branch for Capella+).
        //
        // TODO: Rename... this function name sounds like it's checking the sync committee's signature over a light client's beacon block header, but it's checking execution payload's inclusion proof.
        verify_light_client_header(&update.attested_header)?;
        if let Some(ref finalized) = update.finalized {
            verify_light_client_header(&finalized.header)?;
        }

        if update.signature_slot > current_slot {
            return Err(Error::InvalidInput(
                "Update signature slot is in the future".to_string(),
            ));
        }

        Ok(())
    }

    fn verify_update_signature(&self, update: &LightClientUpdate) -> Result<()> {
        let attested_header_root = update.attested_header.beacon().hash_tree_root();

        // Look up the committee for the signature slot from the store
        let committee = sync_committee::committee_for_signature_slot(
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

        if let Some(ref finalized) = update.finalized {
            if finalized.header.slot() > self.store.finalized_header.slot() {
                verify_merkle_proof(
                    &finalized.header.beacon().hash_tree_root(),
                    &finalized.branch,
                    self.chain_spec
                        .finalized_root_gindex(update.attested_header.slot()),
                    update.attested_header.state_root(),
                )?;

                self.store.finalized_header = finalized.header.clone();
                changes.finalized_updated = true;
            }

            if sync_committee::should_rotate(
                finalized.header.slot(),
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

        // Learn next AFTER the finalized-header update + rotation, using the now-
        // updated finalized period (see consensus/README data flow).
        let finalized_period = self.store.finalized_sync_committee_period(&self.chain_spec);
        if let Some(verified) = sync_committee::learn_next_sync_committee(
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

        Ok(changes)
    }

    pub(crate) fn optimistic_beacon_block_header(&self) -> &BeaconBlockHeader {
        self.store.optimistic_header.beacon()
    }

    pub(crate) fn finalized_beacon_block_header(&self) -> &BeaconBlockHeader {
        self.store.finalized_header.beacon()
    }

    pub(crate) fn current_sync_committee(&self) -> &SyncCommittee {
        &self.store.current_sync_committee
    }

    pub(crate) fn next_sync_committee(&self) -> Option<&SyncCommittee> {
        self.store.next_sync_committee.as_ref()
    }

    pub(crate) fn current_sync_committee_period(&self) -> u64 {
        self.store.finalized_sync_committee_period(&self.chain_spec)
    }

    pub(crate) fn chain_spec(&self) -> &ChainSpec {
        &self.chain_spec
    }

    #[cfg(test)]
    pub(crate) fn optimistic_light_client_header(&self) -> &LightClientHeader {
        &self.store.optimistic_header
    }

    #[cfg(test)]
    pub(crate) fn finalized_light_client_header(&self) -> &LightClientHeader {
        &self.store.finalized_header
    }
}

// TODO: Do we need this test module at all? Processor is tested against spec tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_spec::Fork;
    use crate::test_utils::SyncTestCase;
    use crate::types::consensus::{AltairLightClientHeader, SyncAggregate};

    fn create_test_beacon_header(slot: Slot) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body_root: [3u8; 32],
        }
    }

    /// The two validate rules are Err paths the valid-only fixtures never
    /// produce: minority participation (the safety threshold) and a signature
    /// slot not strictly after the attested slot. Deleting either check leaves
    /// every replay green.
    #[test]
    fn rejects_updates_failing_basic_validation() {
        let mut processor = LightClientProcessor {
            chain_spec: crate::chain_spec::ChainSpec::minimal(),
            store: LightClientStore::new(
                LightClientHeader::Altair(AltairLightClientHeader {
                    beacon: create_test_beacon_header(1),
                }),
                SyncCommittee::from_parts(vec![[1u8; 48]; 32], [2u8; 48]).unwrap(),
                [0u8; 32],
            ),
        };
        let update = |bits, signature_slot| {
            LightClientUpdate::new(
                create_test_beacon_header(2),
                SyncAggregate::new(bits, [0u8; 96]),
                signature_slot,
            )
        };

        // 10 of 32 participants — under the 2/3 supermajority.
        let mut minority = vec![false; 32];
        minority[..10].fill(true);
        let err = processor
            .process_update_at_slot(update(minority, 3), 4)
            .err()
            .unwrap();
        assert!(err.to_string().contains("participation"), "got: {err}");

        // signature_slot == attested slot — must be strictly after.
        let err = processor
            .process_update_at_slot(update(vec![true; 32], 2), 4)
            .err()
            .unwrap();
        assert!(err.to_string().contains("Signature slot"), "got: {err}");
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
        let bootstrap = SyncTestCase::light_client_sync(Fork::Altair)
            .load_bootstrap()
            .expect("Failed to load bootstrap");
        let chain_spec = crate::chain_spec::ChainSpec::minimal();
        let bootstrap_slot = bootstrap.header.slot();

        let mut processor = LightClientProcessor::new(
            chain_spec.clone(),
            bootstrap.header.clone(),
            bootstrap.current_sync_committee.clone(),
            &bootstrap.current_sync_committee_branch,
            bootstrap.genesis_validators_root,
        )
        .unwrap();

        let initial_period = chain_spec.slot_to_sync_committee_period(bootstrap_slot);
        assert_eq!(processor.current_sync_committee_period(), initial_period);
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
            processor.store.finalized_header =
                LightClientHeader::Altair(AltairLightClientHeader { beacon: finalized });
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
            processor.current_sync_committee_period(),
            initial_period + 1,
            "period should reflect the new finalized header"
        );
    }
}
