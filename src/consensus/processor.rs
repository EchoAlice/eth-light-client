use crate::chain_spec::ChainSpec;
use crate::consensus::bls;
use crate::consensus::merkle::{verify_light_client_header, verify_merkle_proof};
use crate::consensus::store::LightClientStore;
use crate::consensus::sync_committee::{
    compute_domain, compute_signing_root, DOMAIN_SYNC_COMMITTEE,
};
use crate::error::{Error, Result};
#[cfg(test)]
use crate::types::consensus::LightClientHeader; // TODO: Why can't i consolidate?
use crate::types::consensus::{
    BeaconBlockHeader, LightClientBootstrap, LightClientUpdate, SyncCommittee,
};
use crate::types::primitives::{Root, Slot};

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
    /// Spec: `initialize_light_client_store()`
    pub(crate) fn new(
        chain_spec: ChainSpec,
        trusted_block_root: Root,
        bootstrap: LightClientBootstrap,
    ) -> Result<Self> {
        verify_light_client_header(&bootstrap.header)?;

        if bootstrap.header.beacon().hash_tree_root() != trusted_block_root {
            return Err(Error::InvalidInput(
                "Bootstrap doesn't match the trusted block root".to_string(),
            ));
        }

        verify_merkle_proof(
            &bootstrap.current_sync_committee.hash_tree_root(),
            &bootstrap.current_sync_committee_branch,
            chain_spec
                .fork_at_slot(bootstrap.header.slot())
                .current_sync_committee_gindex(),
            bootstrap.header.state_root(),
        )?;

        let store = LightClientStore::new(
            bootstrap.header,
            bootstrap.current_sync_committee,
            bootstrap.genesis_validators_root,
        );

        Ok(Self { chain_spec, store })
    }

    pub(crate) fn process_light_client_update(
        &mut self,
        update: LightClientUpdate,
        current_slot: Slot,
    ) -> Result<UpdateChanges> {
        let mut changes = UpdateChanges::default();
        // Strict 2/3 participation requirement up front. Diverges from spec for simplicity.
        if !update
            .sync_aggregate
            .has_supermajority(&self.store.current_sync_committee)
        {
            return Err(Error::InvalidInput(
                "Insufficient sync committee participation".to_string(),
            ));
        }

        self.validate_light_client_update(&update, current_slot)?;

        // Update the optimistic header
        if update.attested_header.slot() > self.store.optimistic_header.slot() {
            self.store.optimistic_header = update.attested_header.clone();
            changes.optimistic_updated = true;
        }

        // Update finalized header and/or sync committee within the store
        let update_finalized_slot = update.finalized.as_ref().map_or(0, |f| f.header.slot());
        let update_attested_period = self
            .chain_spec
            .slot_to_sync_committee_period(update.attested_header.slot());
        let update_finalized_period = self
            .chain_spec
            .slot_to_sync_committee_period(update_finalized_slot);

        let update_has_finalized_next_sync_committee = self.store.next_sync_committee.is_none()
            && update.next_sync_committee.is_some()
            && update.finalized.is_some()
            && update_finalized_period == update_attested_period;

        if update_finalized_slot > self.store.finalized_header.slot()
            || update_has_finalized_next_sync_committee
        {
            self.apply_light_client_update(update, &mut changes);
        }

        Ok(changes)
    }

    /// Verifies update's (i) relevance, (ii) internal construction, and (iii) sync committee signature is sound
    fn validate_light_client_update(
        &self,
        update: &LightClientUpdate,
        current_slot: Slot,
    ) -> Result<()> {
        // Verify update's sync committee signature can be checked (based on local store's registry)
        verify_light_client_header(&update.attested_header)?;
        let update_attested_slot = update.attested_header.slot();
        let update_finalized_slot = update.finalized.as_ref().map_or(0, |f| f.header.slot());
        if !(current_slot >= update.signature_slot
            && update.signature_slot > update_attested_slot
            && update_attested_slot >= update_finalized_slot)
        {
            return Err(Error::InvalidInput(
                "Update slots must satisfy current slot >= signature slot > attested slot >= finalized slot"
                    .to_string(),
            ));
        }

        let store_period = self.store.finalized_sync_committee_period(&self.chain_spec);
        let update_signature_period = self
            .chain_spec
            .slot_to_sync_committee_period(update.signature_slot);
        if self.store.next_sync_committee.is_some() {
            if !(update_signature_period == store_period
                || update_signature_period == store_period + 1)
            {
                return Err(Error::InvalidInput(
                    "Signature period not servable by store's known committees".to_string(),
                ));
            }
        } else if !(update_signature_period == store_period) {
            return Err(Error::InvalidInput(
                "Signature period not servable by store's known committees".to_string(),
            ));
        }

        // Verify update's information is relevant
        let update_attested_period = self
            .chain_spec
            .slot_to_sync_committee_period(update.attested_header.slot());
        let update_supplies_next_sync_committee = self.store.next_sync_committee.is_none()
            && update.next_sync_committee.is_some()
            && update_attested_period == store_period;
        if !(update_attested_slot > self.store.finalized_header.beacon().slot
            || update_supplies_next_sync_committee)
        {
            return Err(Error::InvalidInput(
                "Update doesn't contain relevant information".to_string(),
            ));
        }

        // Verify that the `finalized_header` (if present) is rooted in the state of `attested_header`.
        if let Some(ref finalized) = update.finalized {
            verify_light_client_header(&finalized.header)?;
            verify_merkle_proof(
                &finalized.header.beacon().hash_tree_root(),
                &finalized.branch,
                self.chain_spec
                    .fork_at_slot(update.attested_header.slot())
                    .finalized_root_gindex(),
                update.attested_header.state_root(),
            )?;
        }

        // Verify that the `next_sync_committee` (if present) is rooted within the state of the `attested_header`
        if let Some(ref next_sync_committee) = update.next_sync_committee {
            if let Some(ref stored_next) = self.store.next_sync_committee {
                if update_attested_period == store_period
                    && next_sync_committee.committee != *stored_next
                {
                    return Err(Error::InvalidInput("Sync committee updates should match if they fall within the same sync period".to_string()));
                }
            }
            verify_merkle_proof(
                &next_sync_committee.committee.hash_tree_root(),
                &next_sync_committee.branch,
                self.chain_spec
                    .fork_at_slot(update.attested_header.slot())
                    .next_sync_committee_gindex(),
                update.attested_header.state_root(),
            )?;
        }

        // Verify sync committee aggregate signature
        let sync_committee = if update_signature_period == store_period {
            &self.store.current_sync_committee
        } else if let Some(ref next) = self.store.next_sync_committee {
            next
        } else {
            return Err(Error::Internal(
                "Unservable signature period reached committee selection; the period-servability check above should have rejected update.".to_string(),
            ));
        };
        let participating_pubkeys =
            sync_committee.participating_pubkeys(&update.sync_aggregate.sync_committee_bits)?;

        let fork_version_slot = update.signature_slot.saturating_sub(1);
        let epoch = self.chain_spec.slot_to_epoch(fork_version_slot);
        let fork_version = self.chain_spec.fork_version_at_epoch(epoch);
        let domain = compute_domain(
            DOMAIN_SYNC_COMMITTEE,
            fork_version,
            self.store.genesis_validators_root,
        );
        let attested_header_root = update.attested_header.beacon().hash_tree_root();
        let signing_root = compute_signing_root(attested_header_root, domain);

        if !bls::fast_aggregate_verify(
            &participating_pubkeys,
            &signing_root,
            &update.sync_aggregate.sync_committee_signature,
        ) {
            return Err(Error::InvalidInput(
                "Invalid sync committee signature".to_string(),
            ));
        }
        Ok(())
    }

    /// Mutates store (write-once). Assumes validation and gate admission
    fn apply_light_client_update(
        &mut self,
        update: LightClientUpdate,
        changes: &mut UpdateChanges,
    ) {
        let store_period = self.store.finalized_sync_committee_period(&self.chain_spec);
        let finality_update = update
            .finalized
            .expect("apply gate admits only updates carrying finality");
        let update_finalized_period = self
            .chain_spec
            .slot_to_sync_committee_period(finality_update.header.slot());
        let clock_ticked = update_finalized_period == store_period + 1;

        // Spec: `if not is_next_sync_committee_known / elif` logic.  This is the full, uncollapsed (known, ticked) grid
        match (self.store.next_sync_committee.is_some(), clock_ticked) {
            (false, false) => {
                if let Some(next_sync_committee) = update.next_sync_committee {
                    self.store.next_sync_committee = Some(next_sync_committee.committee);
                    changes.next_committee_learned = true;
                }
            }
            // unreachable: next unknown ⇒ sig_period == store_period (validate) ⇒ finality ≤ store_period
            (false, true) => {}
            // finality moved within store_period; committee labels still correct
            (true, false) => {}
            (true, true) => {
                self.store.current_sync_committee = self
                    .store
                    .next_sync_committee
                    .take()
                    .expect("this arm matches `next_sync_committee` is Some");
                changes.rotated = true;

                if let Some(committee_update) = update.next_sync_committee {
                    self.store.next_sync_committee = Some(committee_update.committee);
                    changes.next_committee_learned = true;
                }
            }
        }

        if finality_update.header.slot() > self.store.finalized_header.slot() {
            self.store.finalized_header = finality_update.header;
            changes.finalized_updated = true;
        }
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

/// Spec tests have *valid-only* fixtures.  They never exercise negative cases.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{SyncTestCase, TestStep};
    use crate::types::consensus::{AltairLightClientHeader, FinalityUpdate, SyncAggregate};
    use crate::Fork;

    fn create_test_beacon_header(slot: Slot) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body_root: [3u8; 32],
        }
    }

    #[test]
    fn rejects_bootstrap_with_mismatched_trusted_root() {
        let bootstrap = LightClientBootstrap {
            header: LightClientHeader::Altair(AltairLightClientHeader {
                beacon: create_test_beacon_header(1),
            }),
            current_sync_committee: SyncCommittee::from_parts(vec![[1u8; 48]; 32], [2u8; 48])
                .unwrap(),
            current_sync_committee_branch: vec![],
            genesis_validators_root: [0u8; 32],
        };
        let err = LightClientProcessor::new(
            crate::chain_spec::ChainSpec::minimal(),
            [9u8; 32],
            bootstrap,
        )
        .err()
        .unwrap();
        assert!(
            err.to_string()
                .contains("Bootstrap doesn't match the trusted block root"),
            "got: {err}"
        );
    }

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
        let update = |bits, signature_slot| LightClientUpdate {
            attested_header: LightClientHeader::Altair(AltairLightClientHeader {
                beacon: create_test_beacon_header(2),
            }),
            finalized: None,
            next_sync_committee: None,
            sync_aggregate: SyncAggregate::new(bits, [0u8; 96]),
            signature_slot,
        };

        // Case 1: Supermajority Gate. Only 10 of 32 participants
        let mut minority = vec![false; 32];
        minority[..10].fill(true);
        let err = processor
            .process_light_client_update(update(minority, 3), 4)
            .err()
            .unwrap();
        assert!(
            err.to_string()
                .contains("Insufficient sync committee participation"),
            "got: {err}"
        );

        let slot_chain_msg =
            "Update slots must satisfy current slot >= signature slot > attested slot >= finalized slot";

        // Case 2: Slot Chain.  Signature_slot == attested slot (must be strictly after).
        let err = processor
            .process_light_client_update(update(vec![true; 32], 2), 4)
            .err()
            .unwrap();
        assert!(err.to_string().contains(slot_chain_msg), "got: {err}");

        // Case 3: Slot Chain.  Signature_slot is one past current_slot (update must not be in the future, relative to the light client).
        let err = processor
            .process_light_client_update(update(vec![true; 32], 5), 4)
            .err()
            .unwrap();
        assert!(err.to_string().contains(slot_chain_msg), "got: {err}");

        // Case 4: Slot Chain.  Finalized slot is ahead of attested slot (a state cannot finalize a block from its own future).
        let mut bad_finality = update(vec![true; 32], 3);
        bad_finality.finalized = Some(FinalityUpdate {
            header: LightClientHeader::Altair(AltairLightClientHeader {
                beacon: create_test_beacon_header(5),
            }),
            branch: vec![],
        });
        let err = processor
            .process_light_client_update(bad_finality, 10)
            .err()
            .unwrap();
        assert!(err.to_string().contains(slot_chain_msg), "got: {err}");

        // TODO: Case 5:  Period Servability.  Signature slot 65 is period 1; store is period 0 with no next committee, so LC can't check its sig

        // TODO: Case 6:  Relevance.  Attested slot 1 == store's finalized slot and no committee data: the update can't change the store
    }

    #[test]
    #[ignore = "TODO: servability-beyond-known and committee-equality cases"]
    fn rejects_updates_failing_validation_with_known_next_committee() {
        // Store at slot 1 (period 0) with `next = committee_A`, so it can serve periods 0 and 1.

        // TODO: Case 1: Period Servability.  Signature slot 129 is period 2; store holds committees for periods 0 and 1 only.

        // TODO: Case 2: Committee Equality.  Store holds `next = committee_A`; update carries B for the same period. Must match
    }

    #[test]
    fn committee_update_without_finality_is_not_learned() {
        let sync_test_case = SyncTestCase::light_client_sync(Fork::Altair);

        let bootstrap = sync_test_case.load_bootstrap().unwrap();
        let mut processor = LightClientProcessor::new(
            sync_test_case.chain_spec().clone(),
            sync_test_case.trusted_block_root(),
            bootstrap,
        )
        .unwrap();

        let steps = sync_test_case.load_steps().unwrap();
        let TestStep::ProcessUpdate(step) = &steps[0] else {
            panic!("first step is a process_update")
        };
        let mut update = sync_test_case
            .load_update(&step.update, step.update_fork_digest)
            .unwrap();
        assert!(update.next_sync_committee.is_some());
        update.finalized = None;

        let changes = processor
            .process_light_client_update(update, step.current_slot)
            .unwrap();
        assert!(changes.optimistic_updated);
        assert!(!changes.next_committee_learned);
        assert!(processor.next_sync_committee().is_none());
    }
}
