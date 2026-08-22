use crate::chain_spec::ChainSpec;
use crate::consensus::bls;
use crate::consensus::merkle::{verify_light_client_header, verify_merkle_proof};
use crate::consensus::store::LightClientStore;
use crate::consensus::sync_committee::{
    compute_domain, compute_signing_root, learn_next_sync_committee, DOMAIN_SYNC_COMMITTEE,
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
        self.validate_light_client_update(&update, current_slot)?;

        self.apply_light_client_update(update)
    }

    fn validate_light_client_update(
        &self,
        update: &LightClientUpdate,
        current_slot: Slot,
    ) -> Result<()> {
        // # Verify sync committee has sufficient participants
        if !update
            .sync_aggregate
            .has_supermajority(&self.store.current_sync_committee)
        {
            return Err(Error::InvalidInput(
                "Insufficient sync committee participation".to_string(),
            ));
        }

        // # Verify update's sync committee signature can be checked (based on local store's registry)
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

        // # Verify update's information is relevant
        let update_attested_period = self
            .chain_spec
            .slot_to_sync_committee_period(update.attested_header.slot());
        let update_supplies_next_sync_committee = self.store.next_sync_committee.is_none()
            && update.has_sync_committee_update()
            && update_attested_period == store_period;
        if !(update_attested_slot > self.store.finalized_header.beacon().slot
            || update_supplies_next_sync_committee)
        {
            return Err(Error::InvalidInput(
                "Update doesn't contain relevant information".to_string(),
            ));
        }

        // # Verify that the `finalized_header` (if present) matches the finalized checkpoint root saved in the state of `attested_header`.
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

        // # Verify that the `next_sync_committee` (if present) matches next sync committee root within the state of the `attested_header`
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

        // # Verify sync committee aggregate signature
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

    fn apply_light_client_update(&mut self, update: LightClientUpdate) -> Result<UpdateChanges> {
        let mut changes = UpdateChanges::default();
        // Capture store period BEFORE any finalized-header mutation.
        let store_period = self.store.finalized_sync_committee_period(&self.chain_spec);

        if let Some(ref finalized) = update.finalized {
            let update_finalized_slot = finalized.header.slot();

            if update_finalized_slot > self.store.finalized_header.slot() {
                self.store.finalized_header = finalized.header.clone();
                changes.finalized_updated = true;
            }
            // Rotate on finalized-period advancement (invariant I-2).
            if self
                .chain_spec
                .slot_to_sync_committee_period(update_finalized_slot)
                == store_period + 1
                && self.store.next_sync_committee.is_some()
            {
                self.store.current_sync_committee =
                    self.store.next_sync_committee.take().expect("TODO");
                changes.rotated = true;
            }
        }

        // TODO: Scrutinize this block of code
        //
        // Learn next sync committee AFTER the finalized-header update + rotation, using the now-updated finalized period (see consensus/README data flow).
        let finalized_period = self.store.finalized_sync_committee_period(&self.chain_spec);
        if let Some(verified) = learn_next_sync_committee(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::consensus::{AltairLightClientHeader, FinalityUpdate, SyncAggregate};

    fn create_test_beacon_header(slot: Slot) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body_root: [3u8; 32],
        }
    }

    /// Sole detector: the replays bootstrap only with matching roots.
    #[test]
    fn rejects_bootstrap_with_mismatched_trusted_root() {
        let bootstrap = LightClientBootstrap::from_header(
            LightClientHeader::Altair(AltairLightClientHeader {
                beacon: create_test_beacon_header(1),
            }),
            SyncCommittee::from_parts(vec![[1u8; 48]; 32], [2u8; 48]).unwrap(),
            vec![],
            [0u8; 32],
        );
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

    /// Sole detector: valid-only fixtures never exercise these Err arms.
    #[test]
    fn rejects_updates_failing_basic_validation() {
        // Missing Err-arm cases (period servability, relevance, committee
        // equality) are catalogued in #143.
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

        // 10 of 32 participants (under the 2/3 supermajority).
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

        // signature_slot == attested slot (must be strictly after).
        let err = processor
            .process_light_client_update(update(vec![true; 32], 2), 4)
            .err()
            .unwrap();
        assert!(err.to_string().contains(slot_chain_msg), "got: {err}");

        // signature_slot one past current_slot (must not be in the future).
        let err = processor
            .process_light_client_update(update(vec![true; 32], 5), 4)
            .err()
            .unwrap();
        assert!(err.to_string().contains(slot_chain_msg), "got: {err}");

        // finalized slot is ahead of attested slot (a state cannot finalize a block from its own future).
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
    }

    // TODO: Add new test with a store that has a known next committee
    //     - rejects unservable sig period beyond known committees
    //     - rejects conflicting next committee for same period
}
