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
            chain_spec
                .fork_at_slot(trusted_header.slot())
                .current_sync_committee_gindex(),
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
                        .fork_at_slot(update.attested_header.slot())
                        .finalized_root_gindex(),
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

        // Learn next AFTER the finalized-header update + rotation, using the now-updated finalized period (see consensus/README data flow).
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

#[cfg(test)]
mod tests {
    use super::*;
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

    /// Sole detector: valid-only fixtures never exercise these Err arms.
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
}
