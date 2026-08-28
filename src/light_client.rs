use crate::chain_spec::ChainSpec;
use crate::consensus::processor::{LightClientProcessor, UpdateChanges};
use crate::error::Result;
use crate::types::consensus::{
    BeaconBlockHeader, LightClientBootstrap, LightClientUpdate, SyncCommittee,
};
use crate::types::primitives::{Root, Slot};

pub struct LightClient {
    inner: LightClientProcessor,
}

impl LightClient {
    pub fn new(
        chain_spec: ChainSpec,
        trusted_block_root: Root,
        bootstrap: LightClientBootstrap,
    ) -> Result<Self> {
        let inner = LightClientProcessor::new(chain_spec, trusted_block_root, bootstrap)?;

        Ok(Self { inner })
    }

    pub fn process_light_client_update(
        &mut self,
        update: LightClientUpdate,
        current_slot: Slot,
    ) -> Result<UpdateChanges> {
        self.inner.process_light_client_update(update, current_slot)
    }

    pub fn finalized_beacon_block_header(&self) -> &BeaconBlockHeader {
        self.inner.store().finalized_header.beacon()
    }

    pub fn optimistic_beacon_block_header(&self) -> &BeaconBlockHeader {
        self.inner.store().optimistic_header.beacon()
    }

    pub fn current_sync_committee(&self) -> &SyncCommittee {
        &self.inner.store().current_sync_committee
    }

    /// The next period's sync committee, if it has been learned yet.
    pub fn next_sync_committee(&self) -> Option<&SyncCommittee> {
        self.inner.store().next_sync_committee.as_ref()
    }

    pub fn current_sync_committee_period(&self) -> u64 {
        self.inner
            .store()
            .finalized_sync_committee_period(self.inner.chain_spec())
    }

    pub fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }
}

impl std::fmt::Debug for LightClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LightClient")
            .field("finalized_slot", &self.finalized_beacon_block_header().slot)
            .field(
                "optimistic_slot",
                &self.optimistic_beacon_block_header().slot,
            )
            .field("current_period", &self.current_sync_committee_period())
            .field("has_next_committee", &self.next_sync_committee().is_some())
            .finish()
    }
}
