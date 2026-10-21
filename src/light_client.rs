use crate::chain_spec::{ChainSpec, Fork};
use crate::consensus::merkle::get_lc_execution_root;
use crate::consensus::processor::{LightClientProcessor, StoreChanges};
use crate::error::Result;
use crate::types::consensus::{
    BeaconBlockHeader, LightClientBootstrap, LightClientHeader, LightClientUpdate, SyncCommittee,
};
use crate::types::primitives::{Root, Slot};

pub struct LightClient {
    inner: LightClientProcessor,
}

impl LightClient {
    pub fn new(
        chain_spec: ChainSpec,
        genesis_validators_root: Root,
        trusted_block_root: Root,
        bootstrap: LightClientBootstrap,
        current_slot: Slot,
    ) -> Result<Self> {
        let inner = LightClientProcessor::new(
            chain_spec,
            genesis_validators_root,
            trusted_block_root,
            bootstrap,
            current_slot,
        )?;

        Ok(Self { inner })
    }

    pub fn process_light_client_update(
        &mut self,
        update: LightClientUpdate,
        current_slot: Slot,
    ) -> Result<StoreChanges> {
        self.inner.process_light_client_update(update, current_slot)
    }

    pub fn finalized_beacon_block_header(&self) -> &BeaconBlockHeader {
        self.inner.store().finalized_header.beacon()
    }

    pub fn finalized_execution_payload_root(&self) -> Option<Root> {
        self.execution_payload_root(&self.inner.store().finalized_header)
    }

    pub fn finalized_execution_state_root(&self) -> Option<Root> {
        self.execution_state_root(&self.inner.store().finalized_header)
    }

    pub fn optimistic_beacon_block_header(&self) -> &BeaconBlockHeader {
        self.inner.store().optimistic_header.beacon()
    }

    pub fn optimistic_execution_payload_root(&self) -> Option<Root> {
        self.execution_payload_root(&self.inner.store().optimistic_header)
    }

    pub fn optimistic_execution_state_root(&self) -> Option<Root> {
        self.execution_state_root(&self.inner.store().optimistic_header)
    }

    fn execution_payload_root(&self, header: &LightClientHeader) -> Option<Root> {
        let block_fork = self.inner.chain_spec().fork_at_slot(header.slot());
        if block_fork < Fork::Capella {
            return None;
        }
        Some(get_lc_execution_root(header, block_fork))
    }

    fn execution_state_root(&self, header: &LightClientHeader) -> Option<Root> {
        let block_fork = self.inner.chain_spec().fork_at_slot(header.slot());
        if block_fork < Fork::Capella {
            return None;
        }
        header.execution_state_root()
    }

    pub fn current_sync_committee(&self) -> &SyncCommittee {
        &self.inner.store().current_sync_committee
    }

    pub fn next_sync_committee(&self) -> Option<&SyncCommittee> {
        self.inner.store().next_sync_committee.as_ref()
    }

    pub fn finalized_sync_committee_period(&self) -> u64 {
        self.inner
            .store()
            .finalized_sync_committee_period(self.inner.chain_spec())
    }

    pub fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }

    pub fn genesis_validators_root(&self) -> Root {
        self.inner.genesis_validators_root()
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
            .field("finalized_period", &self.finalized_sync_committee_period())
            .field("has_next_committee", &self.next_sync_committee().is_some())
            .finish()
    }
}
