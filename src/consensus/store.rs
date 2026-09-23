use crate::chain_spec::ChainSpec;
use crate::types::consensus::{LightClientHeader, SyncCommittee};

/// The persistent state that a light client maintains across updates.
#[derive(Debug)]
pub(crate) struct LightClientStore {
    pub optimistic_header: LightClientHeader,
    pub finalized_header: LightClientHeader,
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: Option<SyncCommittee>,
}

impl LightClientStore {
    pub(crate) fn new(
        finalized_header: LightClientHeader,
        current_sync_committee: SyncCommittee,
    ) -> Self {
        Self {
            optimistic_header: finalized_header.clone(),
            finalized_header,
            current_sync_committee,
            next_sync_committee: None,
        }
    }

    /// The canonical "store period" per consensus-specs.
    pub(crate) fn finalized_sync_committee_period(&self, spec: &ChainSpec) -> u64 {
        spec.slot_to_sync_committee_period(self.finalized_header.slot())
    }
}
