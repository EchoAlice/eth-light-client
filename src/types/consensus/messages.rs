use super::{LightClientHeader, SyncAggregate, SyncCommittee};
use crate::types::primitives::{Root, Slot};

#[derive(Debug, Clone, PartialEq)]
pub struct LightClientBootstrap {
    pub header: LightClientHeader,
    pub current_sync_committee: SyncCommittee,
    pub current_sync_committee_branch: Vec<Root>,
    pub genesis_validators_root: Root,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LightClientUpdate {
    pub attested_header: LightClientHeader,
    pub finalized: Option<FinalityProof>,
    pub next_sync_committee: Option<SyncCommitteeProof>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: Slot, // Slot of the block that carries the sync aggregate onchain
}

impl From<LightClientOptimisticUpdate> for LightClientUpdate {
    fn from(optimistic: LightClientOptimisticUpdate) -> Self {
        LightClientUpdate {
            attested_header: optimistic.attested_header,
            finalized: None,
            next_sync_committee: None,
            sync_aggregate: optimistic.sync_aggregate,
            signature_slot: optimistic.signature_slot,
        }
    }
}

impl From<LightClientFinalityUpdate> for LightClientUpdate {
    fn from(_finality: LightClientFinalityUpdate) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LightClientOptimisticUpdate {
    pub attested_header: LightClientHeader,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: Slot,
}

pub struct LightClientFinalityUpdate {
    pub attested_header: LightClientHeader,
    pub finalized: FinalityProof,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: Slot,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FinalityProof {
    pub header: LightClientHeader,
    pub branch: Vec<Root>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SyncCommitteeProof {
    pub committee: SyncCommittee,
    pub branch: Vec<Root>,
}
