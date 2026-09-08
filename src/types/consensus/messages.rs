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
    pub signature_slot: Slot, // Must be > attested_header.slot
}

#[derive(Debug, Clone, PartialEq)]
pub struct LightClientOptimisticUpdate {
    pub attested_header: LightClientHeader,
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
