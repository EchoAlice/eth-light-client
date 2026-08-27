use super::{LightClientHeader, SyncAggregate, SyncCommittee};
use crate::chain_spec::Fork;
use crate::error::Result;
use crate::types::primitives::{Root, Slot};

#[derive(Debug, Clone, PartialEq)]
pub struct LightClientBootstrap {
    pub header: LightClientHeader,
    pub current_sync_committee: SyncCommittee,
    pub current_sync_committee_branch: Vec<Root>,
    pub genesis_validators_root: Root,
}

impl LightClientBootstrap {
    pub fn from_ssz(
        bytes: &[u8],
        fork: Fork,
        sync_committee_size: usize,
        genesis_validators_root: Root,
    ) -> Result<Self> {
        crate::types::ssz::decode_bootstrap(
            bytes,
            fork,
            sync_committee_size,
            genesis_validators_root,
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LightClientUpdate {
    pub attested_header: LightClientHeader,
    pub finalized: Option<FinalityUpdate>,
    pub next_sync_committee: Option<SyncCommitteeUpdate>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: Slot, // Must be > attested_header.slot
}

impl LightClientUpdate {
    pub fn from_ssz(bytes: &[u8], fork: Fork, sync_committee_size: usize) -> Result<Self> {
        crate::types::ssz::decode_update(bytes, fork, sync_committee_size)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FinalityUpdate {
    pub header: LightClientHeader,
    pub branch: Vec<Root>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SyncCommitteeUpdate {
    pub committee: SyncCommittee,
    pub branch: Vec<Root>,
}
