use super::{LightClientHeader, SyncAggregate, SyncCommittee};
use crate::chain_spec::Fork;
use crate::error::Result;
use crate::types::primitives::{Root, Slot};

#[cfg(test)]
use super::AltairLightClientHeader;
#[cfg(test)]
use super::BeaconBlockHeader;

#[derive(Debug, Clone, PartialEq)]
pub struct LightClientUpdate {
    pub attested_header: LightClientHeader,
    pub finalized: Option<FinalityUpdate>,
    pub next_sync_committee: Option<SyncCommitteeUpdate>,
    pub sync_aggregate: SyncAggregate,
    /// Must be > attested_header.slot
    pub signature_slot: Slot,
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

impl LightClientUpdate {
    pub fn from_ssz(bytes: &[u8], fork: Fork, sync_committee_size: usize) -> Result<Self> {
        crate::types::ssz::decode_update(bytes, fork, sync_committee_size)
    }

    #[cfg(test)]
    pub fn new(
        attested_header: BeaconBlockHeader,
        sync_aggregate: SyncAggregate,
        signature_slot: Slot,
    ) -> Self {
        Self {
            attested_header: LightClientHeader::Altair(AltairLightClientHeader {
                beacon: attested_header,
            }),
            finalized: None,
            next_sync_committee: None,
            sync_aggregate,
            signature_slot,
        }
    }

    #[cfg(test)]
    pub fn with_next_sync_committee(mut self, committee: SyncCommittee, branch: Vec<Root>) -> Self {
        self.next_sync_committee = Some(SyncCommitteeUpdate { committee, branch });
        self
    }

    pub(crate) fn has_sync_committee_update(&self) -> bool {
        self.next_sync_committee.is_some()
    }
}

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

    pub(crate) fn from_header(
        header: LightClientHeader,
        current_sync_committee: SyncCommittee,
        current_sync_committee_branch: Vec<Root>,
        genesis_validators_root: Root,
    ) -> Self {
        Self {
            header,
            current_sync_committee,
            current_sync_committee_branch,
            genesis_validators_root,
        }
    }
}
