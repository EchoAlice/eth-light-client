//! Light client update / bootstrap messages exchanged during sync.

use super::{LightClientHeader, SyncAggregate, SyncCommittee};
use crate::config::Fork;
use crate::error::{Error, Result};
use crate::types::primitives::{Root, Slot};

#[cfg(test)]
use super::BeaconBlockHeader;

#[derive(Debug, Clone, PartialEq)]
pub struct LightClientUpdate {
    pub attested_header: LightClientHeader,
    /// The finalized header and its finality branch — present together or not at all.
    pub finalized: Option<FinalityUpdate>,
    /// The next sync committee and its inclusion branch — present together or not at all.
    pub next_sync_committee: Option<SyncCommitteeUpdate>,
    pub sync_aggregate: SyncAggregate,
    /// Should be attested_header.slot + 1
    pub signature_slot: Slot,
}

/// A finalized header paired with the Merkle branch proving it in the attested state.
#[derive(Debug, Clone, PartialEq)]
pub struct FinalityUpdate {
    pub header: LightClientHeader,
    pub branch: Vec<Root>,
}

/// A next sync committee paired with the Merkle branch proving it in the attested state.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncCommitteeUpdate {
    pub committee: SyncCommittee,
    pub branch: Vec<Root>,
}

impl LightClientUpdate {
    pub fn from_ssz(bytes: &[u8], fork: Fork, sync_committee_size: usize) -> Result<Self> {
        crate::types::ssz::decode_update(bytes, fork, sync_committee_size)
    }

    /// Test builder: an Altair-wrapped update with no finality / next committee.
    #[cfg(test)]
    pub fn new(
        attested_header: BeaconBlockHeader,
        sync_aggregate: SyncAggregate,
        signature_slot: Slot,
    ) -> Self {
        Self {
            attested_header: LightClientHeader::altair(attested_header),
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

    /// Validate basic properties of the light client update.
    ///
    /// Enforces:
    /// - `signature_slot > attested_header.slot`
    /// - supermajority participation
    pub(crate) fn validate_basic(&self, sync_committee: &SyncCommittee) -> Result<()> {
        if self.signature_slot <= self.attested_header.slot() {
            return Err(Error::InvalidInput(
                "Signature slot must be after attested header slot".to_string(),
            ));
        }

        if !self.sync_aggregate.has_supermajority(sync_committee) {
            return Err(Error::InvalidInput(
                "Insufficient sync committee participation".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if this update contains sync committee changes
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

    /// Assemble a bootstrap from a fork-aware [`LightClientHeader`] (used by decode).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_light_client_update_validation() {
        let attested_header = BeaconBlockHeader::new(1000, 42, [1u8; 32], [2u8; 32], [3u8; 32]);
        let sync_aggregate = SyncAggregate::new(vec![true; 32], [1u8; 96]);

        let update = LightClientUpdate::new(
            attested_header,
            sync_aggregate,
            1001, // signature_slot must be > attested_header.slot
        );

        let sync_committee = SyncCommittee::from_parts(vec![[1u8; 48]; 32], [2u8; 48]).unwrap();
        assert!(update.validate_basic(&sync_committee).is_ok());
        assert!(update.finalized.is_none());
        assert!(!update.has_sync_committee_update());
    }
}
