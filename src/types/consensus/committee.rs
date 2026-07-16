//! Sync committee and sync aggregate.

use crate::error::{Error, Result};
use crate::types::primitives::{BLSPublicKey, BLSSignature, Root};
use ssz_types::typenum::{U32, U48, U512};
use ssz_types::FixedVector;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub type PubkeyBytes = FixedVector<u8, U48>;

#[derive(Debug, Clone, PartialEq)]
pub struct SyncCommittee {
    pubkeys: Vec<PubkeyBytes>,
    aggregate_pubkey: PubkeyBytes,
}

// Size-specific SSZ-native views used only to derive the committee root
// (`Vector[pubkey, N]`); the library does the merkleization, not hand-rolled.
#[derive(TreeHash)]
struct CommitteeRoot512 {
    pubkeys: FixedVector<PubkeyBytes, U512>,
    aggregate_pubkey: PubkeyBytes,
}
#[derive(TreeHash)]
struct CommitteeRoot32 {
    pubkeys: FixedVector<PubkeyBytes, U32>,
    aggregate_pubkey: PubkeyBytes,
}

impl SyncCommittee {
    /// SSZ `hash_tree_root`, dispatched on the (spec-sized) committee length.
    pub(crate) fn hash_tree_root(&self) -> Root {
        let agg = self.aggregate_pubkey.clone();
        match self.pubkeys.len() {
            512 => {
                CommitteeRoot512 {
                    pubkeys: FixedVector::new(self.pubkeys.clone()).expect("len checked"),
                    aggregate_pubkey: agg,
                }
                .tree_hash_root()
                .0
            }
            32 => {
                CommitteeRoot32 {
                    pubkeys: FixedVector::new(self.pubkeys.clone()).expect("len checked"),
                    aggregate_pubkey: agg,
                }
                .tree_hash_root()
                .0
            }
            n => unreachable!("sync committee is 32 or 512 members, got {n}"),
        }
    }

    pub fn pubkeys(&self) -> &[PubkeyBytes] {
        &self.pubkeys
    }

    pub fn aggregate_pubkey(&self) -> &PubkeyBytes {
        &self.aggregate_pubkey
    }

    pub(crate) fn len(&self) -> usize {
        self.pubkeys.len()
    }

    /// 2/3 supermajority over the spec-sized committee.
    pub(crate) fn has_supermajority_participation(&self, participation_bits: &[bool]) -> bool {
        if participation_bits.len() != self.len() {
            return false;
        }
        let participants = participation_bits.iter().filter(|&&b| b).count();
        participants >= (self.len() * 2 / 3)
    }

    /// Bit-selected participating pubkeys as raw 48-byte keys (for BLS).
    pub(crate) fn participating_pubkeys(
        &self,
        participation_bits: &[bool],
    ) -> Result<Vec<BLSPublicKey>> {
        if participation_bits.len() != self.len() {
            return Err(Error::InvalidInput(
                "Participation bits length mismatch".to_string(),
            ));
        }
        let mut out = Vec::new();
        for (i, &bit) in participation_bits.iter().enumerate() {
            if bit {
                let mut key = [0u8; 48];
                key.copy_from_slice(&self.pubkeys[i]);
                out.push(key);
            }
        }
        Ok(out)
    }

    /// Build a spec-sized committee (32 or 512 keys) from raw pubkey bytes.
    ///
    /// Enforces the `{32, 512}` size invariant at construction, so the size
    /// dispatch in [`hash_tree_root`](Self::hash_tree_root) is total.
    pub(crate) fn from_parts(
        pubkeys: Vec<BLSPublicKey>,
        aggregate_pubkey: BLSPublicKey,
    ) -> Result<Self> {
        if pubkeys.len() != 32 && pubkeys.len() != 512 {
            return Err(Error::InvalidInput(format!(
                "sync committee must have 32 or 512 members, got {}",
                pubkeys.len()
            )));
        }
        Ok(SyncCommittee {
            pubkeys: pubkeys
                .into_iter()
                .map(|pk| PubkeyBytes::new(pk.to_vec()).expect("48-byte pubkey"))
                .collect(),
            aggregate_pubkey: PubkeyBytes::new(aggregate_pubkey.to_vec()).expect("48-byte pubkey"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregate {
    pub sync_committee_bits: Vec<bool>,
    pub sync_committee_signature: BLSSignature,
}

impl SyncAggregate {
    pub fn new(sync_committee_bits: Vec<bool>, sync_committee_signature: BLSSignature) -> Self {
        Self {
            sync_committee_bits,
            sync_committee_signature,
        }
    }

    /// Check if sync aggregate has supermajority participation
    /// Uses actual committee size from the provided sync committee
    pub(crate) fn has_supermajority(&self, sync_committee: &SyncCommittee) -> bool {
        sync_committee.has_supermajority_participation(self.sync_committee_bits.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_committee() -> SyncCommittee {
        SyncCommittee::from_parts(vec![[1u8; 48]; 32], [2u8; 48]).unwrap()
    }

    #[test]
    fn test_sync_committee_supermajority() {
        let committee = test_committee();
        let threshold = 32 * 2 / 3; // 21 of 32

        // Exactly 2/3 passes.
        let mut participation = vec![false; 32];
        participation
            .iter_mut()
            .take(threshold)
            .for_each(|p| *p = true);
        assert!(committee.has_supermajority_participation(&participation));

        // One below 2/3 fails.
        let mut participation = vec![false; 32];
        participation
            .iter_mut()
            .take(threshold - 1)
            .for_each(|p| *p = true);
        assert!(!committee.has_supermajority_participation(&participation));

        // Full participation passes.
        assert!(committee.has_supermajority_participation(&[true; 32]));
    }
}
