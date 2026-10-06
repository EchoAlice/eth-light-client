use ssz_types::typenum::U48;
use ssz_types::FixedVector;

use crate::error::{Error, Result};
use crate::types::primitives::{BLSPublicKey, BLSSignature};

// TODO: Should this move to primitives.rs?
pub type PubkeyBytes = FixedVector<u8, U48>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregate {
    pub sync_committee_bits: Vec<bool>,
    pub sync_committee_signature: BLSSignature,
}

impl SyncAggregate {
    /// Spec: `sum(sync_aggregate.sync_committee_bits) * 3 >= len(sync_committee_bits) * 2`
    pub(crate) fn has_supermajority_participation(&self) -> bool {
        let participants = self.sync_committee_bits.iter().filter(|b| **b).count();
        participants * 3 >= self.sync_committee_bits.len() * 2
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SyncCommittee {
    pubkeys: Vec<PubkeyBytes>,
    aggregate_pubkey: PubkeyBytes,
}

impl SyncCommittee {
    pub(crate) fn participating_pubkeys(
        &self,
        participation_bits: &[bool],
    ) -> Result<Vec<BLSPublicKey>> {
        if participation_bits.len() != self.pubkeys.len() {
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

    /// Enforces the `{32, 512}` size invariant at construction, so the size
    /// dispatch in [`hash_tree_root`](Self::hash_tree_root) (and the
    /// `FixedVector` rebuild behind it) can treat other lengths as unreachable.
    pub(crate) fn from_parts(
        pubkeys: Vec<PubkeyBytes>,
        aggregate_pubkey: PubkeyBytes,
    ) -> Result<Self> {
        if pubkeys.len() != 32 && pubkeys.len() != 512 {
            return Err(Error::InvalidInput(format!(
                "sync committee must have 32 or 512 members, got {}",
                pubkeys.len()
            )));
        }
        Ok(SyncCommittee {
            pubkeys,
            aggregate_pubkey,
        })
    }

    pub fn pubkeys(&self) -> &[PubkeyBytes] {
        &self.pubkeys
    }

    pub fn aggregate_pubkey(&self) -> &PubkeyBytes {
        &self.aggregate_pubkey
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supermajority_threshold_minimal_preset() {
        let aggregate = |bits: Vec<bool>| SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature: [0u8; 96],
        };

        // 2/3 of 32 is 21.33…, so 22 is the smallest supermajority
        assert!(!aggregate([vec![true; 21], vec![false; 11]].concat())
            .has_supermajority_participation());
        assert!(
            aggregate([vec![true; 22], vec![false; 10]].concat()).has_supermajority_participation()
        );
        assert!(aggregate(vec![true; 32]).has_supermajority_participation());
    }
}
