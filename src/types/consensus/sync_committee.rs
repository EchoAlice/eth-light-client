use crate::error::{Error, Result};
use crate::types::primitives::{BLSPublicKey, BLSSignature};
use ssz_types::typenum::U48;
use ssz_types::FixedVector;

// TODO: Should this move to primitives.rs?
pub type PubkeyBytes = FixedVector<u8, U48>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregate {
    pub sync_committee_bits: Vec<bool>,
    pub sync_committee_signature: BLSSignature,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SyncCommittee {
    pubkeys: Vec<PubkeyBytes>,
    aggregate_pubkey: PubkeyBytes,
}

impl SyncCommittee {
    pub(crate) fn has_supermajority_participation(&self, participation_bits: &[bool]) -> bool {
        if participation_bits.len() != self.pubkeys.len() {
            return false;
        }
        let participants = participation_bits.iter().filter(|&&b| b).count();
        participants * 3 >= self.pubkeys.len() * 2
    }

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

    fn test_committee() -> SyncCommittee {
        let pubkey = |byte| PubkeyBytes::new(vec![byte; 48]).unwrap();
        SyncCommittee::from_parts(vec![pubkey(1); 32], pubkey(2)).unwrap()
    }

    #[test]
    fn test_sync_committee_supermajority() {
        let committee = test_committee();
        // 2/3 of 32 is 21.33…, so 22 is the smallest supermajority for minimal spec values.
        let threshold = 22;

        let mut participation = vec![false; 32];
        participation
            .iter_mut()
            .take(threshold)
            .for_each(|p| *p = true);
        assert!(committee.has_supermajority_participation(&participation));

        let mut participation = vec![false; 32];
        participation
            .iter_mut()
            .take(threshold - 1)
            .for_each(|p| *p = true);
        assert!(!committee.has_supermajority_participation(&participation));

        assert!(committee.has_supermajority_participation(&[true; 32]));
    }
}
