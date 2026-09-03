mod bootstrap;
mod update;

use crate::error::{Error, Result};
use crate::types::consensus::{PubkeyBytes, SyncAggregate, SyncCommittee};
use crate::types::primitives::Root;
use ssz::Decode;
use ssz_derive::Decode;
use ssz_types::typenum::{Unsigned, U32, U512, U96};
use ssz_types::{BitVector, FixedVector};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

// Sized Types:
// The sync committee size consists of 32 members for minimal and 512
// for mainnet.  Neither the fork nor the committee size are
// self-described by SSZ payloads.  Must be supplied out-of-band

#[derive(Decode, TreeHash)]
struct RawSyncCommittee<N: Unsigned> {
    pubkeys: FixedVector<PubkeyBytes, N>,
    aggregate_pubkey: PubkeyBytes,
}

impl<N: Unsigned> RawSyncCommittee<N> {
    fn into_sync_committee(self) -> SyncCommittee {
        SyncCommittee::from_parts(self.pubkeys.to_vec(), self.aggregate_pubkey)
            .expect("wire committee is spec-sized")
    }

    fn from_sync_committee(sync_committee: &SyncCommittee) -> Self {
        Self {
            pubkeys: FixedVector::new(sync_committee.pubkeys().to_vec()).expect("len checked"),
            aggregate_pubkey: sync_committee.aggregate_pubkey().clone(),
        }
    }
}

impl SyncCommittee {
    pub(crate) fn hash_tree_root(&self) -> Root {
        match self.pubkeys().len() {
            32 => {
                RawSyncCommittee::<U32>::from_sync_committee(self)
                    .tree_hash_root()
                    .0
            }
            512 => {
                RawSyncCommittee::<U512>::from_sync_committee(self)
                    .tree_hash_root()
                    .0
            }
            n => unreachable!("sync committee is 32 or 512 members, got {n}"),
        }
    }
}

#[derive(Decode)]
struct RawSyncAggregate<N: Unsigned> {
    sync_committee_bits: BitVector<N>,
    sync_committee_signature: FixedVector<u8, U96>,
}

impl<N: Unsigned> RawSyncAggregate<N> {
    fn into_sync_aggregate(self) -> SyncAggregate {
        let sync_committee_bits: Vec<bool> = self.sync_committee_bits.iter().collect();

        let mut sync_committee_signature = [0u8; 96];
        sync_committee_signature.copy_from_slice(self.sync_committee_signature.as_ref());

        SyncAggregate {
            sync_committee_bits,
            sync_committee_signature,
        }
    }
}

// Helper fns

fn decode_as<R: Decode>(bytes: &[u8]) -> Result<R> {
    R::from_ssz_bytes(bytes).map_err(decode_err)
}

fn decode_err(e: ssz::DecodeError) -> Error {
    Error::Serialization(format!("SSZ decode: {e:?}"))
}

fn bad_size(n: usize) -> Error {
    Error::InvalidInput(format!("sync_committee_size must be 32 or 512, got {n}"))
}
