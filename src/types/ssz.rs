use crate::chain_spec::Fork;
use crate::error::{Error, Result};
use crate::types::consensus::{
    AltairLightClientHeader, BellatrixLightClientHeader, CapellaLightClientHeader,
    DenebLightClientHeader, ElectraLightClientHeader, FinalityUpdate, LightClientBootstrap,
    LightClientHeader, LightClientUpdate, PubkeyBytes, SyncAggregate, SyncCommittee,
    SyncCommitteeUpdate,
};
use crate::types::primitives::Root;
use crate::LightClientHeader::{Altair, Bellatrix, Capella, Deneb, Electra};
use ssz::Decode;
use ssz_derive::Decode;
use ssz_types::typenum::{Unsigned, U32, U5, U512, U6, U7, U96};
use ssz_types::{BitVector, FixedVector};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

// Sync committee size is 32 for minimal and 512 for mainnet.
// Neither the fork nor the committee size are self-described by SSZ payload.

impl LightClientBootstrap {
    pub fn from_ssz(
        bytes: &[u8],
        fork: Fork,
        sync_committee_size: usize,
        genesis_validators_root: Root,
    ) -> Result<LightClientBootstrap> {
        match fork {
            Fork::Altair => match sync_committee_size {
                32 => Ok(decode_as::<RawAltairLightClientBootstrap<U32>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                512 => Ok(decode_as::<RawAltairLightClientBootstrap<U512>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                n => Err(bad_size(n)),
            },
            Fork::Bellatrix => match sync_committee_size {
                32 => Ok(decode_as::<RawBellatrixLightClientBootstrap<U32>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                512 => Ok(decode_as::<RawBellatrixLightClientBootstrap<U512>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                n => Err(bad_size(n)),
            },
            Fork::Capella => match sync_committee_size {
                32 => Ok(decode_as::<RawCapellaLightClientBootstrap<U32>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                512 => Ok(decode_as::<RawCapellaLightClientBootstrap<U512>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                n => Err(bad_size(n)),
            },
            Fork::Deneb => match sync_committee_size {
                32 => Ok(decode_as::<RawDenebLightClientBootstrap<U32>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                512 => Ok(decode_as::<RawDenebLightClientBootstrap<U512>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                n => Err(bad_size(n)),
            },
            Fork::Electra => match sync_committee_size {
                32 => Ok(decode_as::<RawElectraLightClientBootstrap<U32>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                512 => Ok(decode_as::<RawElectraLightClientBootstrap<U512>>(bytes)?
                    .into_bootstrap(genesis_validators_root)),
                n => Err(bad_size(n)),
            },
        }
    }
}

impl LightClientUpdate {
    pub fn from_ssz(
        bytes: &[u8],
        fork: Fork,
        sync_committee_size: usize,
    ) -> Result<LightClientUpdate> {
        match fork {
            Fork::Altair => match sync_committee_size {
                32 => decode_as::<RawAltairLightClientUpdate<U32>>(bytes)?.into_update(),
                512 => decode_as::<RawAltairLightClientUpdate<U512>>(bytes)?.into_update(),
                n => Err(bad_size(n)),
            },
            Fork::Bellatrix => match sync_committee_size {
                32 => decode_as::<RawBellatrixLightClientUpdate<U32>>(bytes)?.into_update(),
                512 => decode_as::<RawBellatrixLightClientUpdate<U512>>(bytes)?.into_update(),
                n => Err(bad_size(n)),
            },
            Fork::Capella => match sync_committee_size {
                32 => decode_as::<RawCapellaLightClientUpdate<U32>>(bytes)?.into_update(),
                512 => decode_as::<RawCapellaLightClientUpdate<U512>>(bytes)?.into_update(),
                n => Err(bad_size(n)),
            },
            Fork::Deneb => match sync_committee_size {
                32 => decode_as::<RawDenebLightClientUpdate<U32>>(bytes)?.into_update(),
                512 => decode_as::<RawDenebLightClientUpdate<U512>>(bytes)?.into_update(),
                n => Err(bad_size(n)),
            },
            Fork::Electra => match sync_committee_size {
                32 => decode_as::<RawElectraLightClientUpdate<U32>>(bytes)?.into_update(),
                512 => decode_as::<RawElectraLightClientUpdate<U512>>(bytes)?.into_update(),
                n => Err(bad_size(n)),
            },
        }
    }
}

fn decode_as<R: Decode>(bytes: &[u8]) -> Result<R> {
    R::from_ssz_bytes(bytes).map_err(decode_err)
}

fn decode_err(e: ssz::DecodeError) -> Error {
    Error::Serialization(format!("SSZ decode: {e:?}"))
}

fn bad_size(n: usize) -> Error {
    Error::InvalidInput(format!("sync_committee_size must be 32 or 512, got {n}"))
}

// Wire Shells

#[derive(Decode)]
struct RawAltairLightClientBootstrap<N: Unsigned> {
    header: AltairLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}

impl<N: Unsigned> RawAltairLightClientBootstrap<N> {
    fn into_bootstrap(self, genesis_validators_root: Root) -> LightClientBootstrap {
        LightClientBootstrap {
            header: Altair(self.header),
            current_sync_committee: self.current_sync_committee.into_sync_committee(),
            current_sync_committee_branch: self.current_sync_committee_branch.to_vec(),
            genesis_validators_root,
        }
    }
}

#[derive(Decode)]
struct RawBellatrixLightClientBootstrap<N: Unsigned> {
    header: BellatrixLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}

impl<N: Unsigned> RawBellatrixLightClientBootstrap<N> {
    fn into_bootstrap(self, genesis_validators_root: Root) -> LightClientBootstrap {
        LightClientBootstrap {
            header: Bellatrix(self.header),
            current_sync_committee: self.current_sync_committee.into_sync_committee(),
            current_sync_committee_branch: self.current_sync_committee_branch.to_vec(),
            genesis_validators_root,
        }
    }
}

#[derive(Decode)]
struct RawCapellaLightClientBootstrap<N: Unsigned> {
    header: CapellaLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}
impl<N: Unsigned> RawCapellaLightClientBootstrap<N> {
    fn into_bootstrap(self, genesis_validators_root: Root) -> LightClientBootstrap {
        LightClientBootstrap {
            header: Capella(self.header),
            current_sync_committee: self.current_sync_committee.into_sync_committee(),
            current_sync_committee_branch: self.current_sync_committee_branch.to_vec(),
            genesis_validators_root,
        }
    }
}

#[derive(Decode)]
struct RawDenebLightClientBootstrap<N: Unsigned> {
    header: DenebLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}
impl<N: Unsigned> RawDenebLightClientBootstrap<N> {
    fn into_bootstrap(self, genesis_validators_root: Root) -> LightClientBootstrap {
        LightClientBootstrap {
            header: Deneb(self.header),
            current_sync_committee: self.current_sync_committee.into_sync_committee(),
            current_sync_committee_branch: self.current_sync_committee_branch.to_vec(),
            genesis_validators_root,
        }
    }
}

#[derive(Decode)]
struct RawElectraLightClientBootstrap<N: Unsigned> {
    header: ElectraLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U6>,
}
impl<N: Unsigned> RawElectraLightClientBootstrap<N> {
    fn into_bootstrap(self, genesis_validators_root: Root) -> LightClientBootstrap {
        LightClientBootstrap {
            header: Electra(self.header),
            current_sync_committee: self.current_sync_committee.into_sync_committee(),
            current_sync_committee_branch: self.current_sync_committee_branch.to_vec(),
            genesis_validators_root,
        }
    }
}

#[derive(Decode)]
struct RawAltairLightClientUpdate<N: Unsigned> {
    attested_header: AltairLightClientHeader,
    next_sync_committee: RawSyncCommittee<N>,
    next_sync_committee_branch: FixedVector<Root, U5>,
    finalized_header: AltairLightClientHeader,
    finality_branch: FixedVector<Root, U6>,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

impl<N: Unsigned> RawAltairLightClientUpdate<N> {
    fn into_update(self) -> Result<LightClientUpdate> {
        assemble_update(
            Altair(self.attested_header),
            Altair(self.finalized_header),
            self.finality_branch.to_vec(),
            self.next_sync_committee.into_sync_committee(),
            self.next_sync_committee_branch.to_vec(),
            self.sync_aggregate.into_sync_aggregate(),
            self.signature_slot,
        )
    }
}

#[derive(Decode)]
struct RawBellatrixLightClientUpdate<N: Unsigned> {
    attested_header: BellatrixLightClientHeader,
    next_sync_committee: RawSyncCommittee<N>,
    next_sync_committee_branch: FixedVector<Root, U5>,
    finalized_header: BellatrixLightClientHeader,
    finality_branch: FixedVector<Root, U6>,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

impl<N: Unsigned> RawBellatrixLightClientUpdate<N> {
    fn into_update(self) -> Result<LightClientUpdate> {
        assemble_update(
            Bellatrix(self.attested_header),
            Bellatrix(self.finalized_header),
            self.finality_branch.to_vec(),
            self.next_sync_committee.into_sync_committee(),
            self.next_sync_committee_branch.to_vec(),
            self.sync_aggregate.into_sync_aggregate(),
            self.signature_slot,
        )
    }
}

#[derive(Decode)]
struct RawCapellaLightClientUpdate<N: Unsigned> {
    attested_header: CapellaLightClientHeader,
    next_sync_committee: RawSyncCommittee<N>,
    next_sync_committee_branch: FixedVector<Root, U5>,
    finalized_header: CapellaLightClientHeader,
    finality_branch: FixedVector<Root, U6>,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}
impl<N: Unsigned> RawCapellaLightClientUpdate<N> {
    fn into_update(self) -> Result<LightClientUpdate> {
        assemble_update(
            Capella(self.attested_header),
            Capella(self.finalized_header),
            self.finality_branch.to_vec(),
            self.next_sync_committee.into_sync_committee(),
            self.next_sync_committee_branch.to_vec(),
            self.sync_aggregate.into_sync_aggregate(),
            self.signature_slot,
        )
    }
}

#[derive(Decode)]
struct RawDenebLightClientUpdate<N: Unsigned> {
    attested_header: DenebLightClientHeader,
    next_sync_committee: RawSyncCommittee<N>,
    next_sync_committee_branch: FixedVector<Root, U5>,
    finalized_header: DenebLightClientHeader,
    finality_branch: FixedVector<Root, U6>,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}
impl<N: Unsigned> RawDenebLightClientUpdate<N> {
    fn into_update(self) -> Result<LightClientUpdate> {
        assemble_update(
            Deneb(self.attested_header),
            Deneb(self.finalized_header),
            self.finality_branch.to_vec(),
            self.next_sync_committee.into_sync_committee(),
            self.next_sync_committee_branch.to_vec(),
            self.sync_aggregate.into_sync_aggregate(),
            self.signature_slot,
        )
    }
}

#[derive(Decode)]
struct RawElectraLightClientUpdate<N: Unsigned> {
    attested_header: ElectraLightClientHeader,
    next_sync_committee: RawSyncCommittee<N>,
    next_sync_committee_branch: FixedVector<Root, U6>,
    finalized_header: ElectraLightClientHeader,
    finality_branch: FixedVector<Root, U7>,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}
impl<N: Unsigned> RawElectraLightClientUpdate<N> {
    fn into_update(self) -> Result<LightClientUpdate> {
        assemble_update(
            Electra(self.attested_header),
            Electra(self.finalized_header),
            self.finality_branch.to_vec(),
            self.next_sync_committee.into_sync_committee(),
            self.next_sync_committee_branch.to_vec(),
            self.sync_aggregate.into_sync_aggregate(),
            self.signature_slot,
        )
    }
}

/// The spec's validation-time consistency asserts can't live in their
/// spec-mirrored home.  Collapsing to `Option` here destroys the evidence
/// before the processor can check it, so consistancy checks exist here.
fn assemble_update(
    attested_header: LightClientHeader,
    finalized_header: LightClientHeader,
    finality_branch: Vec<Root>,
    sync_committee: SyncCommittee,
    next_sync_committee_branch: Vec<Root>,
    sync_aggregate: SyncAggregate,
    signature_slot: u64,
) -> Result<LightClientUpdate> {
    let has_finality_branch = finality_branch.iter().any(|r| r != &[0u8; 32]);
    let has_finalized_header = finalized_header.slot() != 0;
    let is_finality_update = has_finality_branch && has_finalized_header;
    // Deviation: a finality branch traveling with a zeroed header (the spec's
    // genesis-finality case — a proof that nothing is finalized yet) decodes to
    // `finalized: None`, its branch is dropped unverified.
    if !has_finality_branch && has_finalized_header {
        return Err(Error::InvalidInput(
            "finalized header present but finality branch is empty".to_string(),
        ));
    }

    let is_sync_committee_update = next_sync_committee_branch.iter().any(|r| r != &[0u8; 32]);
    if !is_sync_committee_update && !is_zeroed_committee(&sync_committee) {
        return Err(Error::InvalidInput(
            "next sync committee present but its branch is empty".to_string(),
        ));
    }

    Ok(LightClientUpdate {
        attested_header,
        finalized: is_finality_update.then_some(FinalityUpdate {
            header: finalized_header,
            branch: finality_branch,
        }),
        next_sync_committee: is_sync_committee_update.then_some(SyncCommitteeUpdate {
            committee: sync_committee,
            branch: next_sync_committee_branch,
        }),
        sync_aggregate,
        signature_slot,
    })
}

fn is_zeroed_committee(committee: &SyncCommittee) -> bool {
    let zero = [0u8; 48];
    committee.aggregate_pubkey().as_ref() == zero.as_slice()
        && committee
            .pubkeys()
            .iter()
            .all(|pk| pk.as_ref() == zero.as_slice())
}

// Sized Types

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_committee_size() {
        let err = LightClientBootstrap::from_ssz(&[], Fork::Altair, 64, [0u8; 32]);
        assert!(err.is_err());
    }

    // The guard Err paths below have no fixture coverage: the spec's
    // generators only emit consistent encodings. The legal quadrants
    // (both fields absent, both present, genesis branch-without-header)
    // are all exercised by the sync replays.

    fn header_at_slot(slot: u64) -> LightClientHeader {
        Altair(AltairLightClientHeader {
            beacon: crate::types::consensus::BeaconBlockHeader {
                slot,
                proposer_index: 0,
                parent_root: [0u8; 32],
                state_root: [0u8; 32],
                body_root: [0u8; 32],
            },
        })
    }

    fn committee_of(pubkey_byte: u8) -> SyncCommittee {
        let pubkey = PubkeyBytes::new(vec![pubkey_byte; 48]).unwrap();
        SyncCommittee::from_parts(vec![pubkey.clone(); 32], pubkey).unwrap()
    }

    fn zeroed_aggregate() -> SyncAggregate {
        SyncAggregate {
            sync_committee_bits: vec![false; 32],
            sync_committee_signature: [0u8; 96],
        }
    }

    #[test]
    fn rejects_finalized_header_with_zeroed_finality_branch() {
        let result = assemble_update(
            header_at_slot(1),
            header_at_slot(1),
            vec![[0u8; 32]; 6],
            committee_of(0),
            vec![[0u8; 32]; 5],
            zeroed_aggregate(),
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_next_committee_with_zeroed_committee_branch() {
        let result = assemble_update(
            header_at_slot(1),
            header_at_slot(0),
            vec![[0u8; 32]; 6],
            committee_of(1),
            vec![[0u8; 32]; 5],
            zeroed_aggregate(),
            0,
        );
        assert!(result.is_err());
    }
}
