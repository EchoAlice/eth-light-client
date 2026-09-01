use crate::chain_spec::Fork;
use crate::error::{Error, Result};
use crate::types::consensus::{
    AltairLightClientHeader, BellatrixLightClientHeader, CapellaLightClientHeader,
    DenebLightClientHeader, ElectraLightClientHeader, FinalityUpdate, LightClientBootstrap,
    LightClientHeader, LightClientUpdate, PubkeyBytes, SyncAggregate, SyncCommittee,
    SyncCommitteeUpdate,
};
use crate::types::primitives::Root;
use ssz::Decode as _;
use ssz_derive::Decode;
use ssz_types::typenum::{Unsigned, U32, U5, U512, U6, U7, U96};
use ssz_types::{BitVector, FixedVector};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[derive(Decode)]
struct RawAltairLightClientBootstrap<N: Unsigned> {
    header: AltairLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}
fn decode_altair_bootstrap<N: Unsigned>(
    bytes: &[u8],
    genesis_validators_root: Root,
) -> Result<LightClientBootstrap> {
    let raw = RawAltairLightClientBootstrap::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(LightClientBootstrap {
        header: LightClientHeader::Altair(raw.header),
        current_sync_committee: raw.current_sync_committee.into_sync_committee(),
        current_sync_committee_branch: raw.current_sync_committee_branch.to_vec(),
        genesis_validators_root,
    })
}

#[derive(Decode)]
struct RawBellatrixLightClientBootstrap<N: Unsigned> {
    header: BellatrixLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}
fn decode_bellatrix_bootstrap<N: Unsigned>(
    bytes: &[u8],
    genesis_validators_root: Root,
) -> Result<LightClientBootstrap> {
    let raw = RawBellatrixLightClientBootstrap::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(LightClientBootstrap {
        header: LightClientHeader::Bellatrix(raw.header),
        current_sync_committee: raw.current_sync_committee.into_sync_committee(),
        current_sync_committee_branch: raw.current_sync_committee_branch.to_vec(),
        genesis_validators_root,
    })
}

#[derive(Decode)]
struct RawCapellaLightClientBootstrap<N: Unsigned> {
    header: CapellaLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}
fn decode_capella_bootstrap<N: Unsigned>(
    bytes: &[u8],
    genesis_validators_root: Root,
) -> Result<LightClientBootstrap> {
    let raw = RawCapellaLightClientBootstrap::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(LightClientBootstrap {
        header: LightClientHeader::Capella(raw.header),
        current_sync_committee: raw.current_sync_committee.into_sync_committee(),
        current_sync_committee_branch: raw.current_sync_committee_branch.to_vec(),
        genesis_validators_root,
    })
}

#[derive(Decode)]
struct RawDenebLightClientBootstrap<N: Unsigned> {
    header: DenebLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}
fn decode_deneb_bootstrap<N: Unsigned>(
    bytes: &[u8],
    genesis_validators_root: Root,
) -> Result<LightClientBootstrap> {
    let raw = RawDenebLightClientBootstrap::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(LightClientBootstrap {
        header: LightClientHeader::Deneb(raw.header),
        current_sync_committee: raw.current_sync_committee.into_sync_committee(),
        current_sync_committee_branch: raw.current_sync_committee_branch.to_vec(),
        genesis_validators_root,
    })
}

#[derive(Decode)]
struct RawElectraLightClientBootstrap<N: Unsigned> {
    header: ElectraLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U6>,
}
fn decode_electra_bootstrap<N: Unsigned>(
    bytes: &[u8],
    genesis_validators_root: Root,
) -> Result<LightClientBootstrap> {
    let raw = RawElectraLightClientBootstrap::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(LightClientBootstrap {
        header: LightClientHeader::Electra(raw.header),
        current_sync_committee: raw.current_sync_committee.into_sync_committee(),
        current_sync_committee_branch: raw.current_sync_committee_branch.to_vec(),
        genesis_validators_root,
    })
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
fn raw_altair_update_to_pub<N: Unsigned>(raw: RawAltairLightClientUpdate<N>) -> LightClientUpdate {
    let finalized_header = (raw.finalized_header.beacon.slot != 0)
        .then_some(LightClientHeader::Altair(raw.finalized_header));

    assemble_update(
        LightClientHeader::Altair(raw.attested_header),
        finalized_header,
        raw.finality_branch.to_vec(),
        raw.next_sync_committee.into_sync_committee(),
        raw.next_sync_committee_branch.to_vec(),
        raw.sync_aggregate.into_sync_aggregate(),
        raw.signature_slot,
    )
}
fn decode_altair_update<N: Unsigned>(bytes: &[u8]) -> Result<LightClientUpdate> {
    let raw = RawAltairLightClientUpdate::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(raw_altair_update_to_pub(raw))
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
fn raw_bellatrix_update_to_pub<N: Unsigned>(
    raw: RawBellatrixLightClientUpdate<N>,
) -> LightClientUpdate {
    let finalized_header = (raw.finalized_header.beacon.slot != 0)
        .then_some(LightClientHeader::Bellatrix(raw.finalized_header));

    assemble_update(
        LightClientHeader::Bellatrix(raw.attested_header),
        finalized_header,
        raw.finality_branch.to_vec(),
        raw.next_sync_committee.into_sync_committee(),
        raw.next_sync_committee_branch.to_vec(),
        raw.sync_aggregate.into_sync_aggregate(),
        raw.signature_slot,
    )
}
fn decode_bellatrix_update<N: Unsigned>(bytes: &[u8]) -> Result<LightClientUpdate> {
    let raw = RawBellatrixLightClientUpdate::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(raw_bellatrix_update_to_pub(raw))
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
fn raw_capella_update_to_pub<N: Unsigned>(
    raw: RawCapellaLightClientUpdate<N>,
) -> LightClientUpdate {
    let finalized_header = (raw.finalized_header.beacon.slot != 0)
        .then_some(LightClientHeader::Capella(raw.finalized_header));

    assemble_update(
        LightClientHeader::Capella(raw.attested_header),
        finalized_header,
        raw.finality_branch.to_vec(),
        raw.next_sync_committee.into_sync_committee(),
        raw.next_sync_committee_branch.to_vec(),
        raw.sync_aggregate.into_sync_aggregate(),
        raw.signature_slot,
    )
}
fn decode_capella_update<N: Unsigned>(bytes: &[u8]) -> Result<LightClientUpdate> {
    let raw = RawCapellaLightClientUpdate::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(raw_capella_update_to_pub(raw))
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
fn raw_deneb_update_to_pub<N: Unsigned>(raw: RawDenebLightClientUpdate<N>) -> LightClientUpdate {
    let finalized_header = (raw.finalized_header.beacon.slot != 0)
        .then_some(LightClientHeader::Deneb(raw.finalized_header));

    assemble_update(
        LightClientHeader::Deneb(raw.attested_header),
        finalized_header,
        raw.finality_branch.to_vec(),
        raw.next_sync_committee.into_sync_committee(),
        raw.next_sync_committee_branch.to_vec(),
        raw.sync_aggregate.into_sync_aggregate(),
        raw.signature_slot,
    )
}
fn decode_deneb_update<N: Unsigned>(bytes: &[u8]) -> Result<LightClientUpdate> {
    let raw = RawDenebLightClientUpdate::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(raw_deneb_update_to_pub(raw))
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
fn raw_electra_update_to_pub<N: Unsigned>(
    raw: RawElectraLightClientUpdate<N>,
) -> LightClientUpdate {
    let finalized_header = (raw.finalized_header.beacon.slot != 0)
        .then_some(LightClientHeader::Electra(raw.finalized_header));

    assemble_update(
        LightClientHeader::Electra(raw.attested_header),
        finalized_header,
        raw.finality_branch.to_vec(),
        raw.next_sync_committee.into_sync_committee(),
        raw.next_sync_committee_branch.to_vec(),
        raw.sync_aggregate.into_sync_aggregate(),
        raw.signature_slot,
    )
}
fn decode_electra_update<N: Unsigned>(bytes: &[u8]) -> Result<LightClientUpdate> {
    let raw = RawElectraLightClientUpdate::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(raw_electra_update_to_pub(raw))
}

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

/// Assemble a `LightClientUpdate` from converted parts, applying the spec's
/// optional-field rules uniformly: a `None` finalized header means "no finality
/// update" (empty finality branch), and an all-zero sync committee means "no
/// committee update" (empty next-committee branch).
fn assemble_update(
    attested_header: LightClientHeader,
    finalized_header: Option<LightClientHeader>,
    finality_branch: Vec<Root>,
    sync_committee: SyncCommittee,
    next_sync_committee_branch: Vec<Root>,
    sync_aggregate: SyncAggregate,
    signature_slot: u64,
) -> LightClientUpdate {
    let has_sync_committee = !sync_committee
        .pubkeys()
        .iter()
        .all(|pk| pk.iter().all(|&b| b == 0));

    LightClientUpdate {
        attested_header,
        finalized: finalized_header.map(|header| FinalityUpdate {
            header,
            branch: finality_branch,
        }),
        next_sync_committee: has_sync_committee.then_some(SyncCommitteeUpdate {
            committee: sync_committee,
            branch: next_sync_committee_branch,
        }),
        sync_aggregate,
        signature_slot,
    }
}

// Fork- and size-dispatched SSZ decode: raw bytes -> public type. `bytes` is raw
// SSZ (not snappy-framed). `fork` selects the wire layout and `sync_committee_size`
// (32 minimal / 512 mainnet) the committee/aggregate width — neither is carried
// by the bytes.

pub(crate) fn decode_bootstrap(
    bytes: &[u8],
    fork: Fork,
    sync_committee_size: usize,
    genesis_validators_root: Root,
) -> Result<LightClientBootstrap> {
    match fork {
        Fork::Altair => match sync_committee_size {
            32 => decode_altair_bootstrap::<U32>(bytes, genesis_validators_root),
            512 => decode_altair_bootstrap::<U512>(bytes, genesis_validators_root),
            n => Err(bad_size(n)),
        },
        Fork::Bellatrix => match sync_committee_size {
            32 => decode_bellatrix_bootstrap::<U32>(bytes, genesis_validators_root),
            512 => decode_bellatrix_bootstrap::<U512>(bytes, genesis_validators_root),
            n => Err(bad_size(n)),
        },
        Fork::Capella => match sync_committee_size {
            32 => decode_capella_bootstrap::<U32>(bytes, genesis_validators_root),
            512 => decode_capella_bootstrap::<U512>(bytes, genesis_validators_root),
            n => Err(bad_size(n)),
        },
        Fork::Deneb => match sync_committee_size {
            32 => decode_deneb_bootstrap::<U32>(bytes, genesis_validators_root),
            512 => decode_deneb_bootstrap::<U512>(bytes, genesis_validators_root),
            n => Err(bad_size(n)),
        },
        Fork::Electra => match sync_committee_size {
            32 => decode_electra_bootstrap::<U32>(bytes, genesis_validators_root),
            512 => decode_electra_bootstrap::<U512>(bytes, genesis_validators_root),
            n => Err(bad_size(n)),
        },
    }
}

/// SSZ-decode a light client update for `fork` + `sync_committee_size`
/// (see [`LightClientUpdate::from_ssz`] for the wire-layout contract).
pub(crate) fn decode_update(
    bytes: &[u8],
    fork: Fork,
    sync_committee_size: usize,
) -> Result<LightClientUpdate> {
    match fork {
        Fork::Altair => match sync_committee_size {
            32 => decode_altair_update::<U32>(bytes),
            512 => decode_altair_update::<U512>(bytes),
            n => Err(bad_size(n)),
        },
        Fork::Bellatrix => match sync_committee_size {
            32 => decode_bellatrix_update::<U32>(bytes),
            512 => decode_bellatrix_update::<U512>(bytes),
            n => Err(bad_size(n)),
        },
        Fork::Capella => match sync_committee_size {
            32 => decode_capella_update::<U32>(bytes),
            512 => decode_capella_update::<U512>(bytes),
            n => Err(bad_size(n)),
        },
        Fork::Deneb => match sync_committee_size {
            32 => decode_deneb_update::<U32>(bytes),
            512 => decode_deneb_update::<U512>(bytes),
            n => Err(bad_size(n)),
        },
        Fork::Electra => match sync_committee_size {
            32 => decode_electra_update::<U32>(bytes),
            512 => decode_electra_update::<U512>(bytes),
            n => Err(bad_size(n)),
        },
    }
}

fn decode_err(e: ssz::DecodeError) -> Error {
    Error::Serialization(format!("SSZ decode: {e:?}"))
}

fn bad_size(n: usize) -> Error {
    Error::InvalidInput(format!("sync_committee_size must be 32 or 512, got {n}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_committee_size() {
        let err = LightClientBootstrap::from_ssz(&[], Fork::Altair, 64, [0u8; 32]);
        assert!(err.is_err());
    }
}
