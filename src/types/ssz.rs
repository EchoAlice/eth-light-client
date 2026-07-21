//! SSZ wire decode for the light client types.
//!
//! Most public types decode themselves (`#[derive(Decode)]`): `BeaconBlockHeader`
//! and `CapellaLightClientHeader` are used directly as wire fields. What remains
//! here is the irreducible adapter: fork-dispatched wrapping of headers into the
//! [`LightClientHeader`] enum, the spec-sized sync committee / aggregate (which
//! can't be a plain derive), and the spec's optional-field collapse.
//!
//! The sync committee / aggregate size (32 minimal, 512 mainnet) is a preset
//! constant the wire layout depends on but the bytes don't carry, so the `Raw*`
//! structs are generic over it (`N`) and the caller supplies
//! `sync_committee_size`. These generics stay internal to this module.

use crate::config::Fork;
use crate::types::consensus::{
    BeaconBlockHeader, CapellaLightClientHeader, DenebLightClientHeader, FinalityUpdate,
    LightClientBootstrap, LightClientHeader, LightClientUpdate, SyncAggregate, SyncCommittee,
    SyncCommitteeUpdate,
};
use crate::types::primitives::Root;
use ssz::Decode as _;
use ssz_derive::Decode;
use ssz_types::typenum::{Unsigned, U32, U48, U5, U512, U6, U96};
use ssz_types::{BitVector, FixedVector};

#[derive(Decode)]
struct RawSyncCommittee<N: Unsigned> {
    pubkeys: FixedVector<FixedVector<u8, U48>, N>,
    aggregate_pubkey: FixedVector<u8, U48>,
}

impl<N: Unsigned> RawSyncCommittee<N> {
    fn into_sync_committee(self) -> SyncCommittee {
        let pubkeys: Vec<[u8; 48]> = self
            .pubkeys
            .iter()
            .map(|pk| {
                let mut key = [0u8; 48];
                key.copy_from_slice(pk.as_ref());
                key
            })
            .collect();

        let mut aggregate = [0u8; 48];
        aggregate.copy_from_slice(self.aggregate_pubkey.as_ref());

        SyncCommittee::from_parts(pubkeys, aggregate).expect("wire committee is spec-sized")
    }
}

#[derive(Decode)]
struct RawSyncAggregate<N: Unsigned> {
    sync_committee_bits: BitVector<N>,
    sync_committee_signature: FixedVector<u8, U96>,
}

impl<N: Unsigned> RawSyncAggregate<N> {
    fn into_sync_aggregate(self) -> SyncAggregate {
        let bits: Vec<bool> = self.sync_committee_bits.iter().collect();

        let mut signature = [0u8; 96];
        signature.copy_from_slice(self.sync_committee_signature.as_ref());

        SyncAggregate::new(bits, signature)
    }
}

// Beacon-only (Altair/Bellatrix): the header is a `BeaconBlockHeader` on the wire
// (the 1-field LightClientHeader wrapper is serialization-transparent).
#[derive(Decode)]
struct RawLightClientUpdate<N: Unsigned> {
    attested_header: BeaconBlockHeader,
    next_sync_committee: RawSyncCommittee<N>,
    next_sync_committee_branch: FixedVector<Root, U5>,
    finalized_header: BeaconBlockHeader,
    finality_branch: FixedVector<Root, U6>,
    sync_aggregate: RawSyncAggregate<N>,
    signature_slot: u64,
}

#[derive(Decode)]
struct RawLightClientBootstrap<N: Unsigned> {
    header: BeaconBlockHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}

// Capella+: the header is the public `CapellaLightClientHeader` container.
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

#[derive(Decode)]
struct RawCapellaLightClientBootstrap<N: Unsigned> {
    header: CapellaLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}

// Deneb+: identical wire shape to Capella except the header is a
// `DenebLightClientHeader` (its execution payload carries the two EIP-4844 fields).
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

#[derive(Decode)]
struct RawDenebLightClientBootstrap<N: Unsigned> {
    header: DenebLightClientHeader,
    current_sync_committee: RawSyncCommittee<N>,
    current_sync_committee_branch: FixedVector<Root, U5>,
}

/// Wrap a decoded beacon header into the fork's `LightClientHeader` variant.
fn wrap_beacon_only(fork: Fork, beacon: BeaconBlockHeader) -> LightClientHeader {
    match fork {
        Fork::Altair => LightClientHeader::altair(beacon),
        Fork::Bellatrix => LightClientHeader::bellatrix(beacon),
        Fork::Capella | Fork::Deneb | Fork::Electra => {
            unreachable!("beacon-only header for {fork:?}")
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

fn raw_beacon_only_update_to_pub<N: Unsigned>(
    fork: Fork,
    raw: RawLightClientUpdate<N>,
) -> LightClientUpdate {
    // A default (slot-0) finalized header means the update carries no finality.
    let finalized_header =
        (raw.finalized_header.slot != 0).then_some(wrap_beacon_only(fork, raw.finalized_header));

    assemble_update(
        wrap_beacon_only(fork, raw.attested_header),
        finalized_header,
        raw.finality_branch.to_vec(),
        raw.next_sync_committee.into_sync_committee(),
        raw.next_sync_committee_branch.to_vec(),
        raw.sync_aggregate.into_sync_aggregate(),
        raw.signature_slot,
    )
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

// Fork- and size-dispatched SSZ decode: raw bytes -> public type. `bytes` is raw
// SSZ (not snappy-framed). `fork` selects the wire layout and `sync_committee_size`
// (32 minimal / 512 mainnet) the committee/aggregate width — neither is carried
// by the bytes.

fn decode_beacon_only_update<N: Unsigned>(
    bytes: &[u8],
    fork: Fork,
) -> crate::error::Result<LightClientUpdate> {
    let raw = RawLightClientUpdate::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(raw_beacon_only_update_to_pub(fork, raw))
}

fn decode_capella_update<N: Unsigned>(bytes: &[u8]) -> crate::error::Result<LightClientUpdate> {
    let raw = RawCapellaLightClientUpdate::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(raw_capella_update_to_pub(raw))
}

fn decode_deneb_update<N: Unsigned>(bytes: &[u8]) -> crate::error::Result<LightClientUpdate> {
    let raw = RawDenebLightClientUpdate::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(raw_deneb_update_to_pub(raw))
}

/// SSZ-decode a light client update for `fork` + `sync_committee_size`
/// (see [`LightClientUpdate::from_ssz`] for the wire-layout contract).
pub(crate) fn decode_update(
    bytes: &[u8],
    fork: Fork,
    sync_committee_size: usize,
) -> crate::error::Result<LightClientUpdate> {
    match fork {
        Fork::Altair | Fork::Bellatrix => match sync_committee_size {
            32 => decode_beacon_only_update::<U32>(bytes, fork),
            512 => decode_beacon_only_update::<U512>(bytes, fork),
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
        Fork::Electra => Err(unsupported(fork)),
    }
}

fn decode_beacon_only_bootstrap<N: Unsigned>(
    bytes: &[u8],
    fork: Fork,
    genesis_validators_root: Root,
) -> crate::error::Result<LightClientBootstrap> {
    let raw = RawLightClientBootstrap::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(LightClientBootstrap::from_header(
        wrap_beacon_only(fork, raw.header),
        raw.current_sync_committee.into_sync_committee(),
        raw.current_sync_committee_branch.to_vec(),
        genesis_validators_root,
    ))
}

fn decode_capella_bootstrap<N: Unsigned>(
    bytes: &[u8],
    genesis_validators_root: Root,
) -> crate::error::Result<LightClientBootstrap> {
    let raw = RawCapellaLightClientBootstrap::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(LightClientBootstrap::from_header(
        LightClientHeader::Capella(raw.header),
        raw.current_sync_committee.into_sync_committee(),
        raw.current_sync_committee_branch.to_vec(),
        genesis_validators_root,
    ))
}

fn decode_deneb_bootstrap<N: Unsigned>(
    bytes: &[u8],
    genesis_validators_root: Root,
) -> crate::error::Result<LightClientBootstrap> {
    let raw = RawDenebLightClientBootstrap::<N>::from_ssz_bytes(bytes).map_err(decode_err)?;
    Ok(LightClientBootstrap::from_header(
        LightClientHeader::Deneb(raw.header),
        raw.current_sync_committee.into_sync_committee(),
        raw.current_sync_committee_branch.to_vec(),
        genesis_validators_root,
    ))
}

pub(crate) fn decode_bootstrap(
    bytes: &[u8],
    fork: Fork,
    sync_committee_size: usize,
    genesis_validators_root: Root,
) -> crate::error::Result<LightClientBootstrap> {
    match fork {
        Fork::Altair | Fork::Bellatrix => match sync_committee_size {
            32 => decode_beacon_only_bootstrap::<U32>(bytes, fork, genesis_validators_root),
            512 => decode_beacon_only_bootstrap::<U512>(bytes, fork, genesis_validators_root),
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
        Fork::Electra => Err(unsupported(fork)),
    }
}

fn decode_err(e: ssz::DecodeError) -> crate::error::Error {
    crate::error::Error::Serialization(format!("SSZ decode: {e:?}"))
}

fn bad_size(n: usize) -> crate::error::Error {
    crate::error::Error::InvalidInput(format!("sync_committee_size must be 32 or 512, got {n}"))
}

fn unsupported(fork: Fork) -> crate::error::Error {
    crate::error::Error::InvalidInput(format!(
        "SSZ decode not supported for {fork:?} (supported through Deneb)"
    ))
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
