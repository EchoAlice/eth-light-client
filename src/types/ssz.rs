//! SSZ wire decode for the light client types.
//!
//! Most public types decode themselves (`#[derive(Decode)]`): `BeaconBlockHeader`
//! and `CapellaLightClientHeader` are used directly as wire fields. What remains
//! here is the irreducible adapter: fork-dispatched wrapping of headers into the
//! [`LightClientHeader`] enum, the spec-sized sync committee / aggregate (which
//! can't be a plain derive), and the spec's optional-field collapse.
//!
//! The mirror is minimal-preset only: it decodes 32-key committees. Mainnet
//! committee decode is not yet wired.

use crate::config::Fork;
use crate::types::consensus::{
    BeaconBlockHeader, CapellaLightClientHeader, LightClientBootstrap, LightClientHeader,
    LightClientUpdate, SyncAggregate, SyncCommittee,
};
use crate::types::primitives::Root;
use ssz::Decode as _;
use ssz_derive::Decode;
use ssz_types::typenum::{U32, U48, U5, U6, U96};
use ssz_types::{BitVector, FixedVector};

#[derive(Decode)]
pub(crate) struct RawSyncCommittee {
    pubkeys: FixedVector<FixedVector<u8, U48>, U32>,
    aggregate_pubkey: FixedVector<u8, U48>,
}

impl RawSyncCommittee {
    fn into_sync_committee(self) -> SyncCommittee {
        // Minimal fixtures hold exactly 32 pubkeys (SSZ `Vector<_, 32>` decode) —
        // the spec-sized minimal committee, no padding.
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

        SyncCommittee::from_minimal_parts(pubkeys, aggregate)
            .expect("minimal fixture committee is 32 valid pubkeys")
    }
}

#[derive(Decode)]
struct RawSyncAggregate {
    sync_committee_bits: BitVector<U32>,
    sync_committee_signature: FixedVector<u8, U96>,
}

impl RawSyncAggregate {
    fn into_sync_aggregate(self) -> SyncAggregate {
        // Spec-sized bits (32 for minimal fixtures), no padding.
        let bits: Vec<bool> = self.sync_committee_bits.iter().collect();

        let mut signature = [0u8; 96];
        signature.copy_from_slice(self.sync_committee_signature.as_ref());

        SyncAggregate::new(bits, signature)
    }
}

// Beacon-only (Altair/Bellatrix): the header is a `BeaconBlockHeader` on the wire
// (the 1-field LightClientHeader wrapper is serialization-transparent).
#[derive(Decode)]
struct RawLightClientUpdate {
    attested_header: BeaconBlockHeader,
    next_sync_committee: RawSyncCommittee,
    next_sync_committee_branch: FixedVector<Root, U5>,
    finalized_header: BeaconBlockHeader,
    finality_branch: FixedVector<Root, U6>,
    sync_aggregate: RawSyncAggregate,
    signature_slot: u64,
}

#[derive(Decode)]
struct RawLightClientBootstrap {
    header: BeaconBlockHeader,
    current_sync_committee: RawSyncCommittee,
    current_sync_committee_branch: FixedVector<Root, U5>,
}

// Capella+: the header is the public `CapellaLightClientHeader` container.
#[derive(Decode)]
struct RawCapellaLightClientUpdate {
    attested_header: CapellaLightClientHeader,
    next_sync_committee: RawSyncCommittee,
    next_sync_committee_branch: FixedVector<Root, U5>,
    finalized_header: CapellaLightClientHeader,
    finality_branch: FixedVector<Root, U6>,
    sync_aggregate: RawSyncAggregate,
    signature_slot: u64,
}

#[derive(Decode)]
struct RawCapellaLightClientBootstrap {
    header: CapellaLightClientHeader,
    current_sync_committee: RawSyncCommittee,
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
    let has_finality = finalized_header.is_some();
    let has_sync_committee = !sync_committee
        .pubkeys()
        .iter()
        .all(|pk| pk.iter().all(|&b| b == 0));

    LightClientUpdate {
        attested_header,
        finalized_header,
        finality_branch: if has_finality {
            finality_branch
        } else {
            Vec::new()
        },
        next_sync_committee: has_sync_committee.then_some(sync_committee),
        next_sync_committee_branch: if has_sync_committee {
            next_sync_committee_branch
        } else {
            Vec::new()
        },
        sync_aggregate,
        signature_slot,
    }
}

fn raw_beacon_only_update_to_pub(fork: Fork, raw: RawLightClientUpdate) -> LightClientUpdate {
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

fn raw_capella_update_to_pub(raw: RawCapellaLightClientUpdate) -> LightClientUpdate {
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

// Fork-dispatched SSZ decode: raw bytes -> public type. `bytes` is raw SSZ (not
// snappy-framed). Fork selects the wire layout (SSZ is not self-describing).

pub(crate) fn decode_update(bytes: &[u8], fork: Fork) -> crate::error::Result<LightClientUpdate> {
    match fork {
        Fork::Altair | Fork::Bellatrix => {
            let raw = RawLightClientUpdate::from_ssz_bytes(bytes).map_err(decode_err)?;
            Ok(raw_beacon_only_update_to_pub(fork, raw))
        }
        Fork::Capella => {
            let raw = RawCapellaLightClientUpdate::from_ssz_bytes(bytes).map_err(decode_err)?;
            Ok(raw_capella_update_to_pub(raw))
        }
        Fork::Deneb | Fork::Electra => Err(unsupported(fork)),
    }
}

pub(crate) fn decode_bootstrap(
    bytes: &[u8],
    fork: Fork,
    genesis_validators_root: Root,
) -> crate::error::Result<LightClientBootstrap> {
    match fork {
        Fork::Altair | Fork::Bellatrix => {
            let raw = RawLightClientBootstrap::from_ssz_bytes(bytes).map_err(decode_err)?;
            Ok(LightClientBootstrap::from_header(
                wrap_beacon_only(fork, raw.header),
                raw.current_sync_committee.into_sync_committee(),
                raw.current_sync_committee_branch.to_vec(),
                genesis_validators_root,
            ))
        }
        Fork::Capella => {
            let raw = RawCapellaLightClientBootstrap::from_ssz_bytes(bytes).map_err(decode_err)?;
            Ok(LightClientBootstrap::from_header(
                LightClientHeader::Capella(raw.header),
                raw.current_sync_committee.into_sync_committee(),
                raw.current_sync_committee_branch.to_vec(),
                genesis_validators_root,
            ))
        }
        Fork::Deneb | Fork::Electra => Err(unsupported(fork)),
    }
}

fn decode_err(e: ssz::DecodeError) -> crate::error::Error {
    crate::error::Error::Serialization(format!("SSZ decode: {e:?}"))
}

fn unsupported(fork: Fork) -> crate::error::Error {
    crate::error::Error::InvalidInput(format!(
        "SSZ decode not supported for {fork:?} (supported through Capella)"
    ))
}
