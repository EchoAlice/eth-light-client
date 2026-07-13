//! SSZ wire types and their conversions into the public light client types.
//!
//! These `Raw*` structs mirror the on-the-wire SSZ layout and decode via
//! `ethereum_ssz` (the crate's single SSZ implementation). The converters adapt
//! them to the ergonomic public types — fork-enum headers, `Option` fields, and
//! the spec-sized committee — applying the spec's optional-field rules.
//!
//! The mirror is minimal-preset only: it decodes 32-key committees. Mainnet
//! committee decode is not yet wired.

use crate::config::Fork;
use crate::types::consensus::{
    BeaconBlockHeader, ExecutionPayloadHeaderCapella, LightClientBootstrap, LightClientHeader,
    LightClientUpdate, SyncAggregate, SyncCommittee,
};
use crate::types::primitives::Root;
use ssz::Decode as _;
use ssz_derive::Decode;
use ssz_types::typenum::{U20, U256 as BloomBytes, U32, U4, U48, U5, U6, U96};
use ssz_types::{BitVector, FixedVector, VariableList};

#[derive(Decode)]
struct RawBeaconBlockHeader {
    slot: u64,
    proposer_index: u64,
    parent_root: Root,
    state_root: Root,
    body_root: Root,
}

impl RawBeaconBlockHeader {
    fn into_beacon_block_header(self) -> BeaconBlockHeader {
        BeaconBlockHeader::new(
            self.slot,
            self.proposer_index,
            self.parent_root,
            self.state_root,
            self.body_root,
        )
    }
}

#[derive(Decode)]
pub(crate) struct RawLightClientHeader {
    beacon: RawBeaconBlockHeader,
}

#[derive(Decode)]
pub(crate) struct RawLightClientBootstrap {
    pub(crate) header: RawLightClientHeader,
    pub(crate) current_sync_committee: RawSyncCommittee,
    pub(crate) current_sync_committee_branch: FixedVector<Root, U5>,
}

#[derive(Decode)]
pub(crate) struct RawSyncCommittee {
    pubkeys: FixedVector<FixedVector<u8, U48>, U32>,
    aggregate_pubkey: FixedVector<u8, U48>,
}

impl RawSyncCommittee {
    pub(crate) fn into_sync_committee(self) -> SyncCommittee {
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

// Altair/Bellatrix update (beacon-only headers)
#[derive(Decode)]
pub(crate) struct RawLightClientUpdate {
    attested_header: RawLightClientHeader,
    next_sync_committee: RawSyncCommittee,
    next_sync_committee_branch: FixedVector<Root, U5>,
    finalized_header: RawLightClientHeader,
    finality_branch: FixedVector<Root, U6>,
    sync_aggregate: RawSyncAggregate,
    signature_slot: u64,
}

#[derive(Decode)]
struct RawExecutionPayloadHeader {
    parent_hash: Root,
    fee_recipient: FixedVector<u8, U20>,
    state_root: Root,
    receipts_root: Root,
    logs_bloom: FixedVector<u8, BloomBytes>,
    prev_randao: Root,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: VariableList<u8, U32>,
    base_fee_per_gas: ethereum_types::U256,
    block_hash: Root,
    transactions_root: Root,
    withdrawals_root: Root,
}

impl RawExecutionPayloadHeader {
    fn into_execution_payload_header(self) -> ExecutionPayloadHeaderCapella {
        let mut fee_recipient = [0u8; 20];
        fee_recipient.copy_from_slice(self.fee_recipient.as_ref());

        ExecutionPayloadHeaderCapella {
            parent_hash: self.parent_hash,
            fee_recipient: ethereum_types::H160(fee_recipient),
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom,
            prev_randao: self.prev_randao,
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data,
            base_fee_per_gas: self.base_fee_per_gas,
            block_hash: self.block_hash,
            transactions_root: self.transactions_root,
            withdrawals_root: self.withdrawals_root,
        }
    }
}

#[derive(Decode)]
pub(crate) struct RawCapellaLightClientHeader {
    beacon: RawBeaconBlockHeader,
    execution: RawExecutionPayloadHeader,
    execution_branch: FixedVector<Root, U4>,
}

#[derive(Decode)]
pub(crate) struct RawCapellaLightClientBootstrap {
    pub(crate) header: RawCapellaLightClientHeader,
    pub(crate) current_sync_committee: RawSyncCommittee,
    pub(crate) current_sync_committee_branch: FixedVector<Root, U5>,
}

#[derive(Decode)]
pub(crate) struct RawCapellaLightClientUpdate {
    attested_header: RawCapellaLightClientHeader,
    next_sync_committee: RawSyncCommittee,
    next_sync_committee_branch: FixedVector<Root, U5>,
    finalized_header: RawCapellaLightClientHeader,
    finality_branch: FixedVector<Root, U6>,
    sync_aggregate: RawSyncAggregate,
    signature_slot: u64,
}

/// Convert a beacon-only fixture header into the matching production
/// `LightClientHeader` variant. Only valid for Altair/Bellatrix.
pub(crate) fn raw_beacon_only_header_to_pub(
    fork: Fork,
    raw: RawLightClientHeader,
) -> LightClientHeader {
    let beacon = raw.beacon.into_beacon_block_header();
    match fork {
        Fork::Altair => LightClientHeader::altair(beacon),
        Fork::Bellatrix => LightClientHeader::bellatrix(beacon),
        Fork::Capella | Fork::Deneb | Fork::Electra => {
            unreachable!("beacon-only converter called for {fork:?}")
        }
    }
}

pub(crate) fn raw_capella_header_to_pub(raw: RawCapellaLightClientHeader) -> LightClientHeader {
    let beacon = raw.beacon.into_beacon_block_header();
    let execution = raw.execution.into_execution_payload_header();
    let mut execution_branch = [[0u8; 32]; 4];
    for (i, node) in raw.execution_branch.iter().enumerate() {
        execution_branch[i] = *node;
    }
    LightClientHeader::capella(beacon, execution, execution_branch)
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

pub(crate) fn raw_beacon_only_update_to_pub(
    fork: Fork,
    raw: RawLightClientUpdate,
) -> LightClientUpdate {
    let sync_committee = raw.next_sync_committee.into_sync_committee();
    let sync_aggregate = raw.sync_aggregate.into_sync_aggregate();
    let finality_branch = raw.finality_branch.to_vec();
    let next_sync_committee_branch = raw.next_sync_committee_branch.to_vec();

    // A default (slot-0) finalized header means the update carries no finality.
    let finalized_header = if raw.finalized_header.beacon.slot != 0 {
        Some(raw_beacon_only_header_to_pub(fork, raw.finalized_header))
    } else {
        None
    };
    let attested_header = raw_beacon_only_header_to_pub(fork, raw.attested_header);

    assemble_update(
        attested_header,
        finalized_header,
        finality_branch,
        sync_committee,
        next_sync_committee_branch,
        sync_aggregate,
        raw.signature_slot,
    )
}

pub(crate) fn raw_capella_update_to_pub(raw: RawCapellaLightClientUpdate) -> LightClientUpdate {
    let sync_committee = raw.next_sync_committee.into_sync_committee();
    let sync_aggregate = raw.sync_aggregate.into_sync_aggregate();
    let finality_branch = raw.finality_branch.to_vec();
    let next_sync_committee_branch = raw.next_sync_committee_branch.to_vec();

    // A default (slot-0) finalized header means the update carries no finality.
    let finalized_header = if raw.finalized_header.beacon.slot != 0 {
        Some(raw_capella_header_to_pub(raw.finalized_header))
    } else {
        None
    };
    let attested_header = raw_capella_header_to_pub(raw.attested_header);

    assemble_update(
        attested_header,
        finalized_header,
        finality_branch,
        sync_committee,
        next_sync_committee_branch,
        sync_aggregate,
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
            let sync_committee = raw.current_sync_committee.into_sync_committee();
            let branch = raw.current_sync_committee_branch.to_vec();
            let header = raw_beacon_only_header_to_pub(fork, raw.header);
            Ok(LightClientBootstrap::from_header(
                header,
                sync_committee,
                branch,
                genesis_validators_root,
            ))
        }
        Fork::Capella => {
            let raw = RawCapellaLightClientBootstrap::from_ssz_bytes(bytes).map_err(decode_err)?;
            let sync_committee = raw.current_sync_committee.into_sync_committee();
            let branch = raw.current_sync_committee_branch.to_vec();
            let header = raw_capella_header_to_pub(raw.header);
            Ok(LightClientBootstrap::from_header(
                header,
                sync_committee,
                branch,
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
