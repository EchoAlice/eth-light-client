//! Raw SSZ wire types and their conversions into the public light client types.
//!
//! These `Raw*` structs mirror the on-the-wire SSZ layout (decoded with
//! `ssz_rs`); the converters adapt them to the ergonomic public types. See the
//! crate README ("SSZ libraries") for why decode lives on `ssz_rs`, and issue
//! #69 for the eventual SSZ-native consolidation.

use crate::config::Fork;
use crate::types::consensus::{
    BeaconBlockHeader, ExecutionPayloadHeaderCapella, LightClientBootstrap, LightClientHeader,
    LightClientUpdate, SyncAggregate, SyncCommittee,
};
use crate::types::primitives::Root;
use ssz_rs::prelude::*;

#[derive(Default, SimpleSerialize)]
struct RawBeaconBlockHeader {
    slot: u64,
    proposer_index: u64,
    parent_root: Node,
    state_root: Node,
    body_root: Node,
}

impl RawBeaconBlockHeader {
    fn into_beacon_block_header(self) -> BeaconBlockHeader {
        BeaconBlockHeader::new(
            self.slot,
            self.proposer_index,
            node_to_root(&self.parent_root),
            node_to_root(&self.state_root),
            node_to_root(&self.body_root),
        )
    }
}

#[derive(Default, SimpleSerialize)]
pub(crate) struct RawLightClientHeader {
    beacon: RawBeaconBlockHeader,
}

#[derive(Default, SimpleSerialize)]
pub(crate) struct RawLightClientBootstrap {
    pub(crate) header: RawLightClientHeader,
    pub(crate) current_sync_committee: RawSyncCommittee,
    pub(crate) current_sync_committee_branch: Vector<Node, 5>,
}

#[derive(Default, SimpleSerialize)]
pub(crate) struct RawSyncCommittee {
    pubkeys: Vector<Vector<u8, 48>, 32>,
    aggregate_pubkey: Vector<u8, 48>,
}

impl RawSyncCommittee {
    pub(crate) fn into_sync_committee(self) -> SyncCommittee {
        // Minimal fixtures hold 32 pubkeys; production is mainnet-sized (512).
        // Padding is inert: root + signature checks read only pubkeys[..N] (N from ChainSpec).
        // The 32-element count is guaranteed by the SSZ `Vector<_, 32>` decode.
        let mut pubkeys_array = Box::new([[0u8; 48]; 512]);
        for (i, pk) in self.pubkeys.iter().enumerate() {
            let mut key = [0u8; 48];
            key.copy_from_slice(pk.as_ref());
            pubkeys_array[i] = key;
        }

        let mut aggregate = [0u8; 48];
        aggregate.copy_from_slice(self.aggregate_pubkey.as_ref());

        SyncCommittee::new(pubkeys_array, aggregate)
    }
}

#[derive(Default, SimpleSerialize)]
struct RawSyncAggregate {
    sync_committee_bits: Bitvector<32>,
    sync_committee_signature: Vector<u8, 96>,
}

impl RawSyncAggregate {
    fn into_sync_aggregate(self) -> SyncAggregate {
        let mut bits_array = Box::new([false; 512]);
        for (i, bit) in self.sync_committee_bits.iter().enumerate() {
            bits_array[i] = *bit;
        }

        let mut signature = [0u8; 96];
        signature.copy_from_slice(self.sync_committee_signature.as_ref());

        SyncAggregate::new(bits_array, signature)
    }
}

// Altair/Bellatrix update (beacon-only headers)
#[derive(Default, SimpleSerialize)]
pub(crate) struct RawLightClientUpdate {
    attested_header: RawLightClientHeader,
    next_sync_committee: RawSyncCommittee,
    next_sync_committee_branch: Vector<Node, 5>,
    finalized_header: RawLightClientHeader,
    finality_branch: Vector<Node, 6>,
    sync_aggregate: RawSyncAggregate,
    signature_slot: u64,
}

#[derive(Default, SimpleSerialize)]
struct RawExecutionPayloadHeader {
    parent_hash: Node,
    fee_recipient: Vector<u8, 20>,
    state_root: Node,
    receipts_root: Node,
    logs_bloom: Vector<u8, 256>,
    prev_randao: Node,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: List<u8, 32>,
    base_fee_per_gas: ssz_rs::U256,
    block_hash: Node,
    transactions_root: Node,
    withdrawals_root: Node,
}

impl RawExecutionPayloadHeader {
    fn into_execution_payload_header(self) -> crate::error::Result<ExecutionPayloadHeaderCapella> {
        let mut fee_recipient = [0u8; 20];
        fee_recipient.copy_from_slice(self.fee_recipient.as_ref());

        // ssz_rs::U256 -> ethereum_types::U256 via LE bytes.
        let le_bytes = self.base_fee_per_gas.to_bytes_le();
        let mut u256_bytes = [0u8; 32];
        let len = le_bytes.len().min(32);
        u256_bytes[..len].copy_from_slice(&le_bytes[..len]);

        let logs_bloom = ssz_types::FixedVector::new(self.logs_bloom.as_ref().to_vec())
            .map_err(|e| crate::error::Error::Serialization(format!("logs_bloom: {e:?}")))?;
        let extra_data = ssz_types::VariableList::new(self.extra_data.to_vec())
            .map_err(|e| crate::error::Error::Serialization(format!("extra_data: {e:?}")))?;

        Ok(ExecutionPayloadHeaderCapella {
            parent_hash: node_to_root(&self.parent_hash),
            fee_recipient: ethereum_types::H160(fee_recipient),
            state_root: node_to_root(&self.state_root),
            receipts_root: node_to_root(&self.receipts_root),
            logs_bloom,
            prev_randao: node_to_root(&self.prev_randao),
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data,
            base_fee_per_gas: ethereum_types::U256::from_little_endian(&u256_bytes),
            block_hash: node_to_root(&self.block_hash),
            transactions_root: node_to_root(&self.transactions_root),
            withdrawals_root: node_to_root(&self.withdrawals_root),
        })
    }
}

#[derive(Default, SimpleSerialize)]
pub(crate) struct RawCapellaLightClientHeader {
    beacon: RawBeaconBlockHeader,
    execution: RawExecutionPayloadHeader,
    execution_branch: Vector<Node, 4>,
}

#[derive(Default, SimpleSerialize)]
pub(crate) struct RawCapellaLightClientBootstrap {
    pub(crate) header: RawCapellaLightClientHeader,
    pub(crate) current_sync_committee: RawSyncCommittee,
    pub(crate) current_sync_committee_branch: Vector<Node, 5>,
}

#[derive(Default, SimpleSerialize)]
pub(crate) struct RawCapellaLightClientUpdate {
    attested_header: RawCapellaLightClientHeader,
    next_sync_committee: RawSyncCommittee,
    next_sync_committee_branch: Vector<Node, 5>,
    finalized_header: RawCapellaLightClientHeader,
    finality_branch: Vector<Node, 6>,
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

pub(crate) fn raw_capella_header_to_pub(
    raw: RawCapellaLightClientHeader,
) -> crate::error::Result<LightClientHeader> {
    let beacon = raw.beacon.into_beacon_block_header();
    let execution = raw.execution.into_execution_payload_header()?;
    let mut execution_branch = [[0u8; 32]; 4];
    for (i, node) in raw.execution_branch.iter().enumerate() {
        execution_branch[i] = node_to_root(node);
    }
    Ok(LightClientHeader::capella(
        beacon,
        execution,
        execution_branch,
    ))
}

/// Copy a 32-byte SSZ node into a `Root`.
fn node_to_root(node: &Node) -> Root {
    let mut root = [0u8; 32];
    root.copy_from_slice(node.as_ref());
    root
}

/// Convert a branch of SSZ nodes into `Root`s.
pub(crate) fn nodes_to_roots(nodes: &[Node]) -> Vec<Root> {
    nodes.iter().map(node_to_root).collect()
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
        .pubkeys
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
    let finality_branch = nodes_to_roots(&raw.finality_branch);
    let next_sync_committee_branch = nodes_to_roots(&raw.next_sync_committee_branch);

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

pub(crate) fn raw_capella_update_to_pub(
    raw: RawCapellaLightClientUpdate,
) -> crate::error::Result<LightClientUpdate> {
    let sync_committee = raw.next_sync_committee.into_sync_committee();
    let sync_aggregate = raw.sync_aggregate.into_sync_aggregate();
    let finality_branch = nodes_to_roots(&raw.finality_branch);
    let next_sync_committee_branch = nodes_to_roots(&raw.next_sync_committee_branch);

    // A default (slot-0) finalized header means the update carries no finality.
    let finalized_header = if raw.finalized_header.beacon.slot != 0 {
        Some(raw_capella_header_to_pub(raw.finalized_header)?)
    } else {
        None
    };
    let attested_header = raw_capella_header_to_pub(raw.attested_header)?;

    Ok(assemble_update(
        attested_header,
        finalized_header,
        finality_branch,
        sync_committee,
        next_sync_committee_branch,
        sync_aggregate,
        raw.signature_slot,
    ))
}

// Fork-dispatched SSZ decode: raw bytes -> public type. `bytes` is raw SSZ (not
// snappy-framed). Fork selects the wire layout (SSZ is not self-describing).

pub(crate) fn decode_update(bytes: &[u8], fork: Fork) -> crate::error::Result<LightClientUpdate> {
    match fork {
        Fork::Altair | Fork::Bellatrix => {
            let raw = RawLightClientUpdate::deserialize(bytes).map_err(decode_err)?;
            Ok(raw_beacon_only_update_to_pub(fork, raw))
        }
        Fork::Capella => {
            let raw = RawCapellaLightClientUpdate::deserialize(bytes).map_err(decode_err)?;
            raw_capella_update_to_pub(raw)
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
            let raw = RawLightClientBootstrap::deserialize(bytes).map_err(decode_err)?;
            let sync_committee = raw.current_sync_committee.into_sync_committee();
            let branch = nodes_to_roots(&raw.current_sync_committee_branch);
            let header = raw_beacon_only_header_to_pub(fork, raw.header);
            Ok(LightClientBootstrap::from_header(
                header,
                sync_committee,
                branch,
                genesis_validators_root,
            ))
        }
        Fork::Capella => {
            let raw = RawCapellaLightClientBootstrap::deserialize(bytes).map_err(decode_err)?;
            let sync_committee = raw.current_sync_committee.into_sync_committee();
            let branch = nodes_to_roots(&raw.current_sync_committee_branch);
            let header = raw_capella_header_to_pub(raw.header)?;
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

fn decode_err(e: ssz_rs::DeserializeError) -> crate::error::Error {
    crate::error::Error::Serialization(format!("SSZ decode: {e:?}"))
}

fn unsupported(fork: Fork) -> crate::error::Error {
    crate::error::Error::InvalidInput(format!(
        "SSZ decode not supported for {fork:?} (supported through Capella)"
    ))
}
