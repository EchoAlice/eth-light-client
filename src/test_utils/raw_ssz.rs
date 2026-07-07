//! Raw SSZ fixture types and their conversions into production light client types.

use super::TestFork;
use crate::types::consensus::{
    BeaconBlockHeader, ExecutionPayloadHeaderCapella, LightClientHeader, LightClientUpdate,
    SyncAggregate, SyncCommittee,
};
use crate::types::primitives::{Bloom, ExtraData, Root};
use ssz_rs::prelude::*;

#[derive(Debug, Clone, Default, SimpleSerialize)]
pub(crate) struct RawBeaconBlockHeader {
    slot: u64,
    proposer_index: u64,
    parent_root: Node,
    state_root: Node,
    body_root: Node,
}

impl RawBeaconBlockHeader {
    pub(crate) fn into_beacon_block_header(self) -> BeaconBlockHeader {
        let mut parent_root = [0u8; 32];
        parent_root.copy_from_slice(self.parent_root.as_ref());
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(self.state_root.as_ref());
        let mut body_root = [0u8; 32];
        body_root.copy_from_slice(self.body_root.as_ref());

        BeaconBlockHeader::new(
            self.slot,
            self.proposer_index,
            parent_root,
            state_root,
            body_root,
        )
    }
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
pub(crate) struct RawLightClientHeader {
    pub(crate) beacon: RawBeaconBlockHeader,
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
pub(crate) struct RawLightClientBootstrap {
    pub(crate) header: RawLightClientHeader,
    pub(crate) current_sync_committee: RawSyncCommittee,
    pub(crate) current_sync_committee_branch: Vector<Node, 5>,
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
pub(crate) struct RawSyncCommittee {
    pubkeys: Vector<Vector<u8, 48>, 32>,
    aggregate_pubkey: Vector<u8, 48>,
}

impl RawSyncCommittee {
    pub(crate) fn to_sync_committee(&self) -> Result<SyncCommittee, String> {
        if self.pubkeys.len() != 32 {
            return Err(format!(
                "Expected 32 pubkeys (minimal preset), got {}",
                self.pubkeys.len()
            ));
        }

        let mut pubkeys_array = Box::new([[0u8; 48]; 512]);
        for (i, pk) in self.pubkeys.iter().enumerate() {
            let mut key = [0u8; 48];
            key.copy_from_slice(pk.as_ref());
            pubkeys_array[i] = key;
        }

        let mut aggregate = [0u8; 48];
        aggregate.copy_from_slice(self.aggregate_pubkey.as_ref());

        Ok(SyncCommittee::new(pubkeys_array, aggregate))
    }
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
struct RawSyncAggregate {
    sync_committee_bits: Bitvector<32>,
    sync_committee_signature: Vector<u8, 96>,
}

impl RawSyncAggregate {
    fn into_sync_aggregate(self) -> Result<SyncAggregate, String> {
        let mut bits_array = Box::new([false; 512]);
        for (i, bit) in self.sync_committee_bits.iter().enumerate() {
            bits_array[i] = *bit;
        }

        let mut signature = [0u8; 96];
        signature.copy_from_slice(self.sync_committee_signature.as_ref());

        Ok(SyncAggregate::new(bits_array, signature))
    }
}

// Altair/Bellatrix update (beacon-only headers)
#[derive(Debug, Clone, Default, SimpleSerialize)]
pub(crate) struct RawLightClientUpdate {
    attested_header: RawLightClientHeader,
    next_sync_committee: RawSyncCommittee,
    next_sync_committee_branch: Vector<Node, 5>,
    finalized_header: RawLightClientHeader,
    finality_branch: Vector<Node, 6>,
    sync_aggregate: RawSyncAggregate,
    signature_slot: u64,
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
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
    fn into_execution_payload_header(self) -> Result<ExecutionPayloadHeaderCapella, String> {
        fn node_to_root(n: &Node) -> [u8; 32] {
            let mut r = [0u8; 32];
            r.copy_from_slice(n.as_ref());
            r
        }

        let mut fee_recipient = [0u8; 20];
        fee_recipient.copy_from_slice(self.fee_recipient.as_ref());

        let mut bloom_bytes = [0u8; 256];
        bloom_bytes.copy_from_slice(self.logs_bloom.as_ref());

        // Convert ssz_rs::U256 to ruint::U256 via LE bytes
        let le_bytes = self.base_fee_per_gas.to_bytes_le();
        let mut u256_bytes = [0u8; 32];
        let len = le_bytes.len().min(32);
        u256_bytes[..len].copy_from_slice(&le_bytes[..len]);
        let base_fee = ruint::aliases::U256::from_le_bytes(u256_bytes);

        let extra_data_vec: Vec<u8> = self.extra_data.to_vec();
        let extra_data = ExtraData::try_new(extra_data_vec).map_err(|e| e.to_string())?;

        Ok(ExecutionPayloadHeaderCapella {
            parent_hash: node_to_root(&self.parent_hash),
            fee_recipient,
            state_root: node_to_root(&self.state_root),
            receipts_root: node_to_root(&self.receipts_root),
            logs_bloom: Bloom(bloom_bytes),
            prev_randao: node_to_root(&self.prev_randao),
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data,
            base_fee_per_gas: base_fee,
            block_hash: node_to_root(&self.block_hash),
            transactions_root: node_to_root(&self.transactions_root),
            withdrawals_root: node_to_root(&self.withdrawals_root),
        })
    }
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
pub(crate) struct RawCapellaLightClientHeader {
    beacon: RawBeaconBlockHeader,
    execution: RawExecutionPayloadHeader,
    execution_branch: Vector<Node, 4>,
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
pub(crate) struct RawCapellaLightClientBootstrap {
    pub(crate) header: RawCapellaLightClientHeader,
    pub(crate) current_sync_committee: RawSyncCommittee,
    pub(crate) current_sync_committee_branch: Vector<Node, 5>,
}

#[derive(Debug, Clone, Default, SimpleSerialize)]
pub(crate) struct RawCapellaLightClientUpdate {
    attested_header: RawCapellaLightClientHeader,
    next_sync_committee: RawSyncCommittee,
    next_sync_committee_branch: Vector<Node, 5>,
    finalized_header: RawCapellaLightClientHeader,
    finality_branch: Vector<Node, 6>,
    sync_aggregate: RawSyncAggregate,
    signature_slot: u64,
}

pub(crate) fn raw_capella_header_to_pub(
    raw: &RawCapellaLightClientHeader,
) -> Result<LightClientHeader, String> {
    let beacon = raw.beacon.clone().into_beacon_block_header();
    let execution = raw.execution.clone().into_execution_payload_header()?;
    let mut execution_branch = [[0u8; 32]; 4];
    for (i, node) in raw.execution_branch.iter().enumerate() {
        execution_branch[i].copy_from_slice(node.as_ref());
    }
    Ok(LightClientHeader::capella(
        beacon,
        execution,
        execution_branch,
    ))
}

pub(crate) fn raw_capella_update_to_pub(
    raw: RawCapellaLightClientUpdate,
) -> Result<LightClientUpdate, String> {
    let sync_committee = raw.next_sync_committee.to_sync_committee()?;
    let sync_aggregate = raw.sync_aggregate.into_sync_aggregate()?;

    let has_sync_committee = !sync_committee
        .pubkeys
        .iter()
        .all(|pk| pk.iter().all(|&b| b == 0));

    let finality_branch: Vec<[u8; 32]> = raw
        .finality_branch
        .iter()
        .map(|node| {
            let mut root = [0u8; 32];
            root.copy_from_slice(node.as_ref());
            root
        })
        .collect();

    let next_sync_committee_branch: Vec<[u8; 32]> = raw
        .next_sync_committee_branch
        .iter()
        .map(|node| {
            let mut root = [0u8; 32];
            root.copy_from_slice(node.as_ref());
            root
        })
        .collect();

    // A default finalized header (slot=0) means no finality update.
    let has_finality = raw.finalized_header.beacon.slot != 0;
    let finalized_header = if has_finality {
        Some(raw_capella_header_to_pub(&raw.finalized_header)?)
    } else {
        None
    };

    Ok(LightClientUpdate {
        attested_header: raw_capella_header_to_pub(&raw.attested_header)?,
        finalized_header,
        finality_branch: if has_finality {
            finality_branch
        } else {
            Vec::new()
        },
        next_sync_committee: if has_sync_committee {
            Some(sync_committee)
        } else {
            None
        },
        next_sync_committee_branch: if has_sync_committee {
            next_sync_committee_branch
        } else {
            Vec::new()
        },
        sync_aggregate,
        signature_slot: raw.signature_slot,
    })
}

impl RawLightClientUpdate {
    pub(crate) fn into_light_client_update(
        self,
        fork: TestFork,
    ) -> Result<LightClientUpdate, String> {
        let sync_committee = self.next_sync_committee.to_sync_committee()?;
        let sync_aggregate = self.sync_aggregate.into_sync_aggregate()?;

        let has_sync_committee = !sync_committee
            .pubkeys
            .iter()
            .all(|pk| pk.iter().all(|&b| b == 0));

        let finality_branch: Vec<Root> = self
            .finality_branch
            .iter()
            .map(|node| {
                let mut root = [0u8; 32];
                root.copy_from_slice(node.as_ref());
                root
            })
            .collect();

        let next_sync_committee_branch: Vec<Root> = self
            .next_sync_committee_branch
            .iter()
            .map(|node| {
                let mut root = [0u8; 32];
                root.copy_from_slice(node.as_ref());
                root
            })
            .collect();

        Ok(LightClientUpdate {
            attested_header: fork
                .wrap_header(self.attested_header.beacon.into_beacon_block_header()),
            finalized_header: Some(
                fork.wrap_header(self.finalized_header.beacon.into_beacon_block_header()),
            ),
            finality_branch,
            next_sync_committee: if has_sync_committee {
                Some(sync_committee)
            } else {
                None
            },
            next_sync_committee_branch: if has_sync_committee {
                next_sync_committee_branch
            } else {
                Vec::new()
            },
            sync_aggregate,
            signature_slot: self.signature_slot,
        })
    }
}
