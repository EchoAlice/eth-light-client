use alloy_primitives::{Address, U256};
use ssz_derive::Decode;
use ssz_types::typenum::{U256 as BloomLen, U32, U4};
use ssz_types::{FixedVector, VariableList};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::chain_spec::Fork;
use crate::types::primitives::{Root, Slot, ValidatorIndex};

#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Decode)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    pub state_root: Root,
    pub body_root: Root,
}

impl BeaconBlockHeader {
    pub(crate) fn hash_tree_root(&self) -> Root {
        TreeHash::tree_hash_root(self).0
    }
}

/// Verification logic accesses the inner `BeaconBlockHeader` through [`beacon()`](Self::beacon), keeping the pipeline fork-agnostic.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum LightClientHeader {
    Altair(AltairLightClientHeader),
    Bellatrix(BellatrixLightClientHeader),
    Capella(CapellaLightClientHeader),
    Deneb(DenebLightClientHeader),
    Electra(ElectraLightClientHeader),
    Fulu(FuluLightClientHeader),
}

impl LightClientHeader {
    pub fn beacon(&self) -> &BeaconBlockHeader {
        match self {
            Self::Altair(h) => &h.beacon,
            Self::Bellatrix(h) => &h.beacon,
            Self::Capella(h) => &h.beacon,
            Self::Deneb(h) => &h.beacon,
            Self::Electra(h) => &h.beacon,
            Self::Fulu(h) => &h.beacon,
        }
    }

    /// Returns the slot the beacon block was proposed in, not the signature slot.
    pub fn slot(&self) -> Slot {
        self.beacon().slot
    }

    pub fn state_root(&self) -> &Root {
        &self.beacon().state_root
    }

    pub fn fork(&self) -> Fork {
        match self {
            Self::Altair(_) => Fork::Altair,
            Self::Bellatrix(_) => Fork::Bellatrix,
            Self::Capella(_) => Fork::Capella,
            Self::Deneb(_) => Fork::Deneb,
            Self::Electra(_) => Fork::Electra,
            Self::Fulu(_) => Fork::Fulu,
        }
    }

    pub fn execution_state_root(&self) -> Option<Root> {
        match self {
            Self::Altair(_) | Self::Bellatrix(_) => None,
            Self::Capella(h) => Some(h.execution.state_root),
            Self::Deneb(h) => Some(h.execution.state_root),
            Self::Electra(h) => Some(h.execution.state_root),
            Self::Fulu(h) => Some(h.execution.state_root),
        }
    }

    pub(crate) fn execution_payload_root(&self) -> Root {
        match self {
            Self::Altair(_) | Self::Bellatrix(_) => {
                unreachable!("Pre-Capella containers don't carry an execution header.")
            }
            Self::Capella(h) => h.execution.hash_tree_root(),
            Self::Deneb(h) => h.execution.hash_tree_root(),
            Self::Electra(h) => h.execution.hash_tree_root(),
            Self::Fulu(h) => h.execution.hash_tree_root(),
        }
    }

    pub(crate) fn execution_branch(&self) -> &[Root] {
        match self {
            Self::Altair(_) | Self::Bellatrix(_) => {
                unreachable!("Pre-Capella containers don't carry an execution branch.")
            }
            Self::Capella(h) => &h.execution_branch,
            Self::Deneb(h) => &h.execution_branch,
            Self::Electra(h) => &h.execution_branch,
            Self::Fulu(h) => &h.execution_branch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Decode)]
pub struct AltairLightClientHeader {
    pub beacon: BeaconBlockHeader,
}

#[derive(Debug, Clone, PartialEq, Decode)]
pub struct BellatrixLightClientHeader {
    pub beacon: BeaconBlockHeader,
}

#[derive(Debug, Clone, PartialEq, Decode)]
pub struct CapellaLightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: CapellaExecutionPayloadHeader,
    pub execution_branch: FixedVector<Root, U4>,
}

#[derive(Debug, Clone, PartialEq, Decode, TreeHash)]
pub struct CapellaExecutionPayloadHeader {
    pub parent_hash: Root,
    pub fee_recipient: Address,
    pub state_root: Root,
    pub receipts_root: Root,
    pub logs_bloom: FixedVector<u8, BloomLen>,
    pub prev_randao: Root,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: VariableList<u8, U32>,
    pub base_fee_per_gas: U256,
    pub block_hash: Root,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
}

impl CapellaExecutionPayloadHeader {
    pub(crate) fn hash_tree_root(&self) -> Root {
        self.tree_hash_root().0
    }
}

#[derive(Debug, Clone, PartialEq, Decode)]
pub struct DenebLightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: DenebExecutionPayloadHeader,
    pub execution_branch: FixedVector<Root, U4>,
}

#[derive(Debug, Clone, PartialEq, Decode, TreeHash)]
pub struct DenebExecutionPayloadHeader {
    pub parent_hash: Root,
    pub fee_recipient: Address,
    pub state_root: Root,
    pub receipts_root: Root,
    pub logs_bloom: FixedVector<u8, BloomLen>,
    pub prev_randao: Root,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: VariableList<u8, U32>,
    pub base_fee_per_gas: U256,
    pub block_hash: Root,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

impl DenebExecutionPayloadHeader {
    pub(crate) fn hash_tree_root(&self) -> Root {
        self.tree_hash_root().0
    }

    /// Spec: the Capella-era arm of `get_lc_execution_root`. A Capella block's
    /// `body_root` committed the 15-field header; this is that header.
    pub(crate) fn to_capella(&self) -> CapellaExecutionPayloadHeader {
        CapellaExecutionPayloadHeader {
            parent_hash: self.parent_hash,
            fee_recipient: self.fee_recipient,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom.clone(),
            prev_randao: self.prev_randao,
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data.clone(),
            base_fee_per_gas: self.base_fee_per_gas,
            block_hash: self.block_hash,
            transactions_root: self.transactions_root,
            withdrawals_root: self.withdrawals_root,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Decode)]
pub struct ElectraLightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: ElectraExecutionPayloadHeader,
    pub execution_branch: FixedVector<Root, U4>,
}

pub type ElectraExecutionPayloadHeader = DenebExecutionPayloadHeader;

#[derive(Debug, Clone, PartialEq, Decode)]
pub struct FuluLightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: FuluExecutionPayloadHeader,
    pub execution_branch: FixedVector<Root, U4>,
}

pub type FuluExecutionPayloadHeader = DenebExecutionPayloadHeader;
