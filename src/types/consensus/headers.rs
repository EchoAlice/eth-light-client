use crate::config::ChainSpec;
use crate::error::Result;
use crate::types::primitives::{Epoch, Root, Slot, ValidatorIndex};
use ethereum_types::{Address, U256};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::{U256 as BloomLen, U32, U4};
use ssz_types::{FixedVector, VariableList};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[derive(Debug, Clone, PartialEq, Eq, TreeHash, Encode, Decode)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    pub state_root: Root,
    pub body_root: Root,
}

impl BeaconBlockHeader {
    pub fn new(
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Root,
        state_root: Root,
        body_root: Root,
    ) -> Self {
        Self {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
        }
    }

    pub(crate) fn hash_tree_root(&self) -> Result<Root> {
        let hash256 = TreeHash::tree_hash_root(self);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash256.as_bytes());
        Ok(result)
    }

    pub fn epoch(&self, spec: &ChainSpec) -> Epoch {
        spec.slot_to_epoch(self.slot)
    }
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
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

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltairLightClientHeader {
    pub beacon: BeaconBlockHeader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BellatrixLightClientHeader {
    pub beacon: BeaconBlockHeader,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct CapellaLightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: CapellaExecutionPayloadHeader,
    pub execution_branch: FixedVector<Root, U4>,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct DenebLightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: DenebExecutionPayloadHeader,
    pub execution_branch: FixedVector<Root, U4>,
}

// Electra leaves the execution payload header unchanged from Deneb (the new
// execution-layer requests live in a separate BeaconBlockBody field, not the
// payload), and EXECUTION_PAYLOAD_GINDEX is unchanged, so the wire shape matches
// Deneb. What changes are the BeaconState branch lengths in the surrounding
// update/bootstrap containers (see ssz.rs), not this header.
#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct ElectraLightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: DenebExecutionPayloadHeader,
    pub execution_branch: FixedVector<Root, U4>,
}

impl LightClientHeader {
    pub(crate) fn altair(beacon: BeaconBlockHeader) -> Self {
        Self::Altair(AltairLightClientHeader { beacon })
    }

    pub(crate) fn bellatrix(beacon: BeaconBlockHeader) -> Self {
        Self::Bellatrix(BellatrixLightClientHeader { beacon })
    }

    pub fn beacon(&self) -> &BeaconBlockHeader {
        match self {
            Self::Altair(h) => &h.beacon,
            Self::Bellatrix(h) => &h.beacon,
            Self::Capella(h) => &h.beacon,
            Self::Deneb(h) => &h.beacon,
            Self::Electra(h) => &h.beacon,
        }
    }

    pub fn slot(&self) -> Slot {
        self.beacon().slot
    }

    pub fn state_root(&self) -> &Root {
        &self.beacon().state_root
    }
}
