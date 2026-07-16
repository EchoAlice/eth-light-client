use crate::config::{ChainSpec, Fork};
use crate::error::{Error, Result};
use crate::types::primitives::{BLSPublicKey, BLSSignature, Epoch, Root, Slot, ValidatorIndex};
use ethereum_types::{Address, U256};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::{U256 as BloomLen, U32, U4, U48, U512};
use ssz_types::{FixedVector, VariableList};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub type PubkeyBytes = FixedVector<u8, U48>;

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

    /// Compute the hash tree root of the beacon block header using TreeHash
    pub(crate) fn hash_tree_root(&self) -> Result<Root> {
        let hash256 = TreeHash::tree_hash_root(self);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash256.as_bytes());
        Ok(result)
    }

    /// Returns the epoch for this header's slot.
    pub fn epoch(&self, spec: &ChainSpec) -> Epoch {
        spec.slot_to_epoch(self.slot)
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
    // Future variants:
    // Electra(ElectraLightClientHeader),
    // Fulu(FuluLightClientHeader),
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
    pub execution: ExecutionPayloadHeaderCapella,
    pub execution_branch: FixedVector<Root, U4>,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct ExecutionPayloadHeaderCapella {
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

// TODO: Does this method make sense?
impl ExecutionPayloadHeaderCapella {
    /// SSZ `hash_tree_root` as a [`Root`] — thin wrapper over the derived
    /// [`TreeHash`] impl (the field-by-field merkleization is now generated).
    pub(crate) fn hash_tree_root(&self) -> Root {
        self.tree_hash_root().0
    }
}

#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct DenebLightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeaderDeneb,
    pub execution_branch: FixedVector<Root, U4>,
}
#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct ExecutionPayloadHeaderDeneb {
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

// TODO: Does this method make sense?
impl ExecutionPayloadHeaderDeneb {
    /// SSZ `hash_tree_root` as a [`Root`] — thin wrapper over the derived
    /// [`TreeHash`] impl.
    pub(crate) fn hash_tree_root(&self) -> Root {
        self.tree_hash_root().0
    }
}

impl LightClientHeader {
    // TODO: Does this method make sense?
    /// Wrap a `BeaconBlockHeader` as an Altair-era header.
    pub(crate) fn altair(beacon: BeaconBlockHeader) -> Self {
        Self::Altair(AltairLightClientHeader { beacon })
    }

    // TODO: Should we delete?
    /// Wrap a `BeaconBlockHeader` as a Bellatrix-era header.
    pub(crate) fn bellatrix(beacon: BeaconBlockHeader) -> Self {
        Self::Bellatrix(BellatrixLightClientHeader { beacon })
    }

    /// The inner `BeaconBlockHeader` (available for all forks).
    pub fn beacon(&self) -> &BeaconBlockHeader {
        match self {
            Self::Altair(h) => &h.beacon,
            Self::Bellatrix(h) => &h.beacon,
            Self::Capella(h) => &h.beacon,
            Self::Deneb(h) => &h.beacon,
        }
    }

    pub fn slot(&self) -> Slot {
        self.beacon().slot
    }

    pub fn state_root(&self) -> &Root {
        &self.beacon().state_root
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SyncCommittee {
    pubkeys: Vec<PubkeyBytes>,
    aggregate_pubkey: PubkeyBytes,
}

// Size-specific SSZ-native views used only to derive the committee root
// (`Vector[pubkey, N]`); the library does the merkleization, not hand-rolled.
#[derive(TreeHash)]
struct CommitteeRoot512 {
    pubkeys: FixedVector<PubkeyBytes, U512>,
    aggregate_pubkey: PubkeyBytes,
}
#[derive(TreeHash)]
struct CommitteeRoot32 {
    pubkeys: FixedVector<PubkeyBytes, U32>,
    aggregate_pubkey: PubkeyBytes,
}

// TODO: Should any of these methods be scoped to pub(crate)?
impl SyncCommittee {
    /// SSZ `hash_tree_root`, dispatched on the (spec-sized) committee length.
    pub(crate) fn hash_tree_root(&self) -> Root {
        let agg = self.aggregate_pubkey.clone();
        match self.pubkeys.len() {
            512 => {
                CommitteeRoot512 {
                    pubkeys: FixedVector::new(self.pubkeys.clone()).expect("len checked"),
                    aggregate_pubkey: agg,
                }
                .tree_hash_root()
                .0
            }
            32 => {
                CommitteeRoot32 {
                    pubkeys: FixedVector::new(self.pubkeys.clone()).expect("len checked"),
                    aggregate_pubkey: agg,
                }
                .tree_hash_root()
                .0
            }
            n => unreachable!("sync committee is 32 or 512 members, got {n}"),
        }
    }

    pub fn pubkeys(&self) -> &[PubkeyBytes] {
        &self.pubkeys
    }

    pub fn aggregate_pubkey(&self) -> &PubkeyBytes {
        &self.aggregate_pubkey
    }

    // TODO: Should this be here? can't users call pubkeys.len locally?
    pub fn len(&self) -> usize {
        self.pubkeys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pubkeys.is_empty()
    }

    /// 2/3 supermajority over the spec-sized committee.
    pub(crate) fn has_supermajority_participation(&self, participation_bits: &[bool]) -> bool {
        if participation_bits.len() != self.len() {
            return false;
        }
        let participants = participation_bits.iter().filter(|&&b| b).count();
        participants >= (self.len() * 2 / 3)
    }

    /// Bit-selected participating pubkeys as raw 48-byte keys (for BLS).
    pub(crate) fn participating_pubkeys(
        &self,
        participation_bits: &[bool],
    ) -> Result<Vec<BLSPublicKey>> {
        if participation_bits.len() != self.len() {
            return Err(Error::InvalidInput(
                "Participation bits length mismatch".to_string(),
            ));
        }
        let mut out = Vec::new();
        for (i, &bit) in participation_bits.iter().enumerate() {
            if bit {
                let mut key = [0u8; 48];
                key.copy_from_slice(&self.pubkeys[i]);
                out.push(key);
            }
        }
        Ok(out)
    }

    // TODO: Should this method be more explicitly named?
    /// Build a spec-sized committee (32 or 512 keys) from raw pubkey bytes.
    ///
    /// Enforces the `{32, 512}` size invariant at construction, so the size
    /// dispatch in [`hash_tree_root`](Self::hash_tree_root) is total.
    pub(crate) fn from_parts(
        pubkeys: Vec<BLSPublicKey>,
        aggregate_pubkey: BLSPublicKey,
    ) -> Result<Self> {
        if pubkeys.len() != 32 && pubkeys.len() != 512 {
            return Err(Error::InvalidInput(format!(
                "sync committee must have 32 or 512 members, got {}",
                pubkeys.len()
            )));
        }
        Ok(SyncCommittee {
            pubkeys: pubkeys
                .into_iter()
                .map(|pk| PubkeyBytes::new(pk.to_vec()).expect("48-byte pubkey"))
                .collect(),
            aggregate_pubkey: PubkeyBytes::new(aggregate_pubkey.to_vec()).expect("48-byte pubkey"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregate {
    pub sync_committee_bits: Vec<bool>,
    pub sync_committee_signature: BLSSignature,
}

impl SyncAggregate {
    pub fn new(sync_committee_bits: Vec<bool>, sync_committee_signature: BLSSignature) -> Self {
        Self {
            sync_committee_bits,
            sync_committee_signature,
        }
    }

    /// Check if sync aggregate has supermajority participation
    /// Uses actual committee size from the provided sync committee
    pub(crate) fn has_supermajority(&self, sync_committee: &SyncCommittee) -> bool {
        sync_committee.has_supermajority_participation(self.sync_committee_bits.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LightClientUpdate {
    pub attested_header: LightClientHeader,
    /// The finalized header and its finality branch — present together or not at all.
    pub finalized: Option<FinalityUpdate>,
    /// The next sync committee and its inclusion branch — present together or not at all.
    pub next_sync_committee: Option<SyncCommitteeUpdate>,
    pub sync_aggregate: SyncAggregate,
    /// Should be attested_header.slot + 1
    pub signature_slot: Slot,
}

/// A finalized header paired with the Merkle branch proving it in the attested state.
#[derive(Debug, Clone, PartialEq)]
pub struct FinalityUpdate {
    pub header: LightClientHeader,
    pub branch: Vec<Root>,
}

/// A next sync committee paired with the Merkle branch proving it in the attested state.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncCommitteeUpdate {
    pub committee: SyncCommittee,
    pub branch: Vec<Root>,
}

impl LightClientUpdate {
    pub fn from_ssz(bytes: &[u8], fork: Fork, sync_committee_size: usize) -> Result<Self> {
        crate::types::ssz::decode_update(bytes, fork, sync_committee_size)
    }

    /// Test builder: an Altair-wrapped update with no finality / next committee.
    #[cfg(test)]
    pub fn new(
        attested_header: BeaconBlockHeader,
        sync_aggregate: SyncAggregate,
        signature_slot: Slot,
    ) -> Self {
        Self {
            attested_header: LightClientHeader::altair(attested_header),
            finalized: None,
            next_sync_committee: None,
            sync_aggregate,
            signature_slot,
        }
    }

    #[cfg(test)]
    pub fn with_next_sync_committee(mut self, committee: SyncCommittee, branch: Vec<Root>) -> Self {
        self.next_sync_committee = Some(SyncCommitteeUpdate { committee, branch });
        self
    }

    /// Validate basic properties of the light client update.
    ///
    /// Enforces:
    /// - `signature_slot > attested_header.slot`
    /// - supermajority participation
    pub(crate) fn validate_basic(&self, sync_committee: &SyncCommittee) -> Result<()> {
        if self.signature_slot <= self.attested_header.slot() {
            return Err(Error::InvalidInput(
                "Signature slot must be after attested header slot".to_string(),
            ));
        }

        if !self.sync_aggregate.has_supermajority(sync_committee) {
            return Err(Error::InvalidInput(
                "Insufficient sync committee participation".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if this update contains sync committee changes
    pub(crate) fn has_sync_committee_update(&self) -> bool {
        self.next_sync_committee.is_some()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LightClientBootstrap {
    pub header: LightClientHeader,
    pub current_sync_committee: SyncCommittee,
    pub current_sync_committee_branch: Vec<Root>,
    pub genesis_validators_root: Root,
}

impl LightClientBootstrap {
    pub fn from_ssz(
        bytes: &[u8],
        fork: Fork,
        sync_committee_size: usize,
        genesis_validators_root: Root,
    ) -> Result<Self> {
        crate::types::ssz::decode_bootstrap(
            bytes,
            fork,
            sync_committee_size,
            genesis_validators_root,
        )
    }

    /// Assemble a bootstrap from a fork-aware [`LightClientHeader`] (used by decode).
    pub(crate) fn from_header(
        header: LightClientHeader,
        current_sync_committee: SyncCommittee,
        current_sync_committee_branch: Vec<Root>,
        genesis_validators_root: Root,
    ) -> Self {
        Self {
            header,
            current_sync_committee,
            current_sync_committee_branch,
            genesis_validators_root,
        }
    }
}

/// Light client store maintaining the trusted state.
///
/// This is the persistent state that a light client maintains across updates.
/// It includes the trusted headers, sync committees, and chain identity.
/// Headers are fork-aware [`LightClientHeader`] values.
#[derive(Debug, Clone)]
pub(crate) struct LightClientStore {
    pub finalized_header: LightClientHeader,
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: Option<SyncCommittee>,
    pub optimistic_header: LightClientHeader,
    pub genesis_validators_root: Root,
}

impl LightClientStore {
    pub fn new(
        finalized_header: LightClientHeader,
        current_sync_committee: SyncCommittee,
        genesis_validators_root: Root,
    ) -> Self {
        Self {
            optimistic_header: finalized_header.clone(),
            finalized_header,
            current_sync_committee,
            next_sync_committee: None,
            genesis_validators_root,
        }
    }

    /// Get the sync committee period derived from the finalized header.
    ///
    /// This is the canonical "store period" per consensus-specs.
    pub(crate) fn finalized_sync_committee_period(&self, spec: &ChainSpec) -> u64 {
        spec.slot_to_sync_committee_period(self.finalized_header.slot())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_beacon_header() -> BeaconBlockHeader {
        BeaconBlockHeader::new(
            1000,      // slot
            42,        // proposer_index
            [1u8; 32], // parent_root
            [2u8; 32], // state_root
            [3u8; 32], // body_root
        )
    }

    fn create_test_sync_committee() -> SyncCommittee {
        SyncCommittee::from_parts(vec![[1u8; 48]; 32], [2u8; 48]).unwrap()
    }

    #[test]
    fn test_sync_committee_supermajority() {
        let committee = create_test_sync_committee();
        let threshold = 32 * 2 / 3; // 21 of 32

        // Exactly 2/3 passes.
        let mut participation = vec![false; 32];
        participation
            .iter_mut()
            .take(threshold)
            .for_each(|p| *p = true);
        assert!(committee.has_supermajority_participation(&participation));

        // One below 2/3 fails.
        let mut participation = vec![false; 32];
        participation
            .iter_mut()
            .take(threshold - 1)
            .for_each(|p| *p = true);
        assert!(!committee.has_supermajority_participation(&participation));

        // Full participation passes.
        assert!(committee.has_supermajority_participation(&[true; 32]));
    }

    #[test]
    fn test_light_client_update_validation() {
        let attested_header = create_test_beacon_header();
        let sync_committee_bits = vec![true; 32]; // Full participation
        let sync_committee_signature = [1u8; 96];
        let sync_aggregate = SyncAggregate::new(sync_committee_bits, sync_committee_signature);

        let update = LightClientUpdate::new(
            attested_header,
            sync_aggregate,
            1001, // signature_slot must be > attested_header.slot
        );

        let sync_committee = create_test_sync_committee();
        assert!(update.validate_basic(&sync_committee).is_ok());
        assert!(update.finalized.is_none());
        assert!(!update.has_sync_committee_update());
    }

    #[test]
    fn test_light_client_store() {
        let spec = ChainSpec::mainnet();
        let finalized_header = create_test_beacon_header();
        let sync_committee = create_test_sync_committee();
        let genesis_validators_root = [0u8; 32];

        let store = LightClientStore::new(
            LightClientHeader::altair(finalized_header),
            sync_committee,
            genesis_validators_root,
        );
        // slot 1000 -> epoch 31 -> period 0
        assert_eq!(store.finalized_sync_committee_period(&spec), 0);
        assert_eq!(store.genesis_validators_root, genesis_validators_root);
    }
}
