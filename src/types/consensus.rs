use crate::config::{ChainSpec, Fork};
use crate::error::{Error, Result};
use crate::types::primitives::{BLSPublicKey, BLSSignature, Epoch, Root, Slot, ValidatorIndex};
use ethereum_types::{Address, U256};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::{U256 as BloomLen, U32, U4, U48, U512};
use ssz_types::{FixedVector, VariableList};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// Beacon block header as per consensus specs
/// Uses TreeHash derive for proper SSZ hash_tree_root computation
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
    pub fn hash_tree_root(&self) -> Result<Root> {
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

// =============================================================================
// LightClientHeader (fork-aware)
// =============================================================================

/// Fork-aware light client header.
///
/// Each consensus fork defines its own `LightClientHeader` shape.
/// In Altair and Bellatrix the header contains only a `BeaconBlockHeader`.
/// Later forks (Capella onward) add execution payload header fields;
/// those variants will be added here as the library gains support.
///
/// Verification logic accesses the inner `BeaconBlockHeader` through
/// [`beacon()`](Self::beacon), keeping the pipeline fork-agnostic.
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

/// Altair light client header — beacon header only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltairLightClientHeader {
    pub beacon: BeaconBlockHeader,
}

/// Bellatrix light client header — same shape as Altair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BellatrixLightClientHeader {
    pub beacon: BeaconBlockHeader,
}

/// Capella light client header — adds execution payload.
///
/// Starting at Capella, the `LightClientHeader` includes an execution
/// payload header and a merkle branch proving it is embedded in
/// `beacon.body_root` at `EXECUTION_PAYLOAD_GINDEX` (25).
#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct CapellaLightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeaderCapella,
    /// Merkle branch proving `execution` is at gindex 25 in `beacon.body_root`.
    /// Fixed length = floorlog2(EXECUTION_PAYLOAD_GINDEX) = floorlog2(25) = 4.
    pub execution_branch: FixedVector<Root, U4>,
}

/// Execution payload header for Capella (15 fields).
///
/// This is the execution-layer block header embedded in the beacon block.
/// Capella adds `withdrawals_root` compared to Bellatrix.
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
    /// `ByteList[32]` — the 32-byte bound is enforced by the `VariableList` type.
    pub extra_data: VariableList<u8, U32>,
    pub base_fee_per_gas: U256,
    pub block_hash: Root,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
}

impl ExecutionPayloadHeaderCapella {
    /// SSZ `hash_tree_root` as a [`Root`] — thin wrapper over the derived
    /// [`TreeHash`] impl (the field-by-field merkleization is now generated).
    pub fn hash_tree_root(&self) -> Root {
        self.tree_hash_root().0
    }
}

/// Deneb light client header — same shape as Capella, with a Deneb execution payload.
///
/// The execution branch length is unchanged: `EXECUTION_PAYLOAD_GINDEX` (25) is
/// constant from Capella through Electra, so `floorlog2(25) = 4`.
#[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
pub struct DenebLightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeaderDeneb,
    /// Merkle branch proving `execution` is at gindex 25 in `beacon.body_root`.
    pub execution_branch: FixedVector<Root, U4>,
}

/// Execution payload header for Deneb (17 fields).
///
/// Adds `blob_gas_used` and `excess_blob_gas` to the Capella shape, increasing
/// the SSZ container field count from 15 to 17. Merkleization pads to 32 leaves
/// (next power of two ≥ 17), which differs from Capella's 16-leaf padding.
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
    /// `ByteList[32]` — the 32-byte bound is enforced by the `VariableList` type.
    pub extra_data: VariableList<u8, U32>,
    pub base_fee_per_gas: U256,
    pub block_hash: Root,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

impl ExecutionPayloadHeaderDeneb {
    /// SSZ `hash_tree_root` as a [`Root`] — thin wrapper over the derived
    /// [`TreeHash`] impl.
    pub fn hash_tree_root(&self) -> Root {
        self.tree_hash_root().0
    }
}

impl LightClientHeader {
    /// Wrap a `BeaconBlockHeader` as an Altair-era header.
    pub fn altair(beacon: BeaconBlockHeader) -> Self {
        Self::Altair(AltairLightClientHeader { beacon })
    }

    /// Wrap a `BeaconBlockHeader` as a Bellatrix-era header.
    #[allow(dead_code)]
    pub fn bellatrix(beacon: BeaconBlockHeader) -> Self {
        Self::Bellatrix(BellatrixLightClientHeader { beacon })
    }

    /// Construct a Capella header with execution payload and inclusion proof.
    #[allow(dead_code)]
    pub fn capella(
        beacon: BeaconBlockHeader,
        execution: ExecutionPayloadHeaderCapella,
        execution_branch: [Root; 4],
    ) -> Self {
        Self::Capella(CapellaLightClientHeader {
            beacon,
            execution,
            execution_branch: FixedVector::new(execution_branch.to_vec()).expect("branch is 4"),
        })
    }

    /// Construct a Deneb header with execution payload and inclusion proof.
    #[allow(dead_code)]
    pub fn deneb(
        beacon: BeaconBlockHeader,
        execution: ExecutionPayloadHeaderDeneb,
        execution_branch: [Root; 4],
    ) -> Self {
        Self::Deneb(DenebLightClientHeader {
            beacon,
            execution,
            execution_branch: FixedVector::new(execution_branch.to_vec()).expect("branch is 4"),
        })
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

    /// The header's slot.
    pub fn slot(&self) -> Slot {
        self.beacon().slot
    }

    /// The header's state root.
    pub fn state_root(&self) -> &Root {
        &self.beacon().state_root
    }

    /// Compute the hash tree root of this header.
    ///
    /// - Altair/Bellatrix: `hash_tree_root(beacon)` (1-field container).
    /// - Capella/Deneb: `hash_tree_root({beacon, execution, execution_branch})`
    ///   (3-field container). The container shape is identical; only the inner
    ///   `execution.hash_tree_root()` differs across forks.
    pub fn hash_tree_root(&self) -> Result<Root> {
        match self {
            // Altair/Bellatrix have no LightClientHeader container (it arrived in
            // Capella); the header root is the beacon root.
            Self::Altair(h) => h.beacon.hash_tree_root(),
            Self::Bellatrix(h) => h.beacon.hash_tree_root(),
            // Capella/Deneb are 3-field containers `{beacon, execution,
            // execution_branch}` — the derived TreeHash does the merkleization.
            Self::Capella(h) => Ok(h.tree_hash_root().0),
            Self::Deneb(h) => Ok(h.tree_hash_root().0),
        }
    }
}

// =============================================================================
// SyncCommittee
// =============================================================================

/// A single BLS public key as SSZ bytes (`Vector[byte, 48]`).
pub type PubkeyBytes = FixedVector<u8, U48>;

/// Sync committee: a spec-sized list of BLS pubkeys plus the aggregate.
///
/// The list length *is* the committee size (32 minimal / 512 mainnet), so there
/// is no zero-padding (#21). The SSZ size — which the network preset fixes and
/// [`ChainSpec`] owns — is not carried on the value; the root is computed by
/// dispatching on the list length to a size-specific SSZ-native helper below.
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

impl SyncCommittee {
    /// SSZ `hash_tree_root`, dispatched on the (spec-sized) committee length.
    pub fn hash_tree_root(&self) -> Root {
        let agg = self.aggregate_pubkey.clone();
        match self.pubkeys.len() {
            512 => CommitteeRoot512 {
                pubkeys: FixedVector::new(self.pubkeys.clone()).expect("len checked"),
                aggregate_pubkey: agg,
            }
            .tree_hash_root()
            .0,
            32 => CommitteeRoot32 {
                pubkeys: FixedVector::new(self.pubkeys.clone()).expect("len checked"),
                aggregate_pubkey: agg,
            }
            .tree_hash_root()
            .0,
            n => unreachable!("sync committee is 32 or 512 members, got {n}"),
        }
    }

    /// The committee members (spec-sized: 32 or 512, no padding).
    pub fn pubkeys(&self) -> &[PubkeyBytes] {
        &self.pubkeys
    }

    pub fn aggregate_pubkey(&self) -> &PubkeyBytes {
        &self.aggregate_pubkey
    }

    /// Number of committee members (spec-sized; no padding).
    pub fn len(&self) -> usize {
        self.pubkeys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pubkeys.is_empty()
    }

    /// 2/3 supermajority over the spec-sized committee.
    pub fn has_supermajority_participation(&self, participation_bits: &[bool]) -> bool {
        if participation_bits.len() != self.len() {
            return false;
        }
        let participants = participation_bits.iter().filter(|&&b| b).count();
        participants >= (self.len() * 2 / 3)
    }

    /// Bit-selected participating pubkeys as raw 48-byte keys (for BLS).
    pub fn participating_pubkeys(&self, participation_bits: &[bool]) -> Result<Vec<BLSPublicKey>> {
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

    /// Build a minimal-preset (32-key) committee from raw pubkey bytes.
    /// The fixture decoder uses this; mainnet committee decode is not yet wired.
    pub(crate) fn from_minimal_parts(
        pubkeys: Vec<BLSPublicKey>,
        aggregate_pubkey: BLSPublicKey,
    ) -> Result<Self> {
        Ok(SyncCommittee {
            pubkeys: pubkeys
                .into_iter()
                .map(|pk| PubkeyBytes::new(pk.to_vec()).expect("48-byte pubkey"))
                .collect(),
            aggregate_pubkey: PubkeyBytes::new(aggregate_pubkey.to_vec()).expect("48-byte pubkey"),
        })
    }
}

/// Sync aggregate data for light client updates.
///
/// `sync_committee_bits` is spec-sized (32 or 512, no padding) — one bit per
/// committee member. The aggregate is never `hash_tree_root`'d, so it needs no
/// SSZ derive; it's decoded off the wire and used for participation + BLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregate {
    pub sync_committee_bits: Vec<bool>,
    /// BLS aggregate signature
    pub sync_committee_signature: BLSSignature,
}

impl SyncAggregate {
    pub fn new(sync_committee_bits: Vec<bool>, sync_committee_signature: BLSSignature) -> Self {
        Self {
            sync_committee_bits,
            sync_committee_signature,
        }
    }

    pub fn participation_count(&self) -> usize {
        self.sync_committee_bits.iter().filter(|&&bit| bit).count()
    }

    /// Check if sync aggregate has supermajority participation
    /// Uses actual committee size from the provided sync committee
    pub fn has_supermajority(&self, sync_committee: &SyncCommittee) -> bool {
        sync_committee.has_supermajority_participation(self.sync_committee_bits.as_ref())
    }
}

/// Light client update containing all data needed for verification.
///
/// Headers are fork-aware [`LightClientHeader`] values.
#[derive(Debug, Clone, PartialEq)]
pub struct LightClientUpdate {
    /// The header being attested to (fork-aware).
    pub attested_header: LightClientHeader,
    /// The finalized header (fork-aware), if present.
    pub finalized_header: Option<LightClientHeader>,
    /// Merkle proof for finalized header
    pub finality_branch: Vec<Root>,
    /// Next sync committee (if committee changes)
    pub next_sync_committee: Option<SyncCommittee>,
    /// Merkle proof for next sync committee
    pub next_sync_committee_branch: Vec<Root>,
    /// Sync committee aggregate signature and participation
    pub sync_aggregate: SyncAggregate,
    /// Signature slot (should be attested_header.slot + 1)
    pub signature_slot: Slot,
}

impl LightClientUpdate {
    /// Decode an SSZ-encoded light client update for `fork`.
    ///
    /// `bytes` is raw SSZ as served by the beacon API (not snappy-framed).
    /// `fork` selects the wire layout — obtain it from the beacon API's
    /// `Eth-Consensus-Version` header, or the per-item fork-version prefix on
    /// `/eth/v1/beacon/light_client/updates`. (SSZ is not self-describing, so
    /// the fork cannot be inferred from the bytes.)
    pub fn from_ssz(bytes: &[u8], fork: Fork) -> Result<Self> {
        crate::types::ssz::decode_update(bytes, fork)
    }

    /// Create a new update wrapping a `BeaconBlockHeader` as Altair.
    pub fn new(
        attested_header: BeaconBlockHeader,
        sync_aggregate: SyncAggregate,
        signature_slot: Slot,
    ) -> Self {
        Self {
            attested_header: LightClientHeader::altair(attested_header),
            finalized_header: None,
            finality_branch: Vec::new(),
            next_sync_committee: None,
            next_sync_committee_branch: Vec::new(),
            sync_aggregate,
            signature_slot,
        }
    }

    pub fn with_finalized_header(
        mut self,
        finalized_header: BeaconBlockHeader,
        finality_branch: Vec<Root>,
    ) -> Self {
        self.finalized_header = Some(LightClientHeader::altair(finalized_header));
        self.finality_branch = finality_branch;
        self
    }

    pub fn with_next_sync_committee(
        mut self,
        next_sync_committee: SyncCommittee,
        next_sync_committee_branch: Vec<Root>,
    ) -> Self {
        self.next_sync_committee = Some(next_sync_committee);
        self.next_sync_committee_branch = next_sync_committee_branch;
        self
    }

    /// Validate basic properties of the light client update.
    ///
    /// Enforces:
    /// - `signature_slot > attested_header.slot`
    /// - supermajority participation
    pub fn validate_basic(&self, sync_committee: &SyncCommittee) -> Result<()> {
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
    pub fn has_sync_committee_update(&self) -> bool {
        self.next_sync_committee.is_some()
    }

    /// Check if this update contains finality information
    pub fn has_finality_update(&self) -> bool {
        self.finalized_header.is_some()
    }

    /// Get the period of the attested header.
    pub fn attested_period(&self, spec: &ChainSpec) -> u64 {
        spec.slot_to_sync_committee_period(self.attested_header.slot())
    }

    /// Get the period of the signature slot.
    pub fn signature_period(&self, spec: &ChainSpec) -> u64 {
        spec.slot_to_sync_committee_period(self.signature_slot)
    }
}

/// Bootstrap data for initializing a light client.
///
/// This is the trusted anchor from which light client sync begins. It contains:
/// - A trusted light client header (fork-aware, typically a finalized checkpoint)
/// - The sync committee active at that header's slot
/// - A merkle proof that the sync committee is embedded in the header's state root
/// - The genesis validators root for the chain (used in signature domain computation)
///
/// Corresponds to the `LightClientBootstrap` object in the Ethereum consensus specs.
#[derive(Debug, Clone, PartialEq)]
pub struct LightClientBootstrap {
    /// The trusted header (fork-aware).
    pub header: LightClientHeader,
    /// The current sync committee at the header's slot.
    pub current_sync_committee: SyncCommittee,
    /// Merkle branch proving `current_sync_committee` is in `header.state_root`.
    /// Length depends on the fork (Altair: 5 nodes).
    pub current_sync_committee_branch: Vec<Root>,
    /// Genesis validators root for the chain (network identifier for domain computation).
    pub genesis_validators_root: Root,
}

impl LightClientBootstrap {
    /// Decode an SSZ-encoded light client bootstrap for `fork`.
    ///
    /// `bytes` is raw SSZ as served by the beacon API (not snappy-framed).
    /// `fork` selects the wire layout (see [`LightClientUpdate::from_ssz`]).
    /// `genesis_validators_root` is supplied out-of-band (from beacon genesis);
    /// it is not part of the bootstrap message.
    pub fn from_ssz(bytes: &[u8], fork: Fork, genesis_validators_root: Root) -> Result<Self> {
        crate::types::ssz::decode_bootstrap(bytes, fork, genesis_validators_root)
    }

    /// Create a new bootstrap package from a `BeaconBlockHeader` (convenience, wraps as Altair).
    pub fn new(
        header: BeaconBlockHeader,
        current_sync_committee: SyncCommittee,
        current_sync_committee_branch: Vec<Root>,
        genesis_validators_root: Root,
    ) -> Self {
        Self::from_header(
            LightClientHeader::altair(header),
            current_sync_committee,
            current_sync_committee_branch,
            genesis_validators_root,
        )
    }

    /// Create a new bootstrap package from a fork-aware [`LightClientHeader`].
    pub fn from_header(
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
    /// Best finalized header we've seen (fork-aware).
    pub finalized_header: LightClientHeader,
    /// Current sync committee
    pub current_sync_committee: SyncCommittee,
    /// Next sync committee (if known)
    pub next_sync_committee: Option<SyncCommittee>,
    /// Optimistic header (may not be finalized, fork-aware).
    pub optimistic_header: LightClientHeader,
    /// Genesis validators root (chain identity for signature domains)
    pub genesis_validators_root: Root,
    /// Previous max active participants (used by force_update - not yet implemented)
    #[allow(dead_code)]
    pub previous_max_active_participants: u64,
    /// Current max active participants
    pub current_max_active_participants: u64,
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
            previous_max_active_participants: 0,
            current_max_active_participants: 0,
        }
    }

    /// Get the sync committee period derived from the finalized header.
    ///
    /// This is the canonical "store period" per consensus-specs.
    pub(crate) fn finalized_sync_committee_period(&self, spec: &ChainSpec) -> u64 {
        spec.slot_to_sync_committee_period(self.finalized_header.slot())
    }

    // The following methods are reserved for future force_update implementation

    /// Get the next sync committee period.
    #[allow(dead_code)]
    pub fn next_period(&self, spec: &ChainSpec) -> u64 {
        self.finalized_sync_committee_period(spec) + 1
    }

    /// Check if we should update the sync committee for the given period.
    #[allow(dead_code)]
    pub fn should_update_sync_committee(&self, spec: &ChainSpec, period: u64) -> bool {
        period == self.next_period(spec) && self.next_sync_committee.is_some()
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
        SyncCommittee::from_minimal_parts(vec![[1u8; 48]; 32], [2u8; 48]).unwrap()
    }

    #[test]
    fn test_sync_committee_supermajority() {
        let committee = create_test_sync_committee();
        let threshold = 32 * 2 / 3; // 21 of 32

        // Exactly 2/3 passes.
        let mut participation = vec![false; 32];
        participation.iter_mut().take(threshold).for_each(|p| *p = true);
        assert!(committee.has_supermajority_participation(&participation));

        // One below 2/3 fails.
        let mut participation = vec![false; 32];
        participation.iter_mut().take(threshold - 1).for_each(|p| *p = true);
        assert!(!committee.has_supermajority_participation(&participation));

        // Full participation passes.
        assert!(committee.has_supermajority_participation(&vec![true; 32]));
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
        assert!(!update.has_finality_update());
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
        assert_eq!(store.next_period(&spec), 1);
        assert_eq!(store.genesis_validators_root, genesis_validators_root);
    }
}
