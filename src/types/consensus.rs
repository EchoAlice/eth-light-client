use crate::config::ChainSpec;
use crate::error::{Error, Result};
use crate::types::primitives::{
    Address, BLSPublicKey, BLSSignature, Bloom, Epoch, ExtraData, Root, Slot, ValidatorIndex, U256,
};
use ssz_derive::{Decode, Encode};
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LightClientHeader {
    Altair(AltairLightClientHeader),
    Bellatrix(BellatrixLightClientHeader),
    Capella(CapellaLightClientHeader),
    // Future variants:
    // Deneb(DenebLightClientHeader),
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapellaLightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeaderCapella,
    /// Merkle branch proving `execution` is at gindex 25 in `beacon.body_root`.
    /// Fixed length = floorlog2(EXECUTION_PAYLOAD_GINDEX) = floorlog2(25) = 4.
    pub execution_branch: [Root; 4],
}

/// Execution payload header for Capella (15 fields).
///
/// This is the execution-layer block header embedded in the beacon block.
/// Capella adds `withdrawals_root` compared to Bellatrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPayloadHeaderCapella {
    pub parent_hash: Root,
    pub fee_recipient: Address,
    pub state_root: Root,
    pub receipts_root: Root,
    pub logs_bloom: Bloom,
    pub prev_randao: Root,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    /// Variable-length extra data (`ByteList[32]`). Bound-enforced at construction.
    pub extra_data: ExtraData,
    pub base_fee_per_gas: U256,
    pub block_hash: Root,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
}

impl ExecutionPayloadHeaderCapella {
    /// Compute the SSZ `hash_tree_root` of this 15-field container.
    ///
    /// Uses `TreeHash::tree_hash_root()` for fields that implement it
    /// (`u64`, `[u8; 32]`, `Bloom`, `ExtraData`). Two field types still
    /// need custom hashing because `tree_hash` lacks impls:
    ///
    /// - `[u8; 20]` (Address): right-padded to 32 bytes
    /// - `ruint::U256`: 32-byte little-endian value (single chunk)
    pub fn hash_tree_root(&self) -> Root {
        use tree_hash::TreeHash;

        fn to_root(h: tree_hash::Hash256) -> Root {
            let mut r = [0u8; 32];
            r.copy_from_slice(h.as_bytes());
            r
        }

        // [u8; 20]: right-padded to 32 bytes (no tree_hash impl exists).
        fn address_root(addr: &[u8; 20]) -> Root {
            let mut buf = [0u8; 32];
            buf[..20].copy_from_slice(addr);
            buf
        }

        // ruint::U256: 32-byte little-endian value (single chunk).
        fn u256_root(v: &U256) -> Root {
            v.to_le_bytes()
        }

        let field_roots: [Root; 15] = [
            self.parent_hash,                            // 0: [u8; 32]
            address_root(&self.fee_recipient),           // 1: [u8; 20]
            self.state_root,                             // 2: [u8; 32]
            self.receipts_root,                          // 3: [u8; 32]
            to_root(self.logs_bloom.tree_hash_root()),   // 4: Bloom (TreeHash)
            self.prev_randao,                            // 5: [u8; 32]
            to_root(self.block_number.tree_hash_root()), // 6: u64
            to_root(self.gas_limit.tree_hash_root()),    // 7: u64
            to_root(self.gas_used.tree_hash_root()),     // 8: u64
            to_root(self.timestamp.tree_hash_root()),    // 9: u64
            to_root(self.extra_data.tree_hash_root()),   // 10: ExtraData (TreeHash)
            u256_root(&self.base_fee_per_gas),           // 11: U256
            self.block_hash,                             // 12: [u8; 32]
            self.transactions_root,                      // 13: [u8; 32]
            self.withdrawals_root,                       // 14: [u8; 32]
        ];

        // 15-field container → pad to 16 leaves and merkleize.
        let mut leaf_bytes = [0u8; 32 * 16];
        for (i, root) in field_roots.iter().enumerate() {
            leaf_bytes[i * 32..(i + 1) * 32].copy_from_slice(root);
        }

        to_root(tree_hash::merkle_root(&leaf_bytes, 16))
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
            execution_branch,
        })
    }

    /// The inner `BeaconBlockHeader` (available for all forks).
    pub fn beacon(&self) -> &BeaconBlockHeader {
        match self {
            Self::Altair(h) => &h.beacon,
            Self::Bellatrix(h) => &h.beacon,
            Self::Capella(h) => &h.beacon,
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
    /// - Capella: `hash_tree_root({beacon, execution, execution_branch})`
    ///   (3-field container).
    pub fn hash_tree_root(&self) -> Result<Root> {
        match self {
            Self::Altair(h) => h.beacon.hash_tree_root(),
            Self::Bellatrix(h) => h.beacon.hash_tree_root(),
            Self::Capella(h) => {
                let beacon_root = h.beacon.hash_tree_root()?;
                let execution_root = h.execution.hash_tree_root();

                // execution_branch: Vector[Bytes32, 4] → merkleize 4 × 32-byte leaves.
                let mut branch_bytes = [0u8; 32 * 4];
                for (i, node) in h.execution_branch.iter().enumerate() {
                    branch_bytes[i * 32..(i + 1) * 32].copy_from_slice(node);
                }
                let mut branch_root = [0u8; 32];
                branch_root.copy_from_slice(tree_hash::merkle_root(&branch_bytes, 4).as_bytes());

                // 3-field container → pad to 4 leaves and merkleize.
                let mut container = [0u8; 32 * 4];
                container[0..32].copy_from_slice(&beacon_root);
                container[32..64].copy_from_slice(&execution_root);
                container[64..96].copy_from_slice(&branch_root);
                // container[96..128] is already zero (padding).
                let mut result = [0u8; 32];
                result.copy_from_slice(tree_hash::merkle_root(&container, 4).as_bytes());
                Ok(result)
            }
        }
    }
}

// =============================================================================
// SyncCommittee
// =============================================================================

/// Sync committee with 512 validators
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCommittee {
    /// 512 BLS public keys (heap-allocated to avoid stack overflow)
    pub pubkeys: Box<[BLSPublicKey; 512]>,
    /// Aggregate public key for the committee
    pub aggregate_pubkey: BLSPublicKey,
}

impl SyncCommittee {
    pub const SYNC_COMMITTEE_SIZE: usize = 512;

    pub fn new(pubkeys: Box<[BLSPublicKey; 512]>, aggregate_pubkey: BLSPublicKey) -> Self {
        Self {
            pubkeys,
            aggregate_pubkey,
        }
    }

    /// TODO(#21): delete once SyncCommittee is spec-sized (no zero-padding).
    ///
    /// Count the number of actual (non-zero) pubkeys in the committee
    /// This handles both minimal preset (32 keys) and mainnet (512 keys)
    pub fn actual_committee_size(&self) -> usize {
        self.pubkeys
            .iter()
            .filter(|pk| !pk.iter().all(|&b| b == 0))
            .count()
    }

    /// Check if we have the minimum threshold for a valid sync committee signature
    /// Uses actual committee size (non-zero pubkeys) rather than hardcoded 512
    pub fn has_supermajority_participation(&self, participation_bits: &[bool]) -> bool {
        if participation_bits.len() != Self::SYNC_COMMITTEE_SIZE {
            return false;
        }

        let participant_count = participation_bits.iter().filter(|&&bit| bit).count();
        let actual_size = self.actual_committee_size();

        // Need 2/3+ of actual committee members, not the padded size
        participant_count >= (actual_size * 2 / 3)
    }

    /// Get participating public keys based on participation bits
    /// Filters out zero pubkeys to handle minimal preset (32 keys) vs mainnet (512 keys)
    pub fn participating_pubkeys(&self, participation_bits: &[bool]) -> Result<Vec<BLSPublicKey>> {
        if participation_bits.len() != Self::SYNC_COMMITTEE_SIZE {
            return Err(Error::InvalidInput(
                "Participation bits length mismatch".to_string(),
            ));
        }

        let mut participating_pubkeys = Vec::new();
        for (i, &bit) in participation_bits.iter().enumerate() {
            if bit {
                let pubkey = self.pubkeys[i];
                // Filter out zero pubkeys (padding for minimal preset)
                if !pubkey.iter().all(|&b| b == 0) {
                    participating_pubkeys.push(pubkey);
                }
            }
        }

        Ok(participating_pubkeys)
    }
}

/// Sync aggregate data for light client updates
/// Note: Cannot derive SSZ Decode because [bool; 512] and [u8; 96] aren't supported by ethereum_ssz
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregate {
    /// Participation bits for 512 sync committee members (heap-allocated to avoid stack overflow)
    pub sync_committee_bits: Box<[bool; 512]>,
    /// BLS aggregate signature
    pub sync_committee_signature: BLSSignature,
}

impl SyncAggregate {
    pub fn new(
        sync_committee_bits: Box<[bool; 512]>,
        sync_committee_signature: BLSSignature,
    ) -> Self {
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
        let pubkeys = Box::new([[1u8; 48]; 512]);
        let aggregate_pubkey = [2u8; 48];
        SyncCommittee::new(pubkeys, aggregate_pubkey)
    }

    #[test]
    fn test_sync_committee_supermajority() {
        let committee = create_test_sync_committee();

        // Test with exactly 2/3 participation (341 out of 512)
        let mut participation = [false; 512];
        for i in 0..341 {
            participation[i] = true;
        }
        assert!(committee.has_supermajority_participation(&participation));

        // Test with less than 2/3 participation
        let mut participation = [false; 512];
        for i in 0..340 {
            participation[i] = true;
        }
        assert!(!committee.has_supermajority_participation(&participation));

        // Test with full participation
        let participation = [true; 512];
        assert!(committee.has_supermajority_participation(&participation));
    }

    #[test]
    fn test_light_client_update_validation() {
        let attested_header = create_test_beacon_header();
        let sync_committee_bits = Box::new([true; 512]); // Full participation
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
