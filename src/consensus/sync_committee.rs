use crate::config::ChainSpec;
use crate::consensus::merkle::verify_next_sync_committee;
use crate::error::{Error, Result};
use crate::types::consensus::{LightClientUpdate, SyncCommittee};
use crate::types::primitives::{BLSPublicKey, BLSSignature, Domain, ForkVersion, Root, Slot};
use std::collections::HashMap;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

// Domain type constants as per beacon chain specification
/// Domain type for sync committee signatures
pub(crate) const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];

/// Domain type for beacon block proposals (used in tests)
#[cfg(test)]
const DOMAIN_BEACON_PROPOSER: [u8; 4] = [0, 0, 0, 0];

/// Sync committee tracker for managing committee rotations
#[derive(Debug, Clone)]
pub(crate) struct SyncCommitteeTracker {
    /// Current trusted sync committee
    current_committee: SyncCommittee,
    /// Next sync committee (if known and verified)
    next_committee: Option<SyncCommittee>,
    /// Current sync committee period
    current_period: u64,
    /// Committee update history for verification
    committee_history: HashMap<u64, SyncCommittee>,
    /// Fork version from bootstrap (retained for API stability; domain computation
    /// now uses chain_spec.fork_version_at_epoch())
    #[allow(dead_code)]
    fork_version: ForkVersion,
}

impl SyncCommitteeTracker {
    /// Create new sync committee tracker with initial trusted committee
    pub(crate) fn new(
        initial_committee: SyncCommittee,
        initial_period: u64,
        fork_version: ForkVersion,
    ) -> Result<Self> {
        let mut tracker = Self {
            current_committee: initial_committee.clone(),
            next_committee: None,
            current_period: initial_period,
            committee_history: HashMap::new(),
            fork_version,
        };

        // Store initial committee in history
        tracker
            .committee_history
            .insert(initial_period, initial_committee);

        Ok(tracker)
    }

    /// Get the current active sync committee for a given slot
    ///
    /// Returns the appropriate committee based on the slot's sync committee period.
    /// - If slot is in current period, return current_committee
    /// - If slot is in next period, return next_committee (if available)
    /// - Otherwise, return an error
    pub(crate) fn get_committee_for_slot(
        &self,
        slot: Slot,
        chain_spec: &ChainSpec,
    ) -> Result<&SyncCommittee> {
        let period = chain_spec.slot_to_sync_committee_period(slot);

        if period == self.current_period {
            Ok(&self.current_committee)
        } else if period == self.current_period + 1 {
            self.next_committee
                .as_ref()
                .ok_or_else(|| Error::InvalidInput("Next sync committee not available".to_string()))
        } else {
            Err(Error::InvalidInput(format!(
                "Cannot get committee for period {}, current period is {}",
                period, self.current_period
            )))
        }
    }

    /// Update with a new sync committee from a light client update
    ///
    /// This verifies the merkle branch proof that the next_sync_committee is properly
    /// embedded in the attested header's state root before accepting the update.
    pub(crate) fn process_sync_committee_update(
        &mut self,
        update: &LightClientUpdate,
        chain_spec: &ChainSpec,
    ) -> Result<bool> {
        if !update.has_sync_committee_update() {
            return Ok(false);
        }

        let update_period = chain_spec.slot_to_sync_committee_period(update.attested_header.slot);
        let next_committee = update.next_sync_committee.as_ref().unwrap();

        // Validate that the update is for current or next period
        // We accept updates for current period (replacing next) or next period (preparing for transition)
        if update_period != self.current_period && update_period != self.current_period + 1 {
            return Err(Error::InvalidInput(format!(
                "Sync committee update for wrong period: expected {} or {}, got {}",
                self.current_period,
                self.current_period + 1,
                update_period
            )));
        }

        // Verify the merkle branch proof that next_sync_committee is in the attested state
        verify_next_sync_committee(
            next_committee,
            &update.next_sync_committee_branch,
            update.attested_header.slot,
            &update.attested_header.state_root,
            chain_spec,
        )?;

        // Store the next committee
        self.next_committee = Some(next_committee.clone());
        self.committee_history
            .insert(self.current_period + 1, next_committee.clone());

        Ok(true)
    }

    /// Advance to the next sync committee period
    pub(crate) fn advance_to_next_period(&mut self) -> Result<()> {
        if let Some(next_committee) = self.next_committee.take() {
            self.current_committee = next_committee;
            self.current_period += 1;
            Ok(())
        } else {
            Err(Error::InvalidInput(
                "No next sync committee available".to_string(),
            ))
        }
    }

    /// Check if we should advance to the next period based on current slot
    pub(crate) fn should_advance_period(&self, current_slot: Slot, chain_spec: &ChainSpec) -> bool {
        let current_slot_period = chain_spec.slot_to_sync_committee_period(current_slot);
        let has_next = self.next_committee.is_some();
        current_slot_period > self.current_period && has_next
    }

    /// Get current period
    pub(crate) fn current_period(&self) -> u64 {
        self.current_period
    }

    /// Check if we have the next sync committee (test helper)
    #[cfg(test)]
    pub fn has_next_committee(&self) -> bool {
        self.next_committee.is_some()
    }

    /// Verify a sync aggregate signature against the appropriate committee.
    ///
    /// The `genesis_validators_root` is passed from the caller (LightClientStore)
    /// to compute the signature domain.
    pub(crate) fn verify_sync_aggregate(
        &self,
        signature_slot: Slot,
        attested_header_root: Root,
        sync_committee_bits: &[bool; 512],
        sync_committee_signature: &BLSSignature,
        genesis_validators_root: Root,
        chain_spec: &ChainSpec,
    ) -> Result<bool> {
        let committee = self.get_committee_for_slot(signature_slot, chain_spec)?;

        // Get participating public keys
        let participating_pubkeys = committee.get_participating_pubkeys(sync_committee_bits)?;

        if participating_pubkeys.is_empty() {
            return Ok(false);
        }

        // Compute domain using fork_version_slot = max(signature_slot, 1) - 1 (per spec)
        let domain = compute_sync_committee_domain_for_slot(
            signature_slot,
            genesis_validators_root,
            chain_spec,
        );

        // Verify BLS aggregate signature
        let result = verify_sync_committee_signature(
            &participating_pubkeys,
            attested_header_root,
            sync_committee_signature,
            domain,
        )?;

        Ok(result)
    }
}

/// Compute the sync committee domain for a given signature slot.
///
/// Per spec: `fork_version_slot = max(signature_slot, 1) - 1`
/// The sync committee signs at `signature_slot` but attests to the previous slot's state,
/// so the fork version is determined by `signature_slot - 1` (saturating at 0).
pub(crate) fn compute_sync_committee_domain_for_slot(
    signature_slot: Slot,
    genesis_validators_root: Root,
    chain_spec: &ChainSpec,
) -> Domain {
    // Spec: fork_version_slot = max(signature_slot, 1) - 1
    // Equivalent to saturating_sub(1) in Rust
    let fork_version_slot = signature_slot.saturating_sub(1);
    let epoch = chain_spec.slot_to_epoch(fork_version_slot);
    let fork_version = chain_spec.fork_version_at_epoch(epoch);
    compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)
}

/// Fork data structure for domain computation
/// Uses TreeHash derive for proper SSZ hash_tree_root computation
#[derive(Debug, Clone, TreeHash)]
struct ForkData {
    current_version: ForkVersion,
    genesis_validators_root: Root,
}

/// Compute fork data root as per beacon chain specification
fn compute_fork_data_root(fork_version: ForkVersion, genesis_validators_root: Root) -> Root {
    let fork_data = ForkData {
        current_version: fork_version,
        genesis_validators_root,
    };
    let hash256 = TreeHash::tree_hash_root(&fork_data);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash256.as_bytes());
    result
}

/// Compute domain as per beacon chain specification
/// Domain = domain_type + fork_data_root[:28]
fn compute_domain(
    domain_type: [u8; 4],
    fork_version: ForkVersion,
    genesis_validators_root: Root,
) -> Domain {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);

    let mut domain = [0u8; 32];
    domain[0..4].copy_from_slice(&domain_type);
    domain[4..32].copy_from_slice(&fork_data_root[0..28]);

    domain
}

/// Public function to compute domain for any domain type (exposed for testing)
#[cfg(test)]
pub fn compute_beacon_domain(
    domain_type: [u8; 4],
    fork_version: ForkVersion,
    genesis_validators_root: Root,
) -> Domain {
    compute_domain(domain_type, fork_version, genesis_validators_root)
}

/// Validate a BLS public key (exposed for testing)
#[cfg(test)]
pub fn validate_bls_public_key(pubkey_bytes: &BLSPublicKey) -> Result<()> {
    use blst::{min_pk::PublicKey, BLST_ERROR};

    let pubkey = PublicKey::from_bytes(pubkey_bytes).map_err(|e| match e {
        BLST_ERROR::BLST_BAD_ENCODING => {
            Error::InvalidInput("Invalid public key encoding".to_string())
        }
        BLST_ERROR::BLST_POINT_NOT_ON_CURVE => {
            Error::InvalidInput("Public key point not on curve".to_string())
        }
        BLST_ERROR::BLST_POINT_NOT_IN_GROUP => {
            Error::InvalidInput("Public key point not in group".to_string())
        }
        _ => Error::InvalidInput(format!("BLS public key error: {:?}", e)),
    })?;

    if pubkey.validate().is_err() {
        return Err(Error::InvalidInput("Invalid BLS public key".to_string()));
    }

    Ok(())
}

/// Validate a BLS signature (exposed for testing)
#[cfg(test)]
pub fn validate_bls_signature(signature_bytes: &BLSSignature) -> Result<()> {
    use blst::{min_pk::Signature, BLST_ERROR};

    let sig = Signature::from_bytes(signature_bytes).map_err(|e| match e {
        BLST_ERROR::BLST_BAD_ENCODING => {
            Error::InvalidInput("Invalid signature encoding".to_string())
        }
        BLST_ERROR::BLST_POINT_NOT_ON_CURVE => {
            Error::InvalidInput("Signature point not on curve".to_string())
        }
        BLST_ERROR::BLST_POINT_NOT_IN_GROUP => {
            Error::InvalidInput("Signature point not in group".to_string())
        }
        _ => Error::InvalidInput(format!("BLS signature error: {:?}", e)),
    })?;

    if sig.validate(false).is_err() {
        return Err(Error::InvalidInput("Invalid BLS signature".to_string()));
    }

    Ok(())
}

/// Verify BLS aggregate signature for sync committee using our tested bls module
/// Uses fast_aggregate_verify as per Ethereum consensus spec
fn verify_sync_committee_signature(
    participating_pubkeys: &[BLSPublicKey],
    message: Root,
    signature: &BLSSignature,
    domain: Domain,
) -> Result<bool> {
    use crate::consensus::bls;

    if participating_pubkeys.is_empty() {
        return Ok(false);
    }

    // Compute the signing root using our spec-compliant function
    let signing_root = compute_signing_root(message, domain)?;

    // Use our tested fast_aggregate_verify from bls module
    // This passes all official Ethereum consensus spec BLS tests
    Ok(bls::fast_aggregate_verify(
        participating_pubkeys,
        &signing_root,
        signature,
    ))
}

/// SigningData container as per Ethereum consensus spec
/// Used to compute the signing root for BLS signatures
#[derive(tree_hash_derive::TreeHash)]
struct SigningData {
    object_root: Root,
    domain: Domain,
}

/// Compute signing root for BLS signature as per beacon chain specification
/// Uses TreeHash derive for spec-compliant hash_tree_root computation
fn compute_signing_root(object_root: Root, domain: Domain) -> Result<Root> {
    use tree_hash::TreeHash;

    let signing_data = SigningData {
        object_root,
        domain,
    };
    let root = signing_data.tree_hash_root();

    let mut signing_root = [0u8; 32];
    signing_root.copy_from_slice(root.as_bytes());
    Ok(signing_root)
}

// TODO: BLS implementation needs validation against official Ethereum consensus specification test vectors to ensure compatibility with real beacon chain signatures.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::consensus::SyncCommittee;

    /// Aggregate BLS public keys using blst library (test-only helper)
    fn aggregate_public_keys(pubkeys: &[BLSPublicKey]) -> Result<BLSPublicKey> {
        use blst::{
            min_pk::{AggregatePublicKey, PublicKey},
            BLST_ERROR,
        };

        if pubkeys.is_empty() {
            return Err(Error::InvalidInput(
                "Cannot aggregate empty pubkey list".to_string(),
            ));
        }

        let mut aggregate = if let Ok(first_pubkey) = PublicKey::from_bytes(&pubkeys[0]) {
            AggregatePublicKey::from_public_key(&first_pubkey)
        } else {
            return Err(Error::InvalidInput("Invalid first public key".to_string()));
        };

        for pubkey_bytes in &pubkeys[1..] {
            let pubkey = PublicKey::from_bytes(pubkey_bytes).map_err(|e| match e {
                BLST_ERROR::BLST_BAD_ENCODING => {
                    Error::InvalidInput("Invalid public key encoding".to_string())
                }
                BLST_ERROR::BLST_POINT_NOT_ON_CURVE => {
                    Error::InvalidInput("Public key point not on curve".to_string())
                }
                BLST_ERROR::BLST_POINT_NOT_IN_GROUP => {
                    Error::InvalidInput("Public key point not in group".to_string())
                }
                _ => Error::InvalidInput(format!("BLS public key error: {:?}", e)),
            })?;

            if pubkey.validate().is_err() {
                return Err(Error::InvalidInput("Invalid BLS public key".to_string()));
            }

            aggregate.add_public_key(&pubkey, false).map_err(|e| {
                Error::InvalidInput(format!("Failed to aggregate public key: {:?}", e))
            })?;
        }

        let aggregated_pubkey = aggregate.to_public_key();
        let compressed_bytes = aggregated_pubkey.compress();
        let mut result = [0u8; 48];
        result.copy_from_slice(&compressed_bytes);

        Ok(result)
    }

    fn create_test_sync_committee() -> SyncCommittee {
        let pubkeys = Box::new([[1u8; 48]; 512]);
        let aggregate_pubkey = [2u8; 48];
        SyncCommittee::new(pubkeys, aggregate_pubkey)
    }

    #[test]
    fn test_sync_committee_tracker_creation() {
        let committee = create_test_sync_committee();
        let fork_version = [1u8; 4];

        let tracker = SyncCommitteeTracker::new(committee.clone(), 0, fork_version).unwrap();

        assert_eq!(tracker.current_period(), 0);
        assert!(!tracker.has_next_committee());
    }

    #[test]
    fn test_sync_committee_tracker_get_committee() {
        let committee = create_test_sync_committee();
        let fork_version = [1u8; 4];
        let chain_spec = ChainSpec::mainnet();

        let tracker = SyncCommitteeTracker::new(committee.clone(), 0, fork_version).unwrap();

        // Should return current committee for period 0 slots (mainnet: 0-8191)
        assert!(tracker.get_committee_for_slot(0, &chain_spec).is_ok());
        assert!(tracker.get_committee_for_slot(8191, &chain_spec).is_ok());

        // Should fail for next period without next committee
        assert!(tracker.get_committee_for_slot(8192, &chain_spec).is_err());
    }

    #[test]
    fn test_sync_committee_tracker_period_advancement() {
        let committee = create_test_sync_committee();
        let fork_version = [1u8; 4];
        let chain_spec = ChainSpec::mainnet();

        let mut tracker = SyncCommitteeTracker::new(committee.clone(), 0, fork_version).unwrap();

        // Should not advance without next committee (mainnet period boundary: slot 8192)
        assert!(!tracker.should_advance_period(8192, &chain_spec));

        // Add next committee and test advancement
        tracker.next_committee = Some(committee.clone());
        assert!(tracker.should_advance_period(8192, &chain_spec));

        // Test actual advancement
        assert!(tracker.advance_to_next_period().is_ok());
        assert_eq!(tracker.current_period(), 1);
        assert!(!tracker.has_next_committee());
    }

    #[test]
    fn test_beacon_chain_domain_computation() {
        let fork_version = [1, 2, 3, 4];
        let genesis_validators_root = [5u8; 32];

        // Test sync committee domain
        let sync_domain =
            compute_beacon_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root);

        // Domain should start with the domain type
        assert_eq!(sync_domain[0..4], DOMAIN_SYNC_COMMITTEE);

        // Test different domain types produce different domains
        let proposer_domain = compute_beacon_domain(
            DOMAIN_BEACON_PROPOSER,
            fork_version,
            genesis_validators_root,
        );
        assert_ne!(sync_domain, proposer_domain);

        // Same inputs should produce same domain
        let sync_domain2 =
            compute_beacon_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root);
        assert_eq!(sync_domain, sync_domain2);

        // Different fork version should produce different domain
        let different_fork = [4, 3, 2, 1];
        let sync_domain3 = compute_beacon_domain(
            DOMAIN_SYNC_COMMITTEE,
            different_fork,
            genesis_validators_root,
        );
        assert_ne!(sync_domain, sync_domain3);
    }

    #[test]
    fn test_mainnet_electra_domain() {
        // Electra fork version for mainnet
        let fork_version: ForkVersion = [0x05, 0x00, 0x00, 0x00];
        // Mainnet genesis validators root
        let genesis_validators_root: Root = [
            0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f,
            0xdd, 0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f,
            0x51, 0x1b, 0xfe, 0x95,
        ];

        let _fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);

        let domain =
            compute_beacon_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root);

        // The domain should start with 0x07000000
        assert_eq!(&domain[0..4], &[0x07, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_fork_data_root_computation() {
        let fork_version = [1, 2, 3, 4];
        let genesis_validators_root = [5u8; 32];

        let fork_root1 = compute_fork_data_root(fork_version, genesis_validators_root);
        let fork_root2 = compute_fork_data_root(fork_version, genesis_validators_root);

        // Should be deterministic
        assert_eq!(fork_root1, fork_root2);

        // Should change with different inputs
        let different_genesis = [6u8; 32];
        let fork_root3 = compute_fork_data_root(fork_version, different_genesis);
        assert_ne!(fork_root1, fork_root3);
    }

    #[test]
    fn test_signing_root_computation() {
        let message = [7u8; 32];
        let domain = [8u8; 32];

        let signing_root1 = compute_signing_root(message, domain).unwrap();
        let signing_root2 = compute_signing_root(message, domain).unwrap();

        // Should be deterministic
        assert_eq!(signing_root1, signing_root2);

        // Should change with different message
        let different_message = [9u8; 32];
        let signing_root3 = compute_signing_root(different_message, domain).unwrap();
        assert_ne!(signing_root1, signing_root3);

        // Should change with different domain
        let different_domain = [10u8; 32];
        let signing_root4 = compute_signing_root(message, different_domain).unwrap();
        assert_ne!(signing_root1, signing_root4);
    }

    #[test]
    fn test_blst_sizes() {
        use blst::min_pk::SecretKey;
        let sk = SecretKey::key_gen(&[1u8; 32], &[]).unwrap();
        let pk = sk.sk_to_pk();
        let pk_bytes = pk.to_bytes();
        println!("Public key size: {}", pk_bytes.len());

        let message = b"test message";
        let sig = sk.sign(message, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", &[]);
        let sig_bytes = sig.to_bytes();
        println!("Signature size: {}", sig_bytes.len());
    }

    #[test]
    fn test_bls_key_validation() {
        // Test with zero key (should fail)
        let zero_key = [0u8; 48];
        assert!(validate_bls_public_key(&zero_key).is_err());

        // Test with invalid encoding (should fail)
        let invalid_key = [255u8; 48];
        assert!(validate_bls_public_key(&invalid_key).is_err());

        // Generate a valid BLS key pair for testing
        use blst::min_pk::SecretKey;
        let sk = SecretKey::key_gen(&[1u8; 32], &[]).unwrap();
        let pk = sk.sk_to_pk();
        let pk_bytes = pk.compress();

        // Valid key should pass validation
        assert!(validate_bls_public_key(&pk_bytes).is_ok());
    }

    #[test]
    fn test_bls_signature_validation() {
        // Test with zero signature (should fail)
        let zero_sig = [0u8; 96];
        assert!(validate_bls_signature(&zero_sig).is_err());

        // Test with invalid encoding (should fail)
        let invalid_sig = [255u8; 96];
        assert!(validate_bls_signature(&invalid_sig).is_err());

        // Generate a valid BLS signature for testing
        use blst::min_pk::SecretKey;
        let sk = SecretKey::key_gen(&[1u8; 32], &[]).unwrap();
        let message = b"test message";
        let sig = sk.sign(message, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", &[]);
        let sig_bytes = sig.compress();

        // Valid signature should pass validation
        assert!(validate_bls_signature(&sig_bytes).is_ok());
    }

    #[test]
    fn test_bls_public_key_aggregation() {
        use blst::min_pk::SecretKey;

        // Generate multiple valid BLS key pairs
        let mut secret_keys = Vec::new();
        let mut public_keys = Vec::new();

        for i in 0..3 {
            let mut seed = [0u8; 32];
            seed[0] = i as u8 + 1; // Ensure different seeds
            let sk = SecretKey::key_gen(&seed, &[]).unwrap();
            let pk = sk.sk_to_pk();
            secret_keys.push(sk);
            public_keys.push(pk.compress());
        }

        // Test aggregation with valid keys
        let aggregated = aggregate_public_keys(&public_keys);
        assert!(aggregated.is_ok());

        // Test with empty list (should fail)
        let empty_keys = Vec::new();
        assert!(aggregate_public_keys(&empty_keys).is_err());

        // Test with invalid key mixed in (should fail)
        let mut mixed_keys = public_keys.clone();
        mixed_keys.push([0u8; 48]); // Invalid zero key
        assert!(aggregate_public_keys(&mixed_keys).is_err());
    }

    #[test]
    fn test_complete_bls_verification_flow() {
        use blst::min_pk::{AggregateSignature, SecretKey};

        // Generate test keys and signatures
        let mut secret_keys = Vec::new();
        let mut public_keys = Vec::new();

        for i in 0..3 {
            let mut seed = [0u8; 32];
            seed[0] = i as u8 + 1;
            let sk = SecretKey::key_gen(&seed, &[]).unwrap();
            let pk = sk.sk_to_pk();
            secret_keys.push(sk);
            public_keys.push(pk.compress());
        }

        // Create a test message and domain
        let message = [42u8; 32];
        let fork_version = [1u8; 4];
        let genesis_validators_root = [2u8; 32];
        let domain =
            compute_beacon_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root);

        // Compute signing root. (A real-world signing root would be a hashed beaconblockheader + domain)
        let signing_root = compute_signing_root(message, domain).unwrap();

        // Create individual signatures for the signing root
        // DST uses G2 curve for Ethereum beacon chain
        let first_sig = secret_keys[0].sign(
            &signing_root,
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
            &[],
        );
        let mut aggregate_sig = AggregateSignature::from_signature(&first_sig);
        for sk in &secret_keys[1..] {
            let sig = sk.sign(
                &signing_root,
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                &[],
            );
            aggregate_sig.add_signature(&sig, true).unwrap();
        }

        let final_signature = aggregate_sig.to_signature();
        let signature_bytes = final_signature.compress();

        // Verify the signature using our implementation
        let verification_result =
            verify_sync_committee_signature(&public_keys, message, &signature_bytes, domain);

        assert!(verification_result.is_ok());
        assert!(verification_result.unwrap()); // Should verify successfully

        // Test with wrong message (should fail)
        let wrong_message = [43u8; 32];
        let wrong_verification =
            verify_sync_committee_signature(&public_keys, wrong_message, &signature_bytes, domain);
        assert!(wrong_verification.is_ok());
        assert!(!wrong_verification.unwrap()); // Should fail verification

        // Test with wrong domain (should fail)
        let wrong_domain = compute_beacon_domain(
            DOMAIN_BEACON_PROPOSER,
            fork_version,
            genesis_validators_root,
        );
        let wrong_domain_verification =
            verify_sync_committee_signature(&public_keys, message, &signature_bytes, wrong_domain);
        assert!(wrong_domain_verification.is_ok());
        assert!(!wrong_domain_verification.unwrap()); // Should fail verification
    }

    /// Test that domain computation uses the fork version for the epoch of signature_slot.
    ///
    /// Uses `compute_sync_committee_domain_for_slot`, the same path as production code
    /// (`SyncCommitteeTracker::verify_sync_aggregate`), to compute domains.
    ///
    /// Creates a custom ChainSpec with an artificial fork boundary:
    /// - Fork A (Altair): epoch 0, fork_version = [0,0,0,0]
    /// - Fork B (Bellatrix): epoch 1, fork_version = [1,0,0,0]
    ///
    /// Verifies that domains differ across the fork boundary because the fork version
    /// is hashed into `fork_data_root`, which forms part of the domain.
    #[test]
    fn test_domain_uses_fork_version_at_signature_slot_epoch() {
        use super::compute_sync_committee_domain_for_slot;
        use crate::config::ChainSpec;

        // Create custom ChainSpec with fork boundary at epoch 1
        // Fork A (Altair) at epoch 0, Fork B (Bellatrix) at epoch 1
        let chain_spec = ChainSpec::for_test(
            8,                        // slots_per_epoch
            [0x00, 0x00, 0x00, 0x00], // altair_fork_version (Fork A)
            [0x01, 0x00, 0x00, 0x00], // bellatrix_fork_version (Fork B)
            0,                        // altair_fork_epoch
            1,                        // bellatrix_fork_epoch
        );

        let genesis_validators_root = [0xABu8; 32];

        // Compute expected domains directly from known fork versions
        let expected_domain_fork_a = compute_beacon_domain(
            DOMAIN_SYNC_COMMITTEE,
            [0x00, 0x00, 0x00, 0x00],
            genesis_validators_root,
        );
        let expected_domain_fork_b = compute_beacon_domain(
            DOMAIN_SYNC_COMMITTEE,
            [0x01, 0x00, 0x00, 0x00],
            genesis_validators_root,
        );

        // Sanity check: expected domains must differ (fork version hashed into fork_data_root)
        assert_ne!(
            expected_domain_fork_a, expected_domain_fork_b,
            "expected domains should differ for different fork versions"
        );

        // Test case 1: signature_slot 0
        // fork_version_slot = 0.saturating_sub(1) = 0 -> epoch 0 -> Fork A
        let slot_0: u64 = 0;
        let domain_slot_0 =
            compute_sync_committee_domain_for_slot(slot_0, genesis_validators_root, &chain_spec);
        assert_eq!(
            domain_slot_0, expected_domain_fork_a,
            "signature_slot 0: fork_version_slot 0 (epoch 0) -> Fork A"
        );

        // Test case 2: signature_slot 8 (first slot of epoch 1)
        // fork_version_slot = 8 - 1 = 7 -> epoch 0 -> Fork A (NOT Fork B!)
        // This is the key spec behavior: domain uses signature_slot - 1
        let slot_8: u64 = chain_spec.slots_per_epoch(); // 8
        let domain_slot_8 =
            compute_sync_committee_domain_for_slot(slot_8, genesis_validators_root, &chain_spec);
        assert_eq!(
            domain_slot_8, expected_domain_fork_a,
            "signature_slot 8: fork_version_slot 7 (epoch 0) -> Fork A"
        );

        // Test case 3: signature_slot 9
        // fork_version_slot = 9 - 1 = 8 -> epoch 1 -> Fork B
        // This is the first signature_slot that uses Fork B
        let slot_9: u64 = chain_spec.slots_per_epoch() + 1; // 9
        let domain_slot_9 =
            compute_sync_committee_domain_for_slot(slot_9, genesis_validators_root, &chain_spec);
        assert_eq!(
            domain_slot_9, expected_domain_fork_b,
            "signature_slot 9: fork_version_slot 8 (epoch 1) -> Fork B"
        );

        // Verify the fork_version_slot -> epoch mapping
        assert_eq!(chain_spec.slot_to_epoch(0), 0); // slot 0 -> epoch 0
        assert_eq!(chain_spec.slot_to_epoch(7), 0); // slot 7 -> epoch 0
        assert_eq!(chain_spec.slot_to_epoch(8), 1); // slot 8 -> epoch 1
    }
}
