use crate::config::ChainSpec;
use crate::consensus::merkle::verify_next_sync_committee;
use crate::error::{Error, Result};
use crate::types::consensus::{LightClientUpdate, SyncCommittee};
use crate::types::primitives::{BLSPublicKey, BLSSignature, Domain, ForkVersion, Root, Slot};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

// Domain type constants as per beacon chain specification
/// Domain type for sync committee signatures
pub(crate) const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];

/// Domain type for beacon block proposals (used in tests)
#[cfg(test)]
const DOMAIN_BEACON_PROPOSER: [u8; 4] = [0, 0, 0, 0];

// =============================================================================
// Stateless sync-committee helpers
// =============================================================================

/// Select the appropriate sync committee for `signature_slot`.
///
/// Keyed off the store's finalized slot (canonical period source).
/// - signature period == store_period -> current committee
/// - signature period == store_period + 1, next known -> next committee
/// - otherwise -> error
pub(crate) fn committee_for_slot<'a>(
    signature_slot: Slot,
    store_finalized_slot: Slot,
    current_committee: &'a SyncCommittee,
    next_committee: Option<&'a SyncCommittee>,
    chain_spec: &ChainSpec,
) -> Result<&'a SyncCommittee> {
    let sig_period = chain_spec.slot_to_sync_committee_period(signature_slot);
    let store_period = chain_spec.slot_to_sync_committee_period(store_finalized_slot);

    if sig_period == store_period {
        Ok(current_committee)
    } else if sig_period == store_period + 1 {
        next_committee
            .ok_or_else(|| Error::InvalidInput("Next sync committee not available".to_string()))
    } else {
        Err(Error::InvalidInput(format!(
            "Cannot get committee for period {}, store period is {}",
            sig_period, store_period
        )))
    }
}

/// Attempt to learn `next_sync_committee` from an update.
///
/// Guards:
/// - update must carry a next_sync_committee
/// - store must not already have a next committee (no overwrite)
/// - attested header must be in the store's finalized-derived period
///
/// On success returns `Ok(Some(verified_committee))` for the caller to
/// set on the store. Returns `Ok(None)` when the update is skipped.
pub(crate) fn learn_next_sync_committee_from_update(
    update: &LightClientUpdate,
    finalized_period: u64,
    next_committee_known: bool,
    chain_spec: &ChainSpec,
) -> Result<Option<SyncCommittee>> {
    if !update.has_sync_committee_update() {
        return Ok(None);
    }

    if next_committee_known {
        return Ok(None);
    }

    let update_period = chain_spec.slot_to_sync_committee_period(update.attested_header.slot);
    let attested_next_committee = update.next_sync_committee.as_ref().unwrap();

    if update_period != finalized_period {
        return Err(Error::InvalidInput(format!(
            "Cannot learn next sync committee from period {}; \
             next committee is unknown, so update must attest to finalized period {}",
            update_period, finalized_period
        )));
    }

    // Verify the merkle branch proof
    verify_next_sync_committee(
        attested_next_committee,
        &update.next_sync_committee_branch,
        update.attested_header.slot,
        &update.attested_header.state_root,
        chain_spec,
    )?;

    Ok(Some(attested_next_committee.clone()))
}

/// Verify a sync aggregate signature.
///
/// TODO(#21): make sync committee bits spec-sized (use ChainSpec::sync_committee_size()).
pub(crate) fn verify_sync_aggregate(
    committee: &SyncCommittee,
    signature_slot: Slot,
    attested_header_root: Root,
    sync_committee_bits: &[bool; 512],
    sync_committee_signature: &BLSSignature,
    genesis_validators_root: Root,
    chain_spec: &ChainSpec,
) -> Result<bool> {
    let participating_pubkeys = committee.participating_pubkeys(sync_committee_bits)?;

    if participating_pubkeys.is_empty() {
        return Ok(false);
    }

    let domain =
        compute_sync_committee_domain_for_slot(signature_slot, genesis_validators_root, chain_spec);

    verify_sync_committee_signature(
        &participating_pubkeys,
        attested_header_root,
        sync_committee_signature,
        domain,
    )
}

/// Check if rotation should happen for the given update.
#[cfg(test)]
pub fn should_rotate(
    update_finalized_slot: Slot,
    store_period: u64,
    has_next_committee: bool,
    chain_spec: &ChainSpec,
) -> bool {
    let update_finalized_period = chain_spec.slot_to_sync_committee_period(update_finalized_slot);
    update_finalized_period == store_period + 1 && has_next_committee
}

/// Compute the sync committee domain for a given signature slot.
///
/// Per spec: `fork_version_slot = max(signature_slot, 1) - 1`
pub(crate) fn compute_sync_committee_domain_for_slot(
    signature_slot: Slot,
    genesis_validators_root: Root,
    chain_spec: &ChainSpec,
) -> Domain {
    let fork_version_slot = signature_slot.saturating_sub(1);
    let epoch = chain_spec.slot_to_epoch(fork_version_slot);
    let fork_version = chain_spec.fork_version_at_epoch(epoch);
    compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)
}

/// Fork data structure for domain computation
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

/// Verify BLS aggregate signature for sync committee
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

    let signing_root = compute_signing_root(message, domain)?;

    Ok(bls::fast_aggregate_verify(
        participating_pubkeys,
        &signing_root,
        signature,
    ))
}

/// SigningData container as per Ethereum consensus spec
#[derive(tree_hash_derive::TreeHash)]
struct SigningData {
    object_root: Root,
    domain: Domain,
}

/// Compute signing root for BLS signature as per beacon chain specification
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::consensus::SyncCommittee;

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
        let pubkeys = Box::new([[1u8; 48]; SyncCommittee::SYNC_COMMITTEE_SIZE]);
        let aggregate_pubkey = [2u8; 48];
        SyncCommittee::new(pubkeys, aggregate_pubkey)
    }

    #[test]
    fn test_committee_for_slot_selection() {
        let chain_spec = ChainSpec::mainnet();
        let current = create_test_sync_committee();
        let next = {
            let mut c = create_test_sync_committee();
            c.aggregate_pubkey = [3u8; 48];
            c
        };

        let got = committee_for_slot(0, 0, &current, Some(&next), &chain_spec).unwrap();
        assert_eq!(got.aggregate_pubkey, current.aggregate_pubkey);

        let got = committee_for_slot(8191, 0, &current, Some(&next), &chain_spec).unwrap();
        assert_eq!(got.aggregate_pubkey, current.aggregate_pubkey);

        let got = committee_for_slot(8192, 0, &current, Some(&next), &chain_spec).unwrap();
        assert_eq!(got.aggregate_pubkey, next.aggregate_pubkey);

        assert!(committee_for_slot(8192, 0, &current, None, &chain_spec).is_err());
        assert!(committee_for_slot(16384, 0, &current, Some(&next), &chain_spec).is_err());
    }

    #[test]
    fn test_rotation_gating() {
        let chain_spec = ChainSpec::mainnet();
        let store_period = 0;

        assert!(!should_rotate(8192, store_period, false, &chain_spec));
        assert!(should_rotate(8192, store_period, true, &chain_spec));
        assert!(!should_rotate(100, store_period, true, &chain_spec));
    }

    #[test]
    fn test_beacon_chain_domain_computation() {
        let fork_version = [1, 2, 3, 4];
        let genesis_validators_root = [5u8; 32];

        let sync_domain =
            compute_beacon_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root);

        assert_eq!(sync_domain[0..4], DOMAIN_SYNC_COMMITTEE);

        let proposer_domain = compute_beacon_domain(
            DOMAIN_BEACON_PROPOSER,
            fork_version,
            genesis_validators_root,
        );
        assert_ne!(sync_domain, proposer_domain);

        let sync_domain2 =
            compute_beacon_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root);
        assert_eq!(sync_domain, sync_domain2);

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
        let fork_version: ForkVersion = [0x05, 0x00, 0x00, 0x00];
        let genesis_validators_root: Root = [
            0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f,
            0xdd, 0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f,
            0x51, 0x1b, 0xfe, 0x95,
        ];

        let _fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);

        let domain =
            compute_beacon_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root);

        assert_eq!(&domain[0..4], &[0x07, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_fork_data_root_computation() {
        let fork_version = [1, 2, 3, 4];
        let genesis_validators_root = [5u8; 32];

        let fork_root1 = compute_fork_data_root(fork_version, genesis_validators_root);
        let fork_root2 = compute_fork_data_root(fork_version, genesis_validators_root);
        assert_eq!(fork_root1, fork_root2);

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
        assert_eq!(signing_root1, signing_root2);

        let different_message = [9u8; 32];
        let signing_root3 = compute_signing_root(different_message, domain).unwrap();
        assert_ne!(signing_root1, signing_root3);

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
        let zero_key = [0u8; 48];
        assert!(validate_bls_public_key(&zero_key).is_err());

        let invalid_key = [255u8; 48];
        assert!(validate_bls_public_key(&invalid_key).is_err());

        use blst::min_pk::SecretKey;
        let sk = SecretKey::key_gen(&[1u8; 32], &[]).unwrap();
        let pk = sk.sk_to_pk();
        let pk_bytes = pk.compress();
        assert!(validate_bls_public_key(&pk_bytes).is_ok());
    }

    #[test]
    fn test_bls_signature_validation() {
        let zero_sig = [0u8; 96];
        assert!(validate_bls_signature(&zero_sig).is_err());

        let invalid_sig = [255u8; 96];
        assert!(validate_bls_signature(&invalid_sig).is_err());

        use blst::min_pk::SecretKey;
        let sk = SecretKey::key_gen(&[1u8; 32], &[]).unwrap();
        let message = b"test message";
        let sig = sk.sign(message, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", &[]);
        let sig_bytes = sig.compress();
        assert!(validate_bls_signature(&sig_bytes).is_ok());
    }

    #[test]
    fn test_bls_public_key_aggregation() {
        use blst::min_pk::SecretKey;

        let mut public_keys = Vec::new();

        for i in 0..3 {
            let mut seed = [0u8; 32];
            seed[0] = i as u8 + 1;
            let sk = SecretKey::key_gen(&seed, &[]).unwrap();
            let pk = sk.sk_to_pk();
            public_keys.push(pk.compress());
        }

        let aggregated = aggregate_public_keys(&public_keys);
        assert!(aggregated.is_ok());

        let empty_keys = Vec::new();
        assert!(aggregate_public_keys(&empty_keys).is_err());

        let mut mixed_keys = public_keys.clone();
        mixed_keys.push([0u8; 48]);
        assert!(aggregate_public_keys(&mixed_keys).is_err());
    }

    #[test]
    fn test_complete_bls_verification_flow() {
        use blst::min_pk::{AggregateSignature, SecretKey};

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

        let message = [42u8; 32];
        let fork_version = [1u8; 4];
        let genesis_validators_root = [2u8; 32];
        let domain =
            compute_beacon_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root);

        let signing_root = compute_signing_root(message, domain).unwrap();

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

        let verification_result =
            verify_sync_committee_signature(&public_keys, message, &signature_bytes, domain);

        assert!(verification_result.is_ok());
        assert!(verification_result.unwrap());

        let wrong_message = [43u8; 32];
        let wrong_verification =
            verify_sync_committee_signature(&public_keys, wrong_message, &signature_bytes, domain);
        assert!(wrong_verification.is_ok());
        assert!(!wrong_verification.unwrap());

        let wrong_domain = compute_beacon_domain(
            DOMAIN_BEACON_PROPOSER,
            fork_version,
            genesis_validators_root,
        );
        let wrong_domain_verification =
            verify_sync_committee_signature(&public_keys, message, &signature_bytes, wrong_domain);
        assert!(wrong_domain_verification.is_ok());
        assert!(!wrong_domain_verification.unwrap());
    }

    #[test]
    fn test_domain_uses_fork_version_at_signature_slot_epoch() {
        use super::compute_sync_committee_domain_for_slot;
        use crate::config::ChainSpec;

        let chain_spec =
            ChainSpec::for_test(8, [0x00, 0x00, 0x00, 0x00], [0x01, 0x00, 0x00, 0x00], 0, 1);

        let genesis_validators_root = [0xABu8; 32];

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

        assert_ne!(expected_domain_fork_a, expected_domain_fork_b);

        // signature_slot 0: fork_version_slot = 0.saturating_sub(1) = 0 -> epoch 0 -> Fork A
        let slot_0: u64 = 0;
        let domain_slot_0 =
            compute_sync_committee_domain_for_slot(slot_0, genesis_validators_root, &chain_spec);
        assert_eq!(domain_slot_0, expected_domain_fork_a);

        // signature_slot 8: fork_version_slot = 7 -> epoch 0 -> Fork A
        let slot_8: u64 = chain_spec.slots_per_epoch();
        let domain_slot_8 =
            compute_sync_committee_domain_for_slot(slot_8, genesis_validators_root, &chain_spec);
        assert_eq!(domain_slot_8, expected_domain_fork_a);

        // signature_slot 9: fork_version_slot = 8 -> epoch 1 -> Fork B
        let slot_9: u64 = chain_spec.slots_per_epoch() + 1;
        let domain_slot_9 =
            compute_sync_committee_domain_for_slot(slot_9, genesis_validators_root, &chain_spec);
        assert_eq!(domain_slot_9, expected_domain_fork_b);

        assert_eq!(chain_spec.slot_to_epoch(0), 0);
        assert_eq!(chain_spec.slot_to_epoch(7), 0);
        assert_eq!(chain_spec.slot_to_epoch(8), 1);
    }

    #[test]
    fn test_no_rotation_on_attested_period_alone() {
        let chain_spec = ChainSpec::mainnet();
        let store_period = 0;

        let finalized_slot: Slot = 100;
        let attested_slot: Slot = 8192;

        assert_eq!(
            chain_spec.slot_to_sync_committee_period(attested_slot),
            1,
            "attested slot should be in period 1"
        );

        assert!(
            !should_rotate(finalized_slot, store_period, true, &chain_spec),
            "must NOT rotate when finalized period has not advanced"
        );
    }

    #[test]
    fn test_rejects_next_period_update_when_next_committee_unknown() {
        use crate::types::consensus::{BeaconBlockHeader, SyncAggregate};

        let committee = create_test_sync_committee();
        let chain_spec = ChainSpec::mainnet();
        let finalized_period = 0;

        let attested_header = BeaconBlockHeader::new(8192, 42, [1u8; 32], [2u8; 32], [3u8; 32]);
        let bits = Box::new([true; SyncCommittee::SYNC_COMMITTEE_SIZE]);
        let sync_aggregate = SyncAggregate::new(bits, [0u8; 96]);
        let update = LightClientUpdate::new(attested_header, sync_aggregate, 8193)
            .with_next_sync_committee(committee, vec![[0u8; 32]; 5]);

        let result =
            learn_next_sync_committee_from_update(&update, finalized_period, false, &chain_spec);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("next committee is unknown"),
            "Expected guard error, got: {}",
            err_msg
        );
    }
}
