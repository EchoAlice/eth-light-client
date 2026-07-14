use crate::config::ChainSpec;
use crate::consensus::bls;
use crate::consensus::merkle::verify_next_sync_committee;
use crate::error::{Error, Result};
use crate::types::consensus::{LightClientUpdate, SyncCommittee};
use crate::types::primitives::{BLSSignature, Domain, ForkVersion, Root, Slot};
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
//
// All functions derive the current period from `store_finalized_slot`
// (the canonical period source).
// =============================================================================

/// Select the appropriate sync committee for `signature_slot`.
///
/// Keyed off the store's finalized slot (canonical period source).
/// - signature period == store_period → current committee
/// - signature period == store_period + 1, next known → next committee
/// - otherwise → error
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
/// `finalized_period` should be `store.finalized_sync_committee_period(spec)`
/// evaluated at the time the guard is applied (i.e. after the finalized header
/// and rotation logic have already run in `apply_light_client_update`).
///
/// On success returns `Ok(Some(verified_committee))` for the caller to
/// set on the store.  Returns `Ok(None)` when the update is skipped
/// (no committee data, or next already known).
pub(crate) fn learn_next_sync_committee_from_update(
    update: &LightClientUpdate,
    finalized_period: u64,
    next_committee_known: bool,
    chain_spec: &ChainSpec,
) -> Result<Option<SyncCommittee>> {
    if !update.has_sync_committee_update() {
        return Ok(None);
    }

    // Once next_sync_committee is known it is only consumed during a
    // finalized-boundary rotation.  Don't overwrite it.
    if next_committee_known {
        return Ok(None);
    }

    let update_period = chain_spec.slot_to_sync_committee_period(update.attested_header.slot());
    let attested_next_committee = update.next_sync_committee.as_ref().unwrap();

    // Defensive invariant: only learn `next_sync_committee` when
    // `attested_period == finalized_period` (store period). This should
    // already be enforced by validation; keep as a guard against future changes.
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
        update.attested_header.slot(),
        update.attested_header.state_root(),
        chain_spec,
    )?;

    Ok(Some(attested_next_committee.clone()))
}

/// Verify a sync aggregate signature.
///
/// The caller supplies the correct committee (via `committee_for_slot`)
/// and the `genesis_validators_root` from the store.
///
/// `sync_committee_bits` is spec-sized (its length must match the committee).
pub(crate) fn verify_sync_aggregate(
    committee: &SyncCommittee,
    signature_slot: Slot,
    attested_header_root: Root,
    sync_committee_bits: &[bool],
    sync_committee_signature: &BLSSignature,
    genesis_validators_root: Root,
    chain_spec: &ChainSpec,
) -> Result<bool> {
    let participating_pubkeys = committee.participating_pubkeys(sync_committee_bits)?;

    let domain =
        compute_sync_committee_domain_for_slot(signature_slot, genesis_validators_root, chain_spec);
    let signing_root = compute_signing_root(attested_header_root, domain);

    // An empty pubkey set is handled by `verify_aggregate_signature` (returns false).
    Ok(bls::verify_aggregate_signature(
        &participating_pubkeys,
        &signing_root,
        sync_committee_signature,
    ))
}

/// Whether committee rotation should happen for this update (invariant I-2).
///
/// Rotation happens iff the update's finalized period is exactly one past the
/// store period and the next committee is known. This is the single predicate
/// used by both `apply_light_client_update` and the rotation tests — keep it the
/// only place this condition is expressed.
pub(crate) fn should_rotate(
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

/// SigningData container as per Ethereum consensus spec
/// Used to compute the signing root for BLS signatures
#[derive(tree_hash_derive::TreeHash)]
struct SigningData {
    object_root: Root,
    domain: Domain,
}

/// Compute signing root for BLS signature as per beacon chain specification
/// Uses TreeHash derive for spec-compliant hash_tree_root computation
fn compute_signing_root(object_root: Root, domain: Domain) -> Root {
    use tree_hash::TreeHash;

    let signing_data = SigningData {
        object_root,
        domain,
    };
    let root = signing_data.tree_hash_root();

    let mut signing_root = [0u8; 32];
    signing_root.copy_from_slice(root.as_bytes());
    signing_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::consensus::SyncCommittee;

    fn test_committee(agg: u8) -> SyncCommittee {
        SyncCommittee::from_parts(vec![[1u8; 48]; 32], [agg; 48]).unwrap()
    }

    #[test]
    fn test_committee_for_slot_selection() {
        let chain_spec = ChainSpec::mainnet();
        let current = test_committee(2);
        let next = test_committee(3); // distinguishable by aggregate

        // Current period slots → current committee
        let got = committee_for_slot(0, 0, &current, Some(&next), &chain_spec).unwrap();
        assert_eq!(got.aggregate_pubkey(), current.aggregate_pubkey());

        let got = committee_for_slot(8191, 0, &current, Some(&next), &chain_spec).unwrap();
        assert_eq!(got.aggregate_pubkey(), current.aggregate_pubkey());

        // Next period slots → next committee (when known)
        let got = committee_for_slot(8192, 0, &current, Some(&next), &chain_spec).unwrap();
        assert_eq!(got.aggregate_pubkey(), next.aggregate_pubkey());

        // Next period slots → error when next is None
        assert!(committee_for_slot(8192, 0, &current, None, &chain_spec).is_err());

        // Way-out-of-range period → error
        assert!(committee_for_slot(16384, 0, &current, Some(&next), &chain_spec).is_err());
    }

    #[test]
    fn test_rotation_gating() {
        let chain_spec = ChainSpec::mainnet();
        let store_period = 0;

        // Should not rotate without next committee
        assert!(!should_rotate(8192, store_period, false, &chain_spec));

        // Should rotate when next is known and slot crosses boundary
        assert!(should_rotate(8192, store_period, true, &chain_spec));

        // Should not rotate when finalized period hasn't advanced
        assert!(!should_rotate(100, store_period, true, &chain_spec));
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

        let signing_root1 = compute_signing_root(message, domain);
        let signing_root2 = compute_signing_root(message, domain);

        // Should be deterministic
        assert_eq!(signing_root1, signing_root2);

        // Should change with different message
        let different_message = [9u8; 32];
        let signing_root3 = compute_signing_root(different_message, domain);
        assert_ne!(signing_root1, signing_root3);

        // Should change with different domain
        let different_domain = [10u8; 32];
        let signing_root4 = compute_signing_root(message, different_domain);
        assert_ne!(signing_root1, signing_root4);
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
        let signing_root = compute_signing_root(message, domain);

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

        // Verify against the signing root via the production BLS path.
        assert!(
            bls::verify_aggregate_signature(&public_keys, &signing_root, &signature_bytes),
            "should verify successfully"
        );

        // Wrong message -> different signing root -> fails.
        let wrong_message = [43u8; 32];
        let wrong_message_root = compute_signing_root(wrong_message, domain);
        assert!(
            !bls::verify_aggregate_signature(&public_keys, &wrong_message_root, &signature_bytes),
            "wrong message should fail verification"
        );

        // Wrong domain -> different signing root -> fails.
        let wrong_domain = compute_beacon_domain(
            DOMAIN_BEACON_PROPOSER,
            fork_version,
            genesis_validators_root,
        );
        let wrong_domain_root = compute_signing_root(message, wrong_domain);
        assert!(
            !bls::verify_aggregate_signature(&public_keys, &wrong_domain_root, &signature_bytes),
            "wrong domain should fail verification"
        );
    }

    /// Test that domain computation uses the fork version for the epoch of signature_slot.
    ///
    /// Uses `compute_sync_committee_domain_for_slot`, the same path as production code
    /// (`verify_sync_aggregate`), to compute domains.
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

    /// Regression: rotation must be gated by the finalized period, not the
    /// attested period.  With `has_next = true` and finalized still in period 0,
    /// `should_rotate` must return false even when the attested slot
    /// crosses into period 1.
    #[test]
    fn test_no_rotation_on_attested_period_alone() {
        let chain_spec = ChainSpec::mainnet();
        let store_period = 0;

        // Finalized slot still in period 0
        let finalized_slot: Slot = 100;
        // Attested slot crosses into period 1
        let attested_slot: Slot = 8192;

        assert_eq!(
            chain_spec.slot_to_sync_committee_period(attested_slot),
            1,
            "attested slot should be in period 1"
        );

        // Finalized hasn't advanced → no rotation (even though next is known)
        assert!(
            !should_rotate(finalized_slot, store_period, true, &chain_spec),
            "must NOT rotate when finalized period has not advanced"
        );
    }

    #[test]
    fn test_rejects_next_period_update_when_next_committee_unknown() {
        use crate::types::consensus::{BeaconBlockHeader, SyncAggregate};

        let committee = test_committee(2);
        let chain_spec = ChainSpec::mainnet();
        let finalized_period = 0;

        // Create an update with attested_header in period 1 (slot 8192 on mainnet)
        let attested_header = BeaconBlockHeader::new(8192, 42, [1u8; 32], [2u8; 32], [3u8; 32]);
        let bits = vec![true; 32];
        let sync_aggregate = SyncAggregate::new(bits, [0u8; 96]);
        let update = LightClientUpdate::new(attested_header, sync_aggregate, 8193)
            .with_next_sync_committee(committee, vec![[0u8; 32]; 5]);

        // next_committee_known = false, but update attests to period 1 while
        // finalized period is 0 → rejected by period guard
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
