//! Beacon State Merkle Verification
//!
//! Implements SSZ merkle verification using `tree_hash` from Lighthouse.
//! Handles merkle branch verification for light client sync:
//! sync committee proofs, finality proofs against beacon state roots.
//!
//! Generalized indices are obtained from `ChainSpec` to support fork transitions.

use crate::config::ChainSpec;
use crate::error::{Error, Result};
use crate::types::consensus::SyncCommittee;
use crate::types::primitives::Root;
use crate::types::primitives::Slot;
use tree_hash::TreeHash;

/// Compute SSZ hash_tree_root for SyncCommittee using tree_hash library.
///     (SyncCommittee is an SSZ Container:)
fn compute_sync_committee_root(spec: &ChainSpec, committee: &SyncCommittee) -> Root {
    let n = spec.sync_committee_size();

    // Hash each of the first N pubkeys
    let mut pubkeys_bytes = Vec::with_capacity(32 * n);
    for pk in &committee.pubkeys.as_ref()[..n] {
        pubkeys_bytes.extend_from_slice(pk.tree_hash_root().as_bytes());
    }

    // Merkleize pubkey roots as Vector[BLSPubkey, N]
    let pubkeys_root_hash = tree_hash::merkle_root(&pubkeys_bytes, n);
    let mut pubkeys_root = [0u8; 32];
    pubkeys_root.copy_from_slice(pubkeys_root_hash.as_bytes());

    // Compute hash_tree_root for aggregate_pubkey
    let aggregate_hash = committee.aggregate_pubkey.tree_hash_root();
    let mut aggregate_root = [0u8; 32];
    aggregate_root.copy_from_slice(aggregate_hash.as_bytes());

    // Container root = hash(pubkeys_root || aggregate_root)
    let mut container_data = [0u8; 64];
    container_data[..32].copy_from_slice(&pubkeys_root);
    container_data[32..].copy_from_slice(&aggregate_root);
    let container_hash = tree_hash::merkle_root(&container_data, 2);

    let mut result = [0u8; 32];
    result.copy_from_slice(container_hash.as_bytes());
    result
}

/// Verify that a sync committee is properly embedded in a beacon state root
/// using the provided merkle branch proof (bootstrap verification).
pub(crate) fn verify_bootstrap_sync_committee(
    sync_committee: &SyncCommittee,
    sync_committee_branch: &[Root],
    header_slot: Slot,
    finalized_state_root: &Root,
    spec: &ChainSpec,
) -> Result<()> {
    let sync_committee_root = compute_sync_committee_root(spec, sync_committee);
    let gindex = spec.current_sync_committee_gindex(header_slot);

    let is_valid = is_valid_merkle_branch(
        &sync_committee_root,
        sync_committee_branch,
        gindex,
        finalized_state_root,
    )?;

    if !is_valid {
        return Err(Error::InvalidInput(
            "Sync committee merkle branch verification failed".to_string(),
        ));
    }

    Ok(())
}

/// Verify that the next sync committee is properly embedded in the attested header's state root.
pub(crate) fn verify_next_sync_committee(
    next_sync_committee: &SyncCommittee,
    next_sync_committee_branch: &[Root],
    attested_header_slot: Slot,
    attested_state_root: &Root,
    spec: &ChainSpec,
) -> Result<()> {
    let sync_committee_root = compute_sync_committee_root(spec, next_sync_committee);
    let gindex = spec.next_sync_committee_gindex(attested_header_slot);

    let is_valid = is_valid_merkle_branch(
        &sync_committee_root,
        next_sync_committee_branch,
        gindex,
        attested_state_root,
    )?;

    if !is_valid {
        return Err(Error::InvalidInput(
            "Next sync committee merkle branch verification failed".to_string(),
        ));
    }

    Ok(())
}

/// Verify that the finalized header root is properly embedded in the attested header's state root.
pub(crate) fn verify_finality_branch(
    finalized_header_root: &Root,
    finality_branch: &[Root],
    attested_header_slot: Slot,
    attested_state_root: &Root,
    spec: &ChainSpec,
) -> Result<()> {
    let gindex = spec.finalized_root_gindex(attested_header_slot);

    let is_valid = is_valid_merkle_branch(
        finalized_header_root,
        finality_branch,
        gindex,
        attested_state_root,
    )?;

    if !is_valid {
        return Err(Error::InvalidInput(
            "Finality branch merkle verification failed".to_string(),
        ));
    }

    Ok(())
}

/// Verify a standard SSZ merkle branch proof.
///
/// Implements `is_valid_merkle_branch` from the Ethereum consensus specs.
/// The branch length must equal `floor(log2(gindex))` exactly.
fn is_valid_merkle_branch(leaf: &Root, branch: &[Root], gindex: u64, root: &Root) -> Result<bool> {
    if gindex == 0 {
        return Err(Error::InvalidInput("gindex cannot be 0".to_string()));
    }

    if gindex == 1 {
        return Ok(leaf == root);
    }

    // depth = floor(log2(gindex))
    let expected_depth = 63u32 - gindex.leading_zeros();

    if branch.len() != expected_depth as usize {
        return Err(Error::InvalidInput(format!(
            "Branch length {} doesn't match expected depth {} for gindex {}",
            branch.len(),
            expected_depth,
            gindex
        )));
    }

    // Reconstruct root by walking up the tree
    let mut current_hash = *leaf;
    let mut current_gindex = gindex;

    for sibling_hash in branch {
        let is_right_child = (current_gindex % 2) == 1;

        current_hash = if is_right_child {
            hash_pair(sibling_hash, &current_hash)
        } else {
            hash_pair(&current_hash, sibling_hash)
        };

        current_gindex /= 2;
    }

    debug_assert_eq!(
        current_gindex, 1,
        "merkle branch traversal should end at root"
    );

    Ok(current_hash == *root)
}

/// Hash two 32-byte roots together using tree_hash library.
#[inline]
fn hash_pair(left: &Root, right: &Root) -> Root {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left);
    data[32..].copy_from_slice(right);

    let hash = tree_hash::merkle_root(&data, 2);

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gindex_from_chain_spec() {
        let spec = ChainSpec::minimal();
        assert_eq!(spec.current_sync_committee_gindex(0), 54);
        assert_eq!(spec.next_sync_committee_gindex(0), 55);
        assert_eq!(spec.finalized_root_gindex(0), 105);
    }

    #[test]
    fn test_merkle_branch_validation() {
        let leaf = [1u8; 32];
        let root = [2u8; 32];
        let empty_branch: Vec<Root> = vec![];

        // Root node case (gindex = 1)
        let result = is_valid_merkle_branch(&root, &empty_branch, 1, &root);
        assert!(result.unwrap());

        // Invalid gindex
        let result = is_valid_merkle_branch(&leaf, &empty_branch, 0, &root);
        assert!(result.is_err());

        // Branch length mismatch (gindex=54, depth=5)
        let short_branch = vec![[0u8; 32]; 3];
        let result = is_valid_merkle_branch(&leaf, &short_branch, 54, &root);
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_pair() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        let result = hash_pair(&left, &right);
        assert_ne!(result, [0u8; 32]);
        assert_ne!(result, left);
        assert_ne!(result, right);

        // Deterministic
        let result2 = hash_pair(&left, &right);
        assert_eq!(result, result2);

        // Asymmetric
        let result_reversed = hash_pair(&right, &left);
        assert_ne!(result, result_reversed);
    }

    #[test]
    fn test_sync_committee_root_deterministic() {
        let spec = ChainSpec::minimal();
        let committee = SyncCommittee::new(Box::new([[1u8; 48]; 512]), [2u8; 48]);

        let root1 = compute_sync_committee_root(&spec, &committee);
        let root2 = compute_sync_committee_root(&spec, &committee);

        assert_eq!(root1, root2);
        assert_ne!(root1, [0u8; 32]);
    }

    #[test]
    fn test_sync_committee_root_uses_declared_n() {
        let minimal_spec = ChainSpec::minimal();
        let mainnet_spec = ChainSpec::mainnet();

        let committee = SyncCommittee::new(Box::new([[1u8; 48]; 512]), [2u8; 48]);

        let minimal_root = compute_sync_committee_root(&minimal_spec, &committee);
        let mainnet_root = compute_sync_committee_root(&mainnet_spec, &committee);

        // Roots differ because minimal uses only first 32 pubkeys
        assert_ne!(minimal_root, mainnet_root);
    }

    #[test]
    fn test_bootstrap_verification_structure() {
        let spec = ChainSpec::minimal();
        let sync_committee = SyncCommittee::new(Box::new([[0u8; 48]; 512]), [0u8; 48]);

        let empty_branch: Vec<Root> = vec![];
        let slot = 1000;
        let state_root = [0u8; 32];

        // Should fail with branch length mismatch (gindex 54 needs 5 elements)
        let result = verify_bootstrap_sync_committee(
            &sync_committee,
            &empty_branch,
            slot,
            &state_root,
            &spec,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_next_sync_committee_verification_structure() {
        let spec = ChainSpec::minimal();
        let sync_committee = SyncCommittee::new(Box::new([[1u8; 48]; 512]), [2u8; 48]);

        let empty_branch: Vec<Root> = vec![];
        let slot = 1000;
        let state_root = [0u8; 32];

        // Should fail with branch length mismatch (gindex 55 needs 5 elements)
        let result =
            verify_next_sync_committee(&sync_committee, &empty_branch, slot, &state_root, &spec);
        assert!(result.is_err());
    }

    #[test]
    fn test_finality_branch_verification_structure() {
        let spec = ChainSpec::minimal();
        let finalized_header_root = [1u8; 32];
        let empty_branch: Vec<Root> = vec![];
        let slot = 1000;
        let state_root = [0u8; 32];

        // Should fail with branch length mismatch (gindex 105 needs 6 elements)
        let result = verify_finality_branch(
            &finalized_header_root,
            &empty_branch,
            slot,
            &state_root,
            &spec,
        );
        assert!(result.is_err());
    }

    /// Test that sync committee root computation matches spec fixtures.
    #[test]
    fn test_sync_committee_root_against_spec_fixture() {
        use crate::test_utils::SpecTestLoader;

        let spec = ChainSpec::minimal();
        let loader = SpecTestLoader::minimal_altair_sync();
        let bootstrap = loader.load_bootstrap().expect("Failed to load bootstrap");

        let computed_root = compute_sync_committee_root(&spec, &bootstrap.sync_committee);

        let gindex = spec.current_sync_committee_gindex(bootstrap.header.slot);
        let is_valid = is_valid_merkle_branch(
            &computed_root,
            &bootstrap.branch,
            gindex,
            &bootstrap.header.state_root,
        )
        .expect("Branch verification should not error");

        assert!(
            is_valid,
            "Computed sync committee root should verify against spec fixture"
        );
    }
}
