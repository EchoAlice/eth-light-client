//! Beacon State Merkle Verification
//!
//! Implements SSZ merkle verification using production-grade libraries:
//! - `tree_hash`: TreeHash trait and merkle root computation (from Lighthouse)
//!
//! This module handles merkle branch verification for light client sync,
//! specifically verifying sync committee and finality proofs against beacon state roots.
//!
//! Generalized indices are obtained from `ChainSpec` to support future fork transitions.

use crate::config::ChainSpec;
use crate::error::{Error, Result};
use crate::types::consensus::SyncCommittee;
use crate::types::primitives::Root;
use crate::types::primitives::Slot;
use tree_hash::TreeHash;

/// Compute SSZ hash_tree_root for SyncCommittee using tree_hash library.
///     (SyncCommittee is an SSZ Container:)
fn compute_sync_committee_root(spec: &ChainSpec, committee: &SyncCommittee) -> Root {
    let n = spec.sync_committee_size;

    // Step 1 & 2: Compute hash_tree_root for each of the first N pubkeys directly into a single buffer.
    let mut pubkeys_bytes = Vec::with_capacity(32 * n);
    for pk in &committee.pubkeys.as_ref()[..n] {
        pubkeys_bytes.extend_from_slice(pk.tree_hash_root().as_bytes());
    }

    // Merkleize pubkey roots as Vector[BLSPubkey, N]
    let pubkeys_root_hash = tree_hash::merkle_root(&pubkeys_bytes, n);
    let mut pubkeys_root = [0u8; 32];
    pubkeys_root.copy_from_slice(pubkeys_root_hash.as_bytes());

    // Step 3: Compute hash_tree_root for aggregate_pubkey
    let aggregate_hash = committee.aggregate_pubkey.tree_hash_root();
    let mut aggregate_root = [0u8; 32];
    aggregate_root.copy_from_slice(aggregate_hash.as_bytes());

    // Step 4: Container root = hash(pubkeys_root || aggregate_root)
    // Use tree_hash::merkle_root on 64 bytes with 2 leaves
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
///
/// Implements the spec's `is_valid_merkle_branch` check for current_sync_committee.
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
///
/// The finality branch proves that `finalized_header.hash_tree_root()` equals the
/// `finalized_checkpoint.root` field in the beacon state at `attested_header.state_root`.
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
/// Reference: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#is_valid_merkle_branch
///
/// The branch length must equal `floor(log2(gindex))` exactly.
fn is_valid_merkle_branch(leaf: &Root, branch: &[Root], gindex: u64, root: &Root) -> Result<bool> {
    if gindex == 0 {
        return Err(Error::InvalidInput("gindex cannot be 0".to_string()));
    }

    if gindex == 1 {
        // Root node - leaf must equal root
        return Ok(leaf == root);
    }

    // Calculate expected branch length: depth = floor(log2(gindex))
    // For gindex > 0: floor(log2(gindex)) = 63 - leading_zeros
    // Use explicit 63u32 for clarity (u64 has 64 bits, minus 1 for 0-indexing)
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
        // Determine if we're the left or right child
        let is_right_child = (current_gindex % 2) == 1;

        // Hash pair using tree_hash library (no heap allocation)
        current_hash = if is_right_child {
            hash_pair(sibling_hash, &current_hash)
        } else {
            hash_pair(&current_hash, sibling_hash)
        };

        // Move up to parent
        current_gindex /= 2;
    }

    // After traversing the full branch, we should be at the root (gindex 1)
    debug_assert_eq!(
        current_gindex, 1,
        "merkle branch traversal should end at root"
    );

    Ok(current_hash == *root)
}

/// Hash two 32-byte roots together using tree_hash library.
///
/// Uses a fixed stack buffer (no heap allocation).
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gindex_from_chain_spec() {
        let spec = ChainSpec::minimal();
        // Altair gindices
        assert_eq!(spec.current_sync_committee_gindex(0), 54);
        assert_eq!(spec.next_sync_committee_gindex(0), 55);
        assert_eq!(spec.finalized_root_gindex(0), 105);
    }

    #[test]
    fn test_merkle_branch_validation() {
        let leaf = [1u8; 32];
        let root = [2u8; 32];
        let empty_branch: Vec<Root> = vec![];

        // Test root node case (gindex = 1)
        let result = is_valid_merkle_branch(&root, &empty_branch, 1, &root);
        assert!(result.unwrap());

        // Test invalid gindex
        let result = is_valid_merkle_branch(&leaf, &empty_branch, 0, &root);
        assert!(result.is_err());

        // Test branch length mismatch
        // gindex=54 has depth=5 (floor(log2(54)) = 5), so needs exactly 5 elements
        let short_branch = vec![[0u8; 32]; 3];
        let result = is_valid_merkle_branch(&leaf, &short_branch, 54, &root);
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_pair() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        let result = hash_pair(&left, &right);

        // Should produce a deterministic hash
        assert_ne!(result, [0u8; 32]);
        assert_ne!(result, left);
        assert_ne!(result, right);

        // Should be deterministic
        let result2 = hash_pair(&left, &right);
        assert_eq!(result, result2);

        // Should be asymmetric
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
        // Minimal uses N=32, mainnet uses N=512
        // Even with same data, roots should differ due to different N
        let minimal_spec = ChainSpec::minimal();
        let mainnet_spec = ChainSpec::mainnet();

        let committee = SyncCommittee::new(Box::new([[1u8; 48]; 512]), [2u8; 48]);

        let minimal_root = compute_sync_committee_root(&minimal_spec, &committee);
        let mainnet_root = compute_sync_committee_root(&mainnet_spec, &committee);

        // Roots should be different because minimal uses only first 32 pubkeys
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
    /// Uses the minimal preset test vectors.
    #[test]
    fn test_sync_committee_root_against_spec_fixture() {
        use crate::test_utils::SpecTestLoader;

        let spec = ChainSpec::minimal();
        let loader = SpecTestLoader::minimal_altair_sync();
        let bootstrap = loader.load_bootstrap().expect("Failed to load bootstrap");

        // Compute sync committee root using our hardened function
        let computed_root = compute_sync_committee_root(&spec, &bootstrap.sync_committee);

        // Verify against the state root using the branch
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
