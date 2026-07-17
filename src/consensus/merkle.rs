use crate::config::ChainSpec;
use crate::error::{Error, Result};
use crate::types::consensus::{LightClientHeader, SyncCommittee};
use crate::types::primitives::{Root, Slot};

pub(crate) fn verify_bootstrap_sync_committee(
    sync_committee: &SyncCommittee,
    sync_committee_branch: &[Root],
    header_slot: Slot,
    finalized_state_root: &Root,
    spec: &ChainSpec,
) -> Result<()> {
    verify_merkle_branch(
        &sync_committee.hash_tree_root(),
        sync_committee_branch,
        spec.current_sync_committee_gindex(header_slot),
        finalized_state_root,
        "current sync committee",
    )
}

pub(crate) fn verify_next_sync_committee(
    next_sync_committee: &SyncCommittee,
    next_sync_committee_branch: &[Root],
    attested_header_slot: Slot,
    attested_state_root: &Root,
    spec: &ChainSpec,
) -> Result<()> {
    verify_merkle_branch(
        &next_sync_committee.hash_tree_root(),
        next_sync_committee_branch,
        spec.next_sync_committee_gindex(attested_header_slot),
        attested_state_root,
        "next sync committee",
    )
}

pub(crate) fn verify_finality_branch(
    finalized_header_root: &Root,
    finality_branch: &[Root],
    attested_header_slot: Slot,
    attested_state_root: &Root,
    spec: &ChainSpec,
) -> Result<()> {
    verify_merkle_branch(
        finalized_header_root,
        finality_branch,
        spec.finalized_root_gindex(attested_header_slot),
        attested_state_root,
        "finality branch",
    )
}

pub(crate) fn validate_light_client_header(header: &LightClientHeader) -> Result<()> {
    match header {
        LightClientHeader::Altair(_) | LightClientHeader::Bellatrix(_) => Ok(()),
        LightClientHeader::Capella(h) => {
            let execution_root = h.execution.hash_tree_root();
            verify_execution_payload_inclusion(
                &execution_root,
                &h.execution_branch,
                &h.beacon.body_root,
            )
        }
        LightClientHeader::Deneb(h) => {
            let execution_root = h.execution.hash_tree_root();
            verify_execution_payload_inclusion(
                &execution_root,
                &h.execution_branch,
                &h.beacon.body_root,
            )
        }
    }
}

/// Constant for forks Capella -> Electra
const EXECUTION_PAYLOAD_GINDEX: u64 = 25;

pub(crate) fn verify_execution_payload_inclusion(
    execution_root: &Root,
    execution_branch: &[Root],
    body_root: &Root,
) -> Result<()> {
    verify_merkle_branch(
        execution_root,
        execution_branch,
        EXECUTION_PAYLOAD_GINDEX,
        body_root,
        "execution payload",
    )
}

fn verify_merkle_branch(
    leaf: &Root,
    branch: &[Root],
    gindex: u64,
    root: &Root,
    what: &str,
) -> Result<()> {
    if is_valid_merkle_branch(leaf, branch, gindex, root)? {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "{what} merkle branch verification failed"
        )))
    }
}

fn is_valid_merkle_branch(leaf: &Root, branch: &[Root], gindex: u64, root: &Root) -> Result<bool> {
    if gindex == 0 {
        return Err(Error::InvalidInput("gindex cannot be 0".to_string()));
    }

    if gindex == 1 {
        return Ok(branch.is_empty() && leaf == root);
    }

    // depth = floor(log2(gindex)) = 63 - leading_zeros
    let expected_depth = 63u32 - gindex.leading_zeros();

    if branch.len() != expected_depth as usize {
        return Err(Error::InvalidInput(format!(
            "Branch length {} doesn't match expected depth {} for gindex {}",
            branch.len(),
            expected_depth,
            gindex
        )));
    }

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

#[inline]
fn hash_pair(left: &Root, right: &Root) -> Root {
    ethereum_hashing::hash32_concat(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_branch_validation() {
        let leaf = [1u8; 32];
        let root = [2u8; 32];
        let empty_branch: Vec<Root> = vec![];

        let result = is_valid_merkle_branch(&root, &empty_branch, 1, &root);
        assert!(result.unwrap());

        let result = is_valid_merkle_branch(&leaf, &empty_branch, 0, &root);
        assert!(result.is_err());

        // gindex 54 has depth 5, so a 3-element branch is rejected.
        let short_branch = vec![[0u8; 32]; 3];
        let result = is_valid_merkle_branch(&leaf, &short_branch, 54, &root);
        assert!(result.is_err());
    }

    #[test]
    fn test_merkle_branch_roundtrip() {
        // 2-leaf tree: root = hash(l, r). l at gindex 2 (left), r at gindex 3 (right).
        let (l, r) = ([1u8; 32], [2u8; 32]);
        let root = hash_pair(&l, &r);

        assert!(is_valid_merkle_branch(&l, &[r], 2, &root).unwrap());
        assert!(is_valid_merkle_branch(&r, &[l], 3, &root).unwrap());

        // Correct length, wrong root: reconstructs but doesn't match -> Ok(false).
        assert!(!is_valid_merkle_branch(&l, &[r], 2, &[9u8; 32]).unwrap());
    }

    #[test]
    fn test_sync_committee_root_against_spec_fixture() {
        use crate::test_utils::LightClientSyncTest;

        let spec = ChainSpec::minimal();
        let sync_test = LightClientSyncTest::minimal_altair();
        let bootstrap = sync_test
            .load_bootstrap()
            .expect("Failed to load bootstrap");

        let computed_root = bootstrap.current_sync_committee.hash_tree_root();

        let gindex = spec.current_sync_committee_gindex(bootstrap.header.slot());
        let is_valid = is_valid_merkle_branch(
            &computed_root,
            &bootstrap.current_sync_committee_branch,
            gindex,
            bootstrap.header.state_root(),
        )
        .expect("Branch verification should not error");

        assert!(
            is_valid,
            "Computed sync committee root should verify against spec fixture"
        );
    }
}
