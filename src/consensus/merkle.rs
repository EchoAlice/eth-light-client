use crate::chain_spec::{ChainSpec, Fork};
use crate::error::{Error, Result};
use crate::types::consensus::LightClientHeader;
use crate::types::primitives::Root;

// The fork defines the SSZ schema. The SSZ schema defines the index.
impl Fork {
    pub(crate) const fn current_sync_committee_gindex(&self) -> u64 {
        match self {
            Fork::Altair | Fork::Bellatrix | Fork::Capella | Fork::Deneb => 54,
            Fork::Electra | Fork::Fulu => 86,
        }
    }

    pub(crate) const fn next_sync_committee_gindex(&self) -> u64 {
        match self {
            Fork::Altair | Fork::Bellatrix | Fork::Capella | Fork::Deneb => 55,
            Fork::Electra | Fork::Fulu => 87,
        }
    }

    pub(crate) const fn finalized_root_gindex(&self) -> u64 {
        match self {
            Fork::Altair | Fork::Bellatrix | Fork::Capella | Fork::Deneb => 105,
            Fork::Electra | Fork::Fulu => 169,
        }
    }

    pub(crate) const fn execution_payload_gindex(&self) -> u64 {
        match self {
            // No execution payload in the body before Capella; callers return before asking.
            Fork::Altair | Fork::Bellatrix => unreachable!(),
            Fork::Capella | Fork::Deneb | Fork::Electra | Fork::Fulu => 25,
        }
    }
}

/// Spec: `is_valid_light_client_header`.
pub(crate) fn verify_light_client_header(
    header: &LightClientHeader,
    chain_spec: &ChainSpec,
) -> Result<()> {
    if header.fork() == Fork::Altair || header.fork() == Fork::Bellatrix {
        return Ok(());
    }

    let block_fork = chain_spec.fork_at_slot(header.beacon().slot);
    // TODO: Implement the container checks that the spec has for zeroed fields

    verify_merkle_proof(
        &get_lc_execution_root(header, block_fork),
        header.execution_branch(),
        block_fork.execution_payload_gindex(),
        &header.beacon().body_root,
    )
}

/// Hashes execution payload header the way it was committed within `body_root`.
fn get_lc_execution_root(header: &LightClientHeader, block_fork: Fork) -> Root {
    if header.fork() == block_fork {
        return header.execution_payload_root();
    }

    // The exception at fork boundaries: The wire's container doesn't match the
    // fork its block was made within.  Deneb container
    match header {
        LightClientHeader::Deneb(h) if block_fork == Fork::Capella => {
            h.execution.to_capella().hash_tree_root()
        }
        _ => header.execution_payload_root(),
    }
}

/// Spec: `is_valid_normalized_merkle_branch`
pub(crate) fn verify_merkle_proof(
    leaf: &Root,
    branch: &[Root],
    gindex: u64,
    root: &Root,
) -> Result<()> {
    // TODO: Implement the logic that's present in spec's normalization

    if is_valid_merkle_branch(leaf, branch, gindex, root)? {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!(
            "merkle branch verification failed at gindex {gindex}"
        )))
    }
}

fn is_valid_merkle_branch(leaf: &Root, branch: &[Root], gindex: u64, root: &Root) -> Result<bool> {
    let expected_depth = gindex
        .checked_ilog2()
        .ok_or_else(|| Error::InvalidInput("gindex cannot be 0".to_string()))?;

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
}
