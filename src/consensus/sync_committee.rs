use crate::chain_spec::ChainSpec;
use crate::types::consensus::{LightClientUpdate, SyncCommittee};
use crate::types::primitives::{Domain, ForkVersion, Root};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub(crate) const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];

// TODO: Delete this helper function. `process_*` and `apply_*` should hold this logic
pub(crate) fn learn_next_sync_committee(
    update: &LightClientUpdate,
    _finalized_period: u64,
    next_committee_known: bool,
    _chain_spec: &ChainSpec,
) -> Option<SyncCommittee> {
    if next_committee_known {
        return None;
    }
    let next = update.next_sync_committee.as_ref()?;

    Some(next.committee.clone())
}

#[derive(TreeHash)]
struct SigningData {
    object_root: Root,
    domain: Domain,
}

// TODO: Should this be a method of SigningData? Should SigningData be called SigningRoot?
pub(crate) fn compute_signing_root(object_root: Root, domain: Domain) -> Root {
    let signing_data = SigningData {
        object_root,
        domain,
    };
    let root = signing_data.tree_hash_root();

    let mut signing_root = [0u8; 32];
    signing_root.copy_from_slice(root.as_bytes());
    signing_root
}

pub(crate) fn compute_domain(
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

#[derive(TreeHash)]
struct ForkData {
    current_version: ForkVersion,
    genesis_validators_root: Root,
}

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
