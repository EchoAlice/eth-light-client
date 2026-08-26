use crate::types::primitives::{Domain, ForkVersion, Root};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub(crate) const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];

#[derive(TreeHash)]
struct SigningData {
    object_root: Root,
    domain: Domain,
}

pub(crate) fn compute_signing_root(object_root: Root, domain: Domain) -> Root {
    SigningData {
        object_root,
        domain,
    }
    .tree_hash_root()
    .0
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
    ForkData {
        current_version: fork_version,
        genesis_validators_root,
    }
    .tree_hash_root()
    .0
}
