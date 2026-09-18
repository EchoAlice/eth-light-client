use ethereum_hashing::hash32_concat;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::types::primitives::{Domain, ForkDigest, ForkVersion, Root};

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

pub(crate) fn compute_fork_digest(
    fork_version: ForkVersion,
    genesis_validators_root: Root,
) -> ForkDigest {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);

    let mut digest = [0u8; 4];
    digest.copy_from_slice(&fork_data_root[0..4]);

    digest
}

// TODO(#37): caller lands with ChainSpec's blob-schedule walk; drop the allow then.
#[allow(dead_code)]
pub(crate) fn compute_bpo_fork_digest(
    fork_version: ForkVersion,
    genesis_validators_root: Root,
    bpo_epoch: u64,
    max_blobs_per_block: u64,
) -> ForkDigest {
    let base_digest = compute_fork_digest(fork_version, genesis_validators_root);
    let mask = hash32_concat(&bpo_epoch.to_le_bytes(), &max_blobs_per_block.to_le_bytes());

    // Spec xors the full 32-byte fork data root with the mask, then truncates.
    // XOR is bytewise, so it commutes with truncation — mixing on the already-
    // truncated digest is bit-identical and lets us reuse compute_fork_digest.
    let mut digest = base_digest;
    for i in 0..4 {
        digest[i] ^= mask[i];
    }
    digest
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
