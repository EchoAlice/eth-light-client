use crate::chain_spec::ChainSpec;
use crate::consensus::merkle::verify_merkle_proof;
use crate::error::{Error, Result};
use crate::types::consensus::{LightClientUpdate, SyncCommittee};
use crate::types::primitives::{Domain, ForkVersion, Root};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub(crate) const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];

pub(crate) fn learn_next_sync_committee(
    update: &LightClientUpdate,
    finalized_period: u64,
    next_committee_known: bool,
    chain_spec: &ChainSpec,
) -> Result<Option<SyncCommittee>> {
    if !update.has_sync_committee_update() || next_committee_known {
        return Ok(None);
    }

    let update_period = chain_spec.slot_to_sync_committee_period(update.attested_header.slot());
    let next = update.next_sync_committee.as_ref().unwrap();

    if update_period != finalized_period {
        return Err(Error::InvalidInput(format!(
            "Cannot learn next sync committee from period {}; \
             next committee is unknown, so update must attest to finalized period {}",
            update_period, finalized_period
        )));
    }

    verify_merkle_proof(
        &next.committee.hash_tree_root(),
        &next.branch,
        chain_spec
            .fork_at_slot(update.attested_header.slot())
            .next_sync_committee_gindex(),
        update.attested_header.state_root(),
    )?;

    Ok(Some(next.committee.clone()))
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

#[derive(TreeHash)]
struct SigningData {
    object_root: Root,
    domain: Domain,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_committee(agg: u8) -> SyncCommittee {
        SyncCommittee::from_parts(vec![[1u8; 48]; 32], [agg; 48]).unwrap()
    }

    #[test]
    fn rejects_next_period_update_when_next_committee_unknown() {
        use crate::types::consensus::{BeaconBlockHeader, SyncAggregate};

        let committee = test_committee(2);
        let chain_spec = ChainSpec::mainnet();
        let finalized_period = 0;
        let attested_header = BeaconBlockHeader {
            slot: 8192,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body_root: [3u8; 32],
        };
        let bits = vec![true; 32];
        let sync_aggregate = SyncAggregate::new(bits, [0u8; 96]);
        let update = LightClientUpdate::new(attested_header, sync_aggregate, 8193)
            .with_next_sync_committee(committee, vec![[0u8; 32]; 5]);

        // next_committee_known = false, but update attests to period 1 while
        // finalized period is 0 → rejected by period guard
        let result = learn_next_sync_committee(&update, finalized_period, false, &chain_spec);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("next committee is unknown"),
            "Expected guard error, got: {}",
            err_msg
        );
    }
}
