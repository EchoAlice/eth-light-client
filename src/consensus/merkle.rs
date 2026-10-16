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

/// Spec: `is_valid_light_client_header`, fused with its caller-side `assert`.
pub(crate) fn verify_light_client_header(
    header: &LightClientHeader,
    chain_spec: &ChainSpec,
) -> Result<()> {
    if header.fork() == Fork::Altair || header.fork() == Fork::Bellatrix {
        return Ok(());
    }

    let block_fork = chain_spec.fork_at_slot(header.beacon().slot);
    if block_fork < Fork::Deneb && header.has_blob_gas() {
        return Err(Error::InvalidProof(
            "Header contains non-zeroed blob gas fields".to_string(),
        ));
    }
    if block_fork < Fork::Capella {
        return if header.has_execution_payload() {
            Err(Error::InvalidProof(
                "Header contains non-zeroed execution payload and/or branch".to_string(),
            ))
        } else {
            Ok(())
        };
    }

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

/// Spec: `is_valid_merkle_branch`, fused with its caller-side `assert`.
pub(crate) fn verify_merkle_proof(
    leaf: &Root,
    branch: &[Root],
    gindex: u64,
    root: &Root,
) -> Result<()> {
    let expected_depth = gindex
        .checked_ilog2()
        .ok_or_else(|| Error::Internal("gindex cannot be 0".to_string()))?;

    if branch.len() != expected_depth as usize {
        return Err(Error::InvalidProof(format!(
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

    if current_hash == *root {
        Ok(())
    } else {
        Err(Error::InvalidProof(format!(
            "merkle branch doesn't resolve to root at gindex {gindex}"
        )))
    }
}

#[inline]
pub(crate) fn hash_pair(left: &Root, right: &Root) -> Root {
    ethereum_hashing::hash32_concat(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz_types::FixedVector;

    use crate::chain_spec::ChainSpecConfig;
    use crate::types::consensus::{
        BellatrixLightClientHeader, CapellaExecutionPayloadHeader, CapellaLightClientHeader,
        DenebExecutionPayloadHeader, DenebLightClientHeader, LightClientUpdate,
    };

    fn spec(capella_epoch: u64, deneb_epoch: u64) -> ChainSpec {
        let mut config = ChainSpecConfig::minimal();
        config.bellatrix_fork_epoch = 0;
        config.capella_fork_epoch = capella_epoch;
        config.deneb_fork_epoch = deneb_epoch;
        ChainSpec::try_from_config(config).unwrap()
    }

    fn bellatrix_fixture_header() -> BellatrixLightClientHeader {
        let path = "tests/fixtures/minimal/bellatrix/light_client/sync/light_client_sync/\
        update_0x47c97bfd79102f9616861fde11a204427e5ff3032e9ba6754d77a9fdff9ca1f1_sf.ssz_snappy";
        let compressed = std::fs::read(path).unwrap();
        let bytes = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .unwrap();
        let update = LightClientUpdate::from_ssz(&bytes, Fork::Bellatrix, 32).unwrap();
        match update.attested_header {
            LightClientHeader::Bellatrix(h) => h,
            _ => unreachable!(),
        }
    }

    fn capella_fixture_header() -> CapellaLightClientHeader {
        let path = "tests/fixtures/minimal/capella/light_client/sync/light_client_sync/\
        update_0x068c574b9bcfae81ecae2ab779d14f66761e5d21ac44e4ed2dd49a40da491212_sx.ssz_snappy";
        let compressed = std::fs::read(path).unwrap();
        let bytes = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .unwrap();
        let update = LightClientUpdate::from_ssz(&bytes, Fork::Capella, 32).unwrap();
        match update.attested_header {
            LightClientHeader::Capella(h) => h,
            _ => unreachable!(),
        }
    }

    // A pre-Capella block has no execution payload to prove, so the server
    // fills the slot with defaults and a zero branch.
    fn widened_to_capella(header: BellatrixLightClientHeader) -> CapellaLightClientHeader {
        CapellaLightClientHeader {
            beacon: header.beacon,
            execution: CapellaExecutionPayloadHeader::default(),
            execution_branch: FixedVector::default(),
        }
    }

    fn widened_to_deneb(header: CapellaLightClientHeader) -> DenebLightClientHeader {
        let e = header.execution;
        DenebLightClientHeader {
            beacon: header.beacon,
            execution: DenebExecutionPayloadHeader {
                parent_hash: e.parent_hash,
                fee_recipient: e.fee_recipient,
                state_root: e.state_root,
                receipts_root: e.receipts_root,
                logs_bloom: e.logs_bloom,
                prev_randao: e.prev_randao,
                block_number: e.block_number,
                gas_limit: e.gas_limit,
                gas_used: e.gas_used,
                timestamp: e.timestamp,
                extra_data: e.extra_data,
                base_fee_per_gas: e.base_fee_per_gas,
                block_hash: e.block_hash,
                transactions_root: e.transactions_root,
                withdrawals_root: e.withdrawals_root,
                blob_gas_used: 0,
                excess_blob_gas: 0,
            },
            execution_branch: header.execution_branch,
        }
    }

    #[test]
    fn merkle_branch_validation() {
        let leaf = [1u8; 32];
        let root = [2u8; 32];
        let empty_branch: Vec<Root> = vec![];

        let result = verify_merkle_proof(&root, &empty_branch, 1, &root);
        assert!(result.is_ok());

        let result = verify_merkle_proof(&leaf, &empty_branch, 0, &root);
        assert!(matches!(result, Err(Error::Internal(_))));

        let short_branch = vec![[0u8; 32]; 3];
        let result = verify_merkle_proof(&leaf, &short_branch, 54, &root);
        assert!(matches!(result, Err(Error::InvalidProof(_))));

        let long_branch = vec![[0u8; 32]; 6];
        let result = verify_merkle_proof(&leaf, &long_branch, 54, &root);
        assert!(matches!(result, Err(Error::InvalidProof(_))));
    }

    #[test]
    fn merkle_branch_roundtrip() {
        let (l, r) = ([1u8; 32], [2u8; 32]);
        let root = hash_pair(&l, &r);

        assert!(verify_merkle_proof(&l, &[r], 2, &root).is_ok());
        assert!(verify_merkle_proof(&r, &[l], 3, &root).is_ok());
        assert!(matches!(
            verify_merkle_proof(&l, &[r], 2, &[9u8; 32]),
            Err(Error::InvalidProof(_))
        ));
    }

    #[test]
    fn bellatrix_block_in_capella_container_accepted_when_empty() {
        let widened = widened_to_capella(bellatrix_fixture_header());
        let bellatrix_era = spec(u64::MAX, u64::MAX);

        let empty = LightClientHeader::Capella(widened.clone());
        assert!(verify_light_client_header(&empty, &bellatrix_era).is_ok());

        let mut flipped = widened.clone();
        flipped.execution.block_number = 1;
        let nonzero_execution = LightClientHeader::Capella(flipped);
        assert!(matches!(
            verify_light_client_header(&nonzero_execution, &bellatrix_era),
            Err(Error::InvalidProof(_))
        ));

        let mut flipped = widened;
        flipped.execution_branch[0] = [1u8; 32];
        let nonzero_branch = LightClientHeader::Capella(flipped);
        assert!(matches!(
            verify_light_client_header(&nonzero_branch, &bellatrix_era),
            Err(Error::InvalidProof(_))
        ));
    }

    #[test]
    fn capella_block_in_deneb_container_hashes_as_capella() {
        let header = LightClientHeader::Deneb(widened_to_deneb(capella_fixture_header()));

        assert!(verify_light_client_header(&header, &spec(0, u64::MAX)).is_ok());
        // Schedule says Deneb-era: hashed as 17 fields, same branch must fail.
        assert!(matches!(
            verify_light_client_header(&header, &spec(0, 0)),
            Err(Error::InvalidProof(_))
        ));
    }

    #[test]
    fn capella_block_with_blob_gas_is_rejected() {
        let mut widened = widened_to_deneb(capella_fixture_header());
        widened.execution.blob_gas_used = 1;
        let header = LightClientHeader::Deneb(widened);

        assert!(matches!(
            verify_light_client_header(&header, &spec(0, u64::MAX)),
            Err(Error::InvalidProof(_))
        ));
    }
}
