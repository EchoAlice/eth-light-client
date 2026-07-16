//! The verified light client state maintained across updates.

use crate::config::ChainSpec;
use crate::types::consensus::{LightClientHeader, SyncCommittee};
use crate::types::primitives::Root;

/// Light client store maintaining the trusted state.
///
/// This is the persistent state that a light client maintains across updates.
/// It includes the trusted headers, sync committees, and chain identity.
/// Headers are fork-aware [`LightClientHeader`] values.
#[derive(Debug, Clone)]
pub(crate) struct LightClientStore {
    pub finalized_header: LightClientHeader,
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: Option<SyncCommittee>,
    pub optimistic_header: LightClientHeader,
    pub genesis_validators_root: Root,
}

impl LightClientStore {
    pub fn new(
        finalized_header: LightClientHeader,
        current_sync_committee: SyncCommittee,
        genesis_validators_root: Root,
    ) -> Self {
        Self {
            optimistic_header: finalized_header.clone(),
            finalized_header,
            current_sync_committee,
            next_sync_committee: None,
            genesis_validators_root,
        }
    }

    /// Get the sync committee period derived from the finalized header.
    ///
    /// This is the canonical "store period" per consensus-specs.
    pub(crate) fn finalized_sync_committee_period(&self, spec: &ChainSpec) -> u64 {
        spec.slot_to_sync_committee_period(self.finalized_header.slot())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::consensus::BeaconBlockHeader;

    fn test_header() -> LightClientHeader {
        LightClientHeader::altair(BeaconBlockHeader::new(
            1000,      // slot
            42,        // proposer_index
            [1u8; 32], // parent_root
            [2u8; 32], // state_root
            [3u8; 32], // body_root
        ))
    }

    fn test_committee() -> SyncCommittee {
        SyncCommittee::from_parts(vec![[1u8; 48]; 32], [2u8; 48]).unwrap()
    }

    #[test]
    fn test_light_client_store() {
        let spec = ChainSpec::mainnet();
        let genesis_validators_root = [0u8; 32];

        let store = LightClientStore::new(test_header(), test_committee(), genesis_validators_root);
        // slot 1000 -> epoch 31 -> period 0
        assert_eq!(store.finalized_sync_committee_period(&spec), 0);
        assert_eq!(store.genesis_validators_root, genesis_validators_root);
    }
}
