use crate::chain_spec::ChainSpec;
use crate::consensus::processor::{LightClientProcessor, UpdateChanges};
use crate::error::{Error, Result};
use crate::types::consensus::{
    BeaconBlockHeader, LightClientBootstrap, LightClientUpdate, SyncCommittee,
};
use crate::types::primitives::{Root, Slot};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct LightClient {
    inner: LightClientProcessor,
}

impl LightClient {
    pub fn new(
        chain_spec: ChainSpec,
        trusted_block_root: Root,
        bootstrap: LightClientBootstrap,
    ) -> Result<Self> {
        let inner = LightClientProcessor::new(chain_spec, trusted_block_root, bootstrap)?;

        Ok(Self { inner })
    }

    pub fn process_update(&mut self, update: LightClientUpdate) -> Result<UpdateOutcome> {
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Internal("Failed to get current time".to_string()))?
            .as_secs();
        let current_slot = self.inner.chain_spec().timestamp_to_slot(current_timestamp);
        self.process_light_client_update(update, current_slot)
    }

    pub fn process_light_client_update(
        &mut self,
        update: LightClientUpdate,
        current_slot: Slot,
    ) -> Result<UpdateOutcome> {
        Ok(self
            .inner
            .process_light_client_update(update, current_slot)?
            .into())
    }

    #[inline]
    pub fn finalized_beacon_block_header(&self) -> &BeaconBlockHeader {
        self.inner.finalized_beacon_block_header()
    }

    #[inline]
    pub fn optimistic_beacon_block_header(&self) -> &BeaconBlockHeader {
        self.inner.optimistic_beacon_block_header()
    }

    #[inline]
    pub fn current_sync_committee(&self) -> &SyncCommittee {
        self.inner.current_sync_committee()
    }

    /// The next period's sync committee, if it has been learned yet.
    #[inline]
    pub fn next_sync_committee(&self) -> Option<&SyncCommittee> {
        self.inner.next_sync_committee()
    }

    #[inline]
    pub fn current_sync_committee_period(&self) -> u64 {
        self.inner.current_sync_committee_period()
    }

    #[inline]
    pub fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }
}

impl std::fmt::Debug for LightClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LightClient")
            .field("finalized_slot", &self.finalized_beacon_block_header().slot)
            .field(
                "optimistic_slot",
                &self.optimistic_beacon_block_header().slot,
            )
            .field("current_period", &self.current_sync_committee_period())
            .field("has_next_committee", &self.next_sync_committee().is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpdateOutcome {
    StateAdvanced {
        finalized_updated: bool,
        optimistic_updated: bool,
        rotated: bool,
        next_committee_learned: bool,
    },
    NoChange,
}

impl UpdateOutcome {
    #[inline]
    pub fn state_changed(&self) -> bool {
        matches!(self, UpdateOutcome::StateAdvanced { .. })
    }

    #[inline]
    pub fn finalized_updated(&self) -> bool {
        matches!(
            self,
            UpdateOutcome::StateAdvanced {
                finalized_updated: true,
                ..
            }
        )
    }

    #[inline]
    pub fn optimistic_updated(&self) -> bool {
        matches!(
            self,
            UpdateOutcome::StateAdvanced {
                optimistic_updated: true,
                ..
            }
        )
    }

    #[inline]
    pub fn rotated(&self) -> bool {
        matches!(self, UpdateOutcome::StateAdvanced { rotated: true, .. })
    }

    #[inline]
    pub fn next_committee_learned(&self) -> bool {
        matches!(
            self,
            UpdateOutcome::StateAdvanced {
                next_committee_learned: true,
                ..
            }
        )
    }
}

impl From<UpdateChanges> for UpdateOutcome {
    fn from(c: UpdateChanges) -> Self {
        if !(c.finalized_updated || c.optimistic_updated || c.rotated || c.next_committee_learned) {
            UpdateOutcome::NoChange
        } else {
            UpdateOutcome::StateAdvanced {
                finalized_updated: c.finalized_updated,
                optimistic_updated: c.optimistic_updated,
                rotated: c.rotated,
                next_committee_learned: c.next_committee_learned,
            }
        }
    }
}
