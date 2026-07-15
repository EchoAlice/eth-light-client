//! Public API: [`LightClient`] and [`UpdateOutcome`].
//!
//! `LightClient` is a thin, verification-only wrapper over the internal consensus
//! engine — it does not fetch from the network. The caller supplies a
//! [`LightClientBootstrap`] to initialize it, then feeds [`LightClientUpdate`]s to
//! advance its finalized and optimistic views of the chain. See the crate README
//! for usage, the trust model, and a full example.

use crate::config::ChainSpec;
use crate::consensus::processor::LightClientProcessor;
use crate::error::{Error, Result};
use crate::types::consensus::{
    BeaconBlockHeader, LightClientBootstrap, LightClientUpdate, SyncCommittee,
};
use crate::types::primitives::Slot;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpdateOutcome {
    StateAdvanced {
        finalized_updated: bool,
        optimistic_updated: bool,
        sync_committee_updated: bool,
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
    pub fn sync_committee_updated(&self) -> bool {
        matches!(
            self,
            UpdateOutcome::StateAdvanced {
                sync_committee_updated: true,
                ..
            }
        )
    }
}

impl std::fmt::Display for UpdateOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateOutcome::StateAdvanced {
                finalized_updated,
                optimistic_updated,
                sync_committee_updated,
            } => {
                let mut changes = Vec::new();
                if *finalized_updated {
                    changes.push("finalized");
                }
                if *optimistic_updated {
                    changes.push("optimistic");
                }
                if *sync_committee_updated {
                    changes.push("sync_committee");
                }
                if changes.is_empty() {
                    write!(f, "StateAdvanced(no fields changed)")
                } else {
                    write!(f, "StateAdvanced({})", changes.join(", "))
                }
            }
            UpdateOutcome::NoChange => write!(f, "NoChange"),
        }
    }
}

pub struct LightClient {
    inner: LightClientProcessor,
}

/// Snapshot of the observable state, used to diff an update's effect.
struct StateSnapshot {
    finalized_slot: Slot,
    optimistic_slot: Slot,
    period: u64,
}

impl LightClient {
    pub fn new(chain_spec: ChainSpec, bootstrap: LightClientBootstrap) -> Result<Self> {
        let inner = LightClientProcessor::new(
            chain_spec,
            bootstrap.header,
            bootstrap.current_sync_committee,
            &bootstrap.current_sync_committee_branch,
            bootstrap.genesis_validators_root,
        )?;

        Ok(Self { inner })
    }

    /// Verifies and applies an update using wall-clock time, returning what changed.
    ///
    /// Reads the system clock to derive `current_slot`; use
    /// [`process_update_at_slot`](Self::process_update_at_slot) to supply it
    /// explicitly (tests, custom clocks).
    pub fn process_update(&mut self, update: LightClientUpdate) -> Result<UpdateOutcome> {
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Internal("Failed to get current time".to_string()))?
            .as_secs();
        let current_slot = self.chain_spec().timestamp_to_slot(current_timestamp);
        self.process_update_at_slot(update, current_slot)
    }

    pub fn process_update_at_slot(
        &mut self,
        update: LightClientUpdate,
        current_slot: Slot,
    ) -> Result<UpdateOutcome> {
        let before = self.snapshot();
        let state_changed = self.inner.process_update_at_slot(update, current_slot)?;
        Ok(self.outcome(before, state_changed))
    }

    #[inline]
    pub fn finalized_header(&self) -> &BeaconBlockHeader {
        self.inner.finalized_header()
    }

    #[inline]
    pub fn optimistic_header(&self) -> &BeaconBlockHeader {
        self.inner.optimistic_header()
    }

    /// The current period's sync committee.
    #[inline]
    pub fn current_sync_committee(&self) -> &SyncCommittee {
        self.inner.current_sync_committee()
    }

    /// The next period's sync committee, if it has been learned yet.
    #[inline]
    pub fn next_sync_committee(&self) -> Option<&SyncCommittee> {
        self.inner.next_sync_committee()
    }

    /// The current sync committee period (derived from the finalized header).
    #[inline]
    pub fn current_period(&self) -> u64 {
        self.inner.current_period()
    }

    #[inline]
    pub fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }

    fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            finalized_slot: self.inner.finalized_header().slot,
            optimistic_slot: self.inner.optimistic_header().slot,
            period: self.inner.current_period(),
        }
    }

    fn outcome(&self, before: StateSnapshot, state_changed: bool) -> UpdateOutcome {
        if !state_changed {
            return UpdateOutcome::NoChange;
        }
        let after = self.snapshot();
        UpdateOutcome::StateAdvanced {
            finalized_updated: after.finalized_slot != before.finalized_slot,
            optimistic_updated: after.optimistic_slot != before.optimistic_slot,
            sync_committee_updated: after.period != before.period,
        }
    }
}

impl std::fmt::Debug for LightClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LightClient")
            .field("finalized_slot", &self.finalized_header().slot)
            .field("optimistic_slot", &self.optimistic_header().slot)
            .field("current_period", &self.current_period())
            .field("has_next_committee", &self.next_sync_committee().is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_outcome_no_change() {
        let outcome = UpdateOutcome::NoChange;

        assert!(!outcome.state_changed());
        assert!(!outcome.finalized_updated());
        assert!(!outcome.optimistic_updated());
        assert!(!outcome.sync_committee_updated());
        assert_eq!(outcome.to_string(), "NoChange");
    }

    #[test]
    fn test_update_outcome_finalized_only() {
        let outcome = UpdateOutcome::StateAdvanced {
            finalized_updated: true,
            optimistic_updated: false,
            sync_committee_updated: false,
        };

        assert!(outcome.state_changed());
        assert!(outcome.finalized_updated());
        assert!(!outcome.optimistic_updated());
        assert!(!outcome.sync_committee_updated());
        assert_eq!(outcome.to_string(), "StateAdvanced(finalized)");
    }

    #[test]
    fn test_update_outcome_optimistic_only() {
        let outcome = UpdateOutcome::StateAdvanced {
            finalized_updated: false,
            optimistic_updated: true,
            sync_committee_updated: false,
        };

        assert!(outcome.state_changed());
        assert!(!outcome.finalized_updated());
        assert!(outcome.optimistic_updated());
        assert!(!outcome.sync_committee_updated());
        assert_eq!(outcome.to_string(), "StateAdvanced(optimistic)");
    }

    #[test]
    fn test_update_outcome_sync_committee_only() {
        let outcome = UpdateOutcome::StateAdvanced {
            finalized_updated: false,
            optimistic_updated: false,
            sync_committee_updated: true,
        };

        assert!(outcome.state_changed());
        assert!(!outcome.finalized_updated());
        assert!(!outcome.optimistic_updated());
        assert!(outcome.sync_committee_updated());
        assert_eq!(outcome.to_string(), "StateAdvanced(sync_committee)");
    }

    #[test]
    fn test_update_outcome_all_updated() {
        let outcome = UpdateOutcome::StateAdvanced {
            finalized_updated: true,
            optimistic_updated: true,
            sync_committee_updated: true,
        };

        assert!(outcome.state_changed());
        assert!(outcome.finalized_updated());
        assert!(outcome.optimistic_updated());
        assert!(outcome.sync_committee_updated());
        assert_eq!(
            outcome.to_string(),
            "StateAdvanced(finalized, optimistic, sync_committee)"
        );
    }

    #[test]
    fn test_update_outcome_state_advanced_no_fields() {
        // Edge case: StateAdvanced but nothing actually changed
        // This shouldn't happen in practice, but test the Display impl
        let outcome = UpdateOutcome::StateAdvanced {
            finalized_updated: false,
            optimistic_updated: false,
            sync_committee_updated: false,
        };

        assert!(outcome.state_changed());
        assert!(!outcome.finalized_updated());
        assert_eq!(outcome.to_string(), "StateAdvanced(no fields changed)");
    }

    use crate::test_utils::load_altair_bootstrap;

    #[test]
    fn test_light_client_creation() {
        let bootstrap = load_altair_bootstrap();
        let chain_spec = ChainSpec::minimal();
        let expected_slot = bootstrap.header.slot();

        let client = LightClient::new(chain_spec, bootstrap).expect("should create light client");

        assert_eq!(client.finalized_header().slot, expected_slot);
        assert_eq!(client.optimistic_header().slot, expected_slot);
    }

    #[test]
    fn test_light_client_chain_spec() {
        let bootstrap = load_altair_bootstrap();
        let chain_spec = ChainSpec::minimal();

        let client = LightClient::new(chain_spec, bootstrap).expect("should create");

        let spec = client.chain_spec();
        assert_eq!(spec.slots_per_epoch(), 8); // minimal preset uses 8
    }

    #[test]
    fn test_light_client_sync_committee_access() {
        let bootstrap = load_altair_bootstrap();
        let chain_spec = ChainSpec::minimal();

        let client = LightClient::new(chain_spec, bootstrap).expect("should create");

        // Should have current committee
        let _current = client.current_sync_committee();

        // Should not have next committee initially
        assert!(client.next_sync_committee().is_none());
    }
}
