//! Public API: [`LightClient`] and [`UpdateOutcome`].
//!
//! `LightClient` is a thin, verification-only wrapper over the internal consensus
//! engine — it does not fetch from the network. The caller supplies a
//! [`LightClientBootstrap`] to initialize it, then feeds [`LightClientUpdate`]s to
//! advance its finalized and optimistic views of the chain. See the crate README
//! for usage, the trust model, and a full example.

use crate::config::ChainSpec;
use crate::consensus::processor::LightClientProcessor;
use crate::error::Result;
use crate::types::consensus::{
    BeaconBlockHeader, LightClientBootstrap, LightClientUpdate, SyncCommittee,
};
use crate::types::primitives::Slot;

// ============================================================================
// UpdateOutcome
// ============================================================================

/// Outcome of processing a [`LightClientUpdate`] — what changed, if anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpdateOutcome {
    /// The update was applied and state advanced.
    StateAdvanced {
        /// `true` if the finalized header changed to a new slot.
        finalized_updated: bool,
        /// `true` if the optimistic header changed to a new slot.
        optimistic_updated: bool,
        /// `true` if the sync committee period advanced (rotation).
        sync_committee_updated: bool,
    },
    /// The update was valid but did not advance the finalized/optimistic header
    /// or period (e.g. a duplicate, an older header, or below threshold).
    NoChange,
}

impl UpdateOutcome {
    /// Returns `true` if processing the update changed any state.
    #[inline]
    pub fn state_changed(&self) -> bool {
        matches!(self, UpdateOutcome::StateAdvanced { .. })
    }

    /// Returns `true` if the finalized header was updated.
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

    /// Returns `true` if the optimistic header was updated.
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

    /// Returns `true` if the sync committee rotated to the next period.
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

// ============================================================================
// LightClient
// ============================================================================

/// Ethereum beacon chain light client — verifies sync committee signatures and
/// maintains the finalized/optimistic headers. `Send` but not `Sync` (wrap in a
/// mutex for concurrent access).
pub struct LightClient {
    /// Internal light client processor (private, not exposed)
    inner: LightClientProcessor,
}

/// Snapshot of the observable state, used to diff an update's effect.
struct StateSnapshot {
    finalized_slot: Slot,
    optimistic_slot: Slot,
    period: u64,
}

impl LightClient {
    /// Creates a light client from bootstrap data, verifying the sync committee
    /// against the bootstrap header's state root.
    ///
    /// # Security
    ///
    /// `bootstrap.header` must come from a trusted source (a checkpoint you trust,
    /// or embedded in your binary). `bootstrap.current_sync_committee` may be
    /// untrusted — its branch proof binds it to `bootstrap.header.state_root`.
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
    /// Computes `current_slot` from system time; use
    /// [`process_update_at_slot`](Self::process_update_at_slot) to supply it explicitly
    /// (tests, custom clocks). Errors if the signature, committee, or Merkle proofs
    /// fail to verify.
    pub fn process_update(&mut self, update: LightClientUpdate) -> Result<UpdateOutcome> {
        let before = self.snapshot();
        let state_changed = self.inner.process_update(update)?;
        Ok(self.outcome(before, state_changed))
    }

    /// Verifies and applies an update using an explicit `current_slot` for
    /// time-based validation, returning what changed.
    ///
    /// Errors if `signature_slot` is beyond `current_slot`, or if the signature,
    /// committee, or Merkle proofs fail to verify.
    pub fn process_update_at_slot(
        &mut self,
        update: LightClientUpdate,
        current_slot: Slot,
    ) -> Result<UpdateOutcome> {
        let before = self.snapshot();
        let state_changed = self.inner.process_update_at_slot(update, current_slot)?;
        Ok(self.outcome(before, state_changed))
    }

    /// The current finalized beacon block header.
    #[inline]
    pub fn finalized_header(&self) -> &BeaconBlockHeader {
        self.inner.finalized_header()
    }

    /// The current optimistic header — the best known header, may not be finalized.
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

    /// The chain specification.
    #[inline]
    pub fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }

    /// Snapshot the observable state (header slots + period) for change detection.
    fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            finalized_slot: self.inner.finalized_header().slot,
            optimistic_slot: self.inner.optimistic_header().slot,
            period: self.inner.current_period(),
        }
    }

    /// Diff the post-update state against `before` into an [`UpdateOutcome`].
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // UpdateOutcome tests
    // ------------------------------------------------------------------------

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

        assert!(outcome.state_changed()); // Still counts as state_changed
        assert!(!outcome.finalized_updated());
        assert_eq!(outcome.to_string(), "StateAdvanced(no fields changed)");
    }

    // ------------------------------------------------------------------------
    // LightClient tests
    // ------------------------------------------------------------------------

    // Import the spec test fixture loader
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

        // Verify we can access chain spec (minimal preset)
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
