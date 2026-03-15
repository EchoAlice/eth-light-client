//! Light Client Public API
//!
//! This module provides the main entry point for the Ethereum light client library.
//! The [`LightClient`] type wraps internal consensus machinery and exposes a stable,
//! minimal interface for tracking the beacon chain.
//!
//! # Overview
//!
//! This library is **verification-only** — it does not fetch data from the network.
//! The caller is responsible for supplying both:
//!
//! 1. A [`LightClientBootstrap`] to initialize the client (from a trusted source)
//! 2. Continuous [`LightClientUpdate`]s to advance the client's view of the chain
//!
//! The light client maintains:
//! - A **finalized header**: the most recent header known to be finalized
//! - An **optimistic header**: the best known header (may not yet be finalized)
//! - The **current sync committee**: 512 validators signing recent blocks
//! - The **next sync committee**: for the upcoming period (if known)
//!
//! # Example
//!
//! ```no_run
//! use eth_light_client::{ChainSpec, LightClient, LightClientBootstrap, LightClientUpdate};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. Bootstrap: fetch from a trusted source
//!     //    GET /eth/v1/beacon/light_client/bootstrap/{block_root}
//!     let bootstrap: LightClientBootstrap = todo!("fetch from beacon API");
//!     let mut client = LightClient::new(ChainSpec::mainnet(), bootstrap)?;
//!
//!     // 2. Continuously feed updates to advance the client
//!     //    GET /eth/v1/beacon/light_client/updates?start_period=X&count=1
//!     let update: LightClientUpdate = todo!("fetch from any source");
//!     let outcome = client.process_update(update)?;
//!
//!     println!("Finalized slot: {}", client.finalized_header().slot);
//!     println!("Update outcome: {}", outcome);
//!     Ok(())
//! }
//! ```

use crate::config::ChainSpec;
use crate::consensus::light_client::LightClientProcessor;
use crate::error::Result;
use crate::types::consensus::{
    BeaconBlockHeader, LightClientBootstrap, LightClientUpdate, SyncCommittee,
};
use crate::types::primitives::Slot;

// ============================================================================
// UpdateOutcome
// ============================================================================

/// Outcome of processing a [`LightClientUpdate`].
///
/// This enum describes what changed (if anything) after processing an update.
/// Use the helper methods to query specific changes without pattern matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpdateOutcome {
    /// The update was applied and state advanced.
    StateAdvanced {
        /// `true` if the finalized header changed to a new slot.
        finalized_updated: bool,
        /// `true` if the optimistic header changed to a new slot.
        optimistic_updated: bool,
        /// `true` if the sync committee period advanced (next committee is now current).
        sync_committee_updated: bool,
    },
    /// The update was valid but did not change state.
    ///
    /// This can happen when:
    /// - The update is a duplicate of one already processed
    /// - The update references headers older than current state
    /// - The update didn't meet the threshold for advancement
    NoChange,
}

impl UpdateOutcome {
    /// Returns `true` if processing the update changed any state.
    ///
    /// # Example
    ///
    /// ```
    /// use eth_light_client::UpdateOutcome;
    ///
    /// let outcome = UpdateOutcome::StateAdvanced {
    ///     finalized_updated: true,
    ///     optimistic_updated: false,
    ///     sync_committee_updated: false,
    /// };
    /// assert!(outcome.state_changed());
    ///
    /// assert!(!UpdateOutcome::NoChange.state_changed());
    /// ```
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

/// Ethereum Beacon Chain Light Client.
///
/// `LightClient` provides a minimal, stable interface for tracking the Ethereum
/// beacon chain without running a full node.
pub struct LightClient {
    inner: LightClientProcessor,
}

impl LightClient {
    /// Creates a new light client from bootstrap data.
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

    /// Processes a light client update using wall-clock time.
    pub fn process_update(&mut self, update: LightClientUpdate) -> Result<UpdateOutcome> {
        let old_finalized_slot = self.inner.finalized_header().slot;
        let old_optimistic_slot = self.inner.optimistic_header().slot;
        let old_period = self.inner.current_period();

        let state_changed = self.inner.process_update(update)?;

        if !state_changed {
            return Ok(UpdateOutcome::NoChange);
        }

        let new_finalized_slot = self.inner.finalized_header().slot;
        let new_optimistic_slot = self.inner.optimistic_header().slot;
        let new_period = self.inner.current_period();

        Ok(UpdateOutcome::StateAdvanced {
            finalized_updated: new_finalized_slot != old_finalized_slot,
            optimistic_updated: new_optimistic_slot != old_optimistic_slot,
            sync_committee_updated: new_period != old_period,
        })
    }

    /// Processes a light client update with an explicit current slot.
    pub fn process_update_at_slot(
        &mut self,
        update: LightClientUpdate,
        current_slot: Slot,
    ) -> Result<UpdateOutcome> {
        let old_finalized_slot = self.inner.finalized_header().slot;
        let old_optimistic_slot = self.inner.optimistic_header().slot;
        let old_period = self.inner.current_period();

        let state_changed = self.inner.process_update_at_slot(update, current_slot)?;

        if !state_changed {
            return Ok(UpdateOutcome::NoChange);
        }

        let new_finalized_slot = self.inner.finalized_header().slot;
        let new_optimistic_slot = self.inner.optimistic_header().slot;
        let new_period = self.inner.current_period();

        Ok(UpdateOutcome::StateAdvanced {
            finalized_updated: new_finalized_slot != old_finalized_slot,
            optimistic_updated: new_optimistic_slot != old_optimistic_slot,
            sync_committee_updated: new_period != old_period,
        })
    }

    /// Returns the current finalized beacon block header.
    #[inline]
    pub fn finalized_header(&self) -> &BeaconBlockHeader {
        self.inner.finalized_header()
    }

    /// Returns the current optimistic beacon block header.
    #[inline]
    pub fn optimistic_header(&self) -> &BeaconBlockHeader {
        self.inner.optimistic_header()
    }

    /// Returns the current sync committee.
    #[inline]
    pub fn current_sync_committee(&self) -> &SyncCommittee {
        self.inner.current_sync_committee()
    }

    /// Returns the next sync committee, if known.
    #[inline]
    pub fn next_sync_committee(&self) -> Option<&SyncCommittee> {
        self.inner.next_sync_committee()
    }

    /// Returns the current sync committee period.
    #[inline]
    pub fn current_period(&self) -> u64 {
        self.inner.current_period()
    }

    /// Returns the chain specification.
    #[inline]
    pub fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
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
        let outcome = UpdateOutcome::StateAdvanced {
            finalized_updated: false,
            optimistic_updated: false,
            sync_committee_updated: false,
        };

        assert!(outcome.state_changed());
        assert!(!outcome.finalized_updated());
        assert_eq!(outcome.to_string(), "StateAdvanced(no fields changed)");
    }

    // ------------------------------------------------------------------------
    // LightClient tests
    // ------------------------------------------------------------------------

    use crate::consensus::light_client_spec_tests::load_bootstrap_fixture;

    #[test]
    fn test_light_client_creation() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = ChainSpec::minimal();
        let expected_slot = bootstrap.header.slot;

        let client = LightClient::new(chain_spec, bootstrap).expect("should create light client");

        assert_eq!(client.finalized_header().slot, expected_slot);
        assert_eq!(client.optimistic_header().slot, expected_slot);
    }

    #[test]
    fn test_light_client_chain_spec() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = ChainSpec::minimal();

        let client = LightClient::new(chain_spec, bootstrap).expect("should create");

        let spec = client.chain_spec();
        assert_eq!(spec.slots_per_epoch(), 8);
    }

    #[test]
    fn test_light_client_sync_committee_access() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = ChainSpec::minimal();

        let client = LightClient::new(chain_spec, bootstrap).expect("should create");

        let _current = client.current_sync_committee();
        assert!(client.next_sync_committee().is_none());
    }
}
