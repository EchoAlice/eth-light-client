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
/// beacon chain without running a full node. It verifies sync committee signatures
/// and maintains finalized/optimistic headers.
///
/// The caller must supply a [`LightClientBootstrap`] via [`LightClient::new`] to
/// initialize the client, then continuously feed [`LightClientUpdate`]s via
/// [`process_update`](Self::process_update) to advance its view of the chain.
/// This library does not fetch data from the network.
///
/// # Internals
///
/// This struct wraps internal consensus machinery and does not expose stores
/// or other implementation details. The internal representation may change
/// between versions.
///
/// # Thread Safety
///
/// `LightClient` is `Send` but not `Sync`. For concurrent access, wrap in a mutex.
pub struct LightClient {
    /// Internal light client processor (private, not exposed)
    inner: LightClientProcessor,
}

impl LightClient {
    /// Creates a new light client from bootstrap data.
    ///
    /// # Arguments
    ///
    /// * `chain_spec` - Network configuration (use [`ChainSpec::mainnet()`] for mainnet)
    /// * `bootstrap` - Bootstrap data containing trusted header, sync committee, merkle proof,
    ///   and genesis validators root
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The sync committee branch proof fails verification
    /// - The sync committee has invalid public keys
    ///
    /// # Security
    ///
    /// The `bootstrap.header` must come from a trusted source (e.g., a checkpoint sync
    /// endpoint you trust, or embedded in your binary).
    ///
    /// The `bootstrap.current_sync_committee` may come from an untrusted source because
    /// the `bootstrap.current_sync_committee_branch` cryptographically proves it matches
    /// the `bootstrap.header.state_root`.
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

    /// Processes a light client update using wall-clock time, potentially advancing state.
    ///
    /// This is a convenience wrapper that computes `current_slot` from system time.
    /// For spec-testable behavior, use [`process_update_at_slot`](Self::process_update_at_slot).
    ///
    /// This method:
    /// 1. Validates the update's sync committee signature
    /// 2. Checks that the update improves on current state
    /// 3. Updates finalized/optimistic headers if valid
    /// 4. Rotates sync committee if a new period is reached
    ///
    /// # Arguments
    ///
    /// * `update` - The update to process (moved, not borrowed)
    ///
    /// # Returns
    ///
    /// Returns [`UpdateOutcome`] describing what changed, or an error if validation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The sync committee signature is invalid
    /// - The update references unknown sync committees
    /// - Merkle proofs don't verify
    pub fn process_update(&mut self, update: LightClientUpdate) -> Result<UpdateOutcome> {
        // Snapshot current state to detect changes
        let old_finalized_slot = self.inner.finalized_header().slot;
        let old_optimistic_slot = self.inner.optimistic_header().slot;
        let old_period = self.inner.current_period();

        // Process the update (may mutate internal state)
        let state_changed = self.inner.process_update(update)?;

        if !state_changed {
            return Ok(UpdateOutcome::NoChange);
        }

        // Determine what specifically changed
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
    ///
    /// This allows spec tests to inject the fixture's `current_slot` so that
    /// time-based validation is properly exercised.
    ///
    /// # Arguments
    ///
    /// * `update` - The update to process (moved, not borrowed)
    /// * `current_slot` - The slot to use for time-based validation checks
    ///
    /// # Returns
    ///
    /// Returns [`UpdateOutcome`] describing what changed, or an error if validation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The update's signature slot is too far in the future relative to `current_slot`
    /// - The sync committee signature is invalid
    /// - The update references unknown sync committees
    /// - Merkle proofs don't verify
    pub fn process_update_at_slot(
        &mut self,
        update: LightClientUpdate,
        current_slot: Slot,
    ) -> Result<UpdateOutcome> {
        // Snapshot current state to detect changes
        let old_finalized_slot = self.inner.finalized_header().slot;
        let old_optimistic_slot = self.inner.optimistic_header().slot;
        let old_period = self.inner.current_period();

        // Process the update with explicit slot (may mutate internal state)
        let state_changed = self.inner.process_update_at_slot(update, current_slot)?;

        if !state_changed {
            return Ok(UpdateOutcome::NoChange);
        }

        // Determine what specifically changed
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
    ///
    /// The finalized header represents the most recent header that has been
    /// finalized by the beacon chain (2/3+ of validators attested to it).
    #[inline]
    pub fn finalized_header(&self) -> &BeaconBlockHeader {
        self.inner.finalized_header()
    }

    /// Returns the current optimistic beacon block header.
    ///
    /// The optimistic header is the best known header, which may be more recent
    /// than the finalized header but hasn't yet achieved finality.
    #[inline]
    pub fn optimistic_header(&self) -> &BeaconBlockHeader {
        self.inner.optimistic_header()
    }

    /// Returns the current sync committee.
    ///
    /// The sync committee consists of 512 validators responsible for signing
    /// beacon block headers during the current period (~27 hours).
    #[inline]
    pub fn current_sync_committee(&self) -> &SyncCommittee {
        self.inner.current_sync_committee()
    }

    /// Returns the next sync committee, if known.
    ///
    /// The next sync committee is learned from light client updates that include
    /// a `next_sync_committee` field. Returns `None` if not yet known.
    #[inline]
    pub fn next_sync_committee(&self) -> Option<&SyncCommittee> {
        self.inner.next_sync_committee()
    }

    /// Returns `true` if the client is considered synced.
    ///
    /// A client is synced if it has recently processed updates and the optimistic
    /// header is close to the current slot.
    #[inline]
    pub fn is_synced(&self) -> bool {
        self.inner.is_synced()
    }

    /// Returns the current sync committee period.
    ///
    /// Periods are ~27 hours long (8192 slots at 12 seconds each).
    /// The period determines which sync committee is active.
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
            .field("is_synced", &self.is_synced())
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

    #[test]
    fn test_update_outcome_equality() {
        let a = UpdateOutcome::StateAdvanced {
            finalized_updated: true,
            optimistic_updated: false,
            sync_committee_updated: false,
        };
        let b = UpdateOutcome::StateAdvanced {
            finalized_updated: true,
            optimistic_updated: false,
            sync_committee_updated: false,
        };
        let c = UpdateOutcome::NoChange;

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_update_outcome_copy() {
        let outcome = UpdateOutcome::StateAdvanced {
            finalized_updated: true,
            optimistic_updated: true,
            sync_committee_updated: false,
        };

        // UpdateOutcome is Copy, so this should work
        let copied = outcome;
        assert_eq!(outcome, copied);
    }

    // ------------------------------------------------------------------------
    // LightClient tests
    // ------------------------------------------------------------------------

    // Import the spec test fixture loader
    use crate::consensus::light_client_spec_tests::load_bootstrap_fixture;

    #[test]
    fn test_light_client_creation() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = ChainSpec::minimal();
        let expected_slot = bootstrap.header.slot;

        let client = LightClient::new(chain_spec, bootstrap).expect("should create light client");

        assert_eq!(client.finalized_header().slot, expected_slot);
        assert_eq!(client.optimistic_header().slot, expected_slot);
        assert!(!client.is_synced());
    }

    #[test]
    fn test_light_client_debug() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = ChainSpec::minimal();
        let expected_slot = bootstrap.header.slot;

        let client = LightClient::new(chain_spec, bootstrap).expect("should create");

        let debug_str = format!("{:?}", client);
        assert!(debug_str.contains("LightClient"));
        assert!(debug_str.contains(&format!("finalized_slot: {}", expected_slot)));
        assert!(debug_str.contains("is_synced: false"));
    }

    #[test]
    fn test_light_client_chain_spec() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = ChainSpec::minimal();

        let client = LightClient::new(chain_spec, bootstrap).expect("should create");

        // Verify we can access chain spec (minimal preset)
        let spec = client.chain_spec();
        assert_eq!(spec.slots_per_epoch(), 8); // minimal preset uses 8
    }

    #[test]
    fn test_light_client_sync_committee_access() {
        let bootstrap = load_bootstrap_fixture();
        let chain_spec = ChainSpec::minimal();

        let client = LightClient::new(chain_spec, bootstrap).expect("should create");

        // Should have current committee
        let _current = client.current_sync_committee();

        // Should not have next committee initially
        assert!(client.next_sync_committee().is_none());
    }
}
