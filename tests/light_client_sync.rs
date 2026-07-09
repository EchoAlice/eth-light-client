//! Integration test: Light Client Sync via Public API
//!
//! Validates the public `LightClient` API against Ethereum consensus-spec test vectors.
//! Uses only public types - no internal crate access.
//!
//! Run with: `cargo test --features test-utils`

#![cfg(feature = "test-utils")]

use eth_light_client::test_utils::{
    beacon_header_matches, ProcessUpdateStep, SpecTestLoader, TestStep,
};
use eth_light_client::{LightClient, UpdateOutcome};

#[test]
fn test_light_client_public_api_sync_altair() {
    run_public_api_sync(SpecTestLoader::minimal_altair_sync());
}

#[test]
fn test_light_client_public_api_sync_bellatrix() {
    run_public_api_sync(SpecTestLoader::minimal_bellatrix_sync());
}

#[test]
fn test_light_client_public_api_sync_capella() {
    run_public_api_sync(SpecTestLoader::minimal_capella_sync());
}

/// Run spec sync steps 1-5 for the given fixture set through the public
/// `LightClient` API. Shared by the per-fork tests above; the fork is
/// determined entirely by the supplied `loader`.
fn run_public_api_sync(loader: SpecTestLoader) {
    let bootstrap = loader.load_bootstrap().expect("Failed to load bootstrap");
    let steps = loader.load_steps().expect("Failed to load steps");

    // Use the loader's fork-appropriate ChainSpec so fork version / domain
    // selection matches the fixtures.
    let mut client =
        LightClient::new(loader.chain_spec(), bootstrap).expect("Failed to initialize LightClient");

    for (i, step) in steps.iter().enumerate().take(5) {
        match step {
            TestStep::ProcessUpdate { process_update } => {
                process_step(&mut client, &loader, process_update, i + 1);
            }
            TestStep::ForceUpdate { .. } => {} // not implemented -- skip
        }
    }
}

fn process_step(
    client: &mut LightClient,
    loader: &SpecTestLoader,
    step: &ProcessUpdateStep,
    step_num: usize,
) {
    let update = loader
        .load_update(&step.update)
        .expect("Failed to load update");

    let before_finalized = client.finalized_header().slot;
    let before_optimistic = client.optimistic_header().slot;

    // Process update via public API with the fixture's current_slot.
    let outcome: UpdateOutcome = client
        .process_update_at_slot(update, step.current_slot)
        .unwrap_or_else(|e| panic!("step {}: error processing update: {}", step_num, e));

    let after_finalized = client.finalized_header().slot;
    let after_optimistic = client.optimistic_header().slot;

    // UpdateOutcome must agree with observed state.
    if outcome.finalized_updated() {
        assert!(
            after_finalized > before_finalized,
            "step {}: finalized_updated()=true but slot didn't advance",
            step_num
        );
    }
    if outcome.optimistic_updated() {
        assert!(
            after_optimistic > before_optimistic,
            "step {}: optimistic_updated()=true but slot didn't advance",
            step_num
        );
    }

    // Observed headers must match the fixture's expected headers.
    if let Some(expected) = &step.checks.finalized_header {
        assert!(
            beacon_header_matches(expected, client.finalized_header()),
            "step {}: finalized header mismatch (expected slot {})",
            step_num,
            expected.slot,
        );
    }
    if let Some(expected) = &step.checks.optimistic_header {
        assert!(
            beacon_header_matches(expected, client.optimistic_header()),
            "step {}: optimistic header mismatch (expected slot {})",
            step_num,
            expected.slot,
        );
    }
}
