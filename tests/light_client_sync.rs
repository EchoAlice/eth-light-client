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
fn altair_sync_via_public_api() {
    run_public_api_sync(SpecTestLoader::minimal_altair_sync());
}

#[test]
fn bellatrix_sync_via_public_api() {
    run_public_api_sync(SpecTestLoader::minimal_bellatrix_sync());
}

#[test]
fn capella_sync_via_public_api() {
    run_public_api_sync(SpecTestLoader::minimal_capella_sync());
}

/// Replay the fixture's `process_update` steps through the public `LightClient`
/// API; the fork is determined by `loader`.
fn run_public_api_sync(loader: SpecTestLoader) {
    let bootstrap = loader.load_bootstrap().expect("Failed to load bootstrap");
    let steps = loader.load_steps().expect("Failed to load steps");

    let mut client =
        LightClient::new(loader.chain_spec(), bootstrap).expect("Failed to initialize LightClient");

    let mut processed = 0;
    for (i, step) in steps.iter().enumerate() {
        match step {
            TestStep::ProcessUpdate { process_update } => {
                process_step(&mut client, &loader, process_update, i + 1);
                processed += 1;
            }
            // later steps depend on force_update's transition -- stop, don't skip
            TestStep::ForceUpdate { .. } => break,
        }
    }
    assert!(
        processed > 0,
        "no process_update steps ran before the first force_update"
    );
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
