//! Integration test: Light Client Sync via Public API
//!
//! Validates the public `LightClient` API against Ethereum consensus-spec test vectors.
//! Uses only public types - no internal crate access.
//!
//! Run with: `cargo test --features test-utils`

#![cfg(feature = "test-utils")]

use eth_light_client::test_utils::{
    beacon_header_matches, LightClientSyncTest, ProcessUpdateStep, TestStep,
};
use eth_light_client::{LightClient, UpdateOutcome};

#[test]
fn altair_sync_via_public_api() {
    run_public_api_sync(LightClientSyncTest::minimal_altair());
}

#[test]
fn bellatrix_sync_via_public_api() {
    run_public_api_sync(LightClientSyncTest::minimal_bellatrix());
}

#[test]
fn capella_sync_via_public_api() {
    run_public_api_sync(LightClientSyncTest::minimal_capella());
}

#[test]
fn deneb_sync_via_public_api() {
    run_public_api_sync(LightClientSyncTest::minimal_deneb());
}

#[test]
fn electra_sync_via_public_api() {
    run_public_api_sync(LightClientSyncTest::minimal_electra());
}

/// Replay the fixture's `process_update` steps through the public `LightClient`
/// API; the fork is determined by `sync_test`.
fn run_public_api_sync(sync_test: LightClientSyncTest) {
    let bootstrap = sync_test
        .load_bootstrap()
        .expect("Failed to load bootstrap");
    let steps = sync_test.load_steps().expect("Failed to load steps");

    let mut client = LightClient::new(sync_test.chain_spec(), bootstrap)
        .expect("Failed to initialize LightClient");

    let mut processed = 0;
    for (i, step) in steps.iter().enumerate() {
        match step {
            TestStep::ProcessUpdate { process_update } => {
                process_step(&mut client, &sync_test, process_update, i + 1);
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
    sync_test: &LightClientSyncTest,
    step: &ProcessUpdateStep,
    step_num: usize,
) {
    let update = sync_test
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
