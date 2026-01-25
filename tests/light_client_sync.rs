//! Integration test: Light Client Sync via Public API
//!
//! Validates the public `LightClient` API against Ethereum consensus-spec test vectors.
//! Uses only public types - no internal crate access.
//!
//! Run with: `cargo test --features test-utils`

#![cfg(feature = "test-utils")]

use eth_light_client::test_utils::{hex_to_root, ProcessUpdateStep, SpecTestLoader, TestStep};
use eth_light_client::{ChainSpec, LightClient, UpdateOutcome};

/// Run spec sync steps 1-5 through the public LightClient API.
#[test]
fn test_light_client_public_api_sync() {
    println!("\n=== Integration Test: LightClient Public API ===\n");

    // Load fixtures using test_utils
    let loader = SpecTestLoader::minimal_altair_sync();
    let bootstrap = loader.load_bootstrap().expect("Failed to load bootstrap");
    let steps = loader.load_steps().expect("Failed to load steps");

    // Initialize LightClient via public API
    let mut client = LightClient::new(ChainSpec::minimal(), bootstrap.into_bootstrap())
        .expect("Failed to initialize LightClient");

    println!(
        "Initialized at slot {} (period {})",
        client.finalized_header().slot,
        client.current_period()
    );

    // Process steps 1-5
    let mut passed = 0;
    let mut failed = 0;

    for (i, step) in steps.iter().enumerate().take(5) {
        let step_num = i + 1;

        match step {
            TestStep::ProcessUpdate { process_update } => {
                println!("\n--- Step {} ---", step_num);
                if process_step(&mut client, &loader, process_update, step_num) {
                    passed += 1;
                } else {
                    failed += 1;
                }
            }
            TestStep::ForceUpdate { .. } => {
                println!("\n--- Step {} (force_update: skipped) ---", step_num);
            }
        }
    }

    println!("\n=== Results ===");
    println!("Passed: {}", passed);
    println!("Failed: {}", failed);

    assert_eq!(failed, 0, "{} step(s) failed", failed);
}

fn process_step(
    client: &mut LightClient,
    loader: &SpecTestLoader,
    step: &ProcessUpdateStep,
    step_num: usize,
) -> bool {
    let update = loader
        .load_update(&step.update)
        .expect("Failed to load update");

    println!("Processing update: {}", step.update);
    println!(
        "  Attested slot: {}, Signature slot: {}",
        update.attested_header.slot, update.signature_slot
    );

    let before_finalized = client.finalized_header().slot;
    let before_optimistic = client.optimistic_header().slot;

    // Process update via public API with fixture's current_slot
    let outcome: UpdateOutcome = match client.process_update_at_slot(update, step.current_slot) {
        Ok(outcome) => outcome,
        Err(e) => {
            println!("  FAIL: Error processing update: {}", e);
            return false;
        }
    };

    let after_finalized = client.finalized_header().slot;
    let after_optimistic = client.optimistic_header().slot;

    println!(
        "  Before: finalized={}, optimistic={}",
        before_finalized, before_optimistic
    );
    println!(
        "  After:  finalized={}, optimistic={}",
        after_finalized, after_optimistic
    );
    println!("  Outcome: {:?}", outcome);

    // Verify UpdateOutcome consistency
    if outcome.finalized_updated() {
        assert!(
            after_finalized > before_finalized,
            "Step {}: finalized_updated()=true but slot didn't advance",
            step_num
        );
    }
    if outcome.optimistic_updated() {
        assert!(
            after_optimistic > before_optimistic,
            "Step {}: optimistic_updated()=true but slot didn't advance",
            step_num
        );
    }

    // Verify against expected state
    let mut step_passed = true;

    if let Some(ref expected) = step.checks.finalized_header {
        if after_finalized != expected.slot {
            println!(
                "  FAIL: Finalized slot mismatch (expected {}, got {})",
                expected.slot, after_finalized
            );
            step_passed = false;
        }

        let actual_root = client
            .finalized_header()
            .hash_tree_root()
            .expect("hash_tree_root failed");
        let expected_root = hex_to_root(&expected.beacon_root).expect("Invalid beacon_root");

        if actual_root != expected_root {
            println!("  FAIL: Finalized beacon_root mismatch");
            step_passed = false;
        }
    }

    if let Some(ref expected) = step.checks.optimistic_header {
        if after_optimistic != expected.slot {
            println!(
                "  FAIL: Optimistic slot mismatch (expected {}, got {})",
                expected.slot, after_optimistic
            );
            step_passed = false;
        }

        let actual_root = client
            .optimistic_header()
            .hash_tree_root()
            .expect("hash_tree_root failed");
        let expected_root = hex_to_root(&expected.beacon_root).expect("Invalid beacon_root");

        if actual_root != expected_root {
            println!("  FAIL: Optimistic beacon_root mismatch");
            step_passed = false;
        }
    }

    if step_passed {
        println!("  PASS");
    }

    step_passed
}
