#![cfg(test)]
//! # Light Client Sync Specification Tests
//!
//! Validates the Ethereum Altair light client sync protocol against official
//! consensus-spec test vectors from https://github.com/ethereum/consensus-spec-tests
//!
//! ## Test Organization
//!
//! - `test_altair_light_client_sync` - Happy path test running steps 1-5 only
//!   (skips `force_update` steps and steps 6-10 that depend on them). Must always pass.
//!
//! - `test_altair_light_client_sync_with_force_update` - Full spec test including
//!   all 10 steps. Currently `#[ignore]` until `force_update` is implemented.
//!
//! ## Step Summary
//!
//! | Step | Type | What It Tests |
//! |------|------|---------------|
//! | 1-5 | process_update | Core sync protocol (happy path) |
//! | 6 | force_update | Safety timeout (NOT IMPLEMENTED) |
//! | 7-8 | process_update | Depends on step 6 state |
//! | 9 | force_update | Safety timeout (NOT IMPLEMENTED) |
//! | 10 | process_update | Depends on step 9 state |

use crate::consensus::light_client::LightClientProcessor;
use crate::test_utils::{
    hex_to_root, ForceUpdateStep, ProcessUpdateStep, SpecTestLoader, TestStep,
};
use crate::types::consensus::{LightClientBootstrap, LightClientUpdate};
use std::collections::HashSet;

// ============================================================================
// Shared Helper Functions
// ============================================================================

fn detect_update_type(update: &LightClientUpdate) -> &'static str {
    match (
        update.finalized_header.is_some(),
        update.next_sync_committee.is_some(),
    ) {
        (false, false) => "Optimistic",
        (true, false) => "Finality",
        (false, true) => "Committee",
        (true, true) => "Combined",
    }
}

/// Load bootstrap data from test fixtures.
pub(crate) fn load_bootstrap_fixture() -> LightClientBootstrap {
    let loader = SpecTestLoader::minimal_altair_sync();
    let bootstrap = loader.load_bootstrap().expect("Failed to load bootstrap");
    bootstrap.into_bootstrap()
}

fn initialize_processor() -> LightClientProcessor {
    let bootstrap = load_bootstrap_fixture();
    let chain_spec = crate::config::ChainSpec::minimal();
    let fork_version = chain_spec.altair_fork_version();

    LightClientProcessor::new(
        chain_spec,
        bootstrap.header,
        bootstrap.current_sync_committee,
        &bootstrap.current_sync_committee_branch,
        bootstrap.genesis_validators_root,
        fork_version,
    )
    .expect("Failed to initialize LightClientProcessor")
}

struct StepResult {
    passed: bool,
    update_type: &'static str,
}

fn execute_process_update_step(
    step_num: usize,
    step: &ProcessUpdateStep,
    processor: &mut LightClientProcessor,
    loader: &SpecTestLoader,
) -> StepResult {
    println!("\n📍 Step {}: process_update", step_num);
    println!("   Update file: {}", step.update);
    println!("   Current slot: {}", step.current_slot);

    let before_finalized = processor.get_finalized_header().slot;
    let before_optimistic = processor.get_optimistic_header().slot;

    let update = match loader.load_update(&step.update) {
        Ok(u) => u,
        Err(e) => {
            println!("   ❌ FAIL: Failed to load update: {}", e);
            return StepResult {
                passed: false,
                update_type: "Unknown",
            };
        }
    };

    let update_type = detect_update_type(&update);
    println!("   Update type: {}", update_type);
    println!("   Attested slot: {}", update.attested_header.slot);
    println!("   Signature slot: {}", update.signature_slot);
    if let Some(ref fin) = update.finalized_header {
        println!("   Finalized slot: {}", fin.slot);
    }
    if update.next_sync_committee.is_some() {
        println!("   Has next sync committee: true");
    }

    match processor.process_update_at_slot(update, step.current_slot) {
        Ok(state_changed) => {
            let after_finalized = processor.get_finalized_header().slot;
            let after_optimistic = processor.get_optimistic_header().slot;

            println!("   State changed: {}", state_changed);
            println!(
                "   Before: finalized={}, optimistic={}",
                before_finalized, before_optimistic
            );
            println!(
                "   After:  finalized={}, optimistic={}",
                after_finalized, after_optimistic
            );

            let mut step_passed = true;

            if let Some(ref expected) = step.checks.finalized_header {
                if after_finalized != expected.slot {
                    println!(
                        "   ❌ Finalized slot mismatch! Expected: {}, Actual: {}",
                        expected.slot, after_finalized
                    );
                    step_passed = false;
                } else {
                    println!("   ✅ Finalized slot matches: {}", after_finalized);
                }

                let actual_root = processor
                    .get_finalized_header()
                    .hash_tree_root()
                    .expect("Failed to compute hash_tree_root");
                let expected_root =
                    hex_to_root(&expected.beacon_root).expect("Invalid beacon_root");

                if actual_root != expected_root {
                    println!("   ❌ Finalized beacon_root mismatch!");
                    step_passed = false;
                } else {
                    println!("   ✅ Finalized beacon_root matches");
                }
            }

            if let Some(ref expected) = step.checks.optimistic_header {
                if after_optimistic != expected.slot {
                    println!(
                        "   ❌ Optimistic slot mismatch! Expected: {}, Actual: {}",
                        expected.slot, after_optimistic
                    );
                    step_passed = false;
                } else {
                    println!("   ✅ Optimistic slot matches: {}", after_optimistic);
                }

                let actual_root = processor
                    .get_optimistic_header()
                    .hash_tree_root()
                    .expect("Failed to compute hash_tree_root");
                let expected_root =
                    hex_to_root(&expected.beacon_root).expect("Invalid beacon_root");

                if actual_root != expected_root {
                    println!("   ❌ Optimistic beacon_root mismatch!");
                    step_passed = false;
                } else {
                    println!("   ✅ Optimistic beacon_root matches");
                }
            }

            if step_passed {
                println!("   ✅ PASS");
            } else {
                println!("   ❌ FAIL");
            }

            StepResult {
                passed: step_passed,
                update_type,
            }
        }
        Err(e) => {
            println!("   ❌ FAIL: Update processing error: {}", e);
            StepResult {
                passed: false,
                update_type,
            }
        }
    }
}

fn execute_force_update_step(
    step_num: usize,
    step: &ForceUpdateStep,
    processor: &mut LightClientProcessor,
) -> bool {
    println!("\n📍 Step {}: force_update", step_num);
    println!("   Current slot: {}", step.current_slot);

    let before_finalized = processor.get_finalized_header().slot;
    let before_optimistic = processor.get_optimistic_header().slot;

    // TODO: Implement force_update in LightClientProcessor
    println!("   ⚠️ force_update not yet implemented");

    let after_finalized = processor.get_finalized_header().slot;
    let after_optimistic = processor.get_optimistic_header().slot;

    println!(
        "   Before: finalized={}, optimistic={}",
        before_finalized, before_optimistic
    );
    println!(
        "   After:  finalized={}, optimistic={}",
        after_finalized, after_optimistic
    );

    let mut step_passed = true;

    if let Some(ref expected) = step.checks.finalized_header {
        if after_finalized != expected.slot {
            println!(
                "   ❌ Finalized slot mismatch! Expected: {}, Actual: {}",
                expected.slot, after_finalized
            );
            step_passed = false;
        }
    }

    if let Some(ref expected) = step.checks.optimistic_header {
        if after_optimistic != expected.slot {
            println!(
                "   ❌ Optimistic slot mismatch! Expected: {}, Actual: {}",
                expected.slot, after_optimistic
            );
            step_passed = false;
        }
    }

    if step_passed {
        println!("   ✅ PASS");
    } else {
        println!("   ❌ FAIL");
    }

    step_passed
}

// ============================================================================
// Tests
// ============================================================================

/// Happy path test: runs steps 1-5 only.
/// Skips force_update steps (6, 9) and steps that depend on them (7, 8, 10).
#[test]
fn test_altair_light_client_sync() {
    println!("\n🧪 Light Client Sync Spec Test (Happy Path: Steps 1-5)");
    println!("{}", "=".repeat(70));

    let loader = SpecTestLoader::minimal_altair_sync();
    let steps = loader.load_steps().expect("Failed to load steps");

    println!("   Total steps in spec: {}", steps.len());
    println!("   Running: steps 1-5 only");

    let mut processor = initialize_processor();

    let mut passed = 0;
    let mut failed = 0;
    let mut update_types_seen = HashSet::new();

    println!("\n🔄 Executing test steps...");
    println!("{}", "=".repeat(70));

    for (i, step) in steps.iter().enumerate().take(5) {
        match step {
            TestStep::ProcessUpdate { process_update } => {
                let result =
                    execute_process_update_step(i + 1, process_update, &mut processor, &loader);
                update_types_seen.insert(result.update_type);
                if result.passed {
                    passed += 1;
                } else {
                    failed += 1;
                }
            }
            TestStep::ForceUpdate { .. } => {
                println!("\n📍 Step {}: force_update (skipped)", i + 1);
            }
        }
    }

    println!("\n{}", "=".repeat(70));
    println!("📊 Test Summary (Happy Path)");
    println!("{}", "=".repeat(70));
    println!("   Steps executed: {}", passed + failed);
    println!("   ✅ Passed: {}", passed);
    println!("   ❌ Failed: {}", failed);
    println!("   Update types tested: {:?}", update_types_seen);

    assert_eq!(failed, 0, "❌ {} test step(s) failed!", failed);
    println!("\n🎉 All happy path tests passed!");
}

/// Full spec compliance test including force_update steps.
/// Currently ignored because force_update is not implemented.
#[test]
#[ignore = "force_update not yet implemented"]
fn test_altair_light_client_sync_with_force_update() {
    println!("\n🧪 Light Client Sync Spec Test (Full)");
    println!("{}", "=".repeat(70));

    let loader = SpecTestLoader::minimal_altair_sync();
    let steps = loader.load_steps().expect("Failed to load steps");

    println!("   Total steps: {}", steps.len());

    let mut processor = initialize_processor();

    let mut passed = 0;
    let mut failed = 0;
    let mut update_types_seen = HashSet::new();

    println!("\n🔄 Executing all test steps...");
    println!("{}", "=".repeat(70));

    for (i, step) in steps.iter().enumerate() {
        match step {
            TestStep::ProcessUpdate { process_update } => {
                let result =
                    execute_process_update_step(i + 1, process_update, &mut processor, &loader);
                update_types_seen.insert(result.update_type);
                if result.passed {
                    passed += 1;
                } else {
                    failed += 1;
                }
            }
            TestStep::ForceUpdate { force_update } => {
                if execute_force_update_step(i + 1, force_update, &mut processor) {
                    passed += 1;
                } else {
                    failed += 1;
                }
            }
        }
    }

    println!("\n{}", "=".repeat(70));
    println!("📊 Test Summary (Full Spec)");
    println!("{}", "=".repeat(70));
    println!("   Total steps: {}", passed + failed);
    println!("   ✅ Passed: {}", passed);
    println!("   ❌ Failed: {}", failed);
    println!("   Update types tested: {:?}", update_types_seen);

    assert_eq!(failed, 0, "❌ {} test step(s) failed!", failed);
    println!("\n🎉 All spec tests passed!");
}
