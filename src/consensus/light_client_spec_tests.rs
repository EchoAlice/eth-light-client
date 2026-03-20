#![cfg(test)]
//! # Light Client Sync Specification Tests
//!
//! Validates the Ethereum light client sync protocol against official
//! consensus-spec test vectors from https://github.com/ethereum/consensus-spec-tests
//!
//! ## Test Organization
//!
//! - `test_altair_light_client_sync` — Altair happy path (steps 1-5).
//! - `test_bellatrix_light_client_sync` — Bellatrix happy path (steps 1-5),
//!   using real Bellatrix spec fixtures.
//! - `test_altair_light_client_sync_with_force_update` — Full Altair spec test
//!   including all 10 steps. Currently `#[ignore]` until `force_update` is implemented.
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

/// Load Altair bootstrap data from test fixtures.
pub(crate) fn load_altair_bootstrap() -> LightClientBootstrap {
    let loader = SpecTestLoader::minimal_altair_sync();
    let bootstrap = loader.load_bootstrap().expect("Failed to load bootstrap");
    bootstrap.into_bootstrap()
}

/// Load Bellatrix bootstrap data from test fixtures.
#[allow(dead_code)]
pub(crate) fn load_bellatrix_bootstrap() -> LightClientBootstrap {
    let loader = SpecTestLoader::minimal_bellatrix_sync();
    let bootstrap = loader.load_bootstrap().expect("Failed to load bootstrap");
    bootstrap.into_bootstrap()
}

fn initialize_processor_from(loader: &SpecTestLoader) -> LightClientProcessor {
    let bootstrap = loader
        .load_bootstrap()
        .expect("Failed to load bootstrap")
        .into_bootstrap();
    let chain_spec = loader.chain_spec();

    LightClientProcessor::new(
        chain_spec,
        bootstrap.header.clone(),
        bootstrap.current_sync_committee,
        &bootstrap.current_sync_committee_branch,
        bootstrap.genesis_validators_root,
    )
    .expect("Failed to initialize LightClientProcessor")
}

struct StepResult {
    passed: bool,
}

fn execute_process_update_step(
    step_num: usize,
    step: &ProcessUpdateStep,
    processor: &mut LightClientProcessor,
    loader: &SpecTestLoader,
) -> StepResult {
    let update = match loader.load_update(&step.update) {
        Ok(u) => u,
        Err(e) => {
            println!("  step {}: FAIL - load error: {}", step_num, e);
            return StepResult { passed: false };
        }
    };

    let update_type = detect_update_type(&update);
    println!(
        "  step {}: {} (attested={}, sig={}, current_slot={})",
        step_num,
        update_type,
        update.attested_header.slot(),
        update.signature_slot,
        step.current_slot,
    );

    match processor.process_update_at_slot(update, step.current_slot) {
        Ok(_state_changed) => {
            let mut step_passed = true;

            if let Some(ref expected) = step.checks.finalized_header {
                let actual_slot = processor.finalized_header().slot;
                let actual_root = processor
                    .finalized_header()
                    .hash_tree_root()
                    .expect("hash_tree_root");
                let expected_root =
                    hex_to_root(&expected.beacon_root).expect("Invalid beacon_root");

                if actual_slot != expected.slot || actual_root != expected_root {
                    println!(
                        "    FAIL finalized: expected slot={} got={}",
                        expected.slot, actual_slot
                    );
                    step_passed = false;
                }
            }

            if let Some(ref expected) = step.checks.optimistic_header {
                let actual_slot = processor.optimistic_header().slot;
                let actual_root = processor
                    .optimistic_header()
                    .hash_tree_root()
                    .expect("hash_tree_root");
                let expected_root =
                    hex_to_root(&expected.beacon_root).expect("Invalid beacon_root");

                if actual_slot != expected.slot || actual_root != expected_root {
                    println!(
                        "    FAIL optimistic: expected slot={} got={}",
                        expected.slot, actual_slot
                    );
                    step_passed = false;
                }
            }

            StepResult {
                passed: step_passed,
            }
        }
        Err(e) => {
            println!("    FAIL: process error: {}", e);
            StepResult { passed: false }
        }
    }
}

fn execute_force_update_step(
    step_num: usize,
    step: &ForceUpdateStep,
    processor: &mut LightClientProcessor,
) -> bool {
    println!("  step {}: force_update (not implemented)", step_num);

    let mut step_passed = true;

    if let Some(ref expected) = step.checks.finalized_header {
        if processor.finalized_header().slot != expected.slot {
            step_passed = false;
        }
    }
    if let Some(ref expected) = step.checks.optimistic_header {
        if processor.optimistic_header().slot != expected.slot {
            step_passed = false;
        }
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
    let loader = SpecTestLoader::minimal_altair_sync();
    let steps = loader.load_steps().expect("Failed to load steps");
    let mut processor = initialize_processor_from(&loader);

    let mut passed = 0;
    let mut failed = 0;

    println!("altair light client sync (steps 1-5):");

    for (i, step) in steps.iter().enumerate().take(5) {
        match step {
            TestStep::ProcessUpdate { process_update } => {
                let result =
                    execute_process_update_step(i + 1, process_update, &mut processor, &loader);
                if result.passed {
                    passed += 1;
                } else {
                    failed += 1;
                }
            }
            TestStep::ForceUpdate { .. } => {
                println!("  step {}: force_update (skipped)", i + 1);
            }
        }
    }

    println!("  result: {}/{} passed", passed, passed + failed);
    assert_eq!(failed, 0, "{} step(s) failed", failed);
}

/// Bellatrix happy path using real Bellatrix spec fixtures.
/// Headers are tagged as `LightClientHeader::Bellatrix` and verified
/// with a Bellatrix-compatible `ChainSpec` (BELLATRIX_FORK_EPOCH=0).
#[test]
fn test_bellatrix_light_client_sync() {
    let loader = SpecTestLoader::minimal_bellatrix_sync();
    let steps = loader.load_steps().expect("Failed to load steps");
    let mut processor = initialize_processor_from(&loader);

    let mut passed = 0;
    let mut failed = 0;

    println!("bellatrix light client sync (steps 1-5):");

    for (i, step) in steps.iter().enumerate().take(5) {
        match step {
            TestStep::ProcessUpdate { process_update } => {
                let result =
                    execute_process_update_step(i + 1, process_update, &mut processor, &loader);
                if result.passed {
                    passed += 1;
                } else {
                    failed += 1;
                }
            }
            TestStep::ForceUpdate { .. } => {
                println!("  step {}: force_update (skipped)", i + 1);
            }
        }
    }

    println!("  result: {}/{} passed", passed, passed + failed);
    assert_eq!(failed, 0, "{} step(s) failed", failed);
}

/// Full spec compliance test including force_update steps.
/// Currently ignored because force_update is not implemented.
#[test]
#[ignore = "force_update not yet implemented"]
fn test_altair_light_client_sync_with_force_update() {
    let loader = SpecTestLoader::minimal_altair_sync();
    let steps = loader.load_steps().expect("Failed to load steps");
    let mut processor = initialize_processor_from(&loader);

    let mut passed = 0;
    let mut failed = 0;

    println!("altair light client sync (full, {} steps):", steps.len());

    for (i, step) in steps.iter().enumerate() {
        match step {
            TestStep::ProcessUpdate { process_update } => {
                let result =
                    execute_process_update_step(i + 1, process_update, &mut processor, &loader);
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

    println!("  result: {}/{} passed", passed, passed + failed);
    assert_eq!(failed, 0, "{} step(s) failed", failed);
}
