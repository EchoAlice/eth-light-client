#![cfg(test)]
//! # Light Client Sync Specification Tests
//!
//! Validates the Ethereum light client sync protocol against official
//! consensus-spec test vectors from https://github.com/ethereum/consensus-spec-tests
//!
//! Each test replays a fork's happy-path steps (1-5, all `process_update`)
//! through a fresh processor. The vectors also contain `force_update` steps
//! (6, 9), but `force_update` is not implemented, so those steps are skipped.

use crate::consensus::light_client::LightClientProcessor;
use crate::test_utils::{
    beacon_header_matches, hex_to_root, ProcessUpdateStep, SpecTestLoader, TestStep,
};
use crate::types::consensus::{LightClientHeader, LightClientUpdate};

/// Altair happy path (steps 1-5).
#[test]
fn test_altair_light_client_sync() {
    run_sync(
        SpecTestLoader::minimal_altair_sync(),
        "altair light client sync (steps 1-5)",
    );
}

/// Bellatrix happy path (steps 1-5).
#[test]
fn test_bellatrix_light_client_sync() {
    run_sync(
        SpecTestLoader::minimal_bellatrix_sync(),
        "bellatrix light client sync (steps 1-5)",
    );
}

/// Capella happy path (steps 1-5), incl. execution_root verification.
#[test]
fn test_capella_light_client_sync() {
    run_sync(
        SpecTestLoader::minimal_capella_sync(),
        "capella light client sync (steps 1-5)",
    );
}

/// Replay a fork's happy-path sync steps (1-5, all `process_update`) through a
/// fresh processor, asserting each passes. Later `force_update` steps are
/// skipped -- that feature is not implemented.
fn run_sync(loader: SpecTestLoader, label: &str) {
    let steps = loader.load_steps().expect("Failed to load steps");
    let mut processor = initialize_processor_from(&loader);
    let mut passed = 0;
    let mut failed = 0;

    println!("{}:", label);

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
                println!("  step {}: force_update (skipped, not implemented)", i + 1);
            }
        }
    }

    println!("  result: {}/{} passed", passed, passed + failed);
    assert_eq!(failed, 0, "{} step(s) failed", failed);
}

fn initialize_processor_from(loader: &SpecTestLoader) -> LightClientProcessor {
    let bootstrap = loader.load_bootstrap().expect("Failed to load bootstrap");
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
                if !beacon_header_matches(expected, processor.finalized_header()) {
                    println!("    FAIL finalized: expected slot={}", expected.slot);
                    step_passed = false;
                }

                if let Some(ref expected_exec_root) = expected.execution_root {
                    if !check_execution_root(
                        processor.finalized_light_client_header(),
                        expected_exec_root,
                        "finalized",
                    ) {
                        step_passed = false;
                    }
                }
            }

            if let Some(ref expected) = step.checks.optimistic_header {
                if !beacon_header_matches(expected, processor.optimistic_header()) {
                    println!("    FAIL optimistic: expected slot={}", expected.slot);
                    step_passed = false;
                }

                if let Some(ref expected_exec_root) = expected.execution_root {
                    if !check_execution_root(
                        processor.optimistic_light_client_header(),
                        expected_exec_root,
                        "optimistic",
                    ) {
                        step_passed = false;
                    }
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

fn check_execution_root(header: &LightClientHeader, expected_hex: &str, label: &str) -> bool {
    let expected = hex_to_root(expected_hex).expect("Invalid execution_root hex");
    match header {
        LightClientHeader::Capella(h) => {
            let actual = h.execution.hash_tree_root();
            if actual != expected {
                println!(
                    "    FAIL {} execution_root: expected {} got {}",
                    label,
                    hex::encode(expected),
                    hex::encode(actual),
                );
                return false;
            }
            true
        }
        _ => {
            // Altair/Bellatrix headers shouldn't have execution_root checks
            println!(
                "    FAIL {}: execution_root check on non-Capella header",
                label
            );
            false
        }
    }
}
