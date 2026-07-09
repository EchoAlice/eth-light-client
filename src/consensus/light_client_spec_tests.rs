#![cfg(test)]
//! # Light Client Sync Specification Tests
//!
//! Validates the Ethereum light client sync protocol against official
//! consensus-spec test vectors from https://github.com/ethereum/consensus-spec-tests
//!
//! Each test replays a fork's happy-path steps (1-5, all `process_update`)
//! through a fresh processor, asserting the resulting store state against the
//! fixture's expected headers. The vectors also contain `force_update` steps
//! (6, 9), but `force_update` is not implemented, so those steps are skipped.

use crate::consensus::light_client::LightClientProcessor;
use crate::test_utils::{
    beacon_header_matches, hex_to_root, ProcessUpdateStep, SpecTestLoader, TestStep,
};
use crate::types::consensus::LightClientHeader;

/// Altair happy path (steps 1-5).
#[test]
fn altair_sync_via_processor() {
    run_processor_sync(SpecTestLoader::minimal_altair_sync());
}

/// Bellatrix happy path (steps 1-5).
#[test]
fn bellatrix_sync_via_processor() {
    run_processor_sync(SpecTestLoader::minimal_bellatrix_sync());
}

/// Capella happy path (steps 1-5), incl. execution_root verification.
#[test]
fn capella_sync_via_processor() {
    run_processor_sync(SpecTestLoader::minimal_capella_sync());
}

/// Replay a fork's happy-path sync steps (1-5, all `process_update`) through a
/// fresh processor, asserting each against the fixture's expected state. Later
/// `force_update` steps are skipped -- that feature is not implemented.
fn run_processor_sync(loader: SpecTestLoader) {
    let steps = loader.load_steps().expect("Failed to load steps");
    let mut processor = initialize_processor_from(&loader);

    for (i, step) in steps.iter().enumerate().take(5) {
        match step {
            TestStep::ProcessUpdate { process_update } => {
                execute_process_update_step(i + 1, process_update, &mut processor, &loader);
            }
            TestStep::ForceUpdate { .. } => {} // not implemented -- skip
        }
    }
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

fn execute_process_update_step(
    step_num: usize,
    step: &ProcessUpdateStep,
    processor: &mut LightClientProcessor,
    loader: &SpecTestLoader,
) {
    let update = loader.load_update(&step.update).unwrap_or_else(|e| {
        panic!(
            "step {}: failed to load update {}: {}",
            step_num, step.update, e
        )
    });

    processor
        .process_update_at_slot(update, step.current_slot)
        .unwrap_or_else(|e| panic!("step {}: process error: {}", step_num, e));

    if let Some(expected) = &step.checks.finalized_header {
        assert!(
            beacon_header_matches(expected, processor.finalized_header()),
            "step {}: finalized header mismatch (expected slot {})",
            step_num,
            expected.slot,
        );
        if let Some(expected_exec_root) = &expected.execution_root {
            assert_execution_root(
                processor.finalized_light_client_header(),
                expected_exec_root,
                "finalized",
                step_num,
            );
        }
    }

    if let Some(expected) = &step.checks.optimistic_header {
        assert!(
            beacon_header_matches(expected, processor.optimistic_header()),
            "step {}: optimistic header mismatch (expected slot {})",
            step_num,
            expected.slot,
        );
        if let Some(expected_exec_root) = &expected.execution_root {
            assert_execution_root(
                processor.optimistic_light_client_header(),
                expected_exec_root,
                "optimistic",
                step_num,
            );
        }
    }
}

fn assert_execution_root(
    header: &LightClientHeader,
    expected_hex: &str,
    label: &str,
    step_num: usize,
) {
    let expected = hex_to_root(expected_hex).expect("Invalid execution_root hex");
    match header {
        LightClientHeader::Capella(h) => {
            let actual = h.execution.hash_tree_root();
            assert!(
                actual == expected,
                "step {}: {} execution_root mismatch: expected {}, got {}",
                step_num,
                label,
                hex::encode(expected),
                hex::encode(actual),
            );
        }
        _ => panic!(
            "step {}: {} execution_root check on non-Capella header",
            step_num, label
        ),
    }
}
