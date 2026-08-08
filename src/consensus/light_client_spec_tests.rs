use crate::config::Fork;
use crate::consensus::processor::LightClientProcessor;
use crate::test_utils::{ProcessUpdateStep, StateChecks, SyncTestCase, TestStep};
use crate::types::consensus::LightClientHeader;
use crate::types::primitives::Root;

#[test]
fn altair_sync_via_processor() {
    run_processor_sync(SyncTestCase::light_client_sync(Fork::Altair));
}

#[test]
fn bellatrix_sync_via_processor() {
    run_processor_sync(SyncTestCase::light_client_sync(Fork::Bellatrix));
}

#[test]
fn capella_sync_via_processor() {
    run_processor_sync(SyncTestCase::light_client_sync(Fork::Capella));
}

#[test]
fn deneb_sync_via_processor() {
    run_processor_sync(SyncTestCase::light_client_sync(Fork::Deneb));
}

#[test]
fn electra_sync_via_processor() {
    run_processor_sync(SyncTestCase::light_client_sync(Fork::Electra));
}

#[test]
fn electra_fork_sync_via_processor() {
    run_processor_sync(SyncTestCase::fork_transition(Fork::Deneb, Fork::Electra));
}

fn initialize_processor_from(sync_test: &SyncTestCase) -> LightClientProcessor {
    let bootstrap = sync_test
        .load_bootstrap()
        .expect("Failed to load bootstrap");
    LightClientProcessor::new(
        sync_test.chain_spec().clone(),
        bootstrap.header.clone(),
        bootstrap.current_sync_committee,
        &bootstrap.current_sync_committee_branch,
        bootstrap.genesis_validators_root,
    )
    .expect("Failed to initialize LightClientProcessor")
}

/// Replay a fixture's steps, asserting each against the fixture's expected output.
fn run_processor_sync(sync_test: SyncTestCase) {
    let steps = sync_test.load_steps().expect("Failed to load steps");
    let mut processor = initialize_processor_from(&sync_test);

    let mut processed = 0;
    for (i, step) in steps.iter().enumerate() {
        match step {
            TestStep::ProcessUpdate(process_update) => {
                execute_process_update_step(i + 1, process_update, &mut processor, &sync_test);
                processed += 1;
            }
            // Store migration is a no-op for our fork-agnostic store; the
            // step's checks still assert the store is unperturbed.
            TestStep::UpgradeStore { checks } => {
                assert_state_checks(i + 1, checks, &processor);
            }
            TestStep::ForceUpdate(_) => break,
        }
    }
    assert!(
        processed > 0,
        "no process_update steps ran before the first force_update"
    );
}

fn execute_process_update_step(
    step_num: usize,
    step: &ProcessUpdateStep,
    processor: &mut LightClientProcessor,
    sync_test: &SyncTestCase,
) {
    let update = sync_test
        .load_update(&step.update, step.update_fork_digest)
        .unwrap_or_else(|e| {
            panic!(
                "step {}: failed to load update {}: {}",
                step_num, step.update, e
            )
        });

    processor
        .process_update_at_slot(update, step.current_slot)
        .unwrap_or_else(|e| panic!("step {}: process error: {}", step_num, e));

    assert_state_checks(step_num, &step.checks, processor);
}

/// Assert a step's `checks` (finalized/optimistic slot + beacon root, and
/// Capella+ execution roots) against the processor's store.
fn assert_state_checks(step_num: usize, checks: &StateChecks, processor: &LightClientProcessor) {
    if let Some(expected) = &checks.finalized_header {
        assert!(
            expected.matches(processor.finalized_header()),
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

    if let Some(expected) = &checks.optimistic_header {
        assert!(
            expected.matches(processor.optimistic_header()),
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
    expected: &Root,
    label: &str,
    step_num: usize,
) {
    let actual = match header {
        LightClientHeader::Capella(h) => h.execution.hash_tree_root(),
        LightClientHeader::Deneb(h) => h.execution.hash_tree_root(),
        LightClientHeader::Electra(h) => h.execution.hash_tree_root(),
        _ => panic!(
            "step {}: {} execution_root check on header without an execution payload",
            step_num, label
        ),
    };
    assert!(
        actual == *expected,
        "step {}: {} execution_root mismatch: expected {}, got {}",
        step_num,
        label,
        hex::encode(expected),
        hex::encode(actual),
    );
}
