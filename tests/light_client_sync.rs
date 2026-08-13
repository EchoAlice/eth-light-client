#![cfg(feature = "test-utils")]

use eth_light_client::test_utils::{ProcessUpdateStep, StateChecks, SyncTestCase, TestStep};
use eth_light_client::{Fork, LightClient, UpdateOutcome};

#[test]
fn altair_sync_via_public_api() {
    run_public_api_sync(SyncTestCase::light_client_sync(Fork::Altair));
}

#[test]
fn bellatrix_sync_via_public_api() {
    run_public_api_sync(SyncTestCase::light_client_sync(Fork::Bellatrix));
}

#[test]
fn capella_sync_via_public_api() {
    run_public_api_sync(SyncTestCase::light_client_sync(Fork::Capella));
}

#[test]
fn deneb_sync_via_public_api() {
    run_public_api_sync(SyncTestCase::light_client_sync(Fork::Deneb));
}

#[test]
fn electra_sync_via_public_api() {
    run_public_api_sync(SyncTestCase::light_client_sync(Fork::Electra));
}

#[test]
fn altair_advance_finality_without_sync_committee_via_public_api() {
    run_public_api_sync(SyncTestCase::advance_finality_without_sync_committee(
        Fork::Altair,
    ));
}

#[test]
fn bellatrix_advance_finality_without_sync_committee_via_public_api() {
    run_public_api_sync(SyncTestCase::advance_finality_without_sync_committee(
        Fork::Bellatrix,
    ));
}

#[test]
fn capella_advance_finality_without_sync_committee_via_public_api() {
    run_public_api_sync(SyncTestCase::advance_finality_without_sync_committee(
        Fork::Capella,
    ));
}

#[test]
fn deneb_advance_finality_without_sync_committee_via_public_api() {
    run_public_api_sync(SyncTestCase::advance_finality_without_sync_committee(
        Fork::Deneb,
    ));
}

#[test]
fn electra_advance_finality_without_sync_committee_via_public_api() {
    run_public_api_sync(SyncTestCase::advance_finality_without_sync_committee(
        Fork::Electra,
    ));
}

#[test]
fn altair_supply_sync_committee_from_past_update_via_public_api() {
    run_public_api_sync(SyncTestCase::supply_sync_committee_from_past_update(
        Fork::Altair,
    ));
}

#[test]
fn bellatrix_supply_sync_committee_from_past_update_via_public_api() {
    run_public_api_sync(SyncTestCase::supply_sync_committee_from_past_update(
        Fork::Bellatrix,
    ));
}

#[test]
fn capella_supply_sync_committee_from_past_update_via_public_api() {
    run_public_api_sync(SyncTestCase::supply_sync_committee_from_past_update(
        Fork::Capella,
    ));
}

#[test]
fn deneb_supply_sync_committee_from_past_update_via_public_api() {
    run_public_api_sync(SyncTestCase::supply_sync_committee_from_past_update(
        Fork::Deneb,
    ));
}

#[test]
fn electra_supply_sync_committee_from_past_update_via_public_api() {
    run_public_api_sync(SyncTestCase::supply_sync_committee_from_past_update(
        Fork::Electra,
    ));
}

#[test]
fn capella_fork_sync_via_public_api() {
    run_public_api_sync(SyncTestCase::fork_transition(
        Fork::Bellatrix,
        Fork::Capella,
    ));
}

#[test]
fn deneb_fork_sync_via_public_api() {
    run_public_api_sync(SyncTestCase::fork_transition(Fork::Capella, Fork::Deneb));
}

#[test]
fn electra_fork_sync_via_public_api() {
    run_public_api_sync(SyncTestCase::fork_transition(Fork::Deneb, Fork::Electra));
}

fn run_public_api_sync(sync_test: SyncTestCase) {
    let bootstrap = sync_test
        .load_bootstrap()
        .expect("Failed to load bootstrap");
    let steps = sync_test.load_steps().expect("Failed to load steps");

    let mut client = LightClient::new(sync_test.chain_spec().clone(), bootstrap)
        .expect("Failed to initialize LightClient");

    let mut processed = 0;
    for (i, step) in steps.iter().enumerate() {
        match step {
            TestStep::ProcessUpdate(process_update) => {
                process_step(&mut client, &sync_test, process_update, i + 1);
                processed += 1;
            }
            // Store migration is a no-op for this store; the step's checks
            // still assert the store is unperturbed.
            TestStep::UpgradeStore { checks } => {
                assert_header_checks(&client, checks, i + 1);
            }
            TestStep::ForceUpdate(_) => break,
        }
    }
    assert!(
        processed > 0,
        "no process_update steps ran before the first force_update"
    );
}

fn process_step(
    client: &mut LightClient,
    sync_test: &SyncTestCase,
    step: &ProcessUpdateStep,
    step_num: usize,
) {
    let update = sync_test
        .load_update(&step.update, step.update_fork_digest)
        .expect("Failed to load update");

    let before_finalized = client.finalized_beacon_block_header().slot;
    let before_optimistic = client.optimistic_beacon_block_header().slot;

    let outcome: UpdateOutcome = client
        .process_update_at_slot(update, step.current_slot)
        .unwrap_or_else(|e| panic!("step {}: error processing update: {}", step_num, e));

    let after_finalized = client.finalized_beacon_block_header().slot;
    let after_optimistic = client.optimistic_beacon_block_header().slot;

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

    assert_header_checks(client, &step.checks, step_num);
}

/// Assert a step's `checks` (slot + beacon root; the public API exposes only
/// `BeaconBlockHeader`, so execution roots are covered by the processor replay).
fn assert_header_checks(client: &LightClient, checks: &StateChecks, step_num: usize) {
    if let Some(expected) = &checks.finalized_header {
        assert!(
            expected.matches(client.finalized_beacon_block_header()),
            "step {}: finalized header mismatch (expected slot {})",
            step_num,
            expected.slot,
        );
    }
    if let Some(expected) = &checks.optimistic_header {
        assert!(
            expected.matches(client.optimistic_beacon_block_header()),
            "step {}: optimistic header mismatch (expected slot {})",
            step_num,
            expected.slot,
        );
    }
}
