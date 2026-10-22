mod common;

use common::{ProcessUpdateStep, StateChecks, SyncTestCase, TestStep};
use eth_light_client::{Fork, LightClient};

#[test]
fn altair_light_client_sync() {
    run_public_api_sync(SyncTestCase::light_client_sync(Fork::Altair));
}

#[test]
fn altair_advance_finality_without_sync_committee() {
    run_public_api_sync(SyncTestCase::advance_finality_without_sync_committee(
        Fork::Altair,
    ));
}

#[test]
fn altair_supply_sync_committee_from_past_update() {
    run_public_api_sync(SyncTestCase::supply_sync_committee_from_past_update(
        Fork::Altair,
    ));
}

#[test]
fn altair_light_client_sync_no_force_update() {
    run_public_api_sync(SyncTestCase::light_client_sync_no_force_update(
        Fork::Altair,
    ));
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn altair_capella_store_with_legacy_data() {
    todo!()
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn altair_deneb_store_with_legacy_data() {
    todo!()
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn altair_electra_store_with_legacy_data() {
    todo!()
}

#[test]
fn bellatrix_light_client_sync() {
    run_public_api_sync(SyncTestCase::light_client_sync(Fork::Bellatrix));
}

#[test]
fn bellatrix_advance_finality_without_sync_committee() {
    run_public_api_sync(SyncTestCase::advance_finality_without_sync_committee(
        Fork::Bellatrix,
    ));
}

#[test]
fn bellatrix_supply_sync_committee_from_past_update() {
    run_public_api_sync(SyncTestCase::supply_sync_committee_from_past_update(
        Fork::Bellatrix,
    ));
}

#[test]
fn bellatrix_capella_fork() {
    run_public_api_sync(SyncTestCase::fork_transition(
        Fork::Bellatrix,
        Fork::Capella,
    ));
}

#[test]
fn bellatrix_light_client_sync_no_force_update() {
    run_public_api_sync(SyncTestCase::light_client_sync_no_force_update(
        Fork::Bellatrix,
    ));
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn bellatrix_capella_deneb_fork() {
    todo!()
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn bellatrix_capella_electra_fork() {
    todo!()
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn bellatrix_capella_store_with_legacy_data() {
    todo!()
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn bellatrix_deneb_store_with_legacy_data() {
    todo!()
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn bellatrix_electra_store_with_legacy_data() {
    todo!()
}

#[test]
fn capella_light_client_sync() {
    run_public_api_sync(SyncTestCase::light_client_sync(Fork::Capella));
}

#[test]
fn capella_advance_finality_without_sync_committee() {
    run_public_api_sync(SyncTestCase::advance_finality_without_sync_committee(
        Fork::Capella,
    ));
}

#[test]
fn capella_supply_sync_committee_from_past_update() {
    run_public_api_sync(SyncTestCase::supply_sync_committee_from_past_update(
        Fork::Capella,
    ));
}

#[test]
fn capella_deneb_fork() {
    run_public_api_sync(SyncTestCase::fork_transition(Fork::Capella, Fork::Deneb));
}

#[test]
fn capella_light_client_sync_no_force_update() {
    run_public_api_sync(SyncTestCase::light_client_sync_no_force_update(
        Fork::Capella,
    ));
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn capella_deneb_electra_fork() {
    todo!()
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn capella_deneb_store_with_legacy_data() {
    todo!()
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn capella_electra_store_with_legacy_data() {
    todo!()
}

#[test]
fn deneb_light_client_sync() {
    run_public_api_sync(SyncTestCase::light_client_sync(Fork::Deneb));
}

#[test]
fn deneb_advance_finality_without_sync_committee() {
    run_public_api_sync(SyncTestCase::advance_finality_without_sync_committee(
        Fork::Deneb,
    ));
}

#[test]
fn deneb_supply_sync_committee_from_past_update() {
    run_public_api_sync(SyncTestCase::supply_sync_committee_from_past_update(
        Fork::Deneb,
    ));
}

#[test]
fn deneb_electra_fork() {
    run_public_api_sync(SyncTestCase::fork_transition(Fork::Deneb, Fork::Electra));
}

#[test]
fn deneb_light_client_sync_no_force_update() {
    run_public_api_sync(SyncTestCase::light_client_sync_no_force_update(Fork::Deneb));
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn deneb_electra_store_with_legacy_data() {
    todo!()
}

#[test]
fn electra_light_client_sync() {
    run_public_api_sync(SyncTestCase::light_client_sync(Fork::Electra));
}

#[test]
fn electra_advance_finality_without_sync_committee() {
    run_public_api_sync(SyncTestCase::advance_finality_without_sync_committee(
        Fork::Electra,
    ));
}

#[test]
fn electra_supply_sync_committee_from_past_update() {
    run_public_api_sync(SyncTestCase::supply_sync_committee_from_past_update(
        Fork::Electra,
    ));
}

#[test]
fn electra_light_client_sync_no_force_update() {
    run_public_api_sync(SyncTestCase::light_client_sync_no_force_update(
        Fork::Electra,
    ));
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn fulu_light_client_sync() {
    todo!()
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn fulu_advance_finality_without_sync_committee() {
    todo!()
}

#[test]
#[ignore = "TODO(#106): wire the constructor"]
fn fulu_supply_sync_committee_from_past_update() {
    todo!()
}

#[test]
#[ignore = "TODO(#106): Fulu digest resolution"]
fn fulu_light_client_sync_no_force_update() {
    run_public_api_sync(SyncTestCase::light_client_sync_no_force_update(Fork::Fulu));
}

// The replay: one fixture case through the public API.

fn run_public_api_sync(sync_test: SyncTestCase) {
    let bootstrap = sync_test
        .load_bootstrap()
        .expect("Failed to load bootstrap");
    let steps = sync_test.load_steps().expect("Failed to load steps");

    // Fixtures don't carry a bootstrap clock. The header's own slot is the
    // earliest honest one.
    let bootstrap_slot = bootstrap.header.slot();
    let mut client = LightClient::new(
        sync_test.chain_spec().clone(),
        sync_test.genesis_validators_root(),
        sync_test.trusted_block_root(),
        bootstrap,
        bootstrap_slot,
    )
    .expect("Failed to initialize LightClient");

    let mut processed = 0;
    for (i, step) in steps.iter().enumerate() {
        match step {
            TestStep::ProcessUpdate(process_update) => {
                process_step(&mut client, &sync_test, process_update, i + 1);
                processed += 1;
            }
            // Store migration is a no-op for this store; the step's checks
            // still assert the store isn't changed.
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

    client
        .process_light_client_update(update, step.current_slot)
        .unwrap_or_else(|e| panic!("step {}: error processing update: {}", step_num, e));

    assert_header_checks(client, &step.checks, step_num);
}

fn assert_header_checks(client: &LightClient, checks: &StateChecks, step_num: usize) {
    if let Some(expected) = &checks.finalized_header {
        assert!(
            expected.matches(client.finalized_beacon_block_header()),
            "step {}: finalized header mismatch (expected slot {})",
            step_num,
            expected.slot,
        );
        if let Some(root) = expected.execution_payload_root {
            assert_eq!(
                Some(root),
                client.finalized_execution_payload_root(),
                "step {step_num}: finalized execution payload root mismatch"
            );
        }
    }

    if let Some(expected) = &checks.optimistic_header {
        assert!(
            expected.matches(client.optimistic_beacon_block_header()),
            "step {}: optimistic header mismatch (expected slot {})",
            step_num,
            expected.slot,
        );
        if let Some(root) = expected.execution_payload_root {
            assert_eq!(
                Some(root),
                client.optimistic_execution_payload_root(),
                "step {step_num}: finalized execution payload root mismatch"
            );
        }
    }
}
