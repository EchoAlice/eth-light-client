mod common;

use common::{SyncTestCase, TestStep};
use eth_light_client::{Error, Fork, LightClient};

// Public-API behavior the all-valid replays can't express.

#[test]
fn committee_update_without_finality_is_not_learned() {
    let sync_test_case = SyncTestCase::light_client_sync(Fork::Altair);
    let bootstrap = sync_test_case.load_bootstrap().unwrap();

    let bootstrap_slot = bootstrap.header.slot();
    let mut client = LightClient::new(
        sync_test_case.chain_spec().clone(),
        sync_test_case.genesis_validators_root(),
        sync_test_case.trusted_block_root(),
        bootstrap,
        bootstrap_slot,
    )
    .unwrap();

    let steps = sync_test_case.load_steps().unwrap();
    let TestStep::ProcessUpdate(step) = &steps[0] else {
        panic!("first step is a process_update")
    };
    let mut update = sync_test_case
        .load_update(&step.update, step.update_fork_digest)
        .unwrap();
    assert!(update.next_sync_committee.is_some());
    update.finalized = None;

    let changes = client
        .process_light_client_update(update, step.current_slot)
        .unwrap();
    assert!(changes.optimistic_updated);
    assert!(!changes.next_committee_learned);
    assert!(client.next_sync_committee().is_none());
}

#[test]
fn trusted_root_freshness_boundary() {
    let sync_test = SyncTestCase::light_client_sync(Fork::Altair);
    let ws_period_as_slots = sync_test
        .chain_spec()
        .epoch_to_slot(sync_test.chain_spec().weak_subjectivity_period());

    // Exactly one weak subjectivity period old: still accepted.
    let bootstrap = sync_test.load_bootstrap().unwrap();
    let at_boundary = bootstrap.header.slot() + ws_period_as_slots;
    assert!(LightClient::new(
        sync_test.chain_spec().clone(),
        sync_test.genesis_validators_root(),
        sync_test.trusted_block_root(),
        bootstrap,
        at_boundary,
    )
    .is_ok());

    // One slot past the period: rejected, and with the staleness variant —
    // not the identity or proof errors that precede and follow the check.
    let bootstrap = sync_test.load_bootstrap().unwrap();
    let err = LightClient::new(
        sync_test.chain_spec().clone(),
        sync_test.genesis_validators_root(),
        sync_test.trusted_block_root(),
        bootstrap,
        at_boundary + 1,
    )
    .unwrap_err();
    assert!(matches!(err, Error::StaleTrustedRoot { .. }), "got: {err}");
}
