//! Tests for the config module.

use super::*;

#[test]
fn test_mainnet_spec() {
    let spec = ChainSpec::mainnet();
    assert_eq!(spec.preset_name(), "mainnet");
    assert_eq!(spec.slots_per_epoch(), 32);
    assert_eq!(spec.epochs_per_sync_committee_period(), 256);
    assert_eq!(spec.sync_committee_size(), 512);
    assert_eq!(spec.slots_per_sync_committee_period(), 8192);
    // Altair version via the live path (Altair is the genesis fork for the LC).
    assert_eq!(spec.fork_version_at_epoch(0), [0x01, 0x00, 0x00, 0x00]);
}

#[test]
fn test_minimal_spec() {
    let spec = ChainSpec::minimal();
    assert_eq!(spec.preset_name(), "minimal");
    assert_eq!(spec.slots_per_epoch(), 8);
    assert_eq!(spec.epochs_per_sync_committee_period(), 8);
    assert_eq!(spec.sync_committee_size(), 32);
    assert_eq!(spec.slots_per_sync_committee_period(), 64);
    assert_eq!(spec.fork_version_at_epoch(0), [0x01, 0x00, 0x00, 0x01]);
}

#[test]
fn test_slot_to_period_mainnet() {
    let spec = ChainSpec::mainnet();
    assert_eq!(spec.slot_to_sync_committee_period(0), 0);
    assert_eq!(spec.slot_to_sync_committee_period(8191), 0);
    assert_eq!(spec.slot_to_sync_committee_period(8192), 1);
    assert_eq!(spec.slot_to_sync_committee_period(16383), 1);
    assert_eq!(spec.slot_to_sync_committee_period(16384), 2);
}

#[test]
fn test_slot_to_period_minimal() {
    let spec = ChainSpec::minimal();
    assert_eq!(spec.slot_to_sync_committee_period(0), 0);
    assert_eq!(spec.slot_to_sync_committee_period(63), 0);
    assert_eq!(spec.slot_to_sync_committee_period(64), 1);
    assert_eq!(spec.slot_to_sync_committee_period(127), 1);
    assert_eq!(spec.slot_to_sync_committee_period(128), 2);
}

#[test]
fn test_period_boundaries() {
    let spec = ChainSpec::minimal();
    assert_eq!(spec.sync_committee_period_start_slot(0), 0);
    assert_eq!(spec.sync_committee_period_end_slot(0), 63);
    assert_eq!(spec.sync_committee_period_start_slot(1), 64);
    assert_eq!(spec.sync_committee_period_end_slot(1), 127);
}

#[test]
fn test_timestamp_to_slot_mainnet() {
    let spec = ChainSpec::mainnet();
    // Mainnet genesis: Dec 1, 2020, 12:00:23 UTC
    // 12 seconds per slot
    assert_eq!(spec.timestamp_to_slot(1606824023), 0); // Genesis
    assert_eq!(spec.timestamp_to_slot(1606824023 + 12), 1); // 1 slot later
    assert_eq!(spec.timestamp_to_slot(1606824023 + 120), 10); // 10 slots later
    assert_eq!(spec.timestamp_to_slot(1606824023 - 100), 0); // Before genesis
}

#[test]
fn test_timestamp_to_slot_minimal() {
    let spec = ChainSpec::minimal();
    // Minimal: 6 seconds per slot
    assert_eq!(spec.timestamp_to_slot(1578009600), 0); // Genesis
    assert_eq!(spec.timestamp_to_slot(1578009600 + 6), 1); // 1 slot later
    assert_eq!(spec.timestamp_to_slot(1578009600 + 60), 10); // 10 slots later
    assert_eq!(spec.timestamp_to_slot(1578009600 - 100), 0); // Before genesis
}

// Fork Detection Tests
#[test]
fn test_fork_at_epoch_mainnet() {
    let spec = ChainSpec::mainnet();

    // Before Altair (shouldn't happen in practice, but returns Altair)
    assert_eq!(spec.fork_at_epoch(0), Fork::Altair);

    // Altair epoch boundary
    assert_eq!(spec.fork_at_epoch(74239), Fork::Altair);
    assert_eq!(spec.fork_at_epoch(74240), Fork::Altair); // Altair activates

    // Bellatrix epoch boundary
    assert_eq!(spec.fork_at_epoch(144895), Fork::Altair);
    assert_eq!(spec.fork_at_epoch(144896), Fork::Bellatrix);

    // Capella epoch boundary
    assert_eq!(spec.fork_at_epoch(194047), Fork::Bellatrix);
    assert_eq!(spec.fork_at_epoch(194048), Fork::Capella);

    // Deneb epoch boundary
    assert_eq!(spec.fork_at_epoch(269567), Fork::Capella);
    assert_eq!(spec.fork_at_epoch(269568), Fork::Deneb);

    // Electra epoch boundary
    assert_eq!(spec.fork_at_epoch(364543), Fork::Deneb);
    assert_eq!(spec.fork_at_epoch(364544), Fork::Electra);

    // Far future
    assert_eq!(spec.fork_at_epoch(1_000_000), Fork::Electra);
}

#[test]
fn test_fork_at_slot_mainnet() {
    let spec = ChainSpec::mainnet();

    // Bellatrix boundary: epoch 144896 * 32 slots = slot 4636672
    let bellatrix_start_slot = 144896 * 32;
    assert_eq!(spec.fork_at_slot(bellatrix_start_slot - 1), Fork::Altair);
    assert_eq!(spec.fork_at_slot(bellatrix_start_slot), Fork::Bellatrix);

    // Electra boundary: epoch 364544 * 32 slots = slot 11665408
    let electra_start_slot = 364544 * 32;
    assert_eq!(spec.fork_at_slot(electra_start_slot - 1), Fork::Deneb);
    assert_eq!(spec.fork_at_slot(electra_start_slot), Fork::Electra);
}

#[test]
fn test_fork_version_at_epoch_mainnet() {
    let spec = ChainSpec::mainnet();

    assert_eq!(spec.fork_version_at_epoch(74240), [0x01, 0x00, 0x00, 0x00]); // Altair
    assert_eq!(spec.fork_version_at_epoch(144896), [0x02, 0x00, 0x00, 0x00]); // Bellatrix
    assert_eq!(spec.fork_version_at_epoch(194048), [0x03, 0x00, 0x00, 0x00]); // Capella
    assert_eq!(spec.fork_version_at_epoch(269568), [0x04, 0x00, 0x00, 0x00]); // Deneb
    assert_eq!(spec.fork_version_at_epoch(364544), [0x05, 0x00, 0x00, 0x00]);
    // Electra
}

#[test]
fn test_fork_minimal_preset() {
    let spec = ChainSpec::minimal();

    // Minimal has only Altair active; all later forks at u64::MAX
    assert_eq!(spec.fork_at_epoch(0), Fork::Altair);
    assert_eq!(spec.fork_at_epoch(1000), Fork::Altair);
    assert_eq!(spec.fork_at_epoch(u64::MAX - 1), Fork::Altair);
    // Note: u64::MAX would match all fork epochs set to MAX, but since
    // we check in reverse order, it would return Electra. However, this
    // is an edge case that doesn't occur in practice.
}

#[test]
fn test_fork_ordering() {
    // Ensure Fork enum ordering is correct for comparisons
    assert!(Fork::Altair < Fork::Bellatrix);
    assert!(Fork::Bellatrix < Fork::Capella);
    assert!(Fork::Capella < Fork::Deneb);
    assert!(Fork::Deneb < Fork::Electra);
}

// Generalized Index Tests
#[test]
fn test_gindex_altair_through_deneb() {
    let spec = ChainSpec::mainnet();

    // Test slots in Altair through Deneb (all should use same gindices)
    let altair_slot = 74240 * 32; // First Altair slot
    let deneb_slot = 269568 * 32; // First Deneb slot

    // Altair
    assert_eq!(spec.current_sync_committee_gindex(altair_slot), 54);
    assert_eq!(spec.next_sync_committee_gindex(altair_slot), 55);
    assert_eq!(spec.finalized_root_gindex(altair_slot), 105);

    // Deneb (same gindices)
    assert_eq!(spec.current_sync_committee_gindex(deneb_slot), 54);
    assert_eq!(spec.next_sync_committee_gindex(deneb_slot), 55);
    assert_eq!(spec.finalized_root_gindex(deneb_slot), 105);
}

#[test]
fn test_gindex_electra() {
    let spec = ChainSpec::mainnet();

    // Electra changes gindices due to BeaconState restructuring
    let electra_slot = 364544 * 32; // First Electra slot

    assert_eq!(spec.current_sync_committee_gindex(electra_slot), 86);
    assert_eq!(spec.next_sync_committee_gindex(electra_slot), 87);
    assert_eq!(spec.finalized_root_gindex(electra_slot), 169);
}

#[test]
fn test_gindex_boundary() {
    let spec = ChainSpec::mainnet();

    // Test right at the Electra boundary
    let pre_electra_slot = 364544 * 32 - 1;
    let electra_slot = 364544 * 32;

    // Pre-Electra (Deneb)
    assert_eq!(spec.current_sync_committee_gindex(pre_electra_slot), 54);
    assert_eq!(spec.next_sync_committee_gindex(pre_electra_slot), 55);
    assert_eq!(spec.finalized_root_gindex(pre_electra_slot), 105);

    // Electra
    assert_eq!(spec.current_sync_committee_gindex(electra_slot), 86);
    assert_eq!(spec.next_sync_committee_gindex(electra_slot), 87);
    assert_eq!(spec.finalized_root_gindex(electra_slot), 169);
}

#[test]
fn test_gindex_minimal_preset() {
    let spec = ChainSpec::minimal();

    // Minimal has Electra at u64::MAX, so all practical slots use pre-Electra gindices
    assert_eq!(spec.current_sync_committee_gindex(0), 54);
    assert_eq!(spec.next_sync_committee_gindex(0), 55);
    assert_eq!(spec.finalized_root_gindex(0), 105);

    assert_eq!(spec.current_sync_committee_gindex(1_000_000), 54);
    assert_eq!(spec.next_sync_committee_gindex(1_000_000), 55);
    assert_eq!(spec.finalized_root_gindex(1_000_000), 105);
}

// ChainSpecConfig Tests

fn valid_config() -> ChainSpecConfig {
    ChainSpecConfig {
        genesis_time: 1700000000,
        seconds_per_slot: 12,
        slots_per_epoch: 32,
        epochs_per_sync_committee_period: 256,
        sync_committee_size: 512,
        altair_fork_version: [0x01, 0x00, 0x00, 0x00],
        bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
        capella_fork_version: [0x03, 0x00, 0x00, 0x00],
        deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
        electra_fork_version: [0x05, 0x00, 0x00, 0x00],
        altair_fork_epoch: 0,
        bellatrix_fork_epoch: 0,
        capella_fork_epoch: 0,
        deneb_fork_epoch: 0,
        electra_fork_epoch: 10,
    }
}

#[test]
fn test_chainspec_config_valid() {
    let config = valid_config();
    assert!(config.validate().is_ok());

    let spec = ChainSpec::try_from_config(config).unwrap();
    assert_eq!(spec.preset_name(), "custom");
    assert_eq!(spec.genesis_time(), 1700000000);
    assert_eq!(spec.seconds_per_slot(), 12);
    assert_eq!(spec.slots_per_epoch(), 32);
    assert_eq!(spec.epochs_per_sync_committee_period(), 256);
    assert_eq!(spec.sync_committee_size(), 512);
}

#[test]
fn test_chainspec_config_custom_timing() {
    let config = ChainSpecConfig {
        genesis_time: 1234567890,
        seconds_per_slot: 6,
        slots_per_epoch: 8,
        epochs_per_sync_committee_period: 8,
        sync_committee_size: 32,
        altair_fork_version: [0xAA, 0xBB, 0xCC, 0xDD],
        bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
        capella_fork_version: [0x03, 0x00, 0x00, 0x00],
        deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
        electra_fork_version: [0x05, 0x00, 0x00, 0x00],
        altair_fork_epoch: 0,
        bellatrix_fork_epoch: 100,
        capella_fork_epoch: 200,
        deneb_fork_epoch: 300,
        electra_fork_epoch: 400,
    };

    let spec = ChainSpec::try_from_config(config).unwrap();

    // Test slot_to_epoch with custom slots_per_epoch=8
    assert_eq!(spec.slot_to_epoch(0), 0);
    assert_eq!(spec.slot_to_epoch(7), 0);
    assert_eq!(spec.slot_to_epoch(8), 1);
    assert_eq!(spec.slot_to_epoch(16), 2);

    // Test fork_at_epoch with custom fork schedule
    assert_eq!(spec.fork_at_epoch(0), Fork::Altair);
    assert_eq!(spec.fork_at_epoch(99), Fork::Altair);
    assert_eq!(spec.fork_at_epoch(100), Fork::Bellatrix);
    assert_eq!(spec.fork_at_epoch(199), Fork::Bellatrix);
    assert_eq!(spec.fork_at_epoch(200), Fork::Capella);
    assert_eq!(spec.fork_at_epoch(300), Fork::Deneb);
    assert_eq!(spec.fork_at_epoch(400), Fork::Electra);

    // Test fork_version_at_epoch with custom fork version
    assert_eq!(spec.fork_version_at_epoch(0), [0xAA, 0xBB, 0xCC, 0xDD]);

    // Test fork_at_slot (slot 800 = epoch 100 = Bellatrix)
    assert_eq!(spec.fork_at_slot(800), Fork::Bellatrix);
}

#[test]
fn test_chainspec_config_validation_seconds_per_slot() {
    let mut config = valid_config();
    config.seconds_per_slot = 0;
    assert!(config.validate().is_err());
    assert!(ChainSpec::try_from_config(config).is_err());
}

#[test]
fn test_chainspec_config_validation_slots_per_epoch() {
    let mut config = valid_config();
    config.slots_per_epoch = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_chainspec_config_validation_epochs_per_period() {
    let mut config = valid_config();
    config.epochs_per_sync_committee_period = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_chainspec_config_validation_sync_committee_size() {
    // Valid sizes: 32 and 512
    let mut config = valid_config();
    config.sync_committee_size = 32;
    assert!(config.validate().is_ok());

    config.sync_committee_size = 512;
    assert!(config.validate().is_ok());

    // Invalid sizes
    config.sync_committee_size = 0;
    assert!(config.validate().is_err());

    config.sync_committee_size = 64;
    assert!(config.validate().is_err());

    config.sync_committee_size = 256;
    assert!(config.validate().is_err());

    config.sync_committee_size = 1024;
    assert!(config.validate().is_err());
}

#[test]
fn test_chainspec_config_validation_altair_epoch() {
    // Altair need not activate at genesis: real mainnet (Altair @ 74240)
    // is a valid config. The LC operates from Altair onward via its trusted
    // bootstrap, not via a genesis-Altair schedule. See #63.
    assert!(ChainSpecConfig::mainnet().validate().is_ok());

    // Altair is still the monotonic floor: a later fork before it is invalid.
    let mut config = valid_config();
    config.altair_fork_epoch = 10;
    config.bellatrix_fork_epoch = 5;
    assert!(config.validate().is_err());
}

#[test]
fn test_chainspec_config_validation_fork_ordering() {
    // bellatrix < altair
    let mut config = valid_config();
    config.altair_fork_epoch = 0;
    config.bellatrix_fork_epoch = 0; // Equal is OK
    assert!(config.validate().is_ok());

    // capella < bellatrix
    let mut config = valid_config();
    config.bellatrix_fork_epoch = 100;
    config.capella_fork_epoch = 50;
    assert!(config.validate().is_err());

    // deneb < capella
    let mut config = valid_config();
    config.capella_fork_epoch = 100;
    config.deneb_fork_epoch = 50;
    assert!(config.validate().is_err());

    // electra < deneb
    let mut config = valid_config();
    config.deneb_fork_epoch = 100;
    config.electra_fork_epoch = 50;
    assert!(config.validate().is_err());
}
