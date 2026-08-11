use super::*;

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

/// timestamp_to_slot is the facade's wall-clock path — the replays never touch
/// it (they inject slots directly). Before-genesis fails closed to slot 0.
#[test]
fn test_timestamp_to_slot() {
    let spec = ChainSpec::mainnet();

    // Mainnet genesis: Dec 1, 2020, 12:00:23 UTC; 12 seconds per slot.
    assert_eq!(spec.timestamp_to_slot(1606824023), 0);
    assert_eq!(spec.timestamp_to_slot(1606824023 + 12), 1);
    assert_eq!(spec.timestamp_to_slot(1606824023 + 120), 10);
    assert_eq!(spec.timestamp_to_slot(1606824023 - 100), 0);
}

// ChainSpecConfig validation: Err paths no fixture can produce — the public
// custom-config contract refuses malformed specs.

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
