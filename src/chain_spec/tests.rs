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
        fulu_fork_version: [0x06, 0x00, 0x00, 0x00],
        altair_fork_epoch: 0,
        bellatrix_fork_epoch: 0,
        capella_fork_epoch: 0,
        deneb_fork_epoch: 0,
        electra_fork_epoch: 10,
        fulu_fork_epoch: 1000,
        blob_schedule: &[],
    }
}

#[test]
fn timestamp_to_slot_fails_closed_before_genesis() {
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
fn rejects_zero_seconds_per_slot() {
    let mut config = valid_config();
    config.seconds_per_slot = 0;
    assert!(config.validate().is_err());
    assert!(ChainSpec::try_from_config(config).is_err());
}

#[test]
fn rejects_zero_slots_per_epoch() {
    let mut config = valid_config();
    config.slots_per_epoch = 0;
    assert!(config.validate().is_err());
}

#[test]
fn rejects_zero_epochs_per_period() {
    let mut config = valid_config();
    config.epochs_per_sync_committee_period = 0;
    assert!(config.validate().is_err());
}

#[test]
fn rejects_unsupported_sync_committee_sizes() {
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
fn rejects_unordered_fork_epochs() {
    let mut config = valid_config();
    config.altair_fork_epoch = 0;
    config.bellatrix_fork_epoch = 0; // Equal is OK
    assert!(config.validate().is_ok());

    let mut config = valid_config();
    config.altair_fork_epoch = 10;
    config.bellatrix_fork_epoch = 5;
    assert!(config.validate().is_err());

    let mut config = valid_config();
    config.bellatrix_fork_epoch = 100;
    config.capella_fork_epoch = 50;
    assert!(config.validate().is_err());

    let mut config = valid_config();
    config.capella_fork_epoch = 100;
    config.deneb_fork_epoch = 50;
    assert!(config.validate().is_err());

    let mut config = valid_config();
    config.deneb_fork_epoch = 100;
    config.electra_fork_epoch = 50;
    assert!(config.validate().is_err());
}

#[test]
fn mainnet_digests_match_wire_observations() {
    // Digests observed in /updates chunks from lodestar-mainnet.chainsafe.io,
    // 2026-09-19; period → era noted per entry.
    let spec = ChainSpec::mainnet();
    let gvr: Root = hex::decode("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
        .expect("valid hex")
        .try_into()
        .expect("32 bytes");
    assert_eq!(
        spec.fork_from_digest([0x4a, 0x26, 0xc5, 0x8b], gvr),
        Some(Fork::Bellatrix)
    ); // period 700
    assert_eq!(
        spec.fork_from_digest([0xcc, 0x2c, 0x5c, 0xdb], gvr),
        Some(Fork::Fulu)
    ); // period 1608, era 1 (fallback params)
    assert_eq!(
        spec.fork_from_digest([0xcb, 0x0d, 0x1a, 0xcc], gvr),
        Some(Fork::Fulu)
    ); // period 1615, era 2 (BPO-1)
    assert_eq!(
        spec.fork_from_digest([0x8c, 0x9f, 0x62, 0xfe], gvr),
        Some(Fork::Fulu)
    ); // period 1638, era 3 (BPO-2)
    assert_eq!(spec.fork_from_digest([0xde, 0xad, 0xbe, 0xef], gvr), None);
}
