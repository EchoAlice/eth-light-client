use super::{BlobParameters, ChainSpecConfig};

impl ChainSpecConfig {
    pub const fn mainnet() -> Self {
        Self {
            genesis_time: 1606824023,
            seconds_per_slot: 12,
            slots_per_epoch: 32,
            epochs_per_sync_committee_period: 256,
            sync_committee_size: 512,
            min_validator_withdrawability_delay: 256,
            churn_limit_quotient: 65536,
            max_blobs_per_block_electra: 9,
            altair_fork_version: [0x01, 0x00, 0x00, 0x00],
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
            capella_fork_version: [0x03, 0x00, 0x00, 0x00],
            deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
            electra_fork_version: [0x05, 0x00, 0x00, 0x00],
            fulu_fork_version: [0x06, 0x00, 0x00, 0x00],
            altair_fork_epoch: 74240,
            bellatrix_fork_epoch: 144896,
            capella_fork_epoch: 194048,
            deneb_fork_epoch: 269568,
            electra_fork_epoch: 364032,
            fulu_fork_epoch: 411392,
            // consensus-specs v1.6.1 BLOB_SCHEDULE
            blob_schedule: &[
                BlobParameters {
                    epoch: 412672,
                    max_blobs_per_block: 15,
                },
                BlobParameters {
                    epoch: 419072,
                    max_blobs_per_block: 21,
                },
            ],
        }
    }

    pub const fn minimal() -> Self {
        Self {
            genesis_time: 1578009600,
            seconds_per_slot: 6,
            slots_per_epoch: 8,
            epochs_per_sync_committee_period: 8,
            sync_committee_size: 32,
            min_validator_withdrawability_delay: 256,
            churn_limit_quotient: 32,
            max_blobs_per_block_electra: 9,
            altair_fork_version: [0x01, 0x00, 0x00, 0x01],
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x01],
            capella_fork_version: [0x03, 0x00, 0x00, 0x01],
            deneb_fork_version: [0x04, 0x00, 0x00, 0x01],
            electra_fork_version: [0x05, 0x00, 0x00, 0x01],
            fulu_fork_version: [0x06, 0x00, 0x00, 0x01],
            altair_fork_epoch: 0,
            bellatrix_fork_epoch: u64::MAX,
            capella_fork_epoch: u64::MAX,
            deneb_fork_epoch: u64::MAX,
            electra_fork_epoch: u64::MAX,
            fulu_fork_epoch: u64::MAX,
            blob_schedule: &[],
        }
    }
}
