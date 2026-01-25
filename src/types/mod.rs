// Domain-specific type modules
pub mod consensus;
pub mod primitives;

// Clean re-exports organized by domain

/// Core primitive types used throughout the system
pub mod primitive {
    pub use crate::types::primitives::{
        Address, BLSPublicKey, BLSSignature, Bloom, Bytes, Domain, Epoch, ForkVersion, Hash, Root,
        Slot, ValidatorIndex, U256,
    };
}

/// Consensus layer types (Beacon chain)
pub mod consensus_types {
    pub use crate::types::consensus::{
        BeaconBlockHeader, LightClientUpdate, SyncAggregate, SyncCommittee,
    };
}

// Top-level re-exports for convenience
pub use consensus::{
    BeaconBlockHeader, LightClientUpdate, SyncAggregate, SyncCommittee,
};
pub use primitives::*;
