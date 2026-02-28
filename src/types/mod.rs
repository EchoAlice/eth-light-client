// Domain-specific type modules
pub mod consensus;
pub mod primitives;

/// Curated primitive types used throughout the light client (CL-focused).
pub mod primitives_types {
    pub use crate::types::primitives::{
        BLSPublicKey, BLSSignature, Bytes, Domain, Epoch, ForkVersion, Root, Slot, ValidatorIndex,
    };
}

/// Consensus layer types (Beacon chain)
pub mod consensus_types {
    pub use crate::types::consensus::{
        BeaconBlockHeader, LightClientUpdate, SyncAggregate, SyncCommittee,
    };
}
