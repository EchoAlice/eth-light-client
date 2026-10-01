use thiserror::Error;

use crate::types::primitives::Slot;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid block header: {0}")]
    InvalidBlockHeader(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Patricia trie error: {0}")]
    PatriciaTrie(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Consensus error: {0}")]
    Consensus(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Trusted root too old: header slot {header_slot}, current slot {current_slot}, max age {ws_period_slots} slots")]
    StaleTrustedRoot {
        header_slot: Slot,
        current_slot: Slot,
        ws_period_slots: Slot,
    },

    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    pub fn invalid_proof(msg: impl Into<String>) -> Self {
        Self::InvalidProof(msg.into())
    }

    pub fn patricia_trie(msg: impl Into<String>) -> Self {
        Self::PatriciaTrie(msg.into())
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::Crypto(msg.into())
    }

    pub fn consensus(msg: impl Into<String>) -> Self {
        Self::Consensus(msg.into())
    }
}
