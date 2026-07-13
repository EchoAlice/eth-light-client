//! Primitive type aliases shared across the crate.
//!
//! Execution-payload field types that need SSZ collection semantics
//! (`fee_recipient`, `logs_bloom`, `extra_data`) live directly on the types in
//! [`super::consensus`] as `ethereum_types` / `ssz_types` values, so they are no
//! longer defined here.

/// 32-byte hash type used throughout Ethereum
pub type Hash = [u8; 32];

/// Variable-length byte array
pub type Bytes = Vec<u8>;

/// 256-bit unsigned integer. `ethereum_types::U256` carries the native SSZ
/// `Encode`/`Decode`/`TreeHash` impls (unlike `ruint`), so execution headers
/// derive their SSZ directly.
pub use ethereum_types::U256;

/// Beacon chain slot number
pub type Slot = u64;

/// Beacon chain epoch number
pub type Epoch = u64;

/// Validator index in the beacon state
pub type ValidatorIndex = u64;

/// BLS public key (48 bytes)
pub type BLSPublicKey = [u8; 48];

/// BLS signature (96 bytes)
pub type BLSSignature = [u8; 96];

/// Beacon chain block root (32 bytes)
pub type Root = [u8; 32];

/// Domain for BLS signatures
pub type Domain = [u8; 32];

/// Fork version for different beacon chain forks
pub type ForkVersion = [u8; 4];
