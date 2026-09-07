//! Primitive type aliases shared across the crate.

pub type Hash = [u8; 32];

pub type Bytes = Vec<u8>;

/// 256-bit unsigned integer. `alloy_primitives::U256` carries the native SSZ
/// `Decode`/`TreeHash` impls (via the sigp stack's alloy support), so execution
/// headers derive their SSZ directly.
pub use alloy_primitives::U256;

pub type Slot = u64;

pub type Epoch = u64;

pub type ValidatorIndex = u64;

pub type BLSPublicKey = [u8; 48];

pub type BLSSignature = [u8; 96];

pub type Root = [u8; 32];

pub type Domain = [u8; 32];

pub type ForkVersion = [u8; 4];

pub type ForkDigest = [u8; 4];
