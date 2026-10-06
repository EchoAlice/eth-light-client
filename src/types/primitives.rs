/// 256-bit unsigned integer. `alloy_primitives::U256` carries the native SSZ
/// `Decode`/`TreeHash` impls (via the sigp stack's alloy support), so execution
/// headers derive their SSZ directly.
pub use alloy_primitives::U256;
use ssz_types::typenum::U48;
use ssz_types::FixedVector;

pub type Slot = u64;

pub type Epoch = u64;

pub type ValidatorIndex = u64;

/// BLS pubkey as the SSZ wire type; the same 48 bytes as BLSPublicKey
pub type PubkeyBytes = FixedVector<u8, U48>;

pub type BLSPublicKey = [u8; 48];

pub type BLSSignature = [u8; 96];

pub type Root = [u8; 32];

pub type Domain = [u8; 32];

pub type ForkVersion = [u8; 4];

pub type ForkDigest = [u8; 4];
