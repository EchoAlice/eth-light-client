use serde::{Deserialize, Serialize};

/// 32-byte hash type used throughout Ethereum
pub type Hash = [u8; 32];

/// Ethereum address (20 bytes)
pub type Address = [u8; 20];

/// 256-byte bloom filter for logs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bloom(pub [u8; 256]);

impl Default for Bloom {
    fn default() -> Self {
        Bloom([0u8; 256])
    }
}

impl Serialize for Bloom {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        hex::encode(&self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Bloom {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_string: String = String::deserialize(deserializer)?;
        let bytes =
            hex::decode(hex_string.trim_start_matches("0x")).map_err(serde::de::Error::custom)?;
        if bytes.len() != 256 {
            return Err(serde::de::Error::custom("Bloom must be 256 bytes"));
        }
        let mut bloom = [0u8; 256];
        bloom.copy_from_slice(&bytes);
        Ok(Bloom(bloom))
    }
}

/// Variable-length byte array
pub type Bytes = Vec<u8>;

// =============================================================================
// SSZ-native TreeHash impls for consensus types
// =============================================================================

impl tree_hash::TreeHash for Bloom {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("Bloom is not a basic type")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Bloom is not a basic type")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        // ByteVector[256]: pack into 8 chunks of 32 bytes and merkleize.
        tree_hash::merkle_root(&self.0, 8)
    }
}

/// Bounded extra data field for execution payload headers.
///
/// SSZ type: `ByteList[MAX_EXTRA_DATA_BYTES]` where `MAX_EXTRA_DATA_BYTES = 32`.
/// The bound is enforced at construction via [`ExtraData::try_new`]; the inner
/// `Vec<u8>` is private, so no code path can bypass the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraData(Vec<u8>);

impl ExtraData {
    /// Maximum length per the consensus spec (`MAX_EXTRA_DATA_BYTES`).
    pub const MAX_BYTES: usize = 32;

    /// Create from a byte vec, returning an error if it exceeds the bound.
    pub fn try_new(data: Vec<u8>) -> crate::error::Result<Self> {
        if data.len() > Self::MAX_BYTES {
            return Err(crate::error::Error::InvalidInput(format!(
                "extra_data length {} exceeds MAX_EXTRA_DATA_BYTES ({})",
                data.len(),
                Self::MAX_BYTES
            )));
        }
        Ok(Self(data))
    }

    /// Create an empty ExtraData.
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Access the inner bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl tree_hash::TreeHash for ExtraData {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("ExtraData is not a basic type")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("ExtraData is not a basic type")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        // ByteList[32] hash: pack bytes into 1 chunk (right-padded to 32),
        // then mix_in_length by hashing the 64-byte buffer
        // [chunk (32 bytes) || length as LE u64 (8 bytes) || zeros (24 bytes)].
        let mut chunk = [0u8; 32];
        chunk[..self.0.len()].copy_from_slice(&self.0);
        let mut mix = [0u8; 64];
        mix[..32].copy_from_slice(&chunk);
        mix[32..40].copy_from_slice(&(self.0.len() as u64).to_le_bytes());
        tree_hash::merkle_root(&mix, 2)
    }
}

/// 256-bit unsigned integer
pub use ruint::aliases::U256;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extra_data_rejects_oversized() {
        assert!(ExtraData::try_new(vec![0u8; 32]).is_ok());
        assert!(ExtraData::try_new(vec![0u8; 33]).is_err());
    }
}
