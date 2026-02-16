use serde::{Deserialize, Serialize};

/// 32-byte hash type used throughout Ethereum
pub type Hash = [u8; 32];

/// Ethereum address (20 bytes)
pub type Address = [u8; 20];

/// TODO: Remove bloom type
///
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
    fn test_hash_creation() {
        let hash: Hash = [0u8; 32];
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_address_creation() {
        let address: Address = [0u8; 20];
        assert_eq!(address.len(), 20);
    }

    #[test]
    fn test_bloom_default() {
        let bloom = Bloom::default();
        assert_eq!(bloom.0, [0u8; 256]);
    }

    #[test]
    fn test_u256_zero() {
        let zero = U256::ZERO;
        assert_eq!(zero.to_string(), "0");
    }
}
