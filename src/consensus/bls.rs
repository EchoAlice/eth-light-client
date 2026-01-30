#[cfg(test)]
use blst::min_pk::AggregateSignature;
/// BLS Signature Verification Module
///
/// Provides BLS signature verification functions for Ethereum consensus layer.
/// Uses the blst library for efficient BLS12-381 operations.
///
/// This module is designed to be compliant with Ethereum consensus spec tests.
use blst::{
    min_pk::{AggregatePublicKey, PublicKey, Signature},
    BLST_ERROR,
};

// Ethereum consensus DST (domain separation tag)
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Verify a single BLS signature
///
/// # Arguments
/// * `pubkey` - 48-byte BLS public key
/// * `message` - Message bytes to verify
/// * `signature` - 96-byte BLS signature
///
/// # Returns
/// * `true` if signature is valid, `false` otherwise
#[cfg(test)]
pub fn verify_bls_signature(pubkey: &[u8; 48], message: &[u8], signature: &[u8; 96]) -> bool {
    // Handle infinity/identity pubkey (all zeros)
    if pubkey.iter().all(|&b| b == 0) {
        // Infinity pubkey with infinity signature is considered valid
        // per Ethereum consensus specs
        return signature.iter().all(|&b| b == 0);
    }

    // Parse public key
    let pk = match PublicKey::from_bytes(pubkey) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Validate public key
    if pk.validate().is_err() {
        return false;
    }

    // Parse signature
    let sig = match Signature::from_bytes(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Validate signature
    if sig.validate(false).is_err() {
        return false;
    }

    // Verify signature
    matches!(
        sig.verify(false, message, DST, &[], &pk, false),
        BLST_ERROR::BLST_SUCCESS
    )
}

/// Verify an aggregate BLS signature from multiple signers
///
/// # Arguments
/// * `pubkeys` - Vector of 48-byte BLS public keys
/// * `message` - Message bytes that was signed
/// * `signature` - 96-byte aggregate BLS signature
///
/// # Returns
/// * `true` if aggregate signature is valid, `false` otherwise
pub(crate) fn verify_bls_aggregate_signature(
    pubkeys: &[[u8; 48]],
    message: &[u8],
    signature: &[u8; 96],
) -> bool {
    // Handle empty pubkeys
    if pubkeys.is_empty() {
        return false;
    }

    // Parse and validate public keys
    let mut pks = Vec::new();
    for pubkey_bytes in pubkeys {
        // Skip infinity/identity pubkeys
        if pubkey_bytes.iter().all(|&b| b == 0) {
            continue;
        }

        match PublicKey::from_bytes(pubkey_bytes) {
            Ok(pk) => {
                if pk.validate().is_ok() {
                    pks.push(pk);
                } else {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }

    // If all pubkeys were infinity, check if signature is also infinity
    if pks.is_empty() {
        return signature.iter().all(|&b| b == 0);
    }

    // Parse signature
    let sig = match Signature::from_bytes(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Validate signature
    if sig.validate(false).is_err() {
        return false;
    }

    // Aggregate public keys
    let agg_pk = match aggregate_pubkeys(&pks) {
        Some(pk) => pk,
        None => return false,
    };

    // Verify aggregate signature
    matches!(
        sig.verify(false, message, DST, &[], &agg_pk, false),
        BLST_ERROR::BLST_SUCCESS
    )
}

/// Fast aggregate verify for sync committee
///
/// This is optimized for the case where all signers sign the same message.
/// Used primarily for sync committee aggregate signatures.
///
/// # Arguments
/// * `pubkeys` - Vector of 48-byte BLS public keys
/// * `message` - Message bytes that was signed by all
/// * `signature` - 96-byte aggregate BLS signature
///
/// # Returns
/// * `true` if aggregate signature is valid, `false` otherwise
pub(crate) fn fast_aggregate_verify(
    pubkeys: &[[u8; 48]],
    message: &[u8],
    signature: &[u8; 96],
) -> bool {
    // Try using blst's native fast_aggregate_verify first
    if let Some(result) = fast_aggregate_verify_native(pubkeys, message, signature) {
        return result;
    }

    // Fallback to aggregate-then-verify approach
    verify_bls_aggregate_signature(pubkeys, message, signature)
}

/// Use blst's native fast_aggregate_verify function
fn fast_aggregate_verify_native(
    pubkeys: &[[u8; 48]],
    message: &[u8],
    signature: &[u8; 96],
) -> Option<bool> {
    if pubkeys.is_empty() {
        return Some(false);
    }

    // Parse all public keys
    let mut pks: Vec<PublicKey> = Vec::with_capacity(pubkeys.len());
    for pk_bytes in pubkeys {
        if pk_bytes.iter().all(|&b| b == 0) {
            continue; // Skip infinity
        }
        match PublicKey::from_bytes(pk_bytes) {
            Ok(pk) => pks.push(pk),
            Err(_) => return None,
        }
    }

    if pks.is_empty() {
        return Some(signature.iter().all(|&b| b == 0));
    }

    // Parse signature
    let sig = match Signature::from_bytes(signature) {
        Ok(s) => s,
        Err(_) => return None,
    };

    // Create references for fast_aggregate_verify
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();

    // Use blst's native fast_aggregate_verify
    match sig.fast_aggregate_verify(true, message, DST, &pk_refs) {
        BLST_ERROR::BLST_SUCCESS => Some(true),
        BLST_ERROR::BLST_VERIFY_FAIL => Some(false),
        _ => None, // Some other error, fall back
    }
}

/// Aggregate multiple BLS public keys
fn aggregate_pubkeys(pubkeys: &[PublicKey]) -> Option<PublicKey> {
    if pubkeys.is_empty() {
        return None;
    }

    // Start with first public key
    let mut aggregate = AggregatePublicKey::from_public_key(&pubkeys[0]);

    // Add remaining keys
    for pk in &pubkeys[1..] {
        if aggregate.add_public_key(pk, false).is_err() {
            return None;
        }
    }

    Some(aggregate.to_public_key())
}

/// Aggregate multiple BLS signatures
#[cfg(test)]
pub fn aggregate_signatures(signatures: &[[u8; 96]]) -> Result<[u8; 96], String> {
    if signatures.is_empty() {
        return Err("No signatures to aggregate".to_string());
    }

    // Parse all signatures first
    let mut sigs = Vec::new();
    for sig_bytes in signatures {
        let sig =
            Signature::from_bytes(sig_bytes).map_err(|e| format!("Invalid signature: {:?}", e))?;
        sigs.push(sig);
    }

    // Create aggregate from first signature
    let mut agg_sig = AggregateSignature::from_signature(&sigs[0]);

    // Add remaining signatures
    for sig in &sigs[1..] {
        agg_sig
            .add_signature(sig, false)
            .map_err(|e| format!("Failed to add signature: {:?}", e))?;
    }

    let result = agg_sig.to_signature();
    Ok(result.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst::min_pk::SecretKey;

    #[test]
    fn test_single_signature_verification() {
        // Generate a test keypair
        let sk_bytes = [42u8; 32];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = sk.sk_to_pk();

        // Sign a message
        let message = b"test message";
        let sig = sk.sign(message, DST, &[]);

        // Verify signature
        let pubkey = pk.to_bytes();
        let signature = sig.to_bytes();

        assert!(verify_bls_signature(&pubkey, message, &signature));

        // Verify with wrong message should fail
        assert!(!verify_bls_signature(&pubkey, b"wrong message", &signature));

        // Verify with wrong pubkey should fail
        let wrong_sk = SecretKey::from_bytes(&[43u8; 32]).unwrap();
        let wrong_pk = wrong_sk.sk_to_pk().to_bytes();
        assert!(!verify_bls_signature(&wrong_pk, message, &signature));
    }

    #[test]
    fn test_aggregate_signature_verification() {
        // Generate multiple keypairs
        let mut pubkeys = Vec::new();
        let mut sigs = Vec::new();

        let message = b"aggregate test message";

        // Note: Secret key bytes cannot be all zeros (invalid scalar)
        // Use non-zero values starting from 1
        for i in 1..=3 {
            let sk_bytes = [i as u8; 32];
            let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
            let pk = sk.sk_to_pk();
            let sig = sk.sign(message, DST, &[]);

            pubkeys.push(pk.to_bytes());
            sigs.push(sig.to_bytes());
        }

        // Aggregate signatures
        let agg_sig = aggregate_signatures(&sigs).unwrap();

        // Verify aggregate
        assert!(verify_bls_aggregate_signature(&pubkeys, message, &agg_sig));

        // Verify with wrong message should fail
        assert!(!verify_bls_aggregate_signature(
            &pubkeys, b"wrong", &agg_sig
        ));
    }

    #[test]
    fn test_infinity_point_handling() {
        // Test infinity pubkey and signature (all zeros)
        let infinity_pubkey = [0u8; 48];
        let infinity_signature = [0u8; 96];
        let message = b"any message";

        // Infinity pubkey with infinity signature should be valid
        assert!(verify_bls_signature(
            &infinity_pubkey,
            message,
            &infinity_signature
        ));

        // Infinity pubkey with non-infinity signature should be invalid
        let non_infinity_sig = [1u8; 96];
        assert!(!verify_bls_signature(
            &infinity_pubkey,
            message,
            &non_infinity_sig
        ));
    }

    #[test]
    fn test_invalid_inputs() {
        // Test with invalid pubkey bytes (not on curve)
        let invalid_pubkey = [0xffu8; 48];
        let signature = [0u8; 96];
        let message = b"test";

        assert!(!verify_bls_signature(&invalid_pubkey, message, &signature));

        // Test with invalid signature bytes
        let sk = SecretKey::from_bytes(&[1u8; 32]).unwrap();
        let pubkey = sk.sk_to_pk().to_bytes();
        let invalid_signature = [0xffu8; 96];

        assert!(!verify_bls_signature(&pubkey, message, &invalid_signature));
    }
}
