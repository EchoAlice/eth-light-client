//! BLS Signature Verification Module
//!
//! Same-message aggregate signature verification for the Ethereum consensus
//! layer. Every actual BLS12-381 operation is delegated to `blst`; this module
//! is the thin adapter that applies Ethereum's conventions (the DST, infinity
//! handling) and marshals our byte types into blst's API.
use blst::{
    min_pk::{PublicKey, Signature},
    BLST_ERROR,
};

// Ethereum consensus DST (domain separation tag)
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Same-message aggregate verification — the sole BLS entry point.
///
/// All sync committee signature checks go through this. It parses the
/// participating pubkeys and the aggregate signature, then defers to blst's
/// native `fast_aggregate_verify`, which is the complete primitive for the
/// one-message/many-signers case. Any parse error or non-success status is a
/// verification failure (`false`).
///
/// Infinity handling follows the consensus spec: all-zero pubkeys are skipped,
/// and an empty participating set verifies only against an infinity signature.
pub(crate) fn fast_aggregate_verify(
    pubkeys: &[[u8; 48]],
    message: &[u8],
    signature: &[u8; 96],
) -> bool {
    if pubkeys.is_empty() {
        return false;
    }

    // Parse pubkeys, skipping infinity (all-zero) entries.
    let mut pks: Vec<PublicKey> = Vec::with_capacity(pubkeys.len());
    for pk_bytes in pubkeys {
        if pk_bytes.iter().all(|&b| b == 0) {
            continue;
        }
        match PublicKey::from_bytes(pk_bytes) {
            Ok(pk) => pks.push(pk),
            Err(_) => return false,
        }
    }

    // Empty participating set: valid only if the signature is also infinity.
    if pks.is_empty() {
        return signature.iter().all(|&b| b == 0);
    }

    let sig = match Signature::from_bytes(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // blst's `fast_aggregate_verify` performs the group checks internally.
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    matches!(
        sig.fast_aggregate_verify(true, message, DST, &pk_refs),
        BLST_ERROR::BLST_SUCCESS
    )
}
