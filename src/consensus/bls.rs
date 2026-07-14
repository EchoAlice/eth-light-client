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

/// Same-message aggregate signature verification — the sole BLS entry point.
///
/// Named to distinguish it from blst's `Signature::fast_aggregate_verify`, which
/// it wraps: our version additionally `KeyValidate`s the pubkeys (blst's does
/// not), so it implements the consensus-spec `FastAggregateVerify`. All sync
/// committee signature checks go through this.
///
/// It parses and `KeyValidate`s the participating pubkeys and parses the
/// aggregate signature, then defers to blst's native `fast_aggregate_verify` for
/// the one-message/many-signers pairing. Any parse failure or non-success status
/// is a verification failure (`false`).
///
/// Per the spec, an empty pubkey set is invalid, and a set containing the
/// infinity pubkey (or any non-subgroup key) is rejected outright, not filtered.
pub(crate) fn verify_aggregate(
    pubkeys: &[[u8; 48]],
    message: &[u8],
    signature: &[u8; 96],
) -> bool {
    if pubkeys.is_empty() {
        return false;
    }

    // Parse and KeyValidate every pubkey. KeyValidate rejects the infinity point
    // and non-subgroup keys, so any such key fails the whole verification.
    let mut pks: Vec<PublicKey> = Vec::with_capacity(pubkeys.len());
    for pk_bytes in pubkeys {
        let pk = match PublicKey::from_bytes(pk_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        if pk.validate().is_err() {
            return false;
        }
        pks.push(pk);
    }

    let sig = match Signature::from_bytes(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    matches!(
        sig.fast_aggregate_verify(true, message, DST, &pk_refs),
        BLST_ERROR::BLST_SUCCESS
    )
}
