use blst::{
    min_pk::{PublicKey, Signature},
    BLST_ERROR,
};

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub(crate) fn verify_aggregate_signature(
    pubkeys: &[[u8; 48]],
    message: &[u8],
    signature: &[u8; 96],
) -> bool {
    if pubkeys.is_empty() {
        return false;
    }

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

#[cfg(test)]
mod spec_tests {
    use super::*;
    use serde::Deserialize;
    use std::fs;
    use std::path::PathBuf;

    #[derive(Deserialize)]
    struct FastAggregateVerifyCase {
        input: FastAggregateVerifyInput,
        output: bool,
    }

    #[derive(Deserialize)]
    struct FastAggregateVerifyInput {
        pubkeys: Vec<String>,
        message: String,
        signature: String,
    }

    fn parse_hex(s: &str) -> Vec<u8> {
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("invalid hex in fixture")
    }

    fn fixed<const N: usize>(bytes: &[u8]) -> [u8; N] {
        bytes.try_into().expect("unexpected fixture field length")
    }

    #[test]
    fn fast_aggregate_verify_spec_vectors() {
        let dir = PathBuf::from("tests/fixtures/general/phase0/bls/fast_aggregate_verify/bls");
        assert!(dir.exists(), "vendored BLS fixtures not found at {dir:?}");

        let mut checked = 0usize;
        let mut failures = Vec::new();

        for entry in fs::read_dir(&dir).expect("read fixture dir") {
            let case_dir = entry.expect("read dir entry").path();
            if !case_dir.is_dir() {
                continue;
            }
            let name = case_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            let contents = fs::read_to_string(case_dir.join("data.yaml")).expect("read fixture");
            let case: FastAggregateVerifyCase =
                serde_yaml::from_str(&contents).unwrap_or_else(|e| panic!("parse {name}: {e}"));

            let pubkeys: Vec<[u8; 48]> = case
                .input
                .pubkeys
                .iter()
                .map(|p| fixed(&parse_hex(p)))
                .collect();
            let message = parse_hex(&case.input.message);
            let signature: [u8; 96] = fixed(&parse_hex(&case.input.signature));

            let actual = verify_aggregate_signature(&pubkeys, &message, &signature);
            if actual != case.output {
                failures.push(format!("{name}: expected {}, got {actual}", case.output));
            }
            checked += 1;
        }

        assert!(checked > 0, "no BLS fixtures were exercised");
        assert!(
            failures.is_empty(),
            "{} of {checked} fast_aggregate_verify vectors failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
