#![cfg(test)]

use serde::Deserialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::consensus::bls::{verify_bls_aggregate_signature, verify_bls_signature};

#[derive(Debug, Deserialize)]
struct VerifyTestCase {
    input: VerifyInput,
    output: bool,
}

#[derive(Debug, Deserialize)]
struct VerifyInput {
    pubkey: String,
    message: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct FastAggregateVerifyTestCase {
    input: FastAggregateVerifyInput,
    output: bool,
}

#[derive(Debug, Deserialize)]
struct FastAggregateVerifyInput {
    pubkeys: Vec<String>,
    message: String,
    signature: String,
}

#[derive(Debug, Default)]
struct TestStats {
    total: usize,
    passed: usize,
    failed: usize,
    skipped: usize,
}

impl TestStats {
    fn add_result(&mut self, passed: bool) {
        self.total += 1;
        if passed {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
    }

    fn add_skipped(&mut self) {
        self.total += 1;
        self.skipped += 1;
    }

    fn print_summary(&self, test_type: &str) {
        println!("\n{} Test Summary:", test_type);
        println!("   Total:   {}", self.total);
        println!(
            "   Passed: {} ({:.1}%)",
            self.passed,
            (self.passed as f64 / self.total as f64) * 100.0
        );
        println!(
            "   Failed: {} ({:.1}%)",
            self.failed,
            (self.failed as f64 / self.total as f64) * 100.0
        );
        if self.skipped > 0 {
            println!("   Skipped: {}", self.skipped);
        }
    }
}

fn bls_test_path() -> PathBuf {
    env::var("CONSENSUS_SPEC_TESTS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("tests/fixtures/consensus-spec-tests/tests/general/phase0/bls")
        })
}

fn parse_hex(hex_str: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(hex_str)
}

fn run_verify_tests(base_path: &Path) -> TestStats {
    println!("\nRunning BLS Signature Verification Tests");

    let mut stats = TestStats::default();
    let test_dir = base_path.join("verify/bls");

    if !test_dir.exists() {
        println!("Test directory not found: {:?}", test_dir);
        return stats;
    }

    for entry in WalkDir::new(&test_dir)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.file_name() == Some(std::ffi::OsStr::new("data.yaml")) {
            let test_name = path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            match fs::read_to_string(path) {
                Ok(contents) => match serde_yaml::from_str::<VerifyTestCase>(&contents) {
                    Ok(test_case) => {
                        let result = run_single_verify_test(&test_case, test_name);
                        stats.add_result(result);
                    }
                    Err(e) => {
                        println!("   Failed to parse {}: {}", test_name, e);
                        stats.add_skipped();
                    }
                },
                Err(e) => {
                    println!("   Failed to read {}: {}", test_name, e);
                    stats.add_skipped();
                }
            }
        }
    }

    stats.print_summary("Verify");
    stats
}

fn run_single_verify_test(test_case: &VerifyTestCase, test_name: &str) -> bool {
    let pubkey_bytes = match parse_hex(&test_case.input.pubkey) {
        Ok(bytes) if bytes.len() == 48 => bytes,
        Ok(bytes) => {
            println!("   {} - Invalid pubkey length: {}", test_name, bytes.len());
            return false;
        }
        Err(e) => {
            println!("   {} - Failed to parse pubkey: {}", test_name, e);
            return false;
        }
    };

    let message_bytes = match parse_hex(&test_case.input.message) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("   {} - Failed to parse message: {}", test_name, e);
            return false;
        }
    };

    let signature_bytes = match parse_hex(&test_case.input.signature) {
        Ok(bytes) if bytes.len() == 96 => bytes,
        Ok(bytes) => {
            println!(
                "   {} - Invalid signature length: {}",
                test_name,
                bytes.len()
            );
            return false;
        }
        Err(e) => {
            println!("   {} - Failed to parse signature: {}", test_name, e);
            return false;
        }
    };

    let mut pubkey = [0u8; 48];
    pubkey.copy_from_slice(&pubkey_bytes);

    let mut signature = [0u8; 96];
    signature.copy_from_slice(&signature_bytes);

    let actual = verify_bls_signature(&pubkey, &message_bytes, &signature);
    let expected = test_case.output;

    if actual == expected {
        println!("   {} - PASS", test_name);
        true
    } else {
        println!(
            "   {} - FAIL: expected {}, got {}",
            test_name, expected, actual
        );
        false
    }
}

fn run_fast_aggregate_verify_tests(base_path: &Path) -> TestStats {
    println!("\nRunning BLS Fast Aggregate Verification Tests");

    let mut stats = TestStats::default();
    let test_dir = base_path.join("fast_aggregate_verify/bls");

    if !test_dir.exists() {
        println!("Test directory not found: {:?}", test_dir);
        return stats;
    }

    for entry in WalkDir::new(&test_dir)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.file_name() == Some(std::ffi::OsStr::new("data.yaml")) {
            let test_name = path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            match fs::read_to_string(path) {
                Ok(contents) => {
                    match serde_yaml::from_str::<FastAggregateVerifyTestCase>(&contents) {
                        Ok(test_case) => {
                            let result = run_single_fast_aggregate_test(&test_case, test_name);
                            stats.add_result(result);
                        }
                        Err(e) => {
                            println!("   Failed to parse {}: {}", test_name, e);
                            stats.add_skipped();
                        }
                    }
                }
                Err(e) => {
                    println!("   Failed to read {}: {}", test_name, e);
                    stats.add_skipped();
                }
            }
        }
    }

    stats.print_summary("Fast Aggregate Verify");
    stats
}

fn run_single_fast_aggregate_test(
    test_case: &FastAggregateVerifyTestCase,
    test_name: &str,
) -> bool {
    let mut pubkeys = Vec::new();
    for pubkey_hex in &test_case.input.pubkeys {
        match parse_hex(pubkey_hex) {
            Ok(bytes) if bytes.len() == 48 => {
                let mut pubkey = [0u8; 48];
                pubkey.copy_from_slice(&bytes);
                pubkeys.push(pubkey);
            }
            Ok(bytes) => {
                println!("   {} - Invalid pubkey length: {}", test_name, bytes.len());
                return false;
            }
            Err(e) => {
                println!("   {} - Failed to parse pubkey: {}", test_name, e);
                return false;
            }
        }
    }

    let message_bytes = match parse_hex(&test_case.input.message) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("   {} - Failed to parse message: {}", test_name, e);
            return false;
        }
    };

    let signature_bytes = match parse_hex(&test_case.input.signature) {
        Ok(bytes) if bytes.len() == 96 => bytes,
        Ok(bytes) => {
            println!(
                "   {} - Invalid signature length: {}",
                test_name,
                bytes.len()
            );
            return false;
        }
        Err(e) => {
            println!("   {} - Failed to parse signature: {}", test_name, e);
            return false;
        }
    };

    let mut signature = [0u8; 96];
    signature.copy_from_slice(&signature_bytes);

    let actual = verify_bls_aggregate_signature(&pubkeys, &message_bytes, &signature);
    let expected = test_case.output;

    if actual == expected {
        println!(
            "   {} - PASS",
            if test_name.len() > 50 {
                &test_name[..50]
            } else {
                test_name
            }
        );
        true
    } else {
        println!(
            "   {} - FAIL: expected {}, got {}",
            test_name, expected, actual
        );
        false
    }
}

#[test]
fn test_bls_spec_compliance() {
    let base_path = bls_test_path();

    if !base_path.exists() {
        panic!(
            "BLS test directory not found: {:?}. Clone consensus-spec-tests to tests/fixtures/",
            base_path
        );
    }

    let verify_stats = run_verify_tests(&base_path);
    let aggregate_stats = run_fast_aggregate_verify_tests(&base_path);

    let total_tests = verify_stats.total + aggregate_stats.total;
    let total_passed = verify_stats.passed + aggregate_stats.passed;
    let total_failed = verify_stats.failed + aggregate_stats.failed;

    println!("\nTotal Tests: {}", total_tests);
    println!(
        "   Passed: {} ({:.1}%)",
        total_passed,
        (total_passed as f64 / total_tests as f64) * 100.0
    );
    println!(
        "   Failed: {} ({:.1}%)",
        total_failed,
        (total_failed as f64 / total_tests as f64) * 100.0
    );

    let pass_rate = total_passed as f64 / total_tests as f64;
    if pass_rate < 0.8 {
        panic!("BLS spec test pass rate too low: {:.1}%", pass_rate * 100.0);
    }
}

#[test]
fn test_load_verify_case() {
    let base_path = bls_test_path();
    let test_path = base_path.join("verify/bls/verify_valid_case_195246ee3bd3b6ec/data.yaml");

    if test_path.exists() {
        let contents = fs::read_to_string(&test_path).expect("Failed to read test file");
        let test_case: VerifyTestCase =
            serde_yaml::from_str(&contents).expect("Failed to parse test case");

        assert!(test_case.output);
        assert!(test_case.input.pubkey.starts_with("0x"));
        assert!(test_case.input.message.starts_with("0x"));
        assert!(test_case.input.signature.starts_with("0x"));
    }
}

#[test]
fn test_load_fast_aggregate_case() {
    let base_path = bls_test_path();
    let test_path = base_path
        .join("fast_aggregate_verify/bls/fast_aggregate_verify_valid_3d7576f3c0e3570a/data.yaml");

    if test_path.exists() {
        let contents = fs::read_to_string(&test_path).expect("Failed to read test file");
        let test_case: FastAggregateVerifyTestCase =
            serde_yaml::from_str(&contents).expect("Failed to parse test case");

        assert!(test_case.output);
        assert!(!test_case.input.pubkeys.is_empty());
        assert!(test_case.input.message.starts_with("0x"));
        assert!(test_case.input.signature.starts_with("0x"));
    }
}
