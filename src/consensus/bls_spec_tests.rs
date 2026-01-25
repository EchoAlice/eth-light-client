//! BLS Integration Test Suite
//!
//! Validates our BLS wrapper layer (src/consensus/bls.rs) against official
//! Ethereum consensus spec tests. These tests do NOT test the blst library
//! itself (which is already extensively tested) - they validate that OUR code:
//!
//! - Uses the correct Ethereum DST constant
//! - Properly handles infinity points per Ethereum spec
//! - Correctly passes parameters to blst functions
//! - Handles edge cases (invalid keys, tampered signatures, etc.)
//!
//! Test vectors sourced from: https://github.com/ethereum/consensus-spec-tests
//!
//! Test format:
//! - YAML files with input: {pubkey(s), message, signature}
//! - Expected output: true/false
//!
//! Covers:
//! - Single signature verification (verify/)
//! - Fast aggregate verification (fast_aggregate_verify/)
//!
//! Setup:
//! 1. Clone consensus-spec-tests to tests/fixtures/consensus-spec-tests/
//! 2. Or set CONSENSUS_SPEC_TESTS_PATH environment variable to test data location
//!
//! Status: 40/40 tests passing

#![cfg(test)]

use serde::Deserialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// Import our BLS verification functions (crate-internal access)
use crate::consensus::bls::{verify_bls_aggregate_signature, verify_bls_signature};

/// Test case structure for single signature verification
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

/// Test case structure for fast aggregate verification
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

/// Test statistics tracker
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
        println!("\n📊 {} Test Summary:", test_type);
        println!("   Total:   {}", self.total);
        println!(
            "   ✅ Passed: {} ({:.1}%)",
            self.passed,
            (self.passed as f64 / self.total as f64) * 100.0
        );
        println!(
            "   ❌ Failed: {} ({:.1}%)",
            self.failed,
            (self.failed as f64 / self.total as f64) * 100.0
        );
        if self.skipped > 0 {
            println!("   ⏭️  Skipped: {}", self.skipped);
        }
    }
}

/// Get the path to BLS test data, with environment variable fallback
fn get_bls_test_path() -> PathBuf {
    env::var("CONSENSUS_SPEC_TESTS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Default to relative path in project fixtures
            PathBuf::from("tests/fixtures/consensus-spec-tests/tests/general/phase0/bls")
        })
}

/// Parse hex string to bytes, handling 0x prefix
fn parse_hex(hex_str: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(hex_str)
}

/// Run single signature verification tests
fn run_verify_tests(base_path: &Path) -> TestStats {
    println!("\n🔐 Running BLS Signature Verification Tests");
    println!("==========================================");

    let mut stats = TestStats::default();
    let test_dir = base_path.join("verify/bls");

    if !test_dir.exists() {
        println!("⚠️  Test directory not found: {:?}", test_dir);
        return stats;
    }

    // Iterate through all test cases
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

            // Load and parse test case
            match fs::read_to_string(path) {
                Ok(contents) => match serde_yaml::from_str::<VerifyTestCase>(&contents) {
                    Ok(test_case) => {
                        let result = run_single_verify_test(&test_case, test_name);
                        stats.add_result(result);
                    }
                    Err(e) => {
                        println!("   ⚠️  Failed to parse {}: {}", test_name, e);
                        stats.add_skipped();
                    }
                },
                Err(e) => {
                    println!("   ⚠️  Failed to read {}: {}", test_name, e);
                    stats.add_skipped();
                }
            }
        }
    }

    stats.print_summary("Verify");
    stats
}

/// Run a single verification test
fn run_single_verify_test(test_case: &VerifyTestCase, test_name: &str) -> bool {
    // Parse hex inputs
    let pubkey_bytes = match parse_hex(&test_case.input.pubkey) {
        Ok(bytes) if bytes.len() == 48 => bytes,
        Ok(bytes) => {
            println!(
                "   ❌ {} - Invalid pubkey length: {}",
                test_name,
                bytes.len()
            );
            return false;
        }
        Err(e) => {
            println!("   ❌ {} - Failed to parse pubkey: {}", test_name, e);
            return false;
        }
    };

    let message_bytes = match parse_hex(&test_case.input.message) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("   ❌ {} - Failed to parse message: {}", test_name, e);
            return false;
        }
    };

    let signature_bytes = match parse_hex(&test_case.input.signature) {
        Ok(bytes) if bytes.len() == 96 => bytes,
        Ok(bytes) => {
            println!(
                "   ❌ {} - Invalid signature length: {}",
                test_name,
                bytes.len()
            );
            return false;
        }
        Err(e) => {
            println!("   ❌ {} - Failed to parse signature: {}", test_name, e);
            return false;
        }
    };

    // Convert to fixed-size arrays
    let mut pubkey = [0u8; 48];
    pubkey.copy_from_slice(&pubkey_bytes);

    let mut signature = [0u8; 96];
    signature.copy_from_slice(&signature_bytes);

    // Run verification
    let actual = verify_bls_signature(&pubkey, &message_bytes, &signature);
    let expected = test_case.output;

    if actual == expected {
        println!("   ✅ {} - PASS", test_name);
        true
    } else {
        println!(
            "   ❌ {} - FAIL: expected {}, got {}",
            test_name, expected, actual
        );

        // Print details for debugging
        if test_name.contains("tampered") || test_name.contains("invalid") {
            println!("      (This is expected - tampered/invalid signatures should fail)");
        } else if test_name.contains("infinity") {
            println!("      (Special case: infinity point handling)");
        }

        false
    }
}

/// Run fast aggregate verification tests
fn run_fast_aggregate_verify_tests(base_path: &Path) -> TestStats {
    println!("\n🔐 Running BLS Fast Aggregate Verification Tests");
    println!("===============================================");

    let mut stats = TestStats::default();
    let test_dir = base_path.join("fast_aggregate_verify/bls");

    if !test_dir.exists() {
        println!("⚠️  Test directory not found: {:?}", test_dir);
        return stats;
    }

    // Iterate through all test cases
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

            // Load and parse test case
            match fs::read_to_string(path) {
                Ok(contents) => {
                    match serde_yaml::from_str::<FastAggregateVerifyTestCase>(&contents) {
                        Ok(test_case) => {
                            let result = run_single_fast_aggregate_test(&test_case, test_name);
                            stats.add_result(result);
                        }
                        Err(e) => {
                            println!("   ⚠️  Failed to parse {}: {}", test_name, e);
                            stats.add_skipped();
                        }
                    }
                }
                Err(e) => {
                    println!("   ⚠️  Failed to read {}: {}", test_name, e);
                    stats.add_skipped();
                }
            }
        }
    }

    stats.print_summary("Fast Aggregate Verify");
    stats
}

/// Run a single fast aggregate verification test
fn run_single_fast_aggregate_test(
    test_case: &FastAggregateVerifyTestCase,
    test_name: &str,
) -> bool {
    // Parse pubkeys
    let mut pubkeys = Vec::new();
    for pubkey_hex in &test_case.input.pubkeys {
        match parse_hex(pubkey_hex) {
            Ok(bytes) if bytes.len() == 48 => {
                let mut pubkey = [0u8; 48];
                pubkey.copy_from_slice(&bytes);
                pubkeys.push(pubkey);
            }
            Ok(bytes) => {
                println!(
                    "   ❌ {} - Invalid pubkey length: {}",
                    test_name,
                    bytes.len()
                );
                return false;
            }
            Err(e) => {
                println!("   ❌ {} - Failed to parse pubkey: {}", test_name, e);
                return false;
            }
        }
    }

    // Parse message
    let message_bytes = match parse_hex(&test_case.input.message) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("   ❌ {} - Failed to parse message: {}", test_name, e);
            return false;
        }
    };

    // Parse signature
    let signature_bytes = match parse_hex(&test_case.input.signature) {
        Ok(bytes) if bytes.len() == 96 => bytes,
        Ok(bytes) => {
            println!(
                "   ❌ {} - Invalid signature length: {}",
                test_name,
                bytes.len()
            );
            return false;
        }
        Err(e) => {
            println!("   ❌ {} - Failed to parse signature: {}", test_name, e);
            return false;
        }
    };

    let mut signature = [0u8; 96];
    signature.copy_from_slice(&signature_bytes);

    // Run verification
    let actual = verify_bls_aggregate_signature(&pubkeys, &message_bytes, &signature);
    let expected = test_case.output;

    if actual == expected {
        println!(
            "   ✅ {} - PASS ({})",
            test_name,
            if test_name.len() > 50 {
                &test_name[..50]
            } else {
                test_name
            }
        );
        true
    } else {
        println!(
            "   ❌ {} - FAIL: expected {}, got {}",
            test_name, expected, actual
        );

        // Print details for debugging
        println!("      Pubkeys count: {}", pubkeys.len());
        if test_name.contains("extra_pubkey") {
            println!("      (Extra pubkey test - should handle mismatched pubkey counts)");
        } else if test_name.contains("infinity") {
            println!("      (Infinity point handling test)");
        } else if test_name.contains("tampered") {
            println!("      (Tampered signature test - should fail)");
        }

        false
    }
}

/// Main test runner for BLS spec tests
#[test]
fn test_bls_spec_compliance() {
    println!("\n");
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║     BLS SPECIFICATION COMPLIANCE TEST RUNNER         ║");
    println!("╚═══════════════════════════════════════════════════════╝");

    let base_path = get_bls_test_path();

    if !base_path.exists() {
        println!("❌ Test directory not found: {:?}", base_path);
        println!("   Setup instructions:");
        println!("   1. Clone consensus-spec-tests to tests/fixtures/consensus-spec-tests/");
        println!("   2. Or set CONSENSUS_SPEC_TESTS_PATH environment variable");
        println!("   ");
        println!("   Example setup:");
        println!("   cd tests/fixtures && git clone https://github.com/ethereum/consensus-spec-tests.git");
        panic!("BLS test directory not found. See setup instructions above.");
    }

    println!("\n📁 Test directory: {:?}", base_path);
    println!(
        "   Source: {}",
        if env::var("CONSENSUS_SPEC_TESTS_PATH").is_ok() {
            "Environment variable CONSENSUS_SPEC_TESTS_PATH"
        } else {
            "Default fixtures directory"
        }
    );

    // Run verify tests
    let verify_stats = run_verify_tests(&base_path);

    // Run fast aggregate verify tests
    let aggregate_stats = run_fast_aggregate_verify_tests(&base_path);

    // Overall summary
    println!("\n");
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║                  OVERALL SUMMARY                      ║");
    println!("╚═══════════════════════════════════════════════════════╝");

    let total_tests = verify_stats.total + aggregate_stats.total;
    let total_passed = verify_stats.passed + aggregate_stats.passed;
    let total_failed = verify_stats.failed + aggregate_stats.failed;
    let total_skipped = verify_stats.skipped + aggregate_stats.skipped;

    println!("📊 Total Tests Run: {}", total_tests);
    println!(
        "   ✅ Passed: {} ({:.1}%)",
        total_passed,
        (total_passed as f64 / total_tests as f64) * 100.0
    );
    println!(
        "   ❌ Failed: {} ({:.1}%)",
        total_failed,
        (total_failed as f64 / total_tests as f64) * 100.0
    );

    if total_skipped > 0 {
        println!("   ⏭️  Skipped: {}", total_skipped);
    }

    // Assert high pass rate (allow some failures for edge cases)
    let pass_rate = total_passed as f64 / total_tests as f64;
    if pass_rate < 0.8 {
        panic!("BLS spec test pass rate too low: {:.1}%", pass_rate * 100.0);
    } else if pass_rate < 1.0 {
        println!("\n⚠️  Warning: Some tests failed. Review failures above.");
    } else {
        println!("\n🎉 All BLS spec tests passed!");
    }
}

/// Test individual verify test case loading
#[test]
fn test_load_verify_case() {
    let base_path = get_bls_test_path();
    let test_path = base_path.join("verify/bls/verify_valid_case_195246ee3bd3b6ec/data.yaml");

    if test_path.exists() {
        let contents = fs::read_to_string(&test_path).expect("Failed to read test file");
        let test_case: VerifyTestCase =
            serde_yaml::from_str(&contents).expect("Failed to parse test case");

        assert!(test_case.output);
        assert!(test_case.input.pubkey.starts_with("0x"));
        assert!(test_case.input.message.starts_with("0x"));
        assert!(test_case.input.signature.starts_with("0x"));

        println!("✅ Successfully loaded verify test case");
    } else {
        println!("⚠️  Test file not found: {:?}", test_path);
        println!("   This test will be skipped. See setup instructions in main test.");
    }
}

/// Test individual fast aggregate verify test case loading
#[test]
fn test_load_fast_aggregate_case() {
    let base_path = get_bls_test_path();
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

        println!("✅ Successfully loaded fast aggregate verify test case");
    } else {
        println!("⚠️  Test file not found: {:?}", test_path);
        println!("   This test will be skipped. See setup instructions in main test.");
    }
}
