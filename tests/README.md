# Integration Tests

This directory contains integration tests for the Ethereum light client implementation.

## Test Structure

```
tests/
├── README.md                                    # This file
├── fixtures/                                    # Test data (SSZ files, YAML configs)
│   └── README.md                               # Fixtures documentation
└── light_client_sync_spec_tests.rs             # Spec compliance tests
```

## Running Tests

Run all tests:
```bash
cargo test
```

Run specific test with output:
```bash
cargo test test_altair_light_client_sync -- --nocapture
```

Run only integration tests:
```bash
cargo test --test '*'
```

## Test Files

### `light_client_sync_spec_tests.rs`

Validates light client sync protocol against official Ethereum consensus-spec test vectors.

**What it tests:**
- Bootstrap initialization with trusted checkpoint
- Light client update processing (10 sequential updates)
- Sync committee signature verification (BLS12-381)
- Merkle proof verification (finality and committee branches)
- Sync committee rotation across periods
- State transitions (finalized and optimistic headers)

**Configuration:**
- Uses **minimal preset** (32 validators, 64 slots/period)
- Tests Altair fork only (can be extended for later forks)
- Comprehensive test coverage: optimistic, finality, period, and combined updates

**Expected results:**
- Steps 1-5, 10: Should pass ✅
- Steps 6, 9: Force update not implemented yet (expected to fail)
- Steps 7, 8: Under investigation

## Test Coverage

### Current Coverage

| Component | Coverage | Notes |
|-----------|----------|-------|
| Bootstrap verification | ✅ Full | With merkle proof validation |
| Optimistic updates | ✅ Full | Attested header only |
| Finality updates | ✅ Full | With finalized header + proof |
| Period updates | ✅ Full | With next sync committee |
| Combined updates | ✅ Full | Multiple features in one update |
| Force updates | ⚠️ Partial | Not yet implemented |
| BLS signatures | ✅ Full | Aggregate signature verification |
| Merkle proofs | ✅ Full | Both finality and committee branches |
| Period transitions | ✅ Full | Advancing sync committee periods |

### Future Test Coverage

Planned additions:
- [ ] Edge cases (empty committee, invalid proofs)
- [ ] Mainnet preset tests (slower, but production-realistic)
- [ ] Bellatrix/Capella/Deneb/Electra/Fulu fork tests
- [ ] Performance benchmarks

## Writing New Tests

To add a new integration test:

1. **Create test file**: `tests/my_new_test.rs`
2. **Import dependencies**:
   ```rust
   use eth_light_client::config::ChainSpec;
   use eth_light_client::consensus::BeaconConsensus;
   // ... other imports
   ```
3. **Load fixtures** (if needed):
   ```rust
   let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
       .join("tests/fixtures/...");
   ```
4. **Write test function**:
   ```rust
   #[test]
   fn test_my_feature() {
       let chain_spec = ChainSpec::minimal();
       // ... test code
   }
   ```

### Testing Best Practices

1. **Use minimal preset** for fast unit tests
2. **Test one thing** per test function
3. **Provide clear error messages** when assertions fail
4. **Use fixtures** for complex test data
5. **Document expected behavior** in comments
6. **Test both success and failure cases**

## Debugging Tests

Enable detailed output:
```bash
cargo test -- --nocapture
```

Run single test:
```bash
cargo test test_altair_light_client_sync -- --nocapture
```

Show debug logging (if eprintln! statements are present):
```bash
cargo test -- --nocapture 2>&1 | grep "DEBUG:"
```

Check test compilation without running:
```bash
cargo test --no-run
```

## Continuous Integration

Tests run automatically on:
- Every commit (via GitHub Actions)
- Pull requests
- Release builds

CI configuration: `.github/workflows/` (when added)

## References

- [Ethereum Consensus Specs](https://github.com/ethereum/consensus-specs)
- [Light Client Sync Protocol](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md)
- [Consensus Spec Tests](https://github.com/ethereum/consensus-spec-tests)
- [Rust Testing Guide](https://doc.rust-lang.org/book/ch11-00-testing.html)
