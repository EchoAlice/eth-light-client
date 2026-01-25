# Test Fixtures

This directory contains official Ethereum consensus specification test vectors used to validate the light client implementation.

## Source

These test vectors are from the official Ethereum consensus-spec-tests repository:
- Repository: https://github.com/ethereum/consensus-spec-tests
- License: CC0-1.0 (Public Domain)

## Structure

```
tests/fixtures/
└── minimal/              # Minimal preset (faster tests, 32 validators)
    └── altair/           # Altair fork
        └── light_client/
            └── sync/
                └── light_client_sync/
                    ├── meta.yaml              # Test metadata (genesis root, fork digests)
                    ├── steps.yaml             # Test steps and expected results
                    ├── config.yaml            # Network configuration
                    ├── bootstrap.ssz_snappy   # Initial bootstrap state
                    └── update_*.ssz_snappy    # Light client updates
```

## Presets

### Minimal Preset (Current)
- **Purpose**: Fast unit testing
- **Sync committee size**: 32 validators (vs 512 on mainnet)
- **Slots per epoch**: 8 (vs 32 on mainnet)
- **Epochs per sync committee period**: 8 (vs 256 on mainnet)
- **Total slots per period**: 64 (vs 8192 on mainnet)

### Mainnet Preset (Not included)
- Used for production
- Tests would be much slower due to larger committee sizes
- Can be added later if needed for integration testing

## File Formats

- **`.yaml`**: Human-readable test metadata and steps
- **`.ssz_snappy`**: Snappy-compressed SSZ (Simple Serialize) encoded data
  - SSZ is Ethereum's serialization format
  - Snappy provides fast compression/decompression

## Test Case: light_client_sync

This test validates the complete light client sync workflow:

1. **Bootstrap**: Initialize with a trusted checkpoint
2. **Process updates**: Handle 10 different update types:
   - Optimistic updates (attested header only)
   - Finality updates (with finalized header + proof)
   - Period updates (with next sync committee)
   - Combined updates (multiple features)
   - Force updates (timeout-based advancement)

The test covers:
- Sync committee signature verification (BLS)
- Merkle proof verification
- Sync committee rotation across periods
- State transitions (finalized → optimistic headers)

## Updating Test Vectors

To update to a newer version of the spec tests:

1. Download the latest release from https://github.com/ethereum/consensus-spec-tests/releases
2. Extract the archive
3. Copy the desired test case to this directory:
   ```bash
   cp -r consensus-spec-tests/tests/minimal/altair/light_client/sync/pyspec_tests/light_client_sync \
         tests/fixtures/minimal/altair/light_client/sync/
   ```
4. Run tests to verify compatibility:
   ```bash
   cargo test --test light_client_sync_spec_tests -- --nocapture
   ```

## Adding More Test Cases

To add additional test cases from the spec-tests repository:

1. Copy the test directory to `tests/fixtures/` preserving the path structure
2. Create a new test file in `tests/` that loads from the fixtures directory
3. Follow the pattern in `tests/light_client_sync_spec_tests.rs`

Example test cases available in ethereum/consensus-spec-tests:
- `light_client/sync/` - Sync committee updates (current)
- `light_client/update_ranking/` - Update quality scoring
- `light_client/single_merkle_proof/` - Individual proof verification
- `bls/` - BLS signature verification
- `ssz_static/` - SSZ serialization

## References

- [Ethereum Consensus Specs](https://github.com/ethereum/consensus-specs)
- [Light Client Specification](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md)
- [SSZ Specification](https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md)
- [Consensus Spec Tests](https://github.com/ethereum/consensus-spec-tests)
