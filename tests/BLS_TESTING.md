# BLS Spec-Vector Testing

BLS signature verification is validated against the official Ethereum consensus
`fast_aggregate_verify` spec vectors. These tests do **not** test the `blst`
library itself (already extensively tested) — they pin down that *our* adapter
(`src/consensus/bls.rs`) uses the correct DST, handles infinity / empty sets per
spec, and marshals parameters correctly, including the **negative** cases
(tampered signatures, wrong pubkey sets, infinity pubkeys) that the light-client
fixture replays never reach.

Sync-committee verification is same-message aggregate, so `fast_aggregate_verify`
is the only production BLS entry point — and the only path these vectors drive.

## Running

```bash
cargo test --lib fast_aggregate_verify_spec_vectors
```

The test (`src/consensus/bls_spec_tests.rs`) walks every
`fast_aggregate_verify/bls/*` vector and asserts each result strictly — any
mismatch fails the suite and all mismatches are reported at once.

## Fixtures

The vectors live under
`tests/fixtures/consensus-spec-tests/tests/general/phase0/bls`. Clone them, or
point at an existing copy:

```bash
# Option A: clone into fixtures
cd tests/fixtures && git clone https://github.com/ethereum/consensus-spec-tests.git

# Option B: use an existing checkout
export CONSENSUS_SPEC_TESTS_PATH="/path/to/consensus-spec-tests/tests/general/phase0/bls"
```

## Where this fits

The accept path is also covered in context by the light-client fixture replays
(a valid sync aggregate is verified as part of processing each update). These
spec vectors add the reject/edge coverage those replays structurally cannot. See
[`../src/consensus/README.md`](../src/consensus/README.md) for the full testing
taxonomy.
