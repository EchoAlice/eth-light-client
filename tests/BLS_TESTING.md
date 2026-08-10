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

The test (`spec_tests` in `src/consensus/bls.rs`) walks every
`fast_aggregate_verify/bls/*` vector and asserts each result strictly — any
mismatch fails the suite and all mismatches are reported at once.

## Fixtures

The `fast_aggregate_verify` vectors are vendored at
`tests/fixtures/general/phase0/bls` — the fixtures tree mirrors the upstream
[`consensus-spec-tests`](https://github.com/ethereum/consensus-spec-tests)
layout (`tests/general/phase0/bls/…`), the same way `tests/fixtures/minimal/`
mirrors the minimal-preset tree. No setup is needed; a fresh clone passes.

To validate against a newer spec-tests release, re-vendor: copy its
`fast_aggregate_verify` directory over the vendored one and rerun.

## Where this fits

The accept path is also covered in context by the light-client fixture replays
(a valid sync aggregate is verified as part of processing each update). These
spec vectors add the reject/edge coverage those replays structurally cannot. See
[`../src/consensus/README.md`](../src/consensus/README.md) for the full testing
taxonomy.
