# One-Shot Rebuild Plan

Rebuild `src/` from scratch as a verification-only Ethereum consensus light client.
Cargo.toml and tests/ remain untouched.

## Invariants

- `cargo fmt --all` passes after every milestone
- `cargo test` passes after every milestone (incremental green)
- `cargo test --features test-utils` passes at final milestone
- Public API surface matches existing: `LightClient`, `UpdateOutcome`, `ChainSpec`, `ChainSpecConfig`, `Error`, `Result`, `Root`, `Slot`, `BeaconBlockHeader`, `LightClientBootstrap`, `LightClientUpdate`, `SyncAggregate`, `SyncCommittee`
- No networking code — verification only
- BLS via `blst` (min_pk), SSZ via `tree_hash`/`tree_hash_derive`, errors via `thiserror`
- Sync committee size hardcoded to 512 with TODOs referencing #21
- Period derived from `store.finalized_header.slot` (no tracker)
- Domain uses `fork_version_slot = max(signature_slot, 1) - 1`

## Milestones (commit after each)

- [x] M0: Create this plan, commit
- [ ] M1: Scaffold crate modules (lib.rs, error.rs, module stubs) — compiles
- [ ] M2: Implement ChainSpec/ChainSpecConfig with fork schedule + gindices — config tests pass
- [ ] M3: Implement core types (types/primitives.rs, types/consensus.rs) — type tests pass
- [ ] M4: Implement consensus/merkle.rs — merkle unit tests pass
- [ ] M5: Implement consensus/bls.rs — BLS unit tests + spec tests pass
- [ ] M6: Implement consensus/sync_committee.rs — domain/signing root + sig verification tests pass
- [ ] M7: Implement consensus/light_client.rs processor pipeline — processor tests pass
- [ ] M8: Wire public API (light_client.rs, test_utils.rs) — all tests pass including integration

## File Plan for src/

```
src/
├── lib.rs                          # Crate root, module declarations, re-exports, prelude
├── error.rs                        # Error enum (thiserror) + Result alias
├── config.rs                       # Fork, ForkParams, ForkSchedule, ChainSpecConfig, ChainSpec
├── light_client.rs                 # Public API: LightClient, UpdateOutcome
├── test_utils.rs                   # Fixture loading (cfg test-utils)
├── types/
│   ├── mod.rs                      # Module re-exports
│   ├── primitives.rs               # Hash, Slot, Root, BLSPublicKey, etc.
│   └── consensus.rs                # BeaconBlockHeader, SyncCommittee, SyncAggregate,
│                                   # LightClientUpdate, LightClientBootstrap, LightClientStore
└── consensus/
    ├── mod.rs                      # Module declarations
    ├── bls.rs                      # blst wrappers: verify, fast_aggregate_verify
    ├── bls_spec_tests.rs           # BLS spec test runner
    ├── merkle.rs                   # is_valid_merkle_branch, verify_bootstrap/next/finality
    ├── sync_committee.rs           # committee_for_slot, domain, signing root, verify_sync_aggregate
    ├── light_client.rs             # LightClientProcessor pipeline
    └── light_client_spec_tests.rs  # Light client spec test runner
```
