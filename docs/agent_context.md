# Contributor Context

How to work on this repository safely.  Read this before making changes.

---

## Project Constraints

- **Verification-only library.** This crate does not fetch data from the
  network.  Users supply `LightClientBootstrap` and `LightClientUpdate`
  objects; the library verifies them.
- **No runtime dependencies beyond crypto.**  The core depends on `blst`
  (BLS12-381), `tree_hash`/`tree_hash_derive` (SSZ merkle), and a few
  utility crates.  No async runtime, no networking, no database.
- **Altair-only (for now).**  Later fork header formats are not yet supported.
  Do not assume execution payload fields exist on `LightClientUpdate`.
- **Two presets matter:** `ChainSpec::mainnet()` (512 committee, 32
  slots/epoch) and `ChainSpec::minimal()` (32 committee, 8 slots/epoch).
  Spec tests run against minimal.
- **`LightClientStore` is the single source of truth** for sync committee
  data (`current_sync_committee`, `next_sync_committee`).
  `SyncCommitteeTracker` holds only a period counter and reads committees via
  references.  Never give the tracker its own committee copies.

## Non-Goals

These are explicitly out of scope.  Do not introduce them:

- Feature flags or "strict mode" toggles
- Networking, HTTP clients, or async
- Execution-layer state proofs
- Persistent storage or serialization (planned but not yet)
- Backwards-compatibility shims for removed internal APIs

---

## Change Checklists

### Modifying committee rotation or selection logic

1. Read `src/consensus/light_client.rs` — `apply_light_client_update()`
2. Read `src/consensus/sync_committee.rs` — `committee_for_slot()`,
   `process_sync_committee_update()`, `advance_to_next_period()`
3. Check all five invariants in `docs/architecture.md` (I-1 through I-5)
4. Run `./scripts/warner-check.sh` (fmt + test + clippy)
5. Verify the drift-prevention test still passes:
   `cargo test test_store_tracker_agree_after_rotation`

### Modifying merkle verification

1. Read `src/consensus/merkle.rs`
2. Check that generalized indices come from `ChainSpec`, not hardcoded
3. Check the spec fixture test:
   `cargo test test_sync_committee_root_against_spec_fixture`
4. Run `./scripts/warner-check.sh`

### Modifying BLS or domain logic

1. Read `src/consensus/sync_committee.rs` — `compute_sync_committee_domain_for_slot()`,
   `verify_sync_aggregate()`
2. Read `src/consensus/bls.rs` — `fast_aggregate_verify()`
3. Check `fork_version_slot = max(signature_slot, 1) - 1` invariant (I-5)
4. Run BLS spec tests: `cargo test bls_spec`
5. Run full spec sync test: `cargo test test_altair_light_client_sync`
6. Run `./scripts/warner-check.sh`

### Adding a new fork

1. Add fork variant to `config.rs` → `Fork` enum
2. Add `ForkParams` entry in `ForkSchedule`
3. Add gindex values in `ChainSpec::*_gindex()` methods
4. Extend `LightClientUpdate` / header types if the fork changes them
5. Add spec test vectors under `tests/consensus-spec-tests/`
6. Run `./scripts/warner-check.sh`

### Touching the public API (`src/light_client.rs`, `src/lib.rs`)

1. Keep the public surface minimal; prefer adding to internal modules
2. `LightClient` is a thin wrapper — logic belongs in `LightClientProcessor`
3. Do not expose `LightClientStore`, `SyncCommitteeTracker`, or `LightClientProcessor`
4. Run doc-tests: `cargo test --doc`

---

## Quality Gates

Every PR must pass before merge:

```bash
# The single command that covers everything:
./scripts/warner-check.sh

# Which runs:
cargo fmt --all          # no formatting drift
cargo test               # all unit + integration tests (83+ tests)
cargo clippy --all-features -- -D warnings   # zero warnings
```

Additional checks for sensitive areas:

```bash
# Full spec sync (happy path, steps 1-5)
cargo test test_altair_light_client_sync -- --nocapture

# BLS spec vectors
cargo test bls_spec -- --nocapture

# Drift-prevention regression
cargo test test_store_tracker_agree_after_rotation
```

---

## PR Description Template

```markdown
## Summary
- [ one-line description of what changed and why ]

## Invariants
- [ which invariants from docs/architecture.md were checked / affected ]

## Test plan
- [ ] `./scripts/warner-check.sh` passes
- [ ] [ any additional targeted tests ]

## Files changed
- [ list key files with brief rationale ]
```

---

## Key File Quick Reference

| What you need | Where to look |
|---|---|
| Public API surface | `src/light_client.rs`, `src/lib.rs` |
| Update processing engine | `src/consensus/light_client.rs` |
| Committee selection + BLS domain | `src/consensus/sync_committee.rs` |
| Merkle proofs | `src/consensus/merkle.rs` |
| BLS signature verification | `src/consensus/bls.rs` |
| Type definitions | `src/types/consensus.rs`, `src/types/primitives.rs` |
| Network constants + fork schedule | `src/config.rs` |
| Spec test runner | `src/consensus/light_client_spec_tests.rs` |
| Test fixture loader | `src/test_utils.rs` |
| Design invariants | `docs/architecture.md` |
