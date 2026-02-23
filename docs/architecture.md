# Architecture: Design and Invariants

This document describes the internal design of the library, the invariants it
maintains, and how the modules relate.  For usage examples and public API, see
the root `README.md`.

---

## Module Map

```
src/
├── lib.rs                         # Crate root; re-exports public API
├── light_client.rs                # Public API: LightClient, UpdateOutcome
├── config.rs                      # ChainSpec, ChainSpecConfig, ForkSchedule
├── error.rs                       # Error enum (thiserror)
├── types/
│   ├── primitives.rs              # Type aliases: Slot, Root, BLSPublicKey, …
│   └── consensus.rs               # BeaconBlockHeader, SyncCommittee,
│                                  #   LightClientUpdate, LightClientStore,
│                                  #   LightClientBootstrap, SyncAggregate
└── consensus/
    ├── light_client.rs            # LightClientProcessor (internal engine)
    ├── sync_committee.rs          # SyncCommitteeTracker + BLS domain/sig helpers
    ├── merkle.rs                  # Merkle branch verification (SSZ proofs)
    ├── bls.rs                     # BLS12-381 signature verification (blst)
    ├── light_client_spec_tests.rs # Altair spec-test runner (#[cfg(test)])
    └── bls_spec_tests.rs          # BLS spec-test vectors (#[cfg(test)])
```

### Responsibilities

| Module | Owns | Does |
|---|---|---|
| `light_client.rs` (public) | `LightClient` wrapper | Thin facade; delegates to `LightClientProcessor`, computes `UpdateOutcome` |
| `consensus/light_client.rs` | `LightClientProcessor` | Validation, signature check, apply-update; holds `LightClientStore` + `SyncCommitteeTracker` |
| `types/consensus.rs` | `LightClientStore` | Single source of truth for `current_sync_committee`, `next_sync_committee`, `finalized_header`, `optimistic_header` |
| `consensus/sync_committee.rs` | `SyncCommitteeTracker` (period counter only) | Committee selection, period-guard validation, BLS domain computation, aggregate signature verification |
| `consensus/merkle.rs` | — | `verify_bootstrap_sync_committee`, `verify_next_sync_committee`, `verify_finality_branch` |
| `consensus/bls.rs` | — | `fast_aggregate_verify`, `verify_bls_aggregate_signature` via blst |
| `config.rs` | `ChainSpec` | Slot/epoch/period arithmetic, fork schedule, generalized indices |

---

## Data Flow

### Bootstrap

```
User supplies LightClientBootstrap (and optionally network specifications)
        │
        ▼
LightClient::new(spec, bootstrap)
        │
        ▼
LightClientProcessor::new(spec, header, committee, branch, genesis_root)
        │
        ├─► merkle::verify_bootstrap_sync_committee
        │       proves committee is within the bootstrap header.state_root
        │
        ├─► LightClientStore::new(header, committee, genesis_root)
        │       sets finalized_header, optimistic_header, current_sync_committee
        │
        └─► SyncCommitteeTracker::new(initial_period)
                period = spec.slot_to_sync_committee_period(header.slot)
```

### Processing an Update

```
LightClient::process_update(update)
        │
        ▼
LightClientProcessor::process_update_at_slot(update, current_slot)
        │
        ├─[1]─► validate_light_client_update
        │          • validate_basic: signature_slot > attested.slot, supermajority
        │          • signature_slot <= current_slot
        │          • attested.slot > finalized.slot (or >=, for committee updates)
        │
        ├─[2]─► verify_update_signature  (&self, no mutation)
        │          │
        │          ├─► tracker.committee_for_slot(sig_slot, store.finalized.slot,
        │          │       &store.current_committee, store.next_committee.as_ref(), spec)
        │          │     selects current or next committee by period comparison
        │          │
        │          └─► tracker.verify_sync_aggregate(committee, sig_slot,
        │                  header_root, bits, signature, genesis_root, spec)
        │                domain = compute_sync_committee_domain_for_slot(sig_slot, …)
        │                bls::fast_aggregate_verify(participating_pubkeys, signing_root, sig)
        │
        └─[3]─► apply_light_client_update  (&mut self)
                   │
                   │  store_period = store.finalized_sync_committee_period(spec)
                   │
                   ├─ if update has finalized_header with newer slot:
                   │    ► merkle::verify_finality_branch
                   │    ► store.finalized_header = finalized_header
                   │
                   ├─ ROTATION: if period(update.finalized_header) == store_period + 1
                   │            AND store.next_sync_committee.is_some():
                   │    ► tracker.advance_to_next_period()
                   │    ► store.current = store.next.take()
                   │
                   ├─ COMMITTEE LEARNING: tracker.process_sync_committee_update(
                   │        update, store.next_committee.is_some(), spec)
                   │    guards: has committee data, next not already known,
                   │            attested period == tracker.current_period
                   │    ► merkle::verify_next_sync_committee
                   │    ► returns Ok(Some(committee)) → store.next = Some(committee)
                   │
                   └─ update optimistic header, participation tracking
```

---

## Critical Invariants

These properties must hold after every successful `apply_light_client_update`.
Breaking any of them is a correctness bug.

### I-1: Single Source of Truth for Committees

`LightClientStore` is the sole owner of `current_sync_committee` and
`next_sync_committee`.  `SyncCommitteeTracker` holds only a period counter;
it reads committees via caller-supplied references.

**Why:** Dual ownership previously allowed silent divergence between store and
tracker committee copies, causing signature verification against the wrong
committee.

**Enforced by:** `SyncCommitteeTracker` struct has a single field
(`current_period: u64`) — there are no committee fields to diverge.

### I-2: Period Derivation from Finalized Header

The canonical "store period" is always:

```
store_period = spec.slot_to_sync_committee_period(store.finalized_header.slot)
```

See `LightClientStore::finalized_sync_committee_period()` in
`src/types/consensus.rs:334`.

`SyncCommitteeTracker.current_period` must equal this value.  The tracker
period is only incremented inside the rotation block of
`apply_light_client_update`, immediately alongside the store rotation.

### I-3: Rotation Gating

Committee rotation happens if and only if:

```
period(update.finalized_header.slot) == store_period + 1
    AND store.next_sync_committee.is_some()
```

See `src/consensus/light_client.rs:192-209`.

Rotation is gated by the **finalized** period advancing, never by the attested
period alone.  This prevents premature rotation on unfinalized attestations.

### I-4: Committee Learning Guard

A new `next_sync_committee` is accepted only when:

1. The update carries `next_sync_committee` data
2. `store.next_sync_committee` is `None` (no overwrite of already-known next)
3. `attested_period == tracker.current_period` (must attest to current period)
4. Merkle proof verifies against `attested_header.state_root`

See `SyncCommitteeTracker::process_sync_committee_update()` in
`src/consensus/sync_committee.rs:78-116`.

### I-5: Signature Domain Uses fork_version_slot

Domain computation for sync committee signatures uses:

```
fork_version_slot = max(signature_slot, 1) - 1
```

The fork version is determined by the epoch of `fork_version_slot`, not the
epoch of `signature_slot` itself.  This matches the consensus spec and is
tested across fork boundaries.

See `compute_sync_committee_domain_for_slot()` in
`src/consensus/sync_committee.rs:188-199`.

### I-6: Committee Selection by Period

`committee_for_slot()` selects the signing committee:

- `sig_period == store_period` → `current_sync_committee`
- `sig_period == store_period + 1` → `next_sync_committee` (must be Some)
- otherwise → error

Period comparison is keyed off `store.finalized_header.slot`, not the
tracker's internal counter.

See `SyncCommitteeTracker::committee_for_slot()` in
`src/consensus/sync_committee.rs:44-66`.

---

## Cryptography Map

| Operation | Function | Library | Spec Reference |
|---|---|---|---|
| BLS aggregate verify | `bls::fast_aggregate_verify` | `blst` (min_pk) | `eth2_fast_aggregate_verify` |
| Signing root | `compute_signing_root` | `tree_hash` | `compute_signing_root` |
| Domain computation | `compute_domain` → `compute_fork_data_root` | `tree_hash` | `compute_domain` |
| Sync committee domain | `compute_sync_committee_domain_for_slot` | — | Domain with `DOMAIN_SYNC_COMMITTEE` |
| Merkle branch verify | `merkle::is_valid_merkle_branch` | `tree_hash` | `is_valid_merkle_branch` |
| Sync committee root | `merkle::compute_sync_committee_root` | `tree_hash` | SSZ `hash_tree_root(SyncCommittee)` |
| Header root | `BeaconBlockHeader::hash_tree_root` | `tree_hash_derive` | SSZ `hash_tree_root(BeaconBlockHeader)` |

Generalized indices for merkle proofs are fork-dependent (change at Electra):

| Field | Altair–Deneb | Electra |
|---|---|---|
| `current_sync_committee` | 54 | 86 |
| `next_sync_committee` | 55 | 87 |
| `finalized_checkpoint.root` | 105 | 169 |

See `ChainSpec::current_sync_committee_gindex()` and siblings in
`src/config.rs:429-452`.

---

## Test Coverage Map

| Area | Test Location | What It Covers |
|---|---|---|
| End-to-end spec sync | `consensus/light_client_spec_tests.rs` | Altair spec vectors steps 1-5 (happy path) through public-ish `LightClientProcessor` API |
| BLS spec vectors | `consensus/bls_spec_tests.rs` | Official Ethereum BLS test vectors |
| BLS primitives | `consensus/bls.rs::tests` | Single sig, aggregate sig, infinity handling |
| Merkle verification | `consensus/merkle.rs::tests` | Branch validation, sync committee root, spec fixture root match |
| Domain computation | `consensus/sync_committee.rs::tests` | Fork boundary domain, signing root, fork data root |
| Committee selection | `consensus/sync_committee.rs::tests` | `committee_for_slot` period logic, period advancement, next-period guard |
| Rotation drift | `consensus/light_client.rs::tests` | `test_store_tracker_agree_after_rotation` — verifies store/tracker stay aligned |
| Update validation | `consensus/light_client.rs::tests` | Basic header age checks, future-slot rejection |
| Public API | `light_client.rs::tests` | `LightClient` creation, getters, `UpdateOutcome` variants |
| Store logic | `types/consensus.rs::tests` | Store creation, period computation, supermajority math |
| ChainSpec | `config.rs::tests` | Slot/period arithmetic, fork detection, gindex boundaries, custom config validation |

**Not yet tested:** `force_update` (steps 6-10 are `#[ignore]`), serialization/persistence.

---

## Fork Awareness

The library currently implements light client verification for **Altair** only.
The `ChainSpec` already carries a full fork schedule (Altair through Electra)
and generalized indices change at Electra, but verification of later fork
`LightClientHeader` formats (execution payload fields added in Capella/Deneb)
is not yet implemented.

The roadmap for fork-aware verification is:
1. Extend `LightClientUpdate` to carry fork-specific header variants
2. Add per-fork deserialization
3. Add per-fork gindex selection (already wired in `ChainSpec`)
4. Validate against spec test vectors for each fork
