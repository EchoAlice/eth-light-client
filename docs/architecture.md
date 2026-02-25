# Architecture
This document is meant to be a reference for users of the library to understand 1) Ethereum consensus layer related design/concepts and 2) specific repository design.  It's currently a work-in-progress document.

## How Data Structures and Cryptography Connect:
**Trusted Bootstrap Header**  (this is **the** single trust point required for a light client)
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;^
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|
**Sync Committee**  (merkle proof proves the sync committee to be part of the bootstrap header's state root)
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;^
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|
**Attested Header**   (BLS aggregate signature is proven to be attested to by over 2/3rds of the trusted sync committee)
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;^
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|
From here, finalized checkpoints, next sync committee, and arbitrary consensus + execution proofs can be anchored


## Flow of the Light Client Sync Protocol:
**Phase 1: Bootstrap**
The client needs a trusted checkpoint:
- Recent finalized beacon block header
- Corresponding sync committee (512 validators)
- Merkle proof that the sync committee is committed to by the checkpoint's beacon state

**Phase 2: Following the Chain**
For each light client update:
1. Current sync committee signs beacon block headers
2. Light client receives updates (providers can cause liveness issues, but not safety issues)
3. Light client verifies BLS aggregate signatures against known committee
4. When supermajority (2/3+) signs, header is accepted
5. Finalized and optimistic headers are updated accordingly

**Phase 3: Sync Committee Transitions**
Every ~27 hours (8192 slots per period):
1. Beacon state commits to next sync committee
2. Current committee signs this transition
3. Light client updates its stored committee
4. Process continues with new committee


## Questions to answer:
- Why does a light client need to rely on a trusted checkpoint?
- What is a sync committee?
- Why is 2/3rds supermajority important for finality?
- What is weak subjectivity?

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
    ├── sync_committee.rs          # Stateless committee helpers + BLS domain/sig
    ├── merkle.rs                  # Merkle branch verification (SSZ proofs)
    ├── bls.rs                     # BLS12-381 signature verification (blst)
    ├── light_client_spec_tests.rs # Altair spec-test runner (#[cfg(test)])
    └── bls_spec_tests.rs          # BLS spec-test vectors (#[cfg(test)])
```

### Responsibilities

| Module | Owns | Does |
|---|---|---|
| `light_client.rs` (public) | `LightClient` wrapper | Thin facade; delegates to `LightClientProcessor`, computes `UpdateOutcome` |
| `consensus/light_client.rs` | `LightClientProcessor` | Validation, signature check, apply-update; holds `LightClientStore` |
| `types/consensus.rs` | `LightClientStore` | Single source of truth for `current_sync_committee`, `next_sync_committee`, `finalized_header`, `optimistic_header` |
| `consensus/sync_committee.rs` | — (stateless) | `committee_for_slot`, `learn_next_sync_committee_from_update`, `verify_sync_aggregate`, BLS domain computation |
| `consensus/merkle.rs` | — | `verify_bootstrap_sync_committee`, `verify_next_sync_committee`, `verify_finality_branch` |
| `consensus/bls.rs` | — | `fast_aggregate_verify`, `verify_bls_aggregate_signature` via blst |
| `config.rs` | `ChainSpec` | Slot/epoch/period arithmetic, fork schedule, generalized indices |

---

## Data Flow

### Bootstrap

```
User supplies LightClientBootstrap
        │
        ▼
LightClient::new(spec, bootstrap)
        │
        ▼
LightClientProcessor::new(spec, header, committee, branch, genesis_root)
        │
        ├─► merkle::verify_bootstrap_sync_committee
        │       proves committee ∈ header.state_root
        │
        └─► LightClientStore::new(header, committee, genesis_root)
                sets finalized_header, optimistic_header, current_sync_committee
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
        │          ├─► sync_committee::committee_for_slot(sig_slot, store.finalized.slot,
        │          │       &store.current_committee, store.next_committee.as_ref(), spec)
        │          │     selects current or next committee by period comparison
        │          │
        │          └─► sync_committee::verify_sync_aggregate(committee, sig_slot,
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
                   │    ► store.current = store.next.take()
                   │
                   ├─ COMMITTEE LEARNING: sync_committee::learn_next_sync_committee_from_update(
                   │        update, current_period, next_known, spec)
                   │    guards: has committee data, next not already known,
                   │            attested period == current store period
                   │    ► merkle::verify_next_sync_committee
                   │    ► returns Ok(Some(committee)) → store.next = Some(committee)
                   │
                   └─ update optimistic header, participation tracking
```

---

## Critical Invariants

These properties must hold after every successful `apply_light_client_update`.

### I-1: Store is the Single Source of Truth

`LightClientStore` is the sole owner of `current_sync_committee` and
`next_sync_committee`.  There is no separate tracker or period counter;
the sync-committee module provides stateless helper functions that
accept committee references and derive periods from store state.

**Enforced by:** `sync_committee.rs` contains only free functions — no
struct, no stored state.

### I-2: Period Derived from Finalized Header

The canonical "store period" is always:

```
store_period = spec.slot_to_sync_committee_period(store.finalized_header.slot)
```

See `LightClientStore::finalized_sync_committee_period()` in
`src/types/consensus.rs`.  There is no separate period counter that
could fall out of sync.

### I-3: Rotation Gating

Committee rotation happens if and only if:

```
period(update.finalized_header.slot) == store_period + 1
    AND store.next_sync_committee.is_some()
```

See `src/consensus/light_client.rs`, `apply_light_client_update()`.

Rotation is gated by the **finalized** period advancing, never by the attested
period alone.

### I-4: Committee Learning Guard

A new `next_sync_committee` is accepted only when:

1. The update carries `next_sync_committee` data
2. `store.next_sync_committee` is `None` (no overwrite of already-known next)
3. `attested_period == store_period` (must attest to current period)
4. Merkle proof verifies against `attested_header.state_root`

See `sync_committee::learn_next_sync_committee_from_update()` in
`src/consensus/sync_committee.rs`.

### I-5: Signature Domain Uses fork_version_slot

Domain computation for sync committee signatures uses:

```
fork_version_slot = max(signature_slot, 1) - 1
```

The fork version is determined by the epoch of `fork_version_slot`, not the
epoch of `signature_slot` itself.

See `compute_sync_committee_domain_for_slot()` in
`src/consensus/sync_committee.rs`.

### I-6: Committee Selection by Period

`committee_for_slot()` selects the signing committee:

- `sig_period == store_period` → `current_sync_committee`
- `sig_period == store_period + 1` → `next_sync_committee` (must be Some)
- otherwise → error

Period comparison is keyed off `store.finalized_header.slot`.

See `sync_committee::committee_for_slot()` in
`src/consensus/sync_committee.rs`.

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
`src/config.rs`.

---

## Test Coverage Map

| Area | Test Location | What It Covers |
|---|---|---|
| End-to-end spec sync | `consensus/light_client_spec_tests.rs` | Altair spec vectors steps 1-5 (happy path) |
| BLS spec vectors | `consensus/bls_spec_tests.rs` | Official Ethereum BLS test vectors |
| BLS primitives | `consensus/bls.rs::tests` | Single sig, aggregate sig, infinity handling |
| Merkle verification | `consensus/merkle.rs::tests` | Branch validation, sync committee root, spec fixture root match |
| Domain computation | `consensus/sync_committee.rs::tests` | Fork boundary domain, signing root, fork data root |
| Committee selection | `consensus/sync_committee.rs::tests` | `committee_for_slot` period logic, rotation gating, next-period guard |
| Rotation correctness | `consensus/light_client.rs::tests` | `test_store_period_correct_after_rotation` — verifies store state after rotation |
| Update validation | `consensus/light_client.rs::tests` | Basic header age checks, future-slot rejection |
| Public API | `light_client.rs::tests` | `LightClient` creation, getters, `UpdateOutcome` variants |
| Store logic | `types/consensus.rs::tests` | Store creation, period computation, supermajority math |
| ChainSpec | `config.rs::tests` | Slot/period arithmetic, fork detection, gindex boundaries, custom config validation |

**Not yet tested:** `force_update` (steps 6-10 are `#[ignore]`), serialization/persistence.
