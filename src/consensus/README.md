# Consensus

Core consensus-layer verification for the light client: BLS signatures, Merkle
proofs, sync-committee validation, and the light-client sync state machine. This
is the engine behind the thin public `LightClient` facade.

This README documents the engine end-to-end: the **data flow** through
verification, the **correctness invariants** it maintains, the **cryptography**
it relies on, its **fork awareness**, and the module's **testing** setup. For the
crate's layered module map, see [`../README.md`](../README.md); for usage and
public API, see the root [`README.md`](../../README.md).

## Data Flow

### Bootstrap
```text
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
        └─► LightClientStore::new(header, committee, genesis_root)
                sets finalized_header, optimistic_header, current_sync_committee
```

### Processing an Update
```text
LightClient::process_update(update)
    │
    ▼
LightClientProcessor::process_update_at_slot(update, current_slot)
    │
    ├─[1]─► validate_light_client_update
    │         • validate_basic: signature_slot > attested.slot, supermajority
    │         • signature_slot <= current_slot
    │         • relevance/age checks (attested vs store.finalized)
    │
    ├─[2]─► verify_update_signature  (&self, no mutation)
    │         │
    │         ├─► sync_committee::committee_for_slot(sig_slot,
    │         │       store.finalized_header.slot,
    │         │       &store.current_sync_committee, store.next_sync_committee.as_ref(),
    │         │       spec)
    │         │     selects current or next committee by period comparison
    │         │
    │         └─► sync_committee::verify_sync_aggregate(committee, sig_slot,
    │                 header_root, bits, signature, genesis_root, spec)
    │               domain = compute_sync_committee_domain_for_slot(sig_slot, …)
    │               bls::fast_aggregate_verify(participating_pubkeys, signing_root, sig)
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
              │             AND store.next_sync_committee.is_some():
              │    ► store.current_sync_committee = store.next_sync_committee.take()
              │
              ├─ COMMITTEE LEARNING: sync_committee::learn_next_sync_committee_from_update(
              │       update, finalized_period, next_known, spec)
              │    guards: has committee data, next not already known,
              │            attested period == finalized period
              │    ► merkle::verify_next_sync_committee
              │    ► store.next_sync_committee = Some(verified_committee)
              │
              └─ update optimistic header, participation tracking
```

## Critical Invariants

These properties must hold after every successful `apply_light_client_update`.
Breaking any of them is a correctness bug.

### I-1: Period Derivation from Finalized Header

The canonical "store period" is always:

```text
store_period = spec.slot_to_sync_committee_period(store.finalized_header.slot)
```

See `LightClientStore::finalized_sync_committee_period()` in `../types/consensus.rs`.

### I-2: Rotation Gating

Committee rotation happens if and only if:

```text
period(update.finalized_header.slot) == store_period + 1
    AND store.next_sync_committee.is_some()
```

Rotation is gated by the **finalized** period advancing, never by the attested
period alone. This prevents premature rotation on unfinalized attestations.

### I-3: Committee Learning Guard

A new `next_sync_committee` is accepted only when:

1. The update carries `next_sync_committee` data
2. `store.next_sync_committee` is `None` (no overwrite of already-known next)
3. `attested_period == store_period` (must attest to current period)
4. Merkle proof verifies against `attested_header.state_root`

See committee learning helpers and guards in `sync_committee.rs` and the proof
verification in `merkle.rs`.

### I-4: Signature Domain Uses fork_version_slot

Domain computation for sync committee signatures uses:

```text
fork_version_slot = max(signature_slot, 1) - 1
```

The fork version is determined by the epoch of `fork_version_slot`, not the
epoch of `signature_slot` itself. This matches the consensus spec and is
tested across fork boundaries.

See `compute_sync_committee_domain_for_slot()` in `sync_committee.rs`.

### I-5: Committee Selection by Period

`committee_for_slot()` selects the signing committee:

- `sig_period == store_period` → `current_sync_committee`
- `sig_period == store_period + 1` → `next_sync_committee` (must be Some)
- otherwise → error

Period comparison is keyed off `store.finalized_header.slot`.

See `committee_for_slot()` in `sync_committee.rs`.

## Cryptography

| Operation | Function | Library | Spec Reference |
|---|---|---|---|
| BLS aggregate verify | `bls::fast_aggregate_verify` | `blst` (min_pk) | `eth2_fast_aggregate_verify` |
| Signing root | `compute_signing_root` | `tree_hash` | `compute_signing_root` |
| Domain computation | `compute_domain` → `compute_fork_data_root` | `tree_hash` | `compute_domain` |
| Sync committee domain | `compute_sync_committee_domain_for_slot` | — | Domain with `DOMAIN_SYNC_COMMITTEE` |
| Merkle branch verify | `merkle::is_valid_merkle_branch` | `tree_hash` | `is_valid_merkle_branch` |
| Sync committee root | `SyncCommittee::hash_tree_root` (size-dispatched derive) | `tree_hash_derive` | SSZ `hash_tree_root(SyncCommittee)` |
| Header root | `BeaconBlockHeader::hash_tree_root` | `tree_hash_derive` | SSZ `hash_tree_root(BeaconBlockHeader)` |

Generalized indices for merkle proofs are fork-dependent (change at Electra):

| Field | Altair–Deneb | Electra |
|---|---|---|
| `current_sync_committee` | 54 | 86 |
| `next_sync_committee` | 55 | 87 |
| `finalized_checkpoint.root` | 105 | 169 |

See `ChainSpec::current_sync_committee_gindex()` and siblings in `../config.rs`.

## Fork Awareness

The engine implements fork-aware light client verification through **Capella**.
`LightClientHeader` is a fork enum whose Capella+ variants carry the execution
payload header and its inclusion branch; `ChainSpec` carries the full fork
schedule (Altair through Electra) and selects the generalized indices, which
change at Electra.

Each supported fork was added by the same steps, which also remain for Deneb
onward:
1. Add the fork's `LightClientHeader` / execution-payload-header types
2. Wire per-fork SSZ decode (the fork-dispatched adapter in `../types/ssz.rs`)
3. Select per-fork generalized indices (already wired in `ChainSpec`)
4. Validate against that fork's official spec test vectors

Deneb has its header types defined but decode/verification is not yet wired;
Electra (which changes the generalized indices) and Fulu follow.

## Testing

The consensus tests split along two **orthogonal** axes — *scope* (what a test
exercises) and, for the end-to-end tests, *surface* (which API it drives). A
third property, *whether a test uses official spec fixtures*, cuts across both.

### Scope

| Scope | What it does | Where |
|-------|--------------|-------|
| **Unit** | Exercises one function/method in isolation. | `bls.rs`, `merkle.rs`, `sync_committee.rs`, `processor.rs` |
| **Conformance replay** | Bootstraps a store and replays the official `light_client_sync` step sequence (updates + expected post-state) end-to-end. | `light_client_spec_tests.rs` (+ its public-API counterpart under `tests/`) |

A conformance replay is *not* a unit test even though it lives in a
`#[cfg(test)]` module: in Rust, `src/` vs `tests/` decides **access** (can it see
`pub(crate)` internals?), not **scope**.

### Surface — conformance replays only

Both replays run the *same* spec vectors; they differ only in which API surface
they drive, which is why both exist. They are complementary, not redundant.

| Surface | Driver / test names | Notes |
|---------|---------------------|-------|
| **Internal processor** | `light_client_spec_tests.rs` — `run_processor_sync`, `<fork>_sync_via_processor` | Drives `LightClientProcessor` (`pub(crate)`); also verifies Capella execution roots via the fork-aware header. |
| **Public API** | `tests/light_client_sync.rs` — `run_public_api_sync`, `<fork>_sync_via_public_api` | Drives the public `LightClient` with public types only; also checks the `UpdateOutcome` contract. Lives in the integration-test crate, outside this module. |

### "Spec test" is orthogonal to scope

A *spec test* uses official Ethereum consensus fixtures — independent of scope.
Fixtures appear at **unit** scope too, not just in the replays:

- `bls_spec_tests.rs` — official BLS `verify` / `fast_aggregate_verify` vectors, each driving a single function.
- `merkle.rs::test_sync_committee_root_against_spec_fixture` — one sync-committee root + branch, checked against a bootstrap fixture.

So "spec test", "unit test", and "the sync replay" are three different
properties that cut across one another.

Fixtures are loaded off disk by the `test_utils` module (see its README); the
consensus tests only consume the typed objects it returns.

### Coverage at a glance

| Area | Test Location | What It Covers |
|---|---|---|
| End-to-end spec sync | `consensus/light_client_spec_tests.rs` | Altair/Bellatrix/Capella end-to-end spec harness (steps 1-5); full force-update path (steps 6-10) remains `#[ignore]` |
| BLS spec vectors | `consensus/bls_spec_tests.rs` | Official Ethereum BLS test vectors exercising the production `fast_aggregate_verify` path |
| BLS primitives | `consensus/bls.rs::tests` | Single sig, aggregate sig, infinity handling |
| Merkle verification | `consensus/merkle.rs::tests` | Branch validation, sync committee root, spec fixture root match |
| Domain computation | `consensus/sync_committee.rs::tests` | Fork boundary domain, signing root, fork data root |
| Committee selection | `consensus/sync_committee.rs::tests` | `committee_for_slot` period logic, next-period guard |
| Rotation drift | `consensus/processor.rs::tests` | Store period correctness after rotation (finalized-derived period remains consistent) |
| Update validation | `consensus/processor.rs::tests` | Basic header age checks, future-slot rejection |
| Public API | `light_client.rs::tests` | `LightClient` creation, getters, `UpdateOutcome` variants |
| Store logic | `types/consensus.rs::tests` | Store creation, period computation, supermajority math |
| ChainSpec | `config.rs::tests` | Slot/period arithmetic, fork detection, gindex boundaries, custom config validation |

**Not yet tested:** `force_update` (steps 6-10 are `#[ignore]`), serialization/persistence.
