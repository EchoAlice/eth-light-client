# Consensus

Core consensus-layer verification for the light client: BLS signatures, Merkle
proofs, sync-committee validation, and the light-client sync state machine.

> **Note:** This README currently documents only the module's **testing** setup.
> A broader overview of the consensus components is still to be written.

## Testing

The consensus tests split along two **orthogonal** axes — *scope* (what a test
exercises) and, for the end-to-end tests, *surface* (which API it drives). A
third property, *whether a test uses official spec fixtures*, cuts across both.

### Scope

| Scope | What it does | Where |
|-------|--------------|-------|
| **Unit** | Exercises one function/method in isolation. | `bls.rs`, `merkle.rs`, `sync_committee.rs`, `light_client.rs` |
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
