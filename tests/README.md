# Tests
Integration tests and the vendored spec fixtures that drive them.

```
tests/
├── light_client_sync.rs   # the sync-vector replay
├── light_client_api.rs    # public-API behavior the replays can't express
├── common/                # fixture loader
└── fixtures/              # vendored consensus-spec-tests
    ├── minimal/<fork>/light_client/sync/<case>/
    └── general/phase0/bls/fast_aggregate_verify/
```

Run everything with `cargo test`; the replay alone with `cargo test --test light_client_sync`.

## Fixtures
Vendored from [`ethereum/consensus-spec-tests`](https://github.com/ethereum/consensus-spec-tests) **v1.6.0-beta.0** (CC0-1.0): every `light_client/sync` case that release ships, 39 in all. The directory layout mirrors upstream, so re-vendoring a case is a straight `cp -r` of its directory.  All sync cases use the **minimal preset**: 32-member sync committees, 8 slots per epoch, 8 epochs per sync committee period.

### A sync case
Each case is one scenario in a box: a toy chain, a starting point, a sequence of inputs, and the reference implementation's expected store after each input.

| File | Contents |
|---|---|
| `config.yaml` | The toy chain's parameters (fork activation epochs and versions).  The authority behind the hand-transcribed schedules in `common/fork.rs`; replays fail loudly if the transcription diverges. |
| `meta.yaml` | The out-of-band facts a light client needs: genesis validators root, trusted block root, and the fork digest each object was encoded under. |
| `bootstrap.ssz_snappy` | The `LightClientBootstrap` for the trusted root. |
| `update_<root>_<sf>.ssz_snappy` | One `LightClientUpdate`, named by its attested header root.  The suffix says what it carries: `s`/`x` = next sync committee present/absent, `f`/`x` = finality proof present/absent. |
| `steps.yaml` | The script: an ordered list of updates to feed, the `current_slot` to feed each at, and the finalized/optimistic headers expected afterward. |

### Case kinds vendored
| Case | What it exercises | Forks |
|---|---|---|
| `light_client_sync` | The primary replay: bootstrap, then updates through several sync periods with rotation | Altair → Electra |
| `advance_finality_without_sync_committee` | Finality advances on updates that carry no committee | Altair → Electra |
| `supply_sync_committee_from_past_update` | A non-advancing past update still teaches the next committee | Altair → Electra |
| `<fork>_fork` | Fork-transition boundary: chain crosses into the next fork mid-replay, with an `upgrade_store` step | `capella_fork`, `deneb_fork`, `electra_fork` |
| `<fork>_<fork>_fork` | Multi-hop transition: one store crosses two boundaries, so both shape changes land in one replay | `capella_deneb_fork`, `capella_electra_fork`, `deneb_electra_fork` |
| `<fork>_store_with_legacy_data` | Bootstrap in one fork, store already migrated to a later one (pyspec's `upgrade_lc_store`) | 9 cases, Altair → Deneb origins |
| `light_client_sync_no_force_update` | The baseline chain, ending in a `force_update` step that must leave the store unchanged | Altair → Fulu |

Every case the release ships is wired, but not every case exercises something.  The `*_store_with_legacy_data` cases test pyspec's store migration, which has no counterpart in a fork-agnostic store; they pass trivially.  The `*_no_force_update` cases halt at their `force_update` step like every other replay.  Both kinds are kept so the vendored set is exactly one upstream release, not a curated subset.  The vectors' `force_update` steps are deferred with the feature ([#205](https://github.com/EchoAlice/eth-light-client/issues/205)).

## The loader (`common/`)
`SyncTestCase` picks a case directory and its chain schedule, parses `meta.yaml`, and builds a `ChainSpec` once at construction.  The `load_*` methods snappy-decompress a fixture file and hand the raw SSZ to the crate's public `from_ssz` decoders under the fork **that object's own fixture digest names**; this is never a per-test fork assumption.  That is what lets one replay span a fork boundary: pre-fork updates keep arriving after the chain forks, and each decodes under its own layout.

Constructors are named by case kind (`light_client_sync(fork)`, `fork_transition(from, to)`, …). `light_client_sync.rs` is the worked example.

## BLS vectors
The BLS math is `blst`'s.  What the official `fast_aggregate_verify` vectors pin is *our adapter* around it (`src/consensus/bls.rs`): the domain separation tag, infinity-pubkey and empty-set handling, and byte marshaling — including the **negative** cases (tampered signatures, wrong pubkey sets, infinity pubkeys) that the all-valid sync replays never reach.  Sync-committee verification is a same-message aggregate, so `fast_aggregate_verify` is the only production BLS entry point and the only path these vectors drive.

The test lives with the adapter (`spec_tests` in `bls.rs`) and walks every vendored vector, reporting all mismatches at once: `cargo test --lib fast_aggregate_verify_spec_vectors`.
