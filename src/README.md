# `src/` — module map

A map of the crate: first how it's layered as a whole, then how to think about
each module. Per-module coverage starts with `config`; more added over time.

## Architecture — how the crate is layered
Nearly all of this crate is verification machinery, kept private in `consensus/` behind a thin `LightClient` facade. The other modules — `config` (network rules), `types`, and `error` — exist to feed that verification. The stack runs from the foundational floor (stable, correctness-critical) up to the public surface:

```mermaid
flowchart TD
    fac["'light_client'<br/>public FACADE —<br/>'LightClient', 'UpdateOutcome'"]
    eng["'consensus/'<br/>verification ENGINE —<br/>'merkle', 'bls', 'sync_committee'<br/>(private)"]
    ct["'types::consensus'<br/>headers, committees,<br/>updates, 'Store'"]
    cfg["'config'<br/>'ChainSpec' —<br/>fork + param oracle"]
    prim["'types::primitives'<br/>leaf aliases — 'Slot', 'Root', …"]
    err["'error'<br/>'Error' / 'Result' — no deps, underlies all"]

    fac --> eng --> ct --> cfg --> prim
    prim -.-> err
```

| Module | Layer | Role |
|--------|-------|------|
| `error` | floor | `Error` / `Result` |
| `types::primitives` | leaf | byte-array type aliases |
| `config` | oracle | `ChainSpec`: fork schedule + network params |
| `types::consensus` | data | fork-aware headers, committees, updates, store |
| `consensus/` | engine | SSZ / Merkle / BLS verification (private) |
| `light_client` | facade | `LightClient`, `UpdateOutcome` (public entry) |

**Facade vs engine.** `LightClient` (`src/light_client.rs`) is a thin public wrapper; the real work lives in `LightClientProcessor` (`src/consensus/processor.rs`, `pub(crate)`). `process_update` delegates to the processor and wraps its `bool` into the richer `UpdateOutcome`. Consumers touch only the facade — `consensus/` is private.

**The `types` umbrella spans two layers.** `types::primitives` sits *below* config (leaf aliases, no deps); `types::consensus` sits *above* it (its types carry a `&ChainSpec`). So `config` depends on `types::primitives` while `types::consensus` depends on `config`, which makes the crate-level `config ↔ types` edge *look* circular. It isn't — the real order is `primitives → config → consensus`; only the shared `types` name blurs it.

<br/>

## `config` — the network rulebook & fork oracle
The `config` module is the single source of truth for **network parameters** and the **fork schedule**. The rest of the crate consults it for two things:
1. *A network's constants* — genesis time, seconds/slot, slots/epoch,
   sync-committee period math, committee size.  Each network defines its own fork rules/parameters.
2. *Which fork's rules/parameters apply (within a specific network) at a given slot/epoch*.

This module owns two consensus-critical, fork-dependent lookups:
- `fork_version_at_epoch` → the signing **domain** (sync-committee sig checks)
- `*_gindex(slot)` → the Merkle **generalized indices** (proof checks)

**The module holds no verification behavior** — no SSZ, Merkle, or signature logic, only data and pure lookups. Verification lives in `consensus/`, parameterized by what `config` returns:
> `config` module = inert, correctness-critical data + pure lookups
> `consensus` module = contains behavior driven by that data

### Two layers (parse, don't validate)
| Type | Role |
|------|------|
| `ChainSpecConfig` | Raw, untrusted **input**. Public fields, constructible/deserializable, *can be invalid*. |
| `ChainSpec` | The **validated, immutable** runtime object. `#[non_exhaustive]`, `const fn` accessors only. |

`try_from_config` validates; `from_config` is the *one* place the config→spec
mapping lives. Once code holds a `ChainSpec`, it trusts it.

```mermaid
flowchart TD
    cfg["ChainSpecConfig<br/> ingests raw input params"]

    cfg --> tfc["try_from_config()"]
    tfc --> v{"validate()"}
    v -->|Err| err["Err(InvalidInput)"]
    v -->|Ok| fc["from_config()<br/>single config-to-spec<br/>mapping"]

    main["mainnet()"] --> fc
    min["minimal()"] --> fc
    ft["for_test()"] --> fc

    fc --> spec["ChainSpec<br/>validated<br/>immutable · trusted"]
```

The validated door (`try_from_config`) is the only path that checks input; the
trusted presets (`minimal`, `mainnet`, `for_test`) skip `validate()` as a
`const` construction optimization but still go through the single `from_config`
mapping. Their params are known-good, so `try_from_config` would accept them
just the same.

### Handle this module carefully
`config` sits near the **floor** of the dependency graph (depends only on `error` + `types::primitives`); nearly everything consensus-y depends on it. So it's foundational.  The module should be stable and low-churn.

It's also where each **new fork lands** (a `ForkParams`, a gindex arm, a fork version) as support advances (Deneb → Electra → Fulu).
