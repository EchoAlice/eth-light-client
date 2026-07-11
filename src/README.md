# `src/` — module map

How to think about each top-level module. Currently covers `config`; more
modules to be documented over time.

## `config` — the network rulebook & fork oracle

`config` is the single source of truth for **network parameters** and **fork
dispatch**. The rest of the crate consults it for two things:

1. *This network's constants* — genesis time, seconds/slot, slots/epoch,
   sync-committee period math, committee size.
2. *Which fork's rules apply at a given slot/epoch, and its parameters* — the
   core job, and the home of the crate's explicit fork-awareness.

It owns exactly two consensus-critical dispatches:

- `fork_version_at_epoch` → the signing **domain** (sync-committee sig checks)
- `*_gindex(slot)` → the Merkle **generalized indices** (proof checks)

Everything downstream branches on `Fork`; `config` is the one place that maps
`slot/epoch → Fork → parameters`.

**It holds no verification behavior** — no SSZ, Merkle, or signature logic, only
data and pure lookups. Verification lives in `consensus/`, parameterized by what
`config` returns:

> `config` = inert, correctness-critical data + pure lookups
> `consensus` = behavior driven by that data

### Two layers (parse, don't validate)

| Type | Role |
|------|------|
| `ChainSpecConfig` | Raw, untrusted **input**. Public fields, constructible/deserializable, *can be invalid*. |
| `ChainSpec` | The **validated, immutable** runtime object. `#[non_exhaustive]`, `const fn` accessors only. |

`try_from_config` validates; `from_config` is the *one* place the config→spec
mapping lives. Once code holds a `ChainSpec`, it trusts it.

### Why it's handled carefully

`config` sits near the **floor** of the dependency graph (depends only on
`error` + `types::primitives`); nearly everything consensus-y depends on it. So
it's foundational, stable, and low-churn — its surface should be exactly the
questions the rest of the repo legitimately asks. It's also where each **new
fork lands** (a `ForkParams`, a gindex arm, a fork version) as support advances
(Deneb → Electra → Fulu).
