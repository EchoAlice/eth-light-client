# CLAUDE.md

## Project identity

This repository is a correctness-first Ethereum consensus light client implementation in Rust.

The goal is to verify Ethereum consensus-layer light client bootstraps and updates without running a full beacon node. Correctness, fork-awareness, and spec compatibility are more important than minimizing code size or moving quickly.

## Core rules

- Prefer small, reviewable PR-sized changes.
- Preserve explicit fork-aware design.
- Do not collapse fork-specific types into vague generic structs unless explicitly justified.
- Do not silently weaken verification logic to make tests pass.
- Treat merkleization logic, fork versions, signing domains, and sync committee validation as correctness-critical.
- Prefer official Ethereum consensus spec tests and fixtures whenever possible.
- Before editing code, inspect the relevant architecture and summarize the proposed change.
- After editing code, run targeted tests and explain what passed, what failed, and what remains untested.

## Invariants 

1. protocol/spec conformance is the highest priority
2. fork behavior must be spec-driven, not hardcoded ad hoc
3. avoid duplicate mutable sources of truth
4. validation before state mutation
5. public API should expose stable protocol-level concepts, not convenience internals
6. regression-prone bugs should get targeted tests

## Architecture assumptions

Important public API / processing anchors:

- `LightClient::new` performs bootstrap verification.
- `process_update` / `process_update_at_slot` perform update verification.
- `LightClientProcessor` and `LightClientStore` manage verified light client state.
- `ChainSpec` models fork schedule and fork versions.
- Light client data structures are fork-aware.
- Capella and later headers include execution payload header data plus an execution branch.
- Verification should use the beacon header root where the protocol expects it, not the full light client header root.

## Development direction

The current long-term goal is continued fork support after Capella:

1. Deneb
2. Electra
3. Fulu

For each new fork:

1. Identify structural changes in the Ethereum consensus light client spec.
2. Add or update explicit fork-aware Rust types.
3. Wire fork dispatch deliberately.
4. Add fixture loading if needed.
5. Add official consensus spec tests where available.
6. Avoid public API changes unless necessary.

## Consensus-critical areas

Be especially careful with:

- Fork-specific SSZ field order.
- Manual `hash_tree_root` implementations.
- Execution payload header roots.
- Execution payload inclusion branches.
- Merkle proof generalized indices.
- Signature slot vs attested/finalized slot.
- Fork version and domain selection by slot.
- Sync committee participation threshold logic.
- Test fixture expectations that compare beacon roots, execution roots, finalized headers, or store state.
- Any abstraction that makes it unclear which fork’s rules are being applied.

## Working style

When asked to implement a feature:

1. Inspect existing code first.
2. Explain the current design.
3. Explain the smallest sensible PR boundary.
4. Do not make broad refactors unless explicitly requested.
5. Make minimal changes.
6. Run targeted tests first.
7. Run broader tests if the targeted tests pass and the change justifies it.
8. Summarize the diff, test results, and remaining correctness risks.

When asked to investigate a fork upgrade:

1. Compare the relevant Ethereum consensus spec types against the previous fork.
2. Identify which changes are structural, which are verification-related, and which are test-fixture-related.
3. State what is already handled by existing fork-parameterized code.
4. State what actually needs to be added.
5. Do not edit code until the proposed boundary is clear.

## Rust/code expectations

- Prefer explicit types over clever generic abstractions.
- Keep fork dispatch readable.
- Keep error paths meaningful.
- Avoid large unrelated formatting churn.
- Avoid changing public API surface unless the benefit is clear.
- Keep tests close to the behavior they verify.
- If adding helpers, name them according to the consensus concept they represent.

## Test expectations

Use targeted tests during development, then broader tests before finalizing.

Useful commands may include:

```sh
cargo test
cargo clippy -- -D warnings
cargo test --features test-utils
cargo test -- --ignored