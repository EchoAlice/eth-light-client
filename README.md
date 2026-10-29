# Ethereum Light Client

This library implements the verification and store-update logic of Ethereum’s consensus-layer [light client sync protocol](https://ethereum.github.io/consensus-specs/specs/altair/light-client/sync-protocol/).  

**Security Disclaimer:** Experimental.  Do not use for security-critical decisions.

# Summary 
Light clients give users a highly secure way to access information within Ethereum's blockchain without having to run a full node.  Where a full node *re-derives* the chain's validity from scratch, a light client just *verifies commitments* to the current state of the chain.  

Commitments are produced by a randomly-shuffled, rotating subset of validators called the sync committee.  **A sync committee's commitment is the single authority a light client derives its view of the chain from.**

This library exposes functionality to track and independently verify sync committee commitments to the latest finalized and optimistic beacon block headers, and execution state roots for blocks in forks starting at Capella.

### Resource Requirements
| | Full node | Light client |
|---|---|---|
| **Bandwidth** | ~65 GB/day. Gossip peer, continuous | ~7 MB/day. A ~1KB update per slot|
| **Compute** | Executes every transaction (with most of the computational work being state reads and writes) and verifies every attestation (~64-128 aggregate signatures per block).  **Scales with throughput** | One aggregate signature check + a few Merkle proofs per update.  One ~1,000-hash committee root per sync period (~27 hrs). No state I/O.  **Constant** |
| **Storage** | Chain state + history: ~1-1.5TB. **Grows with the chain** ~14GB/week | Only the verified store: ~50KB (2 sets of sync committee keys + 2 `LightClientHeader`s). **Constant** |

**Note:** A full node wants a quad-core, 16 GB, NVMe machine; the light client runs on anything. 

### Use Cases 
- Wallets: “Is this transaction actually finalized?”
- Bridges / relays: “Has this event that happened on Ethereum been finalized?” (safety-critical)
- Browsers/extensions: “Show accurate chain status without trusting an RPC.”
- Embedded / constrained devices: verify minimal facts with minimal resources.

## Trust Model
#### The Trusted Block Root
Because a light client doesn't download and process all blocks since the inception of Ethereum, information processing must start at some point along the chain.  This point is the **trusted block root** and is the one fact the library must accept without a proof.  

A user can cross-check this root against multiple independent sources (e.g. a checkpoint provider, a block explorer, a friend's node) to get strong evidence that the trusted root is valid.  The root should be finalized, and must fall within the weak subjectivity period (~16 days on mainnet) to protect against long-range attacks; the client rejects older roots. 

All information the light client stores is grounded in this trusted block root.  

#### Sync Committee Commitments
The network's sync committee is the one party the light client has to constantly trust.  On mainnet, Ethereum's consensus protocol randomly selects 512 validators every ~27 hours to participate as the sync committee.

The first committee the light client learns about comes from the trusted root's own block.  A user requests a bootstrap update from a light client server, which gives the client a sync committee + merkle proof that that committee is rooted within the block the trusted root represents.

Every future update reduces to one question: *"Did at least 2/3 of the sync committee the client already trusts sign this beacon block header?"*.  If committee signatures pass this threshold and the light client's update source is responsive, the client sees the update as valid and remains **live**.  If more than 1/3 of the sync committee is honest, the light client won't accept a malicious update and remains **safe**.

The bootstrap and every update can come from any source (e.g. beacon node API or block relay); a dishonest source can stall the client, but never mislead it. 

## Status
The library currently supports fork-aware light client verification through **Fulu**.

| Fork | Light client-relevant change | Official spec vectors |
|---|---|---|
| Altair | Sync committees and the light client protocol introduced | ✅ |
| Bellatrix | The Merge; no light client-specific changes | ✅ |
| Capella | `LightClientHeader` gains the execution payload header and its inclusion branch | ✅ |
| Deneb | Blobs; payload header adds `blob_gas_used` / `excess_blob_gas` | ✅ |
| Electra | `BeaconState` restructured — generalized indices shift, committee and finality branches deepen | ✅ |
| Fulu | PeerDAS; blob-parameter-only forks change the fork digest | ✅ |

Capella+ light client headers include authenticated execution payload header data rooted within the verified beacon block.  This exposes trusted execution-layer commitments (like state, transaction, and receipt roots), which can serve as anchors for proving arbitrary execution-layer facts.

## Roadmap
### V1
**To Do:** Architecture doc, then the tag.  

Tracking in issue [#131](https://github.com/EchoAlice/eth-light-client/issues/131).

### V2
- **Formal verification** — harden what exists before extending it.  Bounded model checking (Kani) of the arithmetic predicates and the Merkle walker first; then machine-checked proofs, via Rust-to-Lean translation, that the store's invariants survive every update.  BLS and SHA-256 stay the assumed primitives.

### Deferred
- **`eth_getProof` verification** — the finalized execution state root is the anchor; EIP-1186 account and storage proofs are the questions.  A different tree (hexary Merkle-Patricia), so its own slice, and it gets the same harnesses.
- **`force_update`** — the spec's escape hatch for finality outages.  The client stalls rather than force-applies; recovery is re-bootstrapping.  Keeping the store's state machine fixed is what makes proving its invariants worthwhile.
- **Store persistence** — disk, a format, and trusting your own disk all sit outside what a prover models.  Callers that need it serialize the store at the facade.

Tracking in issue [#205](https://github.com/EchoAlice/eth-light-client/issues/205)

<br/>

# Usage
**Installation**
```toml
[dependencies]
eth-light-client = "0.1"
```

Check out [`examples/live_sync.rs`](examples/live_sync.rs) for an example of how to use the library.  Run example binary with ```cargo run --example live_sync -- <provider-url> <trusted-block-root>```

### Scope
This library begins at the SSZ-decode and verification boundary, and is built on Sigma Prime's SSZ stack (`ethereum_ssz`, `ssz_types`, `tree_hash`).  Users are responsible for obtaining the trusted block root, initial bootstrap, and each subsequent block update from an external data provider.  

`ExecutionPayloadHeader`s are exposed by the library too. But gathering and validating information against the roots within the payload is also the user's responsibility.

### API Notes
- Time is always the caller's: `process_light_client_update(update, current_slot)` takes the current slot explicitly and never reads the system clock. `ChainSpec::timestamp_to_slot(unix_secs)` does the conversion. A slow clock rejects more updates but accepts slightly older trusted roots.
- For local testnets or devnets, use `ChainSpecConfig` with `ChainSpec::try_from_config()`; the presets (`ChainSpec::mainnet()`, `ChainSpec::minimal()`) are the reference.

<br/>

# Testing
The official Ethereum consensus `light_client/sync` spec vectors (minimal preset) replay end-to-end through the public `LightClient` API, for every supported fork and every fork-transition boundary the official suite covers (Bellatrix→Capella, Capella→Deneb, Deneb→Electra, and the multi-hop chains across them).  Fulu changes no light client container, so upstream ships no Electra→Fulu transition case; its single-fork cases exercise the blob-parameter fork digests instead.

The consensus spec's sync replays are all-valid, so they only prove acceptance, not rejection.  Rejection is covered from two directions: (i) the official `fast_aggregate_verify` vectors and (ii) unit tests.

The `fast_aggregate_verify` vectors pin the `blst` *adapter* (not `blst` itself), checking invalid inputs like tampered signatures, wrong pubkey sets, and infinity pubkeys.  Unit tests cover the rejection paths for things like wrong roots, malformed branches, and minority participation.

**To Do:**
- The 512-member committee arm is exercised by `examples/live_sync.rs` against mainnet, not by the test suite: upstream generates the sync suite for the minimal preset only.  A recorded mainnet replay is a v2 item ([#263](https://github.com/EchoAlice/eth-light-client/issues/263)).
- The vectors' `force_update` steps are deferred with the feature ([#205](https://github.com/EchoAlice/eth-light-client/issues/205)).

Fixture layout, the vendored case inventory, and the loader are documented in [`tests/README.md`](tests/README.md).

```bash
# Lints (includes examples and tests)
cargo clippy --all-targets -- -D warnings

# Unit + integration tests
cargo test
```

## License
MIT OR Apache-2.0
