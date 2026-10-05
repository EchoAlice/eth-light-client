# Ethereum Light Client

This library implements the verification and store-update logic of Ethereum’s consensus-layer [light client sync protocol](https://ethereum.github.io/consensus-specs/specs/altair/light-client/sync-protocol/).  

**Security Disclaimer:** Experimental.  Do not use for security-critical decisions.

# Summary 
Light clients give users a highly secure way to access information within Ethereum's blockchain without having to run a full node.  Where a full node *re-derives* the chain's validity from scratch, a light client just *verifies a commitment* to the current state of the chain.  The commitment is produced by a randomly-shuffled, rotating subset of validators called the sync committee.

This library exposes functionality to track and independently verify sync committee commitments to the latest (i) finalized and (ii) optimistic beacon block headers.

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
- Users provide a **trusted block root**, which should be finalized, is chosen out-of-band (a checkpoint provider, a block explorer, a friend's node), and must be within the weak subjectivity period (~16 days on mainnet; the client rejects older roots).  This is the client's entire root of trust.  The bootstrap and all future updates can be provided by any untrusted source (beacon node API, relay, etc).  All updates ultimately stem from this root. 
- After providing a trusted block root, users fetch the `LightClientBootstrap`.  Its `BeaconBlockHeader`'s root has to match the trusted block root and provide a valid proof that the sync committee it claims is rooted within the header.  This gives the light client its first sync committee. 
- Users then fetch subsequent updates and verify each is signed by the sync committee associated with the block's sync period (which rotates every ~27 hrs).  Updates regularly advance a light client's optimistic/finalized view of the chain, and provide the light client with the next sync committee once per sync period.  

Every update reduces to one question: *"Did at least 2/3 of the sync committee the client already trusts sign this beacon block header?"*.  If committee signatures pass this threshold and the light client's update source is responsive, the client sees the update as valid and remains **live**.  If more than 1/3 of the sync committee is honest, the light client won't accept a malicious update and remains **safe**.

## Status
The library currently supports fork-aware light client verification through **Fulu**.

| Fork | Light client-relevant change | Official spec vectors |
|---|---|---|
| Altair | Sync committees and the light client protocol introduced | ✅ |
| Bellatrix | The Merge; no light client-specific changes | ✅ |
| Capella | `LightClientHeader` gains the execution payload header and its inclusion branch | ✅ |
| Deneb | Blobs; payload header adds `blob_gas_used` / `excess_blob_gas` | ✅ |
| Electra | `BeaconState` restructured — generalized indices shift, committee and finality branches deepen | ✅ |
| Fulu | PeerDAS; blob-parameter-only forks change the fork digest | pending ([#106](https://github.com/EchoAlice/eth-light-client/issues/106)) |

Capella+ light client headers include authenticated execution payload header data rooted within the verified beacon block.  This exposes trusted execution-layer commitments (like state, transaction, and receipt roots), which can serve as anchors for proving arbitrary execution-layer facts.

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
The official Ethereum consensus `light_client/sync` spec vectors (minimal preset) replay end-to-end through the public `LightClient` API, for every supported fork and every fork-transition boundary that changes light client behavior (Bellatrix→Capella, Capella→Deneb, Deneb→Electra).  Electra→Fulu is pending ([#106](https://github.com/EchoAlice/eth-light-client/issues/106)).

The consensus spec's sync replays are all-valid, so they only prove acceptance, not rejection.  Rejection is covered from two directions: (i) the official `fast_aggregate_verify` vectors and (ii) unit tests.

The `fast_aggregate_verify` vectors pin the `blst` *adapter* (not `blst` itself), checking invalid inputs like tampered signatures, wrong pubkey sets, and infinity pubkeys.  Unit tests cover the rejection paths for things like wrong roots, malformed branches, and minority participation.

**To Do:**
- Mainnet-preset replays (512-member committees) are pending ([#122](https://github.com/EchoAlice/eth-light-client/issues/122))
- The vectors' `force_update` steps are deferred with the feature ([#205](https://github.com/EchoAlice/eth-light-client/issues/205)).

Fixture layout, the vendored case inventory, and the loader are documented in [`tests/README.md`](tests/README.md).

```bash
# Lints (includes examples and tests)
cargo clippy --all-targets -- -D warnings

# Unit + integration tests
cargo test
```

# Roadmap
### V1
**To Do:** Implement the rest of the official vectors and mainnet-preset replays.  

Tracking in issue [#131](https://github.com/EchoAlice/eth-light-client/issues/131).

### V2
- **`eth_getProof` verification** — the finalized execution state root is the anchor; EIP-1186 account and storage proofs are the questions.  A different tree (hexary Merkle-Patricia), so its own slice.
- **Store persistence** — the store lives in memory; every restart re-bootstraps from a trusted root.
- **`force_update`** — the spec's escape hatch for finality outages.  Cut so that the client stalls rather than force-applies; recovery is re-bootstrapping.

Tracking in issue [#205](https://github.com/EchoAlice/eth-light-client/issues/205)

## License
MIT OR Apache-2.0
