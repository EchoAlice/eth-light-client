# Ethereum Light Client

This library implements the verification and store-update logic of Ethereum’s consensus-layer [light client sync protocol](https://ethereum.github.io/consensus-specs/specs/altair/light-client/sync-protocol/).  

**Security Disclaimer:** Experimental.  Do not use for security-critical decisions.

# Summary 
Light clients give users a highly secure way to access information within Ethereum's blockchain without having to run a full node.  Where a full node *re-derives* the chain's validity from scratch, a light client just *verifies a commitment* to the current state of the chain.  The commitment is produced by a randomly-shuffled, rotating subset of validators called the sync committee.

This library exposes functionality to track and independently verify sync committee commitments to the latest (i) finalized and (ii) optimistic beacon block headers.

For protocol background, see `docs/consensus-primer.md` (work in progress).

### Resource Requirements
| | Full node | Light client |
|---|---|---|
| **Bandwidth** | ~65 GB/day. Gossip peer, continuous | ~7 MB/day. A ~1KB update per slot|
| **Compute** | Executes every transaction and checks ~64-128 aggregate attestation signatures per block.  Scales with throughput | One aggregate signature check + a few Merkle proofs per block. And one 1,000-hash committee root per sync period (~27 hrs).  **constant** |
| **Storage** | Chain state + history: ~1-1.5TB, **grows with the chain** ~14GB/week | Only the verified store: ~50KB (2 sets of sync committee keys + 2 `LightClientHeader`s), **constant** |

### Use Cases 
- Wallets: “Is this transaction actually finalized?”
- Bridges / relays: “Has this event that happened on Ethereum been finalized?” (safety-critical)
- Browsers/extensions: “Show accurate chain status without trusting an RPC.”
- Embedded / constrained devices: verify minimal facts with minimal resources.

## Trust Model
- Users provide a recent **trusted block root**, which is finalized and chosen out-of-band (a checkpoint provider, a block explorer, a friend's node).  This is the client's entire root of trust.  The bootstrap and all future updates can be provided by any untrusted source (beacon node API, relay, etc), and ultimately must stem from this root. 
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

Check out `examples/live_sync.rs` for an example of how to use the library.  Run example binary with ```cargo run --example live_sync -- <provider-url> <trusted-block-root>```

**Note:** This library begins at the SSZ-decode and verification boundary.

**API Notes:**
- Time is always the caller's: `process_light_client_update(update, current_slot)` takes the current slot explicitly and never reads the system clock. `ChainSpec::timestamp_to_slot(unix_secs)` does the conversion; a clock that runs slow rejects more, never accepts more.
- Getters: `finalized_beacon_block_header()`, `optimistic_beacon_block_header()`,
  `current_sync_committee()`, `next_sync_committee()`,
  `finalized_sync_committee_period()`, `chain_spec()`

**Custom/Devnet Configuration:**
For local testnets or devnets, use `ChainSpecConfig` with `ChainSpec::try_from_config()`. See the rustdoc on `ChainSpecConfig` for usage examples.

### Current Scope and Constraints:
- `sync_committee_size` currently supports only the standard Ethereum consensus preset values:
  - `512` for mainnet
  - `32` for the minimal preset
- SSZ tree layouts and generalized indices are not fully generic inputs; proof paths are implemented explicitly for each supported fork

## SSZ 
The crate uses a single SSZ implementation — the Sigma Prime / Lighthouse stack: **`ethereum_ssz`** (encode/decode) + **`ssz_types`** (length-bounded collections: `FixedVector`, `VariableList`, `BitVector`) + **`tree_hash`** (`hash_tree_root`). Public types carry their SSZ traits by deriving them (`#[derive(Encode, Decode, TreeHash)]`), so there is no hand-written merkleization.

The one piece of custom SSZ code is the wire-decode adapter in `src/types/ssz.rs`: it decodes fork-specific wire layouts and adapts them to the library's public types (fork-enum headers, `Option` fields, the spec-sized sync committee).  The wire adapter leverages `ethereum_ssz` where it can.

## Testing
This library is end-to-end tested against official Ethereum Consensus minimal-preset light client spec tests for every supported fork (Altair through Electra), plus every fork-transition boundary (Bellatrix→Capella, Capella→Deneb, Deneb→Electra).  Tests exercise the full verification flow through the public API:
`LightClient::new` (bootstrap verification) and `process_light_client_update` (update verification).  For the full case inventory (vendored vs. upstream), see the spec-case coverage table in [`src/consensus/README.md`](src/consensus/README.md).  End-to-end coverage against mainnet parameters (512-member committees) is still pending.

```bash
# Unit + integration tests
cargo test

# Lints
cargo clippy -- -D warnings

# Enables optional test utilities used by spec-test fixture loading (not stable API)
cargo test --features test-utils

# The second half of Altair vectors (steps 6–10) are present but marked ignored until `force_update` is implemented.
cargo test -- --ignored
```

BLS signature verification is covered by official Ethereum consensus spec test vectors, and Merkle proof verification is exercised through fixture-driven light client tests. See [tests/BLS_TESTING.md](tests/BLS_TESTING.md) for signature verification details.

## Roadmap
1. Add fork-aware verification across all mainnet consensus forks (driven by `ChainSpec`):
- [x] Altair
- [x] Bellatrix
- [x] Capella
- [x] Deneb
- [x] Electra
- [ ] Fulu
2. Expand the module READMEs (esp. [`src/consensus/README.md`](src/consensus/README.md)).  Discuss major Ethereum Consensus concepts and repository design
3. Add serialization support (e.g. serde feature) so consumers can persist/restore LightClientStore
4. Implement `force_update` for all forks
5. Add a small "HTTP updater" example crate (separate from core; keep library verification-only)

## License
MIT OR Apache-2.0
