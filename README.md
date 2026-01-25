# Ethereum Light Client

Independently verified knowledge of the Ethereum blockchain used to be something only people running full Ethereum nodes had access to (requiring relatively large computational resources and technical expertise). But since the Altair upgrade, verification of the truth of the chain became accessible to a larger class of people... through light clients.

This is a lightweight Rust library implementing Ethereum’s consensus-layer [light client sync protocol](https://ethereum.github.io/consensus-specs/specs/altair/light-client/sync-protocol/
) (**verification only**).  The library enables resource constrained apps/devices to independently verify the legitimacy of the latest finalized and optimistic beacon block headers **without having to run a full node**.

### Security Disclaimer:
Experimental; do not use for mainnet security-critical decisions!

---

<br>

### Beacon Block Headers
Beacon block headers are a light client’s anchor into Ethereum.  Legitimate headers give people a trusted root they can verify specific blockchain information against (like current account balances or state changes from smart contract execution).  Given trusted finalized and optimistic headers, light clients can ask an Ethereum node/RPC for specific information about the chain **without having to keep track of all blockchain information themselves**.  

Previously, individuals and devices that didn't operate a full node had to ask a beacon node/RPC for blockchain information; they had to *trust* the node/RPC wasn't lying to them.  But now, nodes and RPCs can give details to light clients about consensus/execution-layer information, along with a proof, **tying claimed information back to the locally derived, trusted beacon block header**.  When a proof checks out against a light client's header, users can verify correctness locally.  The provider can still withhold/censor data, but can no longer lie to them about what's true. 

**Who Can Benefit?**
- Wallets: “Is this transaction actually finalized?”
- Bridges / relays: “Has this event that happened on Ethereum finalized?” (safety-critical)
- Browsers/extensions: “Show accurate chain status without trusting an RPC.”
- Embedded / constrained devices: verify minimal facts with minimal resources.
---

<br>

### Status
- **Supported Today:** This library is currently validated against the official Ethereum Consensus-spec tests for the **Altair** light client sync protocol.  Bootstrapping + light client update processing works for normal functionality (test steps 1-5).
- **Limitations:** 
    - Fork-aware generalized indices + domains beyond Altair **are not implemented yet**, so data from later forks may not verify correctly.
    - The library doesn't implement `force_update` functionality yet (test steps 6-10).  This is a timeout recovery path used when the chain isn't finalizing and the client can't make progress through normal updates.  

### Library Functionality
- **Bootstraps from a trusted checkpoint** — Takes a trusted `LightClientBootstrap` (checkpoint header + its current sync committee + proof) and verifies the committee binding to the header; subsequent updates can be verified deterministically.
- **Verifies light client updates** — Maintains the latest finalized and optimistic `BeaconBlockHeader`s by validating sync committee signatures and Merkle proofs via `LightClient::process_update`.
- **Handles sync committee rotations** — Tracks current/next sync committees as periods change. (Details in docs/architecture.md.)
- **Configurable presets via `ChainSpec`** — Provides Altair's mainnet and "minimal" presets.  Minimal presets are used by spec tests.  (Fork schedule support is in progress.)

### What This Library Does *Not* Do
- **Fetch updates from the network** — Users must provide `LightClientUpdate`s from their own source (beacon node API, relay, etc). 
- **Prove execution-layer state** — This library tracks consensus-layer information only; no execution-layer types or execution state proof verification.
- **Store full chain history** — This library only contains the current verified view needed for light client operations.

### Design and Trust Model
Users need to provide a **trusted bootstrap** (a checkpoint/finalized header + current sync committee + Merkle proof binding the committee to the header’s `state_root`).  After bootstrapping, the library deterministically verifies updates.
- **Safety** follows from correct verification, given the user provides a legitimate bootstrap
- **Liveness** depends on the user's update source (and will improve further once `force_update` is implemented).

Design notes: `docs/architecture.md` (WIP)

## Roadmap
1. Add fork-aware verification across all mainnet consensus forks (Altair → Bellatrix → Capella → Deneb → Electra → Fulu) driven by `ChainSpec`
2. Expand on the `docs/architecture.md` document.  Discuss major Ethereum Consensus concepts and repository design
3. Add serialization support (e.g. serde feature) so consumers can persist/restore LightClientStore
4. Implement `force_update` for all forks
5. Add a small "HTTP updater" example crate (separate from core; keep library verification-only)

---

<br>

## Installation  
Add this to your `Cargo.toml`:

```toml
[dependencies]
eth-light-client = "0.1"
```

## Quickstart
- Users supply a `LightClientBootstrap` and `LightClientUpdate`s from any source (beacon node API, relay, file, etc.).
- The library deterministically verifies updates and maintains the latest verified **finalized + optimistic headers** and **current + next sync committees**.
- The values below are placeholders. In production, fetch a real bootstrap from:
- `/eth/v1/beacon/light_client/bootstrap/{block_root}`

```rust,ignore
use eth_light_client::{ChainSpec, LightClient, LightClientBootstrap};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fetch bootstrap from a trusted endpoint:
    // GET /eth/v1/beacon/light_client/bootstrap/{block_root}
    let bootstrap: LightClientBootstrap = /* fetch from bootstrap endpoint */;

    // Create light client - merkle proof verification happens automatically
    let mut client = LightClient::new(ChainSpec::mainnet(), bootstrap)?;

    // Then fetch updates from any source and verify them:
    // GET /eth/v1/beacon/light_client/updates?start_period=X&count=1
    let update = /* fetch from updates endpoint */;
    client.process_update(update)?;

    println!("Finalized slot: {}", client.finalized_header().slot);
    Ok(())
}
```

### API (small)
- `LightClient::new(chain_spec, bootstrap)`
- `process_update(update) -> Result<UpdateOutcome>`
- getters: `finalized_header()`, `optimistic_header()`, `current_sync_committee()`,
  `next_sync_committee()`, `current_period()`, `is_synced()`, `chain_spec()`

## Testing
This library is end-to-end tested against official Ethereum Consensus light client spec tests for **Altair**.
These tests exercise the full verification flow through the public API:
`LightClient::new` (bootstrap verification) and `process_update` (update verification).

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

BLS signature verification is tested against official Ethereum consensus spec test vectors.
See [tests/BLS_TESTING.md](tests/BLS_TESTING.md) for cryptographic verification details.

## Acknowledgements
This project was created with assistance from AI tooling (Claude + ChatGPT).

## License

MIT OR Apache-2.0
