# Ethereum Light Client

<br>

### Security Disclaimer:
Experimental.  Do not use for mainnet security-critical decisions!

<br>

## Summary
**Independently verified** information within the Ethereum blockchain used to be something only people running full Ethereum nodes had access to, requiring relatively large amounts of computational resources and technical expertise. Individuals that didn't run their own node had to ask someone operating one for blockchain information: they had to *trust* that the responding party wasn't lying to them.  But since Ethereum implemented the Altair upgrade, verifying the truth of the chain became accessible to a larger class of applications and devices... through light clients.

This is a Rust library that implements Ethereum’s consensus-layer [light client sync protocol](https://ethereum.github.io/consensus-specs/specs/altair/light-client/sync-protocol/).  It exposes the **consensus-layer verification logic** required for light clients to independently verify the legitimacy of the latest (i) finalized and (ii) optimistic beacon block headers, **without having to run a full node**.

For protocol details and library design, see `docs/architecture.md`.
For contributor guidelines and change checklists, see `docs/agent_context.md`.

**Who Can Benefit?**
- Wallets: “Is this transaction actually finalized?”
- Bridges / relays: “Has this event that happened on Ethereum finalized?” (safety-critical)
- Browsers/extensions: “Show accurate chain status without trusting an RPC.”
- Embedded / constrained devices: verify minimal facts with minimal resources.

<br>

### Status
- **Supported Today:** This library *currently* implements light client verification logic for the **Altair** hardfork only (the library will eventually support all hardforks).  Altair functionality is validated against light client spec tests (steps 1-5).
- **Limitations:** 
    - Data from later forks may not verify correctly.
    - The library hasn't implemented `force_update` functionality yet (test steps 6-10).  This is a timeout recovery path used when the chain isn't finalizing and the client can't make progress through normal updates.  
- **This library does *not*:**
    - fetch updates from the Ethereum network (users supply `LightClientBootstrap` and `LightClientUpdate`s)
    - prove execution-layer state
    - store full chain history 

<br>

## Usage 
- Users must provide a `LightClientBootstrap` from a **trusted** source.  This information ties a light client to a specific finalized block within the chain.  
- Users then fetch `LightClientUpdate`s from any source (beacon node API, relay, etc).  Updates provide the light client with locally verifiable information related to the current state of the chain (current and finalized beacon block headers).

**Installation**
Add this to your `Cargo.toml`:

```toml
[dependencies]
eth-light-client = "0.1"
```

**Example** 
```rust,ignore
use eth_light_client::{ChainSpec, LightClient, LightClientBootstrap};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fetch bootstrap from a trusted endpoint:
    // GET /eth/v1/beacon/light_client/bootstrap/{block_root}
    let bootstrap: LightClientBootstrap = /* fetch from bootstrap endpoint */;

    // Create light client 
    let mut client = LightClient::new(ChainSpec::mainnet(), bootstrap)?;

    // Then fetch updates from any source and verify them:
    // GET /eth/v1/beacon/light_client/updates?start_period=X&count=1
    let update = /* fetch from updates endpoint */;
    client.process_update(update)?;

    println!("Finalized slot: {}", client.finalized_header().slot);
    Ok(())
}
```

**API Notes:**
- Injectable time is available: If you want to supply your own notion of time (tests, embedded devices, custom clocks), use `process_update_at_slot(update, current_slot)`
- Getters: `finalized_header()`, `optimistic_header()`, `current_sync_committee()`,
  `next_sync_committee()`, `current_period()`, `is_synced()`, `chain_spec()`

**Custom/Devnet Configuration:**

For local testnets or devnets, use `ChainSpecConfig` with `ChainSpec::try_from_config()`. See the rustdoc on `ChainSpecConfig` for usage examples.

Current limitations (Tier-0):
- `sync_committee_size` must be 32 or 512 (matching minimal/mainnet presets)
- `altair_fork_epoch` must be 0 (light client protocol requires Altair from genesis)
- Generalized indices and BeaconState layout are not configurable (hardcoded per-fork)

### Trust Model
- **Safety**: follows from correct verification, given the user provides a legitimate bootstrap.
- **Liveness** depends on the user's update source (and will improve further once `force_update` is implemented).

See `docs/architecture.md` for design details and invariants.

<br>

## Roadmap
1. Add fork-aware verification across all mainnet consensus forks (Altair → Bellatrix → Capella → Deneb → Electra → Fulu) driven by `ChainSpec`
2. Expand on the `docs/architecture.md` document.  Discuss major Ethereum Consensus concepts and repository design
3. Add serialization support (e.g. serde feature) so consumers can persist/restore LightClientStore
4. Implement `force_update` for all forks
5. Add a small "HTTP updater" example crate (separate from core; keep library verification-only)

<br>

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

<br>

## Credits
This library is being created with the help of Claude Code (Opus 4.6) and ChatGPT (5.2).


## License

MIT OR Apache-2.0
