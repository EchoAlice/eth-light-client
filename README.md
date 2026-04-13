# Ethereum Light Client

<br>

### Security Disclaimer:
Experimental.  Do not use for Ethereum mainnet security-critical decisions!

<br>

## Summary
Independently verified information within the Ethereum blockchain used to be something only people running full Ethereum nodes had access to. Individuals that didn't have the computational resources or technical expertise to run their own node had to ask someone operating one for blockchain information.  And they had to *trust* that the responding party wasn't lying to them.  

But since Ethereum began supporting the [light client sync protocol](https://ethereum.github.io/consensus-specs/specs/altair/light-client/sync-protocol/), the "truth of the chain" became accessible to a much larger class of applications and devices... through light clients.  

**This is a Rust library that implements Ethereum’s consensus-layer light client sync protocol**.  It exposes the consensus-layer verification logic required for light clients to independently verify the legitimacy of the latest (i) finalized and (ii) optimistic beacon block headers, *without having to run a full node*.

For protocol details and library design, see `docs/architecture.md`.

**Who Can Benefit?**
- Wallets: “Is this transaction actually finalized?”
- Bridges / relays: “Has this event that happened on Ethereum finalized?” (safety-critical)
- Browsers/extensions: “Show accurate chain status without trusting an RPC.”
- Embedded / constrained devices: verify minimal facts with minimal resources.

### Status
The library currently supports fork-aware light client verification through **Capella**.

| Fork      | Type support | Verification logic | Fixture-driven tests | Status    |
|-----------|--------------|--------------------|----------------------|-----------|
| Altair    | Yes          | Yes                | Yes                  | Supported |
| Bellatrix | Yes          | Yes                | Yes                  | Supported |
| Capella   | Yes          | Yes                | Yes                  | Supported |
| Deneb     | No           | No                 | No                   | Planned   |
| Electra   | No           | No                 | No                   | Planned   |
| Fulu      | No           | No                 | No                   | Planned   |

From Capella onward, supported light client headers also include authenticated execution payload header data committed by the verified beacon block.  This exposes trusted execution-layer commitments (such as state, transaction, and receipt roots), which can serve as anchors for proving execution-layer facts.  

However, "proving execution-layer facts" is outside the scope of this library.

## Usage 
- Users must provide a `LightClientBootstrap` from a **trusted** source.  This information ties a light client to a specific finalized block within the chain.  
- Users then fetch `LightClientUpdate`s from any source (beacon node API, relay, etc).  Updates provide the light client with locally verifiable information related to the current state of the chain (current and finalized beacon block headers).

**Trust Model:**
- **Safety** follows from correct verification, given the user provides a legitimate bootstrap.
- **Liveness** depends on the user's update source (and will improve further once `force_update` is implemented).

See `docs/architecture.md` for design details and invariants.

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
  `next_sync_committee()`, `current_period()`, `chain_spec()`

**Custom/Devnet Configuration:**
For local testnets or devnets, use `ChainSpecConfig` with `ChainSpec::try_from_config()`. See the rustdoc on `ChainSpecConfig` for usage examples.

### Current Scope and Constraints:
- `sync_committee_size` currently supports only the standard Ethereum consensus preset values:
  - `32` for the minimal preset
  - `512` for mainnet
- the library currently assumes the light client protocol is active from the network’s starting point, so `altair_fork_epoch` must be `0`
- SSZ tree layouts and generalized indices are not fully generic inputs; proof paths are implemented explicitly for each supported fork

## Testing
This library is end-to-end tested against official Ethereum Consensus light client spec tests for Altair, Bellatrix, and Capella hardforks.  Tests exercise the full verification flow through the public API:
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

BLS signature verification is covered by official Ethereum consensus spec test vectors, and Merkle proof verification is exercised through fixture-driven light client tests. See [tests/BLS_TESTING.md](tests/BLS_TESTING.md) for signature verification details.

## Roadmap
1. Add fork-aware verification across all mainnet consensus forks (driven by `ChainSpec`):
- [x] Altair
- [x] Bellatrix 
- [x] Capella 
- [ ] Deneb 
- [ ] Electra 
- [ ] Fulu 
2. Expand on the `docs/architecture.md` document.  Discuss major Ethereum Consensus concepts and repository design
3. Add serialization support (e.g. serde feature) so consumers can persist/restore LightClientStore
4. Implement `force_update` for all forks
5. Add a small "HTTP updater" example crate (separate from core; keep library verification-only)

## Credits
This library is being created with the help of Claude Code (Opus 4.6) and ChatGPT (5.3).

## License
MIT OR Apache-2.0
