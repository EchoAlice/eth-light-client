# Crate Layout 
Nearly all of this crate is verification machinery, kept private in `consensus/` behind a thin `LightClient` facade. The other modules (`chain_spec` (network rules), `types`, and `error`) exist to feed that verification. 

The stack runs from the foundational floor (stable, correctness-critical) up to the public surface:

| Module | Layer | Role |
|--------|-------|------|
| 1. `light_client` | facade (public entry) | `LightClient` |
| 2. `consensus/` | engine (private - users of the crate can't corrupt the store's state) | SSZ / Merkle / BLS verification |
| 3. `types::consensus` | data | fork-aware headers, committees, updates, store; extended by `types::ssz` with `from_ssz` |
| 4. `chain_spec` | oracle | `ChainSpec`: single source of truth for fork schedule + network params |
| 5. `types::primitives` | leaf | byte-array type aliases |
| 6. `error` | floor | `Error` / `Result` |

# From Wire to Store 
### 1. Caller's Obligations
This library is strictly message conversion, verification, and storage logic for light clients.  Users are responsible for four things:
- **Choosing/creating a `ChainSpec`** - The library supports mainnet and minimal presets, alongside a custom, configurable network (committee size is limited to 512 or 32 members).  User must declare which network they want to operate on top of.  `chain_spec.rs` states the network's rulebook, answering questions like "What fork is this block in?". 
- **Supplying a trusted root** - see [The Trusted Block Root](../README.md#the-trusted-block-root) in the README. 
- **Supplying a clock** and **fetching SSZ bytes** - The library is deliberately a pure verification core with no ambient state. 

### 2. Bootstrapping
The user fetches the bootstrap update that corresponds to its trusted root.  This update holds the client's first sync committee and a proof that it's the committee associated with the trusted beacon block root.  

A bootstrap update is passed into `LightClient::new` to create the processor.  The processor verifies this update is internally consistent and corresponds to the user's trusted root.  If checks pass, the first trusted sync committee is passed to the light client's store, and the client can begin processing updates.

### 3. Messages from the Wire
#### Message Types
The three classes of updates a light client ingests (outside of an initial bootstrap) are (i) optimistic updates, (ii) finality updates, and (iii) sync committee updates. Each of these updates carries a sync committee signature over its attested block header. 

Optimistic updates carry an attested header; finality updates carry both an attested and finalized header + finality proof; and sync committee updates carry an attested and a finalized header + finality proof, alongside the next period's sync committee + committee proof. Sync committee updates are ~25KB, while optimistic and finality updates are a few hundred bytes each.

All message types get converted to a single `LightClientUpdate` with optional finality and sync committee fields.  The engine processes this unified type through one path for simplicity.

#### The Wire Adapter
All light client updates are SSZ encoded. SSZ bytes exist in fork-specific layouts that aren't self-describing, so conversion from the wire requires out-of-band information (fork and committee size) the library caller must provide. 

`types/ssz` contains a wire adapter that takes a message's bytes + out-of-band information and bakes it into intermediate `Raw` types.  These raw types use external ssz libraries, *which need fork and committee-size layouts at compile time*, to convert those richer types into types the library's processor understands.  The wire adapter handles (i) fork-dispatched wrapping of headers into the `LightClientHeader` enum, (ii) the spec-sized sync committee and aggregate, and (iii) the spec's optional-field collapse (zeroed committee + finality on the wire → `None`).

By the time an update reaches the engine, its layout has already been checked against the fork and committee size the caller declared. A mismatch fails at decode, so the engine never sees a malformed shape.

**Note:** `hash_tree_root` uses the same size-typed `Raw*` view that the wire adapter leverages, since merkleizing a `Vector` needs its committee size (`N`) at compile time too.  The public `SyncCommittee` deliberately stores a plain `Vec` and rebuilds the `Raw` view when it needs SSZ behavior in either direction, so generics never leave the module.

### 4. Processing an Update 
Order of operations when an update is sent to the processor:
a. There was >=2/3 participation within *a* sync aggregate (fail-fast principle).
b. The update is internally consistent: its slot ordering makes sense with respect to the client's clock, and merkle proofs check-out against its claimed root
c. Sync committee checks:
  - (i) the message created was bound to the right network and fork, 
  - (ii) it was signed properly, and 
  - (iii) the committee that signed it is one of the two committees the client keeps track of.
d. Store all relevant update's info (first optimistic, then finalized header and/or sync committee). 

**Note:** Each update's `BeaconBlockHeader` is checked against the fork its block was proposed in, not the container it arrived in. Necessary for updates that cross fork boundaries.

# Sync Committee Rotation
To keep from creating an easy attack target, the protocol randomly selects and rotates the validators chosen to be in the sync committee. Sync committee rotation happens at fixed time intervals, known as the sync period (~27 hours on mainnet). The light client is responsible for keeping up with relevant sync committees as rotation happens across sync period boundaries. 

A light client can only process updates from periods that correspond to the sync committees it has already verified as legitimate and holds within its `LightClient::Store`. The store derives the sync period it's in based on its own finalized header's slot, not from an external clock.

While processing most updates, a light client only needs to check update signatures that are associated with its `current_sync_committee` for period P. But for the store to cross a sync period boundary, it needs to use its `next_sync_committee` (learned from a previously processed sync committee update) to verify the finalized header crossed into period P + 1.

Once finality across a sync period boundary is proven to the client, its stored `next_sync_committee` value is moved to `current_sync_committee`, and the client must learn the new `next_sync_committee` (corresponding to period P + 2) sometime after the store's committee rotation and before it can cross the next sync period boundary.

**Each new committee learned by the client is authenticated by a committee it already trusts.**

### Syncing to the Chain's Current Period 
When a caller's trusted root isn't within the network's current sync committee period, the library user is responsible for catching up to it. A light client can't just jump from some historical block up to the current head of the chain: a jump implies that there's no verification of each sequential sync committee, so ultimately no proof of the current state's legitimacy.

Syncing from the trusted root's sync committee period to the chain's current sync committee period is facilitated by a light client server's `/eth/v1/beacon/light_client/updates?start_period=…&count=…` response. The server creates a chain of updates that link the committee the store currently holds to the next relative sync committee, all the way up to the committee within the blockchain's current sync period.  The light client steps through these updates.

See `examples/live_sync.rs` for an example of this walk.

# Deviations From Spec
1. **No per-fork store type:**
The spec defines a different `LightClientStore` for each fork and requires `upgrade_lc_store_to_*` before post-fork data can be processed. Our store is a single type holding fork-tagged headers, so it accommodates every fork at once: no `upgrade_lc_store_to_*` is needed.

2. **No `force_update`:** 
The escape hatch for a finality outage was left out for simplicity. Instead of implementing this fallback, the client would stall and need to be re-bootstrapped from a future trusted root once finality returns.  Because of this design decision, three pieces of the library diverge from the spec:
  a. Strict 2/3rds participation is checked at the beginning of `LightClientProcessor::process_light_client_update`.
  b. `apply_light_client_update` doesn't advance `optimistic_header` to `finalized_header` when finality passes it: `optimistic >= finalized` holds structurally.
  c. `LightClientStore` doesn't hold `best_valid_update`, `previous_max_active_participants`, or `current_max_active_participants`. 

3. **Weak Subjectivity Period Check (Stricter than Spec):**
In the Light Client Sync Protocol spec, there is no weak subjectivity check for the user-supplied trusted block root.  Like Helios, we chose to implement one for safety. 

Instead of directly translating the Ethereum Consensus spec's `compute_weak_subjectivity_period`, the library assumes the per-epoch churn limit equals total active balance / CHURN_LIMIT_QUOTIENT, which reduces the computation to config constants.  Calculating the WSP would otherwise depend on reading beacon state, which a light client doesn't have access to before bootstrap. See `ChainSpec::weak_subjectivity_period` for more details.

This assumption holds true on mainnet today, but can vastly overestimate the true WSP on custom networks, meaning the client could **accept trusted roots that are older than what's actually safe**. 

**Note:** The library's `weak_subjectivity_period` will not reduce to config constants in the upcoming Gloas fork. The current constant would be ~2.25× too permissive on mainnet. 

# Conventions 
- `u64` for spec quantities vs `usize` for lengths, no casts between them
- `x_to_y()` = arithmetic, `x_at_y()` = schedule lookup