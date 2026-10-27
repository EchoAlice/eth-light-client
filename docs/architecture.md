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
a. **Choosing/creating a `chain_spec`** - This library supports mainnet and minimal presets, alongside a custom, configurable network (committee size is limited to 512 or 32 members).  User must declare which network it wants to operate on top of.  `chain_spec` states the network's rulebook, which answers questions like "What fork is this block in?". 
b. **Supplying a trusted root** - Because a light client doesn't download and process all historical information since the inception of Ethereum, information processing must start at some point along the chain.  This is the one fact the library takes without proof. Once the client has this root, all future information can be verified against it. 
c. **Supplying a clock** (TODO) - *Why* does our library opt out of reading a clock? 
d. **Fetching SSZ bytes** (TODO) - *Why* does our library opt out of fetching bytes? 

### 2. Bootstrapping
The user fetches the bootstrap update that corresponds to its trusted root.  This update holds the client's first sync committee and a proof that it's the committee associated with the trusted beacon block root.  

The bootstrap update is passed into `LightClient::new` to create the processor.  The processor verifies this update is internally consistent and corresponds to the user's trusted root.  If checks pass, the first trusted sync committee is passed to the light client's store, and the client can begin processing updates.

### 3. Messages from the Wire
#### Message Types
The classes of updates a light client ingests (outside of an initial bootstrap) are (i) optimistic updates, (ii) finality updates, and (iii) sync committee updates. 

Optimistic updates carry an attested header; finality updates carry both attested and finalized headers + proof; and sync committee updates carry an attested and a finalized header + proof, along with the next period's sync committee + proof. Sync committee updates are ~25KB, while optimistic and finality updates are a few hundred bytes each.

All message types get converted to a single `LightClientUpdate` with optional finality and sync committee fields.  The engine processes this unified type through one path.

#### The Wire Adapter
All light client updates are SSZ encoded. SSZ bytes exist in fork-specific layouts that aren't self-describing; conversion from the wire requires out-of-band information (fork and committee size) the library caller must provide. 

`types/ssz` contains a wire adapter that takes a message's bytes + out-of-band information and bakes it into intermediate `Raw` types.  These raw types use external ssz libraries, which need exact layouts at compile time, to convert those richer types into types the library's processor understands.  The wire adapter handles (i) fork-dispatched wrapping of headers into the `LightClientHeader` enum, (ii) the spec-sized sync committee and aggregate, and (iii) the spec's optional-field collapse (zeroed committee / finality on the wire → `None`). 

By the time an update reaches the engine, its layout has already been checked against the fork and committee size the caller declared. A mismatch fails at decode, so the engine never sees a malformed shape.

**Note:** `hash_tree_root` uses the same size-typed `Raw*` view that the wire adapter leverages, since merkleizing a `Vector` needs `N` at compile time too.  The public `SyncCommittee` deliberately stores a plain `Vec` and rebuilds the `Raw` view when it needs SSZ behavior in either direction, so generics never leave the module.

### 4. Processing an Update 
Each update must be signed by a sync committee the client's store recognizes as legitimate.

Order of operations when an update arrives:

a. There was >=2/3 participation within *a* sync aggregate.
b. The update is internally consistent: it's slot ordering makes sense, and merkle proofs check-out against its claimed root
c. the sync committee that did participate (i) created a message that was bound to the right network+ fork, (ii) signed its message properly, and (iii) the committee that signed lines up with one of the two committees the client keeps track of.
d. store all relevant updates' info (first optimistic, then finalized header and/or sync committee). 


# Syncing and Catchup
*Forthcoming: how committee rotation lets a client bootstrapped from an older root walk forward one sync period at a time.*
