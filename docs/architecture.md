# Architecture
This document is meant to be a reference for users of the library to understand 1) Ethereum consensus layer related design/concepts and 2) specific repository design.  It's currently a work-in-progress document. 

## Outline
1. Mental model
- Light clients keep a small verified view of the beacon chain.

2. Beacon block headers
- What they contain (slot, proposer, parent root, state_root, body_root)
- What “commitment” means (state_root anchors proofs)

3. Finalized vs optimistic
- What each means for consumers (safety vs liveness)

4. What an update provider is
- beacon node / consensus client API / RPC / relay
- can censor, can’t lie (with valid proofs)

5. Verification flow
- bootstrap → process_update → store evolves
- A `LightClientBootstrap` contains a finalized header, its current sync committee, and a merkle proof binding the committee to the header's `state_root`.
- `LightClientUpdate`s contain an attested beacon block header, a sync committee aggregate signature over that header, and (optionally) finalized header + finality proof and next sync committee + proof


6. Trust model
- Explain the difference in trust assumptions between a full node and light client
- trusted checkpoint requirement
- liveness depends on update source

---

WORK IN PROGRESS!!!

### 1. Mental Model
TODO!

### 2. Beacon Block Headers
Beacon block headers are small cryptographich representations of Ethereum blocks that ____. 
They're a light client’s anchor into Ethereum.  Legitimate headers give people a trusted root they can verify specific information against, like current account balances or state changes from smart contract execution.  Given trusted finalized and optimistic headers, light clients can ask a (Beacon Node)[https://ethereum.org/developers/docs/nodes-and-clients/#what-are-nodes-and-clients] for specific information about the chain **without having to keep track of all blockchain information themselves**.  
**TODO:** 
- is "ask a Beacon Node" completely accurate?
- individuals that didn't run their own node had to ask someone operating one for blockchain information: they had to *trust* that the responding party wasn't lying to them.

Nodes can then reply to requests with i) the relevant information and ii) a proof that **ties claimed information back to the light client's locally derived, trusted beacon block header**.  When a node's proof checks out against the light client's header, a user can verify correctness of a ____ node's message locally.  Nodes can still withhold/censor data, but can no longer trick those dependent upon them about what's true. 



## How Data Structures and Cryptography Connect:
**Trusted Bootstrap Header**  (this is **the** single trust point required for a light client)
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;^
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|        
**Sync Committee**  (merkle proof proves the sync committee to be part of the bootstrap header's state root)
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;^
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|
**Attested Header**   (BLS aggregate signature is proven to be attested to by over 2/3rds of the trusted sync committee)
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;^
 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|
From here, finalized checkpoints, next sync committee, and arbitrary consensus + execution proofs can be anchored


## Flow of the Light Client Sync Protocol:
**Phase 1: Bootstrap**
The client needs a trusted checkpoint:
- Recent finalized beacon block header
- Corresponding sync committee (512 validators)
- Merkle proof that the sync committee is committed to by the checkpoint's beacon state

**Phase 2: Following the Chain**
For each light client update:
1. Current sync committee signs beacon block headers
2. Light client receives updates (providers can cause liveness issues, but not safety issues)
3. Light client verifies BLS aggregate signatures against known committee
4. When supermajority (2/3+) signs, header is accepted
5. Finalized and optimistic headers are updated accordingly

**Phase 3: Sync Committee Transitions**
Every ~27 hours (8192 slots per period):
1. Beacon state commits to next sync committee
2. Current committee signs this transition
3. Light client updates its stored committee
4. Process continues with new committee


**TODO:** Where should this go?
- **Configurable presets via `ChainSpec`** — Provides Altair's mainnet and "minimal" presets.  Minimal presets are used by spec tests.  (Fork schedule support is in progress.)






## Questions to answer:
- Why does a light client need to rely on a trusted checkpoint?  
- What is a sync committee? 
- Why is 2/3rds supermajority important for finality?
- What is weak subjectivity?   
