# Architecture
This document is meant to be a reference for users of the library to understand 1) Ethereum consensus layer related design/concepts and 2) specific repository design.  It's currently a work-in-progress document. 

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


## Questions to answer:
- Why does a light client need to rely on a trusted checkpoint?  
- What is a sync committee? 
- Why is 2/3rds supermajority important for finality?
- What is weak subjectivity?   
