# Background

Table of Contents:
1. Blockchains
    - Public Blockchains
    - Transactions, Blocks, and State
    - Safety and Liveness
2. Ethereum Consensus
    - GHOST + Casper FFG
    - Sharing Information with Commitments
3. Light Clients within Ethereum
    - Sync Committees
    - Bootstrapping
    - Light Client Updates
        - Optimistic (live)
        - Finalized (safe)
------------------------------------------------

## 1. Blockchains
### Public Blockchains
Public blockchains, like Bitcoin and Ethereum, aim to be credibly neutral digital ledgers which anyone can interact with and no one can unilaterally control.  This class of blockchains act as trustless, programmatic intermediaries to facilitate coordination throughout the digital world. 

Unlike traditional authoritative databases (e.g. the Federal Reserve's ledger), public blockchains are explicitly designed to *not* be controlled by a central operator; it would degrade one such system's credible neutrality.  Instead, these ledgers are meant to be simultaneously kept by large networks of independently operated computers.  

Nodes within a blockchain's network (i) each store their own copy of the ledger, (ii) verify the ledger's information is sound and (iii) help propagate information to other nodes, so everyone's copy of the ledger can be in sync.  

People operate nodes by running open-source software that implements a blockchain's governing ruleset- its protocol.  With public blockchains, anyone can operate a node to help contribute to the network.  This combination of open-source protocol + public participation in the network is foundational to a blockchain's resilience.

**Note:** In this doc from here on out, "blockchain" will be shorthand for "public blockchain".

### Transactions, Blocks, and an Asynchronous Network
#### Transactions
Users trustlessly coordinate with one another by creating transactions that update the ledger.  Transactions must follow rules defined within the protocol and are always grounded in the reality of the current ledger's state. For example, Alice can send Bob 1 BTC *if* the ledger says she has at least 1 BTC at the time of her request.

To create a transaction, a user sends a transaction request to a node in the network.  This node independently verifies the request follows protocol rules, and spreads it to other nodes.  Other nodes then do the same, until the request has been distributed throughout the network.

In an effort to keep nodes on the same page, propogated transaction requests don't get applied to the ledger immediately; they sit inside nodes' storage as pending.

#### Blocks

#### An Asynchronous Network

### Safety and Liveness

## 2. Ethereum Consensus

### Ghost + Casper FFG

### Sharing Information with Commitments

## 3. Light Clients within Ethereum

### Sync Committees

### Bootstrapping

### Light Client Updates
#### Optimistic (live)
#### Finalized (safe)
