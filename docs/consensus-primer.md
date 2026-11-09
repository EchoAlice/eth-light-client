# Ethereum Consensus and Light Clients Primer (WIP)

Table of Contents:
1. Blockchains
    - Why and How
    - Transactions, Blocks, and The Blockchain
    - An Asynchronous Network
    - Safety and Liveness
2. Ethereum Consensus
    - Overview 
    - Ethereum's Consensus Protocol - Gasper
3. Sharing Information within Ethereum
    - Signatures + Hashing
    - SSZ
4. Ethereum Light Clients
    - Sync Committees
    - Bootstrapping
    - Light Client Updates

------------------------------------------------

## 1. Blockchains
#### Why
People coordinate with one another by sharing and acting upon information.  Throughout history, humanity has created new ways of representing and sharing information to coordinate more efficiently.  In the 20th century, people created computers, which allow us to process and share vast amounts of digital information.  Almost all of humanity's organizing information now exists within this medium.

Money itself is one set of organizing information that's, for the most part, represented as digital information within an authoritative computer's database, or *digital ledger*.  Historically, digital ledgers have been unilaterally controlled by small groups of people behind closed doors (e.g. the Federal Reserve's ledger).  Opaque, unilateral control of monetary information has led to problems, like debanking and manipulation of a civilization's underlying monetary supply.  **Those who control a database hold sovereignty over the information inside.**

Satoshi changed this paradigm in 2009 by creating the first digital ledger that anyone could use and independently verify, and no one could unilaterally control: he created the first blockchain — Bitcoin.  Other projects, like Ethereum, have since iterated on this concept and expanded upon what kinds of information could exist and be processed within a blockchain.

The underlying ethos of these two blockchains (and many others) is the same: create a digital ledger that no one can gatekeep or taint to facilitate credibly neutral coordination throughout the digital world.

**Note:** Unlike Bitcoin and Ethereum, some blockchains restrict who can use and verify them.  These are "private blockchains", but they're largely irrelevant at a civilizational scale, because they ultimately rely on a small group of people who operate behind closed doors.  In this doc, "blockchain" is shorthand for "public blockchain".

#### How
The responsibility of verifying and updating a digital ledger doesn't disappear with blockchains: it moves from a single actor to thousands of independent ones.  Anyone with a computer and an internet connection can take part in this responsibility by operating a *node*. Each node within a blockchain runs a piece of software that automatically enforces the blockchain's governing ruleset, or *protocol*.

Nodes must (i) store their own copy of the ledger, (ii) independently verify that the information within their copy is sound, and (iii) communicate with other nodes to make sure everyone's ledger stores the exact same set of information — they must come to *consensus* about the state of the ledger.

When a blockchain is operating smoothly, the nodes within its network are in sync with one another and processing new information, creating a coherent digital ledger that's simultaneously held and used by tons of individuals around the world.

A blockchain's protocol is necessarily open-source: anyone can read the rules that dictate how information is processed and added to the ledger.  A blockchain is necessarily open to public participation: anyone can run the software that implements the protocol to independently verify the ledger is sound.

**This combination of properties gives digital sovereignty over organizing information back to the individual.**

### Transactions, Blocks, and The Blockchain