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
People coordinate with one another by sharing and acting upon information.  Throughout history, humanity has created new ways of representing and sharing information to coordinate more effectively.  In the 20th century, people created computers, which allow us to process and share vast amounts of digital information.  Almost all of humanity's organizing information now exists within this medium.

Money itself is one set of organizing information that's, for the most part, represented as digital information within authoritative computers' databases, or *digital ledgers*.  Historically, digital ledgers have been unilaterally controlled by small groups of people behind closed doors (e.g. the Federal Reserve's ledger).  Opaque, unilateral control of monetary information has led to problems, like debanking and manipulation of a civilization's underlying monetary supply.  **Those who control a database hold sovereignty over the information inside.**

Satoshi changed this paradigm in 2009 by creating the first digital ledger that anyone could use and independently verify, and no one could unilaterally control: he created the first blockchain — Bitcoin.  Other projects, like Ethereum, have since iterated on this concept and expanded upon what kinds of information could exist and be processed within a blockchain.

The underlying ethos of these two blockchains (and many others) is the same: create a digital ledger that no one can gatekeep or taint to facilitate credibly neutral coordination throughout the digital world.

**Note:** Unlike Bitcoin and Ethereum, some blockchains restrict who can use and verify them.  These are "private blockchains", but they're largely irrelevant at a civilizational scale, because they ultimately rely on a small group of people who operate behind closed doors.  In this doc, "blockchain" is shorthand for "public blockchain".

#### How
The responsibility of verifying and updating a digital ledger doesn't disappear with blockchains: it moves from a single actor to thousands of independent ones.  Anyone with a computer and an internet connection can take part in this responsibility by operating a *node*. Each node within a blockchain runs a piece of software that automatically enforces the blockchain's governing ruleset, or *protocol*.

Nodes must (i) store their own copy of the ledger, (ii) independently verify that the information within their copy is sound, and (iii) communicate with other nodes to make sure everyone's ledger stores the exact same set of information — they must come to *consensus* about the state of the ledger.

When a blockchain is operating smoothly, the nodes within its network are in sync with one another and are constantly processing new information, creating a coherent digital ledger that's simultaneously held and used by tons of individuals around the world.

A blockchain's protocol is necessarily open-source: anyone can read the rules that dictate how information is processed and added to the ledger.  A blockchain is necessarily open to public participation: anyone can run the software that implements the protocol to independently verify the ledger is sound.

**This combination of properties gives digital sovereignty over organizing information back to the individual.**

### Transactions, Blocks, and The Blockchain
A blockchain's users coordinate with one another by creating transactions that update its shared ledger.  Transactions must follow rules defined by the protocol and are always grounded in the reality of the ledger's current state. For example, Alice can send Bob 1 BTC *if* the ledger says she has at least 1 BTC at the time of her request.

To create a transaction, a user must first send a transaction request to nodes in the network.  These nodes each verify the request follows protocol rules, then spread it to others who do the same.  The process repeats until the pending request has been distributed throughout the network.

Transaction requests need to be ordered and applied to the ledger in a systematic way.  But there's no central operator, so **who's responsible for updating the database?**  Every few seconds or minutes, a blockchain's protocol randomly selects one eligible node to propose an update to the ledger.

The proposer groups a batch of pending transactions together into a *block*.  A block carries a proposer's three explicit claims: (i) the ordering of the transaction requests they want to apply to the ledger, (ii) the previous block they're building their update upon (linking their block to the previous one), and (iii) an output stating how the applied transactions would affect the ledger.  Once created, the block is broadcasted throughout the network. 

Nodes independently check the proposer's work and communicate with one another to make sure everyone is on the same page.  Nodes ask "Should we accept or reject the proposer's block?"  If enough of the network agrees a proposer's update is valid, all nodes append the block to their copy of the ledger — they "add the block to the chain."

The blockchain itself is just a bunch of agreed-upon updates which each point to the one before it.  Pointing to a previous block forces every proposer to explicitly state what historical ledger they believe to be true: this is what enables the network to come to consensus on a single history at all.

**Note:** A blockchain, like any database or ledger, is a [state machine](https://en.wikipedia.org/wiki/Finite-state_machine).  It's a system that keeps track of a current state (the ledger) by processing new inputs (a block) based on a specific set of rules (the protocol).

### An Asynchronous Network