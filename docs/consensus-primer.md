# Ethereum Consensus and Light Clients Primer (WIP)

Table of Contents:
1. Blockchains: ELI5
    - Why and How
    - Transactions and Blocks
    - Communication Over the Internet 
    - Conflicting Views and Consensus
    - Safety and Liveness
2. Ethereum Consensus
    - Overview 
    - Ethereum's Consensus Protocol - Gasper
    - Future Direction
3. Sharing Information within Ethereum
    - Signatures + Hashing
    - SSZ
4. Ethereum Light Clients
    - Sync Committees
    - Bootstrapping
    - Light Client Updates

------------------------------------------------
## 1. Blockchains: ELI5
#### Why
People coordinate with one another by sharing and acting upon information.  Throughout history, humanity has created new ways of representing and sharing information to coordinate more effectively.  In the 20th century, people created computers, which allow us to process and share vast amounts of digital information.  Almost all of humanity's organizing information now exists within this medium.

Money itself is one set of organizing information that's, for the most part, represented as digital information within authoritative computers' databases, or *digital ledgers*.  Historically, digital ledgers have been unilaterally controlled by small groups of people behind closed doors (e.g. the Federal Reserve's ledger).  Opaque, unilateral control of monetary information has led to problems, including the manipulation of our civilization's underlying monetary supply.  **Those who control a database hold sovereignty over the information inside.**

Satoshi changed this paradigm in 2009 by creating the first digital ledger that anyone could use and independently verify, and no one could unilaterally control: he created the first blockchain — Bitcoin.  Other projects, like Ethereum, have since iterated on this concept and expanded upon what kinds of information could exist and be processed within a blockchain.

The underlying ethos of these two blockchains (and many others) is the same: create a digital ledger that no one can gatekeep or taint to facilitate credibly neutral coordination throughout the digital world.

**Note:** Unlike Bitcoin and Ethereum, some blockchains restrict who can use and verify them.  These are "private blockchains", but they're largely irrelevant at a civilizational scale, because they ultimately rely on a small group of people who operate behind closed doors.  In this doc, "blockchain" is shorthand for "public blockchain".

#### How
The responsibility of control over a digital ledger doesn't disappear with blockchains: it moves from a single actor to thousands of independent ones.  Anyone with a computer and an internet connection can take part in upholding a blockchain's ledger by operating a *node*. 

Each node within a blockchain runs a piece of software that automatically enforces the blockchain's governing ruleset, or *protocol*.  The protocol defines how nodes (i) store their own copy of the ledger, (ii) independently verify that the information within their copy is sound, and (iii) communicate with other nodes to make sure everyone's copy of the ledger stores the exact same set of information.

When a blockchain is operating smoothly, the nodes within its network are in sync with one another and are constantly processing new information, creating a coherent digital ledger that's simultaneously held and used by tons of individuals around the world.

A blockchain's protocol is necessarily open-source: anyone can read the rules that dictate how information is processed and added to the ledger.  And a blockchain is necessarily open to public participation: anyone can run the software that implements the protocol to independently verify the ledger is adhering to its rules.  **This combination of properties gives digital sovereignty over organizing information back to the individual.**

### Transactions and Blocks
A blockchain's users coordinate with one another by creating transactions that update its shared ledger.  Transactions must follow the rules of the protocol and are always grounded in the reality of the ledger's current state. For example, Alice can send Bob 1 BTC *if* the ledger says she has at least 1 BTC to send.

To create a transaction, a user must first send a transaction request to nodes in the network.  These nodes each verify the request follows protocol rules, then spread it to others who do the same.  The process repeats until the pending request has been distributed throughout the network.

Transaction requests need to be ordered and applied to the ledger in a systematic way.  But there's no central operator, so **who's responsible for updating the database?**

Every few seconds or minutes, a blockchain's protocol randomly selects one eligible node to propose an update to the ledger.  This *proposer* groups a batch of pending transactions together into a *block*.  A block carries a proposer's three explicit claims: (i) the ordering of the transaction requests they want to apply to the ledger, (ii) the previous block they're building their update upon (linking their block to the previous one), and (iii) an output stating how the applied transactions would affect the ledger.

Once created, the block is broadcasted throughout the network and checked by other nodes.  If the block passes independent verification, a node appends it to their local copy of the ledger — or "adds the block to the chain".

### Communication Over the Internet
All nodes run a single, deterministic protocol: given the same input, every node computes the same output. But coming to agreement on one coherent ledger across a distributed network of thousands of computers is hard because **a node's inputs are nondeterministic**.

This is a function of blockchain networks operating on top of the internet.  Messages traveling over the internet typically take a few hundred milliseconds to land, but they could take a much longer time than that, or drop out completely.  Properties of uncertainty within the underlying communication channel permeate up the tech stack.

Tons of messages about proposed blocks and transaction requests (among other things) are constantly churning through a blockchain's network: it's every node's job to parse this flow of information. Because the delivery of messages varies between nodes, each node ends up with their own *view* of what information exists within the network.

### Conflicting Views and Consensus
Since the shared protocol is deterministic, differences in nodes' views are what lead individuals to believe in different versions of the ledger.  Theoretically, if nodes could wait long enough, they could all have the same information from the network to compute the same ledger.  But nodes can't wait around indefinitely before taking action — they have to make decisions within bounded time intervals for the ledger to keep progressing.

#### Forks
Sometimes nodes don't see others' newly proposed blocks by the time they're chosen to propose themselves.  This can cause a *fork*, where multiple proposers create blocks that name the same parent block.

Each block points to the one before it, so every proposed block commits to an entire history of blocks that reflects the proposer's view.  From the parent backwards, nodes agree on the same historical ledger; but from the conflicting blocks onward, the single ledger splits.  Divergent histories can compound as future proposers must choose between different branching chains to build upon.

None of these branches are necessarily wrong. Each could be a coherent ledger that different factions of the network believe is true. But if left unresolved, factions could only cooperate with others who hold the same version of record.

A blockchain aims to have one unified ledger, not tons of fragmented ledgers with some similar historical lineage: **coordination requires disparate parties to be on the *same page* about what version of the ledger is canonical.**

#### Fork-Choice
It's each node's job to help resolve otherwise compounding discrepancies by running the protocol's *fork-choice rule*.  Regardless of the specific rule, choosing between forks requires individuals to be able to make claims about what version of the ledger they believe is true, and interpret the weight of others' claims.

The "weight" of a claim is measured by how much economic value was committed to make it (electricity spent in Bitcoin; stake put up in Ethereum).  Economic weight turns costless assertions into meaningful commitments, which is essential in a network where anyone can join and make claims about the state of the ledger.

Nodes aren't attached to any specific chain: they are always listening for new information to update their view of the network. They don't just keep track of one ledger, they keep track of all possible ledgers they've heard of.  Individuals are constantly applying the fork-choice rule to reevaluate the economic weight that has accumulated throughout conflicting branches.  The branch a node perceives to have the most weight is the branch they believe is the true chain.

Blockchain protocols (i) reward those who propose blocks on the chain that ultimately "wins", and (ii) ensure a claim's weight is attatched to a single block.  The former encourages individuals to take their best guess, while the latter forces individuals to *actually* guess (instead of freely creating a block for multiple branching chains).  **This combination of mechanisms makes forks unstable.**

#### Consensus
