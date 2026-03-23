## High-Level Design Rules for Agents

1. protocol/spec conformance is the highest priority
2. fork behavior must be spec-driven, not hardcoded ad hoc
3. avoid duplicate mutable sources of truth
4. validation before state mutation
5. public API should expose stable protocol-level concepts, not convenience internals
6. regression-prone bugs should get targeted tests