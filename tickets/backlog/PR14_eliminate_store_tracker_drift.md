# PR14 — Eliminate Store/Tracker Drift (single source of truth for committees + period)

**Owner:** Echo  
**Agent:** Warner  
**Branch:** `warner/pr14-eliminate-store-tracker-drift`  
**Related:** PR #14 (to be opened)

## Context

Today, sync committee state is duplicated across:
- `LightClientStore` (current/next committees + headers)
- `SyncCommitteeTracker` (current/next committees + internal period counter)

We recently:
- made `LightClientProcessor::current_period()` finalized-derived
- rotated committees on finalized boundary
- added a guard to prevent learning “next committee” from next-period attestations when next is unknown

But there is still duplication: store committees and tracker committees can drift if one updates and the other doesn’t.

## Goal

Make it impossible (or very difficult) for `LightClientStore` and `SyncCommitteeTracker` to diverge on:
- current sync committee
- next sync committee
- active sync committee period

## Constraints / Non-goals (important)

- Do NOT change light-client validation rules, domain computation, committee selection rules, or merkle gindex logic.
- Do NOT introduce feature flags or “strict mode”.
- Keep diff reviewable: prefer 2–3 small commits.
- No large module reorgs. No public API changes unless absolutely necessary.

## Proposed approach (minimal diff)

Pick **one canonical owner** for committees (choose smallest viable):
- Preferred: `LightClientStore` is canonical for `current_sync_committee` / `next_sync_committee`.
- `SyncCommitteeTracker` should not silently diverge; either reference store, or be explicitly synced in one place.

Steps:
1) Ensure committee updates/rotations happen in ONE place in `apply_light_client_update`.
2) Add runtime invariant enforcement after successful apply:
   - store.current_sync_committee == tracker.current_committee
   - store.next_sync_committee == tracker.next_committee
   - If equality is hard, compare committee `hash_tree_root()`.
3) Add one targeted unit test that would have caught drift.

## Files likely to change
- `src/consensus/light_client.rs`
- `src/consensus/sync_committee.rs`
- `src/types/consensus.rs` (maybe)

## Definition of done
- [ ] `./scripts/warner-check.sh` passes
- [ ] Targeted drift-prevention test added
- [ ] PR description explains the chosen source of truth and how drift is prevented

## Stop rule
If blocked after **3 attempts**, stop and report logs + hypothesis + what was tried.
