# Ticket: PR #10 Commit 2 — Rotate sync committees on finalized boundary (spec-aligned)

## Context
We already landed Commit 1 in this PR:
- `LightClientStore::finalized_sync_committee_period(spec)` exists (period derived from `store.finalized_header.slot`)
- `LightClientProcessor::current_period()` returns the finalized-derived period
- Tracker still has an internal counter, but it is no longer the canonical source of period for the public API

Now implement **Commit 2**: rotate committees only when the **finalized period advances**, not when the **attested** header is in period+1.

## Goal (spec alignment)
Match consensus-specs semantics:
- **Store period** is derived from `finalized_header.slot`.
- Committees rotate only when finalized crosses a period boundary **and** `next_sync_committee` is known.
- Still allow “learning next committee” from attested headers during the current period (existing behavior is fine; don’t redesign it).

## Constraints (non-negotiable)
- Keep changes minimal and reviewable.
- Do NOT refactor ownership/duplication between `SyncCommitteeTracker` and `LightClientStore` beyond what is required to implement finalized-boundary rotation.
- Do NOT rename public APIs or reorganize modules.
- No git history rewriting (no rebase/force-push).

## What to change (minimal-diff plan)
### 1) Locate current rotation trigger
Find where rotation is triggered today (it likely uses `update.attested_header.slot` and/or `SyncCommitteeTracker::should_advance_period`).

### 2) Change trigger to be finalized-derived
Replace/augment the trigger logic so that rotation happens only when:
- `let finalized_period = self.store.finalized_sync_committee_period(&self.chain_spec);`
- `let has_next = self.store.next_sync_committee.is_some();` (or equivalent “next known”)
- rotate when `finalized_period` has advanced relative to the currently-active committee period.

**Important:** Do NOT rotate solely because `period(update.attested_header.slot) == finalized_period + 1`.

### 3) Track “which period are we currently rotated to?”
You need some notion of the current active committee period to compare against `finalized_period`. Keep this minimal:
- EITHER continue using the tracker's internal counter as “active committee period” BUT ensure it is only advanced based on finalized advancement
- OR introduce a tiny field in the processor/store that represents “active committee period” (only if absolutely necessary)

Choose the smallest diff that:
- doesn’t change public API
- doesn’t require large refactors
- makes rotation keyed off finalized-derived period

### 4) Ensure store + tracker stay consistent at rotation point
When rotation happens, update both representations exactly as before:
- Tracker rotates `current_committee <- next_committee`
- Store rotates `current_sync_committee <- next_sync_committee`
- Consume `next_*` on rotation
- Set `state_changed = true` (if applicable)

## Tests (must add 1 targeted test)
Add **one** targeted unit test that would fail if rotation could happen based on attested period alone.

Test shape (conceptual):
- Start with:
  - finalized header still in period N
  - attested header in period N+1
  - `next_sync_committee` is known
- Process update(s) such that:
  - learning next is possible / signature verification passes (use existing helpers)
- Assert:
  - **no rotation happens** until finalized header moves to period N+1

This test should specifically guard against: “attested period+1 causes rotation early”.

(If easiest: construct store/tracker + call the specific rotation trigger function directly if one exists.)

## Definition of Done
- Behavior: rotation is keyed off `finalized_sync_committee_period`, not attested period
- Add the targeted test described above
- All gates pass:
  - `./scripts/warner-check.sh`
- Push commits to the existing PR branch for PR #10 (no new PR)

## Procedure
1) Create a short plan (3–7 bullets) in the PR as a comment or in the PR description update
2) Implement minimal changes
3) Add the test
4) Run `./scripts/warner-check.sh`
5) Commit(s) with clear messages (prefer 1 commit for behavior + test; avoid drive-by refactors)
6) Push to the PR branch and update PR body with:
   - what changed
   - why (spec alignment)
   - how tested

## Stop rule
If blocked after 3 attempts:
- Post a PR comment with logs + hypothesis + smallest proposed unblock step

