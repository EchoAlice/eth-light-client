# AGENT_WORKFLOW.md
Workflow + boundaries for the OpenClaw agent ("Warner") working on this repository.

## Goal
Help ship high-quality changes quickly:
- Agent does the implementation work (edits, tests, commits, pushes, PRs).
- Human owner reviews and merges on GitHub.

## Environment model (important)
This repo is typically worked on inside the OpenClaw gateway container:

- Container view (agent runtime):
  - Workspace root: `/home/node/.openclaw/workspace`
  - Repo path: `/home/node/.openclaw/workspace/projects/eth-light-client`

- Host view (VPS):
  - Workspace root: `/home/echo/.openclaw/workspace`
  - Repo path: `/home/echo/.openclaw/workspace/projects/eth-light-client`

These are the *same underlying files* via Docker volume mounts.

## Hard safety boundaries (non-negotiable)
The agent MUST:
- Stay inside this repo directory (and its workspace). Do not read/write outside.
- Never access secrets:
  - No touching `~/.ssh`, private keys, tokens, password managers, etc.
- Never change infrastructure unless explicitly instructed:
  - No Docker / compose edits, no system package upgrades, no firewall changes.
- Never run destructive / high-risk git operations without explicit approval:
  - No `git reset --hard`, `git rebase`, `git push --force`, `git clean -fdx`
  - No branch deletion, tag deletion, history rewrites.

If something requires any of the above, STOP and ask.

## Allowed actions (default permissions)
The agent MAY (without asking) do the following inside this repo:
- Edit code and docs
- Add/remove files as part of normal feature work
- Run local commands for verification:
  - `cargo fmt --all`
  - `cargo test`
  - `cargo clippy --all-features -- -D warnings`
  - `./scripts/warner-check.sh` (preferred)
- Create commits
- Push commits to the agent branch on GitHub
- Open or update a PR (draft is fine)

## Git workflow (branch + PR policy)
### Branch naming
All agent work goes on a dedicated branch, e.g.
- `warner/<topic>` (preferred)

### Keeping changes reviewable
- Prefer multiple small, logical commits instead of one massive commit.
- Separate concerns when possible:
  1) mechanical refactor / formatting
  2) behavior changes
  3) cleanup / docs

### No history rewriting
- Do NOT rebase or force-push.
- If commit cleanup is needed, ask first.

### PR policy
- Open a draft PR early for non-trivial work.
- Keep the PR description updated with:
  - what changed
  - why it changed
  - how it was tested
  - any follow-ups / TODOs

## Quality gates (required before “ready for review”)
Before marking a PR as ready:
1) Code formatted:
   - `cargo fmt --all`
2) Tests pass:
   - `cargo test`
3) Lints pass:
   - `cargo clippy --all-features -- -D warnings`

Preferred one-liner:
- `./scripts/warner-check.sh`

If checks fail:
- Fix them, or if blocked, document the failure clearly in the PR.

## “Large edits” policy (allowed, but structured)
Large changes are allowed if they’re organized:
- Make a short plan first (bullets in PR or commit message).
- Push early (draft PR) and update it as you go.
- Keep commits coherent and explain intent.

## Communication expectations
When starting a task, provide:
- a 3–7 bullet plan
- files likely to change
- definition of done

When finishing:
- summary of changes
- how to test
- risks / edge cases
- follow-ups if any

## “Stop and ask” triggers
The agent must stop and ask before:
- Any destructive git operation (reset/rebase/force-push/clean)
- Any access outside the repo/workspace
- Any interaction with secrets (`~/.ssh`, tokens, API keys)
- Any infrastructure changes (Docker, system packages, networking)
- Any change that affects security-critical behavior without an explicit request

---
Owner: Echo
Agent: Warner 🧭
