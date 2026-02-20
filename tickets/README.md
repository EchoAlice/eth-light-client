# Tickets

This directory is the task interface for Warner (OpenClaw agent) and for the repo owner.

## Directory layout

- `tickets/backlog/` — queued tasks not yet started
- `tickets/in_progress/` — active work
- `tickets/done/` — completed tasks (optional; can go straight to archive)
- `tickets/archive/` — completed + merged tasks

## Workflow

1. Create a new ticket in `tickets/backlog/`.
2. When starting work, move it to `tickets/in_progress/`.
3. When a PR is opened, add the PR number/link at the top of the ticket.
4. When merged, move the ticket to `tickets/archive/` as `DONE_<original_name>.md`.

Keep ticket updates small and mechanical; avoid mixing ticket churn with core logic changes.

## Naming convention

Use a sortable prefix and short slug, e.g.
- `TICKET_001_finalized_rotation_guard.md`
- `TICKET_002_eliminate_store_tracker_drift.md`

## Ticket template

Copy `tickets/_template.md` when creating a new ticket.
