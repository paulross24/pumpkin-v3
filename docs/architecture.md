# Architecture (v0)

This document captures the minimal core design for Pumpkin v3.

## Goals
- Persistent, auditable stewardship
- Explicit boundaries and approvals
- Clear extensibility without rewrites

## Core components
- **Daemon (pumpkin-core)**: main loop; coordinates observe → understand → propose → approve → act → record.
- **DB layer**: SQLite for events, proposals, approvals, actions, and memory.
- **Policy engine**: parses `policy.yaml` and enforces boundaries.
- **CLI**: inspection, approvals, and manual observations.
- **Audit log**: append-only JSONL for grepping and backup.

## Storage
- SQLite is the source of truth.
- JSONL audit log mirrors key events and actions.

## Data model (initial)
- `events`: observations and system signals.
- `proposals`: candidate actions with rationale, risk, and expected outcome.
- `proposal_events`: join table linking proposals to source events.
- `approvals`: human or policy decisions.
- `actions`: execution records.
- `memory`: durable notes and facts.
- `policy_snapshots`: policy hash, path, excerpt, timestamp.

## Risk and status
- Risk is a float in the range 0.0 to 1.0.
- Proposal status enum: pending, approved, rejected, executed, failed, superseded.

## Boundaries
- Stored in `policy.yaml`.
- Default mode: strict.
- Auto-approve is empty unless explicitly configured.

## Action surface (v0)
- `notify.local`: write to JSONL and optionally stdout.
- `system.snapshot`: internal observation, not user-exposed as an action.

## Module registry
- Module metadata lives in `modules/registry.yaml`.
- Module proposals use `module.install` kind and are proposal-only.
- Registry entries define safety level, prerequisites, config schema, and provided signals.
- Runbooks can be generated for module.install proposals to guide manual installation.
- Module runtime config lives in `modules/config.yaml` and is applied manually.

## Future growth
- Add more actions behind explicit policy rules.
- Add optional API/UI once CLI workflow is stable.
- Add integration plugins (e.g., Home Assistant) as separate modules.
