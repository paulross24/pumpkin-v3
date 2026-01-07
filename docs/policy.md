# Policy and Boundaries

Pumpkin v3 uses a human-editable YAML policy file to define boundaries, approval requirements, and allowed actions.

## Principles
- Boundaries are explicit and inspectable.
- Actions are forbidden unless explicitly allowed.
- Auto-approval is disabled by default and must be explicitly enabled per action type.

## Policy fields (v0)
- `version`: policy schema version.
- `mode`: `strict` or `normal` (default: `strict`).
- `defaults.require_approval`: global default for actions.
- `auto_approve`: whitelist of action types and conditions (empty by default).
- `actions`: allowed action types and parameter schemas.

## Example
```yaml
version: 1
mode: strict
defaults:
  require_approval: true
auto_approve: []
actions:
  - action_type: notify.local
    params_schema:
      type: object
      properties:
        message: { type: string, maxLength: 2000 }
      required: [message]
```

## Notes
- Policy is the canonical source of truth and lives on disk as `policy.yaml`.
- The system records a policy hash with every proposal and action for traceability.

## Module proposals
- `module.install` proposals are informational only and require explicit approval.
- The module registry at `modules/registry.yaml` is the source of truth for allowed modules.
- Module install proposals must match the registry schema and include a rollback plan.
- Runbooks can be generated from module.install proposals and stored with the proposal.

## Example runbook (excerpt)
```
# Module Install Runbook: homeassistant.observer

## Overview
- Rationale: Enable richer context from Home Assistant.
- Description: Ingests state and event data from Home Assistant for richer context.
- Safety level: med
...
Manual step includes: Set PUMPKIN_HA_TOKEN as an environment variable.
```

## Commands
- View current policy: `python3 -m pumpkin policy current`
- Preview a proposal: `python3 -m pumpkin policy preview --proposal <id>`
- Diff a proposal: `python3 -m pumpkin policy diff --proposal <id>`
- Apply a policy change (requires approval): `python3 -m pumpkin policy apply --proposal <id> --actor <name> --reason "..."`
- Roll back to a backup (requires approval): `python3 -m pumpkin policy rollback --backup <path> --actor <name> --reason "..."`

## Examples
```
python3 -m pumpkin policy current
python3 -m pumpkin policy diff --proposal 15
python3 -m pumpkin proposals approve 15 --reason "safe change"
python3 -m pumpkin policy apply --proposal 15 --actor "rossp" --reason "safe change"
```
