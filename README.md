# Pumpkin v3

Pumpkin v3 is a persistent, context-aware digital steward designed to observe, understand, propose, approve, act, and record within explicit boundaries. It prioritizes safety, auditability, and long-term evolvability over cleverness.

## Mission
- Reduce fragility by surfacing issues early
- Assist with proposals before actions
- Keep boundaries explicit and human-adjustable
- Maintain durable history and traceability

## Core loop
1. Observe system context and events
2. Understand and update internal context
3. Propose candidate actions with rationale, risk, and expected outcome
4. Await explicit approval (unless explicitly auto-approved)
5. Act within boundaries
6. Record outcomes and update history

## Safety contract
- Proposals are default; actions require approval
- Boundaries are explicit in policy and enforced in code
- All proposals and actions are recorded with policy hash
- Audit logs are append-only JSONL
- Auto-approval is off by default and must be explicitly enabled per action type

## What Pumpkin Can and Cannot Do
- Can observe system status, accept text-only voice input, and generate proposals
- Can execute only `notify.local` after explicit approval
- Cannot run shell commands or execute arbitrary actions
- Cannot apply policy or module config changes without explicit approval
- Cannot store or log secrets; tokens are read from environment only

## How to run
### Voice intake server
- `python3 -m pumpkin voice server`
- Binds to `PUMPKIN_VOICE_HOST` (default `0.0.0.0`) and `PUMPKIN_VOICE_PORT` (default `9000`).
- Endpoints: `GET /health`, `GET /`, `GET /config`, `GET /openapi.json`, `POST /voice`, `POST /satellite/voice`, `POST /ingest`.

### Core daemon loop
- `python3 -m pumpkin run`
- Stores events, proposals, and actions in SQLite at `PUMPKIN_DB_PATH` (default `data/pumpkin.db`).

### Systemd (optional)
- `sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin.service /etc/systemd/system/pumpkin.service`
- `sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin-voice.service /etc/systemd/system/pumpkin-voice.service`
- `sudo systemctl enable --now pumpkin.service pumpkin-voice.service`

## How to inspect proposals
- `python3 -m pumpkin proposals list`
- `python3 -m pumpkin proposals show <id>`
- `python3 -m pumpkin proposals approve <id> --reason "..."`
- `python3 -m pumpkin proposals reject <id> --reason "..."`
