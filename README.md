# Pumpkin v3

Pumpkin v3 is a persistent, context-aware digital steward that observes, proposes, approves, acts, and records within explicit boundaries. It integrates Home Assistant, vision, network discovery, and mobile clients with a proposal-first workflow and auditable history.

## Mission
- Reduce fragility by surfacing issues early
- Assist with proposals before actions
- Keep boundaries explicit and human-adjustable
- Maintain durable history and traceability
- Make the system feel alive while remaining safe and reversible

## Core loop
1. Observe system context and events
2. Understand and update internal context
3. Propose candidate actions with rationale, risk, and expected outcome
4. Await approval (unless explicitly auto-approved)
5. Act within boundaries
6. Record outcomes and update history

## Components
- Core daemon: proposal engine, actions, memory, audits
- Voice server: REST API + UI pages + ingest endpoints
- UI: status, proposals, vision review, mic diagnostics, shopping list

## Key capabilities
- Home Assistant sync: entities, areas, persons, presence
- Network discovery + deep scan + RTSP probe
- Vision pipeline: snapshots, unknowns, recognition, CompreFace enroll
- Car telemetry ingestion and reporting
- Dog watch alerts (camera-based behavior alerts)
- Shopping list for suggested hardware, with mark acquired
- Proposal workflow with approvals and audit log

## Safety and guardrails
- Proposals are default; actions require approval
- Boundaries are enforced in code and policy
- All proposals/actions recorded with policy hash
- Audit logs are append-only JSONL
- Protected patch paths prevent auto-editing critical files

## Runtime
### Voice server
- `python3 -m pumpkin voice server`
- Binds to `PUMPKIN_VOICE_HOST` (default `0.0.0.0`) and `PUMPKIN_VOICE_PORT` (default `9000`)
- OpenAPI: `GET /openapi.json`

### Core daemon
- `python3 -m pumpkin daemon`
- SQLite store: `data/pumpkin.db`
- Audit log: `data/audit.jsonl`

### Systemd
- `sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin.service /etc/systemd/system/pumpkin.service`
- `sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin-voice.service /etc/systemd/system/pumpkin-voice.service`
- `sudo systemctl enable --now pumpkin.service pumpkin-voice.service`
- Optional watchdog timer: `pumpkin-core-watchdog.timer`

## Configuration
- `modules/config.yaml`: module settings and autonomy toggles
- `policy.yaml`: action boundaries and approval rules
- Secrets:
  - Home Assistant token via env (default `PUMPKIN_HA_TOKEN`)
  - CompreFace API key via env
  - OpenAI key stored in memory or `PUMPKIN_OPENAI_API_KEY`

## UI pages
- `/ui` main dashboard
- `/ui/proposals` proposals and approvals
- `/ui/vision` vision review + enroll + correction
- `/ui/mic` mic diagnostics and transcription
- `/ui/shopping` hardware suggestions and status

## Proposal management
- `python3 -m pumpkin proposals list`
- `python3 -m pumpkin proposals show <id>`
- `python3 -m pumpkin proposals approve <id> --reason "..."`
- `python3 -m pumpkin proposals reject <id> --reason "..."`
