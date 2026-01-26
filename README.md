# Pumpkin v3

Pumpkin v3 is a persistent, context-aware digital steward that observes, decides, acts within explicit boundaries, and records outcomes with an auditable trail. It integrates Home Assistant, vision, network discovery, and mobile clients with a proposal-first workflow.

## Mission
- Reduce fragility by surfacing issues early
- Keep boundaries explicit and human-adjustable
- Maintain durable history and traceability
- Make the system feel alive while remaining safe and reversible

## Closed-loop model
1. Observe system context and events
2. Detect interesting changes or anomalies
3. Decide next steps with reasoning
4. Execute low-risk actions or open approvals
5. Verify outcomes with evidence
6. Record results and brief

## Components
- Core daemon: observations, detections, decisions, actions, outcomes, briefings
- Voice server: REST API + UI pages + ingest endpoints
- UI: command center, decisions, briefings, proposals/approvals, audit, vision review, mic diagnostics, shopping list

## Key capabilities
- Home Assistant sync: entities, areas, persons, presence
- Network discovery + deep scan + RTSP probe
- Vision pipeline: snapshots, unknowns, recognition, CompreFace enroll, auto-tuned thresholds
- Car telemetry ingestion and reporting
- Dog watch alerts (camera-based behavior alerts)
- Shopping list for suggested hardware, with mark acquired
- Proposal workflow with approvals, follow-through queue, and audit log

## Autonomy modes and safety lanes
Autonomy is controlled by mode + policy lanes:
- Modes: `observer`, `operator`, `steward`
- Lanes:
  - Lane A: low-risk, reversible (auto)
  - Lane B: medium-risk (proposal)
  - Lane C: high-risk (restricted request)

These are enforced in `policy.yaml`. Safe mode can disable execution while keeping observation on.
Detection noise is reduced with suppression/backoff rules in `modules/config.yaml`.

## Runtime
### Voice server
- `python3 -m pumpkin voice server`
- Binds to `PUMPKIN_VOICE_HOST` (default `0.0.0.0`) and `PUMPKIN_VOICE_PORT` (default `9000`)
- OpenAPI: `GET /openapi.json`
- Status: `GET /status`
- Health: `GET /health`

### Core daemon
- `python3 -m pumpkin daemon`
- SQLite store: `data/pumpkin.db`
- Audit log: `data/audit.jsonl`

### Systemd
- `sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin.service /etc/systemd/system/pumpkin.service`
- `sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin-voice.service /etc/systemd/system/pumpkin-voice.service`
- `sudo systemctl enable --now pumpkin.service pumpkin-voice.service`
- Optional watchdog timer: `pumpkin-core-watchdog.timer`

## Data model (high-level)
Pumpkin records:
- Heartbeats
- Detections
- Decisions
- Actions/outcomes
- Proposals and restricted requests
- Briefings (hourly/daily)
- Audit log (append-only)

## Configuration
- `modules/config.yaml`: module settings and autonomy toggles
- `policy.yaml`: action boundaries and approval rules
- Secrets (env only, see `.env.example`):
  - `PUMPKIN_HA_TOKEN`
  - `PUMPKIN_COMPRE_FACE_KEY`
  - `PUMPKIN_OPENAI_API_KEY`
  - `PUMPKIN_INGEST_KEY`

## Status and ingest
- `GET /status` for the Command Center state snapshot

## Ingest v1
- Endpoint: `POST /ingest`
- Required fields: `schema_version: 1`, `request_id`
- Optional: `location`
- Response: `{accepted, request_id, received_at, correlation_ids}`
- Auth: `X-Pumpkin-Key` or `Authorization: Bearer` (when `PUMPKIN_INGEST_KEY` is set)

## UI pages
- `/ui` Command Center (health score, approvals, recent changes)
- `/ui/decisions` Decisions feed
- `/ui/briefings` Hourly and daily briefings
- `/ui/proposals` Proposals + restricted approvals
- `/ui/audit` Audit log feed
- `/ui/vision` Vision review + enroll + correction
- `/ui/mic` Mic diagnostics and transcription
- `/ui/shopping` Hardware suggestions and status

## Proposal management
- `python3 -m pumpkin proposals list`
- `python3 -m pumpkin proposals show <id>`
- `python3 -m pumpkin proposals approve <id> --reason "..."`
- `python3 -m pumpkin proposals reject <id> --reason "..."`
