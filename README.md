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
- Camera recordings: rolling RTSP segments with retention and playback
- Live camera HLS: low-latency stream at `/camera/live`
- Car telemetry ingestion and reporting
- Dog watch alerts (camera-based behavior alerts)
- Shopping list for suggested hardware, with mark acquired
- Proposal workflow with approvals, follow-through queue, and audit log
- UI auto-curation: hides low-signal panels and keeps high-signal ones prominent, while preserving full access via menu
- Feedback loop: mark decisions/alerts as helpful or not to improve signal quality
- System goals: seeded objectives shown in settings to guide evolution
- Learning loop: feedback stats + distilled highlights + next-focus suggestions
- Capability map: consolidated view of HA domains, cameras, and network device counts
- Self model: live confidence, focus, and narrative of decisions

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
  - `PUMPKIN_LLM_PROVIDER` (openai|ollama)
  - `PUMPKIN_OLLAMA_URL` (e.g., http://127.0.0.1:11434)
  - `PUMPKIN_OLLAMA_MODEL` (e.g., llava) — vision descriptions
  - `PUMPKIN_OLLAMA_TEXT_MODEL` (e.g., llama3.1) — text reasoning/summaries
  - `PUMPKIN_OLLAMA_CODER_MODEL` (e.g., qwen2.5-coder) — local code generation
  - `PUMPKIN_LLM_CODER_MODEL` (override for any provider)
  - `PUMPKIN_INGEST_KEY`

## Memory
- Conversation memory: rolling summary + extracted facts per device/person
- Working memory: last 200 user/assistant turns stored in `llm.working_memory`
- LLM context includes last 50 working-memory entries for continuity

## Status and ingest
- `GET /status` for the Command Center state snapshot
- `GET /summary` for learning loop + capability map

## Ingest v1
- Endpoint: `POST /ingest`
- Required fields: `schema_version: 1`, `request_id`
- Optional: `location`
- Response: `{accepted, request_id, received_at, correlation_ids}`
- Auth: `X-Pumpkin-Key` or `Authorization: Bearer` (when `PUMPKIN_INGEST_KEY` is set)

## UI pages
- `/ui` Command Center (health score, approvals, recent changes)
  - Auto-curation hides low-signal panels but never removes them from the menu
- `/ui/decisions` Decisions feed
- `/ui/briefings` Hourly and daily briefings
- `/ui/proposals` Proposals + restricted approvals
- `/ui/audit` Audit log feed
- `/ui/settings` Autonomy + LLM configuration
- `/ui/settings` also displays system goals + learning loop stats
- Command Center includes Self Model card with confidence + narrative
- Decision cards include risk/confidence/reversibility scoring
- `/ui/vision` Vision review + enroll + correction
- `/ui/recordings` Camera recordings with playback
- `/ui/mic` Mic diagnostics and transcription
- `/ui/shopping` Hardware suggestions and status

## Proposal management
- `python3 -m pumpkin proposals list`
- `python3 -m pumpkin proposals show <id>`
- `python3 -m pumpkin proposals approve <id> --reason "..."`
- `python3 -m pumpkin proposals reject <id> --reason "..."`
