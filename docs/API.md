# Pumpkin API

## Auth
If `PUMPKIN_INGEST_KEY` is set, provide one of:
- `X-Pumpkin-Key: <key>`
- `Authorization: Bearer <key>`

## Health
`GET /health`

Returns `{status, metrics}`.

## Status
`GET /status`

Returns a real-time state snapshot:
- `heartbeat` timestamp
- `version`, `build_id`
- `health_score` (0-100)
- `recent_changes` (last 3 events)
- `pending_approvals` counts

## Ingest v1
`POST /ingest`

Body:
```json
{
  "schema_version": 1,
  "request_id": "uuid",
  "text": "...",
  "source": "app",
  "device": "...",
  "location": {
    "lat": 51.5,
    "lon": -0.1,
    "accuracy_m": 15
  }
}
```

Response:
```json
{
  "accepted": true,
  "request_id": "uuid",
  "received_at": "2026-01-01T00:00:00Z",
  "correlation_ids": {"event_id": 1234}
}
```

## Decisions
`GET /decisions?limit=20`

## Briefings
`GET /briefings?limit=20`

## Proposals
`GET /proposals?status=pending&limit=25`

Approve/Reject:
- `POST /proposals/approve` `{ "id": 123, "actor": "web", "reason": "..." }`
- `POST /proposals/reject` `{ "id": 123, "actor": "web", "reason": "..." }`

## Restricted Requests
`GET /restricted_requests?status=pending`

Approve/Deny:
- `POST /restricted/approve` `{ "id": 123 }`
- `POST /restricted/deny` `{ "id": 123 }`

## Autonomy Mode
`POST /autonomy/mode` `{ "mode": "observer|operator|steward" }`

## Demo Incidents
`POST /demo/incidents` `{ "type": "service_down", "target": "pumpkin-voice", "severity": "warn" }`
