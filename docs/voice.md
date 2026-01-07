# Voice Input (Text Only)

Pumpkin v3 accepts text input over HTTP for future voice satellite integration.

## Endpoint
- POST `http://<host>:9000/voice`
- POST `http://<host>:9000/satellite/voice`
- JSON body:
  ```json
  {
    "text": "turn the lounge lamp on",
    "device_id": "optional",
    "confidence": 0.92,
    "satellite_id": "optional",
    "room": "optional"
  }
  ```

## Validation
- `text` is required
- max length 500 characters
- empty or non-JSON requests return HTTP 400

## Responses
- Success: `200` with `{ "event_id": <int> }`
- Error: `400` with `{ "error": "..." }`

## Examples
Supported request:
- Input: `{"text":"notify me when the backup finishes"}`
- Output: proposal with `notify.local` (approval required)

Ambiguous request:
- Input: `{"text":"help"}`
- Output: proposal asking for clarification

Unsupported request:
- Input: `{"text":"turn on the lounge lamp"}`
- Output: `capability.offer` + `module.install` (if a matching module exists)

## Satellite examples

Basic:
```
curl -sS -X POST http://192.168.1.157:9000/satellite/voice \
  -H "Content-Type: application/json" \
  -d '{"text":"turn the lounge lamp on"}'
```

With satellite metadata:
```
curl -sS -X POST http://192.168.1.157:9000/satellite/voice \
  -H "Content-Type: application/json" \
  -d '{"text":"turn the lounge lamp on","satellite_id":"pumpkin-sat-1","room":"kitchen"}'
```

## Security expectations
- Treat the endpoint as internal-only.
- Do not expose it publicly without network controls.
- No secrets are accepted in the payload.

## Wyoming readiness (no code yet)
- Wyoming satellites should POST the same payload shape to `/voice`.
- Satellites must not include audio data or tokens in the payload.
- Authentication/authorization should be handled by network policy or a reverse proxy.

## Governance
- Voice input creates `voice.command` events only.
- All actions still require propose → approve → act.
