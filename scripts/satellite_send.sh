#!/usr/bin/env bash
set -euo pipefail

HOST=""
PORT="9000"
SATELLITE_ID=""
ROOM=""

usage() {
  echo "Usage: $0 --host <host> [--port <port>] [--sat <id>] [--room <room>] \"text here\"" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      HOST="${2:-}"
      shift 2
      ;;
    --port)
      PORT="${2:-}"
      shift 2
      ;;
    --sat)
      SATELLITE_ID="${2:-}"
      shift 2
      ;;
    --room)
      ROOM="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      ;;
    *)
      break
      ;;
  esac
done

TEXT="${*:-}"

if [[ -z "$HOST" || -z "$TEXT" ]]; then
  usage
fi

PAYLOAD="$(python3 - <<'PY'
import json
import os

payload = {"text": os.environ["TEXT"]}
sat = os.environ.get("SATELLITE_ID")
room = os.environ.get("ROOM")
if sat:
    payload["satellite_id"] = sat
if room:
    payload["room"] = room
print(json.dumps(payload, ensure_ascii=True))
PY
TEXT="$TEXT" SATELLITE_ID="$SATELLITE_ID" ROOM="$ROOM")"

curl --fail --show-error --silent \
  -X POST "http://${HOST}:${PORT}/satellite/voice" \
  -H "Content-Type: application/json" \
  -d "${PAYLOAD}"
