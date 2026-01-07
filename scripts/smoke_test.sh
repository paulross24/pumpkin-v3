#!/usr/bin/env bash
set -euo pipefail

python3 -m pumpkin ops verify

if grep -q "not_listening" <(python3 - <<'PY'
import socket
try:
    sock = socket.create_connection(("127.0.0.1", 9000), timeout=1)
    sock.close()
    print("listening")
except Exception:
    print("not_listening")
PY
); then
  python3 -m pumpkin voice server >/tmp/pumpkin_voice_test.log 2>&1 &
  voice_pid=$!
  sleep 1
else
  voice_pid=""
fi

cleanup() {
  if [ -n "${voice_pid:-}" ]; then
    kill "$voice_pid" || true
  fi
}
trap cleanup EXIT

python3 - <<'PY'
import json
import urllib.request
payload = json.dumps({"text":"smoke test voice"}).encode("utf-8")
req = urllib.request.Request(
    "http://127.0.0.1:9000/voice",
    data=payload,
    method="POST",
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(req, timeout=2) as resp:
    print(resp.read().decode("utf-8"))
PY

python3 -m pumpkin daemon --once
python3 -m pumpkin proposals list | head -n 10

python3 - <<'PY'
from pumpkin import settings
from pumpkin.db import init_db
conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
row = conn.execute("SELECT id, ts FROM events WHERE source = 'voice' AND type = 'voice.command' ORDER BY id DESC LIMIT 1").fetchone()
if row:
    print(f"last voice.event: id={row['id']} ts={row['ts']}")
else:
    raise SystemExit(1)
PY
