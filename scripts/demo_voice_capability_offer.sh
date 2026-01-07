#!/usr/bin/env bash
set -euo pipefail

python3 -m pumpkin voice send "turn on the lounge lamp" || true
python3 -m pumpkin daemon --once
python3 -m pumpkin proposals list | head -n 10
python3 - <<'PY'
from pumpkin import settings
from pumpkin.db import init_db

conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
row = conn.execute("SELECT id, summary FROM proposals WHERE kind = 'capability.offer' ORDER BY id DESC LIMIT 1").fetchone()
if row:
    print(f"capability.offer: id={row['id']} summary={row['summary']}")
else:
    print("capability.offer: none")
PY
