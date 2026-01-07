#!/usr/bin/env python3
"""Regression check: voice event produces proposals without crashing."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.request


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(REPO_ROOT, "data", "pumpkin.db")


def _post_voice(port: int) -> int:
    payload = json.dumps({"text": "test"}).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/voice",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        raw = resp.read().decode("utf-8")
    decoded = json.loads(raw)
    return int(decoded["event_id"])


def _fetch_event_ts(conn: sqlite3.Connection, event_id: int) -> str:
    row = conn.execute("SELECT ts FROM events WHERE id = ?", (event_id,)).fetchone()
    if not row:
        raise RuntimeError("voice event not found in DB")
    return row[0]


def _fetch_newest_proposal(conn: sqlite3.Connection, ts: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM proposals WHERE ts_created > ? ORDER BY ts_created DESC LIMIT 1",
        (ts,),
    ).fetchone()


def main() -> int:
    port = int(os.getenv("PUMPKIN_REGRESS_VOICE_PORT", "9000"))
    server = subprocess.Popen(
        [sys.executable, "-m", "pumpkin", "voice", "server", "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.5)
        event_id = _post_voice(port)
        conn = sqlite3.connect(DB_PATH)
        event_ts = _fetch_event_ts(conn, event_id)
        result = subprocess.run(
            [sys.executable, "-m", "pumpkin", "daemon", "--once"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            sys.stderr.write(result.stderr)
            return 1
        conn.row_factory = sqlite3.Row
        proposal = _fetch_newest_proposal(conn, event_ts)
        if not proposal:
            sys.stderr.write("no new proposals created after voice event\n")
            return 1
        print(f"newest proposal: {proposal['kind']} - {proposal['summary']}")
        return 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=2)
        except subprocess.TimeoutExpired:
            server.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
