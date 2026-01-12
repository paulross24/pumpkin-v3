"""Database helpers for Pumpkin v3."""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, Iterable, List, Optional

from .db import utc_now_iso


def insert_event(
    conn: sqlite3.Connection,
    source: str,
    event_type: str,
    payload: Dict[str, Any],
    severity: str = "info",
    ts: Optional[str] = None,
) -> int:
    ts = ts or utc_now_iso()
    cur = conn.execute(
        """
        INSERT INTO events (ts, source, type, payload_json, severity)
        VALUES (?, ?, ?, ?, ?)
        """,
        (ts, source, event_type, json.dumps(payload, ensure_ascii=True), severity),
    )
    conn.commit()
    return int(cur.lastrowid)


def fetch_events_since(conn: sqlite3.Connection, last_id: int) -> List[sqlite3.Row]:
    rows = conn.execute(
        "SELECT * FROM events WHERE id > ? ORDER BY id ASC", (last_id,)
    ).fetchall()
    return rows


def list_events(
    conn: sqlite3.Connection,
    limit: int = 50,
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    since_id: Optional[int] = None,
) -> List[sqlite3.Row]:
    clauses = []
    params: List[Any] = []
    if source:
        clauses.append("source = ?")
        params.append(source)
    if event_type:
        clauses.append("type = ?")
        params.append(event_type)
    if since_id is not None:
        clauses.append("id > ?")
        params.append(int(since_id))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(int(limit))
    query = f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ?"
    return conn.execute(query, tuple(params)).fetchall()


def insert_proposal(
    conn: sqlite3.Connection,
    kind: str,
    summary: str,
    details: Dict[str, Any],
    risk: float,
    expected_outcome: str,
    status: str,
    policy_hash: str,
    needs_new_capability: bool = False,
    capability_request: Optional[str] = None,
    ai_context_hash: Optional[str] = None,
    ai_context_excerpt: Optional[str] = None,
    ts_created: Optional[str] = None,
    steps: Optional[List[str]] = None,
) -> int:
    ts_created = ts_created or utc_now_iso()
    details_payload = dict(details) if isinstance(details, dict) else {}
    if steps is not None:
        details_payload["steps"] = steps
    cur = conn.execute(
        """
        INSERT INTO proposals (
            ts_created, kind, summary, details_json, risk, expected_outcome, status, policy_hash,
            needs_new_capability, capability_request, ai_context_hash, ai_context_excerpt
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ts_created,
            kind,
            summary,
            json.dumps(details_payload, ensure_ascii=True),
            risk,
            expected_outcome,
            status,
            policy_hash,
            1 if needs_new_capability else 0,
            capability_request,
            ai_context_hash,
            ai_context_excerpt,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def update_proposal_details(conn: sqlite3.Connection, proposal_id: int, details: Dict[str, Any]) -> None:
    conn.execute(
        "UPDATE proposals SET details_json = ? WHERE id = ?",
        (json.dumps(details, ensure_ascii=True), proposal_id),
    )
    conn.commit()


def link_proposal_event(conn: sqlite3.Connection, proposal_id: int, event_id: int) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO proposal_events (proposal_id, event_id) VALUES (?, ?)",
        (proposal_id, event_id),
    )
    conn.commit()


def insert_approval(
    conn: sqlite3.Connection,
    proposal_id: int,
    actor: str,
    decision: str,
    reason: Optional[str],
    policy_hash: str,
    ts: Optional[str] = None,
) -> int:
    ts = ts or utc_now_iso()
    cur = conn.execute(
        """
        INSERT INTO approvals (proposal_id, ts, actor, decision, reason, policy_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (proposal_id, ts, actor, decision, reason, policy_hash),
    )
    conn.commit()
    return int(cur.lastrowid)


def update_proposal_status(conn: sqlite3.Connection, proposal_id: int, status: str) -> None:
    conn.execute("UPDATE proposals SET status = ? WHERE id = ?", (status, proposal_id))
    conn.commit()


def insert_action(
    conn: sqlite3.Connection,
    proposal_id: Optional[int],
    action_type: str,
    params: Dict[str, Any],
    status: str,
    policy_hash: str,
    ts_started: Optional[str] = None,
) -> int:
    ts_started = ts_started or utc_now_iso()
    cur = conn.execute(
        """
        INSERT INTO actions (proposal_id, ts_started, action_type, params_json, status, policy_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            proposal_id,
            ts_started,
            action_type,
            json.dumps(params, ensure_ascii=True),
            status,
            policy_hash,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def finish_action(
    conn: sqlite3.Connection,
    action_id: int,
    status: str,
    result: Optional[Dict[str, Any]] = None,
    ts_finished: Optional[str] = None,
) -> None:
    ts_finished = ts_finished or utc_now_iso()
    result_json = json.dumps(result, ensure_ascii=True) if result is not None else None
    conn.execute(
        """
        UPDATE actions
        SET ts_finished = ?, status = ?, result_json = ?
        WHERE id = ?
        """,
        (ts_finished, status, result_json, action_id),
    )
    conn.commit()


def get_memory(conn: sqlite3.Connection, key: str) -> Optional[Any]:
    row = conn.execute("SELECT value_json FROM memory WHERE key = ?", (key,)).fetchone()
    if not row:
        return None
    return json.loads(row[0])


def get_memory_all(conn: sqlite3.Connection) -> Dict[str, Any]:
    rows = conn.execute("SELECT key, value_json FROM memory").fetchall()
    data: Dict[str, Any] = {}
    for row in rows:
        data[row[0]] = json.loads(row[1])
    return data


def set_memory(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute(
        """
        INSERT INTO memory (key, value_json, ts_updated)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, ts_updated = excluded.ts_updated
        """,
        (key, json.dumps(value, ensure_ascii=True), utc_now_iso()),
    )
    conn.commit()


def list_proposals(
    conn: sqlite3.Connection, status: Optional[str] = None, limit: int = 50
) -> List[sqlite3.Row]:
    if status:
        return conn.execute(
            "SELECT * FROM proposals WHERE status = ? ORDER BY ts_created DESC LIMIT ?",
            (status, limit),
        ).fetchall()
    return conn.execute(
        "SELECT * FROM proposals ORDER BY ts_created DESC LIMIT ?", (limit,)
    ).fetchall()


def get_proposal(conn: sqlite3.Connection, proposal_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM proposals WHERE id = ?", (proposal_id,)).fetchone()


def get_proposal_events(conn: sqlite3.Connection, proposal_id: int) -> List[sqlite3.Row]:
    return conn.execute(
        """
        SELECT e.* FROM events e
        INNER JOIN proposal_events pe ON pe.event_id = e.id
        WHERE pe.proposal_id = ?
        ORDER BY e.id ASC
        """,
        (proposal_id,),
    ).fetchall()


def proposal_exists(conn: sqlite3.Connection, summary: str, statuses: Iterable[str]) -> bool:
    placeholders = ",".join("?" for _ in statuses)
    query = f"SELECT 1 FROM proposals WHERE summary = ? AND status IN ({placeholders}) LIMIT 1"
    params = [summary, *statuses]
    row = conn.execute(query, params).fetchone()
    return row is not None


def approval_exists(conn: sqlite3.Connection, proposal_id: int, decision: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM approvals WHERE proposal_id = ? AND decision = ? LIMIT 1",
        (proposal_id, decision),
    ).fetchone()
    return row is not None


def fetch_approved_unexecuted(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    return conn.execute(
        """
        SELECT p.* FROM proposals p
        WHERE p.status = 'approved'
          AND p.kind = 'action.request'
          AND p.id NOT IN (SELECT proposal_id FROM actions WHERE proposal_id IS NOT NULL)
        ORDER BY p.ts_created ASC
        """
    ).fetchall()


def latest_heartbeat(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM events WHERE type = 'heartbeat' ORDER BY id DESC LIMIT 1"
    ).fetchone()


def count_proposals_by_status(conn: sqlite3.Connection) -> Dict[str, int]:
    rows = conn.execute(
        "SELECT status, COUNT(*) as count FROM proposals GROUP BY status"
    ).fetchall()
    return {row[0]: int(row[1]) for row in rows}


def list_voice_events(conn: sqlite3.Connection, limit: int) -> List[sqlite3.Row]:
    return conn.execute(
        """
        SELECT * FROM events
        WHERE source = 'voice' AND type = 'voice.command'
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
