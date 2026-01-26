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


def insert_identity(conn: sqlite3.Connection, name: str, notes: Optional[str] = None) -> int:
    ts = utc_now_iso()
    cur = conn.execute(
        "INSERT INTO identity (ts_created, name, notes) VALUES (?, ?, ?)",
        (ts, name, notes),
    )
    conn.commit()
    return int(cur.lastrowid)


def latest_identity(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM identity ORDER BY id DESC LIMIT 1").fetchone()


def insert_heartbeat(
    conn: sqlite3.Connection, policy_hash: str, details: Optional[Dict[str, Any]] = None
) -> int:
    ts = utc_now_iso()
    details_json = json.dumps(details or {}, ensure_ascii=True)
    cur = conn.execute(
        "INSERT INTO heartbeats (ts, policy_hash, details_json) VALUES (?, ?, ?)",
        (ts, policy_hash, details_json),
    )
    conn.commit()
    return int(cur.lastrowid)


def latest_heartbeat(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM heartbeats ORDER BY id DESC LIMIT 1").fetchone()


def insert_detection(
    conn: sqlite3.Connection,
    source: str,
    detection_type: str,
    severity: str,
    summary: str,
    details: Dict[str, Any],
    event_id: Optional[int] = None,
    ts: Optional[str] = None,
) -> int:
    ts = ts or utc_now_iso()
    cur = conn.execute(
        """
        INSERT INTO detections (ts, source, detection_type, severity, summary, details_json, event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (ts, source, detection_type, severity, summary, json.dumps(details, ensure_ascii=True), event_id),
    )
    conn.commit()
    return int(cur.lastrowid)


def list_detections(conn: sqlite3.Connection, limit: int = 50) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM detections ORDER BY id DESC LIMIT ?", (int(limit),)
    ).fetchall()


def insert_decision(
    conn: sqlite3.Connection,
    detection_id: Optional[int],
    observation: str,
    reasoning: str,
    decision: str,
    action_type: Optional[str],
    action_id: Optional[int],
    proposal_id: Optional[int],
    restricted_id: Optional[int],
    verification_status: Optional[str],
    evidence: Optional[Dict[str, Any]],
    ts: Optional[str] = None,
) -> int:
    ts = ts or utc_now_iso()
    cur = conn.execute(
        """
        INSERT INTO decisions (
            ts, detection_id, observation, reasoning, decision, action_type, action_id,
            proposal_id, restricted_id, verification_status, evidence_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ts,
            detection_id,
            observation,
            reasoning,
            decision,
            action_type,
            action_id,
            proposal_id,
            restricted_id,
            verification_status,
            json.dumps(evidence or {}, ensure_ascii=True),
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def list_decisions(conn: sqlite3.Connection, limit: int = 50) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM decisions ORDER BY id DESC LIMIT ?", (int(limit),)
    ).fetchall()


def insert_outcome(
    conn: sqlite3.Connection, action_id: int, status: str, evidence: Dict[str, Any]
) -> int:
    ts = utc_now_iso()
    cur = conn.execute(
        "INSERT INTO outcomes (ts, action_id, status, evidence_json) VALUES (?, ?, ?, ?)",
        (ts, action_id, status, json.dumps(evidence, ensure_ascii=True)),
    )
    conn.commit()
    return int(cur.lastrowid)


def list_outcomes(conn: sqlite3.Connection, limit: int = 50) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM outcomes ORDER BY id DESC LIMIT ?", (int(limit),)
    ).fetchall()


def insert_restricted_request(
    conn: sqlite3.Connection,
    summary: str,
    details: Dict[str, Any],
    risk: float,
    expected_outcome: str,
    status: str,
    policy_hash: str,
    ts_created: Optional[str] = None,
) -> int:
    ts_created = ts_created or utc_now_iso()
    cur = conn.execute(
        """
        INSERT INTO restricted_requests (
            ts_created, summary, details_json, risk, expected_outcome, status, policy_hash
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ts_created,
            summary,
            json.dumps(details, ensure_ascii=True),
            risk,
            expected_outcome,
            status,
            policy_hash,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def update_restricted_request_status(conn: sqlite3.Connection, request_id: int, status: str) -> None:
    conn.execute(
        "UPDATE restricted_requests SET status = ? WHERE id = ?", (status, request_id)
    )
    conn.commit()


def list_restricted_requests(conn: sqlite3.Connection, status: Optional[str] = None) -> List[sqlite3.Row]:
    if status:
        return conn.execute(
            "SELECT * FROM restricted_requests WHERE status = ? ORDER BY id DESC", (status,)
        ).fetchall()
    return conn.execute(
        "SELECT * FROM restricted_requests ORDER BY id DESC"
    ).fetchall()


def insert_restricted_approval(
    conn: sqlite3.Connection,
    restricted_id: int,
    actor: str,
    decision: str,
    reason: Optional[str],
    policy_hash: str,
    ts: Optional[str] = None,
) -> int:
    ts = ts or utc_now_iso()
    cur = conn.execute(
        """
        INSERT INTO restricted_approvals (restricted_id, ts, actor, decision, reason, policy_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (restricted_id, ts, actor, decision, reason, policy_hash),
    )
    conn.commit()
    return int(cur.lastrowid)


def insert_briefing(
    conn: sqlite3.Connection, period: str, summary: str, details: Dict[str, Any]
) -> int:
    ts = utc_now_iso()
    cur = conn.execute(
        "INSERT INTO briefings (ts, period, summary, details_json) VALUES (?, ?, ?, ?)",
        (ts, period, summary, json.dumps(details, ensure_ascii=True)),
    )
    conn.commit()
    return int(cur.lastrowid)


def list_briefings(conn: sqlite3.Connection, limit: int = 50) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM briefings ORDER BY id DESC LIMIT ?", (int(limit),)
    ).fetchall()


def set_setting(conn: sqlite3.Connection, key: str, value: Any) -> None:
    ts = utc_now_iso()
    conn.execute(
        """
        INSERT INTO settings (key, value_json, ts_updated)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, ts_updated = excluded.ts_updated
        """,
        (key, json.dumps(value, ensure_ascii=True), ts),
    )
    conn.commit()


def get_setting(conn: sqlite3.Connection, key: str) -> Any:
    row = conn.execute("SELECT value_json FROM settings WHERE key = ?", (key,)).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["value_json"])
    except Exception:
        return None


def insert_audit_log(conn: sqlite3.Connection, kind: str, payload: Dict[str, Any]) -> int:
    ts = utc_now_iso()
    cur = conn.execute(
        "INSERT INTO audit_log (ts, kind, payload_json) VALUES (?, ?, ?)",
        (ts, kind, json.dumps(payload, ensure_ascii=True)),
    )
    conn.commit()
    return int(cur.lastrowid)


def list_audit_log(conn: sqlite3.Connection, limit: int = 50) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (int(limit),)
    ).fetchall()


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
    if status in {"rejected", "failed"}:
        row = conn.execute(
            "SELECT summary FROM proposals WHERE id = ?",
            (proposal_id,),
        ).fetchone()
        if row and row["summary"]:
            snooze_proposal_summary(conn, row["summary"], reason=status)
    if status == "approved":
        row = conn.execute(
            "SELECT summary FROM proposals WHERE id = ?",
            (proposal_id,),
        ).fetchone()
        if row and row["summary"]:
            conn.execute(
                """
                UPDATE proposals
                SET status = 'rejected'
                WHERE summary = ?
                  AND status = 'pending'
                  AND id != ?
                """,
                (row["summary"], proposal_id),
            )
            conn.commit()


def snooze_proposal_summary(
    conn: sqlite3.Connection, summary: str, reason: str, max_entries: int = 500
) -> None:
    if not isinstance(summary, str) or not summary.strip():
        return
    entries = get_memory(conn, "proposal.snoozed")
    if not isinstance(entries, list):
        entries = []
    kept = [item for item in entries if isinstance(item, dict) and item.get("summary") != summary]
    kept.append({"summary": summary, "ts": utc_now_iso(), "reason": reason})
    set_memory(conn, "proposal.snoozed", kept[-max_entries:])


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


def list_actions(conn: sqlite3.Connection, limit: int = 50) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM actions ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()


def list_approvals(conn: sqlite3.Connection, limit: int = 50) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM approvals ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()


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
    row = conn.execute(
        "SELECT * FROM heartbeats ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if row:
        return row
    return conn.execute(
        "SELECT * FROM events WHERE type = 'heartbeat' ORDER BY id DESC LIMIT 1"
    ).fetchone()


def count_proposals_by_status(conn: sqlite3.Connection) -> Dict[str, int]:
    rows = conn.execute(
        "SELECT status, COUNT(*) as count FROM proposals GROUP BY status"
    ).fetchall()
    return {row[0]: int(row[1]) for row in rows}


def count_restricted_by_status(conn: sqlite3.Connection) -> Dict[str, int]:
    rows = conn.execute(
        "SELECT status, COUNT(*) as count FROM restricted_requests GROUP BY status"
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
