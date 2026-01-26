"""Append-only JSONL audit log utilities."""

from __future__ import annotations

import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import settings
from . import db
from . import store


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rotate_if_needed(path: str, max_bytes: int, keep: int) -> None:
    file_path = Path(path)
    if not file_path.exists():
        return
    if file_path.stat().st_size < max_bytes:
        return

    for idx in range(keep, 0, -1):
        src = file_path.with_suffix(file_path.suffix + f".{idx}")
        dst = file_path.with_suffix(file_path.suffix + f".{idx + 1}")
        if dst.exists():
            dst.unlink()
        if src.exists():
            src.replace(dst)

    rotated = file_path.with_suffix(file_path.suffix + ".1")
    if rotated.exists():
        rotated.unlink()
    file_path.replace(rotated)

    entry = {
        "ts": _utc_now_iso(),
        "kind": "audit.rotated",
        "previous_path": str(file_path),
        "rotated_path": str(rotated),
        "max_bytes": max_bytes,
        "keep": keep,
    }
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def append_jsonl(path: str, entry: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    _rotate_if_needed(path, settings.audit_max_bytes(), settings.audit_keep())
    entry = dict(entry)
    entry.setdefault("ts", _utc_now_iso())
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    try:
        conn = db.connect(str(settings.db_path()))
        store.insert_audit_log(conn, entry.get("kind", "audit"), entry)
        conn.close()
    except Exception:
        pass


def read_tail(path: str, limit: int = 100, kind: Optional[str] = None) -> List[Dict[str, Any]]:
    file_path = Path(path)
    if not file_path.exists():
        return []
    data = file_path.read_bytes()
    max_bytes = settings.audit_max_bytes()
    if len(data) > max_bytes:
        data = data[-max_bytes:]
    lines = data.decode("utf-8", errors="ignore").splitlines()
    entries: List[Dict[str, Any]] = []
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except Exception:
            continue
        if kind and entry.get("kind") != kind:
            continue
        entries.append(entry)
        if len(entries) >= limit:
            break
    return entries
