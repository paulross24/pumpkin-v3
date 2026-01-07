"""SQLite access and migration utilities."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def ensure_migrations_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        """
    )


def applied_migrations(conn: sqlite3.Connection) -> List[str]:
    rows = conn.execute("SELECT version FROM schema_migrations;").fetchall()
    return [row[0] for row in rows]


def migration_files(migrations_dir: str) -> List[Path]:
    path = Path(migrations_dir)
    files = sorted(p for p in path.glob("*.sql") if p.is_file())
    return files


def apply_migrations(conn: sqlite3.Connection, migrations_dir: str) -> List[str]:
    ensure_migrations_table(conn)
    applied = set(applied_migrations(conn))
    files = migration_files(migrations_dir)
    applied_now: List[str] = []

    for file_path in files:
        version = file_path.name
        if version in applied:
            continue
        sql = file_path.read_text(encoding="utf-8")
        conn.executescript(sql)
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
            (version, utc_now_iso()),
        )
        applied_now.append(version)

    if applied_now:
        conn.commit()
    return applied_now


def init_db(db_path: str, migrations_dir: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = connect(db_path)
    apply_migrations(conn, migrations_dir)
    return conn
