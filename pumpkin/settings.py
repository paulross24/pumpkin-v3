"""Runtime settings and paths."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def data_dir() -> Path:
    root = repo_root()
    return Path(os.getenv("PUMPKIN_DATA_DIR", str(root / "data")))


def db_path() -> Path:
    return Path(os.getenv("PUMPKIN_DB_PATH", str(data_dir() / "pumpkin.db")))


def audit_path() -> Path:
    return Path(os.getenv("PUMPKIN_AUDIT_PATH", str(data_dir() / "audit.jsonl")))


def policy_path() -> Path:
    return Path(os.getenv("PUMPKIN_POLICY_PATH", str(repo_root() / "policy.yaml")))


def modules_registry_path() -> Path:
    return Path(
        os.getenv("PUMPKIN_MODULES_REGISTRY_PATH", str(repo_root() / "modules/registry.yaml"))
    )


def modules_catalog_path() -> Path:
    return Path(
        os.getenv("PUMPKIN_MODULES_CATALOG_PATH", str(repo_root() / "modules/catalog.yaml"))
    )


def code_assistant_roots() -> List[str]:
    raw = os.getenv("PUMPKIN_CODE_ASSISTANT_ROOTS")
    if raw:
        return [item.strip() for item in raw.split(",") if item.strip()]
    return [str(repo_root())]


def modules_config_path() -> Path:
    return Path(
        os.getenv("PUMPKIN_MODULES_CONFIG_PATH", str(repo_root() / "modules/config.yaml"))
    )


def ha_request_timeout_seconds() -> float:
    value = os.getenv("PUMPKIN_HA_TIMEOUT", "5")
    try:
        return max(1.0, float(value))
    except ValueError:
        return 5.0


def ha_error_cooldown_seconds() -> int:
    value = os.getenv("PUMPKIN_HA_ERROR_COOLDOWN", "600")
    try:
        return max(60, int(value))
    except ValueError:
        return 600


def voice_server_port() -> int:
    value = os.getenv("PUMPKIN_VOICE_PORT", "9000")
    try:
        return max(1, int(value))
    except ValueError:
        return 9000


def voice_server_host() -> str:
    return os.getenv("PUMPKIN_VOICE_HOST", "0.0.0.0")


def voice_event_limit() -> int:
    value = os.getenv("PUMPKIN_VOICE_EVENT_LIMIT", "10")
    try:
        return max(1, int(value))
    except ValueError:
        return 10


def voice_cooldown_seconds() -> int:
    value = os.getenv("PUMPKIN_VOICE_COOLDOWN", "5")
    try:
        return max(1, int(value))
    except ValueError:
        return 5


def audit_max_bytes() -> int:
    value = os.getenv("PUMPKIN_AUDIT_MAX_BYTES", str(50 * 1024 * 1024))
    try:
        return max(1024, int(value))
    except ValueError:
        return 50 * 1024 * 1024


def audit_keep() -> int:
    value = os.getenv("PUMPKIN_AUDIT_KEEP", "5")
    try:
        return max(1, int(value))
    except ValueError:
        return 5


def planner_timeout_seconds() -> int:
    value = os.getenv("PUMPKIN_PLANNER_TIMEOUT", "20")
    try:
        return max(1, int(value))
    except ValueError:
        return 20


def planner_retry_count() -> int:
    value = os.getenv("PUMPKIN_PLANNER_RETRY", "1")
    try:
        return max(0, int(value))
    except ValueError:
        return 1


def planner_cooldown_seconds() -> int:
    value = os.getenv("PUMPKIN_PLANNER_COOLDOWN_SECONDS", "120")
    try:
        return max(0, int(value))
    except ValueError:
        return 120


def planner_cooldown_max_seconds() -> int:
    value = os.getenv("PUMPKIN_PLANNER_COOLDOWN_MAX_SECONDS", "900")
    try:
        return max(60, int(value))
    except ValueError:
        return 900


def context_pack_max_bytes() -> int:
    value = os.getenv("PUMPKIN_CONTEXT_MAX_BYTES", str(200 * 1024))
    try:
        return max(1024, int(value))
    except ValueError:
        return 200 * 1024


def selfcheck_interval_seconds() -> int:
    value = os.getenv("PUMPKIN_SELFCHECK_INTERVAL_SECONDS", "900")
    try:
        return max(60, int(value))
    except ValueError:
        return 900


def loop_interval_seconds() -> float:
    value = os.getenv("PUMPKIN_LOOP_INTERVAL", "30")
    try:
        return float(value)
    except ValueError:
        return 30.0


def max_proposals_per_loop() -> int:
    value = os.getenv("PUMPKIN_MAX_PROPOSALS_PER_LOOP", "3")
    try:
        return max(1, int(value))
    except ValueError:
        return 3


def max_steps_per_proposal() -> int:
    value = os.getenv("PUMPKIN_MAX_STEPS_PER_PROPOSAL", "5")
    try:
        return max(1, int(value))
    except ValueError:
        return 5
