"""Policy loading, validation, and evaluation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sqlite3

try:
    import yaml
except ImportError:  # pragma: no cover - will be handled by caller
    yaml = None  # type: ignore


@dataclass(frozen=True)
class Policy:
    data: Dict[str, Any]
    path: str
    policy_hash: str


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_policy(policy_path: str) -> Policy:
    if yaml is None:
        raise RuntimeError("PyYAML is required to load policy.yaml")

    path = Path(policy_path)
    text = path.read_text(encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    data = yaml.safe_load(text) or {}
    validate_policy(data)
    return Policy(data=data, path=str(path), policy_hash=f"sha256:{digest}")


def policy_excerpt(policy_path: str, max_bytes: int = 2048) -> str:
    path = Path(policy_path)
    data = path.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


def record_policy_snapshot(
    conn: sqlite3.Connection, policy: Policy, excerpt: Optional[str] = None
) -> None:
    if excerpt is None:
        excerpt = policy_excerpt(policy.path)
    conn.execute(
        """
        INSERT INTO policy_snapshots (ts, policy_hash, policy_path, policy_excerpt)
        VALUES (?, ?, ?, ?)
        """,
        (_utc_now_iso(), policy.policy_hash, policy.path, excerpt),
    )
    conn.commit()


def validate_policy(data: Dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise ValueError("policy must be a mapping")

    version = data.get("version")
    if version != 1:
        raise ValueError("policy version must be 1")

    mode = data.get("mode", "strict")
    if mode not in {"strict", "normal"}:
        raise ValueError("policy mode must be 'strict' or 'normal'")

    defaults = data.get("defaults", {})
    if not isinstance(defaults, dict):
        raise ValueError("defaults must be a mapping")

    if "require_approval" not in defaults or not isinstance(
        defaults.get("require_approval"), bool
    ):
        raise ValueError("defaults.require_approval must be boolean")

    approval = data.get("approval", {})
    if approval is not None:
        if not isinstance(approval, dict):
            raise ValueError("approval must be a mapping")
        max_auto = approval.get("max_auto_approve_risk")
        if max_auto is not None:
            if not isinstance(max_auto, (int, float)) or not (0.0 <= max_auto <= 1.0):
                raise ValueError("approval.max_auto_approve_risk must be 0.0-1.0")
        risky = approval.get("risky_action_types", [])
        if risky is not None:
            if not isinstance(risky, list) or not all(isinstance(x, str) for x in risky):
                raise ValueError("approval.risky_action_types must be a list of strings")
        for key in approval.keys():
            if key not in {"max_auto_approve_risk", "risky_action_types"}:
                raise ValueError(f"unsupported approval setting: {key}")

    auto_approve = data.get("auto_approve", [])
    if not isinstance(auto_approve, list):
        raise ValueError("auto_approve must be a list")

    for entry in auto_approve:
        if not isinstance(entry, dict):
            raise ValueError("auto_approve entries must be mappings")
        if "action_type" not in entry or not isinstance(entry["action_type"], str):
            raise ValueError("auto_approve.action_type must be string")
        conditions = entry.get("conditions", {})
        if not isinstance(conditions, dict):
            raise ValueError("auto_approve.conditions must be mapping if present")
        for key, value in conditions.items():
            if key == "max_risk":
                if not isinstance(value, (int, float)) or not (0.0 <= value <= 1.0):
                    raise ValueError("auto_approve.conditions.max_risk must be 0.0-1.0")
            else:
                raise ValueError(f"unsupported auto_approve condition: {key}")

    actions = data.get("actions", [])
    if not isinstance(actions, list):
        raise ValueError("actions must be a list")

    for action in actions:
        if not isinstance(action, dict):
            raise ValueError("action entries must be mappings")
        if "action_type" not in action or not isinstance(action["action_type"], str):
            raise ValueError("action.action_type must be string")
        schema = action.get("params_schema")
        if schema is None:
            raise ValueError("action.params_schema is required")
        if not isinstance(schema, dict):
            raise ValueError("action.params_schema must be mapping")
        if schema.get("type") != "object":
            raise ValueError("action.params_schema.type must be 'object'")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise ValueError("action.params_schema.properties must be mapping")
        required = schema.get("required", [])
        if not isinstance(required, list):
            raise ValueError("action.params_schema.required must be list")


def find_action_schema(policy: Policy, action_type: str) -> Dict[str, Any]:
    actions = policy.data.get("actions", [])
    for action in actions:
        if action.get("action_type") == action_type:
            return action.get("params_schema", {})
    raise ValueError(f"action_type not allowed: {action_type}")


def validate_params(schema: Dict[str, Any], params: Dict[str, Any]) -> None:
    if schema.get("type") != "object":
        raise ValueError("params_schema.type must be 'object'")
    if not isinstance(params, dict):
        raise ValueError("params must be an object")

    properties = schema.get("properties", {})
    required = schema.get("required", [])

    for key in required:
        if key not in params:
            raise ValueError(f"missing required param: {key}")

    for key, value in params.items():
        if key not in properties:
            raise ValueError(f"unexpected param: {key}")
        rules = properties.get(key, {})
        expected_type = rules.get("type")
        if expected_type == "string":
            if not isinstance(value, str):
                raise ValueError(f"param {key} must be string")
            max_len = rules.get("maxLength")
            if isinstance(max_len, int) and len(value) > max_len:
                raise ValueError(f"param {key} exceeds maxLength")
        elif expected_type == "number":
            if not isinstance(value, (int, float)):
                raise ValueError(f"param {key} must be number")
        elif expected_type == "integer":
            if not isinstance(value, int):
                raise ValueError(f"param {key} must be integer")
        elif expected_type == "boolean":
            if not isinstance(value, bool):
                raise ValueError(f"param {key} must be boolean")
        elif expected_type is None:
            raise ValueError(f"param {key} missing type rule")
        else:
            raise ValueError(f"unsupported param type: {expected_type}")


def evaluate_action(
    policy: Policy,
    action_type: str,
    params: Dict[str, Any],
    risk: Optional[float] = None,
) -> str:
    """Return one of: 'forbid', 'require_approval', 'auto_approve'."""

    schema = find_action_schema(policy, action_type)
    validate_params(schema, params)

    mode = policy.data.get("mode", "strict")
    defaults = policy.data.get("defaults", {})
    require_approval = defaults.get("require_approval", True)

    approval = policy.data.get("approval", {}) or {}
    risky_types = approval.get("risky_action_types", []) or []
    if action_type in risky_types:
        return "require_approval"

    auto_approve = policy.data.get("auto_approve", [])
    for entry in auto_approve:
        if entry.get("action_type") != action_type:
            continue
        conditions = entry.get("conditions", {})
        max_risk = conditions.get("max_risk")
        if max_risk is not None:
            if risk is None:
                continue
            if risk > max_risk:
                continue
        return "auto_approve"

    max_auto = approval.get("max_auto_approve_risk")
    if isinstance(max_auto, (int, float)):
        if risk is None:
            return "require_approval"
        if risk < float(max_auto):
            return "auto_approve"
        return "require_approval"

    if mode == "strict":
        return "require_approval"

    return "require_approval" if require_approval else "auto_approve"


def policy_summary(policy: Policy) -> Dict[str, Any]:
    return {
        "path": policy.path,
        "policy_hash": policy.policy_hash,
        "mode": policy.data.get("mode", "strict"),
        "action_types": [a.get("action_type") for a in policy.data.get("actions", [])],
        "auto_approve": policy.data.get("auto_approve", []),
        "approval": policy.data.get("approval", {}),
        "defaults": policy.data.get("defaults", {}),
    }
