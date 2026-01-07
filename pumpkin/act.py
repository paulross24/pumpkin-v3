"""Action execution."""

from __future__ import annotations

from typing import Any, Dict

from .audit import append_jsonl


def notify_local(message: str, audit_path: str) -> Dict[str, Any]:
    entry = {
        "kind": "notify.local",
        "message": message,
    }
    append_jsonl(audit_path, entry)
    print(f"[notify.local] {message}")
    return {"delivered": True}


def execute_action(
    action_type: str, params: Dict[str, Any], audit_path: str
) -> Dict[str, Any]:
    if action_type == "notify.local":
        return notify_local(params.get("message", ""), audit_path)
    raise ValueError(f"unsupported action_type: {action_type}")
