"""Policy change proposal handling."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

from . import policy as policy_mod


DANGEROUS_ACTION_TYPES = {
    "shell.exec",
    "shell.command",
    "shell.run",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_text(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def _load_yaml(text: str) -> Dict[str, Any]:
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError("policy YAML must be a mapping")
    return data


def _action_types(policy_data: Dict[str, Any]) -> List[str]:
    actions = policy_data.get("actions", [])
    result = []
    for action in actions:
        action_type = action.get("action_type")
        if isinstance(action_type, str):
            result.append(action_type)
    return result


def lint_policy_change(
    current_policy_text: str,
    proposed_policy_text: str,
    proposal_details: Dict[str, Any],
) -> List[str]:
    errors: List[str] = []

    current_data = _load_yaml(current_policy_text)
    proposed_data = _load_yaml(proposed_policy_text)

    policy_mod.validate_policy(proposed_data)

    current_actions = set(_action_types(current_data))
    proposed_actions = set(_action_types(proposed_data))

    if any(action.startswith("shell.") for action in proposed_actions):
        errors.append("policy forbids shell.* action types")
    if DANGEROUS_ACTION_TYPES.intersection(proposed_actions):
        errors.append("policy forbids dangerous action types")

    allow_new_actions = bool(proposal_details.get("allow_new_actions"))
    new_actions = proposed_actions - current_actions
    if new_actions and not allow_new_actions:
        errors.append("new action_types require allow_new_actions in proposal details")

    mode = proposed_data.get("mode", "strict")
    auto_approve = proposed_data.get("auto_approve", [])
    allow_auto_approve = bool(
        proposal_details.get("allow_auto_approve_in_strict")
        or proposed_data.get("allow_auto_approve_in_strict")
    )
    if mode == "strict" and auto_approve and not allow_auto_approve:
        errors.append("auto_approve in strict mode requires allow_auto_approve_in_strict")

    return errors


def policy_diff(current_text: str, proposed_text: str) -> str:
    current_lines = current_text.splitlines(keepends=True)
    proposed_lines = proposed_text.splitlines(keepends=True)
    diff = difflib.unified_diff(
        current_lines,
        proposed_lines,
        fromfile="policy.yaml",
        tofile="proposal.yaml",
    )
    return "".join(diff)


def summarize_change(current_text: str, proposed_text: str) -> Dict[str, Any]:
    current_data = _load_yaml(current_text)
    proposed_data = _load_yaml(proposed_text)

    current_actions = set(_action_types(current_data))
    proposed_actions = set(_action_types(proposed_data))

    summary: Dict[str, Any] = {
        "action_types_added": sorted(proposed_actions - current_actions),
        "action_types_removed": sorted(current_actions - proposed_actions),
        "mode_changed": current_data.get("mode") != proposed_data.get("mode"),
        "mode_from": current_data.get("mode"),
        "mode_to": proposed_data.get("mode"),
        "auto_approve_count_from": len(current_data.get("auto_approve", []) or []),
        "auto_approve_count_to": len(proposed_data.get("auto_approve", []) or []),
        "require_approval_from": current_data.get("defaults", {}).get("require_approval"),
        "require_approval_to": proposed_data.get("defaults", {}).get("require_approval"),
    }
    return summary


def apply_policy_change(
    policy_path: str,
    proposed_policy_text: str,
) -> Tuple[str, str, str, str, str]:
    path = Path(policy_path)
    current_text = path.read_text(encoding="utf-8")
    proposed_text = proposed_policy_text

    diff_text = policy_diff(current_text, proposed_text)
    diff_hash = _hash_text(diff_text)

    current_hash = _hash_text(current_text)
    proposed_hash = _hash_text(proposed_text)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = f"{policy_path}.bak.{timestamp}"

    dir_path = path.parent
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=str(dir_path), delete=False
    ) as tmp:
        tmp.write(proposed_text)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name

    with open(backup_path, "w", encoding="utf-8") as backup:
        backup.write(current_text)
        backup.flush()
        os.fsync(backup.fileno())

    os.replace(tmp_path, policy_path)

    return current_hash, proposed_hash, diff_hash, backup_path, diff_text


def find_proposal_for_backup(audit_path: str, backup_path: str) -> int:
    with open(audit_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                record = json.loads(line)
            except Exception:
                continue
            if not isinstance(record, dict):
                continue
            if record.get("kind") == "policy.applied" and record.get("backup_path") == backup_path:
                proposal_id = record.get("proposal_id")
                if isinstance(proposal_id, int):
                    return proposal_id
    raise ValueError("no policy.applied record found for backup path")


def rollback_policy_change(
    policy_path: str,
    backup_path: str,
) -> Tuple[str, str, str, str, str]:
    path = Path(policy_path)
    current_text = path.read_text(encoding="utf-8")
    backup_text = Path(backup_path).read_text(encoding="utf-8")

    diff_text = policy_diff(current_text, backup_text)
    diff_hash = _hash_text(diff_text)
    current_hash = _hash_text(current_text)
    backup_hash = _hash_text(backup_text)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rollback_backup_path = f"{policy_path}.bak.rollback.{timestamp}"

    dir_path = path.parent
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=str(dir_path), delete=False
    ) as tmp:
        tmp.write(backup_text)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name

    with open(rollback_backup_path, "w", encoding="utf-8") as backup:
        backup.write(current_text)
        backup.flush()
        os.fsync(backup.fileno())

    os.replace(tmp_path, policy_path)

    return current_hash, backup_hash, diff_hash, rollback_backup_path, diff_text
