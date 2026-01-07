"""Module config change utilities."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple

import yaml

from . import module_registry


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_text(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def load_config_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def parse_config(text: str) -> Dict[str, Any]:
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError("modules config must be a mapping")
    if data.get("version") != 1:
        raise ValueError("modules config version must be 1")
    data.setdefault("enabled", [])
    data.setdefault("modules", {})
    if not isinstance(data["enabled"], list):
        raise ValueError("enabled must be a list")
    if not isinstance(data["modules"], dict):
        raise ValueError("modules must be a mapping")
    return data


def render_config(data: Dict[str, Any]) -> str:
    return yaml.safe_dump(data, sort_keys=False)


def diff_text(current_text: str, proposed_text: str) -> str:
    current_lines = current_text.splitlines(keepends=True)
    proposed_lines = proposed_text.splitlines(keepends=True)
    diff = difflib.unified_diff(
        current_lines, proposed_lines, fromfile="modules/config.yaml", tofile="proposal.yaml"
    )
    return "".join(diff)


def _validate_no_secrets(config: Dict[str, Any]) -> None:
    for key in config.keys():
        if "token" in key and key != "token_env":
            raise ValueError("config must not include token fields; use token_env instead")


def validate_enable_details(
    registry: Dict[str, Any], details: Dict[str, Any]
) -> Dict[str, Any]:
    module_name = details.get("module_name")
    if not isinstance(module_name, str):
        raise ValueError("module_name must be string")
    module = module_registry.find_module(registry, module_name)
    config = details.get("config", {}) or {}
    if not isinstance(config, dict):
        raise ValueError("config must be object")
    _validate_no_secrets(config)
    schema = module.get("config_schema", {"type": "object", "properties": {}, "required": []})
    module_registry.validate_config_schema(schema, config)
    return module


def validate_disable_details(registry: Dict[str, Any], details: Dict[str, Any]) -> Dict[str, Any]:
    module_name = details.get("module_name")
    if not isinstance(module_name, str):
        raise ValueError("module_name must be string")
    return module_registry.find_module(registry, module_name)


def build_proposed_config(
    current_text: str, proposal_kind: str, details: Dict[str, Any]
) -> str:
    data = parse_config(current_text)
    enabled = data.get("enabled", [])
    modules_cfg = data.get("modules", {})

    module_name = details.get("module_name")
    if proposal_kind == "module.enable":
        if module_name not in enabled:
            enabled.append(module_name)
        modules_cfg[module_name] = details.get("config", {}) or {}
    elif proposal_kind == "module.disable":
        enabled = [m for m in enabled if m != module_name]
        modules_cfg.pop(module_name, None)
    else:
        raise ValueError("unsupported proposal kind for config apply")

    data["enabled"] = enabled
    data["modules"] = modules_cfg
    return render_config(data)


def apply_module_config_change(
    config_path: str, proposed_text: str
) -> Tuple[str, str, str, str, str]:
    path = Path(config_path)
    current_text = path.read_text(encoding="utf-8")

    diff = diff_text(current_text, proposed_text)
    diff_hash = _hash_text(diff)
    old_hash = _hash_text(current_text)
    new_hash = _hash_text(proposed_text)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = f"{config_path}.bak.{timestamp}"

    dir_path = path.parent
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(dir_path), delete=False) as tmp:
        tmp.write(proposed_text)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name

    with open(backup_path, "w", encoding="utf-8") as backup:
        backup.write(current_text)
        backup.flush()
        os.fsync(backup.fileno())

    os.replace(tmp_path, config_path)

    return old_hash, new_hash, diff_hash, backup_path, diff


def rollback_module_config(
    config_path: str, backup_path: str
) -> Tuple[str, str, str, str, str]:
    path = Path(config_path)
    current_text = path.read_text(encoding="utf-8")
    backup_text = Path(backup_path).read_text(encoding="utf-8")

    diff = diff_text(current_text, backup_text)
    diff_hash = _hash_text(diff)
    old_hash = _hash_text(current_text)
    new_hash = _hash_text(backup_text)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rollback_backup_path = f"{config_path}.bak.rollback.{timestamp}"

    dir_path = path.parent
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(dir_path), delete=False) as tmp:
        tmp.write(backup_text)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name

    with open(rollback_backup_path, "w", encoding="utf-8") as backup:
        backup.write(current_text)
        backup.flush()
        os.fsync(backup.fileno())

    os.replace(tmp_path, config_path)

    return old_hash, new_hash, diff_hash, rollback_backup_path, diff


def find_proposal_for_backup(audit_path: str, backup_path: str) -> int:
    with open(audit_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                record = json.loads(line)
            except Exception:
                continue
            if not isinstance(record, dict):
                continue
            if record.get("kind") == "module.config_applied" and record.get("backup_path") == backup_path:
                proposal_id = record.get("proposal_id")
                if isinstance(proposal_id, int):
                    return proposal_id
    raise ValueError("no module.config_applied record found for backup path")
