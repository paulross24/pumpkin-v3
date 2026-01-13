"""Capability snapshot helpers."""

from __future__ import annotations

from typing import Any, Dict, List

from . import act
from . import module_config
from . import module_registry
from . import policy as policy_mod
from . import settings


def _enabled_modules() -> List[str]:
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return []
    try:
        config = module_config.load_config(str(config_path))
    except Exception:
        return []
    enabled = config.get("enabled", [])
    if not isinstance(enabled, list):
        return []
    return [name for name in enabled if isinstance(name, str)]


def _action_catalog(policy: policy_mod.Policy) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for entry in policy.data.get("actions", []) or []:
        action_type = entry.get("action_type")
        if not action_type:
            continue
        meta = act.ACTION_METADATA.get(action_type, {})
        items.append(
            {
                "action_type": action_type,
                "params_schema": entry.get("params_schema"),
                "description": meta.get("description"),
                "verification": meta.get("verification"),
                "rollback": meta.get("rollback"),
            }
        )
    return items


def snapshot() -> Dict[str, Any]:
    policy = policy_mod.load_policy(str(settings.policy_path()))
    registry = module_registry.load_registry(str(settings.modules_registry_path()))
    return {
        "policy": policy_mod.policy_summary(policy),
        "actions": _action_catalog(policy),
        "enabled_modules": _enabled_modules(),
        "registry": module_registry.registry_summary(registry, include_provides=True),
    }
