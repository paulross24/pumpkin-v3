"""Capability snapshot helpers."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import act
from . import module_config
from . import module_registry
from . import policy as policy_mod
from . import settings
from . import store


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


def _device_registry(conn) -> Dict[str, Any]:
    snapshot = store.get_memory(conn, "network.discovery.snapshot") or {}
    useful = store.get_memory(conn, "network.discovery.useful") or []
    devices = snapshot.get("devices") if isinstance(snapshot, dict) else None
    useful_map: Dict[str, Dict[str, Any]] = {}
    if isinstance(useful, list):
        for item in useful:
            if isinstance(item, dict):
                ip = item.get("ip")
                if isinstance(ip, str) and ip.strip():
                    useful_map[ip.strip()] = item
    if not isinstance(devices, list):
        devices = []
    normalized = []
    for item in devices:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        if not isinstance(ip, str):
            continue
        hints = item.get("hints") if isinstance(item.get("hints"), list) else []
        services = item.get("services") if isinstance(item.get("services"), list) else []
        capabilities_list = [str(hint) for hint in hints if isinstance(hint, str)]
        useful_item = useful_map.get(ip)
        normalized.append(
            {
                "ip": ip,
                "mac": item.get("mac"),
                "device": item.get("device"),
                "open_ports": item.get("open_ports") if isinstance(item.get("open_ports"), list) else [],
                "services": services,
                "hints": capabilities_list,
                "useful": bool(useful_item),
                "label": useful_item.get("label") if isinstance(useful_item, dict) else None,
                "note": useful_item.get("note") if isinstance(useful_item, dict) else None,
            }
        )
    return {
        "device_count": len(normalized),
        "devices": normalized,
        "useful": list(useful_map.values()),
    }


def snapshot(conn: Optional[Any] = None) -> Dict[str, Any]:
    policy = policy_mod.load_policy(str(settings.policy_path()))
    registry = module_registry.load_registry(str(settings.modules_registry_path()))
    payload = {
        "policy": policy_mod.policy_summary(policy),
        "actions": _action_catalog(policy),
        "enabled_modules": _enabled_modules(),
        "registry": module_registry.registry_summary(registry, include_provides=True),
    }
    if conn is not None:
        payload["device_registry"] = _device_registry(conn)
    return payload
