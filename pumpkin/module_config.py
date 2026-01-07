"""Module configuration loading."""

from __future__ import annotations

from typing import Any, Dict

import yaml


def load_config(path: str) -> Dict[str, Any]:
    data = yaml.safe_load(open(path, "r", encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("modules config must be a mapping")
    if data.get("version") != 1:
        raise ValueError("modules config version must be 1")
    enabled = data.get("enabled", [])
    modules = data.get("modules", {})
    if not isinstance(enabled, list):
        raise ValueError("enabled must be a list")
    if not isinstance(modules, dict):
        raise ValueError("modules must be a mapping")
    return data
