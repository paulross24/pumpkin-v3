"""Module catalog loading and summary helpers."""

from __future__ import annotations

from typing import Any, Dict, List

import yaml


def load_catalog(path: str) -> Dict[str, Any]:
    data = yaml.safe_load(open(path, "r", encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("catalog must be a mapping")
    if data.get("version") != 1:
        raise ValueError("catalog version must be 1")
    modules = data.get("modules", [])
    if not isinstance(modules, list):
        raise ValueError("modules must be a list")
    return data


def catalog_summary(catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    modules = catalog.get("modules", [])
    summary = []
    for module in modules:
        summary.append(
            {
                "name": module.get("name"),
                "type": module.get("type"),
                "description": module.get("description"),
                "safety_level": module.get("safety_level"),
                "status": module.get("status", "unknown"),
            }
        )
    return summary
