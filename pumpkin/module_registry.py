"""Module registry loading and validation."""

from __future__ import annotations

from typing import Any, Dict, List

import yaml


def load_registry(path: str) -> Dict[str, Any]:
    data = yaml.safe_load(open(path, "r", encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("registry must be a mapping")
    if data.get("version") != 1:
        raise ValueError("registry version must be 1")
    modules = data.get("modules", [])
    if not isinstance(modules, list):
        raise ValueError("modules must be a list")
    return data


def find_module(registry: Dict[str, Any], name: str) -> Dict[str, Any]:
    modules = registry.get("modules", [])
    for module in modules:
        if module.get("name") == name:
            return module
    raise ValueError(f"module not found: {name}")


def validate_config_schema(schema: Dict[str, Any], config: Dict[str, Any]) -> None:
    if schema.get("type") != "object":
        raise ValueError("config_schema.type must be 'object'")
    if not isinstance(config, dict):
        raise ValueError("config must be an object")

    properties = schema.get("properties", {})
    required = schema.get("required", [])

    if not isinstance(properties, dict) or not isinstance(required, list):
        raise ValueError("config_schema must define properties and required")

    for key in required:
        if key not in config:
            raise ValueError(f"missing required config key: {key}")

    for key, value in config.items():
        if key not in properties:
            raise ValueError(f"unexpected config key: {key}")
        rule = properties.get(key, {})
        expected_type = rule.get("type")
        if expected_type == "string":
            if not isinstance(value, str):
                raise ValueError(f"config {key} must be string")
        elif expected_type == "boolean":
            if not isinstance(value, bool):
                raise ValueError(f"config {key} must be boolean")
        elif expected_type == "integer":
            if not isinstance(value, int):
                raise ValueError(f"config {key} must be integer")
        elif expected_type == "number":
            if not isinstance(value, (int, float)):
                raise ValueError(f"config {key} must be number")
        elif expected_type is None:
            raise ValueError(f"config {key} missing type rule")
        else:
            raise ValueError(f"unsupported config type: {expected_type}")


def validate_module_install_details(
    registry: Dict[str, Any], details: Dict[str, Any]
) -> Dict[str, Any]:
    module_name = details.get("module_name")
    rationale = details.get("rationale")
    safety_level = details.get("safety_level")
    prerequisites = details.get("prerequisites")
    rollback_plan = details.get("rollback_plan")

    if not isinstance(module_name, str):
        raise ValueError("module_name must be string")
    if not isinstance(rationale, str):
        raise ValueError("rationale must be string")
    if safety_level not in {"low", "med", "high"}:
        raise ValueError("safety_level must be low/med/high")
    if not isinstance(prerequisites, dict):
        raise ValueError("prerequisites must be object")
    if not isinstance(rollback_plan, str):
        raise ValueError("rollback_plan must be string")

    module = find_module(registry, module_name)
    schema = module.get("config_schema", {"type": "object", "properties": {}, "required": []})
    config = details.get("config", {})
    if config is None:
        config = {}
    if isinstance(config, dict):
        for key in config.keys():
            if "token" in key and key != "token_env":
                raise ValueError("config must not include token fields; use token_env instead")
    validate_config_schema(schema, config)

    return module


def validate_module_enable_details(
    registry: Dict[str, Any], details: Dict[str, Any]
) -> Dict[str, Any]:
    module_name = details.get("module_name")
    if not isinstance(module_name, str):
        raise ValueError("module_name must be string")
    module = find_module(registry, module_name)
    config = details.get("config", {}) or {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object")
    for key in config.keys():
        if "token" in key and key != "token_env":
            raise ValueError("config must not include token fields; use token_env instead")
    schema = module.get("config_schema", {"type": "object", "properties": {}, "required": []})
    validate_config_schema(schema, config)
    return module


def registry_summary(registry: Dict[str, Any]) -> List[Dict[str, Any]]:
    modules = registry.get("modules", [])
    summary = []
    for module in modules:
        summary.append(
            {
                "name": module.get("name"),
                "type": module.get("type"),
                "description": module.get("description"),
                "safety_level": module.get("safety_level"),
            }
        )
    return summary
