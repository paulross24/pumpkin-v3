"""Inventory snapshot and opportunity helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

from . import capabilities
from . import store


def snapshot(conn) -> Dict[str, Any]:
    ha_summary = store.get_memory(conn, "homeassistant.summary") or {}
    ha_entities = store.get_memory(conn, "homeassistant.entities") or {}
    network_snapshot = store.get_memory(conn, "network.discovery.snapshot") or {}
    capability_snapshot = capabilities.snapshot(conn)

    domain_counts: Dict[str, int] = {}
    if isinstance(ha_summary, dict):
        domain_counts = ha_summary.get("counts_by_domain") or {}
    if not isinstance(domain_counts, dict):
        domain_counts = {}
    if not domain_counts and isinstance(ha_entities, dict):
        for entity_id in ha_entities.keys():
            if not isinstance(entity_id, str) or "." not in entity_id:
                continue
            domain = entity_id.split(".", 1)[0]
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

    areas = []
    area_names: Dict[str, str] = {}
    if isinstance(ha_summary, dict):
        areas = ha_summary.get("areas") or []
    if isinstance(areas, list):
        for area in areas:
            if isinstance(area, dict):
                area_id = area.get("area_id")
                name = area.get("name")
                if area_id and name:
                    area_names[area_id] = name
    area_counts: Dict[str, int] = {}
    if isinstance(ha_entities, dict):
        for entity_id, payload in ha_entities.items():
            if not isinstance(payload, dict):
                continue
            area_id = payload.get("area_id")
            if not area_id:
                continue
            name = area_names.get(area_id, area_id)
            area_counts[name] = area_counts.get(name, 0) + 1

    entities_by_domain: Dict[str, List[str]] = {}
    if isinstance(ha_entities, dict):
        for entity_id in ha_entities.keys():
            if not isinstance(entity_id, str) or "." not in entity_id:
                continue
            domain = entity_id.split(".", 1)[0]
            entities_by_domain.setdefault(domain, []).append(entity_id)
    for domain in list(entities_by_domain.keys()):
        entities_by_domain[domain] = sorted(entities_by_domain[domain])[:10]

    return {
        "homeassistant": {
            "domains": domain_counts,
            "areas": areas if isinstance(areas, list) else [],
            "area_entity_counts": area_counts,
            "people_home": ha_summary.get("people_home") if isinstance(ha_summary, dict) else [],
            "zones": ha_summary.get("zones") if isinstance(ha_summary, dict) else [],
            "calendars": ha_summary.get("calendars") if isinstance(ha_summary, dict) else [],
            "entities_by_domain": entities_by_domain,
        },
        "network": {
            "device_count": network_snapshot.get("device_count") if isinstance(network_snapshot, dict) else 0,
            "devices": network_snapshot.get("devices") if isinstance(network_snapshot, dict) else [],
            "ssdp": network_snapshot.get("ssdp") if isinstance(network_snapshot, dict) else [],
        },
        "capabilities": {
            "enabled_modules": capability_snapshot.get("enabled_modules", []),
            "actions": capability_snapshot.get("actions", []),
            "registry": capability_snapshot.get("registry", {}),
        },
    }


def opportunities(inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
    opportunities: List[Dict[str, Any]] = []
    ha = inventory.get("homeassistant", {}) if isinstance(inventory.get("homeassistant"), dict) else {}
    domain_counts = ha.get("domains", {}) if isinstance(ha.get("domains"), dict) else {}
    network = inventory.get("network", {}) if isinstance(inventory.get("network"), dict) else {}
    devices = network.get("devices") if isinstance(network.get("devices"), list) else []

    def add(title: str, why: str, example: str, source: str) -> None:
        opportunities.append({"title": title, "why": why, "example": example, "source": source})

    if domain_counts.get("light", 0) > 0:
        add(
            "Lighting scenes & area control",
            "Lights are available in Home Assistant.",
            "Create 'Downstairs off' and 'Movie mode' scenes.",
            "homeassistant",
        )
    if domain_counts.get("switch", 0) > 0:
        add(
            "Power cutoff routines",
            "Switch entities can be grouped by room or time.",
            "Turn off all kitchen plugs at night.",
            "homeassistant",
        )
    if domain_counts.get("climate", 0) > 0:
        add(
            "Comfort schedules",
            "Climate entities are available for automation.",
            "Warm the lounge before you get home.",
            "homeassistant",
        )
    if domain_counts.get("media_player", 0) > 0:
        add(
            "Media summaries & controls",
            "Media players can be queried and controlled.",
            "What's playing in the living room?",
            "homeassistant",
        )
    if domain_counts.get("camera", 0) > 0:
        add(
            "Camera snapshots on motion",
            "Camera devices are present.",
            "Send a snapshot when motion triggers.",
            "homeassistant",
        )
    if domain_counts.get("lock", 0) > 0 or domain_counts.get("cover", 0) > 0:
        add(
            "Door & cover status checks",
            "Locks/covers can be monitored for security.",
            "Tell me if any doors are unlocked.",
            "homeassistant",
        )
    if domain_counts.get("person", 0) > 0 or domain_counts.get("device_tracker", 0) > 0:
        add(
            "Presence-based automations",
            "Presence tracking is available.",
            "Turn on hallway lights when someone arrives.",
            "homeassistant",
        )
    calendars = ha.get("calendars") if isinstance(ha.get("calendars"), list) else []
    if calendars:
        add(
            "Daily agenda briefings",
            "Calendars are available for summaries.",
            "Give me a morning schedule overview.",
            "homeassistant",
        )
    hints: List[str] = []
    for device in devices:
        if isinstance(device, dict):
            hints.extend(device.get("hints") or [])
    hints = [hint for hint in hints if isinstance(hint, str)]
    if any("camera" in hint for hint in hints):
        add(
            "Network camera inventory",
            "Network discovery hints at camera devices.",
            "List discovered cameras and mark useful ones.",
            "network",
        )
    if any("speaker" in hint or "audio" in hint for hint in hints):
        add(
            "Whole-home audio control",
            "Network discovery hints at speakers.",
            "Play an announcement on all speakers.",
            "network",
        )
    if any("tv" in hint or "display" in hint for hint in hints):
        add(
            "TV/Display shortcuts",
            "Network discovery hints at TVs or displays.",
            "Turn on living room TV and switch input.",
            "network",
        )
    return opportunities[:10]


def summary(inventory: Dict[str, Any]) -> Dict[str, Any]:
    ha = inventory.get("homeassistant", {}) if isinstance(inventory.get("homeassistant"), dict) else {}
    network = inventory.get("network", {}) if isinstance(inventory.get("network"), dict) else {}
    caps = inventory.get("capabilities", {}) if isinstance(inventory.get("capabilities"), dict) else {}
    domains = ha.get("domains", {}) if isinstance(ha.get("domains"), dict) else {}
    areas = ha.get("areas") if isinstance(ha.get("areas"), list) else []
    enabled_modules = caps.get("enabled_modules") if isinstance(caps.get("enabled_modules"), list) else []
    return {
        "ha_domains": domains,
        "ha_area_count": len(areas),
        "network_device_count": network.get("device_count") if isinstance(network, dict) else 0,
        "enabled_modules": enabled_modules,
    }


def digest(inventory: Dict[str, Any], opportunities_list: List[Dict[str, Any]]) -> str:
    payload = {
        "summary": summary(inventory),
        "opportunities": [
            {
                "title": item.get("title"),
                "source": item.get("source"),
                "why": item.get("why"),
                "example": item.get("example"),
            }
            for item in opportunities_list
            if isinstance(item, dict)
        ],
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return f"sha256:{hashlib.sha256(raw.encode('utf-8')).hexdigest()}"
