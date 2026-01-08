"""Observation sources."""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import ha_client
from . import settings

def _read_meminfo() -> Dict[str, int]:
    data: Dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                key = parts[0].strip()
                value = parts[1].strip().split()[0]
                if value.isdigit():
                    data[key] = int(value)
    except FileNotFoundError:
        pass
    return data


def system_snapshot() -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    load1, load5, load15 = os.getloadavg()
    disk = shutil.disk_usage("/")
    disk_used_percent = disk.used / disk.total if disk.total else 0.0
    meminfo = _read_meminfo()

    payload = {
        "loadavg": {"1m": load1, "5m": load5, "15m": load15},
        "disk": {
            "path": "/",
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "free_bytes": disk.free,
            "used_percent": round(disk_used_percent, 4),
        },
        "meminfo_kb": {
            "MemTotal": meminfo.get("MemTotal"),
            "MemAvailable": meminfo.get("MemAvailable"),
        },
    }

    severity = "warn" if disk_used_percent >= 0.9 else "info"
    events.append(
        {
            "source": "system",
            "type": "system.snapshot",
            "payload": payload,
            "severity": severity,
        }
    )

    return events


_DEFAULT_ATTR_ALLOWLIST = [
    "friendly_name",
    "device_class",
    "unit_of_measurement",
    "icon",
    "battery_level",
    "latitude",
    "longitude",
    "radius",
    "passive",
    "temperature",
    "current_temperature",
    "humidity",
    "brightness",
    "hvac_mode",
    "hvac_action",
    "preset_mode",
]


def _normalize_attributes(attributes: Dict[str, Any], allowlist: Iterable[str]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    for key in allowlist:
        if key in attributes:
            normalized[key] = attributes[key]
    return normalized


def _filter_entity(
    entity_id: str,
    include_domains: Optional[Iterable[str]],
    include_entities: Optional[Iterable[str]],
    exclude_domains: Optional[Iterable[str]],
    exclude_entities: Optional[Iterable[str]],
) -> bool:
    domain = entity_id.split(".", 1)[0] if "." in entity_id else ""
    if exclude_entities and entity_id in exclude_entities:
        return False
    if exclude_domains and domain in exclude_domains:
        return False
    if include_entities and entity_id in include_entities:
        return True
    if include_domains:
        if "*" in include_domains:
            return True
        return domain in include_domains
    return True


def _summarize_states(states: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    home_people: List[str] = []
    people: List[Dict[str, Any]] = []
    zones: List[Dict[str, Any]] = []
    for entity_id, payload in states.items():
        domain = entity_id.split(".", 1)[0] if "." in entity_id else ""
        counts[domain] = counts.get(domain, 0) + 1
        if domain == "person":
            name = payload.get("attributes", {}).get("friendly_name") or entity_id
            if payload.get("state") == "home":
                home_people.append(str(name))
            people.append(
                {
                    "entity_id": entity_id,
                    "name": str(name),
                    "state": payload.get("state"),
                }
            )
        if domain == "zone":
            attributes = payload.get("attributes", {}) or {}
            name = attributes.get("friendly_name") or entity_id
            zones.append(
                {
                    "entity_id": entity_id,
                    "name": str(name),
                    "latitude": attributes.get("latitude"),
                    "longitude": attributes.get("longitude"),
                    "radius": attributes.get("radius"),
                    "passive": attributes.get("passive"),
                    "icon": attributes.get("icon"),
                }
            )
    return {
        "entity_count": len(states),
        "counts_by_domain": counts,
        "people_home": sorted(home_people),
        "people": sorted(people, key=lambda item: item.get("name", "")),
        "zones": sorted(zones, key=lambda item: item.get("name", "")),
    }


def _parse_datetime(value: str) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def _event_start(event: Dict[str, Any]) -> Optional[datetime]:
    start = event.get("start") or {}
    if isinstance(start, dict):
        value = start.get("dateTime") or start.get("date")
        return _parse_datetime(value) if value else None
    if isinstance(start, str):
        return _parse_datetime(start)
    return None


def homeassistant_snapshot(
    base_url: str,
    token: str,
    previous: Optional[Dict[str, Dict[str, Any]]] = None,
    include_domains: Optional[Iterable[str]] = None,
    include_entities: Optional[Iterable[str]] = None,
    exclude_domains: Optional[Iterable[str]] = None,
    exclude_entities: Optional[Iterable[str]] = None,
    attribute_allowlist: Optional[Iterable[str]] = None,
    calendar_enabled: bool = False,
    calendar_days_ahead: int = 7,
    calendar_limit: int = 10,
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    result = ha_client.fetch_status(
        base_url=base_url, token=token, timeout=settings.ha_request_timeout_seconds()
    )
    if result.get("ok"):
        events.append(
            {
                "source": "homeassistant",
                "type": "homeassistant.status",
                "payload": {"status": result.get("status")},
                "severity": "info",
            }
        )
    else:
        events.append(
            {
                "source": "homeassistant",
                "type": "homeassistant.request_failed",
                "payload": {"error": result.get("error")},
                "severity": "warn",
            }
        )
        return events, previous or {}, {}

    states_result = ha_client.fetch_states(
        base_url=base_url, token=token, timeout=settings.ha_request_timeout_seconds()
    )
    if not states_result.get("ok"):
        events.append(
            {
                "source": "homeassistant",
                "type": "homeassistant.states_failed",
                "payload": {"error": states_result.get("error")},
                "severity": "warn",
            }
        )
        return events, previous or {}, {}

    allowlist = list(attribute_allowlist or _DEFAULT_ATTR_ALLOWLIST)
    current: Dict[str, Dict[str, Any]] = {}
    for entity in states_result.get("states", []):
        entity_id = entity.get("entity_id")
        if not entity_id:
            continue
        if not _filter_entity(
            entity_id,
            include_domains=include_domains,
            include_entities=include_entities,
            exclude_domains=exclude_domains,
            exclude_entities=exclude_entities,
        ):
            continue
        attributes = entity.get("attributes", {}) or {}
        current[entity_id] = {
            "state": entity.get("state"),
            "attributes": _normalize_attributes(attributes, allowlist),
        }

    summary = _summarize_states(current)
    previous = previous or {}
    if not previous:
        events.append(
            {
                "source": "homeassistant",
                "type": "homeassistant.state_snapshot",
                "payload": {
                    "entity_count": summary.get("entity_count", 0),
                    "counts_by_domain": summary.get("counts_by_domain", {}),
                    "people_home": summary.get("people_home", []),
                },
                "severity": "info",
            }
        )
        return events, current, summary

    changes: List[Dict[str, Any]] = []
    for entity_id, payload in current.items():
        previous_payload = previous.get(entity_id)
        if previous_payload == payload:
            continue
        changes.append(
            {
                "entity_id": entity_id,
                "domain": entity_id.split(".", 1)[0],
                "old": previous_payload,
                "new": payload,
            }
        )
    if changes:
        events.append(
            {
                "source": "homeassistant",
                "type": "homeassistant.entity_changed",
                "payload": {"changes": changes[:200]},
                "severity": "info",
            }
        )
    if calendar_enabled:
        calendars_result = ha_client.fetch_calendars(
            base_url=base_url, token=token, timeout=settings.ha_request_timeout_seconds()
        )
        if calendars_result.get("ok"):
            calendars = []
            for item in calendars_result.get("calendars", []):
                if not isinstance(item, dict):
                    continue
                entity_id = item.get("entity_id")
                name = item.get("name") or entity_id
                if entity_id:
                    calendars.append({"entity_id": entity_id, "name": name})
            summary["calendars"] = calendars
            now = datetime.now(timezone.utc)
            end = now + timedelta(days=max(1, calendar_days_ahead))
            upcoming = []
            for cal in calendars:
                entity_id = cal.get("entity_id")
                if not entity_id:
                    continue
                result = ha_client.fetch_calendar_events(
                    base_url=base_url,
                    token=token,
                    entity_id=entity_id,
                    start=now.isoformat(),
                    end=end.isoformat(),
                    timeout=settings.ha_request_timeout_seconds(),
                )
                if not result.get("ok"):
                    continue
                for event in result.get("events", []):
                    if not isinstance(event, dict):
                        continue
                    upcoming.append(
                        {
                            "calendar": cal.get("name"),
                            "entity_id": entity_id,
                            "summary": event.get("summary"),
                            "start": event.get("start"),
                            "end": event.get("end"),
                            "location": event.get("location"),
                        }
                    )
            upcoming.sort(key=lambda item: _event_start(item) or datetime.max)
            summary["upcoming_events"] = upcoming[: max(1, calendar_limit)]
        else:
            events.append(
                {
                    "source": "homeassistant",
                    "type": "homeassistant.calendar_failed",
                    "payload": {"error": calendars_result.get("error")},
                    "severity": "warn",
                }
            )
    return events, current, summary
