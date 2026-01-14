"""Heuristic insights and briefings."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import store


def _percentage(numerator: Optional[float], denominator: Optional[float]) -> Optional[float]:
    if numerator is None or denominator in (None, 0):
        return None
    try:
        return float(numerator) / float(denominator)
    except Exception:
        return None


def _friendly_name(entity_id: str, payload: Dict[str, Any]) -> str:
    attrs = payload.get("attributes", {}) if isinstance(payload, dict) else {}
    if isinstance(attrs, dict):
        name = attrs.get("friendly_name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    return entity_id


def _lights_on(entities: Dict[str, Dict[str, Any]]) -> List[str]:
    on: List[str] = []
    for entity_id, payload in entities.items():
        if not isinstance(entity_id, str) or not entity_id.startswith("light."):
            continue
        if payload.get("state") == "on":
            on.append(_friendly_name(entity_id, payload))
    return on


def _new_devices(
    current: Dict[str, Any], previous: Dict[str, Any]
) -> List[Dict[str, Any]]:
    current_devices = current.get("devices") if isinstance(current, dict) else None
    previous_devices = previous.get("devices") if isinstance(previous, dict) else None
    if not isinstance(current_devices, list):
        return []
    prev_ips = set()
    if isinstance(previous_devices, list):
        for item in previous_devices:
            if isinstance(item, dict) and isinstance(item.get("ip"), str):
                prev_ips.add(item["ip"])
    new_items = []
    for item in current_devices:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        if isinstance(ip, str) and ip not in prev_ips:
            new_items.append(item)
    return new_items


def build_insights(
    system_snapshot: Optional[Dict[str, Any]],
    ha_entities: Dict[str, Dict[str, Any]],
    ha_summary: Dict[str, Any],
    prev_entities: Dict[str, Dict[str, Any]],
    network_snapshot: Optional[Dict[str, Any]],
    prev_network_snapshot: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    insights: List[Dict[str, Any]] = []
    if isinstance(system_snapshot, dict):
        load1 = (system_snapshot.get("loadavg") or {}).get("1m")
        if isinstance(load1, (int, float)) and load1 >= 2.0:
            insights.append(
                {
                    "type": "insight.system_load",
                    "severity": "warn",
                    "title": "High CPU load",
                    "detail": f"1m load average is {load1:.2f}.",
                }
            )
        disk = system_snapshot.get("disk") if isinstance(system_snapshot.get("disk"), dict) else {}
        used_percent = disk.get("used_percent")
        if isinstance(used_percent, (int, float)) and used_percent >= 0.9:
            insights.append(
                {
                    "type": "insight.disk_usage",
                    "severity": "warn",
                    "title": "Disk nearly full",
                    "detail": f"Disk usage is {used_percent * 100:.1f}%.",
                }
            )
        mem = system_snapshot.get("meminfo_kb") if isinstance(system_snapshot.get("meminfo_kb"), dict) else {}
        mem_total = mem.get("MemTotal")
        mem_avail = mem.get("MemAvailable")
        mem_ratio = _percentage(mem_avail, mem_total)
        if mem_ratio is not None and mem_ratio <= 0.1:
            insights.append(
                {
                    "type": "insight.memory_pressure",
                    "severity": "warn",
                    "title": "Low available memory",
                    "detail": f"Available memory is {mem_ratio * 100:.1f}%.",
                }
            )

    if isinstance(ha_summary, dict):
        people_home = ha_summary.get("people_home") or []
        if not people_home:
            on_lights = _lights_on(ha_entities)
            if on_lights:
                insights.append(
                    {
                        "type": "insight.lights_on_empty",
                        "severity": "info",
                        "title": "Lights on with nobody home",
                        "detail": f"Lights on: {', '.join(on_lights[:4])}.",
                    }
                )

    new_devices = _new_devices(network_snapshot or {}, prev_network_snapshot or {})
    if new_devices:
        sample = ", ".join(
            item.get("ip", "unknown") for item in new_devices[:3] if isinstance(item, dict)
        )
        insights.append(
            {
                "type": "insight.new_device",
                "severity": "info",
                "title": "New device seen on network",
                "detail": f"New devices: {sample}.",
            }
        )

    return insights


def record_insights(conn, insights: Iterable[Dict[str, Any]]) -> None:
    items = [item for item in insights if isinstance(item, dict)]
    if not items:
        return
    now = datetime.now().isoformat()
    payloads = []
    for item in items:
        event_payload = dict(item)
        event_payload["ts"] = now
        payloads.append(event_payload)
        store.insert_event(
            conn,
            source="insight",
            event_type=item.get("type", "insight.generated"),
            payload=event_payload,
            severity=item.get("severity", "info"),
        )
    current = store.get_memory(conn, "insights.latest")
    if not isinstance(current, list):
        current = []
    current.extend(payloads)
    store.set_memory(conn, "insights.latest", current[-30:])


def _should_brief(
    conn,
    in_quiet_hours: bool,
    briefing_time: str,
) -> bool:
    if in_quiet_hours:
        return False
    last_date = store.get_memory(conn, "insights.last_briefing_date")
    today = datetime.now().date().isoformat()
    if last_date == today:
        return False
    try:
        hour, minute = [int(part) for part in briefing_time.split(":", 1)]
    except Exception:
        hour, minute = 8, 0
    now = datetime.now()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return now >= target


def build_briefing(
    ha_summary: Dict[str, Any],
    system_snapshot: Optional[Dict[str, Any]],
    insights: List[Dict[str, Any]],
) -> str:
    parts: List[str] = []
    people_home = ha_summary.get("people_home") or []
    if people_home:
        parts.append(f"People home: {', '.join(people_home)}.")
    else:
        parts.append("No one is marked as home.")
    if insights:
        top = "; ".join(item.get("title", "insight") for item in insights[:3])
        parts.append(f"Insights: {top}.")
    if isinstance(system_snapshot, dict):
        load1 = (system_snapshot.get("loadavg") or {}).get("1m")
        if isinstance(load1, (int, float)):
            parts.append(f"System load {load1:.2f}.")
    return " ".join(parts)


def maybe_daily_briefing(
    conn,
    ha_summary: Dict[str, Any],
    system_snapshot: Optional[Dict[str, Any]],
    insights: List[Dict[str, Any]],
    in_quiet_hours: bool,
    briefing_time: str = "08:00",
) -> None:
    if not _should_brief(conn, in_quiet_hours, briefing_time):
        return
    summary = build_briefing(ha_summary, system_snapshot, insights)
    ts = datetime.now().isoformat()
    store.set_memory(conn, "insights.last_briefing_date", datetime.now().date().isoformat())
    store.set_memory(
        conn,
        "insights.last_briefing",
        {"ts": ts, "summary": summary, "count": len(insights)},
    )
    store.insert_event(
        conn,
        source="insight",
        event_type="insight.briefing",
        payload={"ts": ts, "summary": summary, "count": len(insights)},
        severity="info",
    )
