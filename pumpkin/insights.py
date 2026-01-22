"""Heuristic insights and briefings."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import act
from . import module_config
from . import settings
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


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


def _minutes_since(ts: Optional[datetime]) -> Optional[float]:
    if not ts:
        return None
    now = datetime.now(timezone.utc)
    delta = now - ts
    return delta.total_seconds() / 60.0


def _entity_device_class(payload: Dict[str, Any]) -> Optional[str]:
    attrs = payload.get("attributes", {}) if isinstance(payload, dict) else {}
    if isinstance(attrs, dict):
        device_class = attrs.get("device_class")
        if isinstance(device_class, str) and device_class.strip():
            return device_class.strip()
    return None


def _entity_last_changed(payload: Dict[str, Any]) -> Optional[datetime]:
    if not isinstance(payload, dict):
        return None
    return _parse_timestamp(payload.get("last_changed") or payload.get("last_updated"))


def _open_contacts(entities: Dict[str, Dict[str, Any]]) -> List[Tuple[str, Optional[float]]]:
    open_items: List[Tuple[str, Optional[float]]] = []
    for entity_id, payload in entities.items():
        if not isinstance(entity_id, str) or not entity_id.startswith("binary_sensor."):
            continue
        device_class = _entity_device_class(payload)
        if device_class not in {"door", "window"}:
            continue
        state = payload.get("state")
        if state not in {"on", "open"}:
            continue
        minutes = _minutes_since(_entity_last_changed(payload))
        open_items.append((_friendly_name(entity_id, payload), minutes))
    return open_items


def _recent_motion(entities: Dict[str, Dict[str, Any]], window_minutes: int = 5) -> List[str]:
    triggered: List[str] = []
    for entity_id, payload in entities.items():
        if not isinstance(entity_id, str) or not entity_id.startswith("binary_sensor."):
            continue
        device_class = _entity_device_class(payload)
        if device_class != "motion":
            continue
        if payload.get("state") != "on":
            continue
        minutes = _minutes_since(_entity_last_changed(payload))
        if minutes is None or minutes <= window_minutes:
            triggered.append(_friendly_name(entity_id, payload))
    return triggered


def _load_insights_cfg() -> Dict[str, Any]:
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return {}
    try:
        config = module_config.load_config(str(config_path))
    except Exception:
        return {}
    module_cfg = config.get("modules", {}).get("insights", {})
    return module_cfg if isinstance(module_cfg, dict) else {}


def _auto_notify_types(cfg: Dict[str, Any]) -> List[str]:
    types = cfg.get("auto_notify_types")
    if isinstance(types, list):
        cleaned = [str(item).strip() for item in types if str(item).strip()]
        if cleaned:
            return cleaned
    return [
        "insight.new_device",
        "insight.inventory_change",
        "insight.face_alert",
        "insight.camera_issue",
    ]


def _auto_notify_min_minutes(cfg: Dict[str, Any]) -> int:
    try:
        return max(5, int(cfg.get("auto_notify_min_minutes", 30)))
    except Exception:
        return 30


def _insight_dedupe_minutes(cfg: Dict[str, Any]) -> int:
    try:
        return max(1, int(cfg.get("insight_dedupe_minutes", 10)))
    except Exception:
        return 10


def _insight_signature(insight: Dict[str, Any]) -> str:
    if not isinstance(insight, dict):
        return "invalid"
    parts = [
        str(insight.get("type") or ""),
        str(insight.get("title") or ""),
        str(insight.get("detail") or ""),
    ]
    return "|".join(part.strip() for part in parts if isinstance(part, str))


def _maybe_auto_notify(conn, insight: Dict[str, Any], cfg: Dict[str, Any]) -> None:
    if not isinstance(insight, dict):
        return
    insight_type = str(insight.get("type") or "")
    if not insight_type:
        return
    if insight_type not in _auto_notify_types(cfg):
        return
    min_minutes = _auto_notify_min_minutes(cfg)
    last_ts = store.get_memory(conn, f"insights.last_auto_notify.{insight_type}")
    if isinstance(last_ts, str):
        parsed = _parse_timestamp(last_ts)
        if parsed:
            delta = _minutes_since(parsed)
            if delta is not None and delta < min_minutes:
                return
    title = insight.get("title") or insight_type.replace("insight.", "").replace("_", " ")
    detail = insight.get("detail")
    message = f"{title}."
    if isinstance(detail, str) and detail.strip():
        message = f"{title}: {detail}"
    try:
        act.notify_local(message, str(settings.audit_path()))
        store.set_memory(conn, f"insights.last_auto_notify.{insight_type}", datetime.now(timezone.utc).isoformat())
    except Exception:
        pass


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
    cfg = _load_insights_cfg()
    try:
        door_open_warn_minutes = max(1, int(cfg.get("door_open_warn_minutes", 10)))
    except Exception:
        door_open_warn_minutes = 10
    try:
        lights_on_warn_minutes = max(5, int(cfg.get("lights_on_warn_minutes", 30)))
    except Exception:
        lights_on_warn_minutes = 30
    try:
        motion_recent_minutes = max(1, int(cfg.get("motion_recent_minutes", 5)))
    except Exception:
        motion_recent_minutes = 5
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
            open_contacts = _open_contacts(ha_entities)
            if open_contacts:
                names = [name for name, _minutes in open_contacts]
                insights.append(
                    {
                        "type": "insight.doors_open_empty",
                        "severity": "warn",
                        "title": "Doors or windows open with nobody home",
                        "detail": f"Open: {', '.join(names[:4])}.",
                    }
                )
            motion = _recent_motion(ha_entities, window_minutes=motion_recent_minutes)
            if motion:
                insights.append(
                    {
                        "type": "insight.motion_empty",
                        "severity": "warn",
                        "title": "Motion detected while nobody home",
                        "detail": f"Recent motion: {', '.join(motion[:4])}.",
                    }
                )
        open_contacts = _open_contacts(ha_entities)
        if open_contacts:
            long_open = [
                (name, minutes)
                for name, minutes in open_contacts
                if minutes is not None and minutes >= door_open_warn_minutes
            ]
            if long_open:
                sample = ", ".join(
                    f"{name} ({minutes:.0f}m)"
                    for name, minutes in long_open[:4]
                    if minutes is not None
                )
                insights.append(
                    {
                        "type": "insight.door_open_long",
                        "severity": "info",
                        "title": "Door or window left open",
                        "detail": f"Open for {door_open_warn_minutes}m+: {sample}.",
                    }
                )

        long_lights = []
        for entity_id, payload in ha_entities.items():
            if not isinstance(entity_id, str) or not entity_id.startswith("light."):
                continue
            if payload.get("state") != "on":
                continue
            minutes = _minutes_since(_entity_last_changed(payload))
            if minutes is not None and minutes >= lights_on_warn_minutes:
                long_lights.append((_friendly_name(entity_id, payload), minutes))
        if long_lights:
            sample = ", ".join(
                f"{name} ({minutes:.0f}m)" for name, minutes in long_lights[:4]
            )
            insights.append(
                {
                    "type": "insight.lights_on_long",
                    "severity": "info",
                    "title": "Lights left on for a while",
                    "detail": f"On for {lights_on_warn_minutes}m+: {sample}.",
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
    cfg = _load_insights_cfg()
    dedupe_minutes = _insight_dedupe_minutes(cfg)
    payloads = []
    for item in items:
        signature = _insight_signature(item)
        if signature:
            last_ts = store.get_memory(conn, f"insights.last_event.{signature}")
            if isinstance(last_ts, str):
                parsed = _parse_timestamp(last_ts)
                if parsed:
                    delta = _minutes_since(parsed)
                    if delta is not None and delta < dedupe_minutes:
                        continue
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
        if signature:
            store.set_memory(conn, f"insights.last_event.{signature}", datetime.now(timezone.utc).isoformat())
        _maybe_auto_notify(conn, event_payload, cfg)
    current = store.get_memory(conn, "insights.latest")
    if not isinstance(current, list):
        current = []
    current.extend(payloads)
    store.set_memory(conn, "insights.latest", current[-30:])


def filter_recent_insights(
    conn, insights: Iterable[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    items = [item for item in insights if isinstance(item, dict)]
    if not items:
        return []
    cfg = _load_insights_cfg()
    dedupe_minutes = _insight_dedupe_minutes(cfg)
    filtered: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    for item in items:
        signature = _insight_signature(item)
        if signature:
            last_ts = store.get_memory(conn, f"insights.last_event.{signature}")
            if isinstance(last_ts, str):
                parsed = _parse_timestamp(last_ts)
                if parsed:
                    delta = _minutes_since(parsed)
                    if delta is not None and delta < dedupe_minutes:
                        continue
            store.set_memory(conn, f"insights.last_event.{signature}", now)
        filtered.append(item)
    return filtered


def _should_brief(
    conn,
    in_quiet_hours: bool,
    briefing_time: str,
    memory_key: str,
) -> bool:
    if in_quiet_hours:
        return False
    last_date = store.get_memory(conn, memory_key)
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
    briefing_key: str = "daily",
) -> None:
    memory_key = f"insights.last_briefing_date.{briefing_key}"
    if not _should_brief(conn, in_quiet_hours, briefing_time, memory_key):
        return
    summary = build_briefing(ha_summary, system_snapshot, insights)
    ts = datetime.now().isoformat()
    store.set_memory(conn, memory_key, datetime.now().date().isoformat())
    store.set_memory(
        conn,
        "insights.last_briefing",
        {"ts": ts, "summary": summary, "count": len(insights), "type": briefing_key},
    )
    store.insert_event(
        conn,
        source="insight",
        event_type="insight.briefing",
        payload={"ts": ts, "summary": summary, "count": len(insights), "type": briefing_key},
        severity="info",
    )
    try:
        act.notify_local(f"Briefing: {summary}", str(settings.audit_path()))
    except Exception:
        pass


def briefing_times() -> List[str]:
    cfg = _load_insights_cfg()
    times = cfg.get("briefing_times")
    if isinstance(times, list):
        cleaned = [str(item).strip() for item in times if str(item).strip()]
        if cleaned:
            return cleaned
    return ["08:00", "20:00"]


def maybe_event_briefing(
    conn,
    ha_summary: Dict[str, Any],
    system_snapshot: Optional[Dict[str, Any]],
    insights: List[Dict[str, Any]],
    in_quiet_hours: bool,
) -> None:
    if in_quiet_hours:
        return
    cfg = _load_insights_cfg()
    try:
        min_minutes = max(5, int(cfg.get("event_briefing_min_minutes", 30)))
    except Exception:
        min_minutes = 30
    last_ts = store.get_memory(conn, "insights.last_event_briefing_ts")
    if isinstance(last_ts, str):
        try:
            parsed = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
        except Exception:
            parsed = None
        if parsed:
            now = datetime.now(timezone.utc)
            delta = (now - parsed).total_seconds() / 60.0
            if delta < min_minutes:
                return
    warn_insights = [
        item for item in insights
        if isinstance(item, dict) and item.get("severity") in {"warn", "error"}
    ]
    if not warn_insights:
        return
    summary = build_briefing(ha_summary, system_snapshot, warn_insights)
    ts = datetime.now(timezone.utc).isoformat()
    store.set_memory(conn, "insights.last_event_briefing_ts", ts)
    store.set_memory(
        conn,
        "insights.last_briefing",
        {"ts": ts, "summary": summary, "count": len(warn_insights), "type": "event"},
    )
    store.insert_event(
        conn,
        source="insight",
        event_type="insight.briefing",
        payload={"ts": ts, "summary": summary, "count": len(warn_insights), "type": "event"},
        severity="warn",
    )
    try:
        act.notify_local(f"Alert briefing: {summary}", str(settings.audit_path()))
    except Exception:
        pass


def build_event_insights(events: Iterable[Any]) -> List[Dict[str, Any]]:
    insights: List[Dict[str, Any]] = []
    for row in events:
        try:
            event_type = row["type"]
            payload_raw = row["payload_json"]
        except Exception:
            continue
        if not isinstance(event_type, str):
            continue
        if event_type.startswith("insight."):
            continue
        payload = None
        if isinstance(payload_raw, str):
            try:
                payload = json.loads(payload_raw)
            except Exception:
                payload = {}
        elif isinstance(payload_raw, dict):
            payload = payload_raw
        else:
            payload = {}
        if event_type == "face.alert":
            label = payload.get("label") if isinstance(payload, dict) else None
            title = "Unknown face detected"
            detail = f"Camera: {label}" if label else "Unknown face detected"
            insights.append(
                {
                    "type": "insight.face_alert",
                    "severity": "warn",
                    "title": title,
                    "detail": detail,
                }
            )
        elif event_type in {"camera.capture_failed", "camera.stream_missing"}:
            camera_id = payload.get("camera_id") if isinstance(payload, dict) else None
            title = "Camera capture issue"
            detail = f"Camera {camera_id} reported {event_type.replace('.', ' ')}." if camera_id else "Camera capture issue detected."
            insights.append(
                {
                    "type": "insight.camera_issue",
                    "severity": "warn",
                    "title": title,
                    "detail": detail,
                }
            )
        elif event_type == "inventory.changed":
            summary = payload.get("summary") if isinstance(payload, dict) else {}
            if isinstance(summary, dict):
                areas = summary.get("ha_area_count")
                devices = summary.get("network_device_count")
                modules = summary.get("enabled_modules")
                detail_parts = []
                if isinstance(areas, int):
                    detail_parts.append(f"areas {areas}")
                if isinstance(devices, int):
                    detail_parts.append(f"devices {devices}")
                if isinstance(modules, list):
                    detail_parts.append(f"modules {len(modules)}")
                detail = "Inventory updated"
                if detail_parts:
                    detail = "Inventory updated: " + ", ".join(detail_parts) + "."
            else:
                detail = "Inventory updated."
            insights.append(
                {
                    "type": "insight.inventory_change",
                    "severity": "info",
                    "title": "Inventory changed",
                    "detail": detail,
                }
            )
    return insights
