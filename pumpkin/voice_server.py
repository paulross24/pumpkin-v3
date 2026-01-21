"""Voice text input HTTP server."""

from __future__ import annotations

import json
import hashlib
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from ipaddress import ip_address
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import difflib
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib.parse import parse_qs, quote, urlparse

from . import settings
from . import store
from . import module_config
from . import module_registry
from . import ha_client
from . import observe
from . import catalog as catalog_mod
from . import capabilities
from . import inventory as inventory_mod
from . import retrieval
from . import intent
from . import policy as policy_mod
from . import propose
from . import act
from . import vision
from . import telemetry
from .audit import append_jsonl
from .db import init_db, utc_now_iso


MAX_TEXT_LEN = 500
INGEST_LOG_TEXT_LIMIT = 160
OPENAI_TIMEOUT_SECONDS = 15
_ENV_PATH = Path("/etc/pumpkin/pumpkin.env")

THOUGHT_EVENT_TYPES = {
    "voice.command",
    "voice.reply",
    "voice.ask",
    "voice.ha_action",
    "profile.updated",
    "profile.linked",
    "memory.updated",
    "selfcheck.run",
    "selfcheck.failure",
    "selfheal.action",
    "network.discovery",
    "network.discovery.deep_scan",
    "car.alert",
    "face.alert",
    "insight.generated",
    "insight.briefing",
}

_DEEP_SCAN_LOCK = threading.Lock()
_DEEP_SCAN_RUNNING: set[str] = set()
_last_seen = {}
CODE_PROMPT_MAX_LEN = 8000


def _bad_request(handler: BaseHTTPRequestHandler, message: str) -> None:
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "voice.rejected",
            "reason": message,
        },
    )
    payload = json.dumps({"error": message}, ensure_ascii=True).encode("utf-8")
    handler.send_response(400)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def _send_json(handler: BaseHTTPRequestHandler, status: int, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _send_html(handler: BaseHTTPRequestHandler, status: int, body: str) -> None:
    data = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _update_env_file(updates: Dict[str, str]) -> bool:
    if not updates:
        return True
    try:
        _ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    lines: List[str] = []
    try:
        if _ENV_PATH.exists():
            lines = _ENV_PATH.read_text(encoding="utf-8").splitlines()
    except Exception:
        lines = []
    existing: set[str] = set()
    new_lines: List[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            new_lines.append(line)
            continue
        key_part = stripped
        if key_part.startswith("export "):
            key_part = key_part[len("export ") :].lstrip()
        key_name = key_part.split("=", 1)[0].strip()
        if key_name in updates:
            new_lines.append(f"{key_name}={updates[key_name]}")
            existing.add(key_name)
        else:
            new_lines.append(line)
    for key, value in updates.items():
        if key not in existing:
            new_lines.append(f"{key}={value}")
    try:
        _ENV_PATH.write_text("\n".join(new_lines).rstrip("\n") + "\n", encoding="utf-8")
        return True
    except Exception:
        return False


def _send_redirect(handler: BaseHTTPRequestHandler, location: str) -> None:
    body = f"Redirecting to {location}".encode("utf-8")
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _log_request(handler: BaseHTTPRequestHandler, status: int, payload: Dict[str, Any]) -> None:
    """Lightweight request log for observability."""
    method = getattr(handler, "command", "?")
    path = getattr(handler, "path", "?")
    # avoid large dumps; focus on the essentials
    summary = {
        "kind": "voice.http",
        "method": method,
        "path": path,
        "status": status,
        "payload_keys": sorted(payload.keys()),
    }
    try:
        append_jsonl(str(settings.audit_path()), summary)
    except Exception:
        # best-effort; don't block the request on logging failures
        pass


def _send_reply(handler: BaseHTTPRequestHandler, reply: str, notice: str | None) -> None:
    if notice:
        reply = f"{reply} {notice}"
    payload = {"status": "ok", "reply": reply}
    _send_json(handler, 200, payload)
    _log_request(handler, 200, payload)


def _append_recent_memory(conn, key: str, item: Dict[str, Any], limit: int = 25) -> None:
    current = store.get_memory(conn, key)
    if not isinstance(current, list):
        current = []
    current.append(item)
    store.set_memory(conn, key, current[-limit:])


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return False


def _store_async_result(
    conn,
    event_id: int,
    status: str,
    reply: str | None = None,
    route: str | None = None,
    error: str | None = None,
) -> None:
    payload: Dict[str, Any] = {
        "event_id": event_id,
        "status": status,
        "ts": datetime.now().isoformat(),
    }
    if reply is not None:
        payload["reply"] = reply
    if route is not None:
        payload["route"] = route
    if error is not None:
        payload["error"] = error
    store.set_memory(conn, f"voice.ask.result:{event_id}", payload)


def _record_reply_event(conn, payload: Dict[str, Any], reply: str, route: str) -> None:
    """Persist a reply for later analysis."""
    try:
        event_payload = {
            "text": payload.get("text"),
            "source": payload.get("source"),
            "device": payload.get("device"),
            "route": route,
            "reply": _truncate_text(reply, INGEST_LOG_TEXT_LIMIT),
        }
        store.insert_event(
            conn,
            source="voice",
            event_type="voice.reply",
            payload=event_payload,
            severity="info",
        )
        _append_recent_memory(
            conn,
            "voice.recent_replies",
            {
                "ts": datetime.now().isoformat(),
                "route": route,
                "text": _truncate_text(str(payload.get("text", "")), INGEST_LOG_TEXT_LIMIT),
                "reply": _truncate_text(reply, INGEST_LOG_TEXT_LIMIT),
            },
        )
    except Exception:
        # Do not break the response flow if logging fails.
        pass


def _finalize_reply_only(
    conn,
    payload: Dict[str, Any],
    reply: str,
    notice: str | None,
    route: str,
    memory_ctx: Dict[str, Any] | None = None,
) -> str:
    if notice:
        reply = f"{reply} {notice}"
    _record_reply_event(conn, payload, reply, route)
    if memory_ctx is None:
        memory_ctx = {}
    try:
        _update_conversation_memory(conn, payload, reply, memory_ctx)
    except Exception:
        pass
    return reply


def _reply_and_record(
    handler: BaseHTTPRequestHandler,
    conn,
    payload: Dict[str, Any],
    reply: str,
    notice: str | None,
    route: str,
    memory_ctx: Dict[str, Any] | None = None,
) -> None:
    _record_reply_event(conn, payload, reply, route)
    if memory_ctx is None:
        memory_ctx = {}
    try:
        _update_conversation_memory(conn, payload, reply, memory_ctx)
    except Exception:
        pass
    _send_reply(handler, reply, notice)


def _parse_json(body: bytes) -> Dict[str, Any]:
    try:
        return json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise ValueError("invalid JSON")


def _normalize_text(text: str) -> str:
    return " ".join(text.split())


def _truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _format_thought_message(event_type: str, payload: Dict[str, Any]) -> str:
    text = payload.get("text") if isinstance(payload, dict) else None
    reply = payload.get("reply") if isinstance(payload, dict) else None
    message = payload.get("message") if isinstance(payload, dict) else None
    summary = payload.get("summary") if isinstance(payload, dict) else None
    action = payload.get("action") if isinstance(payload, dict) else None
    title = payload.get("title") if isinstance(payload, dict) else None
    count = payload.get("device_count") if isinstance(payload, dict) else None
    target = payload.get("target") if isinstance(payload, dict) else None

    if event_type == "voice.command":
        return f"heard: {_truncate_text(str(text or 'voice command'), 80)}"
    if event_type == "voice.reply":
        return f"replied: {_truncate_text(str(reply or 'voice reply'), 80)}"
    if event_type == "voice.ask":
        return f"asked: {_truncate_text(str(text or 'question'), 80)}"
    if event_type == "voice.ha_action":
        return f"ha action: {_truncate_text(str(action or 'executed'), 80)}"
    if event_type == "profile.updated":
        return "profile updated"
    if event_type == "profile.linked":
        return "profile linked"
    if event_type == "memory.updated":
        return "memory updated"
    if event_type == "selfcheck.run":
        return "selfcheck run"
    if event_type == "selfcheck.failure":
        return f"selfcheck failed: {_truncate_text(str(summary or 'issue'), 80)}"
    if event_type == "selfheal.action":
        return f"self-heal: {_truncate_text(str(action or 'attempt'), 80)}"
    if event_type == "network.discovery":
        if count is not None:
            return f"network scan: {count} devices"
        return "network scan complete"
    if event_type == "network.discovery.deep_scan":
        return f"deep scan: {_truncate_text(str(target or 'host'), 80)}"
    if event_type == "car.alert":
        return f"car alert: {_truncate_text(str(message or 'check vehicle'), 80)}"
    if event_type == "face.alert":
        return f"vision alert: {_truncate_text(str(message or 'unknown face'), 80)}"
    if event_type.startswith("insight."):
        return f"insight: {_truncate_text(str(title or summary or event_type), 80)}"
    return _truncate_text(str(message or summary or event_type), 80)


def _collect_thoughts(conn: sqlite3.Connection, limit: int = 12) -> List[Dict[str, Any]]:
    rows = store.list_events(conn, limit=120)
    items: List[Dict[str, Any]] = []
    for row in rows:
        event_type = row["type"] or ""
        if event_type in THOUGHT_EVENT_TYPES or event_type.startswith("insight."):
            try:
                payload = json.loads(row["payload_json"])
            except Exception:
                payload = {}
            message = _format_thought_message(event_type, payload)
            items.append(
                {
                    "id": row["id"],
                    "ts": row["ts"],
                    "type": event_type,
                    "severity": row["severity"],
                    "message": message,
                }
            )
            if len(items) >= limit:
                break
    return items


def _conversation_key(device: str | None, profile: Dict[str, Any] | None) -> str | None:
    if isinstance(profile, dict):
        person_id = profile.get("ha_person_id")
        if isinstance(person_id, str) and person_id.strip():
            return f"memory.conversation.person:{person_id.strip()}"
        ha_user_id = profile.get("ha_user_id")
        if isinstance(ha_user_id, str) and ha_user_id.strip():
            return f"memory.conversation.user:{ha_user_id.strip()}"
    if isinstance(device, str) and device.strip():
        return f"memory.conversation.device:{device.strip()}"
    return None


def _load_conversation_memory(conn, key: str) -> Dict[str, Any]:
    data = store.get_memory(conn, key)
    if isinstance(data, dict):
        return data
    return {
        "summary": "",
        "facts": [],
        "recent": [],
        "last_summary_ts": 0.0,
        "turns": 0,
    }


def _store_conversation_memory(conn, key: str, memory: Dict[str, Any]) -> None:
    store.set_memory(conn, key, memory)


def _update_profile_activity(
    conn,
    device: str | None,
    user_text: str,
    reply: str,
) -> None:
    if not isinstance(device, str) or not device.strip():
        return
    key = f"speaker.profile.device:{device.strip()}"
    profile = store.get_memory(conn, key)
    if not isinstance(profile, dict):
        return
    profile["last_seen_ts"] = datetime.now(timezone.utc).isoformat()
    profile["last_text"] = _truncate_text(user_text, 160)
    profile["last_reply"] = _truncate_text(reply, 160)
    profile["last_device"] = device.strip()
    turns = profile.get("turns_count")
    try:
        turns = int(turns) if turns is not None else 0
    except (TypeError, ValueError):
        turns = 0
    profile["turns_count"] = turns + 1
    if not profile.get("created_ts"):
        profile["created_ts"] = profile["last_seen_ts"]
    store.set_memory(conn, key, profile)
    ha_user_id = profile.get("ha_user_id")
    if isinstance(ha_user_id, str) and ha_user_id.strip():
        user_profile = _load_ha_user_profile(conn, ha_user_id) or {}
        merged = _merge_profiles(user_profile, profile)
        merged["last_seen_ts"] = profile["last_seen_ts"]
        merged["last_text"] = profile.get("last_text")
        merged["last_reply"] = profile.get("last_reply")
        merged["last_device"] = profile.get("last_device")
        merged["turns_count"] = profile.get("turns_count")
        _save_ha_user_profile(conn, ha_user_id, merged)
    try:
        store.insert_event(
            conn,
            source="voice",
            event_type="profile.updated",
            payload={
                "device": device.strip(),
                "name": profile.get("name"),
                "turns_count": profile.get("turns_count"),
                "last_seen_ts": profile.get("last_seen_ts"),
            },
            severity="info",
        )
    except Exception:
        pass


def _apply_ha_identity(
    conn,
    device: str | None,
    ha_user_id: str | None,
    ha_user_name: str | None,
) -> None:
    if not isinstance(device, str) or not device.strip():
        return
    if not isinstance(ha_user_id, str) or not ha_user_id.strip():
        return
    key = f"speaker.profile.device:{device.strip()}"
    device_profile = store.get_memory(conn, key)
    if not isinstance(device_profile, dict):
        device_profile = {"state": "named"}
    user_profile = _load_ha_user_profile(conn, ha_user_id) or {}
    merged = _merge_profiles(user_profile, device_profile)
    merged["ha_user_id"] = ha_user_id.strip()
    if isinstance(ha_user_name, str) and ha_user_name.strip():
        merged["name"] = ha_user_name.strip()
    if not merged.get("created_ts"):
        merged["created_ts"] = datetime.now(timezone.utc).isoformat()
    merged["last_seen_ts"] = datetime.now(timezone.utc).isoformat()
    merged["last_device"] = device.strip()
    store.set_memory(conn, key, merged)
    _save_ha_user_profile(conn, ha_user_id, merged)
    store.set_memory(conn, f"speaker.device_for_user:{ha_user_id.strip()}", device.strip())


def _apply_ha_person_link(
    conn,
    device: str | None,
    person_id: str | None,
    person_name: str | None,
) -> None:
    if not isinstance(device, str) or not device.strip():
        return
    if not isinstance(person_id, str) or not person_id.strip():
        return
    key = f"speaker.profile.device:{device.strip()}"
    profile = store.get_memory(conn, key)
    if not isinstance(profile, dict):
        profile = {"state": "linked"}
    profile["ha_person_id"] = person_id.strip()
    if isinstance(person_name, str) and person_name.strip():
        profile["ha_person_name"] = person_name.strip()
        if not profile.get("name"):
            profile["name"] = person_name.strip()
    if not profile.get("created_ts"):
        profile["created_ts"] = datetime.now(timezone.utc).isoformat()
    profile["last_seen_ts"] = datetime.now(timezone.utc).isoformat()
    profile["last_device"] = device.strip()
    store.set_memory(conn, key, profile)
    ha_user_id = profile.get("ha_user_id")
    if isinstance(ha_user_id, str) and ha_user_id.strip():
        user_profile = _load_ha_user_profile(conn, ha_user_id) or {}
        merged = _merge_profiles(user_profile, profile)
        _save_ha_user_profile(conn, ha_user_id, merged)
    try:
        store.insert_event(
            conn,
            source="voice",
            event_type="profile.linked",
            payload={
                "device": device.strip(),
                "ha_person_id": person_id.strip(),
                "ha_person_name": person_name,
            },
            severity="info",
        )
    except Exception:
        pass


def _append_recent_turn(memory: Dict[str, Any], role: str, text: str) -> None:
    recent = memory.get("recent")
    if not isinstance(recent, list):
        recent = []
    recent.append({"role": role, "text": _truncate_text(text, 400), "ts": time.time()})
    memory["recent"] = recent[-12:]


def _extract_facts_simple(text: str) -> List[str]:
    facts: List[str] = []
    lowered = text.lower()
    if "turn on" in lowered or "turn off" in lowered:
        return facts
    patterns = [
        r"\bmy favorite ([a-z ]{3,20}) is ([a-z0-9 '._-]{2,40})\b",
        r"\bmy (timezone|time zone) is ([a-z0-9/_+-]{2,30})\b",
        r"\bi (?:like|love|prefer) ([a-z0-9 '._-]{2,40})\b",
        r"\bmy (?:job|role) is ([a-z0-9 '._-]{2,40})\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, lowered)
        if match:
            if match.lastindex and match.lastindex >= 2:
                facts.append(f"{match.group(1).strip()}: {match.group(2).strip()}")
            else:
                facts.append(match.group(0).strip())
    return facts


def _merge_facts(existing: List[str], new: List[str]) -> List[str]:
    seen = {item.strip().lower() for item in existing if isinstance(item, str)}
    merged = list(existing)
    for fact in new:
        norm = fact.strip().lower()
        if norm and norm not in seen:
            merged.append(fact.strip())
            seen.add(norm)
    return merged[-50:]


def _should_summarize(memory: Dict[str, Any]) -> bool:
    last_ts = memory.get("last_summary_ts", 0.0)
    if not isinstance(last_ts, (int, float)):
        last_ts = 0.0
    recent = memory.get("recent")
    if not isinstance(recent, list) or len(recent) < 6:
        return False
    return (time.time() - float(last_ts)) > 6 * 3600


def _summarize_conversation(memory: Dict[str, Any], llm_ctx: Dict[str, Any]) -> str | None:
    api_key = llm_ctx.get("api_key")
    if not api_key:
        return None
    recent = memory.get("recent", [])
    if not isinstance(recent, list):
        recent = []
    prompt = (
        "Summarize the following conversation in 3-5 short sentences. "
        "Highlight preferences, goals, and relevant facts. Keep it under 600 characters.\n\n"
        f"CURRENT_SUMMARY: {memory.get('summary', '')}\n\n"
        f"RECENT_TURNS: {json.dumps(recent, ensure_ascii=True)}"
    )
    try:
        return _call_openai(
            prompt,
            api_key=api_key,
            model=llm_ctx.get("model"),
            base_url=llm_ctx.get("base_url"),
        )
    except Exception:
        return None


def _update_conversation_memory(
    conn,
    payload: Dict[str, Any],
    reply: str,
    llm_ctx: Dict[str, Any],
) -> None:
    device = payload.get("device")
    profile = _speaker_profile_from_device(conn, device)
    key = _conversation_key(device, profile)
    if not key:
        return
    memory = _load_conversation_memory(conn, key)
    _append_recent_turn(memory, "user", str(payload.get("text", "")))
    _append_recent_turn(memory, "assistant", reply)
    turns = memory.get("turns")
    try:
        turns = int(turns) if turns is not None else 0
    except (TypeError, ValueError):
        turns = 0
    memory["turns"] = turns + 1
    memory["last_user_text"] = _truncate_text(str(payload.get("text", "")), 200)
    memory["last_reply"] = _truncate_text(reply, 200)
    new_facts = _extract_facts_simple(str(payload.get("text", "")))
    facts = memory.get("facts") if isinstance(memory.get("facts"), list) else []
    if new_facts:
        memory["facts"] = _merge_facts(facts, new_facts)
    if _should_summarize(memory):
        summary = _summarize_conversation(memory, llm_ctx)
        if summary:
            memory["summary"] = _truncate_text(summary, 800)
            memory["last_summary_ts"] = time.time()
    memory["updated_ts"] = time.time()
    _store_conversation_memory(conn, key, memory)
    if isinstance(device, str) and device.strip():
        store.set_memory(conn, "voice.last_device", device.strip())
        _update_profile_activity(conn, device, str(payload.get("text", "")), reply)
    try:
        store.insert_event(
            conn,
            source="voice",
            event_type="memory.updated",
            payload={
                "key": key,
                "turns": memory.get("turns"),
                "facts_count": len(memory.get("facts", [])),
                "summary_len": len(memory.get("summary", "")),
            },
            severity="info",
        )
    except Exception:
        pass

def _effective_bind(handler: BaseHTTPRequestHandler) -> tuple[str, int]:
    try:
        address = handler.server.server_address
        return address[0], int(address[1])
    except Exception:
        return settings.voice_server_host(), settings.voice_server_port()


def _load_voice_ui_asset(name: str) -> str:
    ui_path = settings.repo_root() / "pumpkin" / "web" / name
    try:
        return ui_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "<!doctype html><title>Pumpkin UI missing</title><h1>UI file not found</h1>"


def _rate_limited(rate_key: str | None, cooldown: int) -> bool:
    key = rate_key or "unknown"
    now = int(datetime.now(timezone.utc).timestamp())
    history = _last_seen.get(key, [])
    history = [ts for ts in history if (now - ts) < cooldown]
    if len(history) >= 2:
        _last_seen[key] = history
        return True
    history.append(now)
    _last_seen[key] = history
    return False


def _parse_limit(value: str | None, default: int = 25, max_limit: int = 200) -> int:
    if not value:
        return default
    try:
        return min(max(1, int(value)), max_limit)
    except ValueError:
        return default


def _build_area_context(summary: Dict[str, Any]) -> tuple[list, dict, dict, set[str], set[str]]:
    areas_list = summary.get("areas") or []
    if not isinstance(areas_list, list):
        areas_list = []
    area_map = summary.get("entity_areas") if isinstance(summary, dict) else {}
    if not isinstance(area_map, dict):
        area_map = {}
    area_names = {}
    for area in areas_list:
        if isinstance(area, dict):
            aid = area.get("area_id")
            name = area.get("name")
            if aid and name:
                area_names[aid] = str(name)
    upstairs_entities = set(summary.get("upstairs_entities") or [])
    downstairs_entities = set(summary.get("downstairs_entities") or [])
    return areas_list, area_map, area_names, upstairs_entities, downstairs_entities


def _domain_entities(entities: Dict[str, Dict[str, Any]], domain: str) -> List[str]:
    return [eid for eid in entities.keys() if isinstance(eid, str) and eid.startswith(domain + ".")]


def _match_domain_entity_by_name(
    entities: Dict[str, Dict[str, Any]],
    domain: str,
    name_hint: str,
) -> str | None:
    needle = name_hint.lower()
    for entity_id, payload in entities.items():
        if not isinstance(entity_id, str) or not entity_id.startswith(domain + "."):
            continue
        attributes = payload.get("attributes", {}) if isinstance(payload, dict) else {}
        if isinstance(attributes, dict):
            friendly = str(attributes.get("friendly_name") or "").lower()
            if friendly and needle in friendly:
                return entity_id
        if needle in entity_id.lower():
            return entity_id
    return None


def _select_entity_for_domain(
    entities: Dict[str, Dict[str, Any]],
    summary: Dict[str, Any],
    domain: str,
    text: str,
    name_hint: str | None = None,
) -> str | None:
    if name_hint:
        match = _match_domain_entity_by_name(entities, domain, name_hint)
        if match:
            return match
    areas_list, area_map, area_names, upstairs_entities, downstairs_entities = _build_area_context(summary)
    area = _match_area(areas_list, text)
    area_hint = area.get("name") if area else _extract_area_hint(text)
    if area_hint:
        candidates = _match_entities_by_area_hint(
            entities,
            domain,
            str(area_hint),
            area_map=area_map,
            area_names=area_names,
            upstairs_entities=upstairs_entities,
            downstairs_entities=downstairs_entities,
        )
        if candidates:
            return candidates[0]
    domain_list = _domain_entities(entities, domain)
    return domain_list[0] if domain_list else None


def _parse_duration_seconds(text: str) -> int | None:
    lowered = text.lower()
    total = 0.0
    matches = re.findall(r"(\d+(?:\.\d+)?)\s*(hours?|hrs?|hr|h|minutes?|mins?|min|m|seconds?|secs?|sec|s)", lowered)
    for value, unit in matches:
        try:
            amount = float(value)
        except ValueError:
            continue
        if unit.startswith("h"):
            total += amount * 3600
        elif unit.startswith("m"):
            total += amount * 60
        else:
            total += amount
    if total > 0:
        return int(total)
    colon = re.search(r"\b(\d{1,2}):(\d{2})\b", lowered)
    if colon:
        mins = int(colon.group(1))
        secs = int(colon.group(2))
        return mins * 60 + secs
    plain = re.search(r"\b(\d+)\b", lowered)
    if plain:
        return int(plain.group(1)) * 60
    return None


def _format_duration(seconds: int) -> str:
    seconds = max(1, int(seconds))
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _schedule_timer_announcement(conn, seconds: int, label: str) -> None:
    entries = store.get_memory(conn, "voice.timer_announcements") or []
    if not isinstance(entries, list):
        entries = []
    now = datetime.now(timezone.utc)
    due = now + timedelta(seconds=seconds)
    entries.append(
        {
            "id": uuid.uuid4().hex,
            "due_ts": due.isoformat(),
            "created_ts": now.isoformat(),
            "message": label,
        }
    )
    store.set_memory(conn, "voice.timer_announcements", entries)


def _handle_timer_alarm(text: str, conn, device: str | None) -> str | None:
    lowered = text.lower()
    if "timer" not in lowered and "alarm" not in lowered:
        return None
    seconds = _parse_duration_seconds(lowered)
    if not seconds:
        return "How long should the timer be?"
    base_url, token, error = _load_ha_connection(conn)
    if error:
        return error
    entities = store.get_memory(conn, "homeassistant.entities") or {}
    if not isinstance(entities, dict):
        entities = {}
    summary = store.get_memory(conn, "homeassistant.summary") or {}
    timer_id = _select_entity_for_domain(entities, summary, "timer", text)
    if not timer_id:
        return "I couldn't find any timers in Home Assistant."
    duration = _format_duration(seconds)
    result = ha_client.call_service(
        base_url=base_url,
        token=token,
        domain="timer",
        service="start",
        payload={"entity_id": timer_id, "duration": duration},
        timeout=settings.ha_request_timeout_seconds(),
    )
    if not result.get("ok"):
        return "Home Assistant rejected that timer."
    label = "Timer finished."
    _schedule_timer_announcement(conn, seconds, label)
    return f"Timer set for {duration}. I'll announce on all speakers."


def _extract_todo_item(text: str) -> str | None:
    lowered = text.lower()
    remind = re.search(r"remind me to (.+)", lowered)
    if remind:
        return remind.group(1).strip()
    add = re.search(r"add (.+?) to (?:the )?(?:shopping|grocery|todo|to-do)? ?list", lowered)
    if add:
        return add.group(1).strip()
    add_simple = re.search(r"add (.+)", lowered)
    if add_simple:
        return add_simple.group(1).strip()
    return None


def _extract_todo_list(text: str) -> str | None:
    lowered = text.lower()
    if "shopping" in lowered:
        return "shopping"
    if "grocery" in lowered or "groceries" in lowered:
        return "grocery"
    if "todo" in lowered or "to-do" in lowered:
        return "todo"
    if "list" in lowered:
        return "list"
    return None


def _handle_todo_command(text: str, conn, device: str | None) -> str | None:
    lowered = text.lower()
    if "remind me" not in lowered and "list" not in lowered and "todo" not in lowered:
        return None
    item = _extract_todo_item(text)
    if not item:
        return None
    base_url, token, error = _load_ha_connection(conn)
    if error:
        return error
    entities = store.get_memory(conn, "homeassistant.entities") or {}
    if not isinstance(entities, dict):
        entities = {}
    summary = store.get_memory(conn, "homeassistant.summary") or {}
    list_hint = _extract_todo_list(text)
    todo_id = _select_entity_for_domain(entities, summary, "todo", text, name_hint=list_hint)
    if not todo_id:
        return "I couldn't find any todo lists in Home Assistant."
    result = ha_client.call_service(
        base_url=base_url,
        token=token,
        domain="todo",
        service="add_item",
        payload={"entity_id": todo_id, "item": item},
        timeout=settings.ha_request_timeout_seconds(),
    )
    if not result.get("ok"):
        return "Home Assistant rejected that todo update."
    return f"Added '{item}' to your list."


def _handle_weather_query(text: str, conn) -> str | None:
    lowered = text.lower()
    if "weather" not in lowered and "forecast" not in lowered and "temperature" not in lowered:
        return None
    entities = store.get_memory(conn, "homeassistant.entities") or {}
    if not isinstance(entities, dict):
        entities = {}
    summary = store.get_memory(conn, "homeassistant.summary") or {}
    weather_id = _select_entity_for_domain(entities, summary, "weather", text)
    if not weather_id:
        return "I couldn't find any weather entity in Home Assistant."
    payload = entities.get(weather_id, {})
    state = payload.get("state")
    attributes = payload.get("attributes", {}) if isinstance(payload, dict) else {}
    temp = attributes.get("temperature")
    humidity = attributes.get("humidity")
    wind = attributes.get("wind_speed")
    parts = []
    if state:
        parts.append(str(state).replace("_", " "))
    if temp is not None:
        parts.append(f"{temp}°")
    if humidity is not None:
        parts.append(f"humidity {humidity}%")
    if wind is not None:
        parts.append(f"wind {wind}")
    summary_text = ", ".join(parts) if parts else "Weather data is available."
    return f"Weather: {summary_text}."


def _handle_news_query(text: str, conn) -> str | None:
    lowered = text.lower()
    if "news" not in lowered and "headlines" not in lowered:
        return None
    entities = store.get_memory(conn, "homeassistant.entities") or {}
    if not isinstance(entities, dict):
        entities = {}
    bbc_candidates = []
    for entity_id, payload in entities.items():
        if not isinstance(entity_id, str) or not entity_id.startswith("sensor."):
            continue
        attributes = payload.get("attributes", {}) if isinstance(payload, dict) else {}
        name = str(attributes.get("friendly_name") or "").lower()
        if "bbc" in entity_id or ("bbc" in name and "news" in name):
            bbc_candidates.append(entity_id)
    if not bbc_candidates:
        return "I couldn't find a BBC news feed in Home Assistant."
    news_id = bbc_candidates[0]
    payload = entities.get(news_id, {})
    attributes = payload.get("attributes", {}) if isinstance(payload, dict) else {}
    entries = attributes.get("entries") or attributes.get("items") or attributes.get("articles") or []
    headlines = []
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                title = entry.get("title") or entry.get("headline")
                if title:
                    headlines.append(str(title))
            if len(headlines) >= 3:
                break
    if not headlines:
        state = payload.get("state")
        if isinstance(state, str) and state.strip():
            return f"BBC news: {state}"
        return "BBC news feed is available but no headlines were found."
    return "BBC headlines: " + "; ".join(headlines) + "."


def _handle_media_command(text: str, conn, device: str | None) -> str | None:
    lowered = text.lower()
    if "music" not in lowered and "song" not in lowered and "track" not in lowered:
        if "volume" not in lowered and "pause" not in lowered and "play" not in lowered and "resume" not in lowered:
            if "next" not in lowered and "previous" not in lowered and "skip" not in lowered and "stop" not in lowered:
                return None
    base_url, token, error = _load_ha_connection(conn)
    if error:
        return error
    entities = store.get_memory(conn, "homeassistant.entities") or {}
    if not isinstance(entities, dict):
        entities = {}
    summary = store.get_memory(conn, "homeassistant.summary") or {}
    player_id = _select_entity_for_domain(entities, summary, "media_player", text)
    if not player_id:
        return "I couldn't find any media players in Home Assistant."
    service = None
    payload = {"entity_id": player_id}
    if "volume" in lowered:
        value = None
        match = re.search(r"volume (?:to|at) (\d{1,3})", lowered)
        if match:
            try:
                value = max(0, min(100, int(match.group(1))))
            except ValueError:
                value = None
        if value is not None:
            service = "volume_set"
            payload["volume_level"] = value / 100.0
        elif "up" in lowered:
            service = "volume_up"
        elif "down" in lowered:
            service = "volume_down"
    elif "next" in lowered or "skip" in lowered:
        service = "media_next_track"
    elif "previous" in lowered or "back" in lowered:
        service = "media_previous_track"
    elif "pause" in lowered:
        service = "media_pause"
    elif "stop" in lowered:
        service = "media_stop"
    elif "resume" in lowered or "play" in lowered:
        if "amazon" in lowered:
            attributes = entities.get(player_id, {}).get("attributes", {})
            source_list = attributes.get("source_list") if isinstance(attributes, dict) else None
            if isinstance(source_list, list):
                for source in source_list:
                    if isinstance(source, str) and "amazon" in source.lower():
                        select_result = ha_client.call_service(
                            base_url=base_url,
                            token=token,
                            domain="media_player",
                            service="select_source",
                            payload={"entity_id": player_id, "source": source},
                            timeout=settings.ha_request_timeout_seconds(),
                        )
                        if not select_result.get("ok"):
                            return "Home Assistant couldn't switch to Amazon Music."
                        break
        service = "media_play"
    if not service:
        return None
    result = ha_client.call_service(
        base_url=base_url,
        token=token,
        domain="media_player",
        service=service,
        payload=payload,
        timeout=settings.ha_request_timeout_seconds(),
    )
    if not result.get("ok"):
        return "Home Assistant rejected that media command."
    return f"Media command sent: {service.replace('_', ' ')}."


def _compute_ask_reply(
    text: str,
    device: str | None,
    payload: Dict[str, Any],
    conn,
    api_key: str | None,
    llm_config: Dict[str, Any],
    memory_ctx: Dict[str, Any],
    notice: str | None,
) -> tuple[str | None, str, str | None]:
    proposal_followup = _handle_proposal_followup(text, device, conn)
    if proposal_followup:
        return proposal_followup, "proposal_followup", None
    action_followup = _handle_action_confirmation(text, device, conn)
    if action_followup:
        return action_followup, "action_confirm", None
    target_followup = _handle_target_followup(text, device, conn)
    if target_followup:
        return target_followup, "target_followup", None
    presence_reply = _lookup_presence(text)
    if presence_reply:
        return presence_reply, "presence", None
    if _home_query(text):
        home_reply = _local_home_reply(conn)
        if home_reply:
            return home_reply, "home", None
    if _home_summary_query(text):
        summary_reply = _local_house_summary_reply(conn)
        return summary_reply, "home_summary", None
    media_reply = _handle_media_command(text, conn, device)
    if media_reply:
        return media_reply, "media_control", None
    timer_reply = _handle_timer_alarm(text, conn, device)
    if timer_reply:
        return timer_reply, "timer_alarm", None
    todo_reply = _handle_todo_command(text, conn, device)
    if todo_reply:
        return todo_reply, "todo", None
    weather_reply = _handle_weather_query(text, conn)
    if weather_reply:
        return weather_reply, "weather", None
    news_reply = _handle_news_query(text, conn)
    if news_reply:
        return news_reply, "news", None
    control_reply = _execute_ha_command(text, conn, device)
    if control_reply:
        return control_reply, "ha_control", None
    improvement_reply = _maybe_improvement_plan(text, device, conn, api_key)
    if improvement_reply:
        return improvement_reply, "improvement_plan", None
    code_reply = _maybe_code_patch(text, device, api_key, conn)
    if code_reply:
        return code_reply, "code_patch", None
    capability_reply = _maybe_capability_proposal(text, device, payload.get("client_ip"), conn)
    if capability_reply:
        return capability_reply, "capability_proposal", None
    if _recent_query(text):
        return _recent_events_reply(conn, limit=5), "recent_events", None
    if "last ha event" in text.lower() or "last home assistant" in text.lower():
        return _last_ha_event_reply(conn), "ha_last_event", None
    if _inventory_query(text):
        return _inventory_reply(conn, text), "inventory", None
    if _health_query(text):
        return _health_report_reply(conn), "health", None
    name = _parse_speaker_name(text)
    if name:
        error = _store_speaker_name(conn, device, name)
        reply = error or f"Thanks, {name}. I'll remember you."
        return reply, "speaker_name", None
    preference_reply = _handle_preference_update(text, device, conn)
    if preference_reply:
        return preference_reply, "preferences", None
    if _memory_query(text):
        return _memory_reply(conn, device, text), "memory", None
    calendar_reply = _lookup_calendar(text, device, conn)
    if calendar_reply:
        return calendar_reply, "calendar", None
    if _status_query(text):
        return _local_status_reply(conn), "status", None
    router = _llm_route_text(
        text,
        api_key=api_key,
        llm_config=llm_config,
        device=device,
        client_ip=payload.get("client_ip"),
    )
    if router:
        confidence = router.get("confidence")
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.0
        if confidence >= 0.55:
            _log_router_decision(text, router, router.get("route") or "unknown", device)
            if router.get("needs_clarification"):
                questions = router.get("questions") or []
                if isinstance(questions, list) and questions:
                    return (
                        "I need a bit more detail: " + " ".join(str(q) for q in questions),
                        "llm_router_clarify",
                        None,
                    )
                if router.get("action") and not (router.get("target") or router.get("area")):
                    return "Which device or room should I use?", "llm_router_clarify", None
            route = router.get("route")
            normalized = _normalize_router_request(router)
            response = router.get("response")
            if route == "ha_control" and isinstance(normalized, str) and normalized.strip():
                if 0.55 <= confidence < 0.7 and device:
                    _store_pending_action(
                        conn,
                        device,
                        {
                            "command_text": normalized.strip(),
                            "action": router.get("action"),
                            "target": router.get("target"),
                        },
                    )
                    return (
                        f"I think you want me to {normalized.strip()}. Proceed? (yes/no)",
                        "llm_router_confirm",
                        None,
                    )
                reply = _execute_ha_command(normalized, conn, device)
                if reply:
                    return reply, "llm_router_control", None
            if route == "capability":
                reply = _maybe_capability_proposal(
                    normalized if isinstance(normalized, str) and normalized.strip() else text,
                    device,
                    payload.get("client_ip"),
                    conn,
                )
                if reply:
                    return reply, "llm_router_capability", None
            if route == "answer" and isinstance(response, str) and response.strip():
                return response.strip(), "llm_router_answer", None
    context = _build_llm_context(conn, device)
    context["retrieved_context"] = retrieval.retrieve_context(
        text,
        settings.audit_path(),
        [
            settings.modules_config_path(),
            settings.modules_registry_path(),
            settings.policy_path(),
        ],
        max_results=5,
    )
    prompt = (
        "Answer the user question using the context when relevant. "
        "If the context lacks the answer, say so briefly.\n\n"
        f"USER_QUESTION: {text}\n\n"
        f"CONTEXT: {json.dumps(context, ensure_ascii=True)}"
    )
    try:
        reply = _call_openai(
            prompt,
            api_key=api_key,
            model=llm_config["model"],
            base_url=llm_config["base_url"],
        )
    except ValueError as exc:
        return None, "llm_fallback", str(exc)
    except urllib.error.HTTPError as exc:
        return None, "llm_fallback", f"openai_http_{exc.code}"
    except Exception:
        return None, "llm_fallback", "openai_request_failed"
    return reply, "llm_fallback", None


def _call_openai(
    prompt: str,
    api_key: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
) -> str:
    api_key = api_key or os.getenv("PUMPKIN_OPENAI_API_KEY")
    if not api_key:
        raise ValueError("openai_api_key_missing")
    model = model or os.getenv("PUMPKIN_OPENAI_MODEL", "gpt-4o-mini")
    url = base_url or os.getenv(
        "PUMPKIN_OPENAI_BASE_URL", "https://api.openai.com/v1/chat/completions"
    )
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are Pumpkin, a helpful, calm assistant for a home automation system. "
                    "Use the CONTEXT data when relevant. Be concise, friendly, and clear. "
                    "If you are unsure, say so."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.6,
    }
    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")
    with urllib.request.urlopen(req, timeout=OPENAI_TIMEOUT_SECONDS) as resp:
        raw = resp.read().decode("utf-8")
    decoded = json.loads(raw)
    choices = decoded.get("choices", [])
    if not choices:
        raise ValueError("openai_empty_response")
    message = choices[0].get("message", {})
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("openai_empty_content")
    return content.strip()


def _call_openai_json(prompt: str, api_key: str | None, model: str | None, base_url: str | None) -> Dict[str, Any]:
    content = _call_openai(prompt, api_key=api_key, model=model, base_url=base_url)
    try:
        return _parse_json(content.encode("utf-8"))
    except ValueError:
        return {"error": "invalid_json", "raw": content}


def _normalize_router_request(router: Dict[str, Any]) -> str | None:
    normalized = router.get("normalized_request")
    if isinstance(normalized, str) and normalized.strip():
        return normalized.strip()
    action = router.get("action")
    if not isinstance(action, str) or not action.strip():
        return None
    target = router.get("target")
    area = router.get("area")
    domain = router.get("domain")
    if isinstance(target, str) and target.strip():
        return f"{action} {target}".strip()
    if isinstance(area, str) and area.strip() and isinstance(domain, str) and domain.strip():
        return f"{action} {area} {domain}s".strip()
    return None


def _log_router_decision(text: str, router: Dict[str, Any], route: str, device: str | None) -> None:
    payload = {
        "route": route,
        "confidence": router.get("confidence"),
        "needs_clarification": router.get("needs_clarification"),
        "action": router.get("action"),
        "target": router.get("target"),
        "area": router.get("area"),
        "device": router.get("device"),
        "domain": router.get("domain"),
    }
    print(
        "PumpkinVoice router "
        + repr(_truncate_text(text, INGEST_LOG_TEXT_LIMIT))
        + f" -> {json.dumps(payload, ensure_ascii=True)}",
        flush=True,
    )
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "voice.router",
            "text": _truncate_text(text, INGEST_LOG_TEXT_LIMIT),
            "device": device,
            "payload": payload,
        },
    )


def _llm_route_text(
    text: str,
    api_key: str | None,
    llm_config: Dict[str, Any],
    device: str | None,
    client_ip: str | None,
) -> Dict[str, Any]:
    if not api_key:
        return {}
    route_key = device or client_ip or "unknown"
    if _rate_limited(f"llm.route:{route_key}", cooldown=10):
        return {}
    prompt = (
        "You are routing a home assistant voice request. "
        "Return ONLY JSON with keys: route, normalized_request, response, "
        "needs_clarification, questions, confidence, action, target, area, device, domain. "
        "route must be one of: ha_control, capability, answer, ignore. "
        "normalized_request should be a canonical command string when route=ha_control. "
        "action should be one of: turn_on, turn_off, toggle, open, close, lock, unlock, set_temperature. "
        "target is a device or entity name; area is a room/area name; domain is light/switch/fan/cover/lock. "
        "If the request is ambiguous, set needs_clarification true and provide questions. "
        "confidence must be a number 0-1.\n\n"
        f"REQUEST: {text}"
    )
    payload = _call_openai_json(
        prompt,
        api_key=api_key,
        model=llm_config["model"],
        base_url=llm_config["base_url"],
    )
    return payload if isinstance(payload, dict) else {}


def _code_assistant_enabled(conn) -> tuple[bool, Dict[str, Any]]:
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return False, {}
    try:
        config = module_config.load_config(str(config_path))
    except Exception:
        return False, {}
    enabled = set(config.get("enabled", []))
    if "code.assistant" not in enabled:
        return False, {}
    module_cfg = config.get("modules", {}).get("code.assistant", {})
    return True, module_cfg if isinstance(module_cfg, dict) else {}


def _is_code_request(text: str) -> bool:
    lowered = text.lower()
    triggers = [
        "code",
        "patch",
        "edit file",
        "update file",
        "change file",
        "modify file",
        "fix bug",
        "fix the code",
        "add function",
        "refactor",
    ]
    return any(token in lowered for token in triggers)


def _is_improvement_request(text: str) -> bool:
    lowered = text.lower()
    triggers = [
        "improve yourself",
        "work better",
        "get better",
        "self improve",
        "self-improve",
        "self improve",
        "plan improvements",
        "propose improvements",
        "propose system improvements",
        "system improvements",
        "make improvements",
        "improve the system",
        "make plans",
    ]
    return any(token in lowered for token in triggers)


def _maybe_improvement_plan(text: str, device: str | None, conn, api_key: str | None) -> str | None:
    if not _is_improvement_request(text):
        return None
    recent = store.list_events(conn, limit=50)
    events = sorted(recent, key=lambda row: row["id"]) if recent else []
    prev_mode = os.getenv("PUMPKIN_PLANNER_MODE")
    prev_key = os.getenv("PUMPKIN_OPENAI_API_KEY")
    if api_key and not prev_key:
        os.environ["PUMPKIN_OPENAI_API_KEY"] = api_key
    if prev_mode is None:
        os.environ["PUMPKIN_PLANNER_MODE"] = "openai"
    try:
        proposals = propose.build_proposals(events, conn)
    except Exception as exc:
        print(f"PumpkinVoice planner_error {exc}", flush=True)
        return "I couldn't generate improvement plans right now."
    finally:
        if prev_mode is None:
            os.environ.pop("PUMPKIN_PLANNER_MODE", None)
        else:
            os.environ["PUMPKIN_PLANNER_MODE"] = prev_mode
        if prev_key is None and api_key:
            os.environ.pop("PUMPKIN_OPENAI_API_KEY", None)
    created = _record_voice_proposals(conn, proposals)
    if not created:
        return "No improvement plans right now."
    proposal_lines = []
    for proposal_id, proposal in created[:3]:
        summary = proposal.get("summary", "proposal")
        proposal_lines.append(f"#{proposal_id} {summary}")
    if proposal_lines:
        _store_pending_proposal(conn, device, created[0][0])
        joined = "; ".join(proposal_lines)
        return f"Drafted proposals: {joined}. Reply yes to approve the first one."
    return "No improvement plans right now."


def _build_code_prompt(instruction: str, repo_root: str) -> str:
    clipped = instruction[:CODE_PROMPT_MAX_LEN]
    return (
        "You are a senior software engineer. "
        "Return ONLY JSON with keys: summary, rationale, patch, needs_clarification, questions. "
        "If the request is unclear, set needs_clarification true and list questions; patch should be empty. "
        "If clear, provide a unified diff patch that applies cleanly with `patch` in the repo root. "
        "Do not include explanations outside JSON. "
        f"Repository root: {repo_root}\n\n"
        f"REQUEST: {clipped}"
    )


def _maybe_code_patch(
    text: str, device: str | None, api_key: str | None, conn
) -> str | None:
    if not _is_code_request(text):
        return None
    enabled, module_cfg = _code_assistant_enabled(conn)
    if not enabled:
        return "Code assistant is not enabled yet."
    repo_root = module_cfg.get("repo_root") if isinstance(module_cfg, dict) else None
    if not isinstance(repo_root, str) or not repo_root.strip():
        return "Code assistant repo_root is not configured."
    llm_config = _load_llm_config(conn)
    key = api_key or llm_config["api_key"]
    if not key:
        return "OpenAI API key is missing for code assistant."
    prompt = _build_code_prompt(text, repo_root)
    result = _call_openai_json(prompt, key, llm_config["model"], llm_config["base_url"])
    if result.get("needs_clarification"):
        questions = result.get("questions") or []
        if isinstance(questions, list) and questions:
            return "I need a bit more detail: " + " ".join(str(q) for q in questions)
        return "I need a bit more detail about the change you want."
    patch = result.get("patch")
    if not isinstance(patch, str) or not patch.strip():
        return "I couldn't draft a patch for that yet."
    summary = result.get("summary") or "Apply code changes"
    rationale = result.get("rationale") or "Requested code change."
    details = {
        "rationale": rationale,
        "implementation": "Apply the patch with the code runner after approval.",
        "verification": "Verify the change and check service health.",
        "rollback_plan": "Revert the patch if verification fails.",
        "action_type": "code.apply_patch",
        "action_params": {"repo_root": repo_root, "patch": patch},
    }
    policy = policy_mod.load_policy(str(settings.policy_path()))
    proposal_id = store.insert_proposal(
        conn,
        kind="action.request",
        summary=summary,
        details=details,
        steps=[
            "Apply the patch with git apply/patch tool",
            "Run quick self-checks if available",
            "Restart the affected service and verify",
        ],
        risk=0.8,
        expected_outcome="Patch is applied after approval.",
        status="pending",
        policy_hash=policy.policy_hash,
        needs_new_capability=False,
        capability_request=None,
    )
    _store_pending_proposal(conn, device, proposal_id)
    return f"Proposal #{proposal_id}: {summary}. Rationale: {rationale}. Reply yes to approve or no to skip."


def _latest_event(conn, event_type: str) -> Dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM events WHERE type = ? ORDER BY id DESC LIMIT 1", (event_type,)
    ).fetchone()
    if not row:
        return None
    try:
        payload = json.loads(row["payload_json"])
    except Exception:
        payload = {}
    return {
        "id": row["id"],
        "ts": row["ts"],
        "source": row["source"],
        "type": row["type"],
        "payload": payload,
        "severity": row["severity"],
    }


def _load_llm_config(conn) -> Dict[str, Any]:
    api_key = store.get_memory(conn, "llm.openai_api_key")
    model = store.get_memory(conn, "llm.openai_model")
    base_url = store.get_memory(conn, "llm.openai_base_url")
    return {
        "api_key": api_key or os.getenv("PUMPKIN_OPENAI_API_KEY"),
        "model": model or os.getenv("PUMPKIN_OPENAI_MODEL", "gpt-4o-mini"),
        "base_url": base_url
        or os.getenv("PUMPKIN_OPENAI_BASE_URL", "https://api.openai.com/v1/chat/completions"),
    }


def _speaker_profile_from_device(conn, device: str | None) -> Dict[str, Any] | None:
    if not isinstance(device, str) or not device.strip():
        return None
    key = f"speaker.profile.device:{device.strip()}"
    profile = store.get_memory(conn, key)
    if not isinstance(profile, dict):
        return None
    ha_user_id = profile.get("ha_user_id")
    user_profile = _load_ha_user_profile(conn, ha_user_id)
    if isinstance(user_profile, dict):
        return _merge_profiles(user_profile, profile)
    return profile


def _ha_user_profile_key(ha_user_id: str) -> str:
    return f"speaker.profile.ha_user:{ha_user_id.strip()}"


def _load_ha_user_profile(conn, ha_user_id: str | None) -> Dict[str, Any] | None:
    if not isinstance(ha_user_id, str) or not ha_user_id.strip():
        return None
    profile = store.get_memory(conn, _ha_user_profile_key(ha_user_id))
    return profile if isinstance(profile, dict) else None


def _save_ha_user_profile(conn, ha_user_id: str, profile: Dict[str, Any]) -> None:
    if not isinstance(ha_user_id, str) or not ha_user_id.strip():
        return
    store.set_memory(conn, _ha_user_profile_key(ha_user_id), profile)


def _merge_profiles(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    base_prefs = base.get("preferences")
    override_prefs = override.get("preferences")
    if isinstance(base_prefs, dict) or isinstance(override_prefs, dict):
        prefs = dict(base_prefs) if isinstance(base_prefs, dict) else {}
        if isinstance(override_prefs, dict):
            prefs.update(override_prefs)
        merged["preferences"] = prefs
    for key, value in override.items():
        if key == "preferences":
            continue
        if value is not None:
            merged[key] = value
    return merged


def _parse_dt(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            local_tz = datetime.now().astimezone().tzinfo
            return parsed.replace(tzinfo=local_tz)
        return parsed
    except ValueError:
        return None


def _event_window(event: dict) -> tuple[datetime | None, datetime | None, bool]:
    start_raw = event.get("start")
    end_raw = event.get("end")
    start = None
    end = None
    is_all_day = False
    if isinstance(start_raw, dict):
        start_val = start_raw.get("dateTime") or start_raw.get("date")
        start = _parse_dt(start_val)
        if start_raw.get("date") and not start_raw.get("dateTime"):
            is_all_day = True
    elif isinstance(start_raw, str):
        start = _parse_dt(start_raw)
    if isinstance(end_raw, dict):
        end_val = end_raw.get("dateTime") or end_raw.get("date")
        end = _parse_dt(end_val)
    elif isinstance(end_raw, str):
        end = _parse_dt(end_raw)
    return start, end, is_all_day


def _calendar_window(text: str) -> tuple[datetime | None, datetime | None]:
    now = datetime.now(timezone.utc)
    lowered = text.lower()
    if "tomorrow" in lowered:
        start = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        return start, end
    if "today" in lowered:
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        return start, end
    if "this week" in lowered or "next 7 days" in lowered:
        return now, now + timedelta(days=7)
    return None, None


def _availability_time(text: str) -> datetime | None:
    lowered = text.lower()
    match = re.search(r"\b(?:at|around)\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b", lowered)
    if not match:
        return None
    hour = int(match.group(1))
    minute = int(match.group(2) or 0)
    meridiem = match.group(3)
    if meridiem:
        if meridiem == "pm" and hour < 12:
            hour += 12
        if meridiem == "am" and hour == 12:
            hour = 0
    if hour > 23 or minute > 59:
        return None
    base = datetime.now().astimezone()
    if "tomorrow" in lowered:
        base = base + timedelta(days=1)
    target = base.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return target


def _is_busy_at(events: list[dict], target: datetime) -> bool:
    for event in events:
        start, end, is_all_day = _event_window(event)
        if not start:
            continue
        if is_all_day:
            if start.date() == target.date():
                return True
            continue
        if end and start <= target < end:
            return True
        if not end and start <= target < (start + timedelta(hours=1)):
            return True
    return False


def _select_events(events: list[dict], text: str, limit: int = 5) -> list[dict]:
    start, end = _calendar_window(text)
    if start and end:
        filtered = []
        for event in events:
            event_start = _parse_dt(
                (event.get("start") or {}).get("dateTime")
                if isinstance(event.get("start"), dict)
                else event.get("start")
            )
            if event_start and start <= event_start < end:
                filtered.append(event)
        return filtered[:limit]
    return events[:limit]


def _calendar_reply_for_events(label: str, events: list[dict], text: str) -> str:
    if not events:
        lowered = text.lower()
        label_text = label[:1].upper() + label[1:] if label else label
        if "today" in lowered:
            return f"{label_text} is clear today."
        if "tomorrow" in lowered:
            return f"{label_text} is clear tomorrow."
        if "this week" in lowered or "next 7 days" in lowered:
            return f"No events on {label} this week."
        return f"No upcoming events on {label}."
    lines = []
    for event in events:
        summary = event.get("summary") or "Untitled"
        start = event.get("start")
        if isinstance(start, dict):
            start = start.get("dateTime") or start.get("date")
        lines.append(f"{summary} ({start})")
    joined = "; ".join(lines)
    return f"Upcoming events on {label}: {joined}"


def _status_query(text: str) -> bool:
    lowered = text.lower()
    return bool(
        re.search(r"\b(status|health|issues|problem|problems|system)\b", lowered)
        or "how is the system" in lowered
        or "how's the system" in lowered
    )


def _home_query(text: str) -> bool:
    lowered = text.lower()
    return bool(
        re.search(r"\bwho('?s| is)\s+home\b", lowered)
        or "who is at home" in lowered
        or "anyone home" in lowered
    )


def _home_summary_query(text: str) -> bool:
    lowered = text.lower()
    return bool(
        "house summary" in lowered
        or "home summary" in lowered
        or "state of the house" in lowered
        or "state of the home" in lowered
    )


def _parse_control_command(text: str) -> Dict[str, Any] | None:
    lowered = text.lower().strip()
    match = re.search(r"\bturn\s+(on|off)\s+(.+)", lowered)
    if match:
        return {"action": f"turn_{match.group(1)}", "target": match.group(2).strip()}
    match = re.search(r"\bturn\s+(.+)\s+(on|off)\b", lowered)
    if match:
        return {"action": f"turn_{match.group(2)}", "target": match.group(1).strip()}
    match = re.search(r"\bswitch\s+(on|off)\s+(.+)", lowered)
    if match:
        return {"action": f"turn_{match.group(1)}", "target": match.group(2).strip()}
    match = re.search(r"\bswitch\s+(.+)\s+(on|off)\b", lowered)
    if match:
        return {"action": f"turn_{match.group(2)}", "target": match.group(1).strip()}
    match = re.search(r"\btoggle\s+(.+)", lowered)
    if match:
        return {"action": "toggle", "target": match.group(1).strip()}
    match = re.search(r"\b(open|close)\s+(.+)", lowered)
    if match:
        return {"action": match.group(1), "target": match.group(2).strip()}
    match = re.search(r"\b(lock|unlock)\s+(.+)", lowered)
    if match:
        return {"action": match.group(1), "target": match.group(2).strip()}
    match = re.search(
        r"\bset\s+(.+)\s+to\s+(\d{1,2})(?:\s*degrees|\s*c)?\b", lowered
    )
    if match:
        return {
            "action": "set_temperature",
            "target": match.group(1).strip(),
            "value": int(match.group(2)),
        }
    return None


def _match_entity_exact(
    entities: Dict[str, Dict[str, Any]], target: str, domain_hint: str | None = None
) -> str | None:
    needle = target.lower().strip()
    for entity_id, payload in entities.items():
        if not isinstance(entity_id, str):
            continue
        if domain_hint and not entity_id.startswith(domain_hint + "."):
            continue
        if needle == entity_id.lower() or needle == entity_id.split(".", 1)[-1].lower():
            return entity_id
        attributes = payload.get("attributes", {}) if isinstance(payload, dict) else {}
        if isinstance(attributes, dict):
            friendly = str(attributes.get("friendly_name") or "").lower()
            if friendly and needle == friendly:
                return entity_id
    return None


def _build_entity_label(entities: Dict[str, Dict[str, Any]], entity_id: str) -> str:
    payload = entities.get(entity_id) if isinstance(entities, dict) else None
    attributes = payload.get("attributes", {}) if isinstance(payload, dict) else {}
    if isinstance(attributes, dict):
        friendly = attributes.get("friendly_name")
        if isinstance(friendly, str) and friendly.strip():
            return friendly.strip()
    return entity_id.split(".", 1)[-1] if "." in entity_id else entity_id


def _bulk_action_prompt(
    entities: Dict[str, Dict[str, Any]],
    entity_ids: List[str],
    action: str,
    target: str,
) -> str:
    sample = [_build_entity_label(entities, eid) for eid in entity_ids[:4]]
    joined = ", ".join(sample)
    total = len(entity_ids)
    verb = action.replace("_", " ")
    if joined:
        return f"This will {verb} {total} devices ({joined}). Proceed? (yes/no)"
    return f"This will {verb} {total} devices for {target}. Proceed? (yes/no)"


def _find_entity_candidates(
    entities: Dict[str, Dict[str, Any]], target: str, domain_hint: str | None = None
) -> List[str]:
    needle = target.lower().strip()
    needles = [needle]
    for prefix in ("the ", "a ", "an "):
        if needle.startswith(prefix):
            needles.append(needle[len(prefix) :])
    matches: List[str] = []
    for entity_id, payload in entities.items():
        if not isinstance(entity_id, str):
            continue
        if domain_hint and not entity_id.startswith(domain_hint + "."):
            continue
        tail = entity_id.split(".", 1)[-1].lower()
        attributes = payload.get("attributes", {}) if isinstance(payload, dict) else {}
        name = ""
        if isinstance(attributes, dict):
            name = str(attributes.get("friendly_name") or "").lower()
        for candidate in needles:
            if candidate == entity_id.lower() or candidate == tail:
                matches.append(entity_id)
                break
            if name and candidate in name:
                matches.append(entity_id)
                break
    return sorted(set(matches))


def _match_entity(entities: Dict[str, Dict[str, Any]], target: str) -> str | None:
    needle = target.lower().strip()
    needles = [needle]
    for prefix in ("the ", "a ", "an "):
        if needle.startswith(prefix):
            needles.append(needle[len(prefix) :])
    for candidate in needles:
        for entity_id, payload in entities.items():
            if not isinstance(entity_id, str):
                continue
            if candidate == entity_id.lower():
                return entity_id
            tail = entity_id.split(".", 1)[-1].lower()
            if candidate == tail:
                return entity_id
            attributes = payload.get("attributes", {}) if isinstance(payload, dict) else {}
            if isinstance(attributes, dict):
                name = str(attributes.get("friendly_name") or "").lower()
                if name and candidate in name:
                    return entity_id
    return None


def _fuzzy_match_entity(entities: Dict[str, Dict[str, Any]], target: str, domain_hint: str | None = None) -> str | None:
    names = {}
    for entity_id, payload in entities.items():
        if not isinstance(entity_id, str):
            continue
        if domain_hint and not entity_id.startswith(domain_hint + "."):
            continue
        attributes = payload.get("attributes", {}) if isinstance(payload, dict) else {}
        if isinstance(attributes, dict):
            friendly = attributes.get("friendly_name")
            if isinstance(friendly, str):
                names[friendly] = entity_id
        names[entity_id] = entity_id
        tail = entity_id.split(".", 1)[-1]
        names[tail] = entity_id
    candidates = list(names.keys())
    best = difflib.get_close_matches(target, candidates, n=1, cutoff=0.6)
    if best:
        return names.get(best[0])
    return None


def _match_area(areas: List[Dict[str, Any]], target: str) -> Dict[str, Any] | None:
    needle = target.lower()
    synonyms = {
        "downstairs": {"downstairs", "ground floor", "groundfloor", "ground level"},
        "upstairs": {"upstairs", "first floor", "1st floor", "floor one"},
    }
    for area in areas:
        name = str(area.get("name") or "").lower()
        if name and name in needle:
            return area
    # Fallback: match upstairs/downstairs synonyms by area_id/name containing keyword
    for area in areas:
        name = str(area.get("name") or "").lower()
        for key, words in synonyms.items():
            if any(word in needle for word in words) and name:
                if key in name or any(word in name for word in words):
                    return area
    return None


def _area_domain_hint(target: str) -> str | None:
    lowered = target.lower()
    if "light" in lowered:
        return "light"
    if "switch" in lowered:
        return "switch"
    if "fan" in lowered:
        return "fan"
    return None


def _wants_area_control(target: str) -> bool:
    lowered = target.lower()
    return "all" in lowered or "lights" in lowered or "switches" in lowered or "fans" in lowered


def _extract_area_hint(target: str) -> str:
    lowered = target.lower()
    stop = {"all", "the", "a", "an", "in", "on", "at", "of"}
    domain_words = {"light", "lights", "switch", "switches", "fan", "fans"}
    parts = [word for word in re.split(r"\s+", lowered) if word]
    filtered = [word for word in parts if word not in stop and word not in domain_words]
    return " ".join(filtered).strip() or lowered


def _match_entities_by_area_hint(
    entities: Dict[str, Dict[str, Any]],
    domain: str,
    area_hint: str,
    area_map: Dict[str, str] | None = None,
    area_names: Dict[str, str] | None = None,
    upstairs_entities: set[str] | None = None,
    downstairs_entities: set[str] | None = None,
) -> List[str]:
    matched: List[str] = []
    needle = area_hint.lower()
    synonyms = {
        "downstairs": {"downstairs", "ground floor", "groundfloor", "ground level"},
        "upstairs": {"upstairs", "first floor", "1st floor", "floor one"},
    }
    upstairs_entities = upstairs_entities or set()
    downstairs_entities = downstairs_entities or set()
    area_map = area_map or {}
    area_names = {k: v.lower() for k, v in (area_names or {}).items()}

    def _extend(items: Iterable[str]) -> None:
        for eid in items:
            if isinstance(eid, str) and eid.startswith(domain + "."):
                matched.append(eid)

    if any(word in needle for word in synonyms["downstairs"]):
        _extend(downstairs_entities)
    if any(word in needle for word in synonyms["upstairs"]):
        _extend(upstairs_entities)

    for entity_id, payload in entities.items():
        if not isinstance(entity_id, str):
            continue
        if not entity_id.startswith(domain + "."):
            continue
        attributes = payload.get("attributes", {}) if isinstance(payload, dict) else {}
        if not isinstance(attributes, dict):
            continue
        name = str(attributes.get("friendly_name") or "").lower()
        if needle and needle in name:
            matched.append(entity_id)
            continue
        area_id = area_map.get(entity_id)
        if area_id:
            area_name = area_names.get(area_id, "")
            if area_name and (needle in area_name or area_name in needle):
                matched.append(entity_id)
                continue
            if any(word in area_name for word in synonyms["downstairs"]) and any(
                word in needle for word in synonyms["downstairs"]
            ):
                matched.append(entity_id)
            if any(word in area_name for word in synonyms["upstairs"]) and any(
                word in needle for word in synonyms["upstairs"]
            ):
                matched.append(entity_id)
    seen = set()
    unique: List[str] = []
    for eid in matched:
        if eid not in seen:
            seen.add(eid)
            unique.append(eid)
    return unique


def _last_target_key(device: str) -> str:
    return f"voice.last_target.{device}"

def _synonym_key(target: str) -> str:
    return f"voice.synonym.{target.strip().lower()}"


def _store_entity_synonym(conn, target: str, entity_id: str) -> None:
    if not target or not entity_id:
        return
    store.set_memory(conn, _synonym_key(target), entity_id)


def _load_entity_synonym(conn, target: str) -> str | None:
    if not target:
        return None
    value = store.get_memory(conn, _synonym_key(target))
    return value if isinstance(value, str) else None


def _load_last_target(conn, device: str | None) -> str | None:
    if not device:
        return None
    value = store.get_memory(conn, _last_target_key(device))
    return value if isinstance(value, str) else None


def _store_last_target(conn, device: str | None, target: str) -> None:
    if not device or not target:
        return
    store.set_memory(conn, _last_target_key(device), target)


def _resolve_followup_target(target: str, device: str | None, conn) -> str:
    normalized = target.strip().lower()
    if normalized in {"them", "it", "that", "those", "these", "all"}:
        last_target = _load_last_target(conn, device)
        if last_target:
            return last_target
    if normalized in {"all of them", "all of those", "all of these"}:
        last_target = _load_last_target(conn, device)
        if last_target:
            return last_target
    return target


def _load_ha_connection(conn) -> tuple[str | None, str | None, str | None]:
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return None, None, "Home Assistant is not configured."
    try:
        config = module_config.load_config(str(config_path))
    except Exception:
        return None, None, "Home Assistant config is invalid."
    enabled = set(config.get("enabled", []))
    if "homeassistant.observer" not in enabled:
        return None, None, "Home Assistant integration is not enabled."
    module_cfg = config.get("modules", {}).get("homeassistant.observer", {})
    base_url = module_cfg.get("base_url")
    token_env = module_cfg.get("token_env", "PUMPKIN_HA_TOKEN")
    token = os.getenv(token_env)
    if not base_url or not token:
        return None, None, "Home Assistant credentials are missing."
    return base_url, token, None


def _ha_service_payload(action: str, entity_id: str, value: int | None) -> tuple[str | None, Dict[str, Any]]:
    payload: Dict[str, Any] = {"entity_id": entity_id}
    if action in {"turn_on", "turn_off", "toggle"}:
        return action, payload
    if action in {"open", "close"}:
        return ("open_cover" if action == "open" else "close_cover"), payload
    if action in {"lock", "unlock"}:
        return action, payload
    if action == "set_temperature":
        payload["temperature"] = value
        return "set_temperature", payload
    return None, payload


def _expansion_notice(device: str | None, conn) -> str | None:
    if not device:
        return None
    rows = store.list_proposals(conn, status="pending", limit=5)
    candidate = None
    for row in rows:
        if row["kind"] in {"module.install", "capability.offer"}:
            candidate = row
            break
    if not candidate:
        return None
    key = f"voice.last_expansion.{device}"
    last_seen = store.get_memory(conn, key)
    try:
        last_seen_id = int(last_seen) if last_seen is not None else 0
    except Exception:
        last_seen_id = 0
    if candidate["id"] <= last_seen_id:
        return None
    store.set_memory(conn, key, candidate["id"])
    return f"New expansion idea: #{candidate['id']} {candidate['summary']}."


def _log_ha_action(conn, command: Dict[str, Any], domain: str, service: str, payload: Dict[str, Any], result: Dict[str, Any] | None) -> None:
    try:
        store.insert_event(
            conn,
            source="voice",
            event_type="voice.ha_action",
            payload={
                "action": command.get("action"),
                "target": command.get("target"),
                "domain": domain,
                "service": service,
                "payload": payload,
                "result": result,
            },
            severity="info",
        )
    except Exception:
        pass


def _execute_ha_command(text: str, conn, device: str | None) -> str | None:
    command = _parse_control_command(text)
    if not command:
        return None
    command["target"] = _resolve_followup_target(command["target"], device, conn)
    base_url, token, error = _load_ha_connection(conn)
    if error:
        return error

    entities = store.get_memory(conn, "homeassistant.entities") or {}
    if not isinstance(entities, dict):
        entities = {}
    domain_hint = _area_domain_hint(command["target"])
    synonym = _load_entity_synonym(conn, command["target"])
    if synonym:
        entity = entities.get(synonym)
        if isinstance(entity, dict):
            entity_id = synonym
        else:
            entity_id = None
    else:
        entity_id = None

    summary = store.get_memory(conn, "homeassistant.summary") or {}
    areas_list = summary.get("areas") or []
    if not isinstance(areas_list, list):
        areas_list = []
    area_map = summary.get("entity_areas") if isinstance(summary, dict) else {}
    if not isinstance(area_map, dict):
        area_map = {}
    area_names = {}
    for area in areas_list:
        if isinstance(area, dict):
            aid = area.get("area_id")
            name = area.get("name")
            if aid and name:
                area_names[aid] = str(name)
    upstairs_entities = set(summary.get("upstairs_entities") or [])
    downstairs_entities = set(summary.get("downstairs_entities") or [])
    if not entity_id:
        entity_id = _match_entity_exact(entities, command["target"], domain_hint=domain_hint)
    if not entity_id and not _wants_area_control(command["target"]):
        candidates = _find_entity_candidates(entities, command["target"], domain_hint=domain_hint)
        if len(candidates) > 1:
            labeled = [
                {"entity_id": candidate, "label": _build_entity_label(entities, candidate)}
                for candidate in candidates[:5]
            ]
            _store_pending_target(
                conn,
                device,
                {
                    "target": command["target"],
                    "action": command["action"],
                    "value": command.get("value"),
                    "choices": labeled,
                },
            )
            labels = ", ".join(item["label"] for item in labeled)
            return f"I found multiple matches for {command['target']}: {labels}. Which one?"
    entity_id = entity_id or _match_entity(entities, command["target"])
    if not entity_id:
        area = _match_area(areas_list, command["target"])
        if area and domain_hint and _wants_area_control(command["target"]) and command["action"] in {
            "turn_on",
            "turn_off",
            "toggle",
        }:
            area_hint = area.get("name") or command["target"]
            area_entities = _match_entities_by_area_hint(
                entities,
                domain_hint,
                str(area_hint),
                area_map=area_map,
                area_names=area_names,
                upstairs_entities=upstairs_entities,
                downstairs_entities=downstairs_entities,
            )
            if (
                area_entities
                and device
                and _should_confirm_bulk(command["action"], command["target"], area_entities)
            ):
                _store_pending_action(
                    conn,
                    device,
                    {
                        "action": command["action"],
                        "domain": domain_hint,
                        "target": command["target"],
                        "entity_ids": area_entities,
                    },
                )
                return _bulk_action_prompt(
                    entities, area_entities, command["action"], command["target"]
                )
            result = ha_client.call_service(
                base_url=base_url,
                token=token,
                domain=domain_hint,
                service=command["action"],
                payload={"area_id": area.get("area_id")},
                timeout=settings.ha_request_timeout_seconds(),
            )
            if not result.get("ok"):
                return "Home Assistant rejected that command."
            acted = result.get("result")
            if isinstance(acted, list) and not acted:
                area_hint = _extract_area_hint(command["target"])
                entity_ids = _match_entities_by_area_hint(
                    entities,
                    domain_hint,
                    area_hint,
                    area_map=area_map,
                    area_names=area_names,
                    upstairs_entities=upstairs_entities,
                    downstairs_entities=downstairs_entities,
                )
                if entity_ids:
                    fallback = ha_client.call_service(
                        base_url=base_url,
                        token=token,
                        domain=domain_hint,
                        service=command["action"],
                        payload={"entity_id": entity_ids},
                        timeout=settings.ha_request_timeout_seconds(),
                    )
                    if not fallback.get("ok"):
                        return "Home Assistant rejected that command."
                    _log_ha_action(
                        conn,
                        command,
                        domain_hint,
                        command["action"],
                        {"entity_id": entity_ids},
                        fallback,
                    )
                    _store_last_target(conn, device, command["target"])
                    return f"Done. {command['action'].replace('_', ' ')} {area_hint} {domain_hint}s."
                return f"I couldn't find any {domain_hint}s in {area.get('name')}."
            _log_ha_action(
                conn,
                command,
                domain_hint,
                command["action"],
                {"area_id": area.get("area_id")},
                result,
            )
            _store_last_target(conn, device, command["target"])
            return f"Done. {command['action'].replace('_', ' ')} {area.get('name')} {domain_hint}s."
        if domain_hint and _wants_area_control(command["target"]) and command["action"] in {
            "turn_on",
            "turn_off",
            "toggle",
        }:
            area_hint = _extract_area_hint(command["target"])
            entity_ids = _match_entities_by_area_hint(
                entities,
                domain_hint,
                area_hint,
                area_map=area_map,
                area_names=area_names,
                upstairs_entities=upstairs_entities,
                downstairs_entities=downstairs_entities,
            )
            if entity_ids:
                if (
                    device
                    and _should_confirm_bulk(command["action"], command["target"], entity_ids)
                ):
                    _store_pending_action(
                        conn,
                        device,
                        {
                            "action": command["action"],
                            "domain": domain_hint,
                            "target": command["target"],
                            "entity_ids": entity_ids,
                        },
                    )
                    return _bulk_action_prompt(
                        entities, entity_ids, command["action"], command["target"]
                    )
                result = ha_client.call_service(
                    base_url=base_url,
                    token=token,
                    domain=domain_hint,
                    service=command["action"],
                    payload={"entity_id": entity_ids},
                    timeout=settings.ha_request_timeout_seconds(),
                )
                if not result.get("ok"):
                    return "Home Assistant rejected that command."
                _log_ha_action(
                    conn,
                    command,
                    domain_hint,
                    command["action"],
                    {"entity_id": entity_ids},
                    result,
                )
                _store_last_target(conn, device, command["target"])
                return f"Done. {command['action'].replace('_', ' ')} {area_hint} {domain_hint}s."
        fuzzy = _fuzzy_match_entity(entities, command["target"], domain_hint=domain_hint)
        if fuzzy:
            entity_id = fuzzy
        else:
            available = ", ".join(list(entities.keys())[:5])
            return f"I couldn't find {command['target']}. I can see: {available}."
    domain = entity_id.split(".", 1)[0]
    action = command["action"]
    service, payload = _ha_service_payload(action, entity_id, command.get("value"))
    if not service:
        return "I couldn't map that command to a Home Assistant service."

    result = ha_client.call_service(
        base_url=base_url,
        token=token,
        domain=domain,
        service=service,
        payload=payload,
        timeout=settings.ha_request_timeout_seconds(),
    )
    if not result.get("ok"):
        return "Home Assistant rejected that command."
    changed = []
    acted = result.get("result")
    if isinstance(acted, list):
        for item in acted:
            eid = item.get("entity_id") if isinstance(item, dict) else None
            if eid:
                changed.append(eid)
    _log_ha_action(conn, command, domain, service, payload, result)
    _store_last_target(conn, device, command["target"])
    _store_entity_synonym(conn, command["target"], entity_id)
    name_hint = ""
    if changed:
        friendly = []
        for eid in changed[:5]:
            attrs = entities.get(eid, {}).get("attributes", {})
            if isinstance(attrs, dict):
                fname = attrs.get("friendly_name")
                if fname:
                    friendly.append(fname)
        joined = ", ".join(friendly) if friendly else ", ".join(changed[:5])
        name_hint = f" ({len(changed)} changed: {joined})"
    profile = _speaker_profile_from_device(conn, device)
    prefix = f"Okay {profile.get('name')}, " if isinstance(profile, dict) and profile.get("name") else ""
    return f"{prefix}Done. {action.replace('_', ' ')} {command['target']}.{name_hint}"


def _pending_proposal_key(device: str) -> str:
    return f"voice.pending_proposal.{device}"


def _load_pending_proposal(conn, device: str | None) -> int | None:
    if not device:
        return None
    value = store.get_memory(conn, _pending_proposal_key(device))
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _store_pending_proposal(conn, device: str | None, proposal_id: int) -> None:
    if not device:
        return
    store.set_memory(conn, _pending_proposal_key(device), proposal_id)


def _clear_pending_proposal(conn, device: str | None) -> None:
    if not device:
        return
    store.set_memory(conn, _pending_proposal_key(device), None)


def _pending_target_key(device: str) -> str:
    return f"voice.pending_target.{device}"


def _load_pending_target(conn, device: str | None) -> Dict[str, Any] | None:
    if not device:
        return None
    value = store.get_memory(conn, _pending_target_key(device))
    return value if isinstance(value, dict) else None


def _store_pending_target(conn, device: str | None, payload: Dict[str, Any]) -> None:
    if not device:
        return
    store.set_memory(conn, _pending_target_key(device), payload)


def _clear_pending_target(conn, device: str | None) -> None:
    if not device:
        return
    store.set_memory(conn, _pending_target_key(device), None)


def _pending_action_key(device: str) -> str:
    return f"voice.pending_action.{device}"


def _load_pending_action(conn, device: str | None) -> Dict[str, Any] | None:
    if not device:
        return None
    value = store.get_memory(conn, _pending_action_key(device))
    return value if isinstance(value, dict) else None


def _store_pending_action(conn, device: str | None, payload: Dict[str, Any]) -> None:
    if not device:
        return
    store.set_memory(conn, _pending_action_key(device), payload)


def _clear_pending_action(conn, device: str | None) -> None:
    if not device:
        return
    store.set_memory(conn, _pending_action_key(device), None)


def _handle_proposal_followup(text: str, device: str | None, conn) -> str | None:
    decision = intent.parse_affirmation(text)
    if decision not in {"yes", "no"}:
        return None
    proposal_id = _load_pending_proposal(conn, device)
    if not proposal_id:
        return None
    policy = policy_mod.load_policy(str(settings.policy_path()))
    status = "approved" if decision == "yes" else "rejected"
    store.insert_approval(
        conn,
        proposal_id=proposal_id,
        actor="voice",
        decision=status,
        reason="voice follow-up",
        policy_hash=policy.policy_hash,
    )
    store.update_proposal_status(conn, proposal_id, status)
    _clear_pending_proposal(conn, device)
    if status == "approved":
        return f"Approved proposal #{proposal_id}. I'll start the install."
    return f"Rejected proposal #{proposal_id}."


def _handle_target_followup(text: str, device: str | None, conn) -> str | None:
    pending = _load_pending_target(conn, device)
    if not pending:
        return None
    choices = pending.get("choices")
    if not isinstance(choices, list) or not choices:
        _clear_pending_target(conn, device)
        return None
    normalized = text.strip().lower()
    if normalized in {"cancel", "never mind", "nevermind", "stop"}:
        _clear_pending_target(conn, device)
        return "Okay, cancelled."
    index = None
    ordinal_map = {
        "first": 0,
        "1": 0,
        "one": 0,
        "second": 1,
        "2": 1,
        "two": 1,
        "third": 2,
        "3": 2,
        "three": 2,
    }
    for token, idx in ordinal_map.items():
        if token in normalized:
            index = idx
            break
    if index is None:
        for idx, choice in enumerate(choices):
            label = str(choice.get("label", "")).lower()
            entity_id = str(choice.get("entity_id", "")).lower()
            if label and label in normalized:
                index = idx
                break
            if entity_id and entity_id in normalized:
                index = idx
                break
    if index is None or index >= len(choices):
        labels = [str(choice.get("label") or choice.get("entity_id")) for choice in choices[:5]]
        joined = ", ".join(labels)
        return f"Which one did you mean? Options: {joined}."
    base_url, token, error = _load_ha_connection(conn)
    if error:
        _clear_pending_target(conn, device)
        return error
    choice = choices[index]
    entity_id = choice.get("entity_id")
    if not isinstance(entity_id, str):
        _clear_pending_target(conn, device)
        return "I couldn't resolve that device."
    action = pending.get("action")
    value = pending.get("value")
    service, payload = _ha_service_payload(str(action), entity_id, value if isinstance(value, int) else None)
    if not service:
        _clear_pending_target(conn, device)
        return "I couldn't map that follow-up command."
    result = ha_client.call_service(
        base_url=base_url,
        token=token,
        domain=entity_id.split(".", 1)[0],
        service=service,
        payload=payload,
        timeout=settings.ha_request_timeout_seconds(),
    )
    _clear_pending_target(conn, device)
    if not result.get("ok"):
        return "Home Assistant rejected that command."
    _store_last_target(conn, device, pending.get("target") or entity_id)
    label = choice.get("label") or entity_id
    return f"Done. {service.replace('_', ' ')} {label}."


def _should_confirm_bulk(action: str, target: str, entity_ids: List[str]) -> bool:
    if action not in {"turn_on", "turn_off", "toggle"}:
        return False
    if len(entity_ids) >= 3:
        return True
    lowered = target.lower()
    return "all" in lowered or "everything" in lowered


def _handle_action_confirmation(text: str, device: str | None, conn) -> str | None:
    pending = _load_pending_action(conn, device)
    if not pending:
        return None
    decision = intent.parse_affirmation(text)
    if decision not in {"yes", "no"}:
        return None
    _clear_pending_action(conn, device)
    if decision == "no":
        return "Okay, cancelled."
    command_text = pending.get("command_text")
    if isinstance(command_text, str) and command_text.strip():
        return _execute_ha_command(command_text.strip(), conn, device) or "Done."
    base_url, token, error = _load_ha_connection(conn)
    if error:
        return error
    entity_ids = pending.get("entity_ids")
    if not isinstance(entity_ids, list) or not entity_ids:
        return "I couldn't find any devices to act on."
    domain = pending.get("domain")
    if not isinstance(domain, str):
        domain = str(entity_ids[0]).split(".", 1)[0]
    action = pending.get("action")
    service, payload = _ha_service_payload(str(action), entity_ids[0], None)
    if not service:
        return "I couldn't map that command to a Home Assistant service."
    payload = {"entity_id": entity_ids}
    result = ha_client.call_service(
        base_url=base_url,
        token=token,
        domain=domain,
        service=service,
        payload=payload,
        timeout=settings.ha_request_timeout_seconds(),
    )
    if not result.get("ok"):
        return "Home Assistant rejected that command."
    return f"Done. {service.replace('_', ' ')} {pending.get('target', 'devices')}."


def _ensure_proposal_rigor(proposal: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(proposal, dict):
        return proposal
    item = dict(proposal)
    kind = item.get("kind", "general")
    summary = item.get("summary") or "proposal"
    details = item.get("details") if isinstance(item.get("details"), dict) else {}
    defaults = {
        "implementation": "Execute the plan as described.",
        "verification": "Confirm the expected outcome and review logs.",
        "rollback_plan": "Revert or disable the change if verification fails.",
    }
    if kind == "module.install":
        defaults.update(
            {
                "implementation": "Follow the module runbook and apply config changes.",
                "verification": "Confirm the module is enabled and health checks pass.",
                "rollback_plan": "Disable the module and revert config to the previous state.",
            }
        )
    if kind == "policy.change":
        defaults.update(
            {
                "implementation": "Apply the policy change through the policy CLI.",
                "verification": "Confirm the policy diff applied and no validation errors.",
                "rollback_plan": "Restore the previous policy snapshot.",
            }
        )
    for key, value in defaults.items():
        if not isinstance(details.get(key), str) or not str(details.get(key)).strip():
            details[key] = value
    if not isinstance(details.get("rationale"), str) or not str(details.get("rationale")).strip():
        details["rationale"] = summary or "Provide a clear rationale for this proposal."
    item["details"] = details
    steps = item.get("steps")
    if not isinstance(steps, list):
        steps = []
    if kind == "action.request" and not steps:
        steps = [
            "Execute the action using the provided parameters.",
            "Verify the expected outcome and check logs.",
            "Rollback the change if verification fails.",
        ]
    if steps:
        normalized = " ".join(steps).lower()
        if "verify" not in normalized:
            steps.append("Verify the expected outcome and check logs.")
        if "rollback" not in normalized:
            steps.append("Rollback the change if verification fails.")
    item["steps"] = steps
    return item


def _is_capability_request(text: str) -> bool:
    lowered = text.lower()
    triggers = [
        "install",
        "set up",
        "setup",
        "enable",
        "add capability",
        "add a capability",
        "add module",
        "integrate",
        "connect",
        "capability",
        "module",
        "face recognition",
        "play music",
        "music playback",
    ]
    return any(token in lowered for token in triggers)


def _record_voice_proposals(conn, proposals: list[dict[str, Any]]) -> list[tuple[int, dict[str, Any]]]:
    policy = policy_mod.load_policy(str(settings.policy_path()))
    created: list[tuple[int, dict[str, Any]]] = []
    module_install_ids: Dict[str, int] = {}
    ordered = sorted(proposals, key=lambda p: 0 if p.get("kind") == "module.install" else 1)
    for proposal in ordered:
        proposal = _ensure_proposal_rigor(proposal)
        summary = proposal.get("summary", "")
        if summary and store.proposal_exists(conn, summary, statuses=["pending", "approved"]):
            existing_id = _find_pending_proposal_id(conn, summary)
            if existing_id:
                created.append((existing_id, proposal))
            continue
        details = proposal.get("details", {})
        link_key = proposal.get("link_key")
        if proposal.get("kind") == "capability.offer" and link_key in module_install_ids:
            details = dict(details)
            details["runbook_hint"] = (
                f"Run: python3 -m pumpkin modules runbook --proposal {module_install_ids[link_key]}"
            )
            proposal = dict(proposal)
            proposal["details"] = details

        proposal_id = store.insert_proposal(
            conn,
            kind=proposal.get("kind", "general"),
            summary=proposal.get("summary", "proposal"),
            details=proposal.get("details", {}),
            steps=proposal.get("steps"),
            risk=float(proposal.get("risk", 0.5)),
            expected_outcome=proposal.get("expected_outcome", "Human review"),
            status="pending",
            policy_hash=policy.policy_hash,
            needs_new_capability=proposal.get("needs_new_capability", False),
            capability_request=proposal.get("capability_request"),
            ai_context_hash=proposal.get("ai_context_hash"),
            ai_context_excerpt=proposal.get("ai_context_excerpt"),
        )
        if proposal.get("kind") == "module.install" and link_key:
            module_install_ids[link_key] = proposal_id
        created.append((proposal_id, proposal))
        _maybe_auto_approve_action_proposal(conn, policy, proposal_id, proposal)
    return created


def _maybe_auto_approve_action_proposal(
    conn, policy: policy_mod.Policy, proposal_id: int, proposal: Dict[str, Any]
) -> bool:
    if proposal.get("kind") != "action.request":
        return False
    details = proposal.get("details", {})
    if not isinstance(details, dict):
        return False
    action_type = details.get("action_type")
    action_params = details.get("action_params", {})
    if not isinstance(action_type, str) or not isinstance(action_params, dict):
        return False
    try:
        decision = policy_mod.evaluate_action(
            policy, action_type, action_params, risk=proposal.get("risk")
        )
    except Exception:
        return False
    if decision != "auto_approve":
        return False
    if not store.approval_exists(conn, proposal_id, "approved"):
        store.insert_approval(
            conn,
            proposal_id=proposal_id,
            actor="policy.auto",
            decision="approved",
            reason="auto_approved_low_risk",
            policy_hash=policy.policy_hash,
        )
    store.update_proposal_status(conn, proposal_id, "approved")
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "proposal.auto_approved",
            "proposal_id": proposal_id,
            "action_type": action_type,
            "policy_hash": policy.policy_hash,
        },
    )
    return True

def _find_pending_proposal_id(conn, summary: str) -> int | None:
    if not summary:
        return None
    row = conn.execute(
        "SELECT id FROM proposals WHERE summary = ? AND status IN ('pending','approved') "
        "ORDER BY ts_created DESC LIMIT 1",
        (summary,),
    ).fetchone()
    if row and row[0]:
        return int(row[0])
    return None


def _maybe_capability_proposal(text: str, device: str | None, client_ip: str | None, conn) -> str | None:
    if not _is_capability_request(text):
        return None
    payload = {
        "text": text,
        "device_id": device,
        "client_ip": client_ip,
    }
    fake_row = {
        "id": 0,
        "type": "voice.command",
        "payload_json": json.dumps(payload, ensure_ascii=True),
    }
    proposals = propose._rule_based_proposals([fake_row], conn)
    proposals = [_ensure_proposal_rigor(item) for item in proposals if isinstance(item, dict)]
    created = _record_voice_proposals(conn, proposals)
    if not created:
        return "I couldn't draft a proposal for that yet."
    preferred = None
    for proposal_id, proposal in created:
        if proposal.get("kind") == "module.install":
            preferred = (proposal_id, proposal)
            break
    if preferred is None:
        for proposal_id, proposal in created:
            if proposal.get("kind") == "capability.offer":
                preferred = (proposal_id, proposal)
                break
    if preferred is None:
        preferred = created[0]
    proposal_id, proposal = preferred
    _store_pending_proposal(conn, device, proposal_id)
    details = proposal.get("details", {}) if isinstance(proposal.get("details"), dict) else {}
    rationale = details.get("rationale")
    summary = proposal.get("summary", "Proposal ready")
    suggestions = _suggest_capability_modules(text)
    suggestion_text = ""
    if suggestions:
        suggestion_text = " Suggested modules: " + ", ".join(suggestions) + "."
    if rationale:
        return (
            f"Proposal #{proposal_id}: {summary}. "
            f"Rationale: {rationale}.{suggestion_text} Reply yes to approve or no to skip."
        )
    return f"Proposal #{proposal_id}: {summary}.{suggestion_text} Reply yes to approve or no to skip."


def _recent_query(text: str) -> bool:
    lowered = text.lower()
    return bool(
        "what changed" in lowered
        or "recent events" in lowered
        or "last events" in lowered
        or "last thing" in lowered
    )


def _inventory_query(text: str) -> bool:
    lowered = text.lower()
    return bool(
        "list doors" in lowered
        or "list windows" in lowered
        or "which lights are on" in lowered
        or "what lights are on" in lowered
        or "lights are on" in lowered
        or "lights on" in lowered
    )


def _memory_query(text: str) -> bool:
    lowered = text.lower()
    return bool(
        "what do you know about me" in lowered
        or "what do you remember about me" in lowered
        or "forget me" in lowered
        or "forget everything" in lowered
    )


def _suggest_capability_modules(text: str) -> List[str]:
    registry = module_registry.load_registry(str(settings.modules_registry_path()))
    registry_summary = module_registry.registry_summary(registry)
    catalog_summary: List[Dict[str, Any]] = []
    catalog_path = settings.modules_catalog_path()
    if catalog_path.exists():
        try:
            catalog = catalog_mod.load_catalog(str(catalog_path))
            for entry in catalog.get("modules", []):
                if isinstance(entry, dict):
                    catalog_summary.append(
                        {
                            "name": entry.get("name"),
                            "description": entry.get("description"),
                        }
                    )
        except Exception:
            catalog_summary = []
    suggestions = intent.suggest_modules(text, registry_summary + catalog_summary)
    unique = []
    seen = set()
    for name in suggestions:
        if name not in seen:
            unique.append(name)
            seen.add(name)
    return unique[:4]


def _health_query(text: str) -> bool:
    lowered = text.lower()
    return bool(
        "system health" in lowered
        or "health report" in lowered
        or "risk report" in lowered
        or "status report" in lowered
    )


def _parse_time_24h(value: str) -> str | None:
    raw = value.strip().lower()
    digits = re.sub(r"[^0-9]", "", raw)
    if digits and len(digits) in {3, 4}:
        if len(digits) == 3:
            hour = int(digits[0])
            minute = int(digits[1:])
        else:
            hour = int(digits[:2])
            minute = int(digits[2:])
        if hour > 23 or minute > 59:
            return None
        return f"{hour:02d}:{minute:02d}"
    match = re.search(r"(\d{1,2})(?::(\d{2}))?\s*(am|pm)?", raw)
    if not match:
        return None
    hour = int(match.group(1))
    minute = int(match.group(2) or 0)
    meridiem = match.group(3)
    if meridiem:
        if meridiem == "pm" and hour < 12:
            hour += 12
        if meridiem == "am" and hour == 12:
            hour = 0
    if hour > 23 or minute > 59:
        return None
    return f"{hour:02d}:{minute:02d}"


def _parse_quiet_hours(text: str) -> Dict[str, Any] | None:
    lowered = text.lower()
    if "quiet hours" not in lowered and "do not disturb" not in lowered and "dnd" not in lowered:
        return None
    pattern = re.compile(
        r"(?:from|between)?\s*"
        r"(\d{1,4}(?::\d{2})?\s*(?:am|pm)?)\s*"
        r"(?:to|till|and|-)\s*"
        r"(\d{1,4}(?::\d{2})?\s*(?:am|pm)?)"
    )
    windows = []
    for match in pattern.finditer(lowered):
        start = _parse_time_24h(match.group(1))
        end = _parse_time_24h(match.group(2))
        if not start or not end:
            continue
        tail = lowered[match.end() : match.end() + 24]
        day_token = ""
        if "weekday" in tail:
            day_token = "weekdays"
        elif "weekend" in tail:
            day_token = "weekends"
        windows.append({"start": start, "end": end, "days": day_token or None})
    if not windows:
        return None
    has_weekday = "weekday" in lowered
    has_weekend = "weekend" in lowered
    if has_weekday and has_weekend and len(windows) >= 2:
        if windows[0].get("days") is None:
            windows[0]["days"] = "weekdays"
        if windows[1].get("days") is None:
            windows[1]["days"] = "weekends"
    for window in windows:
        if not window.get("days"):
            if has_weekday and not has_weekend:
                window["days"] = "weekdays"
            elif has_weekend and not has_weekday:
                window["days"] = "weekends"
            else:
                window["days"] = "daily"
    if len(windows) == 1:
        return windows[0]
    return {"windows": windows}


def _parse_notification_style(text: str) -> str | None:
    lowered = text.lower()
    if "notification" not in lowered and "notifications" not in lowered:
        return None
    if "brief" in lowered:
        return "brief"
    if "detailed" in lowered or "detail" in lowered:
        return "detailed"
    if "normal" in lowered or "standard" in lowered:
        return "normal"
    return None


def _build_llm_context(conn, device: str | None) -> Dict[str, Any]:
    snapshot_event = _latest_event(conn, "system.snapshot")
    system_snapshot = snapshot_event.get("payload") if snapshot_event else None
    issues = _summarize_issues(system_snapshot)
    ha_summary = store.get_memory(conn, "homeassistant.summary") or {}
    trimmed_ha = {
        "people_home": ha_summary.get("people_home") or [],
        "people": ha_summary.get("people") or [],
        "zones": ha_summary.get("zones") or [],
        "calendars": ha_summary.get("calendars") or [],
        "upcoming_events": (ha_summary.get("upcoming_events") or [])[:5],
        "last_event": store.get_memory(conn, "homeassistant.last_event"),
    }
    pending = store.list_proposals(conn, status="pending", limit=5)
    errors = _latest_errors(conn, limit=3)
    profile = _speaker_profile_from_device(conn, device)
    profile_summary = None
    if isinstance(profile, dict):
        profile_summary = {
            "name": profile.get("name"),
            "ha_person_id": profile.get("ha_person_id"),
            "preferences": profile.get("preferences", {}),
            "voice_recognition_opt_in": profile.get("voice_recognition_opt_in", False),
            "last_seen_ts": profile.get("last_seen_ts"),
            "turns_count": profile.get("turns_count"),
            "last_device": profile.get("last_device"),
        }
    memory_key = _conversation_key(device, profile)
    memory_snapshot = None
    if memory_key:
        stored = store.get_memory(conn, memory_key)
        if isinstance(stored, dict):
            memory_snapshot = {
                "summary": stored.get("summary"),
                "facts": stored.get("facts"),
                "facts_count": len(stored.get("facts") or []),
                "turns": stored.get("turns"),
                "last_updated": stored.get("updated_ts"),
            }
    return {
        "system_snapshot": system_snapshot,
        "issues": issues,
        "homeassistant": trimmed_ha,
        "capabilities_snapshot": capabilities.snapshot(conn),
        "pending_proposals": [
            {"id": row["id"], "summary": row["summary"], "kind": row["kind"]}
            for row in pending
        ],
        "recent_errors": errors,
        "speaker_profile": profile_summary,
        "conversation_memory": memory_snapshot,
    }


def _identity_snapshot(conn, device: str | None) -> Dict[str, Any]:
    profile = _speaker_profile_from_device(conn, device)
    profile_summary = None
    if isinstance(profile, dict):
        profile_summary = {
            "name": profile.get("name"),
            "ha_person_id": profile.get("ha_person_id"),
            "ha_user_id": profile.get("ha_user_id"),
            "preferences": profile.get("preferences", {}),
            "created_ts": profile.get("created_ts"),
            "last_seen_ts": profile.get("last_seen_ts"),
            "turns_count": profile.get("turns_count"),
            "last_device": profile.get("last_device"),
        }
    memory_key = _conversation_key(device, profile)
    memory_summary = None
    if memory_key:
        stored = store.get_memory(conn, memory_key)
        if isinstance(stored, dict):
            memory_summary = {
                "summary": stored.get("summary"),
                "facts": stored.get("facts"),
                "facts_count": len(stored.get("facts") or []),
                "turns": stored.get("turns"),
                "last_updated": stored.get("updated_ts"),
            }
    return {
        "device": device,
        "profile": profile_summary,
        "memory": memory_summary,
    }


def _memory_snapshot(conn, device: str | None) -> Dict[str, Any]:
    profile = _speaker_profile_from_device(conn, device)
    memory_key = _conversation_key(device, profile)
    memory = None
    if memory_key:
        stored = store.get_memory(conn, memory_key)
        if isinstance(stored, dict):
            memory = {
                "summary": stored.get("summary"),
                "facts": stored.get("facts") or [],
                "recent": stored.get("recent") or [],
                "turns": stored.get("turns"),
                "last_updated": stored.get("updated_ts"),
            }
    return {
        "device": device,
        "profile": profile,
        "memory": memory,
    }


def _parse_speaker_name(text: str) -> str | None:
    match = re.search(r"\b(?:i am|i'm|my name is|this is)\s+([a-zA-Z][a-zA-Z\\-\\s']{0,60})$", text.strip(), re.IGNORECASE)
    if not match:
        return None
    name = " ".join(match.group(1).strip().split())
    return name[:80] if name else None


def _local_status_reply(conn) -> str:
    snapshot_event = _latest_event(conn, "system.snapshot")
    system_snapshot = snapshot_event.get("payload") if snapshot_event else None
    issues = _summarize_issues(system_snapshot)
    ha_summary = store.get_memory(conn, "homeassistant.summary") or {}
    people_home = ha_summary.get("people_home") or []
    if issues:
        issue_text = "; ".join(issue.get("message", "issue") for issue in issues)
        return f"I see some issues: {issue_text}"
    if people_home:
        return f"All looks good. People home: {', '.join(people_home)}."
    return "All looks good. No issues detected."


def _local_home_reply(conn) -> str | None:
    ha_summary = store.get_memory(conn, "homeassistant.summary") or {}
    people_home = ha_summary.get("people_home") or []
    if not people_home:
        return "No one is marked as home."
    if len(people_home) == 1:
        return f"{people_home[0]} is home."
    return f"People home: {', '.join(people_home)}."


def _update_profile_preference(conn, device: str | None, key: str, value: Any) -> str | None:
    profile = _speaker_profile_from_device(conn, device)
    if not isinstance(profile, dict):
        if key == "quiet_hours":
            store.set_memory(conn, "core.quiet_hours", value)
            return None
        return "I don't know who this device belongs to yet. Tell me your name first."
    prefs = profile.get("preferences", {})
    if not isinstance(prefs, dict):
        prefs = {}
    prefs[key] = value
    profile["preferences"] = prefs
    store.set_memory(conn, f"speaker.profile.device:{device.strip()}", profile)
    ha_user_id = profile.get("ha_user_id")
    if isinstance(ha_user_id, str) and ha_user_id.strip():
        user_profile = _load_ha_user_profile(conn, ha_user_id) or {}
        merged = _merge_profiles(user_profile, profile)
        _save_ha_user_profile(conn, ha_user_id, merged)
    if key == "quiet_hours":
        store.set_memory(conn, "core.quiet_hours", value)
    return None


def _store_speaker_name(conn, device: str | None, name: str) -> str | None:
    if not isinstance(device, str) or not device.strip():
        return "I need a device ID to remember you."
    key = f"speaker.profile.device:{device.strip()}"
    profile = store.get_memory(conn, key)
    if not isinstance(profile, dict):
        profile = {
            "state": "named",
            "consent": True,
            "preferences": {},
        }
    profile["name"] = name
    profile["state"] = "named"
    if not profile.get("created_ts"):
        profile["created_ts"] = datetime.now(timezone.utc).isoformat()
    profile["last_seen_ts"] = datetime.now(timezone.utc).isoformat()
    store.set_memory(conn, key, profile)
    ha_user_id = profile.get("ha_user_id")
    if isinstance(ha_user_id, str) and ha_user_id.strip():
        user_profile = _load_ha_user_profile(conn, ha_user_id) or {}
        merged = _merge_profiles(user_profile, profile)
        _save_ha_user_profile(conn, ha_user_id, merged)
    return None


def _handle_preference_update(text: str, device: str | None, conn) -> str | None:
    quiet = _parse_quiet_hours(text)
    if quiet:
        error = _update_profile_preference(conn, device, "quiet_hours", quiet)
        if error:
            return error
        if isinstance(quiet, dict) and "windows" in quiet:
            parts = []
            for window in quiet.get("windows", []):
                if not isinstance(window, dict):
                    continue
                parts.append(f"{window.get('start')}–{window.get('end')} ({window.get('days')})")
            if parts:
                return "Quiet hours set to " + "; ".join(parts) + "."
        return f"Quiet hours set to {quiet['start']}–{quiet['end']} ({quiet['days']})."
    lowered = text.lower()
    if "quiet hours" in lowered or "do not disturb" in lowered or "dnd" in lowered:
        return "Tell me the time window, e.g. 'quiet hours 21:00 to 06:00 weekdays'."
    style = _parse_notification_style(text)
    if style:
        error = _update_profile_preference(conn, device, "notification_style", style)
        if error:
            return error
        return f"Notification style set to {style}."
    return None


def _friendly_entity_name(entity_id: str, payload: Dict[str, Any]) -> str:
    attributes = payload.get("attributes", {}) if isinstance(payload, dict) else {}
    name = attributes.get("friendly_name") if isinstance(attributes, dict) else None
    return str(name or entity_id)


def _extract_entities(conn) -> Dict[str, Dict[str, Any]]:
    entities = store.get_memory(conn, "homeassistant.entities")
    if isinstance(entities, dict):
        return entities
    return {}


def _entity_matches(payload: Dict[str, Any], device_class: str) -> bool:
    attributes = payload.get("attributes", {}) if isinstance(payload, dict) else {}
    if not isinstance(attributes, dict):
        return False
    return attributes.get("device_class") == device_class


def _collect_entities(entities: Dict[str, Dict[str, Any]], domain: str, device_class: str | None) -> List[str]:
    matched: List[str] = []
    for entity_id, payload in entities.items():
        if not isinstance(entity_id, str):
            continue
        if not entity_id.startswith(domain + "."):
            continue
        if device_class and not _entity_matches(payload, device_class):
            continue
        state = payload.get("state")
        if state != "on":
            continue
        matched.append(_friendly_entity_name(entity_id, payload))
    return matched


def _home_state_summary(conn) -> Dict[str, Any]:
    ha_summary = store.get_memory(conn, "homeassistant.summary") or {}
    people_home = ha_summary.get("people_home") or []
    entities = _extract_entities(conn)
    doors_open = _collect_entities(entities, "binary_sensor", "door")
    windows_open = _collect_entities(entities, "binary_sensor", "window")
    motion_active = _collect_entities(entities, "binary_sensor", "motion")
    lights_on = _collect_entities(entities, "light", None)
    return {
        "people_home": people_home,
        "doors_open": doors_open,
        "windows_open": windows_open,
        "motion_active": motion_active,
        "lights_on": lights_on,
    }


def _home_state_suggestions(summary: Dict[str, Any]) -> List[str]:
    suggestions: List[str] = []
    doors_open = summary.get("doors_open") or []
    windows_open = summary.get("windows_open") or []
    motion_active = summary.get("motion_active") or []
    people_home = summary.get("people_home") or []
    if doors_open or windows_open:
        suggestions.append("Check open doors or windows.")
    if not people_home and (doors_open or windows_open):
        suggestions.append("No one is home but an entry is open.")
    if not people_home and motion_active:
        suggestions.append("Motion detected while no one is home.")
    return suggestions


def _local_house_summary_reply(conn) -> str:
    summary = _home_state_summary(conn)
    people_home = summary.get("people_home") or []
    doors_open = summary.get("doors_open") or []
    windows_open = summary.get("windows_open") or []
    motion_active = summary.get("motion_active") or []
    lights_on = summary.get("lights_on") or []
    parts = []
    if people_home:
        parts.append(f"People home: {', '.join(people_home)}")
    else:
        parts.append("No one is marked as home")
    if doors_open:
        parts.append(f"Doors open: {', '.join(doors_open)}")
    if windows_open:
        parts.append(f"Windows open: {', '.join(windows_open)}")
    if motion_active:
        parts.append(f"Motion active: {', '.join(motion_active)}")
    if lights_on:
        parts.append(f"Lights on: {', '.join(lights_on)}")
    suggestions = _home_state_suggestions(summary)
    if suggestions:
        parts.append(f"Suggestions: {', '.join(suggestions)}")
    return ". ".join(parts) + "."


def _recent_events_reply(conn, limit: int = 5) -> str:
    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    if not rows:
        return "No recent events recorded."
    summaries = []
    for row in rows:
        summaries.append(f"{row['type']} from {row['source']} at {row['ts']}")
    return "Recent events: " + "; ".join(summaries)


def _last_ha_event_reply(conn) -> str:
    last_event = store.get_memory(conn, "homeassistant.last_event")
    if not isinstance(last_event, dict):
        return "No recent Home Assistant event recorded."
    event_type = last_event.get("event_type") or "event"
    payload = last_event.get("payload") or {}
    entity_id = payload.get("entity_id")
    state = payload.get("state")
    if entity_id and state is not None:
        return f"Last HA event: {event_type} for {entity_id} => {state}."
    return f"Last HA event: {event_type}."


def _inventory_reply(conn, text: str) -> str:
    entities = _extract_entities(conn)
    lowered = text.lower()
    if "door" in lowered:
        doors = _collect_entities(entities, "binary_sensor", "door")
        return "Open doors: " + (", ".join(doors) if doors else "none.")
    if "window" in lowered:
        windows = _collect_entities(entities, "binary_sensor", "window")
        return "Open windows: " + (", ".join(windows) if windows else "none.")
    if "light" in lowered:
        lights = _collect_entities(entities, "light", None)
        return "Lights on: " + (", ".join(lights) if lights else "none.")
    return "I couldn't find matching devices."


def _health_report_reply(conn) -> str:
    snapshot_event = _latest_event(conn, "system.snapshot")
    system_snapshot = snapshot_event.get("payload") if snapshot_event else None
    issues = _summarize_issues(system_snapshot)
    ha_summary = store.get_memory(conn, "homeassistant.summary") or {}
    calendar_error = ha_summary.get("calendar_error")
    parts = []
    if issues:
        parts.append("Issues: " + "; ".join(issue.get("message", "issue") for issue in issues))
    else:
        parts.append("No system issues detected.")
    if calendar_error:
        parts.append(f"Calendar error: {calendar_error}.")
    # Add quick telemetry snapshot
    metrics = telemetry.collect_health_metrics()
    parts.append(
        f"Metrics: cpu_load_1m={metrics.get('cpu_load_1m')} "
        f"mem_avail_kb={metrics.get('memory', {}).get('available_kb')} "
        f"disk_used_pct={metrics.get('disk', {}).get('used_percent')}"
    )
    return " ".join(parts)


def _memory_reply(conn, device: str | None, text: str) -> str:
    lowered = text.lower()
    if "forget" in lowered:
        if not isinstance(device, str) or not device.strip():
            return "I need a device ID to forget you."
        profile = _speaker_profile_from_device(conn, device)
        store.set_memory(conn, f"speaker.profile.device:{device.strip()}", {"state": "guest"})
        key = _conversation_key(device, profile)
        if key:
            store.set_memory(conn, key, None)
        return "Done. I've cleared what I stored about you."
    profile = _speaker_profile_from_device(conn, device)
    if not isinstance(profile, dict):
        return "I don't have a profile stored for you yet."
    summary = {
        "name": profile.get("name"),
        "preferences": profile.get("preferences", {}),
        "ha_person_id": profile.get("ha_person_id"),
    }
    return f"Here's what I remember: {json.dumps(summary, ensure_ascii=True)}"


def _lookup_calendar(text: str, device: str | None, conn) -> str | None:
    lowered = text.lower()
    has_calendar_keyword = bool(
        re.search(r"\b(calendar|schedule|agenda|appointments|events|availability|free|busy)\b", lowered)
    )
    has_availability = bool(re.search(r"\bfree\b|\bbusy\b|\bavailable\b", lowered))
    availability_at = _availability_time(lowered)
    has_whats_on = bool(re.search(r"\bwhat('?s| is)\s+on\b", lowered))
    if not has_calendar_keyword and not has_whats_on:
        return None
    summary = store.get_memory(conn, "homeassistant.summary")
    if not isinstance(summary, dict):
        return "Home Assistant calendar data is not available yet."
    calendars = summary.get("calendars") or []
    events_by_calendar = summary.get("calendar_events") or {}
    config_path = settings.modules_config_path()
    calendar_people: dict[str, str] = {}
    calendar_shared: list[str] = []
    if config_path.exists():
        try:
            config = module_config.load_config(str(config_path))
            module_cfg = config.get("modules", {}).get("homeassistant.observer", {})
            calendar_people = module_cfg.get("calendar_people") or {}
            calendar_shared = module_cfg.get("calendar_shared") or []
        except Exception:
            calendar_people = {}
            calendar_shared = []

    target_label = None
    target_calendar = None

    if "family" in lowered or "shared" in lowered:
        if calendar_shared:
            target_calendar = calendar_shared[0]
        elif calendars:
            target_calendar = calendars[0].get("entity_id")
        target_label = "the family calendar"
    elif "my " in lowered or "mine" in lowered:
        profile = _speaker_profile_from_device(conn, device)
        person_id = profile.get("ha_person_id") if profile else None
        if isinstance(person_id, str):
            target_calendar = calendar_people.get(person_id)
            target_label = profile.get("ha_person_name") or "your calendar"
        else:
            return "I don't know which Home Assistant person you are yet. Tell me your name first."
    else:
        match = re.search(r"\b(?:is|isn't|is not)\s+([a-zA-Z]+)\s+(?:free|busy|available)\b", lowered)
        if not match:
            match = re.search(r"\b([a-zA-Z]+)'s\s+calendar\b", lowered)
        if match:
            name = match.group(1).lower()
            people = summary.get("people") or []
            person_id = None
            person_name = None
            for person in people:
                if not isinstance(person, dict):
                    continue
                pname = str(person.get("name") or "").lower()
                pid = str(person.get("entity_id") or "").lower()
                tail = pid.split(".", 1)[-1] if "." in pid else pid
                if name in {pname, pid, tail}:
                    person_id = person.get("entity_id")
                    person_name = person.get("name") or name
                    break
            profile = _speaker_profile_from_device(conn, device)
            self_id = profile.get("ha_person_id") if profile else None
            if person_id and self_id and person_id != self_id:
                return "I can only share your own calendar right now."
            if person_id:
                target_calendar = calendar_people.get(person_id)
                target_label = person_name or "calendar"
        elif has_whats_on or "today" in lowered or "tomorrow" in lowered or "this week" in lowered:
            profile = _speaker_profile_from_device(conn, device)
            person_id = profile.get("ha_person_id") if profile else None
            if isinstance(person_id, str):
                target_calendar = calendar_people.get(person_id)
                target_label = profile.get("ha_person_name") or "your calendar"
            if not target_calendar and calendar_shared:
                target_calendar = calendar_shared[0]
                target_label = "the family calendar"
            if not target_calendar and calendars:
                target_calendar = calendars[0].get("entity_id")
                target_label = calendars[0].get("name") or "the calendar"

    if not target_calendar:
        return "I couldn't find a calendar for that request yet."

    calendar_events = events_by_calendar.get(target_calendar) or []
    if has_availability and availability_at:
        busy = _is_busy_at(calendar_events, availability_at)
        when = availability_at.strftime("%H:%M %Z").strip()
        if busy:
            return f"{target_label or 'That calendar'} looks busy at {when}."
        return f"{target_label or 'That calendar'} looks free at {when}."
    events = _select_events(calendar_events, text)
    label = target_label or target_calendar
    return _calendar_reply_for_events(label, events, text)


def _lookup_presence(text: str) -> str | None:
    match = re.search(r"\b(?:is|where is)\s+([a-zA-Z]+)\b", text, re.IGNORECASE)
    if not match:
        return None
    name = match.group(1).lower()
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return None
    try:
        config = module_config.load_config(str(config_path))
    except Exception:
        return None
    enabled = set(config.get("enabled", []))
    if "homeassistant.observer" not in enabled:
        return None
    module_cfg = config.get("modules", {}).get("homeassistant.observer", {})
    people = module_cfg.get("people", {})
    entity_id = None
    if isinstance(people, dict):
        entity_id = people.get(name)
    if not isinstance(entity_id, str):
        summary = store.get_memory(init_db(str(settings.db_path()), str(settings.repo_root() / "migrations")), "homeassistant.summary")
        if isinstance(summary, dict):
            for person in summary.get("people", []) or []:
                if not isinstance(person, dict):
                    continue
                pname = str(person.get("name") or "").lower()
                pid = str(person.get("entity_id") or "").lower()
                tail = pid.split(".", 1)[-1] if "." in pid else pid
                if name in {pname, pid, tail}:
                    entity_id = person.get("entity_id")
                    state = person.get("state")
                    if isinstance(state, str):
                        if state == "home":
                            return f"{match.group(1).capitalize()} is home."
                        if state == "not_home":
                            return f"{match.group(1).capitalize()} is not home."
                        return f"{match.group(1).capitalize()} is {state}."
                    break
    if not isinstance(entity_id, str):
        return None
    base_url = module_cfg.get("base_url")
    token_env = module_cfg.get("token_env", "PUMPKIN_HA_TOKEN")
    token = os.getenv(token_env)
    if not base_url or not token:
        return None
    result = ha_client.fetch_entity_state(
        base_url=base_url,
        token=token,
        entity_id=entity_id,
        timeout=settings.ha_request_timeout_seconds(),
    )
    if not result.get("ok"):
        return "I couldn't reach Home Assistant to check presence."
    state = result.get("state")
    if state == "home":
        return f"{match.group(1).capitalize()} is home."
    if state == "not_home":
        return f"{match.group(1).capitalize()} is not home."
    if isinstance(state, str):
        return f"{match.group(1).capitalize()} is {state}."
    return "I couldn't determine presence."


def _coerce_ha_event_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    event_type = data.get("event_type") or data.get("type")
    payload = data.get("data") if isinstance(data.get("data"), dict) else {}
    if not payload:
        payload = {
            "entity_id": data.get("entity_id"),
            "state": data.get("state"),
            "attributes": data.get("attributes"),
        }
    return {
        "event_type": event_type,
        "origin": data.get("origin"),
        "time_fired": data.get("time_fired"),
        "payload": payload,
    }


def _record_ha_event(conn, data: Dict[str, Any]) -> int:
    payload = _coerce_ha_event_payload(data)
    event_id = store.insert_event(
        conn,
        source="homeassistant",
        event_type="homeassistant.webhook",
        payload=payload,
        severity="info",
    )
    entity_id = payload.get("payload", {}).get("entity_id")
    state = payload.get("payload", {}).get("state")
    attributes = payload.get("payload", {}).get("attributes")
    if isinstance(entity_id, str):
        entities = store.get_memory(conn, "homeassistant.entities") or {}
        if not isinstance(entities, dict):
            entities = {}
        entry = entities.get(entity_id, {})
        if not isinstance(entry, dict):
            entry = {}
        if state is not None:
            entry["state"] = state
        if isinstance(attributes, dict):
            entry["attributes"] = attributes
        entities[entity_id] = entry
        store.set_memory(conn, "homeassistant.entities", entities)
    store.set_memory(conn, "homeassistant.last_event", payload)
    return event_id


def _latest_errors(conn, limit: int) -> list[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM events WHERE type = ? ORDER BY id DESC LIMIT ?",
        ("android.error", limit),
    ).fetchall()
    errors: list[Dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            payload = {}
        errors.append(
            {
                "id": row["id"],
                "ts": row["ts"],
                "payload": payload,
                "severity": row["severity"],
            }
        )
    return errors


def _summarize_issues(system_snapshot: Dict[str, Any] | None) -> list[Dict[str, Any]]:
    issues: list[Dict[str, Any]] = []
    if not system_snapshot:
        return issues
    disk = system_snapshot.get("disk", {})
    used_percent = disk.get("used_percent")
    if isinstance(used_percent, (float, int)) and used_percent >= 0.9:
        issues.append(
            {
                "kind": "disk_usage_high",
                "message": f"Disk usage is high ({used_percent:.0%}).",
            }
        )
    return issues


def _parse_car_telemetry_text(text: str) -> Dict[str, Any] | None:
    if not text.startswith("car.telemetry"):
        return None
    parts = text.split(" ", 1)
    if len(parts) < 2:
        return None
    raw = parts[1].strip()
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


_KPH_TO_MPH = 0.621371
_TRIP_GAP_SECONDS = 600
_CAR_TELEMETRY_LONG_TERM_DAYS = 365
_CAR_TELEMETRY_MAX_ROWS = 5000
_CAR_ALERT_MIN_INTERVAL_SECONDS = 1800
_CAR_ALERT_MEMORY_KEY = "car.telemetry.last_alert"


def _safe_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _parse_iso_ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None
    return None


def _format_ts(value: datetime | None) -> str | None:
    if not value:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _collect_car_telemetry(conn, limit: int = 200) -> list[Dict[str, Any]]:
    rows = store.list_events(conn, limit=limit, source="voice", event_type="voice.ingest")
    items: list[Dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            payload = {}
        text = payload.get("text")
        if not isinstance(text, str):
            continue
        record = _parse_car_telemetry_text(text)
        if not record:
            continue
        record["_event_id"] = row["id"]
        record["_event_ts"] = row["ts"]
        items.append(record)
    return items


def _collect_car_telemetry_since(conn, since_ts: str, limit: int = _CAR_TELEMETRY_MAX_ROWS) -> list[Dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT * FROM events
        WHERE ts >= ? AND source = ? AND type = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (since_ts, "voice", "voice.ingest", int(limit)),
    ).fetchall()
    items: list[Dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            payload = {}
        text = payload.get("text")
        if not isinstance(text, str):
            continue
        record = _parse_car_telemetry_text(text)
        if not record:
            continue
        record["_event_id"] = row["id"]
        record["_event_ts"] = row["ts"]
        items.append(record)
    return items


def _car_telemetry_stats(records: list[Dict[str, Any]]) -> Dict[str, Any]:
    speed_samples: list[float] = []
    rpm_samples: list[float] = []
    coolant_samples: list[float] = []
    idle_samples = 0
    samples_with_speed = 0
    for record in records:
        readings = record.get("readings")
        if not isinstance(readings, dict):
            continue
        speed = _safe_float(readings.get("speed_kph"))
        rpm = _safe_float(readings.get("rpm"))
        coolant = _safe_float(readings.get("coolant_c"))
        if speed is not None:
            speed_samples.append(speed)
            samples_with_speed += 1
        if rpm is not None:
            rpm_samples.append(rpm)
        if coolant is not None:
            coolant_samples.append(coolant)
        if speed is not None and rpm is not None and speed < 1 and rpm > 0:
            idle_samples += 1
    avg_speed = sum(speed_samples) / len(speed_samples) if speed_samples else None
    max_speed = max(speed_samples) if speed_samples else None
    avg_speed_mph = avg_speed * _KPH_TO_MPH if avg_speed is not None else None
    max_speed_mph = max_speed * _KPH_TO_MPH if max_speed is not None else None
    avg_rpm = sum(rpm_samples) / len(rpm_samples) if rpm_samples else None
    max_rpm = max(rpm_samples) if rpm_samples else None
    avg_coolant = sum(coolant_samples) / len(coolant_samples) if coolant_samples else None
    max_coolant = max(coolant_samples) if coolant_samples else None
    idle_pct = (idle_samples / samples_with_speed) if samples_with_speed else None
    return {
        "avg_speed_kph": avg_speed,
        "max_speed_kph": max_speed,
        "avg_speed_mph": avg_speed_mph,
        "max_speed_mph": max_speed_mph,
        "avg_rpm": avg_rpm,
        "max_rpm": max_rpm,
        "avg_coolant_c": avg_coolant,
        "max_coolant_c": max_coolant,
        "idle_pct": idle_pct,
        "sampled": len(speed_samples),
    }


def _build_long_term_summary(records: list[Dict[str, Any]]) -> Dict[str, Any]:
    if not records:
        return {"windows": [], "range": None}
    timestamps = []
    for record in records:
        ts = _parse_iso_ts(record.get("ts") or record.get("_event_ts"))
        if ts:
            timestamps.append(ts)
    range_info = None
    if timestamps:
        range_info = {"start": _format_ts(min(timestamps)), "end": _format_ts(max(timestamps))}
    windows = []
    for days in (7, 30, 90, 365):
        window_records = [
            record
            for record in records
            if (_parse_iso_ts(record.get("ts") or record.get("_event_ts")) or datetime.min.replace(tzinfo=timezone.utc))
            >= datetime.now(timezone.utc) - timedelta(days=days)
        ]
        stats = _car_telemetry_stats(window_records)
        windows.append({"days": days, "stats": stats, "samples": stats.get("sampled", 0)})
    return {"windows": windows, "range": range_info}


def _detect_car_anomalies(recent: Dict[str, Any], baseline: Dict[str, Any]) -> list[str]:
    anomalies: list[str] = []
    if recent.get("sampled", 0) < 10 or baseline.get("sampled", 0) < 20:
        return anomalies
    recent_coolant = recent.get("avg_coolant_c")
    baseline_coolant = baseline.get("avg_coolant_c")
    if recent_coolant is not None and baseline_coolant is not None:
        if recent_coolant - baseline_coolant >= 8:
            anomalies.append(
                f"Average coolant is up by {recent_coolant - baseline_coolant:.1f}°C versus baseline."
            )
    recent_idle = recent.get("idle_pct")
    baseline_idle = baseline.get("idle_pct")
    if recent_idle is not None and baseline_idle is not None:
        if recent_idle - baseline_idle >= 0.2:
            anomalies.append(
                f"Idle time increased by {((recent_idle - baseline_idle) * 100):.0f}% versus baseline."
            )
    recent_rpm = recent.get("avg_rpm")
    baseline_rpm = baseline.get("avg_rpm")
    if recent_rpm is not None and baseline_rpm is not None:
        if recent_rpm - baseline_rpm >= 800:
            anomalies.append(
                f"Average RPM is up by {recent_rpm - baseline_rpm:.0f} versus baseline."
            )
    recent_max_rpm = recent.get("max_rpm")
    baseline_max_rpm = baseline.get("max_rpm")
    if recent_max_rpm is not None and baseline_max_rpm is not None:
        if recent_max_rpm - baseline_max_rpm >= 1500:
            anomalies.append(
                f"Max RPM increased by {recent_max_rpm - baseline_max_rpm:.0f} versus baseline."
            )
    return anomalies


def _car_telemetry_summary(conn) -> Dict[str, Any]:
    records = _collect_car_telemetry(conn, limit=200)
    if not records:
        return {"count": 0, "recent_profiles": [], "analysis": {"concerns": [], "notes": ["No telemetry available."]}}
    long_term_since = (datetime.now(timezone.utc) - timedelta(days=_CAR_TELEMETRY_LONG_TERM_DAYS)).isoformat()
    long_term_records = _collect_car_telemetry_since(conn, long_term_since)
    latest = records[0]
    readings = latest.get("readings") if isinstance(latest.get("readings"), dict) else {}
    stats = _car_telemetry_stats(records)
    samples_with_time: list[tuple[datetime, Dict[str, Any], Dict[str, Any]]] = []
    for record in records:
        rec_readings = record.get("readings")
        if not isinstance(rec_readings, dict):
            continue
        ts = _parse_iso_ts(record.get("ts") or record.get("_event_ts"))
        if ts:
            samples_with_time.append((ts, rec_readings, record))
    profiles = []
    seen = set()
    for record in records:
        profile = record.get("profile")
        if isinstance(profile, str) and profile and profile not in seen:
            profiles.append(profile)
            seen.add(profile)
    samples_with_time.sort(key=lambda item: item[0])
    trips: list[Dict[str, Any]] = []
    if samples_with_time:
        trip_start = samples_with_time[0][0]
        trip_end = trip_start
        distance_km = 0.0
        prev_ts = samples_with_time[0][0]
        prev_speed = _safe_float(samples_with_time[0][1].get("speed_kph"))
        for ts, rec_readings, _record in samples_with_time[1:]:
            gap = (ts - prev_ts).total_seconds()
            if gap > _TRIP_GAP_SECONDS:
                duration_s = (trip_end - trip_start).total_seconds()
                if duration_s > 0:
                    trips.append(
                        {
                            "start": _format_ts(trip_start),
                            "end": _format_ts(trip_end),
                            "duration_s": int(duration_s),
                            "distance_km": round(distance_km, 2),
                        }
                    )
                trip_start = ts
                distance_km = 0.0
            else:
                if prev_speed is not None:
                    distance_km += prev_speed * (gap / 3600.0)
            trip_end = ts
            prev_ts = ts
            prev_speed = _safe_float(rec_readings.get("speed_kph"))
        duration_s = (trip_end - trip_start).total_seconds()
        if duration_s > 0:
            trips.append(
                {
                    "start": _format_ts(trip_start),
                    "end": _format_ts(trip_end),
                    "duration_s": int(duration_s),
                    "distance_km": round(distance_km, 2),
                }
            )
    concerns = []
    notes = []
    max_speed = stats.get("max_speed_kph")
    max_speed_mph = stats.get("max_speed_mph")
    avg_speed = stats.get("avg_speed_kph")
    avg_speed_mph = stats.get("avg_speed_mph")
    max_rpm = stats.get("max_rpm")
    avg_rpm = stats.get("avg_rpm")
    max_coolant = stats.get("max_coolant_c")
    avg_coolant = stats.get("avg_coolant_c")
    idle_pct = stats.get("idle_pct")
    latest_fuel = _safe_float(readings.get("fuel_level_pct"))
    if max_coolant is not None and max_coolant >= 110:
        concerns.append(f"Coolant peaked at {max_coolant:.1f}°C (possible overheating).")
    elif avg_coolant is not None and avg_coolant >= 105:
        concerns.append(f"Average coolant temperature is high ({avg_coolant:.1f}°C).")
    if max_rpm is not None and max_rpm >= 5000:
        concerns.append(f"High RPM spikes detected (max {max_rpm:.0f}).")
    if max_speed_mph is not None and max_speed_mph >= 120:
        concerns.append(f"Very high speed detected (max {max_speed_mph:.0f} mph).")
    if latest_fuel is not None and latest_fuel <= 10:
        concerns.append(f"Fuel level is low ({latest_fuel:.0f}%).")
    if idle_pct is not None and idle_pct >= 0.4:
        concerns.append(f"High idle time ({idle_pct * 100:.0f}% of samples).")
    long_term_summary = _build_long_term_summary(long_term_records)
    recent_window = next((entry for entry in long_term_summary["windows"] if entry["days"] == 7), None)
    baseline_window = next((entry for entry in long_term_summary["windows"] if entry["days"] == 90), None)
    anomalies = _detect_car_anomalies(
        recent_window["stats"] if recent_window else {},
        baseline_window["stats"] if baseline_window else {},
    )
    concerns.extend(anomalies)
    if not concerns:
        notes.append("No obvious issues detected in recent telemetry.")
    if len(records) < 10:
        notes.append("Limited telemetry sample size; analysis may be incomplete.")
    if not trips:
        notes.append("Trip segmentation unavailable (insufficient timestamps).")
    return {
        "count": len(records),
        "last": {
            "ts": latest.get("ts") or latest.get("_event_ts"),
            "device_id": latest.get("device_id"),
            "profile": latest.get("profile"),
            "adapter_name": latest.get("adapter_name"),
            "adapter_address": latest.get("adapter_address"),
            "make": latest.get("make"),
            "model": latest.get("model"),
            "year": latest.get("year"),
            "trim": latest.get("trim"),
            "readings": readings,
        },
        "stats": {
            **stats,
        },
        "recent_profiles": profiles,
        "analysis": {
            "concerns": concerns,
            "notes": notes,
            "driving": {
                "avg_speed_mph": avg_speed_mph,
                "max_speed_mph": max_speed_mph,
                "avg_rpm": avg_rpm,
                "max_rpm": max_rpm,
                "idle_pct": idle_pct,
            },
            "health": {
                "avg_coolant_c": avg_coolant,
                "max_coolant_c": max_coolant,
                "fuel_level_pct": latest_fuel,
                "intake_c": _safe_float(readings.get("intake_c")),
            },
            "trips": trips[-5:],
            "long_term": long_term_summary,
            "anomalies": anomalies,
        },
    }


def _format_car_alert_message(summary: Dict[str, Any]) -> tuple[str, list[str], list[str]]:
    analysis = summary.get("analysis") if isinstance(summary.get("analysis"), dict) else {}
    concerns = analysis.get("concerns") if isinstance(analysis.get("concerns"), list) else []
    anomalies = analysis.get("anomalies") if isinstance(analysis.get("anomalies"), list) else []
    vehicle = summary.get("last", {})
    vehicle_name = None
    if isinstance(vehicle, dict):
        make = vehicle.get("make")
        model = vehicle.get("model")
        if isinstance(make, str) or isinstance(model, str):
            vehicle_name = f"{make or ''} {model or ''}".strip()
    prefix = "Car telemetry alert"
    if vehicle_name:
        prefix = f"{prefix} ({vehicle_name})"
    if concerns:
        message = f"{prefix}: " + "; ".join(concerns[:3])
    elif anomalies:
        message = f"{prefix}: " + "; ".join(anomalies[:3])
    else:
        message = f"{prefix}: No issues detected."
    return message, concerns, anomalies


def _maybe_emit_car_alert(conn) -> None:
    summary = _car_telemetry_summary(conn)
    message, concerns, anomalies = _format_car_alert_message(summary)
    if not concerns and not anomalies:
        return
    alert_basis = "|".join(concerns + anomalies)
    alert_hash = hashlib.sha1(alert_basis.encode("utf-8")).hexdigest()
    last_state = store.get_memory(conn, _CAR_ALERT_MEMORY_KEY)
    last_hash = None
    last_ts = None
    if isinstance(last_state, dict):
        last_hash = last_state.get("hash")
        last_ts = _parse_iso_ts(last_state.get("ts"))
    if last_hash == alert_hash and last_ts:
        if (datetime.now(timezone.utc) - last_ts).total_seconds() < _CAR_ALERT_MIN_INTERVAL_SECONDS:
            return
    payload = {
        "message": message,
        "concerns": concerns,
        "anomalies": anomalies,
        "report_url": "/ui/car",
    }
    store.insert_event(
        conn,
        source="voice",
        event_type="car.alert",
        payload=payload,
        severity="warn",
    )
    store.set_memory(
        conn,
        _CAR_ALERT_MEMORY_KEY,
        {"hash": alert_hash, "ts": utc_now_iso()},
    )
    try:
        act.notify_local(message, str(settings.audit_path()))
    except Exception:
        pass


def _list_alerts(conn, limit: int = 50) -> list[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM events WHERE type IN (?, ?) ORDER BY id DESC LIMIT ?",
        ("car.alert", "face.alert", int(limit)),
    ).fetchall()
    alerts: list[Dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            payload = {}
        alerts.append(
            {
                "id": row["id"],
                "ts": row["ts"],
                "severity": row["severity"],
                "type": row["type"],
                "message": payload.get("message"),
                "concerns": payload.get("concerns", []),
                "anomalies": payload.get("anomalies", []),
                "report_url": payload.get("report_url", "/ui/car"),
            }
        )
    return alerts


def _safe_snapshot_path(raw_path: str) -> Path | None:
    if not raw_path:
        return None
    base_dir = (settings.data_dir() / "camera_captures").resolve()
    path = Path(raw_path)
    if not path.is_absolute():
        path = (base_dir / path).resolve()
    else:
        path = path.resolve()
    try:
        path.relative_to(base_dir)
    except ValueError:
        return None
    if not path.exists() or not path.is_file():
        return None
    return path


def _list_unknown_faces(conn, limit: int = 50) -> list[Dict[str, Any]]:
    false_positives = store.get_memory(conn, "vision.false_positives") or []
    if not isinstance(false_positives, list):
        false_positives = []
    false_positive_set = {str(item) for item in false_positives}
    rows = conn.execute(
        "SELECT * FROM events WHERE type = ? ORDER BY id DESC LIMIT ?",
        ("face.unknown", int(limit)),
    ).fetchall()
    results: list[Dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            payload = {}
        snapshot_hash = payload.get("snapshot_hash") if isinstance(payload, dict) else None
        if snapshot_hash and str(snapshot_hash) in false_positive_set:
            continue
        snapshot_path = payload.get("snapshot_path") if isinstance(payload, dict) else None
        snapshot_url = None
        safe_path = None
        if isinstance(snapshot_path, str):
            safe_path = _safe_snapshot_path(snapshot_path)
        if safe_path:
            snapshot_url = f"/vision/snapshot?path={quote(str(safe_path))}"
        results.append(
            {
                "id": row["id"],
                "ts": row["ts"],
                "severity": row["severity"],
                "camera_id": payload.get("camera_id") if isinstance(payload, dict) else None,
                "label": payload.get("label") if isinstance(payload, dict) else None,
                "snapshot_path": snapshot_path,
                "snapshot_url": snapshot_url,
                "snapshot_hash": snapshot_hash,
                "face_box": payload.get("face_box") if isinstance(payload, dict) else None,
            }
        )
    return results


def _list_face_alerts(conn, limit: int = 25) -> list[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM events WHERE type = ? ORDER BY id DESC LIMIT ?",
        ("face.alert", int(limit)),
    ).fetchall()
    results: list[Dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            payload = {}
        snapshot_path = payload.get("snapshot_path") if isinstance(payload, dict) else None
        snapshot_url = None
        safe_path = None
        if isinstance(snapshot_path, str):
            safe_path = _safe_snapshot_path(snapshot_path)
        if safe_path:
            snapshot_url = f"/vision/snapshot?path={quote(str(safe_path))}"
        results.append(
            {
                "id": row["id"],
                "ts": row["ts"],
                "severity": row["severity"],
                "camera_id": payload.get("camera_id") if isinstance(payload, dict) else None,
                "label": payload.get("label") if isinstance(payload, dict) else None,
                "message": payload.get("message") if isinstance(payload, dict) else None,
                "snapshot_path": snapshot_path,
                "snapshot_url": snapshot_url,
                "snapshot_hash": payload.get("snapshot_hash") if isinstance(payload, dict) else None,
                "face_box": payload.get("face_box") if isinstance(payload, dict) else None,
            }
        )
    return results


def _load_network_module_cfg() -> Dict[str, Any]:
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return {}
    try:
        config = module_config.load_config(str(config_path))
    except Exception:
        return {}
    module_cfg = config.get("modules", {}).get("network.discovery", {})
    return module_cfg if isinstance(module_cfg, dict) else {}


def _get_deep_scan_state(conn) -> Dict[str, Any]:
    state = store.get_memory(conn, "network.discovery.deep_scan")
    if not isinstance(state, dict):
        return {"jobs": {}}
    if not isinstance(state.get("jobs"), dict):
        state["jobs"] = {}
    return state


def _merge_deep_scan_devices(
    snapshot: Dict[str, Any] | None,
    deep_scan: Dict[str, Any] | None,
) -> Dict[str, Any]:
    merged_snapshot: Dict[str, Any] = dict(snapshot) if isinstance(snapshot, dict) else {}
    devices = merged_snapshot.get("devices")
    if not isinstance(devices, list):
        devices = []
    merged_devices = list(devices)
    existing = {item.get("ip") for item in merged_devices if isinstance(item, dict)}
    jobs = deep_scan.get("jobs", {}) if isinstance(deep_scan, dict) else {}
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            if job.get("status") != "complete":
                continue
            ip = job.get("ip")
            if not isinstance(ip, str) or not ip.strip():
                continue
            if ip in existing:
                continue
            merged_devices.append(
                {
                    "ip": ip,
                    "mac": None,
                    "device": "deep-scan",
                    "open_ports": job.get("open_ports", []),
                    "services": job.get("services", []),
                    "hints": job.get("hints", []),
                }
            )
            existing.add(ip)
    merged_snapshot["devices"] = merged_devices
    merged_snapshot["device_count"] = len(merged_devices)
    return merged_snapshot


def _run_deep_scan(ip: str, ports: List[int], ports_payload: Any) -> None:
    conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
    module_cfg = _load_network_module_cfg()
    timeout_seconds = float(module_cfg.get("deep_scan_timeout_seconds", 0.2))
    max_workers = int(module_cfg.get("deep_scan_workers", 128))
    active_cfg = module_cfg.get("active") if isinstance(module_cfg.get("active"), dict) else {}
    state = _get_deep_scan_state(conn)
    job = state["jobs"].get(ip, {})
    job.update(
        {
            "ip": ip,
            "status": "running",
            "started_at": utc_now_iso(),
            "ports": ports_payload,
            "open_ports": [],
            "services": [],
            "hints": [],
            "error": None,
            "finished_at": None,
        }
    )
    state["jobs"][ip] = job
    store.set_memory(conn, "network.discovery.deep_scan", state)
    try:
        result = observe.deep_scan_host(
            ip=ip,
            ports=ports,
            timeout_seconds=timeout_seconds,
            max_workers=max_workers,
            active=active_cfg,
        )
        job.update(
            {
                "status": "complete",
                "open_ports": result.get("open_ports", []),
                "services": result.get("services", []),
                "hints": result.get("hints", []),
                "finished_at": utc_now_iso(),
            }
        )
        store.insert_event(
            conn,
            source="network",
            event_type="network.discovery.deep_scan",
            payload=job,
            severity="info",
        )
    except Exception as exc:
        job.update(
            {
                "status": "error",
                "error": str(exc),
                "finished_at": utc_now_iso(),
            }
        )
        store.insert_event(
            conn,
            source="network",
            event_type="network.discovery.deep_scan.error",
            payload=job,
            severity="warn",
        )
    finally:
        state["jobs"][ip] = job
        store.set_memory(conn, "network.discovery.deep_scan", state)
        with _DEEP_SCAN_LOCK:
            _DEEP_SCAN_RUNNING.discard(ip)


class VoiceHandler(BaseHTTPRequestHandler):
    server_version = "PumpkinVoice/0.1"

    def send_response(self, code: int, message: str | None = None) -> None:
        self._response_code = code
        super().send_response(code, message)

    def _log_request(self) -> None:
        status = getattr(self, "_response_code", 0)
        print(f"PumpkinVoice {self.command} {self.path} {status}", flush=True)

    def do_POST(self) -> None:
        try:
            if self.path in {"/voice", "/satellite/voice"}:
                self._handle_voice()
                return
            if self.path == "/ingest":
                self._handle_ingest()
                return
            if self.path == "/ask":
                self._handle_ask()
                return
            if self.path == "/errors":
                self._handle_errors()
                return
            if self.path == "/ha/webhook":
                self._handle_ha_webhook()
                return
            if self.path == "/proposals/approve":
                self._handle_proposal_decision("approved")
                return
            if self.path == "/proposals/reject":
                self._handle_proposal_decision("rejected")
                return
            if self.path == "/llm/config":
                self._handle_llm_config()
                return
            if self.path == "/network/mark":
                self._handle_network_mark()
                return
            if self.path == "/network/deep_scan":
                self._handle_network_deep_scan()
                return
            if self.path == "/network/rtsp_probe":
                self._handle_network_rtsp_probe()
                return
            if self.path == "/vision/alerts":
                self._handle_vision_alerts()
                return
            if self.path == "/vision/enroll":
                self._handle_vision_enroll()
                return
            if self.path == "/vision/false_positive":
                self._handle_vision_false_positive()
                return
            if self.path == "/vision/unknown/clear":
                self._handle_vision_unknown_clear()
                return
            if self.path == "/identity/link":
                self._handle_identity_link()
                return
            if self.path == "/suggestions":
                self._handle_suggestion()
                return
            if self.path == "/notifications/test":
                self._handle_notifications_test()
                return
            self.send_response(404)
            self.end_headers()
            return
        finally:
            self._log_request()

    def _handle_voice(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)

        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "voice.received",
                "content_length": length,
            },
        )

        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return

        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return

        text = data.get("text")
        if not isinstance(text, str):
            _bad_request(self, "text must be a string")
            return

        text = _normalize_text(text)
        if not text:
            _bad_request(self, "text must not be empty")
            return

        if len(text) > MAX_TEXT_LEN:
            _bad_request(self, "text too long")
            return

        device_id = data.get("device_id")
        if device_id is not None and not isinstance(device_id, str):
            _bad_request(self, "device_id must be a string")
            return
        satellite_id = data.get("satellite_id")
        if satellite_id is not None and not isinstance(satellite_id, str):
            _bad_request(self, "satellite_id must be a string")
            return
        room = data.get("room")
        if room is not None and not isinstance(room, str):
            _bad_request(self, "room must be a string")
            return
        client_ip = self.client_address[0] if self.client_address else None
        rate_key = device_id if isinstance(device_id, str) else client_ip
        if _rate_limited(rate_key, settings.voice_cooldown_seconds()):
            _bad_request(self, "rate_limited")
            return

        payload = {
            "text": text,
            "device_id": device_id,
            "confidence": data.get("confidence"),
            "client_ip": client_ip,
            "satellite_id": satellite_id,
            "room": room,
        }

        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        event_id = store.insert_event(
            conn,
            source="voice",
            event_type="voice.command",
            payload=payload,
            severity="med",
        )

        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "voice.event_created",
                "event_id": event_id,
            },
        )

        _send_json(self, 200, {"event_id": event_id})

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            params = parse_qs(parsed.query)
            if path == "/health":
                metrics = telemetry.collect_health_metrics()
                _send_json(
                    self,
                    200,
                    {
                        "status": "ok",
                        "host": settings.voice_server_host(),
                        "port": settings.voice_server_port(),
                        "metrics": metrics,
                    },
                )
                return
            if path == "/":
                _send_json(
                    self,
                    200,
                    {
                        "service": "PumpkinVoice",
                        "version": self.server_version,
                        "endpoints": [
                            "GET /",
                            "GET /health",
                            "GET /ha/callback",
                            "GET /ui",
                            "GET /ui/memory",
                            "GET /ui/autonomy",
                            "GET /ui/homeassistant",
                            "GET /ui/scoreboard",
                            "GET /ui/proposals",
                            "GET /ui/network",
                            "GET /ui/car",
                            "GET /ui/car/alerts",
                            "GET /ui/alerts",
                            "GET /ui/inventory",
                            "GET /ui/vision",
                            "GET /config",
                            "GET /catalog",
                            "GET /capabilities",
                            "GET /openapi.json",
                            "GET /ask/result",
                            "GET /proposals",
                            "GET /summary",
                            "GET /memory",
                            "GET /timeline",
                            "GET /car/telemetry",
                            "GET /inventory",
                            "GET /notifications",
                            "GET /vision/alerts",
                            "GET /vision/unknown",
                            "GET /vision/snapshot",
                            "GET /vision/false_positives",
                            "GET /errors",
                            "GET /llm/config",
                            "POST /ask",
                            "POST /errors",
                            "POST /proposals/approve",
                            "POST /proposals/reject",
                            "POST /llm/config",
                            "POST /ingest",
                            "POST /identity/link",
                            "POST /network/deep_scan",
                            "POST /network/rtsp_probe",
                            "POST /network/mark",
                            "POST /vision/alerts",
                            "POST /vision/enroll",
                            "POST /vision/false_positive",
                            "POST /vision/unknown/clear",
                            "POST /suggestions",
                            "POST /notifications/test",
                            "POST /ha/webhook",
                            "POST /voice",
                            "POST /satellite/voice",
                        ],
                    },
                )
                return
            if path == "/ha/callback":
                code = params.get("code", [None])[0]
                state = params.get("state", [None])[0]
                error = params.get("error", [None])[0]
                target = "pumpkin-ha://auth"
                if error:
                    target = f"{target}?error={quote(str(error))}"
                elif code and state:
                    target = (
                        f"{target}?code={quote(str(code))}"
                        f"&state={quote(str(state))}"
                    )
                _send_redirect(self, target)
                return
            if path in {"/ui", "/ui/"}:
                _send_html(self, 200, _load_voice_ui_asset("voice_ui.html"))
                return
            if path == "/ui/memory":
                _send_html(self, 200, _load_voice_ui_asset("voice_ui_memory.html"))
                return
            if path == "/ui/autonomy":
                _send_html(self, 200, _load_voice_ui_asset("voice_ui_autonomy.html"))
                return
            if path == "/ui/homeassistant":
                _send_html(self, 200, _load_voice_ui_asset("voice_ui_homeassistant.html"))
                return
            if path == "/ui/scoreboard":
                _send_html(self, 200, _load_voice_ui_asset("voice_ui_scoreboard.html"))
                return
            if path == "/ui/proposals":
                _send_html(self, 200, _load_voice_ui_asset("voice_ui_proposals.html"))
                return
            if path == "/ui/network":
                _send_html(self, 200, _load_voice_ui_asset("voice_ui_network.html"))
                return
            if path == "/ui/car":
                _send_html(self, 200, _load_voice_ui_asset("voice_ui_car.html"))
                return
            if path == "/ui/car/alerts":
                _send_html(self, 200, _load_voice_ui_asset("voice_ui_car_alerts.html"))
                return
            if path == "/ui/alerts":
                _send_html(self, 200, _load_voice_ui_asset("voice_ui_alerts.html"))
                return
            if path == "/ui/vision":
                _send_html(self, 200, _load_voice_ui_asset("voice_ui_vision.html"))
                return
            if path == "/ui/inventory":
                _send_html(self, 200, _load_voice_ui_asset("voice_ui_inventory.html"))
                return
            if path == "/car/telemetry":
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                _send_json(self, 200, {"status": "ok", "car_telemetry": _car_telemetry_summary(conn)})
                return
            if path == "/inventory":
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                inventory = inventory_mod.snapshot(conn)
                opportunities = inventory_mod.opportunities(inventory)
                _send_json(
                    self,
                    200,
                    {
                        "status": "ok",
                        "inventory": inventory,
                        "opportunities": opportunities,
                    },
                )
                return
            if path == "/notifications":
                limit = _parse_limit(params.get("limit", [None])[0])
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                alerts = _list_alerts(conn, limit=limit)
                _send_json(self, 200, {"count": len(alerts), "notifications": alerts})
                return
            if path == "/vision/unknown":
                limit = _parse_limit(params.get("limit", [None])[0], default=25)
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                unknown = _list_unknown_faces(conn, limit=limit)
                _send_json(self, 200, {"count": len(unknown), "items": unknown})
                return
            if path == "/vision/alerts/recent":
                limit = _parse_limit(params.get("limit", [None])[0], default=10)
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                alerts = _list_face_alerts(conn, limit=limit)
                _send_json(self, 200, {"count": len(alerts), "items": alerts})
                return
            if path == "/vision/false_positives":
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                disabled = store.get_memory(conn, "vision.false_positives") or []
                if not isinstance(disabled, list):
                    disabled = []
                _send_json(self, 200, {"items": disabled})
                return
            if path == "/vision/snapshot":
                raw_path = params.get("path", [None])[0]
                if not raw_path:
                    self.send_response(400)
                    self.end_headers()
                    return
                snapshot_path = _safe_snapshot_path(raw_path)
                if not snapshot_path:
                    self.send_response(404)
                    self.end_headers()
                    return
                payload = snapshot_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "image/jpeg")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if path == "/vision/alerts":
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                disabled = store.get_memory(conn, "vision.alerts.disabled") or []
                if not isinstance(disabled, list):
                    disabled = []
                _send_json(self, 200, {"disabled": disabled})
                return
            if path == "/config":
                bind_host, bind_port = _effective_bind(self)
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                llm_config = _load_llm_config(conn)
                ha_sync = store.get_memory(conn, "homeassistant.sync") or {}
                _send_json(
                    self,
                    200,
                    {
                        "service": {"name": "PumpkinVoice", "version": self.server_version},
                        "http": {
                            "host": bind_host,
                            "port": bind_port,
                        },
                        "llm": {
                            "provider": "openai",
                            "model": llm_config["model"],
                            "enabled": bool(llm_config["api_key"]),
                        },
                        "upstream": {
                            "planner_mode": os.getenv("PUMPKIN_PLANNER_MODE", "stub"),
                            "planner_url": os.getenv("PUMPKIN_PLANNER_URL"),
                        },
                        "features": {
                            "voice_rate_limit_seconds": settings.voice_cooldown_seconds(),
                            "max_text_len": MAX_TEXT_LEN,
                            "ingest_enabled": True,
                            "ha_webhook_enabled": True,
                            "home_summary_enabled": True,
                        },
                        "homeassistant": {
                            "enabled": bool(ha_sync),
                            "last_sync": ha_sync.get("last_sync"),
                            "entity_count": ha_sync.get("entity_count"),
                            "area_count": ha_sync.get("area_count"),
                            "entity_registry_count": ha_sync.get("entity_registry_count"),
                            "device_registry_count": ha_sync.get("device_registry_count"),
                        },
                        "build": {
                            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                        },
                    },
                )
                return
            if path == "/catalog":
                catalog_path = settings.modules_catalog_path()
                if not catalog_path.exists():
                    _send_json(self, 404, {"error": "catalog_not_found"})
                    return
                try:
                    catalog = catalog_mod.load_catalog(str(catalog_path))
                except Exception as exc:
                    _send_json(self, 500, {"error": "catalog_invalid"})
                    return
                _send_json(
                    self,
                    200,
                    {
                        "count": len(catalog.get("modules", [])),
                        "modules": catalog.get("modules", []),
                    },
                )
                return
            if path == "/capabilities":
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                _send_json(self, 200, capabilities.snapshot(conn))
                return
            if path == "/proposals":
                status = params.get("status", [None])[0]
                limit = _parse_limit(params.get("limit", [None])[0])
                include_events = params.get("include_events", ["0"])[0] == "1"
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                rows = store.list_proposals(conn, status=status, limit=limit)
                proposals = []
                for row in rows:
                    try:
                        details = json.loads(row["details_json"])
                    except Exception:
                        details = {}
                    trail = []
                    if include_events:
                        for ev in store.get_proposal_events(conn, row["id"]):
                            try:
                                payload = json.loads(ev["payload_json"])
                            except Exception:
                                payload = {}
                            trail.append(
                                {
                                    "id": ev["id"],
                                    "ts": ev["ts"],
                                    "source": ev["source"],
                                    "type": ev["type"],
                                    "payload": payload,
                                }
                            )
                    proposals.append(
                        {
                            "id": row["id"],
                            "kind": row["kind"],
                            "summary": row["summary"],
                            "details": details,
                            "risk": row["risk"],
                            "expected_outcome": row["expected_outcome"],
                            "status": row["status"],
                            "needs_new_capability": bool(row["needs_new_capability"]),
                            "capability_request": row["capability_request"],
                            "ai_context_excerpt": row["ai_context_excerpt"],
                            "trail": trail,
                            "ts_created": row["ts_created"],
                        }
                    )
                _send_json(
                    self,
                    200,
                    {
                        "count": len(proposals),
                        "proposals": proposals,
                    },
                )
                return
            if path == "/timeline":
                limit = _parse_limit(params.get("limit", [None])[0], default=20, max_limit=200)
                source = params.get("source", [None])[0]
                event_type = params.get("type", [None])[0]
                since_id_raw = params.get("since_id", [None])[0]
                since_id = None
                if since_id_raw:
                    try:
                        since_id = int(since_id_raw)
                    except ValueError:
                        since_id = None
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                rows = store.list_events(
                    conn,
                    limit=limit,
                    source=source if isinstance(source, str) and source else None,
                    event_type=event_type if isinstance(event_type, str) and event_type else None,
                    since_id=since_id,
                )
                timeline = []
                for row in rows:
                    try:
                        payload = json.loads(row["payload_json"])
                    except Exception:
                        payload = {}
                    timeline.append(
                        {
                            "id": row["id"],
                            "ts": row["ts"],
                            "source": row["source"],
                            "type": row["type"],
                            "payload": payload,
                            "severity": row["severity"],
                        }
                    )
                _send_json(
                    self,
                    200,
                    {
                        "count": len(timeline),
                        "events": timeline,
                    },
                )
                return
            if path == "/memory":
                device = params.get("device", [None])[0]
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                if not isinstance(device, str) or not device.strip():
                    last_device = store.get_memory(conn, "voice.last_device")
                    device = last_device if isinstance(last_device, str) else None
                _send_json(self, 200, _memory_snapshot(conn, device))
                return
            if path == "/summary":
                status = params.get("status", ["pending"])[0]
                limit = _parse_limit(params.get("limit", [None])[0], default=10)
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                last_device = store.get_memory(conn, "voice.last_device")
                if not isinstance(last_device, str):
                    last_device = None
                snapshot_event = _latest_event(conn, "system.snapshot")
                heartbeat_event = _latest_event(conn, "heartbeat")
                proposals = store.list_proposals(conn, status=status, limit=limit)
                proposal_items = []
                for row in proposals:
                    proposal_items.append(
                        {
                            "id": row["id"],
                            "kind": row["kind"],
                            "summary": row["summary"],
                            "risk": row["risk"],
                            "status": row["status"],
                            "expected_outcome": row["expected_outcome"],
                            "ts_created": row["ts_created"],
                        }
                    )
                system_snapshot = snapshot_event["payload"] if snapshot_event else None
                ha_summary = store.get_memory(conn, "homeassistant.summary")
                ha_last_event = store.get_memory(conn, "homeassistant.last_event")
                ha_sync = store.get_memory(conn, "homeassistant.sync")
                home_state = _home_state_summary(conn)
                issues = _summarize_issues(system_snapshot)
                network_discovery = store.get_memory(conn, "network.discovery.snapshot")
                deep_scan_state = store.get_memory(conn, "network.discovery.deep_scan")
                network_discovery = _merge_deep_scan_devices(network_discovery, deep_scan_state)
                camera_registry = store.get_memory(conn, "camera.registry")
                if not isinstance(camera_registry, list):
                    camera_registry = []
                alert_disabled = store.get_memory(conn, "vision.alerts.disabled") or []
                if not isinstance(alert_disabled, list):
                    alert_disabled = []
                alert_disabled_set = {str(item) for item in alert_disabled}
                camera_registry_view = []
                for cam in camera_registry:
                    if not isinstance(cam, dict):
                        continue
                    camera_id = str(cam.get("id") or cam.get("ip") or "")
                    alert_enabled = bool(cam.get("alert_unknown_faces", True))
                    if camera_id and camera_id in alert_disabled_set:
                        alert_enabled = False
                    cam_view = dict(cam)
                    cam_view["alert_unknown_faces"] = alert_enabled
                    camera_registry_view.append(cam_view)
                car_telemetry = _car_telemetry_summary(conn)
                inventory = inventory_mod.snapshot(conn)
                opportunities = inventory_mod.opportunities(inventory)
                insights_latest = store.get_memory(conn, "insights.latest")
                if not isinstance(insights_latest, list):
                    insights_latest = []
                actions_recent = store.get_memory(conn, "actions.recent") or []
                if not isinstance(actions_recent, list):
                    actions_recent = []
                autonomy = {
                    "total_executed": store.get_memory(conn, "actions.total_executed") or 0,
                    "last_executed_count": store.get_memory(conn, "actions.last_executed_count") or 0,
                    "last_executed_ts": store.get_memory(conn, "actions.last_executed_ts"),
                    "recent_actions": actions_recent[-5:],
                }
                briefing = store.get_memory(conn, "insights.last_briefing")
                if not isinstance(briefing, dict):
                    briefing = None
                router_rows = store.list_events(
                    conn,
                    limit=5,
                    source="voice",
                    event_type="voice.router",
                )
                router_events = []
                for row in router_rows:
                    try:
                        payload = json.loads(row["payload_json"])
                    except Exception:
                        payload = {}
                    router_events.append(
                        {
                            "id": row["id"],
                            "ts": row["ts"],
                            "payload": payload,
                        }
                    )
                _send_json(
                    self,
                    200,
                    {
                        "status": "ok",
                        "identity": _identity_snapshot(conn, last_device),
                        "heartbeat": heartbeat_event,
                        "system_snapshot": system_snapshot,
                        "homeassistant": ha_summary,
                        "homeassistant_last_event": ha_last_event,
                        "homeassistant_sync": ha_sync,
                        "home_state": home_state,
                        "network_discovery": network_discovery,
                        "network_deep_scan": deep_scan_state,
                        "camera_registry": camera_registry_view,
                        "car_telemetry": car_telemetry,
                        "inventory": inventory_mod.summary(inventory),
                        "opportunities": opportunities[:5],
                        "issues": issues,
                        "autonomy": autonomy,
                        "insights": insights_latest[-5:],
                        "briefing": briefing,
                        "router_events": router_events,
                        "proposals": proposal_items,
                        "proposal_count": len(proposal_items),
                    },
                )
                return
            if path == "/thoughts":
                limit = _parse_limit(params.get("limit", [None])[0], default=12, max_limit=50)
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                thoughts = _collect_thoughts(conn, limit)
                _send_json(
                    self,
                    200,
                    {
                        "count": len(thoughts),
                        "thoughts": thoughts,
                    },
                )
                return
            if path == "/errors":
                limit = _parse_limit(params.get("limit", [None])[0], default=5, max_limit=50)
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                errors = _latest_errors(conn, limit)
                _send_json(
                    self,
                    200,
                    {
                        "count": len(errors),
                        "errors": errors,
                    },
                )
                return
            if path == "/llm/config":
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                llm_config = _load_llm_config(conn)
                _send_json(
                    self,
                    200,
                    {
                        "provider": "openai",
                        "model": llm_config["model"],
                        "base_url": llm_config["base_url"],
                        "enabled": bool(llm_config["api_key"]),
                    },
                )
                return
            if path == "/ask/result":
                event_id_raw = params.get("event_id", [None])[0] or params.get("id", [None])[0]
                if not event_id_raw:
                    _send_json(self, 400, {"error": "event_id_required"})
                    return
                try:
                    event_id = int(event_id_raw)
                except ValueError:
                    _send_json(self, 400, {"error": "invalid_event_id"})
                    return
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                result = store.get_memory(conn, f"voice.ask.result:{event_id}")
                if not isinstance(result, dict):
                    _send_json(self, 404, {"error": "result_not_found", "event_id": event_id})
                    return
                _send_json(self, 200, result)
                return
            if path == "/openapi.json":
                _send_json(
                    self,
                    200,
                    {
                        "openapi": "3.0.0",
                        "info": {
                            "title": "PumpkinVoice",
                            "version": self.server_version,
                        },
                        "paths": {
                            "/": {"get": {"summary": "Service metadata"}},
                            "/health": {"get": {"summary": "Health check"}},
                            "/ha/callback": {"get": {"summary": "Home Assistant OAuth callback redirect"}},
                            "/config": {"get": {"summary": "Runtime config"}},
                            "/catalog": {"get": {"summary": "Module catalog"}},
                            "/capabilities": {"get": {"summary": "Capability snapshot"}},
                            "/car/telemetry": {"get": {"summary": "Car telemetry summary"}},
                            "/notifications": {"get": {"summary": "Recent alerts"}},
                            "/thoughts": {"get": {"summary": "Recent thought stream"}},
                            "/vision/alerts": {"get": {"summary": "Unknown face alert settings"}},
                            "/vision/unknown": {"get": {"summary": "List unknown face events"}},
                            "/vision/alerts/recent": {"get": {"summary": "List recent face alerts"}},
                            "/vision/snapshot": {"get": {"summary": "Fetch a captured snapshot"}},
                            "/vision/false_positives": {"get": {"summary": "List false positive hashes"}},
                            "/notifications/test": {"post": {"summary": "Create a test alert"}},
                            "/identity/link": {
                                "post": {
                                    "summary": "Link a device to a Home Assistant person",
                                    "requestBody": {
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "device": {"type": "string"},
                                                        "person_id": {"type": "string"},
                                                    },
                                                    "required": ["person_id"],
                                                }
                                            }
                                        }
                                    },
                                }
                            },
                            "/network/deep_scan": {
                                "post": {
                                    "summary": "Start a deep port scan for a host",
                                    "requestBody": {
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "ip": {"type": "string"},
                                                        "ports": {
                                                            "type": "array",
                                                            "items": {"type": "integer"},
                                                        },
                                                    },
                                                    "required": ["ip"],
                                                }
                                            }
                                        }
                                    },
                                }
                            },
                            "/network/rtsp_probe": {
                                "post": {
                                    "summary": "Probe RTSP paths on a host",
                                    "requestBody": {
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "ip": {"type": "string"},
                                                        "port": {"type": "integer"},
                                                        "paths": {
                                                            "type": "array",
                                                            "items": {"type": "string"},
                                                        },
                                                    },
                                                    "required": ["ip"],
                                                }
                                            }
                                        }
                                    },
                                }
                            },
                            "/vision/enroll": {
                                "post": {
                                    "summary": "Enroll a face snapshot into CompreFace",
                                    "requestBody": {
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "subject": {"type": "string"},
                                                        "snapshot_path": {"type": "string"},
                                                    },
                                                    "required": ["subject", "snapshot_path"],
                                                }
                                            }
                                        }
                                    },
                                }
                            },
                            "/vision/false_positive": {
                                "post": {
                                    "summary": "Mark a snapshot hash as false positive",
                                    "requestBody": {
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "snapshot_hash": {"type": "string"},
                                                    },
                                                    "required": ["snapshot_hash"],
                                                }
                                            }
                                        }
                                    },
                                }
                            },
                            "/vision/unknown/clear": {
                                "post": {
                                    "summary": "Clear unknown face events",
                                }
                            },
                            "/suggestions": {
                                "post": {
                                    "summary": "Submit a user suggestion for proposal creation",
                                    "requestBody": {
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "text": {"type": "string"},
                                                        "device": {"type": "string"},
                                                    },
                                                    "required": ["text"],
                                                }
                                            }
                                        }
                                    },
                                }
                            },
                            "/inventory": {"get": {"summary": "Inventory snapshot and opportunities"}},
                            "/ui/autonomy": {"get": {"summary": "Autonomy dashboard"}},
                            "/ui/homeassistant": {"get": {"summary": "Home Assistant dashboard"}},
                            "/ui/memory": {"get": {"summary": "Memory dashboard"}},
                            "/ui/scoreboard": {"get": {"summary": "Scoreboard dashboard"}},
                            "/ui/inventory": {"get": {"summary": "Inventory dashboard"}},
                            "/memory": {"get": {"summary": "Memory snapshot"}},
                            "/summary": {
                                "get": {
                                    "summary": "System summary",
                                    "parameters": [
                                        {
                                            "name": "status",
                                            "in": "query",
                                            "schema": {"type": "string"},
                                        },
                                        {
                                            "name": "limit",
                                            "in": "query",
                                            "schema": {"type": "integer"},
                                        },
                                    ],
                                    "responses": {
                                        "200": {
                                            "description": "Summary snapshot",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/timeline": {
                                "get": {
                                    "summary": "Unified event timeline",
                                    "parameters": [
                                        {
                                            "name": "limit",
                                            "in": "query",
                                            "schema": {"type": "integer"},
                                        },
                                        {
                                            "name": "source",
                                            "in": "query",
                                            "schema": {"type": "string"},
                                        },
                                        {
                                            "name": "type",
                                            "in": "query",
                                            "schema": {"type": "string"},
                                        },
                                        {
                                            "name": "since_id",
                                            "in": "query",
                                            "schema": {"type": "integer"},
                                        },
                                    ],
                                    "responses": {
                                        "200": {
                                            "description": "Timeline events",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/errors": {
                                "get": {
                                    "summary": "List recent client error reports",
                                    "parameters": [
                                        {
                                            "name": "limit",
                                            "in": "query",
                                            "schema": {"type": "integer"},
                                        }
                                    ],
                                    "responses": {
                                        "200": {
                                            "description": "Error reports",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/llm/config": {
                                "get": {
                                    "summary": "Get LLM configuration",
                                    "responses": {
                                        "200": {
                                            "description": "LLM config",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/openapi.json": {"get": {"summary": "OpenAPI spec"}},
                            "/proposals": {
                                "get": {
                                    "summary": "List proposals",
                                    "parameters": [
                                        {
                                            "name": "status",
                                            "in": "query",
                                            "schema": {"type": "string"},
                                        },
                                        {
                                            "name": "limit",
                                            "in": "query",
                                            "schema": {"type": "integer"},
                                        },
                                    ],
                                    "responses": {
                                        "200": {
                                            "description": "Proposal list",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/ingest": {
                                "post": {
                                    "summary": "Ingest text payload",
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "text": {"type": "string"},
                                                        "source": {"type": "string"},
                                                        "device": {"type": "string"},
                                                    },
                                                    "required": ["text"],
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Acknowledged",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/network/mark": {
                                "post": {
                                    "summary": "Mark a discovered device as useful",
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "ip": {"type": "string"},
                                                        "label": {"type": "string"},
                                                        "note": {"type": "string"},
                                                    },
                                                    "required": ["ip"],
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Marked",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/ask": {
                                "post": {
                                    "summary": "Ask Pumpkin (LLM)",
                                    "parameters": [
                                        {
                                            "name": "X-Pumpkin-OpenAI-Key",
                                            "in": "header",
                                            "schema": {"type": "string"},
                                        }
                                    ],
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "text": {"type": "string"},
                                                        "source": {"type": "string"},
                                                        "device": {"type": "string"},
                                                        "ts": {"type": "string"},
                                                        "location": {"type": "object"},
                                                        "async": {"type": "boolean"},
                                                    },
                                                    "required": ["text"],
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Answer",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/ask/result": {
                                "get": {
                                    "summary": "Fetch async ask result",
                                    "parameters": [
                                        {
                                            "name": "event_id",
                                            "in": "query",
                                            "schema": {"type": "integer"},
                                        }
                                    ],
                                    "responses": {
                                        "200": {
                                            "description": "Async ask result",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/errors": {
                                "post": {
                                    "summary": "Record client error report",
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "message": {"type": "string"},
                                                        "stack": {"type": "string"},
                                                        "device": {"type": "string"},
                                                        "manufacturer": {"type": "string"},
                                                        "sdk": {"type": "integer"},
                                                        "app": {"type": "string"},
                                                        "ts": {"type": "string"},
                                                    },
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Acknowledged",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/ha/webhook": {
                                "post": {
                                    "summary": "Record Home Assistant webhook event",
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {"type": "object"}
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Acknowledged",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/llm/config": {
                                "post": {
                                    "summary": "Set LLM configuration",
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "api_key": {"type": "string"},
                                                        "model": {"type": "string"},
                                                        "base_url": {"type": "string"},
                                                    },
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Updated",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/proposals/approve": {
                                "post": {
                                    "summary": "Approve proposal",
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "integer"},
                                                        "actor": {"type": "string"},
                                                        "reason": {"type": "string"},
                                                    },
                                                    "required": ["id"],
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Decision recorded",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/proposals/reject": {
                                "post": {
                                    "summary": "Reject proposal",
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "integer"},
                                                        "actor": {"type": "string"},
                                                        "reason": {"type": "string"},
                                                    },
                                                    "required": ["id"],
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Decision recorded",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                        },
                    },
                )
                return
            self.send_response(404)
            self.end_headers()
            return
        finally:
            self._log_request()

    def _handle_ingest(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        text = data.get("text")
        if not isinstance(text, str):
            _bad_request(self, "text must be a string")
            return
        text = _normalize_text(text)
        if not text:
            _bad_request(self, "text must not be empty")
            return
        source = data.get("source")
        if source is not None and not isinstance(source, str):
            _bad_request(self, "source must be a string")
            return
        device = data.get("device")
        if device is not None and not isinstance(device, str):
            _bad_request(self, "device must be a string")
            return
        ha_user_id = data.get("ha_user_id")
        if ha_user_id is not None and not isinstance(ha_user_id, str):
            _bad_request(self, "ha_user_id must be a string")
            return
        ha_user_name = data.get("ha_user_name")
        if ha_user_name is not None and not isinstance(ha_user_name, str):
            _bad_request(self, "ha_user_name must be a string")
            return
        truncated = _truncate_text(text, INGEST_LOG_TEXT_LIMIT)
        print(
            "PumpkinVoice ingest "
            f"source={source!r} device={device!r} text={truncated!r}"
        )
        try:
            conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
            header_api_key = self.headers.get("X-Pumpkin-OpenAI-Key")
            if header_api_key:
                try:
                    store.set_memory(conn, "llm.openai_api_key", header_api_key.strip())
                except Exception:
                    pass
            _apply_ha_identity(conn, device, ha_user_id, ha_user_name)
            store.insert_event(
                conn,
                source="voice",
                event_type="voice.ingest",
                payload={
                    "text": text,
                    "source": source,
                    "device": device,
                    "ha_user_id": ha_user_id,
                    "ha_user_name": ha_user_name,
                },
                severity="info",
            )
            if _parse_car_telemetry_text(text):
                _maybe_emit_car_alert(conn)
        except Exception:
            pass
        _send_json(
            self,
            200,
            {
                "status": "ok",
                "received": {"text": text, "source": source, "device": device},
            },
        )

    def _handle_notifications_test(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        message = "Test alert from Pumpkin."
        if length:
            try:
                data = _parse_json(body)
            except ValueError:
                _bad_request(self, "invalid JSON")
                return
            if isinstance(data, dict):
                custom = data.get("message")
                if isinstance(custom, str) and custom.strip():
                    message = custom.strip()
        try:
            conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
            payload = {
                "message": message,
                "concerns": ["Test alert"],
                "anomalies": [],
                "report_url": "/ui/car/alerts",
            }
            store.insert_event(
                conn,
                source="voice",
                event_type="car.alert",
                payload=payload,
                severity="warn",
            )
            act.notify_local(message, str(settings.audit_path()))
        except Exception:
            pass
        _send_json(self, 200, {"status": "ok", "message": message})

    def _handle_ask(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        text = data.get("text")
        if not isinstance(text, str):
            _bad_request(self, "text must be a string")
            return
        text = _normalize_text(text)
        if not text:
            _bad_request(self, "text must not be empty")
            return
        if len(text) > MAX_TEXT_LEN:
            _bad_request(self, "text too long")
            return
        source = data.get("source")
        if source is not None and not isinstance(source, str):
            _bad_request(self, "source must be a string")
            return
        device = data.get("device")
        if device is not None and not isinstance(device, str):
            _bad_request(self, "device must be a string")
            return
        ha_user_id = data.get("ha_user_id")
        if ha_user_id is not None and not isinstance(ha_user_id, str):
            _bad_request(self, "ha_user_id must be a string")
            return
        ha_user_name = data.get("ha_user_name")
        if ha_user_name is not None and not isinstance(ha_user_name, str):
            _bad_request(self, "ha_user_name must be a string")
            return
        async_flag = _parse_bool(data.get("async")) or _parse_bool(
            self.headers.get("X-Pumpkin-Async")
        )
        payload = {
            "text": text,
            "source": source,
            "device": device,
            "ha_user_id": ha_user_id,
            "ha_user_name": ha_user_name,
            "client_ip": self.client_address[0] if self.client_address else None,
            "ts": data.get("ts"),
            "location": data.get("location"),
        }
        print(
            "PumpkinVoice ask "
            f"source={source!r} device={device!r} text={_truncate_text(text, INGEST_LOG_TEXT_LIMIT)!r}",
            flush=True,
        )
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        llm_config = _load_llm_config(conn)
        header_api_key = self.headers.get("X-Pumpkin-OpenAI-Key")
        api_key = header_api_key or llm_config["api_key"]
        if header_api_key and not llm_config["api_key"]:
            # Persist a provided key so future planner calls can run without header.
            try:
                store.set_memory(conn, "llm.openai_api_key", header_api_key.strip())
            except Exception:
                pass
        _apply_ha_identity(conn, device, ha_user_id, ha_user_name)
        memory_ctx = {
            "api_key": api_key,
            "model": llm_config["model"],
            "base_url": llm_config["base_url"],
        }
        notice = _expansion_notice(device, conn)
        event_id = store.insert_event(
            conn,
            source="voice",
            event_type="voice.ask",
            payload=payload,
            severity="info",
        )
        if async_flag:
            _store_async_result(conn, event_id, "pending")

            def _async_worker() -> None:
                worker_conn = init_db(
                    str(settings.db_path()), str(settings.repo_root() / "migrations")
                )
                reply, route, error = _compute_ask_reply(
                    text,
                    device,
                    payload,
                    worker_conn,
                    api_key,
                    llm_config,
                    memory_ctx,
                    notice,
                )
                if error:
                    _store_async_result(worker_conn, event_id, "error", route=route, error=error)
                    return
                final_reply = _finalize_reply_only(
                    worker_conn, payload, reply or "", notice, route, memory_ctx
                )
                _store_async_result(
                    worker_conn, event_id, "ok", reply=final_reply, route=route
                )

            threading.Thread(target=_async_worker, daemon=True).start()
            _send_json(self, 202, {"status": "accepted", "event_id": event_id})
            return

        reply, route, error = _compute_ask_reply(
            text, device, payload, conn, api_key, llm_config, memory_ctx, notice
        )
        if error:
            if error == "openai_request_failed" or error.startswith("openai_http_"):
                _send_json(self, 502, {"error": error})
            else:
                _send_json(self, 503, {"error": error})
            return
        print(
            f"PumpkinVoice ask_reply { _truncate_text(reply or '', INGEST_LOG_TEXT_LIMIT)!r}",
            flush=True,
        )
        _reply_and_record(self, conn, payload, reply or "", notice, route, memory_ctx)

    def _handle_errors(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        message = data.get("message")
        stack = data.get("stack")
        if message is not None and not isinstance(message, str):
            _bad_request(self, "message must be a string")
            return
        if stack is not None and not isinstance(stack, str):
            _bad_request(self, "stack must be a string")
            return
        payload = {
            "message": message,
            "stack": stack,
            "device": data.get("device"),
            "manufacturer": data.get("manufacturer"),
            "sdk": data.get("sdk"),
            "app": data.get("app"),
            "ts": data.get("ts"),
            "client_ip": self.client_address[0] if self.client_address else None,
        }
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        event_id = store.insert_event(
            conn,
            source="android",
            event_type="android.error",
            payload=payload,
            severity="warn",
        )
        _send_json(self, 200, {"status": "ok", "event_id": event_id})

    def _handle_ha_webhook(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        event_id = _record_ha_event(conn, data)
        _send_json(self, 200, {"status": "ok", "event_id": event_id})

    def _handle_proposal_decision(self, decision: str) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        proposal_id = data.get("id")
        if not isinstance(proposal_id, int):
            _bad_request(self, "id must be an integer")
            return
        actor = data.get("actor")
        if actor is not None and not isinstance(actor, str):
            _bad_request(self, "actor must be a string")
            return
        reason = data.get("reason")
        if reason is not None and not isinstance(reason, str):
            _bad_request(self, "reason must be a string")
            return
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        row = store.get_proposal(conn, proposal_id)
        if not row:
            _send_json(self, 404, {"error": "proposal_not_found"})
            return
        policy_hash = row["policy_hash"]
        store.insert_approval(
            conn,
            proposal_id=proposal_id,
            actor=actor or "android",
            decision=decision,
            reason=reason,
            policy_hash=policy_hash,
        )
        store.update_proposal_status(conn, proposal_id, decision)
        _send_json(self, 200, {"status": "ok", "id": proposal_id, "decision": decision})

    def _handle_llm_config(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        api_key = data.get("api_key")
        model = data.get("model")
        base_url = data.get("base_url")
        if api_key is not None and not isinstance(api_key, str):
            _bad_request(self, "api_key must be a string")
            return
        if model is not None and not isinstance(model, str):
            _bad_request(self, "model must be a string")
            return
        if base_url is not None and not isinstance(base_url, str):
            _bad_request(self, "base_url must be a string")
            return
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        env_updates: Dict[str, str] = {}
        if api_key is not None:
            cleaned = api_key.strip()
            store.set_memory(conn, "llm.openai_api_key", cleaned)
            os.environ["PUMPKIN_OPENAI_API_KEY"] = cleaned
            env_updates["PUMPKIN_OPENAI_API_KEY"] = cleaned
        if model is not None:
            cleaned = model.strip()
            store.set_memory(conn, "llm.openai_model", cleaned)
            os.environ["PUMPKIN_OPENAI_MODEL"] = cleaned
            env_updates["PUMPKIN_OPENAI_MODEL"] = cleaned
        if base_url is not None:
            cleaned = base_url.strip()
            store.set_memory(conn, "llm.openai_base_url", cleaned)
            os.environ["PUMPKIN_OPENAI_BASE_URL"] = cleaned
            env_updates["PUMPKIN_OPENAI_BASE_URL"] = cleaned
        if env_updates and not _update_env_file(env_updates):
            append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "llm.env_write_failed",
                    "reason": "unable to write /etc/pumpkin/pumpkin.env",
                },
            )
        llm_config = _load_llm_config(conn)
        _send_json(
            self,
            200,
            {
                "status": "ok",
                "provider": "openai",
                "model": llm_config["model"],
                "base_url": llm_config["base_url"],
                "enabled": bool(llm_config["api_key"]),
            },
        )

    def _handle_network_mark(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        ip = data.get("ip")
        label = data.get("label")
        note = data.get("note")
        if not isinstance(ip, str) or not ip.strip():
            _bad_request(self, "ip must be a string")
            return
        if label is not None and not isinstance(label, str):
            _bad_request(self, "label must be a string")
            return
        if note is not None and not isinstance(note, str):
            _bad_request(self, "note must be a string")
            return
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        item = {
            "ip": ip.strip(),
            "label": (label or "useful").strip(),
            "note": (note or "").strip(),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        current = store.get_memory(conn, "network.discovery.useful")
        if not isinstance(current, list):
            current = []
        current.append(item)
        store.set_memory(conn, "network.discovery.useful", current[-200:])
        store.insert_event(
            conn,
            source="network",
            event_type="network.discovery.marked",
            payload=item,
            severity="info",
        )
        _send_json(self, 200, {"status": "ok", "marked": item})

    def _handle_network_deep_scan(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        ip = data.get("ip")
        ports = data.get("ports")
        if not isinstance(ip, str) or not ip.strip():
            _bad_request(self, "ip must be a string")
            return
        ip = ip.strip()
        try:
            ip_address(ip)
        except ValueError:
            _bad_request(self, "ip must be a valid address")
            return
        ports_payload: Any = "all"
        if ports is None:
            ports = list(range(1, 65536))
        elif isinstance(ports, list):
            cleaned: List[int] = []
            for item in ports:
                try:
                    port = int(item)
                except (TypeError, ValueError):
                    continue
                if 1 <= port <= 65535:
                    cleaned.append(port)
            if not cleaned:
                _bad_request(self, "ports must include valid integers")
                return
            ports = sorted(set(cleaned))
            ports_payload = ports
        else:
            _bad_request(self, "ports must be a list")
            return

        with _DEEP_SCAN_LOCK:
            if ip in _DEEP_SCAN_RUNNING:
                _send_json(self, 409, {"status": "running", "ip": ip})
                return
            _DEEP_SCAN_RUNNING.add(ip)

        thread = threading.Thread(
            target=_run_deep_scan,
            args=(ip, ports, ports_payload),
            daemon=True,
        )
        thread.start()
        _send_json(self, 202, {"status": "queued", "ip": ip})

    def _handle_identity_link(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        person_id = data.get("person_id")
        device = data.get("device")
        if person_id is not None and not isinstance(person_id, str):
            _bad_request(self, "person_id must be a string")
            return
        if device is not None and not isinstance(device, str):
            _bad_request(self, "device must be a string")
            return
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        if not device:
            last_device = store.get_memory(conn, "voice.last_device")
            device = last_device if isinstance(last_device, str) else None
        if not device:
            _bad_request(self, "device_required")
            return
        if not isinstance(person_id, str) or not person_id.strip():
            _bad_request(self, "person_id_required")
            return
        ha_summary = store.get_memory(conn, "homeassistant.summary") or {}
        person_name = None
        people = ha_summary.get("people") if isinstance(ha_summary, dict) else None
        if isinstance(people, list):
            for person in people:
                if not isinstance(person, dict):
                    continue
                if person.get("entity_id") == person_id:
                    person_name = person.get("name")
                    break
        _apply_ha_person_link(conn, device, person_id, person_name)
        _send_json(
            self,
            200,
            {
                "status": "ok",
                "device": device,
                "person_id": person_id,
                "person_name": person_name,
            },
        )

    def _handle_network_rtsp_probe(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        ip = data.get("ip")
        port = data.get("port", 554)
        paths = data.get("paths")
        if not isinstance(ip, str) or not ip.strip():
            _bad_request(self, "ip must be a string")
            return
        try:
            ip_address(ip.strip())
        except ValueError:
            _bad_request(self, "ip must be a valid address")
            return
        try:
            port = int(port)
        except (TypeError, ValueError):
            _bad_request(self, "port must be an integer")
            return
        if port < 1 or port > 65535:
            _bad_request(self, "port must be 1-65535")
            return
        if paths is None:
            paths = []
        if isinstance(paths, str):
            paths = [item.strip() for item in paths.split(",") if item.strip()]
        if not isinstance(paths, list):
            _bad_request(self, "paths must be a list or comma-separated string")
            return
        # Cap probes to keep it quick.
        paths = paths[:20]
        module_cfg = _load_network_module_cfg()
        timeout_seconds = float(module_cfg.get("deep_scan_timeout_seconds", 0.2))
        max_banner_bytes = int(module_cfg.get("active", {}).get("max_banner_bytes", 256))
        results = observe.rtsp_probe_paths(
            ip=ip.strip(),
            port=port,
            paths=paths,
            timeout=timeout_seconds,
            max_bytes=max_banner_bytes,
        )
        _send_json(
            self,
            200,
            {
                "status": "ok",
                "ip": ip.strip(),
                "port": port,
                "results": results,
            },
        )

    def _handle_vision_alerts(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        camera_id = data.get("camera_id")
        enabled = data.get("enabled")
        if not isinstance(camera_id, str) or not camera_id.strip():
            _bad_request(self, "camera_id must be a string")
            return
        if not isinstance(enabled, bool):
            _bad_request(self, "enabled must be a boolean")
            return
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        disabled = store.get_memory(conn, "vision.alerts.disabled") or []
        if not isinstance(disabled, list):
            disabled = []
        disabled_set = {str(item) for item in disabled}
        camera_id = camera_id.strip()
        if enabled:
            disabled_set.discard(camera_id)
        else:
            disabled_set.add(camera_id)
        store.set_memory(conn, "vision.alerts.disabled", sorted(disabled_set))
        _send_json(self, 200, {"status": "ok", "camera_id": camera_id, "enabled": enabled})

    def _handle_vision_enroll(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        subject = data.get("subject")
        snapshot_path = data.get("snapshot_path")
        if not isinstance(subject, str) or not subject.strip():
            _bad_request(self, "subject must be a string")
            return
        if not isinstance(snapshot_path, str) or not snapshot_path.strip():
            _bad_request(self, "snapshot_path must be a string")
            return
        safe_path = _safe_snapshot_path(snapshot_path.strip())
        if not safe_path:
            _bad_request(self, "snapshot_path_invalid")
            return
        payload = safe_path.read_bytes()
        config_path = settings.modules_config_path()
        if not config_path.exists():
            _send_json(self, 400, {"status": "error", "error": "modules_config_missing"})
            return
        config = module_config.load_config(str(config_path))
        module_cfg = config.get("modules", {}).get("face.recognition", {})
        provider = module_cfg.get("provider", {}) if isinstance(module_cfg, dict) else {}
        result = vision._compreface_enroll(payload, subject.strip(), provider if isinstance(provider, dict) else {})
        if not result.get("ok"):
            _send_json(self, 400, {"status": "error", "detail": result})
            return
        _send_json(self, 200, {"status": "ok", "subject": subject.strip(), "response": result.get("response")})

    def _handle_vision_false_positive(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        snapshot_hash = data.get("snapshot_hash")
        if not isinstance(snapshot_hash, str) or not snapshot_hash.strip():
            _bad_request(self, "snapshot_hash must be a string")
            return
        snapshot_hash = snapshot_hash.strip()
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        false_positives = store.get_memory(conn, "vision.false_positives") or []
        if not isinstance(false_positives, list):
            false_positives = []
        false_set = {str(item) for item in false_positives}
        false_set.add(snapshot_hash)
        store.set_memory(conn, "vision.false_positives", sorted(false_set))
        _send_json(self, 200, {"status": "ok", "snapshot_hash": snapshot_hash})

    def _handle_vision_unknown_clear(self) -> None:
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        cursor = conn.execute("SELECT COUNT(*) FROM events WHERE type = ?", ("face.unknown",))
        count = cursor.fetchone()[0] if cursor else 0
        conn.execute("DELETE FROM events WHERE type = ?", ("face.unknown",))
        conn.commit()
        _send_json(self, 200, {"status": "ok", "cleared": count})

    def _handle_suggestion(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        text = data.get("text")
        if not isinstance(text, str) or not text.strip():
            _bad_request(self, "text must be a string")
            return
        text = _normalize_text(text)
        if len(text) > MAX_TEXT_LEN:
            _bad_request(self, "text too long")
            return
        device = data.get("device")
        if device is not None and not isinstance(device, str):
            _bad_request(self, "device must be a string")
            return
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        store.insert_event(
            conn,
            source="voice",
            event_type="user.suggestion",
            payload={"text": text, "device": device},
            severity="info",
        )
        summary = f"Suggestion: {text[:80]}"
        policy = policy_mod.load_policy(str(settings.policy_path()))
        if not store.proposal_exists(conn, summary, statuses=["pending", "approved"]):
            store.insert_proposal(
                conn,
                kind="action.request",
                summary=summary,
                details={
                    "rationale": "User submitted a suggestion that should be explored and converted into an actionable plan.",
                    "suggestion": text,
                    "implementation": (
                        "Analyze the suggestion, identify required devices or integrations, "
                        "and draft an implementation plan with steps and verification."
                    ),
                    "verification": "Confirm the proposed implementation is feasible and aligned with the suggestion.",
                    "rollback_plan": "Skip or revise the suggestion if it is not feasible.",
                },
                risk=0.3,
                expected_outcome="Suggestion is evaluated and a clear action plan is prepared.",
                status="pending",
                policy_hash=policy.policy_hash,
                needs_new_capability=False,
                capability_request=None,
                ai_context_hash=None,
                ai_context_excerpt=None,
                steps=[
                    "Analyze the suggestion and existing capabilities.",
                    "Draft an implementation plan with required integrations.",
                    "Verify feasibility and propose next actions.",
                ],
            )
        _send_json(self, 200, {"status": "ok"})

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def _apply_approved_actions(limit: int = 5) -> None:
    conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
    rows = store.fetch_approved_unexecuted(conn)[:limit]
    if not rows:
        return
    audit_path = str(settings.audit_path())
    allow_patch = _parse_bool(os.getenv("PUMPKIN_EXECUTOR_ALLOW_PATCH", "0"))
    for row in rows:
        details = json.loads(row["details_json"])
        action_type = details.get("action_type")
        params = details.get("action_params") or {}
        if action_type == "code.apply_patch" and not allow_patch:
            append_jsonl(
                audit_path,
                {
                    "kind": "executor.skipped",
                    "proposal_id": row["id"],
                    "action_type": action_type,
                    "reason": "patches_disabled",
                },
            )
            continue
        if action_type not in {"code.apply_patch", "notify.local"}:
            continue
        action_id = store.insert_action(
            conn,
            proposal_id=row["id"],
            action_type=action_type,
            params=params,
            status="started",
            policy_hash=row["policy_hash"],
        )
        try:
            result = act.execute_action(action_type, params, audit_path)
            store.finish_action(conn, action_id, status="succeeded", result=result)
            store.update_proposal_status(conn, row["id"], "executed")
            append_jsonl(
                audit_path,
                {
                    "kind": "executor.applied",
                    "proposal_id": row["id"],
                    "action_type": action_type,
                    "result": result,
                },
            )
        except Exception as exc:  # pragma: no cover
            store.finish_action(
                conn, action_id, status="failed", result={"error": str(exc)}
            )
            append_jsonl(
                audit_path,
                {
                    "kind": "executor.failed",
                    "proposal_id": row["id"],
                    "action_type": action_type,
                    "error": str(exc),
                },
            )


def _executor_loop(stop_event: threading.Event, interval_seconds: int = 300) -> None:
    while not stop_event.wait(interval_seconds):
        try:
            _apply_approved_actions(limit=5)
        except Exception as exc:  # pragma: no cover
            append_jsonl(
                str(settings.audit_path()),
                {"kind": "executor.error", "error": str(exc)},
            )


def _process_timer_announcements() -> None:
    conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
    entries = store.get_memory(conn, "voice.timer_announcements") or []
    if not isinstance(entries, list) or not entries:
        return
    now = datetime.now(timezone.utc)
    remaining = []
    ready = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        due_ts = entry.get("due_ts")
        if not isinstance(due_ts, str):
            continue
        try:
            due = datetime.fromisoformat(due_ts)
        except ValueError:
            continue
        if due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        if due <= now:
            ready.append(entry)
        else:
            remaining.append(entry)
    if not ready:
        return
    base_url, token, error = _load_ha_connection(conn)
    if error:
        for entry in ready:
            entry["due_ts"] = (now + timedelta(seconds=60)).isoformat()
            remaining.append(entry)
        store.set_memory(conn, "voice.timer_announcements", remaining)
        store.insert_event(
            conn,
            source="voice",
            event_type="timer.notify_failed",
            payload={"error": error},
            severity="warn",
        )
        return
    for entry in ready:
        message = entry.get("message") or "Timer finished."
        result = ha_client.call_service(
            base_url=base_url,
            token=token,
            domain="notify",
            service="notify",
            payload={"message": message, "title": "Pumpkin Timer"},
            timeout=settings.ha_request_timeout_seconds(),
        )
        if result.get("ok"):
            store.insert_event(
                conn,
                source="voice",
                event_type="timer.finished",
                payload={"message": message},
                severity="info",
            )
        else:
            entry["due_ts"] = (now + timedelta(seconds=60)).isoformat()
            remaining.append(entry)
            store.insert_event(
                conn,
                source="voice",
                event_type="timer.notify_failed",
                payload={"error": result.get("error")},
                severity="warn",
            )
    store.set_memory(conn, "voice.timer_announcements", remaining)


def _timer_announcement_loop(stop_event: threading.Event, interval_seconds: int = 5) -> None:
    while not stop_event.wait(interval_seconds):
        try:
            _process_timer_announcements()
        except Exception as exc:  # pragma: no cover
            append_jsonl(
                str(settings.audit_path()),
                {"kind": "timer.announcement_error", "error": str(exc)},
            )


def run_server(host: str | None = None, port: int | None = None) -> None:
    stop_event = threading.Event()
    executor_thread = threading.Thread(
        target=_executor_loop, args=(stop_event,), daemon=True
    )
    executor_thread.start()
    timer_thread = threading.Thread(
        target=_timer_announcement_loop, args=(stop_event,), daemon=True
    )
    timer_thread.start()
    bind_host = host or settings.voice_server_host()
    bind_port = port or settings.voice_server_port()
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "voice.server_starting",
            "host": bind_host,
            "port": bind_port,
        },
    )
    print(f"voice server starting on {bind_host}:{bind_port}")
    try:
        server = ThreadingHTTPServer((bind_host, bind_port), VoiceHandler)
    except Exception as exc:
        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "voice.server_bind_failed",
                "host": bind_host,
                "port": bind_port,
                "error": str(exc),
            },
        )
        raise
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "voice.server_listening",
            "host": bind_host,
            "port": bind_port,
        },
    )
    print(f"voice server listening on {bind_host}:{bind_port}")
    try:
        server.serve_forever()
    finally:
        stop_event.set()
