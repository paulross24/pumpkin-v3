"""Voice text input HTTP server."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from . import settings
from . import store
from . import module_config
from . import ha_client
from . import catalog as catalog_mod
from . import intent
from . import policy as policy_mod
from . import propose
from .audit import append_jsonl
from .db import init_db


MAX_TEXT_LEN = 500
INGEST_LOG_TEXT_LIMIT = 160
OPENAI_TIMEOUT_SECONDS = 15
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


def _effective_bind(handler: BaseHTTPRequestHandler) -> tuple[str, int]:
    try:
        address = handler.server.server_address
        return address[0], int(address[1])
    except Exception:
        return settings.voice_server_host(), settings.voice_server_port()


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
        "make plans",
    ]
    return any(token in lowered for token in triggers)


def _maybe_improvement_plan(text: str, device: str | None, conn) -> str | None:
    if not _is_improvement_request(text):
        return None
    recent = store.list_events(conn, limit=50)
    events = sorted(recent, key=lambda row: row["id"]) if recent else []
    try:
        proposals = propose.build_proposals(events, conn)
    except Exception:
        return "I couldn't generate improvement plans right now."
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
        "action_type": "code.apply_patch",
        "action_params": {"repo_root": repo_root, "patch": patch},
    }
    policy = policy_mod.load_policy(str(settings.policy_path()))
    proposal_id = store.insert_proposal(
        conn,
        kind="action.request",
        summary=summary,
        details=details,
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
    if isinstance(profile, dict):
        return profile
    return None


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


def _match_area(areas: List[Dict[str, Any]], target: str) -> Dict[str, Any] | None:
    needle = target.lower()
    for area in areas:
        name = str(area.get("name") or "").lower()
        if name and name in needle:
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
    entities: Dict[str, Dict[str, Any]], domain: str, area_hint: str
) -> List[str]:
    matched: List[str] = []
    needle = area_hint.lower()
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
    return matched


def _last_target_key(device: str) -> str:
    return f"voice.last_target.{device}"


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


def _execute_ha_command(text: str, conn, device: str | None) -> str | None:
    command = _parse_control_command(text)
    if not command:
        return None
    command["target"] = _resolve_followup_target(command["target"], device, conn)
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return "Home Assistant is not configured."
    try:
        config = module_config.load_config(str(config_path))
    except Exception:
        return "Home Assistant config is invalid."
    enabled = set(config.get("enabled", []))
    if "homeassistant.observer" not in enabled:
        return "Home Assistant integration is not enabled."
    module_cfg = config.get("modules", {}).get("homeassistant.observer", {})
    base_url = module_cfg.get("base_url")
    token_env = module_cfg.get("token_env", "PUMPKIN_HA_TOKEN")
    token = os.getenv(token_env)
    if not base_url or not token:
        return "Home Assistant credentials are missing."

    entities = store.get_memory(conn, "homeassistant.entities") or {}
    if not isinstance(entities, dict):
        entities = {}
    entity_id = _match_entity(entities, command["target"])
    if not entity_id:
        summary = store.get_memory(conn, "homeassistant.summary") or {}
        areas = summary.get("areas") or []
        if not isinstance(areas, list):
            areas = []
        area = _match_area(areas, command["target"])
        domain_hint = _area_domain_hint(command["target"])
        if area and domain_hint and _wants_area_control(command["target"]) and command["action"] in {
            "turn_on",
            "turn_off",
            "toggle",
        }:
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
                entity_ids = _match_entities_by_area_hint(entities, domain_hint, area_hint)
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
                    _store_last_target(conn, device, command["target"])
                    return f"Done. {command['action'].replace('_', ' ')} {area_hint} {domain_hint}s."
                return f"I couldn't find any {domain_hint}s in {area.get('name')}."
            _store_last_target(conn, device, command["target"])
            return f"Done. {command['action'].replace('_', ' ')} {area.get('name')} {domain_hint}s."
        if domain_hint and _wants_area_control(command["target"]) and command["action"] in {
            "turn_on",
            "turn_off",
            "toggle",
        }:
            area_hint = _extract_area_hint(command["target"])
            entity_ids = _match_entities_by_area_hint(entities, domain_hint, area_hint)
            if entity_ids:
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
                _store_last_target(conn, device, command["target"])
                return f"Done. {command['action'].replace('_', ' ')} {area_hint} {domain_hint}s."
        return f"I couldn't find a device named {command['target']}."
    domain = entity_id.split(".", 1)[0]
    service = None
    payload = {"entity_id": entity_id}
    action = command["action"]
    if action in {"turn_on", "turn_off", "toggle"}:
        service = action
    elif action in {"open", "close"}:
        service = "open_cover" if action == "open" else "close_cover"
    elif action in {"lock", "unlock"}:
        service = action
    elif action == "set_temperature":
        service = "set_temperature"
        payload["temperature"] = command.get("value")
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
    _store_last_target(conn, device, command["target"])
    return f"Done. {action.replace('_', ' ')} {command['target']}."


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
    return created


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
    if rationale:
        return (
            f"Proposal #{proposal_id}: {summary}. "
            f"Rationale: {rationale}. Reply yes to approve or no to skip."
        )
    return f"Proposal #{proposal_id}: {summary}. Reply yes to approve or no to skip."


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


def _health_query(text: str) -> bool:
    lowered = text.lower()
    return bool(
        "system health" in lowered
        or "health report" in lowered
        or "risk report" in lowered
        or "status report" in lowered
    )


def _parse_time_24h(value: str) -> str | None:
    match = re.search(r"(\d{1,2})(?::(\d{2}))?\s*(am|pm)?", value.strip().lower())
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
    match = re.search(
        r"(?:from|between)?\s*(\d{1,2}(?::\d{2})?\s*(?:am|pm)?)\s*(?:to|-)\s*(\d{1,2}(?::\d{2})?\s*(?:am|pm)?)",
        lowered,
    )
    if not match:
        return None
    start = _parse_time_24h(match.group(1))
    end = _parse_time_24h(match.group(2))
    if not start or not end:
        return None
    days = "weekdays" if "weekday" in lowered else "weekends" if "weekend" in lowered else "daily"
    return {"start": start, "end": end, "days": days}


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
        }
    return {
        "system_snapshot": system_snapshot,
        "issues": issues,
        "homeassistant": trimmed_ha,
        "pending_proposals": [
            {"id": row["id"], "summary": row["summary"], "kind": row["kind"]}
            for row in pending
        ],
        "recent_errors": errors,
        "speaker_profile": profile_summary,
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
        return "I don't know who this device belongs to yet. Tell me your name first."
    prefs = profile.get("preferences", {})
    if not isinstance(prefs, dict):
        prefs = {}
    prefs[key] = value
    profile["preferences"] = prefs
    store.set_memory(conn, f"speaker.profile.device:{device.strip()}", profile)
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
    store.set_memory(conn, key, profile)
    return None


def _handle_preference_update(text: str, device: str | None, conn) -> str | None:
    quiet = _parse_quiet_hours(text)
    if quiet:
        error = _update_profile_preference(conn, device, "quiet_hours", quiet)
        if error:
            return error
        return f"Quiet hours set to {quiet['start']}–{quiet['end']} ({quiet['days']})."
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
    return " ".join(parts)


def _memory_reply(conn, device: str | None, text: str) -> str:
    lowered = text.lower()
    if "forget" in lowered:
        if not isinstance(device, str) or not device.strip():
            return "I need a device ID to forget you."
        store.set_memory(conn, f"speaker.profile.device:{device.strip()}", {"state": "guest"})
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
                _send_json(
                    self,
                    200,
                    {
                        "status": "ok",
                        "host": settings.voice_server_host(),
                        "port": settings.voice_server_port(),
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
                            "GET /config",
                            "GET /catalog",
                            "GET /openapi.json",
                            "GET /proposals",
                            "GET /summary",
                            "GET /timeline",
                            "GET /errors",
                            "GET /llm/config",
                            "POST /ask",
                            "POST /errors",
                            "POST /proposals/approve",
                            "POST /proposals/reject",
                            "POST /llm/config",
                            "POST /ingest",
                            "POST /ha/webhook",
                            "POST /voice",
                            "POST /satellite/voice",
                        ],
                    },
                )
                return
            if path == "/config":
                bind_host, bind_port = _effective_bind(self)
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                llm_config = _load_llm_config(conn)
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
            if path == "/proposals":
                status = params.get("status", [None])[0]
                limit = _parse_limit(params.get("limit", [None])[0])
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                rows = store.list_proposals(conn, status=status, limit=limit)
                proposals = []
                for row in rows:
                    try:
                        details = json.loads(row["details_json"])
                    except Exception:
                        details = {}
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
            if path == "/summary":
                status = params.get("status", ["pending"])[0]
                limit = _parse_limit(params.get("limit", [None])[0], default=10)
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
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
                home_state = _home_state_summary(conn)
                issues = _summarize_issues(system_snapshot)
                _send_json(
                    self,
                    200,
                    {
                        "status": "ok",
                        "heartbeat": heartbeat_event,
                        "system_snapshot": system_snapshot,
                        "homeassistant": ha_summary,
                        "homeassistant_last_event": ha_last_event,
                        "home_state": home_state,
                        "issues": issues,
                        "proposals": proposal_items,
                        "proposal_count": len(proposal_items),
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
                            "/config": {"get": {"summary": "Runtime config"}},
                            "/catalog": {"get": {"summary": "Module catalog"}},
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
        truncated = _truncate_text(text, INGEST_LOG_TEXT_LIMIT)
        print(
            "PumpkinVoice ingest "
            f"source={source!r} device={device!r} text={truncated!r}"
        )
        _send_json(
            self,
            200,
            {
                "status": "ok",
                "received": {"text": text, "source": source, "device": device},
            },
        )

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
        payload = {
            "text": text,
            "source": source,
            "device": device,
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
        store.insert_event(
            conn,
            source="voice",
            event_type="voice.ask",
            payload=payload,
            severity="info",
        )
        proposal_followup = _handle_proposal_followup(text, device, conn)
        if proposal_followup:
            print(f"PumpkinVoice ask_reply {proposal_followup!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": proposal_followup})
            return
        presence_reply = _lookup_presence(text)
        if presence_reply:
            print(f"PumpkinVoice ask_reply {presence_reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": presence_reply})
            return
        if _home_query(text):
            home_reply = _local_home_reply(conn)
            if home_reply:
                print(f"PumpkinVoice ask_reply {home_reply!r}", flush=True)
                _send_json(self, 200, {"status": "ok", "reply": home_reply})
                return
        if _home_summary_query(text):
            summary_reply = _local_house_summary_reply(conn)
            print(f"PumpkinVoice ask_reply {summary_reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": summary_reply})
            return
        control_reply = _execute_ha_command(text, conn, device)
        if control_reply:
            print(f"PumpkinVoice ask_reply {control_reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": control_reply})
            return
        improvement_reply = _maybe_improvement_plan(text, device, conn)
        if improvement_reply:
            print(f"PumpkinVoice ask_reply {improvement_reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": improvement_reply})
            return
        llm_config = _load_llm_config(conn)
        api_key = self.headers.get("X-Pumpkin-OpenAI-Key") or llm_config["api_key"]
        code_reply = _maybe_code_patch(text, device, api_key, conn)
        if code_reply:
            print(f"PumpkinVoice ask_reply {code_reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": code_reply})
            return
        capability_reply = _maybe_capability_proposal(text, device, payload.get("client_ip"), conn)
        if capability_reply:
            print(f"PumpkinVoice ask_reply {capability_reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": capability_reply})
            return
        if _recent_query(text):
            reply = _recent_events_reply(conn, limit=5)
            print(f"PumpkinVoice ask_reply {reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": reply})
            return
        if "last ha event" in text.lower() or "last home assistant" in text.lower():
            reply = _last_ha_event_reply(conn)
            print(f"PumpkinVoice ask_reply {reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": reply})
            return
        if _inventory_query(text):
            reply = _inventory_reply(conn, text)
            print(f"PumpkinVoice ask_reply {reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": reply})
            return
        if _health_query(text):
            reply = _health_report_reply(conn)
            print(f"PumpkinVoice ask_reply {reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": reply})
            return
        name = _parse_speaker_name(text)
        if name:
            error = _store_speaker_name(conn, device, name)
            reply = error or f"Thanks, {name}. I'll remember you."
            print(f"PumpkinVoice ask_reply {reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": reply})
            return
        preference_reply = _handle_preference_update(text, device, conn)
        if preference_reply:
            print(f"PumpkinVoice ask_reply {preference_reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": preference_reply})
            return
        if _memory_query(text):
            reply = _memory_reply(conn, device, text)
            print(f"PumpkinVoice ask_reply {reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": reply})
            return
        calendar_reply = _lookup_calendar(text, device, conn)
        if calendar_reply:
            print(f"PumpkinVoice ask_reply {calendar_reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": calendar_reply})
            return
        if _status_query(text):
            status_reply = _local_status_reply(conn)
            print(f"PumpkinVoice ask_reply {status_reply!r}", flush=True)
            _send_json(self, 200, {"status": "ok", "reply": status_reply})
            return
        llm_config = llm_config
        api_key = api_key
        context = _build_llm_context(conn, device)
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
            _send_json(self, 503, {"error": str(exc)})
            return
        except urllib.error.HTTPError as exc:
            _send_json(self, 502, {"error": f"openai_http_{exc.code}"})
            return
        except Exception:
            _send_json(self, 502, {"error": "openai_request_failed"})
            return
        print(
            f"PumpkinVoice ask_reply { _truncate_text(reply, INGEST_LOG_TEXT_LIMIT)!r}",
            flush=True,
        )
        _send_json(self, 200, {"status": "ok", "reply": reply})

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
        if api_key is not None:
            store.set_memory(conn, "llm.openai_api_key", api_key.strip())
        if model is not None:
            store.set_memory(conn, "llm.openai_model", model.strip())
        if base_url is not None:
            store.set_memory(conn, "llm.openai_base_url", base_url.strip())
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

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def run_server(host: str | None = None, port: int | None = None) -> None:
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
    server.serve_forever()
