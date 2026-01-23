"""Proposal generation using AI planner with rule fallback."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from . import planner
from . import policy as policy_mod
from . import capabilities
from . import module_registry
from . import catalog as catalog_mod
from . import module_config_change
from . import intent
from . import runbook
from . import retrieval
from . import settings
from . import store
from . import inventory as inventory_mod
from .audit import append_jsonl

MAX_PROPOSALS_PER_LOOP = settings.max_proposals_per_loop()
MAX_STEPS_PER_PROPOSAL = settings.max_steps_per_proposal()

ALLOWED_KINDS = {
    "general",
    "maintenance",
    "action.request",
    "policy.change",
    "module.install",
    "module.enable",
    "module.disable",
    "hardware.recommendation",
    "capability.offer",
}

SPEAKER_SESSION_WINDOW_SECONDS = 30 * 60
CPU_LOAD_WARN_THRESHOLD = 2.0
MEM_AVAILABLE_WARN_KB = 200_000


def planner_cooldown_until(conn) -> Optional[datetime]:
    raw = store.get_memory(conn, "planner.cooldown_until")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def planner_cooldown_active(conn) -> bool:
    until = planner_cooldown_until(conn)
    return bool(until and until > datetime.now(timezone.utc))


def _set_planner_cooldown(conn, reason: str) -> None:
    base_seconds = settings.planner_cooldown_seconds()
    if base_seconds <= 0:
        return
    max_seconds = settings.planner_cooldown_max_seconds()
    current = store.get_memory(conn, "planner.cooldown_seconds")
    try:
        current_seconds = int(current)
    except Exception:
        current_seconds = 0
    next_seconds = max(base_seconds, current_seconds * 2 if current_seconds else base_seconds)
    next_seconds = min(next_seconds, max_seconds)
    until = datetime.now(timezone.utc) + timedelta(seconds=next_seconds)
    store.set_memory(conn, "planner.cooldown_seconds", next_seconds)
    store.set_memory(conn, "planner.cooldown_until", until.isoformat())
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "planner.cooldown_set",
            "reason": reason,
            "cooldown_seconds": next_seconds,
            "cooldown_until": until.isoformat(),
        },
    )


def _clear_planner_cooldown(conn) -> None:
    if store.get_memory(conn, "planner.cooldown_until") is None:
        return
    store.set_memory(conn, "planner.cooldown_until", None)
    store.set_memory(conn, "planner.cooldown_seconds", 0)
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "planner.cooldown_cleared",
        },
    )


def _is_rate_limited(error: str) -> bool:
    if not isinstance(error, str):
        return False
    lowered = error.lower()
    return "429" in lowered or "too many requests" in lowered or "rate limit" in lowered


def _speaker_key(payload: Dict[str, Any]) -> Optional[str]:
    device_id = payload.get("device_id")
    if isinstance(device_id, str) and device_id.strip():
        return f"device:{device_id.strip()}"
    client_ip = payload.get("client_ip")
    if isinstance(client_ip, str) and client_ip.strip():
        return f"ip:{client_ip.strip()}"
    return None


def _speaker_profile_key(speaker_key: str) -> str:
    return f"speaker.profile.{speaker_key}"


def _speaker_session_key(speaker_key: str) -> str:
    return f"speaker.session.{speaker_key}"


def _load_speaker_profile(conn, speaker_key: str) -> Optional[Dict[str, Any]]:
    data = store.get_memory(conn, _speaker_profile_key(speaker_key))
    return data if isinstance(data, dict) else None


def _save_speaker_profile(conn, speaker_key: str, profile: Dict[str, Any]) -> None:
    store.set_memory(conn, _speaker_profile_key(speaker_key), profile)


def _load_speaker_session(conn, speaker_key: str) -> Dict[str, Any]:
    data = store.get_memory(conn, _speaker_session_key(speaker_key))
    if isinstance(data, dict):
        return data
    return {}


def _save_speaker_session(conn, speaker_key: str, session: Dict[str, Any]) -> None:
    store.set_memory(conn, _speaker_session_key(speaker_key), session)


def _speaker_state(profile: Optional[Dict[str, Any]]) -> str:
    if not profile:
        return "unknown"
    state = profile.get("state")
    if state in {"guest", "named", "recognised"}:
        return state
    if profile.get("name"):
        return "named"
    return "guest"


def _session_is_new(session: Dict[str, Any], now: float) -> bool:
    last_seen = session.get("last_seen_ts")
    if not isinstance(last_seen, (int, float)):
        return True
    return (now - float(last_seen)) > SPEAKER_SESSION_WINDOW_SECONDS


def _normalize_name(text: str) -> str:
    name = " ".join(text.strip().split())
    return name[:80]


def _load_ha_people(conn) -> List[Dict[str, Any]]:
    summary = store.get_memory(conn, "homeassistant.summary")
    if isinstance(summary, dict):
        people = summary.get("people")
        if isinstance(people, list):
            return [item for item in people if isinstance(item, dict)]
    entities = store.get_memory(conn, "homeassistant.entities")
    people = []
    if isinstance(entities, dict):
        for entity_id, payload in entities.items():
            if not isinstance(entity_id, str) or not entity_id.startswith("person."):
                continue
            if not isinstance(payload, dict):
                continue
            attributes = payload.get("attributes", {}) if isinstance(payload.get("attributes"), dict) else {}
            name = attributes.get("friendly_name") or entity_id
            people.append({"entity_id": entity_id, "name": str(name), "state": payload.get("state")})
    return people


def _match_ha_person(name: str, people: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not name:
        return None
    needle = name.strip().lower()
    for person in people:
        pname = str(person.get("name") or "").strip().lower()
        entity_id = str(person.get("entity_id") or "")
        entity_tail = entity_id.split(".", 1)[-1].lower() if "." in entity_id else entity_id.lower()
        if needle == pname or needle == entity_id.lower() or needle == entity_tail:
            return person
    return None


def _ha_people_options(people: List[Dict[str, Any]], limit: int = 6) -> str:
    names = [str(person.get("name") or person.get("entity_id")) for person in people]
    names = [name for name in names if name]
    if not names:
        return ""
    if len(names) > limit:
        names = names[:limit]
        return ", ".join(names) + "..."
    return ", ".join(names)


def _context_pack(
    conn,
    policy: policy_mod.Policy,
    system_snapshot: Dict[str, Any],
    event_limit: int = 20,
) -> Dict[str, Any]:
    recent_events = store.fetch_events_since(conn, 0)[-event_limit:]
    pending = store.list_proposals(conn, status="pending", limit=20)
    memory = store.get_memory_all(conn)
    policy_text = settings.policy_path().read_text(encoding="utf-8")
    policy_excerpt = policy_text[:4096]
    registry = module_registry.load_registry(str(settings.modules_registry_path()))
    voice_events = store.list_voice_events(conn, settings.voice_event_limit())
    voice_payloads = {row["id"]: json.loads(row["payload_json"]) for row in voice_events}
    latest_voice_text = None
    if voice_events:
        latest_payload = voice_payloads.get(voice_events[0]["id"], {})
        if isinstance(latest_payload, dict):
            latest_voice_text = latest_payload.get("text")
    retrieved = retrieval.retrieve_context(
        latest_voice_text or "",
        settings.audit_path(),
        [
            settings.modules_config_path(),
            settings.modules_registry_path(),
            settings.policy_path(),
        ],
        max_results=5,
    )
    voice_speakers: Dict[int, Dict[str, Any]] = {}
    for row in voice_events:
        payload = voice_payloads.get(row["id"], {})
        speaker_key = _speaker_key(payload) if isinstance(payload, dict) else None
        profile = _load_speaker_profile(conn, speaker_key) if speaker_key else None
        voice_speakers[row["id"]] = {
            "speaker_state": _speaker_state(profile),
            "consent": bool(profile.get("consent")) if profile else False,
            "name": profile.get("name") if profile else None,
            "scope": profile.get("scope") if profile else None,
            "voice_recognition_opt_in": bool(profile.get("voice_recognition_opt_in")) if profile else False,
        }

    return {
        "version": "context-pack.v1",
        "policy": {
            "hash": policy.policy_hash,
            "mode": policy.data.get("mode", "strict"),
            "allowed_actions": [
                {
                    "action_type": action.get("action_type"),
                    "params_schema": action.get("params_schema"),
                }
                for action in policy.data.get("actions", [])
            ],
            "policy_text": policy_excerpt,
        },
        "modules_registry": module_registry.registry_summary(registry, include_provides=True),
        "capabilities_snapshot": capabilities.snapshot(),
        "system_snapshot": system_snapshot,
        "retrieved_context": retrieved,
        "recent_events": [
            {
                "id": row["id"],
                "ts": row["ts"],
                "source": row["source"],
                "type": row["type"],
                "payload": json.loads(row["payload_json"]),
                "severity": row["severity"],
            }
            for row in recent_events
        ],
        "pending_proposals": [
            {
                "id": row["id"],
                "ts_created": row["ts_created"],
                "kind": row["kind"],
                "summary": row["summary"],
                "risk": row["risk"],
                "status": row["status"],
            }
            for row in pending
        ],
        "memory": memory,
        "voice_commands": [
            {
                "id": row["id"],
                "ts": row["ts"],
                "text": voice_payloads.get(row["id"], {}).get("text"),
                "device_id": voice_payloads.get(row["id"], {}).get("device_id"),
                "confidence": voice_payloads.get(row["id"], {}).get("confidence"),
                "speaker_state": voice_speakers.get(row["id"], {}).get("speaker_state"),
                "consent": voice_speakers.get(row["id"], {}).get("consent"),
                "name": voice_speakers.get(row["id"], {}).get("name"),
                "scope": voice_speakers.get(row["id"], {}).get("scope"),
                "voice_recognition_opt_in": voice_speakers.get(row["id"], {}).get(
                    "voice_recognition_opt_in"
                ),
                "priority": "high",
            }
            for row in voice_events
        ],
        "constraints": {
            "constitution": [
                "Propose first, act second",
                "Destructive/system-altering actions always require approval",
                "Policy changes always require approval",
                "Network/DNS/cloudflared changes always require approval",
                "All changes are auditable and reversible",
            ]
        },
    }


def _render_prompt(context_pack: Dict[str, Any]) -> str:
    instructions = (
        "You are Pumpkin v3's autonomous planning module. "
        "Continuously improve efficiency, reliability, usability, and self-expansion. "
        "When new devices/services appear, propose concrete steps to identify and integrate them. "
        "Prioritize concrete fixes and upgrades (retry/backoff, caching, telemetry, validations, better prompts). "
        "Return ONLY JSON (no prose) with a top-level key 'proposals' (list). "
        "Each proposal object MUST include keys: kind, summary, details, risk, expected_outcome, "
        "needs_new_capability, capability_request, steps, source_event_ids. "
        "Allowed kinds: action.request, hardware.recommendation, module.install, policy.change, capability.offer. "
        "Disallowed: any other kind (do not emit). "
        "details.rationale, details.implementation, details.verification, details.rollback_plan "
        "MUST be non-empty strings. "
        "risk must be 0.0-1.0. "
        f"Max proposals: {MAX_PROPOSALS_PER_LOOP}; max steps per proposal: {MAX_STEPS_PER_PROPOSAL}. "
        "If you need new capabilities, set needs_new_capability=true and provide capability_request. "
        "For code.apply_patch: include a concrete unified diff that applies at repo root "
        f"{settings.repo_root()}, with correct paths and no placeholders (never use <PATCH_TODO> or similar). "
        "If you cannot provide a real patch, omit that proposal entirely. "
        "Always include concrete steps that describe how to execute the proposal (no placeholders). "
        "Network/DNS/cloudflared changes always require human approval. "
        "If proposing an action.request, include a rollback_action_type and rollback_action_params when feasible. "
        "No extra top-level keys. Strict JSON only."
    )
    themes = [
        "HA reliability (retry/backoff, timeouts, graceful errors)",
        "Caching HA entities/areas for faster intent resolution",
        "Health/metrics exports and self-checks",
        "LLM robustness (better prompts, response validation)",
        "User feedback logging and summaries",
        "Security/credential hygiene",
    ]
    examples = [
        {
            "kind": "action.request",
            "summary": "Add HA service retry/backoff",
            "details": {
                "rationale": "HA commands can fail; add retry/backoff to improve reliability.",
                "action_type": "code.apply_patch",
                "action_params": {
                    "repo_root": str(settings.repo_root()),
                    "patch": (
                        "--- a/pumpkin/ha_client.py\n"
                        "+++ b/pumpkin/ha_client.py\n"
                        "@@\\n"
                        " def fetch_status(base_url: str, token: str, timeout: float) -> Dict[str, Any]:\\n"
                        "     url = base_url.rstrip('/') + \"/api/\"\\n"
                        "     req = Request(url, method=\"GET\")\\n"
                        "     req.add_header(\"Authorization\", f\"Bearer {token}\")\\n"
                        "     req.add_header(\"Content-Type\", \"application/json\")\\n"
                        "     try:\\n"
                        "         with urlopen(req, timeout=timeout) as resp:\\n"
                        "             raw = resp.read().decode(\"utf-8\")\\n"
                        "         data = json.loads(raw)\\n"
                        "         return {\"ok\": True, \"status\": data}\\n"
                        "     except HTTPError as exc:\\n"
                        "         return {\"ok\": False, \"error\": f\"http_{exc.code}\"}\\n"
                        "     except URLError as exc:\\n"
                        "         return {\"ok\": False, \"error\": \"url_error\"}\\n"
                        "     except Exception as exc:\\n"
                        "         return {\"ok\": False, \"error\": \"unknown_error\"}\\n"
                    ),
                },
            },
            "risk": 0.2,
            "expected_outcome": "Fewer transient HA failures.",
            "needs_new_capability": False,
            "capability_request": None,
            "steps": ["Patch ha_client", "Add tests"],
            "source_event_ids": [],
        },
        {
            "kind": "action.request",
            "summary": "Add standard telemetry collection",
            "details": {
                "rationale": "Expose richer health metrics for monitoring.",
                "action_type": "code.apply_patch",
                "action_params": {
                    "repo_root": str(settings.repo_root()),
                    "patch": (
                        "--- a/pumpkin/telemetry.py\n"
                        "+++ b/pumpkin/telemetry.py\n"
                        "@@\\n"
                        " def collect_health_metrics() -> Dict[str, Any]:\\n"
                        "     metrics = {\\n"
                        "         \"cpu_load_1m\": _get_cpu_usage(),\\n"
                        "         \"memory\": _get_memory_usage(),\\n"
                        "         \"disk\": _get_disk_space(),\\n"
                        "     }\\n"
                        "     return metrics\\n"
                    ),
                },
            },
            "risk": 0.3,
            "expected_outcome": "Better visibility into system health.",
            "needs_new_capability": False,
            "capability_request": None,
            "steps": ["Collect metrics", "Integrate into /health", "Add log line"],
            "source_event_ids": [],
        },
    ]
    return (
        f"{instructions}\n\nEXAMPLES:\n{json.dumps(examples, ensure_ascii=True)}\n\n"
        f"THEMES:\n{json.dumps(themes, ensure_ascii=True)}\n\n"
        f"CONTEXT_PACK:\n{json.dumps(context_pack, ensure_ascii=True)}"
    )


def _hash_and_excerpt(prompt: str, max_bytes: int = 2048) -> Tuple[str, str]:
    digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    excerpt = prompt[:max_bytes]
    return f"sha256:{digest}", excerpt


def _proposal_excerpt(proposal: Dict[str, Any], max_len: int = 512) -> str:
    details = proposal.get("details", {})
    rationale = details.get("rationale") if isinstance(details, dict) else None
    if isinstance(rationale, str) and rationale.strip():
        text = rationale.strip()
    else:
        summary = proposal.get("summary")
        text = summary.strip() if isinstance(summary, str) else ""
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


def _cap_context_pack(context_pack: Dict[str, Any], max_bytes: int) -> Dict[str, Any]:
    def size_of(pack: Dict[str, Any]) -> int:
        return len(json.dumps(pack, ensure_ascii=True).encode("utf-8"))

    pack = dict(context_pack)
    while size_of(pack) > max_bytes and pack.get("recent_events"):
        pack["recent_events"] = pack["recent_events"][1:]
    while size_of(pack) > max_bytes and pack.get("pending_proposals"):
        pack["pending_proposals"] = pack["pending_proposals"][1:]
    while size_of(pack) > max_bytes and pack.get("memory"):
        memory = dict(pack.get("memory", {}))
        if not memory:
            break
        memory.pop(next(iter(memory.keys())))
        pack["memory"] = memory
    return pack


def _parse_json_field(value: Any, field: str, expected_type: type) -> Any:
    if not isinstance(value, expected_type):
        raise ValueError(f"{field} must be {expected_type.__name__}")
    return value


def _default_rigor_details(kind: str, summary: str) -> Dict[str, str]:
    base = summary.strip() if isinstance(summary, str) else "this change"
    if kind == "module.install":
        return {
            "implementation": "Follow the module runbook and apply config changes.",
            "verification": "Confirm the module is enabled and health checks pass.",
            "rollback_plan": "Disable the module and revert config to the previous state.",
        }
    if kind == "policy.change":
        return {
            "implementation": "Apply the proposed policy change through the policy CLI.",
            "verification": "Confirm policy diff applied and no validation errors.",
            "rollback_plan": "Restore the previous policy snapshot.",
        }
    if kind == "hardware.recommendation":
        return {
            "implementation": "Review the recommendation and approve procurement.",
            "verification": "Confirm the hardware resolves the identified issue.",
            "rollback_plan": "Defer or cancel the recommendation.",
        }
    if kind == "capability.offer":
        return {
            "implementation": "Review the offered capability and decide whether to install.",
            "verification": "Confirm the new capability is listed and usable.",
            "rollback_plan": "Skip or remove the capability if it is not needed.",
        }
    return {
        "implementation": f"Execute {base} as described.",
        "verification": "Confirm expected outcome and check related logs.",
        "rollback_plan": "Revert the change or disable the action if issues appear.",
    }


def _ensure_rigor_fields(details: Dict[str, Any], kind: str, summary: str) -> Dict[str, Any]:
    defaults = _default_rigor_details(kind, summary)
    for key, value in defaults.items():
        if not isinstance(details.get(key), str) or not str(details.get(key)).strip():
            details[key] = value
    if not isinstance(details.get("rationale"), str) or not str(details.get("rationale")).strip():
        details["rationale"] = summary or "Provide a clear rationale for this proposal."
    return details


def _ensure_rigor_steps(steps: List[str]) -> List[str]:
    normalized = " ".join(steps).lower()
    if "verify" not in normalized:
        steps.append("Verify the expected outcome and check logs.")
    if "rollback" not in normalized:
        steps.append("Rollback the change if verification fails.")
    return steps


def _apply_rigor_defaults(proposals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    updated: List[Dict[str, Any]] = []
    for proposal in proposals:
        if not isinstance(proposal, dict):
            continue
        item = dict(proposal)
        kind = item.get("kind", "general")
        summary = item.get("summary") or "proposal"
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        details = _ensure_rigor_fields(details, kind, summary)
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
        if kind != "action.request" and not steps:
            steps = [
                "Review the proposal details and confirm intent.",
                "Execute the implementation plan.",
                "Verify the expected outcome and rollback if needed.",
            ]
        if steps:
            if kind == "action.request":
                steps = _ensure_rigor_steps(steps)
        item["steps"] = steps
        updated.append(item)
    return updated


def _validate_planner_proposal(
    policy: policy_mod.Policy, proposal: Dict[str, Any]
) -> Dict[str, Any]:
    if not isinstance(proposal, dict):
        raise ValueError("proposal must be an object")

    kind = proposal.get("kind", "general")
    if kind not in ALLOWED_KINDS:
        # Rewrite unknown kinds to action.request with a rationale, so we can surface them instead of discarding.
        proposal = dict(proposal)
        details = proposal.get("details", {}) or {}
        if not isinstance(details, dict):
            details = {"rationale": f"Remapped from unsupported kind {kind}."}
        else:
            details = dict(details)
            if not details.get("rationale"):
                details["rationale"] = f"Remapped from unsupported kind {kind}."
        proposal["kind"] = "action.request"
        proposal["summary"] = proposal.get("summary") or f"Remapped proposal ({kind})"
        proposal["details"] = details
        kind = "action.request"

    summary = proposal.get("summary")
    expected_outcome = proposal.get("expected_outcome")
    details = proposal.get("details")
    risk = proposal.get("risk")

    # Ensure defaults for missing optional fields
    if "steps" not in proposal:
        proposal["steps"] = []
    steps = proposal.get("steps")
    if not isinstance(steps, list):
        steps = [steps]
    normalized_steps: List[str] = []
    for step in steps:
        if isinstance(step, str):
            normalized_steps.append(step)
        elif isinstance(step, dict):
            normalized_steps.append(str(step.get("step") or step))
        elif step is not None:
            normalized_steps.append(str(step))
    proposal["steps"] = normalized_steps
    if "source_event_ids" not in proposal or not isinstance(proposal.get("source_event_ids"), list):
        proposal["source_event_ids"] = []

    if not isinstance(expected_outcome, str):
        if isinstance(expected_outcome, list):
            expected_outcome = " ".join(
                str(item) for item in expected_outcome if item is not None
            ).strip()
        elif isinstance(expected_outcome, dict):
            expected_outcome = json.dumps(expected_outcome, ensure_ascii=True)
        elif expected_outcome is None:
            expected_outcome = summary or "Expected outcome not provided."
        else:
            expected_outcome = str(expected_outcome)
        proposal["expected_outcome"] = expected_outcome
    expected_outcome = proposal.get("expected_outcome")

    _parse_json_field(summary, "summary", str)
    _parse_json_field(expected_outcome, "expected_outcome", str)
    _parse_json_field(details, "details", dict)
    details = _ensure_rigor_fields(details, kind, summary)
    rationale = details.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("rationale must be non-empty string")
    for key in ("implementation", "verification", "rollback_plan"):
        value = details.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} must be non-empty string")
    proposal["details"] = details
    if proposal.get("kind") == "action.request":
        if not details.get("action_type"):
            raise ValueError("missing required param: action_type")
        params = details.get("action_params") or {}
        if not isinstance(params, dict):
            raise ValueError("action_params must be object")
        if details.get("action_type") == "code.apply_patch":
            if not params.get("repo_root"):
                params["repo_root"] = str(settings.repo_root())
            patch_text = params.get("patch")
            # Require a real patch, not a placeholder.
            if not isinstance(patch_text, str) or not patch_text.strip():
                raise ValueError("code.apply_patch requires non-empty patch")
            placeholder_markers = [
                "<PATCH_TODO>",
                "<ADD_UNIFIED_DIFF_HERE>",
                "<ADD_PATCH_HERE>",
            ]
            if any(marker in patch_text for marker in placeholder_markers):
                raise ValueError("code.apply_patch patch cannot contain placeholder text")
            proposal["details"]["action_params"] = params
        # Require an actuation plan so we can see how it will be executed.
        if not proposal["steps"]:
            proposal["steps"] = [
                "Execute the action using the provided parameters.",
                "Verify the expected outcome and check logs.",
                "Rollback the change if verification fails.",
            ]
        proposal["steps"] = _ensure_rigor_steps(proposal["steps"])
    elif not proposal["steps"]:
        proposal["steps"] = [
            "Review the proposal details and confirm intent.",
            "Execute the implementation plan.",
            "Verify the expected outcome and rollback if needed.",
        ]
    if not isinstance(risk, (int, float)) or not (0.0 <= float(risk) <= 1.0):
        raise ValueError("risk must be 0.0-1.0")

    needs_new_capability = proposal.get("needs_new_capability", False)
    if not isinstance(needs_new_capability, bool):
        raise ValueError("needs_new_capability must be boolean")

    capability_request = proposal.get("capability_request")
    if capability_request is not None and not isinstance(capability_request, str):
        raise ValueError("capability_request must be string or null")

    source_event_ids = proposal.get("source_event_ids", [])
    if not isinstance(source_event_ids, list) or not all(
        isinstance(x, int) for x in source_event_ids
    ):
        raise ValueError("source_event_ids must be list of integers")

    steps = proposal.get("steps", [])
    if steps:
        if not isinstance(steps, list) or not all(isinstance(x, str) for x in steps):
            raise ValueError("steps must be list of strings")
        if len(steps) > MAX_STEPS_PER_PROPOSAL:
            steps = steps[:MAX_STEPS_PER_PROPOSAL]
            proposal["steps"] = steps
            if isinstance(details, dict):
                rationale = details.get("rationale")
                suffix = f"(Steps truncated to {MAX_STEPS_PER_PROPOSAL}.)"
                if isinstance(rationale, str) and rationale.strip():
                    details["rationale"] = f"{rationale} {suffix}".strip()
                else:
                    details["rationale"] = suffix
    if kind == "action.request":
        if not steps or not any(step.strip() for step in steps):
            raise ValueError("action.request proposals must include actuation steps")
        placeholder_markers = ["fill in steps", "actuation plan", "<step>"]
        if any(marker.lower() in step.lower() for step in steps for marker in placeholder_markers):
            raise ValueError("actuation steps cannot be placeholders")

    if kind == "action.request":
        action_type = details.get("action_type")
        action_params = details.get("action_params")
        if not isinstance(action_type, str):
            raise ValueError("action_type must be string")
        if not isinstance(action_params, dict):
            raise ValueError("action_params must be object")
        schema = policy_mod.find_action_schema(policy, action_type)
        policy_mod.validate_params(schema, action_params)
    if kind == "policy.change":
        proposed_yaml = details.get("proposed_policy_yaml")
        rationale = details.get("rationale")
        if not isinstance(proposed_yaml, str):
            raise ValueError("proposed_policy_yaml must be string")
        if not isinstance(rationale, str):
            raise ValueError("rationale must be string")
        allow_new_actions = details.get("allow_new_actions", False)
        if not isinstance(allow_new_actions, bool):
            raise ValueError("allow_new_actions must be boolean")
        allow_auto = details.get("allow_auto_approve_in_strict")
        if allow_auto is not None and not isinstance(allow_auto, bool):
            raise ValueError("allow_auto_approve_in_strict must be boolean")
    if kind == "module.install":
        registry = module_registry.load_registry(str(settings.modules_registry_path()))
        module_registry.validate_module_install_details(registry, details)
    if kind == "module.enable":
        registry = module_registry.load_registry(str(settings.modules_registry_path()))
        module_config_change.validate_enable_details(registry, details)
    if kind == "module.disable":
        registry = module_registry.load_registry(str(settings.modules_registry_path()))
        module_config_change.validate_disable_details(registry, details)
    if kind == "capability.offer":
        requested_intent = details.get("requested_intent")
        why_unavailable = details.get("why_unavailable")
        suggested_modules = details.get("suggested_modules", [])
        next_steps = details.get("next_steps", [])
        if not isinstance(requested_intent, str):
            raise ValueError("requested_intent must be string")
        if not isinstance(why_unavailable, str):
            raise ValueError("why_unavailable must be string")
        if not isinstance(suggested_modules, list):
            raise ValueError("suggested_modules must be list")
        if not isinstance(next_steps, list):
            raise ValueError("next_steps must be list")

    return {
        "kind": kind,
        "summary": summary,
        "details": details,
        "risk": float(risk),
        "expected_outcome": expected_outcome,
        "source_event_ids": source_event_ids,
        "needs_new_capability": needs_new_capability,
        "capability_request": capability_request,
        "steps": steps,
    }


def _validate_planner_output(
    policy: policy_mod.Policy, proposals: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    if len(proposals) > MAX_PROPOSALS_PER_LOOP:
        raise ValueError("proposal count exceeds max_proposals_per_loop")
    validated = []
    for proposal in proposals:
        validated.append(_validate_planner_proposal(policy, proposal))
    return validated


def _rule_based_proposals(events: List[Any], conn) -> List[Dict[str, Any]]:
    proposals: List[Dict[str, Any]] = []

    for row in events:
        if row["type"].startswith("insight."):
            payload = json.loads(row["payload_json"])
            if not isinstance(payload, dict):
                continue
            title = str(payload.get("title") or "Insight").strip()
            detail = str(payload.get("detail") or "").strip()
            summary = f"Insight: {title}"
            if store.proposal_exists(conn, summary, {"pending", "approved", "executed", "rejected"}):
                continue
            message = detail or title
            proposals.append(
                {
                    "kind": "action.request",
                    "summary": summary,
                    "details": {
                        "rationale": payload.get("detail") or "System insight detected.",
                        "action_type": "notify.local",
                        "action_params": {
                            "message": message,
                        },
                    },
                    "risk": 0.3,
                    "expected_outcome": "The insight is surfaced for review.",
                    "source_event_ids": [row["id"]],
                    "needs_new_capability": False,
                    "capability_request": None,
                    "steps": ["Notify about the insight"],
                }
            )
            continue
        if row["type"] in {"voice.command", "manual.note"}:
            payload = json.loads(row["payload_json"])
            text = payload.get("text") or payload.get("message") or ""
            if isinstance(text, str) and text:
                is_voice = row["type"] == "voice.command"
                speaker_key = _speaker_key(payload) if is_voice else None
                session = {}
                profile = None
                now = time.time()
                handled_identity_response = False
                if speaker_key:
                    session = _load_speaker_session(conn, speaker_key)
                    if _session_is_new(session, now):
                        session["asked_remember"] = False
                        session["asked_voice_recognition"] = False
                        session["asked_ha_person"] = False
                    session["last_seen_ts"] = now
                    session["interaction_count"] = int(session.get("interaction_count", 0)) + 1

                    profile = _load_speaker_profile(conn, speaker_key)
                    affirmation = intent.parse_affirmation(text)
                    ha_people = _load_ha_people(conn)

                    if session.get("pending_remember_response") and affirmation in {"yes", "no"}:
                        session["pending_remember_response"] = False
                        if affirmation == "no":
                            session["declined_remember"] = True
                            append_jsonl(
                                str(settings.audit_path()),
                                {
                                    "kind": "speaker.opt_in_declined",
                                    "speaker_key": speaker_key,
                                    "opt_in": "remember_me",
                                },
                            )
                            proposals.append(
                                {
                                    "kind": "action.request",
                                    "summary": "Acknowledged memory preference",
                                    "details": {
                                        "rationale": "Speaker declined to be remembered.",
                                        "action_type": "notify.local",
                                        "action_params": {
                                            "message": "Understood. I won't remember you for next time.",
                                        },
                                    },
                                    "risk": 0.2,
                                    "expected_outcome": "Speaker is informed their preference is respected.",
                                    "source_event_ids": [row["id"]],
                                    "needs_new_capability": False,
                                    "capability_request": None,
                                    "steps": ["Confirm memory preference"],
                                }
                            )
                        else:
                            session["pending_remember_name"] = True
                            append_jsonl(
                                str(settings.audit_path()),
                                {
                                    "kind": "speaker.opt_in_accepted",
                                    "speaker_key": speaker_key,
                                    "opt_in": "remember_me",
                                },
                            )
                            proposals.append(
                                {
                                    "kind": "action.request",
                                    "summary": "Ask for speaker name",
                                    "details": {
                                        "rationale": "Speaker opted in to be remembered.",
                                        "action_type": "notify.local",
                                        "action_params": {
                                            "message": "What name should I remember you as?",
                                        },
                                    },
                                    "risk": 0.2,
                                    "expected_outcome": "Speaker provides a name to store.",
                                    "source_event_ids": [row["id"]],
                                    "needs_new_capability": False,
                                    "capability_request": None,
                                    "steps": ["Ask for a preferred name"],
                                }
                            )
                        handled_identity_response = True
                    elif session.get("pending_remember_name"):
                        name = _normalize_name(text)
                        if name and intent.parse_affirmation(name) is None:
                            profile = {
                                "name": name,
                                "created_at": time.time(),
                                "consent": True,
                                "scope": "local",
                                "state": "named",
                                "voice_recognition_opt_in": False,
                                "voice_recognition_enabled": False,
                                "voice_recognition_prompted": False,
                                "preferences": {},
                            }
                            _save_speaker_profile(conn, speaker_key, profile)
                            session["pending_remember_name"] = False
                            append_jsonl(
                                str(settings.audit_path()),
                                {
                                    "kind": "speaker.opt_in_accepted",
                                    "speaker_key": speaker_key,
                                    "opt_in": "remember_name",
                                    "name": name,
                                },
                            )
                            proposals.append(
                                {
                                    "kind": "action.request",
                                    "summary": "Confirm stored name",
                                    "details": {
                                        "rationale": "Speaker provided a name to remember.",
                                        "action_type": "notify.local",
                                        "action_params": {
                                            "message": f"Thanks, {name}. I'll remember you next time.",
                                        },
                                    },
                                    "risk": 0.2,
                                    "expected_outcome": "Speaker is informed their name is stored locally.",
                                    "source_event_ids": [row["id"]],
                                    "needs_new_capability": False,
                                    "capability_request": None,
                                    "steps": ["Confirm stored identity"],
                                }
                            )
                            if ha_people:
                                match = _match_ha_person(name, ha_people)
                                if match:
                                    profile["ha_person_id"] = match.get("entity_id")
                                    profile["ha_person_name"] = match.get("name")
                                    _save_speaker_profile(conn, speaker_key, profile)
                                    proposals.append(
                                        {
                                            "kind": "action.request",
                                            "summary": "Linked Home Assistant profile",
                                            "details": {
                                                "rationale": "Speaker name matched a Home Assistant person.",
                                                "action_type": "notify.local",
                                                "action_params": {
                                                    "message": (
                                                        f"Linked you to Home Assistant profile "
                                                        f"{match.get('name') or match.get('entity_id')}."
                                                    ),
                                                },
                                            },
                                            "risk": 0.2,
                                            "expected_outcome": "Speaker is informed their profile is linked.",
                                            "source_event_ids": [row["id"]],
                                            "needs_new_capability": False,
                                            "capability_request": None,
                                            "steps": ["Confirm HA profile link"],
                                        }
                                    )
                                elif not session.get("asked_ha_person"):
                                    session["asked_ha_person"] = True
                                    session["pending_ha_person"] = True
                                    options = _ha_people_options(ha_people)
                                    message = (
                                        "Which Home Assistant person are you? "
                                        f"Options: {options}. "
                                        "You can say the name or say 'skip'."
                                    )
                                    proposals.append(
                                        {
                                            "kind": "action.request",
                                            "summary": "Ask for Home Assistant person link",
                                            "details": {
                                                "rationale": "Speaker name did not match HA people.",
                                                "action_type": "notify.local",
                                                "action_params": {"message": message},
                                            },
                                            "risk": 0.2,
                                            "expected_outcome": "Speaker links their HA profile.",
                                            "source_event_ids": [row["id"]],
                                            "needs_new_capability": False,
                                            "capability_request": None,
                                            "steps": ["Ask for HA person match"],
                                        }
                                    )
                        else:
                            proposals.append(
                                {
                                    "kind": "action.request",
                                    "summary": "Ask for a valid name",
                                    "details": {
                                        "rationale": "A clear name is required to create a profile.",
                                        "action_type": "notify.local",
                                        "action_params": {
                                            "message": "Please tell me the name you'd like me to remember.",
                                        },
                                    },
                                    "risk": 0.2,
                                    "expected_outcome": "Speaker provides a usable name.",
                                    "source_event_ids": [row["id"]],
                                    "needs_new_capability": False,
                                    "capability_request": None,
                                    "steps": ["Request a clear name"],
                                }
                            )
                        handled_identity_response = True
                    elif session.get("pending_ha_person"):
                        choice = _match_ha_person(text, ha_people)
                        if choice:
                            session["pending_ha_person"] = False
                            profile = profile or {}
                            profile["ha_person_id"] = choice.get("entity_id")
                            profile["ha_person_name"] = choice.get("name")
                            _save_speaker_profile(conn, speaker_key, profile)
                            proposals.append(
                                {
                                    "kind": "action.request",
                                    "summary": "Linked Home Assistant profile",
                                    "details": {
                                        "rationale": "Speaker selected a Home Assistant person.",
                                        "action_type": "notify.local",
                                        "action_params": {
                                            "message": (
                                                f"Linked you to Home Assistant profile "
                                                f"{choice.get('name') or choice.get('entity_id')}."
                                            ),
                                        },
                                    },
                                    "risk": 0.2,
                                    "expected_outcome": "Speaker is informed their profile is linked.",
                                    "source_event_ids": [row["id"]],
                                    "needs_new_capability": False,
                                    "capability_request": None,
                                    "steps": ["Confirm HA profile link"],
                                }
                            )
                            handled_identity_response = True
                        elif intent.parse_affirmation(text) in {"no"} or text.strip().lower() in {"skip", "later"}:
                            session["pending_ha_person"] = False
                            session["declined_ha_person"] = True
                            proposals.append(
                                {
                                    "kind": "action.request",
                                    "summary": "Skipped Home Assistant profile link",
                                    "details": {
                                        "rationale": "Speaker declined to link HA profile.",
                                        "action_type": "notify.local",
                                        "action_params": {
                                            "message": "Understood. I won't link a Home Assistant profile yet.",
                                        },
                                    },
                                    "risk": 0.2,
                                    "expected_outcome": "Speaker is informed no link is stored.",
                                    "source_event_ids": [row["id"]],
                                    "needs_new_capability": False,
                                    "capability_request": None,
                                    "steps": ["Confirm HA link skipped"],
                                }
                            )
                            handled_identity_response = True
                    elif session.get("pending_voice_recognition") and affirmation in {"yes", "no"}:
                        session["pending_voice_recognition"] = False
                        if affirmation == "yes":
                            if profile:
                                profile["voice_recognition_opt_in"] = True
                                profile["voice_recognition_enabled"] = False
                                profile["voice_recognition_note"] = "text_only_no_embedding"
                                _save_speaker_profile(conn, speaker_key, profile)
                            append_jsonl(
                                str(settings.audit_path()),
                                {
                                    "kind": "speaker.opt_in_accepted",
                                    "speaker_key": speaker_key,
                                    "opt_in": "voice_recognition",
                                },
                            )
                            proposals.append(
                                {
                                    "kind": "action.request",
                                    "summary": "Confirm voice recognition opt-in",
                                    "details": {
                                        "rationale": "Speaker opted in to voice recognition.",
                                        "action_type": "notify.local",
                                        "action_params": {
                                            "message": "Got it. Voice recognition is opted in for this speaker.",
                                        },
                                    },
                                    "risk": 0.2,
                                    "expected_outcome": "Speaker is informed of opt-in status.",
                                    "source_event_ids": [row["id"]],
                                    "needs_new_capability": False,
                                    "capability_request": None,
                                    "steps": ["Confirm voice recognition opt-in"],
                                }
                            )
                        else:
                            if profile:
                                profile["voice_recognition_opt_in"] = False
                                _save_speaker_profile(conn, speaker_key, profile)
                            append_jsonl(
                                str(settings.audit_path()),
                                {
                                    "kind": "speaker.opt_in_declined",
                                    "speaker_key": speaker_key,
                                    "opt_in": "voice_recognition",
                                },
                            )
                            proposals.append(
                                {
                                    "kind": "action.request",
                                    "summary": "Confirm voice recognition declined",
                                    "details": {
                                        "rationale": "Speaker declined voice recognition.",
                                        "action_type": "notify.local",
                                        "action_params": {
                                            "message": "Understood. I won't recognize your voice automatically.",
                                        },
                                    },
                                    "risk": 0.2,
                                    "expected_outcome": "Speaker is informed of opt-out.",
                                    "source_event_ids": [row["id"]],
                                    "needs_new_capability": False,
                                    "capability_request": None,
                                    "steps": ["Confirm voice recognition decline"],
                                }
                            )
                        handled_identity_response = True

                    if not handled_identity_response and not profile and not session.get("asked_remember"):
                        session["asked_remember"] = True
                        session["pending_remember_response"] = True
                        append_jsonl(
                            str(settings.audit_path()),
                            {
                                "kind": "speaker.opt_in_requested",
                                "speaker_key": speaker_key,
                                "opt_in": "remember_me",
                            },
                        )
                        proposals.append(
                            {
                                "kind": "action.request",
                                "summary": "Ask to remember speaker",
                                "details": {
                                    "rationale": "Unknown speaker; ask for memory consent.",
                                    "action_type": "notify.local",
                                    "action_params": {
                                        "message": "I don't think we've spoken before. Would you like me to remember you for next time?",
                                    },
                                },
                                "risk": 0.3,
                                "expected_outcome": "Speaker chooses whether to be remembered.",
                                "source_event_ids": [row["id"]],
                                "needs_new_capability": False,
                                "capability_request": None,
                                "steps": ["Ask for memory opt-in"],
                            }
                        )

                    if (
                        not handled_identity_response
                        and profile
                        and _speaker_state(profile) == "named"
                        and not profile.get("voice_recognition_opt_in")
                        and not profile.get("voice_recognition_prompted")
                        and not session.get("asked_voice_recognition")
                        and session.get("interaction_count", 0) >= 2
                    ):
                        session["asked_voice_recognition"] = True
                        session["pending_voice_recognition"] = True
                        profile["voice_recognition_prompted"] = True
                        _save_speaker_profile(conn, speaker_key, profile)
                        append_jsonl(
                            str(settings.audit_path()),
                            {
                                "kind": "speaker.opt_in_requested",
                                "speaker_key": speaker_key,
                                "opt_in": "voice_recognition",
                            },
                        )
                        proposals.append(
                            {
                                "kind": "action.request",
                                "summary": "Ask about voice recognition",
                                "details": {
                                    "rationale": "Named speaker without voice recognition opt-in.",
                                    "action_type": "notify.local",
                                    "action_params": {
                                        "message": "Would you like me to recognise your voice automatically?",
                                    },
                                },
                                "risk": 0.3,
                                "expected_outcome": "Speaker chooses whether to enable voice recognition.",
                                "source_event_ids": [row["id"]],
                                "needs_new_capability": False,
                                "capability_request": None,
                                "steps": ["Ask for voice recognition opt-in"],
                            }
                        )

                    _save_speaker_session(conn, speaker_key, session)

                if handled_identity_response:
                    continue

                if speaker_key and profile and _speaker_state(profile) in {"named", "recognised"}:
                    preference = intent.parse_preference(text)
                    if preference:
                        prefs = profile.get("preferences", {})
                        if not isinstance(prefs, dict):
                            prefs = {}
                        prefs[preference["key"]] = preference["value"]
                        profile["preferences"] = prefs
                        _save_speaker_profile(conn, speaker_key, profile)
                        proposals.append(
                            {
                                "kind": "action.request",
                                "summary": "Preference saved",
                                "details": {
                                    "rationale": "Speaker shared a preference.",
                                    "action_type": "notify.local",
                                    "action_params": {
                                        "message": f"Noted. I'll remember that preference: {preference['value']}",
                                    },
                                },
                                "risk": 0.2,
                                "expected_outcome": "Speaker is informed their preference is saved.",
                                "source_event_ids": [row["id"]],
                                "needs_new_capability": False,
                                "capability_request": None,
                                "steps": ["Confirm preference saved"],
                            }
                        )
                        continue

                classification = intent.classify_intent(text)
                registry = module_registry.load_registry(str(settings.modules_registry_path()))
                registry_summary = module_registry.registry_summary(registry)
                catalog_summary = []
                catalog_path = settings.modules_catalog_path()
                if catalog_path.exists():
                    try:
                        catalog = catalog_mod.load_catalog(str(catalog_path))
                        catalog_summary = catalog_mod.catalog_summary(catalog)
                    except Exception:
                        catalog_summary = []
                suggested_modules = intent.suggest_modules(
                    text, registry_summary + catalog_summary
                )

                intent_type = classification.get("intent_type")
                if intent_type == "memory.query":
                    summary = "Memory profile summary"
                    if speaker_key and profile:
                        memory_payload = {
                            "name": profile.get("name"),
                            "scope": profile.get("scope"),
                            "preferences": profile.get("preferences", {}),
                            "voice_recognition_opt_in": profile.get("voice_recognition_opt_in", False),
                        }
                        message = f"Here's what I remember: {json.dumps(memory_payload, ensure_ascii=True)}"
                    else:
                        message = "I don't have a profile stored for you yet."
                    proposals.append(
                        {
                            "kind": "action.request",
                            "summary": summary,
                            "details": {
                                "rationale": "Speaker requested memory summary.",
                                "action_type": "notify.local",
                                "action_params": {"message": message},
                            },
                            "risk": 0.2,
                            "expected_outcome": "Speaker receives memory summary.",
                            "source_event_ids": [row["id"]],
                            "needs_new_capability": False,
                            "capability_request": None,
                            "steps": ["Report stored memory"],
                        }
                    )
                    continue

                if intent_type == "memory.forget":
                    if speaker_key:
                        _save_speaker_profile(conn, speaker_key, {"state": "guest"})
                    proposals.append(
                        {
                            "kind": "action.request",
                            "summary": "Forget speaker profile",
                            "details": {
                                "rationale": "Speaker asked to be forgotten.",
                                "action_type": "notify.local",
                                "action_params": {"message": "Done. I've cleared what I stored about you."},
                            },
                            "risk": 0.2,
                            "expected_outcome": "Speaker profile is cleared.",
                            "source_event_ids": [row["id"]],
                            "needs_new_capability": False,
                            "capability_request": None,
                            "steps": ["Confirm memory deletion"],
                        }
                    )
                    continue

                if classification["classification"] == "ambiguous":
                    proposals.append(
                        {
                            "kind": "action.request",
                            "summary": "Clarify voice request",
                            "details": {
                                "rationale": "Voice request is ambiguous; ask for clarification.",
                                "action_type": "notify.local",
                                "action_params": {
                                    "message": "I heard a request but need clarification. Please restate the task."
                                },
                            },
                            "risk": 0.4,
                            "expected_outcome": "Human clarifies the request.",
                            "source_event_ids": [row["id"]],
                            "needs_new_capability": False,
                            "capability_request": None,
                            "steps": ["Ask for clarification"],
                        }
                    )
                    continue

                if classification["classification"] == "supported":
                    proposals.append(
                        {
                            "kind": "action.request",
                            "summary": f"Voice command received: {text[:80]}",
                            "details": {
                                "rationale": "Supported request; requires human review.",
                                "action_type": "notify.local",
                                "action_params": {"message": f"Voice command: {text}"},
                            },
                            "risk": 0.7,
                            "expected_outcome": "Human reviews voice command before any action.",
                            "source_event_ids": [row["id"]],
                            "needs_new_capability": False,
                            "capability_request": None,
                            "steps": ["Notify operator about voice command"],
                        }
                    )
                    continue

                link_key = f"cap:{hash(text)}"
                for module_name in suggested_modules:
                    try:
                        module = module_registry.find_module(registry, module_name)
                    except Exception:
                        continue
                    schema = module.get("config_schema", {})
                    config = {}
                    for key, rule in (schema.get("properties", {}) or {}).items():
                        if rule.get("type") == "string":
                            config[key] = ""
                        elif rule.get("type") == "boolean":
                            config[key] = False
                        elif rule.get("type") == "number":
                            config[key] = 0
                        elif rule.get("type") == "integer":
                            config[key] = 0
                    details = {
                        "module_name": module_name,
                        "rationale": f"Requested: {text}",
                        "config": config,
                        "safety_level": module.get("safety_level"),
                        "prerequisites": module.get("prerequisites", {}),
                        "rollback_plan": "Disable module and remove related config entries.",
                    }
                    try:
                        module_registry.validate_module_install_details(registry, details)
                        runbook_data = runbook.generate_runbook(details, module)
                        details["runbook"] = {
                            "format": "md",
                            "content": runbook.runbook_markdown(runbook_data),
                            "generated_at": runbook_data["generated_at"],
                        }
                        proposals.append(
                            {
                                "kind": "module.install",
                                "summary": f"Install module {module_name}",
                                "details": details,
                                "risk": 0.4,
                                "expected_outcome": "Module installation is reviewed by human.",
                                "source_event_ids": [row["id"]],
                                "needs_new_capability": False,
                                "capability_request": None,
                                "steps": ["Review module details", "Approve if acceptable"],
                                "link_key": link_key,
                            }
                        )
                    except Exception:
                        continue

                proposals.append(
                    {
                        "kind": "action.request",
                        "summary": "Clarify unsupported request",
                        "details": {
                            "rationale": "Request is not supported yet; ask for clarification.",
                            "action_type": "notify.local",
                            "action_params": {
                                "message": (
                                    "I can't do that yet. What outcome would you like so I can guide the next step?"
                                )
                            },
                        },
                        "risk": 0.4,
                        "expected_outcome": "Speaker clarifies the desired outcome.",
                        "source_event_ids": [row["id"]],
                        "needs_new_capability": True,
                        "capability_request": "Clarify the desired outcome for this request.",
                        "steps": ["Ask for clarification"],
                    }
                )

                capability_details = {
                    "requested_intent": text,
                    "why_unavailable": "No supported capability matches this request.",
                    "suggested_modules": suggested_modules,
                    "suggested_policy_change": None,
                    "runbook_hint": None,
                    "next_steps": [
                        "Review suggested modules (if any).",
                        "Approve module.install proposals to extend Pumpkin.",
                        "Re-issue the request after capability is added.",
                    ],
                }
                if suggested_modules:
                    capability_details["runbook_hint"] = "Run: python3 -m pumpkin modules runbook --proposal <id>"
                proposals.append(
                    {
                        "kind": "capability.offer",
                        "summary": "I can’t do that yet — here’s how to add it",
                        "details": capability_details,
                        "risk": 0.1,
                        "expected_outcome": "User understands options to extend Pumpkin safely.",
                        "source_event_ids": [row["id"]],
                        "needs_new_capability": True,
                        "capability_request": "Add a module to handle this request.",
                        "steps": ["Review capability offer"],
                        "link_key": link_key,
                    }
                )
            continue

        if row["type"] == "inventory.changed":
            payload = json.loads(row["payload_json"])
            opportunities = payload.get("opportunities", [])
            inventory_summary = payload.get("summary", {})
            if not isinstance(opportunities, list):
                continue
            for item in opportunities:
                if not isinstance(item, dict):
                    continue
                title = item.get("title")
                why = item.get("why")
                example = item.get("example")
                source = item.get("source")
                if not isinstance(title, str) or not title.strip():
                    continue
                summary = f"Inventory opportunity: {title.strip()}"
                if store.proposal_exists(
                    conn,
                    summary,
                    statuses=["pending", "approved", "executed", "failed", "rejected"],
                ):
                    continue
                details = {
                    "rationale": why or "Inventory update suggests an opportunity to improve automation.",
                    "source": source or "inventory",
                    "inventory_summary": inventory_summary if isinstance(inventory_summary, dict) else {},
                    "example": example or "",
                    "implementation": (
                        "Review available devices/entities that enable this opportunity, "
                        "draft a concrete plan, and propose any needed configuration changes."
                    ),
                    "verification": "Confirm the capability works end-to-end and appears in the UI.",
                    "rollback_plan": "Disable or remove the new automation if it causes issues.",
                }
                proposals.append(
                    {
                        "kind": "maintenance",
                        "summary": summary,
                        "details": details,
                        "risk": 0.2,
                        "expected_outcome": "An inventory-driven improvement is reviewed and scoped.",
                        "source_event_ids": [row["id"]],
                        "needs_new_capability": False,
                        "capability_request": None,
                        "steps": [
                            "Review the opportunity details and scope the change.",
                            "Draft the implementation plan and required configuration updates.",
                            "Verify the resulting behavior and rollback if needed.",
                        ],
                    }
                )
            continue

        if row["type"] in {"homeassistant.token_missing", "homeassistant.request_failed"}:
            details = {
                "rationale": "Home Assistant access is not available.",
                "action_type": "notify.local",
                "action_params": {
                    "message": (
                        "Home Assistant access failed. Set PUMPKIN_HA_TOKEN to enable read-only access."
                    )
                },
            }
            proposals.append(
                {
                    "kind": "action.request",
                    "summary": "Home Assistant access unavailable",
                    "details": details,
                    "risk": 0.6,
                    "expected_outcome": "Human is notified to configure Home Assistant access.",
                    "source_event_ids": [row["id"]],
                    "needs_new_capability": True,
                    "capability_request": "Provide PUMPKIN_HA_TOKEN to enable Home Assistant access.",
                    "steps": ["Notify operator about missing HA token"],
                }
            )
            continue

        if row["type"] != "system.snapshot":
            continue

        payload = json.loads(row["payload_json"])
        disk = payload.get("disk", {})
        used_percent = disk.get("used_percent")
        threshold = 0.9
        if isinstance(used_percent, (int, float)) and used_percent >= threshold:
            summary = f"Disk usage high on {disk.get('path', '/')}"
            if not store.proposal_exists(conn, summary, statuses=["pending", "approved"]):
                proposals.append(
                    {
                        "kind": "action.request",
                        "summary": summary,
                        "details": {
                            "rationale": "Disk usage exceeded threshold.",
                            "observed": {"used_percent": used_percent, "threshold": threshold},
                            "action_type": "notify.local",
                            "action_params": {
                                "message": (
                                    f"Disk usage is {used_percent:.0%} on {disk.get('path', '/')}"
                                )
                            },
                        },
                        "risk": 0.7,
                        "expected_outcome": "Human is notified of high disk usage.",
                        "source_event_ids": [row["id"]],
                        "needs_new_capability": False,
                        "capability_request": None,
                        "steps": ["Emit a local notification"],
                    }
                )

        loadavg = payload.get("loadavg", {})
        load_1m = loadavg.get("1m")
        if isinstance(load_1m, (int, float)) and load_1m >= CPU_LOAD_WARN_THRESHOLD:
            summary = "CPU load high"
            if not store.proposal_exists(conn, summary, statuses=["pending", "approved"]):
                proposals.append(
                    {
                        "kind": "action.request",
                        "summary": summary,
                        "details": {
                            "rationale": "CPU load exceeded threshold.",
                            "observed": {"load_1m": load_1m, "threshold": CPU_LOAD_WARN_THRESHOLD},
                            "action_type": "notify.local",
                            "action_params": {
                                "message": f"CPU load 1m is {load_1m:.2f} (threshold {CPU_LOAD_WARN_THRESHOLD})."
                            },
                        },
                        "risk": 0.6,
                        "expected_outcome": "Human is notified of high CPU load.",
                        "source_event_ids": [row["id"]],
                        "needs_new_capability": False,
                        "capability_request": None,
                        "steps": ["Emit a local notification"],
                    }
                )

        meminfo = payload.get("meminfo_kb", {})
        mem_available = meminfo.get("MemAvailable")
        if isinstance(mem_available, int) and mem_available <= MEM_AVAILABLE_WARN_KB:
            summary = "Memory available low"
            if not store.proposal_exists(conn, summary, statuses=["pending", "approved"]):
                proposals.append(
                    {
                        "kind": "action.request",
                        "summary": summary,
                        "details": {
                            "rationale": "Memory available dropped below threshold.",
                            "observed": {"mem_available_kb": mem_available, "threshold_kb": MEM_AVAILABLE_WARN_KB},
                            "action_type": "notify.local",
                            "action_params": {
                                "message": (
                                    f"Memory available is {mem_available}KB "
                                    f"(threshold {MEM_AVAILABLE_WARN_KB}KB)."
                                )
                            },
                        },
                        "risk": 0.6,
                        "expected_outcome": "Human is notified of low available memory.",
                        "source_event_ids": [row["id"]],
                        "needs_new_capability": False,
                        "capability_request": None,
                        "steps": ["Emit a local notification"],
                    }
                )

    useful = store.get_memory(conn, "network.discovery.useful")
    if isinstance(useful, list) and useful:
        snapshot = store.get_memory(conn, "network.discovery.snapshot")
        devices_by_ip: Dict[str, Dict[str, Any]] = {}
        if isinstance(snapshot, dict):
            for device in snapshot.get("devices", []):
                if isinstance(device, dict) and device.get("ip"):
                    devices_by_ip[device["ip"]] = device
        for item in useful[-10:]:
            if not isinstance(item, dict):
                continue
            ip = item.get("ip")
            if not isinstance(ip, str) or not ip.strip():
                continue
            label = item.get("label") or "device"
            summary = f"Integrate {label} device at {ip}"
            if store.proposal_exists(conn, summary, statuses=["pending", "approved", "rejected"]):
                continue
            device = devices_by_ip.get(ip, {})
            hints = device.get("hints", [])
            services = device.get("services", [])
            rationale = (
                f"Device {ip} was marked useful and should be integrated."
                + (f" Hints: {', '.join(hints)}." if hints else "")
            )
            proposals.append(
                {
                    "kind": "hardware.recommendation",
                    "summary": summary,
                    "details": {
                        "rationale": rationale,
                        "device": {
                            "ip": ip,
                            "label": label,
                            "note": item.get("note"),
                            "hints": hints,
                            "services": services,
                        },
                        "implementation": (
                            "Identify the device protocol from hints/services, "
                            "collect any needed credentials, and draft an integration plan "
                            "for Pumpkin or Home Assistant."
                        ),
                        "verification": (
                            "Confirm the device is reachable and appears in the "
                            "network snapshot after integration."
                        ),
                        "rollback_plan": "Remove the integration and stored credentials if needed.",
                    },
                    "risk": 0.3,
                    "expected_outcome": "Integration plan is ready for approval.",
                    "source_event_ids": [],
                    "needs_new_capability": False,
                    "capability_request": None,
                    "steps": [
                        "Confirm device type and access method.",
                        "Draft integration plan and required credentials.",
                        "Propose activation steps and verify reachability.",
                    ],
                }
            )

    snapshot = store.get_memory(conn, "network.discovery.snapshot")
    deep_scan = store.get_memory(conn, "network.discovery.deep_scan")
    devices_by_ip: Dict[str, Dict[str, Any]] = {}
    if isinstance(snapshot, dict):
        for device in snapshot.get("devices", []):
            if isinstance(device, dict) and device.get("ip"):
                devices_by_ip[device["ip"]] = device
    if isinstance(deep_scan, dict):
        jobs = deep_scan.get("jobs", {})
        if isinstance(jobs, dict):
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                if job.get("status") != "complete":
                    continue
                ip = job.get("ip")
                if not isinstance(ip, str) or not ip.strip():
                    continue
                if ip in devices_by_ip:
                    continue
                devices_by_ip[ip] = {
                    "ip": ip,
                    "open_ports": job.get("open_ports", []),
                    "services": job.get("services", []),
                    "hints": job.get("hints", []),
                }

    auto_state = store.get_memory(conn, "network.discovery.auto_proposed")
    if not isinstance(auto_state, dict):
        auto_state = {}
    auto_seen = auto_state.get("camera_ips")
    if not isinstance(auto_seen, list):
        auto_seen = []
    device_labels = auto_state.get("device_labels")
    if not isinstance(device_labels, dict):
        device_labels = {}

    def _device_service_types(service_items: List[Any]) -> List[str]:
        types = []
        for item in service_items:
            if isinstance(item, dict) and isinstance(item.get("type"), str):
                types.append(item["type"].lower())
        return types

    def _classify_device(device: Dict[str, Any]) -> List[str]:
        hints = device.get("hints") or []
        open_ports = device.get("open_ports") or []
        services = device.get("services") or []
        service_types = _device_service_types(services)
        labels: List[str] = []
        hint_text = " ".join(h.lower() for h in hints if isinstance(h, str))
        if "camera" in hint_text or "rtsp" in hint_text or "onvif" in hint_text:
            labels.append("camera")
        if any(port in {554, 8554} for port in open_ports if isinstance(port, int)) or "rtsp" in service_types:
            if "camera" not in labels:
                labels.append("camera")
        if any(port in {8009, 1400} for port in open_ports if isinstance(port, int)) or "cast" in hint_text:
            labels.append("speaker")
        if any(port in {32400} for port in open_ports if isinstance(port, int)) or "plex" in hint_text:
            labels.append("media")
        if any(port in {9100, 631} for port in open_ports if isinstance(port, int)) or "printer" in hint_text:
            labels.append("printer")
        if any(port in {445, 139} for port in open_ports if isinstance(port, int)) or "nas" in hint_text:
            labels.append("nas")
        if any(port in {8123} for port in open_ports if isinstance(port, int)) or "homeassistant" in hint_text:
            labels.append("homeassistant")
        if "ssh" in service_types or any(port == 22 for port in open_ports if isinstance(port, int)):
            labels.append("host")
        if "http" in service_types or any(port in {80, 443, 8000, 8080, 8443} for port in open_ports if isinstance(port, int)):
            labels.append("web")
        return labels

    for ip, device in devices_by_ip.items():
        hints = device.get("hints") or []
        open_ports = device.get("open_ports") or []
        services = device.get("services") or []
        is_camera = False
        if any(isinstance(h, str) and "camera" in h.lower() for h in hints):
            is_camera = True
        if any(port in {554, 8554} for port in open_ports if isinstance(port, int)):
            is_camera = True
        if any(isinstance(s, dict) and s.get("type") == "rtsp" for s in services):
            is_camera = True
        if not is_camera:
            continue
        if ip in auto_seen:
            continue
        scan_summary = f"Deep scan new camera at {ip}"
        mark_summary = f"Mark camera at {ip} as useful"
        if store.proposal_exists(conn, scan_summary, statuses=["pending", "approved"]) or store.proposal_exists(
            conn, mark_summary, statuses=["pending", "approved"]
        ):
            auto_seen.append(ip)
            continue
        proposals.append(
            {
                "kind": "action.request",
                "summary": scan_summary,
                "details": {
                    "rationale": "Camera-like device discovered; scan to enrich service details.",
                    "action_type": "network.deep_scan",
                    "action_params": {"ip": ip},
                    "implementation": "Run a deep scan to identify RTSP/HTTP/ONVIF services.",
                    "verification": "Confirm deep scan results are saved for the device.",
                    "rollback_plan": "No rollback needed; scan is read-only.",
                },
                "risk": 0.1,
                "expected_outcome": "Deep scan results recorded for the new camera.",
                "source_event_ids": [],
                "needs_new_capability": False,
                "capability_request": None,
                "steps": ["Run deep scan", "Review detected services/hints"],
            }
        )
        proposals.append(
            {
                "kind": "action.request",
                "summary": mark_summary,
                "details": {
                    "rationale": "Enable vision modules to auto-sync discovered camera.",
                    "action_type": "network.mark_useful",
                    "action_params": {
                        "ip": ip,
                        "label": "camera",
                        "note": "Auto-marked from network discovery; review credentials if needed.",
                    },
                    "implementation": "Add the device to the useful list for camera sync.",
                    "verification": "Confirm device appears in the useful list and camera registry.",
                    "rollback_plan": "Remove the device from the useful list.",
                },
                "risk": 0.1,
                "expected_outcome": "Camera is flagged for integration workflows.",
                "source_event_ids": [],
                "needs_new_capability": False,
                "capability_request": None,
                "steps": ["Mark device useful", "Verify camera registry updated"],
            }
        )
        auto_seen.append(ip)

    for ip, device in devices_by_ip.items():
        labels = _classify_device(device)
        if not labels:
            continue
        if "camera" in labels:
            labels = [label for label in labels if label != "camera"]
        if not labels:
            continue
        seen_labels = device_labels.get(ip, [])
        if not isinstance(seen_labels, list):
            seen_labels = []
        for label in labels:
            if label in seen_labels:
                continue
            summary = f"Review new {label} device at {ip}"
            if store.proposal_exists(conn, summary, statuses=["pending", "approved"]):
                seen_labels.append(label)
                continue
            message = f"New {label} candidate at {ip}. Review for integration."
            proposals.append(
                {
                    "kind": "action.request",
                    "summary": summary,
                    "details": {
                        "rationale": "Device discovery hints suggest a new capability.",
                        "action_type": "notify.local",
                        "action_params": {
                            "message": message,
                        },
                        "implementation": "Review the device details and decide on integration.",
                        "verification": "Confirm device is reachable and appears in the network snapshot.",
                        "rollback_plan": "No rollback needed; review only.",
                    },
                    "risk": 0.2,
                    "expected_outcome": "Device is reviewed for potential integration.",
                    "source_event_ids": [],
                    "needs_new_capability": False,
                    "capability_request": None,
                    "steps": ["Review device details", "Decide integration approach"],
                }
            )
            if label not in {"web"}:
                mark_summary = f"Mark {label} at {ip} as useful"
                if not store.proposal_exists(conn, mark_summary, statuses=["pending", "approved"]):
                    proposals.append(
                        {
                            "kind": "action.request",
                            "summary": mark_summary,
                            "details": {
                                "rationale": "Tag the device so modules can integrate it.",
                                "action_type": "network.mark_useful",
                                "action_params": {
                                    "ip": ip,
                                    "label": label,
                                    "note": "Auto-marked from discovery; confirm if correct.",
                                },
                                "implementation": "Add the device to the useful list.",
                                "verification": "Confirm device appears in the useful list.",
                                "rollback_plan": "Remove the device from the useful list.",
                            },
                            "risk": 0.1,
                            "expected_outcome": "Device is available for integration workflows.",
                            "source_event_ids": [],
                            "needs_new_capability": False,
                            "capability_request": None,
                            "steps": ["Mark device useful", "Review label accuracy"],
                        }
                    )
            seen_labels.append(label)
        if seen_labels:
            device_labels[ip] = seen_labels

    auto_state["camera_ips"] = auto_seen[-200:]
    auto_state["device_labels"] = device_labels
    store.set_memory(conn, "network.discovery.auto_proposed", auto_state)

    return proposals


def build_context_pack(conn, event_limit: int = 20) -> Tuple[Dict[str, Any], str, str]:
    policy = policy_mod.load_policy(str(settings.policy_path()))
    events = store.fetch_events_since(conn, 0)[-event_limit:]
    system_snapshot = {}
    for row in reversed(events):
        if row["type"] == "system.snapshot":
            system_snapshot = json.loads(row["payload_json"])
            break

    context_pack = _context_pack(conn, policy, system_snapshot, event_limit=event_limit)
    prompt = _render_prompt(context_pack)
    context_hash, context_excerpt = _hash_and_excerpt(prompt)
    context_pack = _cap_context_pack(context_pack, settings.context_pack_max_bytes())
    prompt = _render_prompt(context_pack)
    context_hash, context_excerpt = _hash_and_excerpt(prompt)
    return context_pack, context_hash, context_excerpt


def replay_context_pack(
    context_pack: Dict[str, Any], plan: Optional[planner.Planner] = None
) -> List[Dict[str, Any]]:
    policy = policy_mod.load_policy(str(settings.policy_path()))
    prompt = _render_prompt(context_pack)
    plan = plan or planner.load_planner()
    result = plan.generate(context_pack, prompt)
    validated = _validate_planner_output(policy, result.proposals)
    return validated


def build_proposals(events: List[Any], conn) -> List[Dict[str, Any]]:
    policy = policy_mod.load_policy(str(settings.policy_path()))
    context_pack, context_hash, context_excerpt = build_context_pack(conn)

    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "planner.context_built",
            "ai_context_hash": context_hash,
            "event_count": len(context_pack.get("recent_events", [])),
            "pending_proposals_count": len(context_pack.get("pending_proposals", [])),
            "memory_keys_count": len(context_pack.get("memory", {})),
        },
    )

    rule_based = _apply_rigor_defaults(_rule_based_proposals(events, conn))
    if planner_cooldown_active(conn):
        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "planner.cooldown_active",
                "cooldown_until": planner_cooldown_until(conn).isoformat(),
            },
        )
        return rule_based[:MAX_PROPOSALS_PER_LOOP]

    plan = planner.load_planner()
    retry_limit = settings.planner_retry_count()
    last_error: str | None = None

    for attempt in range(retry_limit + 1):
        try:
            result = plan.generate(context_pack, _render_prompt(context_pack))
            output_payload = {"proposals": result.proposals}
            output_raw = result.raw_response or json.dumps(output_payload, ensure_ascii=True)
            output_hash = f"sha256:{hashlib.sha256(output_raw.encode('utf-8')).hexdigest()}"
            validated = _validate_planner_output(policy, result.proposals)
            append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "planner.output_received",
                    "output_hash": output_hash,
                    "valid": True,
                    "attempt": attempt,
                },
            )
            _clear_planner_cooldown(conn)
            for proposal in validated:
                proposal["ai_context_hash"] = context_hash
                proposal["ai_context_excerpt"] = _proposal_excerpt(proposal)
            combined = rule_based + validated
            return combined[:MAX_PROPOSALS_PER_LOOP]
        except Exception as exc:
            last_error = str(exc)
            if _is_rate_limited(last_error):
                _set_planner_cooldown(conn, last_error)
            append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "planner.output_received",
                    "output_hash": None,
                    "valid": False,
                    "error": last_error,
                    "attempt": attempt,
                },
            )

    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "planner.output_invalid",
            "error": last_error,
        },
    )
    return rule_based[:MAX_PROPOSALS_PER_LOOP]


def build_improvement_proposals(conn) -> List[Dict[str, Any]]:
    policy = policy_mod.load_policy(str(settings.policy_path()))
    context_pack, context_hash, context_excerpt = build_context_pack(conn)
    prompt = (
        _render_prompt(context_pack)
        + "\n\nFocus on making Pumpkin more helpful for the household and suggesting useful hardware additions. "
        "You may propose maintenance, action.request, policy.change, or hardware.recommendation. "
        "For hardware.recommendation proposals, include details.shopping_items as a list of items "
        "with fields: name, category, priority (high/medium/low), reason."
    )
    if planner_cooldown_active(conn):
        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "planner.cooldown_active",
                "cooldown_until": planner_cooldown_until(conn).isoformat(),
            },
        )
        return []

    try:
        plan = planner.load_planner()
        result = plan.generate(context_pack, prompt)
        validated = _validate_planner_output(policy, result.proposals)
    except Exception:
        validated = []
    _clear_planner_cooldown(conn)

    filtered = []
    for proposal in validated:
        if proposal.get("kind") in {"module.install", "capability.offer"}:
            continue
        proposal["ai_context_hash"] = context_hash
        proposal["ai_context_excerpt"] = _proposal_excerpt(proposal)
        filtered.append(proposal)
    heuristic = _hardware_opportunity_proposals(conn)
    filtered.extend(heuristic)
    return filtered[:MAX_PROPOSALS_PER_LOOP]


def _hardware_opportunity_proposals(conn) -> List[Dict[str, Any]]:
    inventory = inventory_mod.snapshot(conn)
    ha = inventory.get("homeassistant", {}) if isinstance(inventory.get("homeassistant"), dict) else {}
    domains = ha.get("domains", {}) if isinstance(ha.get("domains"), dict) else {}
    proposals: List[Dict[str, Any]] = []

    def add(summary: str, rationale: str, items: List[Dict[str, str]], priority: float = 0.2) -> None:
        if store.proposal_exists(conn, summary, statuses=["pending", "approved", "rejected"]):
            return
        proposals.append(
            {
                "kind": "hardware.recommendation",
                "summary": summary,
                "details": {
                    "rationale": rationale,
                    "recommendation": summary,
                    "shopping_items": items,
                    "implementation": "Review options and confirm compatibility with Home Assistant.",
                    "verification": "Confirm device appears in Home Assistant and in Pumpkin inventory.",
                    "rollback_plan": "Skip purchase or return hardware if not needed.",
                },
                "risk": priority,
                "expected_outcome": "Shopping list updated with suggested hardware.",
                "source_event_ids": [],
                "needs_new_capability": False,
                "capability_request": None,
                "steps": ["Review hardware options", "Approve purchase if useful"],
            }
        )

    if domains.get("media_player", 0) == 0:
        add(
            "Add a smart speaker for hands-free voice control",
            "No media_player entities detected; a speaker enables room-by-room voice responses.",
            [
                {
                    "name": "Smart speaker (Echo, Google, or ESPHome audio)",
                    "category": "audio",
                    "priority": "medium",
                    "reason": "Provide voice responses and announcements.",
                }
            ],
        )
    if domains.get("sensor", 0) < 5:
        add(
            "Add multi-sensors in key rooms",
            "Limited environmental sensors detected; more data improves comfort and alerts.",
            [
                {
                    "name": "Temp/humidity/motion multi-sensor",
                    "category": "sensors",
                    "priority": "medium",
                    "reason": "Improve comfort automation and alerts.",
                }
            ],
        )
    if domains.get("binary_sensor", 0) < 5:
        add(
            "Add door/window contact sensors",
            "Few binary sensors detected; contacts improve security and awareness.",
            [
                {
                    "name": "Door/window contact sensor",
                    "category": "security",
                    "priority": "medium",
                    "reason": "Detect open doors/windows for family safety.",
                }
            ],
        )
    if domains.get("camera", 0) == 0:
        add(
            "Add a camera for key entry areas",
            "No camera entities detected; a camera improves security and presence context.",
            [
                {
                    "name": "Indoor/outdoor IP camera with RTSP/ONVIF",
                    "category": "security",
                    "priority": "medium",
                    "reason": "Enable snapshots and person alerts.",
                }
            ],
        )
    if domains.get("lock", 0) == 0:
        add(
            "Add a smart lock for key doors",
            "No smart locks detected; enables secure access tracking.",
            [
                {
                    "name": "Smart lock (Zigbee/Z-Wave)",
                    "category": "security",
                    "priority": "low",
                    "reason": "Track access and lock status remotely.",
                }
            ],
        )
    if domains.get("climate", 0) == 0:
        add(
            "Add a smart thermostat or TRVs",
            "No climate devices detected; improves comfort and energy savings.",
            [
                {
                    "name": "Smart thermostat or radiator TRVs",
                    "category": "comfort",
                    "priority": "low",
                    "reason": "Automate heating based on presence.",
                }
            ],
        )
    add(
        "Add a UPS for Pumpkin Core",
        "Recent power outages show a need for graceful shutdown and uptime.",
        [
            {
                "name": "UPS sized for Pumpkin Core host",
                "category": "reliability",
                "priority": "high",
                "reason": "Keep Pumpkin online during short outages.",
            }
        ],
        priority=0.3,
    )
    return proposals


def build_suggestion_followup(conn, suggestion: str) -> Dict[str, Any] | None:
    if not isinstance(suggestion, str) or not suggestion.strip():
        return None
    policy = policy_mod.load_policy(str(settings.policy_path()))
    if planner_cooldown_active(conn):
        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "planner.cooldown_active",
                "cooldown_until": planner_cooldown_until(conn).isoformat(),
            },
        )
        return None
    context_pack, context_hash, context_excerpt = build_context_pack(conn)
    prompt = (
        _render_prompt(context_pack)
        + "\n\nYou are creating a single action.request proposal based on a user suggestion. "
        "Return ONLY one proposal with explicit action_type and action_params. "
        "If the suggestion is not feasible, propose a notify.local action that explains why. "
        f"\n\nSUGGESTION: {suggestion.strip()}"
    )
    try:
        plan = planner.load_planner()
        result = plan.generate(context_pack, prompt)
        validated = _validate_planner_output(policy, result.proposals)
    except Exception as exc:
        if _is_rate_limited(str(exc)):
            _set_planner_cooldown(conn, str(exc))
        return None
    _clear_planner_cooldown(conn)
    if not validated:
        return None
    proposal = validated[0]
    proposal["ai_context_hash"] = context_hash
    proposal["ai_context_excerpt"] = _proposal_excerpt(proposal)
    return proposal
