"""Proposal generation using AI planner with rule fallback."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Tuple

from . import planner
from . import policy as policy_mod
from . import module_registry
from . import module_config_change
from . import intent
from . import runbook
from . import settings
from . import store
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
        "modules_registry": module_registry.registry_summary(registry),
        "system_snapshot": system_snapshot,
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
                "All changes are auditable and reversible",
            ]
        },
    }


def _render_prompt(context_pack: Dict[str, Any]) -> str:
    instructions = (
        "You are Pumpkin v3's planning module. "
        "Return a JSON object with a top-level 'proposals' list. "
        "Each proposal must follow the contract defined in the context. "
        "Do not execute actions; only propose. "
        "If you need new capabilities, set needs_new_capability true and add capability_request. "
        f"Caps: max_proposals_per_loop={MAX_PROPOSALS_PER_LOOP}, "
        f"max_steps_per_proposal={MAX_STEPS_PER_PROPOSAL}."
    )
    return f"{instructions}\n\nCONTEXT_PACK:\n{json.dumps(context_pack, ensure_ascii=True)}"


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


def _validate_planner_proposal(
    policy: policy_mod.Policy, proposal: Dict[str, Any]
) -> Dict[str, Any]:
    if not isinstance(proposal, dict):
        raise ValueError("proposal must be an object")

    kind = proposal.get("kind", "general")
    if kind not in ALLOWED_KINDS:
        raise ValueError(f"invalid kind: {kind}")

    summary = proposal.get("summary")
    expected_outcome = proposal.get("expected_outcome")
    details = proposal.get("details")
    risk = proposal.get("risk")

    _parse_json_field(summary, "summary", str)
    _parse_json_field(expected_outcome, "expected_outcome", str)
    _parse_json_field(details, "details", dict)
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
            raise ValueError("steps exceeds max_steps_per_proposal")

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
                suggested_modules = intent.suggest_modules(text, registry_summary)

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
                    module = module_registry.find_module(registry, module_name)
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
        if used_percent is None:
            continue

        threshold = 0.9
        if used_percent < threshold:
            continue

        summary = f"Disk usage high on {disk.get('path', '/')}"
        if store.proposal_exists(conn, summary, statuses=["pending", "approved"]):
            continue

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

    plan = planner.load_planner()
    rule_based = _rule_based_proposals(events, conn)
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
            for proposal in validated:
                proposal["ai_context_hash"] = context_hash
                proposal["ai_context_excerpt"] = _proposal_excerpt(proposal)
            combined = rule_based + validated
            return combined[:MAX_PROPOSALS_PER_LOOP]
        except Exception as exc:
            last_error = str(exc)
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

    notify = {
        "kind": "action.request",
        "summary": "Planner output invalid",
        "details": {
            "rationale": "Planner output did not meet validation rules.",
            "action_type": "notify.local",
            "action_params": {"message": "Planner output invalid; check audit log."},
        },
        "risk": 0.9,
        "expected_outcome": "Human is alerted to planner validation issues.",
        "source_event_ids": [],
        "needs_new_capability": False,
        "capability_request": None,
        "steps": ["Emit a local notification"],
    }

    combined = rule_based + [notify]
    return combined[:MAX_PROPOSALS_PER_LOOP]
