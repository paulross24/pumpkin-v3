"""Pumpkin v3 core daemon loop."""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List

from . import audit
from . import policy as policy_mod
from . import settings
from . import observe
from . import propose
from . import store
from . import module_config
from .db import init_db
from .act import execute_action


def _record_policy_snapshot_if_changed(conn, policy: policy_mod.Policy) -> None:
    last_hash = store.get_memory(conn, "policy.last_hash")
    if last_hash != policy.policy_hash:
        policy_mod.record_policy_snapshot(conn, policy)
        store.set_memory(conn, "policy.last_hash", policy.policy_hash)


def _insert_events(conn, events: List[Dict[str, Any]]) -> List[int]:
    event_ids = []
    for event in events:
        event_id = store.insert_event(
            conn,
            event["source"],
            event["type"],
            event.get("payload", {}),
            event.get("severity", "info"),
        )
        event_ids.append(event_id)
    return event_ids


def _cooldown_elapsed(conn, key: str, cooldown_seconds: int) -> bool:
    last = store.get_memory(conn, key)
    if not last:
        return True
    try:
        last_ts = float(last)
    except (TypeError, ValueError):
        return True
    return (time.time() - last_ts) >= cooldown_seconds


def _record_cooldown(conn, key: str) -> None:
    store.set_memory(conn, key, time.time())


def _collect_module_events(conn) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return events

    config = module_config.load_config(str(config_path))
    enabled = set(config.get("enabled", []))
    modules_cfg = config.get("modules", {})

    if "homeassistant.observer" in enabled:
        module_cfg = modules_cfg.get("homeassistant.observer", {})
        base_url = module_cfg.get("base_url")
        token_env = module_cfg.get("token_env", "PUMPKIN_HA_TOKEN")
        token = os.getenv(token_env)
        if not base_url:
            events.append(
                {
                    "source": "homeassistant",
                    "type": "homeassistant.misconfigured",
                    "payload": {"error": "missing base_url"},
                    "severity": "warn",
                }
            )
            return events

        if not token:
            if _cooldown_elapsed(conn, "ha.token_missing", settings.ha_error_cooldown_seconds()):
                events.append(
                    {
                        "source": "homeassistant",
                        "type": "homeassistant.token_missing",
                        "payload": {"base_url": base_url},
                        "severity": "warn",
                    }
                )
                _record_cooldown(conn, "ha.token_missing")
            return events

        if not _cooldown_elapsed(conn, "ha.request", settings.ha_error_cooldown_seconds()):
            return events

        include_domains = module_cfg.get("include_domains")
        include_entities = module_cfg.get("include_entities")
        exclude_domains = module_cfg.get("exclude_domains")
        exclude_entities = module_cfg.get("exclude_entities")
        attribute_allowlist = module_cfg.get("attribute_allowlist")
        calendar_enabled = bool(module_cfg.get("calendar_enabled", False))
        calendar_days_ahead = int(module_cfg.get("calendar_days_ahead", 7))
        calendar_limit = int(module_cfg.get("calendar_limit", 10))
        previous = store.get_memory(conn, "homeassistant.entities") or {}

        ha_events, current_states, summary = observe.homeassistant_snapshot(
            base_url=base_url,
            token=token,
            previous=previous,
            include_domains=include_domains,
            include_entities=include_entities,
            exclude_domains=exclude_domains,
            exclude_entities=exclude_entities,
            attribute_allowlist=attribute_allowlist,
            calendar_enabled=calendar_enabled,
            calendar_days_ahead=calendar_days_ahead,
            calendar_limit=calendar_limit,
        )
        events.extend(ha_events)
        if current_states:
            store.set_memory(conn, "homeassistant.entities", current_states)
        if summary:
            store.set_memory(conn, "homeassistant.summary", summary)
        if any(ev["type"] in {"homeassistant.request_failed", "homeassistant.states_failed"} for ev in ha_events):
            _record_cooldown(conn, "ha.request")

    return events


def _load_events_since_last(conn) -> List[Any]:
    last_id = store.get_memory(conn, "core.last_event_id")
    if last_id is None:
        last_id = 0
    events = store.fetch_events_since(conn, int(last_id))
    if events:
        store.set_memory(conn, "core.last_event_id", events[-1]["id"])
    return events


def _create_heartbeat(conn, policy_hash: str) -> None:
    store.insert_event(
        conn,
        source="core",
        event_type="heartbeat",
        payload={"policy_hash": policy_hash},
        severity="info",
    )


def _record_proposals(conn, policy: policy_mod.Policy, proposals: List[Dict[str, Any]]) -> None:
    module_install_ids: Dict[str, int] = {}
    ordered = sorted(
        proposals, key=lambda p: 0 if p.get("kind") == "module.install" else 1
    )
    for proposal in ordered:
        details = proposal["details"]
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
            summary=proposal["summary"],
            details=proposal["details"],
            risk=proposal["risk"],
            expected_outcome=proposal["expected_outcome"],
            status="pending",
            policy_hash=policy.policy_hash,
            needs_new_capability=proposal.get("needs_new_capability", False),
            capability_request=proposal.get("capability_request"),
            ai_context_hash=proposal.get("ai_context_hash"),
            ai_context_excerpt=proposal.get("ai_context_excerpt"),
        )
        if proposal.get("kind") == "module.install" and link_key:
            module_install_ids[link_key] = proposal_id
        for event_id in proposal.get("source_event_ids", []):
            store.link_proposal_event(conn, proposal_id, event_id)
        audit.append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "proposal.created",
                "proposal_id": proposal_id,
                "proposal_kind": proposal.get("kind", "general"),
                "summary": proposal["summary"],
                "risk": proposal["risk"],
                "policy_hash": policy.policy_hash,
                "ai_context_hash": proposal.get("ai_context_hash"),
                "source_event_ids": proposal.get("source_event_ids", []),
            },
        )
        if proposal.get("kind") == "capability.offer":
            audit.append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "capability.offer_created",
                    "proposal_id": proposal_id,
                    "requested_intent": proposal.get("details", {}).get("requested_intent"),
                    "policy_hash": policy.policy_hash,
                },
            )


def _execute_approved(conn, policy: policy_mod.Policy) -> None:
    approved = store.fetch_approved_unexecuted(conn)
    if not approved:
        pending = store.list_proposals(conn, status="pending", limit=50)
        pending_action_ids = [row["id"] for row in pending if row["kind"] == "action.request"]
        if pending_action_ids:
            audit.append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "action.blocked_no_approval",
                    "proposal_ids": pending_action_ids,
                    "count": len(pending_action_ids),
                    "policy_hash": policy.policy_hash,
                },
            )
    for row in approved:
        proposal_id = row["id"]
        details = json.loads(row["details_json"])
        action_type = details.get("action_type")
        action_params = details.get("action_params", {})

        if not action_type:
            store.update_proposal_status(conn, proposal_id, "failed")
            audit.append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "proposal.failed",
                    "proposal_id": proposal_id,
                    "reason": "missing action_type in proposal details",
                    "policy_hash": policy.policy_hash,
                },
            )
            continue

        try:
            decision = policy_mod.evaluate_action(
                policy, action_type, action_params, risk=row["risk"]
            )
        except Exception as exc:
            store.update_proposal_status(conn, proposal_id, "failed")
            audit.append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "proposal.failed",
                    "proposal_id": proposal_id,
                    "reason": f"policy validation failed: {exc}",
                    "policy_hash": policy.policy_hash,
                },
            )
            continue

        if decision == "forbid":
            store.update_proposal_status(conn, proposal_id, "failed")
            audit.append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "proposal.failed",
                    "proposal_id": proposal_id,
                    "reason": "policy forbids action",
                    "policy_hash": policy.policy_hash,
                },
            )
            continue

        action_id = store.insert_action(
            conn,
            proposal_id=proposal_id,
            action_type=action_type,
            params=action_params,
            status="started",
            policy_hash=policy.policy_hash,
        )
        audit.append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "action.started",
                "action_id": action_id,
                "proposal_id": proposal_id,
                "action_type": action_type,
                "policy_hash": policy.policy_hash,
            },
        )

        try:
            result = execute_action(action_type, action_params, str(settings.audit_path()))
            store.finish_action(conn, action_id, "succeeded", result=result)
            store.update_proposal_status(conn, proposal_id, "executed")
            audit.append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "action.succeeded",
                    "action_id": action_id,
                    "proposal_id": proposal_id,
                    "action_type": action_type,
                    "policy_hash": policy.policy_hash,
                },
            )
        except Exception as exc:
            store.finish_action(conn, action_id, "failed", result={"error": str(exc)})
            store.update_proposal_status(conn, proposal_id, "failed")
            audit.append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "action.failed",
                    "action_id": action_id,
                    "proposal_id": proposal_id,
                    "action_type": action_type,
                    "error": str(exc),
                    "policy_hash": policy.policy_hash,
                },
            )


def run_once() -> None:
    conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
    policy = policy_mod.load_policy(str(settings.policy_path()))
    _record_policy_snapshot_if_changed(conn, policy)

    _create_heartbeat(conn, policy.policy_hash)

    events = observe.system_snapshot()
    _insert_events(conn, events)
    module_events = _collect_module_events(conn)
    _insert_events(conn, module_events)

    new_events = _load_events_since_last(conn)
    proposals = propose.build_proposals(new_events, conn)
    _record_proposals(conn, policy, proposals)

    _execute_approved(conn, policy)


def run_forever(interval: float) -> None:
    while True:
        run_once()
        time.sleep(interval)
