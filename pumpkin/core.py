"""Pumpkin v3 core daemon loop."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List

from . import audit
from . import policy as policy_mod
from . import settings
from . import observe
from . import propose
from . import store
from . import insights
from . import module_config
from . import inventory as inventory_mod
from .db import init_db
from .act import execute_action


def _append_recent_memory(conn, key: str, item: Dict[str, Any], limit: int = 25) -> None:
    current = store.get_memory(conn, key)
    if not isinstance(current, list):
        current = []
    current.append(item)
    store.set_memory(conn, key, current[-limit:])


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
        previous_summary = store.get_memory(conn, "homeassistant.summary") or {}

        ha_events, current_states, summary = observe.homeassistant_snapshot(
            base_url=base_url,
            token=token,
            previous=previous,
            previous_summary=previous_summary,
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

    if "network.discovery" in enabled:
        module_cfg = modules_cfg.get("network.discovery", {})
        subnet = module_cfg.get("subnet")
        tcp_ports = module_cfg.get("tcp_ports", [])
        timeout_seconds = float(module_cfg.get("timeout_seconds", 0.2))
        max_hosts = int(module_cfg.get("max_hosts", 128))
        max_scan_seconds = module_cfg.get("max_scan_seconds")
        if max_scan_seconds is not None:
            try:
                max_scan_seconds = float(max_scan_seconds)
            except (TypeError, ValueError):
                max_scan_seconds = None
        scan_interval = int(module_cfg.get("scan_interval_seconds", settings.ha_error_cooldown_seconds()))
        active = module_cfg.get("active", {})
        if _cooldown_elapsed(conn, "network.discovery", scan_interval):
            snapshot = observe.network_discovery(
                subnet=subnet,
                tcp_ports=tcp_ports if isinstance(tcp_ports, list) else [],
                timeout_seconds=timeout_seconds,
                max_hosts=max_hosts,
                max_scan_seconds=max_scan_seconds,
                active=active if isinstance(active, dict) else {},
            )
            events.append(
                {
                    "source": "network",
                    "type": "network.discovery",
                    "payload": snapshot,
                    "severity": "info",
                }
            )
            store.set_memory(conn, "network.discovery.snapshot", snapshot)
            _record_cooldown(conn, "network.discovery")

    return events


def _inventory_change_event(conn) -> Dict[str, Any] | None:
    inventory = inventory_mod.snapshot(conn)
    opportunities = inventory_mod.opportunities(inventory)
    digest = inventory_mod.digest(inventory, opportunities)
    last_digest = store.get_memory(conn, "inventory.last_hash")
    if last_digest == digest:
        return None
    store.set_memory(conn, "inventory.last_hash", digest)
    return {
        "source": "inventory",
        "type": "inventory.changed",
        "payload": {
            "summary": inventory_mod.summary(inventory),
            "opportunities": opportunities,
        },
        "severity": "info",
    }


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


def _quiet_hours_window(conn) -> Dict[str, Any] | None:
    value = store.get_memory(conn, "core.quiet_hours")
    return value if isinstance(value, dict) else None


def _in_quiet_hours(conn) -> bool:
    quiet = _quiet_hours_window(conn)
    if not quiet:
        return False
    windows = quiet.get("windows")
    if isinstance(windows, list):
        for window in windows:
            if _window_matches(window):
                return True
        return False
    return _window_matches(quiet)


def _window_matches(window: Dict[str, Any]) -> bool:
    start = window.get("start")
    end = window.get("end")
    days = window.get("days", "daily")
    if not isinstance(start, str) or not isinstance(end, str):
        return False
    now = datetime.now()
    weekday = now.weekday()
    if days == "weekdays" and weekday >= 5:
        return False
    if days == "weekends" and weekday < 5:
        return False
    try:
        start_h, start_m = [int(part) for part in start.split(":", 1)]
        end_h, end_m = [int(part) for part in end.split(":", 1)]
    except Exception:
        return False
    now_minutes = now.hour * 60 + now.minute
    start_minutes = start_h * 60 + start_m
    end_minutes = end_h * 60 + end_m
    if start_minutes <= end_minutes:
        return start_minutes <= now_minutes <= end_minutes
    return now_minutes >= start_minutes or now_minutes <= end_minutes


def _should_reflect(conn) -> bool:
    last_date = store.get_memory(conn, "core.last_reflection_date")
    today = datetime.now().date().isoformat()
    if last_date == today:
        return False
    return _in_quiet_hours(conn)


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

        summary = proposal["summary"]
        if store.proposal_exists(conn, summary, statuses=["pending", "approved"]):
            audit.append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "proposal.skipped_duplicate",
                    "summary": summary,
                },
            )
            continue
        proposal_id = store.insert_proposal(
            conn,
            kind=proposal.get("kind", "general"),
            summary=summary,
            details=proposal["details"],
            steps=proposal.get("steps"),
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
        _maybe_auto_approve_action(conn, policy, proposal_id, proposal)
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


def _maybe_auto_approve_action(
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
    audit.append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "proposal.auto_approved",
            "proposal_id": proposal_id,
            "action_type": action_type,
            "policy_hash": policy.policy_hash,
        },
    )
    return True


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
            suggestion = details.get("suggestion")
            followup = propose.build_suggestion_followup(conn, suggestion) if isinstance(suggestion, str) else None
            if followup:
                summary = followup.get("summary") or f"Implement suggestion: {suggestion[:80]}"
                if not store.proposal_exists(conn, summary, statuses=["pending", "approved"]):
                    new_id = store.insert_proposal(
                        conn,
                        kind=followup.get("kind", "action.request"),
                        summary=summary,
                        details=followup.get("details", {}),
                        risk=float(followup.get("risk", 0.4)),
                        expected_outcome=followup.get("expected_outcome", "Implementation plan ready."),
                        status="pending",
                        policy_hash=policy.policy_hash,
                        needs_new_capability=bool(followup.get("needs_new_capability", False)),
                        capability_request=followup.get("capability_request"),
                        ai_context_hash=followup.get("ai_context_hash"),
                        ai_context_excerpt=followup.get("ai_context_excerpt"),
                        steps=followup.get("steps"),
                    )
                else:
                    new_id = None
                store.update_proposal_status(conn, proposal_id, "executed")
                audit.append_jsonl(
                    str(settings.audit_path()),
                    {
                        "kind": "proposal.converted",
                        "proposal_id": proposal_id,
                        "new_proposal_id": new_id,
                        "policy_hash": policy.policy_hash,
                    },
                )
                continue
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
            _append_recent_memory(
                conn,
                "actions.recent",
                {
                    "ts": datetime.now().isoformat(),
                    "proposal_id": proposal_id,
                    "action_id": action_id,
                    "action_type": action_type,
                    "status": "succeeded",
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
            _append_recent_memory(
                conn,
                "actions.recent",
                {
                    "ts": datetime.now().isoformat(),
                    "proposal_id": proposal_id,
                    "action_id": action_id,
                    "action_type": action_type,
                    "status": "failed",
                    "error": str(exc),
                },
            )


def run_once() -> None:
    conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
    policy = policy_mod.load_policy(str(settings.policy_path()))
    _record_policy_snapshot_if_changed(conn, policy)

    prev_entities = store.get_memory(conn, "homeassistant.entities") or {}
    prev_network = store.get_memory(conn, "network.discovery.snapshot") or {}

    _create_heartbeat(conn, policy.policy_hash)

    events = observe.system_snapshot()
    _insert_events(conn, events)
    module_events = _collect_module_events(conn)
    _insert_events(conn, module_events)
    inventory_event = _inventory_change_event(conn)
    if inventory_event:
        _insert_events(conn, [inventory_event])

    snapshot_event = _latest_event(conn, "system.snapshot")
    system_snapshot = snapshot_event.get("payload") if snapshot_event else None
    ha_entities = store.get_memory(conn, "homeassistant.entities") or {}
    ha_summary = store.get_memory(conn, "homeassistant.summary") or {}
    network_snapshot = store.get_memory(conn, "network.discovery.snapshot") or {}
    insight_items = insights.build_insights(
        system_snapshot=system_snapshot,
        ha_entities=ha_entities if isinstance(ha_entities, dict) else {},
        ha_summary=ha_summary if isinstance(ha_summary, dict) else {},
        prev_entities=prev_entities if isinstance(prev_entities, dict) else {},
        network_snapshot=network_snapshot if isinstance(network_snapshot, dict) else {},
        prev_network_snapshot=prev_network if isinstance(prev_network, dict) else {},
    )
    insights.record_insights(conn, insight_items)
    insights.maybe_daily_briefing(
        conn,
        ha_summary=ha_summary if isinstance(ha_summary, dict) else {},
        system_snapshot=system_snapshot,
        insights=insight_items,
        in_quiet_hours=_in_quiet_hours(conn),
    )

    new_events = _load_events_since_last(conn)
    proposals = propose.build_proposals(new_events, conn)
    if _should_reflect(conn):
        improvement = propose.build_improvement_proposals(conn)
        if improvement:
            proposals.extend(improvement)
        store.set_memory(conn, "core.last_reflection_date", datetime.now().date().isoformat())
    _record_proposals(conn, policy, proposals)

    _execute_approved(conn, policy)


def run_forever(interval: float) -> None:
    while True:
        run_once()
        time.sleep(interval)
