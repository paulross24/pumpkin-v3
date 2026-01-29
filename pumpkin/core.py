"""Pumpkin v3 core daemon loop."""

from __future__ import annotations

import json
import hashlib
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from . import audit
from . import policy as policy_mod
from . import settings
from . import observe
from . import vision
from . import rtsp_mic
from . import camera_live
from . import camera_recording
from . import propose
from . import store
from . import insights
from . import module_config
from . import module_config_change
from . import inventory as inventory_mod
from . import selfcheck
from .db import init_db
from . import act
from .act import execute_action, PatchApplyError


def _append_recent_memory(conn, key: str, item: Dict[str, Any], limit: int = 25) -> None:
    current = store.get_memory(conn, key)
    if not isinstance(current, list):
        current = []
    current.append(item)
    store.set_memory(conn, key, current[-limit:])


def _normalize_feedback_events(raw: Any, now: datetime) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    normalized: List[Dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            ts = item.get("ts")
            if isinstance(ts, str):
                normalized.append(item)
            continue
        if isinstance(item, str):
            normalized.append({"ts": now.isoformat(), "snapshot_hash": item})
    return normalized


def _filter_recent_events(events: List[Dict[str, Any]], cutoff: datetime) -> List[Dict[str, Any]]:
    recent: List[Dict[str, Any]] = []
    for item in events:
        ts = item.get("ts")
        if not isinstance(ts, str):
            continue
        try:
            parsed = datetime.fromisoformat(ts)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        if parsed >= cutoff:
            recent.append(item)
    return recent


def _auto_tune_face_recognition(conn: sqlite3.Connection, module_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    auto_cfg = module_cfg.get("auto_tune", {})
    if not isinstance(auto_cfg, dict) or not auto_cfg.get("enabled", False):
        return events
    now = datetime.now(timezone.utc)
    cooldown_hours = int(auto_cfg.get("cooldown_hours", 6))
    last_ts_raw = store.get_memory(conn, "vision.auto_tune.last_ts")
    if isinstance(last_ts_raw, str):
        try:
            last_ts = datetime.fromisoformat(last_ts_raw)
        except ValueError:
            last_ts = None
        if last_ts is not None:
            if last_ts.tzinfo is None:
                last_ts = last_ts.replace(tzinfo=timezone.utc)
            if (now - last_ts).total_seconds() < cooldown_hours * 3600:
                return events

    window_hours = int(auto_cfg.get("window_hours", 24))
    cutoff = now - timedelta(hours=window_hours)

    false_events = _normalize_feedback_events(store.get_memory(conn, "vision.false_positive_events"), now)
    relabel_events = _normalize_feedback_events(store.get_memory(conn, "vision.relabel_events"), now)
    false_recent = _filter_recent_events(false_events, cutoff)
    relabel_recent = _filter_recent_events(relabel_events, cutoff)

    store.set_memory(conn, "vision.false_positive_events", false_recent[-200:])
    store.set_memory(conn, "vision.relabel_events", relabel_recent[-200:])

    target_fp = int(auto_cfg.get("target_false_positives", 2))
    target_relabels = int(auto_cfg.get("target_relabels", 1))
    total_count = len(false_recent) + len(relabel_recent)
    target_total = max(1, target_fp + target_relabels)
    if total_count <= target_total:
        return events

    provider = module_cfg.get("provider", {}) if isinstance(module_cfg, dict) else {}
    if not isinstance(provider, dict):
        provider = {}
    current_conf = float(provider.get("min_confidence", 0.7))
    step = float(auto_cfg.get("step", 0.02))
    floor = float(auto_cfg.get("min_confidence_floor", 0.4))
    ceiling = float(auto_cfg.get("min_confidence_ceiling", 0.9))
    new_conf = min(ceiling, max(floor, current_conf + step))
    if new_conf <= current_conf:
        return events

    config_path = settings.modules_config_path()
    config = module_config.load_config(str(config_path))
    modules_cfg = config.get("modules", {})
    if not isinstance(modules_cfg, dict):
        modules_cfg = {}
    face_cfg = modules_cfg.get("face.recognition", {})
    if not isinstance(face_cfg, dict):
        face_cfg = {}
    provider_cfg = face_cfg.get("provider", {})
    if not isinstance(provider_cfg, dict):
        provider_cfg = {}
    provider_cfg["min_confidence"] = round(new_conf, 3)
    face_cfg["provider"] = provider_cfg
    modules_cfg["face.recognition"] = face_cfg
    config["modules"] = modules_cfg

    proposed_text = module_config_change.render_config(config)
    old_hash, new_hash, diff_hash, backup_path, diff = module_config_change.apply_module_config_change(
        str(config_path), proposed_text
    )
    audit.append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "vision.auto_tune",
            "ts": now.isoformat(),
            "old_confidence": current_conf,
            "new_confidence": new_conf,
            "false_positive_count": len(false_recent),
            "relabel_count": len(relabel_recent),
            "window_hours": window_hours,
            "backup_path": backup_path,
            "diff_hash": diff_hash,
            "old_hash": old_hash,
            "new_hash": new_hash,
        },
    )
    store.set_memory(conn, "vision.auto_tune.last_ts", now.isoformat())
    store.set_memory(conn, "vision.auto_tune.last_confidence", new_conf)
    events.append(
        {
            "source": "vision",
            "type": "vision.auto_tune",
            "payload": {
                "old_confidence": current_conf,
                "new_confidence": new_conf,
                "false_positive_count": len(false_recent),
                "relabel_count": len(relabel_recent),
                "window_hours": window_hours,
            },
            "severity": "info",
        }
    )
    return events


def _record_policy_snapshot_if_changed(conn, policy: policy_mod.Policy) -> None:
    last_hash = store.get_memory(conn, "policy.last_hash")
    if last_hash != policy.policy_hash:
        policy_mod.record_policy_snapshot(conn, policy)
        store.set_memory(conn, "policy.last_hash", policy.policy_hash)


def _seed_bootstrap(conn) -> None:
    if not store.latest_identity(conn):
        store.insert_identity(conn, "Pumpkin", notes="Bootstrap identity")
    if not store.list_briefings(conn, limit=1):
        store.insert_briefing(
            conn,
            period="boot",
            summary="Pumpkin booted and initialized.",
            details={"seed": True},
        )
    if not store.list_decisions(conn, limit=1):
        store.insert_decision(
            conn,
            detection_id=None,
            observation="System initialization",
            reasoning="Bootstrap seed to populate Command Center.",
            decision="Monitor for changes.",
            action_type=None,
            action_id=None,
            proposal_id=None,
            restricted_id=None,
            verification_status="seeded",
            evidence={"seed": True},
        )
    if not store.get_setting(conn, "autonomy.mode"):
        store.set_setting(conn, "autonomy.mode", "OPERATOR")
    if not store.get_setting(conn, "autonomy.policy_hours"):
        store.set_setting(
            conn,
            "autonomy.policy_hours",
            {"start": "06:00", "end": "22:00"},
        )


def _ensure_goals(conn) -> None:
    goals = store.get_memory(conn, "goals.list")
    if isinstance(goals, list) and goals:
        return
    defaults = [
        {
            "id": "safety",
            "title": "Keep the home safe and monitored",
            "priority": "high",
            "tags": ["security"],
        },
        {
            "id": "comfort",
            "title": "Maintain comfort without manual effort",
            "priority": "med",
            "tags": ["comfort"],
        },
        {
            "id": "energy",
            "title": "Reduce wasted energy automatically",
            "priority": "med",
            "tags": ["energy"],
        },
        {
            "id": "clarity",
            "title": "Summarize important changes clearly",
            "priority": "high",
            "tags": ["insights"],
        },
    ]
    store.set_memory(conn, "goals.list", defaults)


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

        ha_events, current_states, summary, details = observe.homeassistant_snapshot(
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
        if details.get("areas") is not None:
            store.set_memory(conn, "homeassistant.areas", details.get("areas"))
        if details.get("entity_registry") is not None:
            store.set_memory(conn, "homeassistant.entity_registry", details.get("entity_registry"))
        if details.get("device_registry") is not None:
            store.set_memory(conn, "homeassistant.device_registry", details.get("device_registry"))
        if summary or current_states:
            sync = {
                "last_sync": datetime.now().isoformat(),
                "entity_count": len(current_states or {}),
                "area_count": len(details.get("areas") or []) if details.get("areas") is not None else None,
                "entity_registry_count": len(details.get("entity_registry") or [])
                if details.get("entity_registry") is not None
                else None,
                "device_registry_count": len(details.get("device_registry") or [])
                if details.get("device_registry") is not None
                else None,
            }
            store.set_memory(conn, "homeassistant.sync", sync)
        if any(ev["type"] in {"homeassistant.request_failed", "homeassistant.states_failed"} for ev in ha_events):
            _record_cooldown(conn, "ha.request")
        ha_error_types = {
            "homeassistant.request_failed",
            "homeassistant.states_failed",
            "homeassistant.areas_failed",
            "homeassistant.entity_registry_failed",
            "homeassistant.device_registry_failed",
            "homeassistant.token_missing",
            "homeassistant.misconfigured",
        }
        current_errors = {
            ev.get("type")
            for ev in events
            if ev.get("source") == "homeassistant" and ev.get("type") in ha_error_types
        }
        previous_errors = store.get_memory(conn, "homeassistant.last_errors") or []
        if not isinstance(previous_errors, list):
            previous_errors = []
        if not previous_errors and not current_errors:
            row = conn.execute(
                "SELECT type, ts FROM events WHERE source = 'homeassistant' "
                "AND type IN ({}) ORDER BY id DESC LIMIT 1".format(
                    ",".join("?" for _ in ha_error_types)
                ),
                tuple(ha_error_types),
            ).fetchone()
            if row:
                ts = _parse_ts(row["ts"]) if isinstance(row, dict) else _parse_ts(row[1])
                if ts and (datetime.now(timezone.utc) - ts).total_seconds() < 3600:
                    previous_errors = [row["type"] if isinstance(row, dict) else row[0]]
        if current_errors:
            store.set_memory(conn, "homeassistant.last_errors", sorted(current_errors))
            store.set_memory(conn, "homeassistant.last_error_ts", datetime.now().isoformat())
        elif previous_errors:
            events.append(
                {
                    "source": "homeassistant",
                    "type": "homeassistant.recovered",
                    "payload": {"cleared": previous_errors},
                    "severity": "info",
                }
            )
            store.set_memory(conn, "homeassistant.last_errors", [])
            store.set_memory(conn, "homeassistant.last_recovered_ts", datetime.now().isoformat())

    if "network.discovery" in enabled:
        module_cfg = modules_cfg.get("network.discovery", {})
        subnet = module_cfg.get("subnet")
        tcp_ports = module_cfg.get("tcp_ports", [])
        timeout_seconds = float(module_cfg.get("timeout_seconds", 0.2))
        fast_ports = module_cfg.get("fast_ports", [])
        fast_timeout_seconds = module_cfg.get("fast_timeout_seconds")
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
                fast_ports=fast_ports if isinstance(fast_ports, list) else [],
                fast_timeout_seconds=fast_timeout_seconds,
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
            store.set_memory(conn, "network.discovery.last_ts", datetime.now(timezone.utc).isoformat())
            _record_cooldown(conn, "network.discovery")

    if "face.recognition" in enabled:
        module_cfg = modules_cfg.get("face.recognition", {})
        scan_interval = int(module_cfg.get("scan_interval_seconds", 300))
        if _cooldown_elapsed(conn, "face.recognition", scan_interval):
            events.extend(vision.run_face_recognition(conn, module_cfg))
            _record_cooldown(conn, "face.recognition")
        events.extend(_auto_tune_face_recognition(conn, module_cfg))

    if "voice.mic_rtsp" in enabled:
        module_cfg = modules_cfg.get("voice.mic_rtsp", {})
        poll_interval = int(module_cfg.get("poll_interval_seconds", 10))
        if _cooldown_elapsed(conn, "voice.mic_rtsp", poll_interval):
            events.extend(rtsp_mic.run_rtsp_mic(conn, module_cfg))
            _record_cooldown(conn, "voice.mic_rtsp")

    if "camera.live" in enabled:
        module_cfg = modules_cfg.get("camera.live", {})
        poll_interval = int(module_cfg.get("poll_interval_seconds", 10))
        if _cooldown_elapsed(conn, "camera.live", poll_interval):
            events.extend(camera_live.ensure_live(conn, module_cfg))
            _record_cooldown(conn, "camera.live")

    if "camera.recording" in enabled:
        module_cfg = modules_cfg.get("camera.recording", {})
        camera_id = module_cfg.get("camera_id") or "kitchen-cam"
        cooldown_seconds = int(module_cfg.get("cooldown_seconds", 60))
        cooldown_key = f"camera.recording:{camera_id}"
        if _cooldown_elapsed(conn, cooldown_key, cooldown_seconds):
            events.extend(camera_recording.run_recording(conn, module_cfg))
            _record_cooldown(conn, cooldown_key)

    return events


def _record_action_summary(
    conn,
    action_type: str,
    status: str,
    proposal_id: int | None,
    detail: str | None = None,
) -> None:
    summary = f"{action_type} {status}"
    if detail:
        summary = f"{summary} ({detail})"
    store.set_memory(conn, "actions.last_summary", summary)
    store.set_memory(conn, "actions.last_summary_ts", datetime.now(timezone.utc).isoformat())
    store.insert_event(
        conn,
        "system",
        "action.summary",
        {
            "summary": summary,
            "action_type": action_type,
            "status": status,
            "proposal_id": proposal_id,
        },
        severity="info" if status == "succeeded" else "warn",
    )


def _infer_action_commands(details: Dict[str, Any]) -> List[str]:
    action_type = details.get("action_type")
    if action_type == "code.apply_patch":
        repo_root = details.get("action_params", {}).get("repo_root")
        if repo_root:
            return [f"apply patch to {repo_root}"]
        return ["apply code patch"]
    if action_type == "network.deep_scan":
        ip = details.get("action_params", {}).get("ip")
        return [f"run deep scan on {ip}"] if ip else ["run deep scan"]
    if action_type == "network.mark_useful":
        ip = details.get("action_params", {}).get("ip")
        return [f"mark {ip} as useful"] if ip else ["mark device useful"]
    if action_type == "proposal.confirm_plan":
        return ["confirm execution plan"]
    if isinstance(action_type, str) and action_type:
        return [f"execute {action_type}"]
    return ["execute action"]


def _ensure_execution_plan(conn, policy: policy_mod.Policy, row: Any) -> bool:
    try:
        details = json.loads(row["details_json"])
    except Exception:
        details = {}
    action_type = details.get("action_type")
    if not action_type:
        return True
    if action_type in {"proposal.confirm_plan", "proposal.retry_execute"}:
        return True
    summary = row["summary"] if "summary" in row.keys() else None
    if isinstance(summary, str) and summary.startswith("Confirm execution plan"):
        return True
    if details.get("execution_plan_confirmed") is True:
        return True
    if "execution_plan" not in details:
        details["execution_plan"] = {
            "owner": "pumpkin",
            "dependencies": details.get("dependencies", []),
            "commands": _infer_action_commands(details),
            "notes": "Confirm before execution.",
        }
        details["execution_plan_confirmed"] = False
        store.update_proposal_details(conn, row["id"], details)

    autonomy_cfg = _load_autonomy_config(conn)
    if autonomy_cfg.get("auto_confirm_execution_plan") is True:
        details["execution_plan_confirmed"] = True
        store.update_proposal_details(conn, row["id"], details)
        audit.append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "proposal.execution_plan_auto_confirmed",
                "proposal_id": row["id"],
                "action_type": action_type,
                "policy_hash": policy.policy_hash,
            },
        )
        return True

    summary = f"Confirm execution plan for proposal #{row['id']}: {row['summary']}"
    if not store.proposal_exists(conn, summary, statuses=["pending", "approved"]):
        store.insert_proposal(
            conn,
            kind="action.request",
            summary=summary,
            details={
                "rationale": "Execution plans must be confirmed before actions run.",
                "action_type": "proposal.confirm_plan",
                "action_params": {"proposal_id": row["id"]},
                "implementation": "Confirm the execution plan so the action can run.",
                "verification": "Proposal details show execution_plan_confirmed=true.",
                "rollback_plan": "Decline if the plan looks incorrect.",
                "execution_plan": details.get("execution_plan"),
            },
            risk=0.1,
            expected_outcome="Execution plan confirmed for the proposal.",
            status="pending",
            policy_hash=policy.policy_hash,
            needs_new_capability=False,
            capability_request=None,
            steps=["Review execution plan", "Approve to confirm"],
        )
    audit.append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "proposal.execution_plan_required",
            "proposal_id": row["id"],
            "action_type": action_type,
            "policy_hash": policy.policy_hash,
        },
    )
    return False


def _cleanup_confirm_plan_proposals(conn, autonomy_cfg: Dict[str, Any]) -> int:
    if autonomy_cfg.get("auto_confirm_execution_plan") is not True:
        return 0
    rows = store.list_proposals(conn, status="pending", limit=200)
    cleaned = 0
    for row in rows:
        try:
            summary = row["summary"]
        except Exception:
            summary = None
        if not isinstance(summary, str):
            continue
        if not summary.startswith("Confirm execution plan for proposal #"):
            continue
        policy_hash = row["policy_hash"]
        store.insert_approval(
            conn,
            proposal_id=row["id"],
            actor="selfheal.auto",
            decision="rejected",
            reason="auto_confirm_execution_plan_enabled",
            policy_hash=policy_hash,
        )
        store.update_proposal_status(conn, row["id"], "rejected")
        audit.append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "proposal.auto_rejected_confirm_plan",
                "proposal_id": row["id"],
                "policy_hash": policy_hash,
            },
        )
        cleaned += 1
    return cleaned


def _auto_approve_pending_repaired_patches(conn, autonomy_cfg: Dict[str, Any]) -> int:
    if autonomy_cfg.get("auto_apply_repaired_patches") is not True:
        return 0
    rows = store.list_proposals(conn, status="pending", limit=200)
    approved = 0
    for row in rows:
        try:
            summary = row["summary"]
        except Exception:
            summary = None
        if not isinstance(summary, str):
            continue
        if not summary.startswith("Repair failed patch for proposal #"):
            continue
        try:
            details = json.loads(row["details_json"])
        except Exception:
            details = {}
        details["execution_plan_confirmed"] = True
        if "execution_plan" not in details:
            details["execution_plan"] = {
                "owner": "pumpkin",
                "dependencies": [],
                "commands": _infer_action_commands(details),
                "notes": "Auto-confirmed for repaired patch.",
            }
        store.update_proposal_details(conn, row["id"], details)
        policy_hash = row["policy_hash"]
        store.insert_approval(
            conn,
            proposal_id=row["id"],
            actor="selfheal.auto",
            decision="approved",
            reason="auto_apply_repaired_patch",
            policy_hash=policy_hash,
        )
        store.update_proposal_status(conn, row["id"], "approved")
        audit.append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "proposal.auto_approved_repair_patch",
                "proposal_id": row["id"],
                "policy_hash": policy_hash,
            },
        )
        approved += 1
    return approved


def _watchdog_stalled_actions(conn, policy: policy_mod.Policy, autonomy_cfg: Dict[str, Any]) -> None:
    try:
        stall_minutes = int(autonomy_cfg.get("action_stall_minutes", 10))
    except (TypeError, ValueError):
        stall_minutes = 10
    if stall_minutes <= 0:
        return
    cutoff = datetime.now(timezone.utc).timestamp() - (stall_minutes * 60)
    approved = store.list_proposals(conn, status="approved", limit=200)
    for row in approved:
        try:
            details = json.loads(row["details_json"])
        except Exception:
            details = {}
        action_type = details.get("action_type")
        if not action_type:
            continue
        if details.get("execution_plan_confirmed") is not True:
            continue
        try:
            ts_created = row["ts_created"]
        except Exception:
            ts_created = None
        if not isinstance(ts_created, str):
            continue
        try:
            created_ts = datetime.fromisoformat(ts_created).timestamp()
        except Exception:
            continue
        if created_ts > cutoff:
            continue
        action_row = conn.execute(
            "SELECT ts_started FROM actions WHERE proposal_id = ? ORDER BY id DESC LIMIT 1",
            (row["id"],),
        ).fetchone()
        if action_row:
            continue
        summary = f"Retry stalled proposal #{row['id']}: {row['summary']}"
        if not store.proposal_exists(conn, summary, statuses=["pending", "approved"]):
            store.insert_proposal(
                conn,
                kind="action.request",
                summary=summary,
                details={
                    "rationale": "Action did not start within the expected window; retry with a single forced execution.",
                    "action_type": "proposal.retry_execute",
                    "action_params": {"proposal_id": row["id"]},
                    "implementation": "Set a one-time force_execute flag so the action runs on the next loop.",
                    "verification": "Confirm an action starts and proposal status updates.",
                    "rollback_plan": "Clear the force_execute flag if retry is not desired.",
                    "retry_plan": {
                        "checks": [
                            "Execution plan confirmed",
                            "No prior action started",
                            "Core loop running",
                        ],
                        "bypass": "action cooldown (one attempt)",
                        "attempts": 1,
                    },
                },
                risk=0.2,
                expected_outcome="A single retry attempt is executed for the stalled action.",
                status="pending",
                policy_hash=policy.policy_hash,
                needs_new_capability=False,
                capability_request=None,
                steps=["Approve retry", "Verify action starts"],
            )
        cooldown_key = f"proposal.stalled:{row['id']}"
        if not _cooldown_elapsed(conn, cooldown_key, stall_minutes * 60):
            continue
        store.insert_event(
            conn,
            source="core",
            event_type="action.stalled",
            payload={
                "proposal_id": row["id"],
                "summary": row["summary"],
                "action_type": action_type,
                "stall_minutes": stall_minutes,
            },
            severity="warn",
        )
        _record_cooldown(conn, cooldown_key)
        audit.append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "action.stalled",
                "proposal_id": row["id"],
                "action_type": action_type,
                "stall_minutes": stall_minutes,
                "policy_hash": policy.policy_hash,
            },
        )

def _record_pulse(
    conn,
    ha_summary: Dict[str, Any],
    network_snapshot: Dict[str, Any],
    proposals_count: int,
    pulse_interval: int,
) -> None:
    if pulse_interval <= 0:
        return
    if not _cooldown_elapsed(conn, "system.pulse", pulse_interval):
        return
    people_home = ha_summary.get("people_home") or []
    device_count = 0
    if isinstance(network_snapshot, dict):
        devices = network_snapshot.get("devices") or []
        if isinstance(devices, list):
            device_count = len(devices)
    payload = {
        "people_home": len(people_home),
        "device_count": device_count,
        "pending_proposals": proposals_count,
    }
    store.insert_event(conn, "system", "system.pulse", payload, severity="info")
    _record_cooldown(conn, "system.pulse")


def _normalize_ts(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _recent_alerts(
    conn: sqlite3.Connection, lookback_seconds: int = 6 * 3600
) -> Dict[str, Any]:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=lookback_seconds)
    rows = store.list_events(conn, limit=200)
    counts: Dict[str, int] = {}
    last_ts: datetime | None = None
    for row in rows:
        event_type = row["type"]
        if event_type not in {"face.alert", "behavior.alert", "car.alert"}:
            continue
        ts = _normalize_ts(row["ts"])
        if not ts or ts < cutoff:
            continue
        counts[event_type] = counts.get(event_type, 0) + 1
        if last_ts is None or ts > last_ts:
            last_ts = ts
    return {
        "counts": counts,
        "last_ts": last_ts.isoformat() if last_ts else None,
    }


def _update_awareness_snapshot(
    conn: sqlite3.Connection,
    ha_summary: Dict[str, Any],
    network_snapshot: Dict[str, Any],
) -> None:
    people_home = ha_summary.get("people_home") or []
    device_count = 0
    if isinstance(network_snapshot, dict):
        devices = network_snapshot.get("devices") or []
        if isinstance(devices, list):
            device_count = len(devices)
    pending_proposals = len(store.list_proposals(conn, status="pending", limit=500))
    alerts = _recent_alerts(conn)
    alert_counts = alerts.get("counts") or {}
    alert_total = sum(alert_counts.values()) if isinstance(alert_counts, dict) else 0
    parts = [
        f"{len(people_home)} home",
        f"{device_count} devices",
        f"{pending_proposals} proposals",
    ]
    if alert_total:
        parts.append(f"{alert_total} alerts")
    summary = ", ".join(parts)
    payload = {
        "people_home": len(people_home),
        "device_count": device_count,
        "pending_proposals": pending_proposals,
        "alert_counts": alert_counts,
        "last_alert_ts": alerts.get("last_ts"),
        "summary": summary,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    signature = hashlib.md5(blob.encode("utf-8")).hexdigest()
    prev_signature = store.get_memory(conn, "awareness.snapshot_hash")
    if signature != prev_signature:
        store.insert_event(conn, "system", "awareness.snapshot", payload, severity="info")
        store.set_memory(conn, "awareness.snapshot", payload)
        store.set_memory(conn, "awareness.snapshot_hash", signature)


def _maybe_hourly_briefing(
    conn,
    ha_summary: Dict[str, Any],
    system_snapshot: Dict[str, Any] | None,
    insights_list: List[Dict[str, Any]],
) -> None:
    last_ts = store.get_memory(conn, "briefing.last_hourly_ts")
    if isinstance(last_ts, str):
        try:
            parsed = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
        except Exception:
            parsed = None
        if parsed:
            delta = (datetime.now(timezone.utc) - parsed).total_seconds()
            if delta < 3600:
                return
    summary = insights.build_briefing(ha_summary, system_snapshot, insights_list)
    ts = datetime.now(timezone.utc).isoformat()
    store.set_memory(conn, "briefing.last_hourly_ts", ts)
    store.insert_briefing(
        conn,
        period="hourly",
        summary=summary,
        details={"count": len(insights_list), "type": "hourly"},
    )


def _update_shopping_list(conn) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    seen = set()
    acquired = store.get_memory(conn, "shopping.acquired")
    if not isinstance(acquired, list):
        acquired = []
    acquired_keys = {str(item).lower() for item in acquired if isinstance(item, str)}
    for status in ("pending", "approved"):
        for row in store.list_proposals(conn, status=status, limit=200):
            try:
                details = json.loads(row["details_json"])
            except Exception:
                details = {}
            shopping = details.get("shopping_items")
            if not isinstance(shopping, list):
                continue
            for entry in shopping:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name") or "").strip()
                if not name:
                    continue
                if name.lower() in acquired_keys:
                    continue
                link = entry.get("link") or entry.get("url") or entry.get("purchase_url")
                if not link:
                    link = f"https://www.amazon.co.uk/s?k={urllib.parse.quote_plus(name)}"
                key = name.lower()
                if key in seen:
                    continue
                seen.add(key)
                items.append(
                    {
                        "name": name,
                        "category": entry.get("category"),
                        "priority": entry.get("priority"),
                        "reason": entry.get("reason"),
                        "link": link,
                        "proposal_id": row["id"],
                        "proposal_summary": row["summary"],
                        "status": row["status"],
                    }
                )
    priority_order = {"high": 0, "medium": 1, "low": 2}
    items.sort(
        key=lambda item: (
            priority_order.get(str(item.get("priority") or "medium").lower(), 9),
            str(item.get("name") or ""),
        )
    )
    store.set_memory(conn, "shopping.list", items)
    return items


def _load_llm_config(conn) -> Dict[str, Any]:
    api_key = os.getenv("PUMPKIN_OPENAI_API_KEY") or store.get_memory(conn, "llm.openai_api_key")
    model = os.getenv("PUMPKIN_OPENAI_MODEL") or store.get_memory(conn, "llm.openai_model") or "gpt-4o-mini"
    base_url = (
        os.getenv("PUMPKIN_OPENAI_BASE_URL")
        or store.get_memory(conn, "llm.openai_base_url")
        or "https://api.openai.com/v1/chat/completions"
    )
    return {"api_key": api_key, "model": model, "base_url": base_url}


def _repair_patch_with_llm(
    api_key: str,
    model: str,
    base_url: str,
    patch: str,
    error: str,
    stderr: str | None,
    context: str,
) -> str | None:
    stderr_block = f"\nPatch stderr:\n{stderr}\n" if isinstance(stderr, str) and stderr.strip() else ""
    prompt = (
        "You are a senior software engineer. Fix the unified diff patch below so it applies cleanly. "
        "Return ONLY a valid unified diff patch with file headers. No explanations.\n"
        "If hunks are offset, adjust line numbers/contexts. Keep changes minimal and consistent.\n\n"
        f"Patch error: {error}\n"
        f"{stderr_block}\n"
        f"FILE CONTEXT:\n{context}\n\nPATCH:\n{patch}\n"
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Return only a valid unified diff patch."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 800,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(base_url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return None
    try:
        parsed = json.loads(body)
        content = parsed["choices"][0]["message"]["content"]
    except Exception:
        return None
    return content.strip()


def _repair_failed_patches(conn) -> None:
    last_ts = store.get_memory(conn, "actions.last_repair_ts")
    if not isinstance(last_ts, str):
        last_ts = "1970-01-01T00:00:00+00:00"
    autonomy_cfg = _load_autonomy_config(conn)
    try:
        max_attempts = int(autonomy_cfg.get("max_patch_repair_attempts", 2))
    except (TypeError, ValueError):
        max_attempts = 2
    try:
        cooldown_hours = int(autonomy_cfg.get("patch_repair_cooldown_hours", 24))
    except (TypeError, ValueError):
        cooldown_hours = 24
    auto_apply = autonomy_cfg.get("auto_apply_repaired_patches") is True
    attempt_map = store.get_memory(conn, "patch.repair.attempts") or {}
    if not isinstance(attempt_map, dict):
        attempt_map = {}
    blocked_map = store.get_memory(conn, "patch.repair.blocked_until") or {}
    if not isinstance(blocked_map, dict):
        blocked_map = {}
    now_ts = datetime.now(timezone.utc)
    rows = conn.execute(
        "SELECT id, proposal_id, ts_finished, action_type, status, result_json, params_json "
        "FROM actions WHERE action_type = 'code.apply_patch' AND status = 'failed' "
        "AND ts_finished > ? ORDER BY ts_finished ASC",
        (last_ts,),
    ).fetchall()
    if not rows:
        return
    llm = _load_llm_config(conn)
    api_key = llm.get("api_key")
    if not isinstance(api_key, str) or not api_key.strip():
        audit.append_jsonl(
            str(settings.audit_path()),
            {"kind": "patch.repair_skipped", "reason": "missing_api_key"},
        )
        return
    model = str(llm.get("model") or "gpt-4o-mini")
    base_url = str(llm.get("base_url") or "https://api.openai.com/v1/chat/completions")
    def _parse_patch_hunks(patch_text: str) -> Dict[str, List[int]]:
        hunks: Dict[str, List[int]] = {}
        current_file: str | None = None
        for line in patch_text.splitlines():
            if line.startswith("+++ "):
                path = line[4:].split("\t")[0].strip()
                if path == "/dev/null":
                    current_file = None
                    continue
                if path.startswith("a/") or path.startswith("b/"):
                    path = path[2:]
                current_file = path
                hunks.setdefault(current_file, [])
                continue
            if current_file and line.startswith("@@"):
                match = re.search(r"\\+(\\d+)(?:,(\\d+))?", line)
                if match:
                    hunks[current_file].append(int(match.group(1)))
        return hunks

    def _format_snippet(lines: List[str], start: int, end: int) -> str:
        formatted = []
        for idx in range(start, end + 1):
            if 1 <= idx <= len(lines):
                formatted.append(f"{idx:>4}│{lines[idx - 1].rstrip()}")
        return "\n".join(formatted)

    def _build_patch_context(patch_text: str, repo_root: str) -> str:
        files = act._patch_files(patch_text) if hasattr(act, "_patch_files") else []
        hunks = _parse_patch_hunks(patch_text)
        repo_root_real = os.path.realpath(repo_root)
        entries = []
        for path in files[:4]:
            safe_path = str(path)
            full = os.path.realpath(os.path.join(repo_root_real, safe_path))
            if not full.startswith(repo_root_real + os.sep):
                continue
            if not os.path.exists(full):
                entries.append(f"FILE {safe_path}: missing")
                continue
            try:
                with open(full, "r", encoding="utf-8") as handle:
                    lines = handle.readlines()
            except Exception:
                entries.append(f"FILE {safe_path}: unreadable")
                continue
            if safe_path in hunks and hunks[safe_path]:
                for start_line in hunks[safe_path][:2]:
                    start = max(1, start_line - 12)
                    end = min(len(lines), start_line + 12)
                    snippet = _format_snippet(lines, start, end)
                    entries.append(
                        f"FILE {safe_path} (around line {start_line}):\n{snippet}"
                    )
            else:
                head = _format_snippet(lines, 1, min(len(lines), 40))
                entries.append(f"FILE {safe_path} (head):\n{head}")
        return "\n\n".join(entries) if entries else "No file context available."
    for row in rows:
        action_id, proposal_id, ts_finished, _, _, result_json, params_json = row
        if isinstance(ts_finished, str):
            last_ts = ts_finished
        try:
            result = json.loads(result_json or "{}")
        except Exception:
            result = {}
        error = str(result.get("error") or "patch_failed")
        stderr = result.get("stderr") or result.get("error_message")
        try:
            params = json.loads(params_json or "{}")
        except Exception:
            params = {}
        patch = params.get("patch")
        repo_root = params.get("repo_root")
        if not isinstance(patch, str) or not isinstance(repo_root, str):
            continue
        target_id = proposal_id or action_id
        summary = f"Repair failed patch for proposal #{target_id}"
        blocked_until = blocked_map.get(str(target_id))
        if isinstance(blocked_until, str):
            try:
                blocked_until_ts = datetime.fromisoformat(blocked_until)
            except Exception:
                blocked_until_ts = None
            if blocked_until_ts and blocked_until_ts > now_ts:
                continue
        attempts = int(attempt_map.get(str(target_id), 0) or 0)
        if attempts >= max_attempts:
            blocked_map[str(target_id)] = (now_ts + timedelta(hours=cooldown_hours)).isoformat()
            store.snooze_proposal_summary(conn, summary, reason="repair_attempts_exceeded")
            audit.append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "patch.repair_blocked",
                    "action_id": action_id,
                    "proposal_id": proposal_id,
                    "attempts": attempts,
                },
            )
            continue
        attempt_map[str(target_id)] = attempts + 1
        if store.proposal_exists(conn, summary, statuses=["pending", "approved"]):
            continue
        context = _build_patch_context(patch, repo_root)
        repaired = _repair_patch_with_llm(
            api_key.strip(),
            model,
            base_url,
            patch,
            error,
            stderr if isinstance(stderr, str) else None,
            context,
        )
        if not isinstance(repaired, str) or not repaired.strip():
            audit.append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "patch.repair_failed",
                    "action_id": action_id,
                    "proposal_id": proposal_id,
                },
            )
            continue
        details = {
            "rationale": "Auto-repaired a failed patch so it can be applied cleanly.",
            "action_type": "code.apply_patch",
            "action_params": {"repo_root": repo_root, "patch": repaired},
            "implementation": "Apply the repaired patch after review.",
            "verification": "Confirm patch applies and run relevant checks.",
            "rollback_plan": "Revert changes if tests fail.",
            "original_action_id": action_id,
            "original_proposal_id": proposal_id,
            "original_error": error,
            "execution_plan_confirmed": True,
            "execution_plan": {
                "owner": "pumpkin",
                "dependencies": [],
                "commands": [f"apply patch to {repo_root}"],
                "notes": "Auto-confirmed for repaired patch.",
            },
        }
        status = "approved" if auto_apply else "pending"
        proposal_id = store.insert_proposal(
            conn,
            kind="action.request",
            summary=summary,
            details=details,
            steps=[
                "Review repaired patch",
                "Approve to apply",
                "Verify behavior",
            ],
            risk=0.4,
            expected_outcome="Patch applied cleanly after review.",
            status=status,
            policy_hash=policy_mod.load_policy(str(settings.policy_path())).policy_hash,
            needs_new_capability=False,
            capability_request=None,
            ai_context_hash=None,
            ai_context_excerpt=None,
        )
        if auto_apply:
            store.insert_approval(
                conn,
                proposal_id=proposal_id,
                actor="selfheal.auto",
                decision="approved",
                reason="auto_apply_repaired_patch",
                policy_hash=policy_mod.load_policy(str(settings.policy_path())).policy_hash,
            )
        audit.append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "patch.repair_proposal_created",
                "action_id": action_id,
                "proposal_id": proposal_id,
            },
        )
    store.set_memory(conn, "actions.last_repair_ts", last_ts)
    store.set_memory(conn, "patch.repair.attempts", attempt_map)
    store.set_memory(conn, "patch.repair.blocked_until", blocked_map)


def _load_autonomy_config(conn=None) -> Dict[str, Any]:
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return {}
    config = module_config.load_config(str(config_path))
    modules_cfg = config.get("modules", {})
    if not isinstance(modules_cfg, dict):
        return {}
    autonomy_cfg = modules_cfg.get("autonomy", {})
    if not isinstance(autonomy_cfg, dict):
        autonomy_cfg = {}
    if conn is not None:
        mode = store.get_setting(conn, "autonomy.mode")
        if isinstance(mode, str) and mode:
            autonomy_cfg["mode"] = mode
        policy_hours = store.get_setting(conn, "autonomy.policy_hours")
        if isinstance(policy_hours, dict):
            autonomy_cfg["policy_hours"] = policy_hours
    return autonomy_cfg


def _load_detection_config(conn=None) -> Dict[str, Any]:
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return {}
    config = module_config.load_config(str(config_path))
    modules_cfg = config.get("modules", {})
    if not isinstance(modules_cfg, dict):
        return {}
    detections_cfg = modules_cfg.get("detections", {})
    if not isinstance(detections_cfg, dict):
        detections_cfg = {}
    return detections_cfg


def _autonomy_mode(conn, autonomy_cfg: Dict[str, Any]) -> str:
    mode = autonomy_cfg.get("mode")
    if isinstance(mode, str) and mode.strip():
        return mode.strip().upper()
    stored = store.get_setting(conn, "autonomy.mode")
    if isinstance(stored, str) and stored.strip():
        return stored.strip().upper()
    return "OPERATOR"


def _within_policy_hours(autonomy_cfg: Dict[str, Any]) -> bool:
    window = autonomy_cfg.get("policy_hours")
    if not isinstance(window, dict):
        return True
    start = window.get("start")
    end = window.get("end")
    if not (isinstance(start, str) and isinstance(end, str)):
        return True
    try:
        now = datetime.now().time()
        start_h, start_m = [int(part) for part in start.split(":", 1)]
        end_h, end_m = [int(part) for part in end.split(":", 1)]
        start_t = datetime.now().replace(hour=start_h, minute=start_m, second=0, microsecond=0).time()
        end_t = datetime.now().replace(hour=end_h, minute=end_m, second=0, microsecond=0).time()
    except Exception:
        return True
    if start_t <= end_t:
        return start_t <= now <= end_t
    return now >= start_t or now <= end_t


def _should_auto_execute(
    mode: str, lane: str, autonomy_cfg: Dict[str, Any]
) -> bool:
    if settings.safe_mode_enabled():
        return False
    if mode == "OBSERVER":
        return False
    if lane != "A":
        return False
    if mode == "STEWARD":
        return _within_policy_hours(autonomy_cfg)
    return True


def _recent_detection_seen(conn, signature: str, window_seconds: int = 900) -> bool:
    entries = store.get_memory(conn, "detections.recent")
    if not isinstance(entries, list):
        return False
    now = time.time()
    kept = []
    seen = False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ts = entry.get("ts")
        sig = entry.get("sig")
        if not isinstance(ts, (int, float)):
            continue
        if now - ts > window_seconds:
            continue
        kept.append(entry)
        if sig == signature:
            seen = True
    store.set_memory(conn, "detections.recent", kept)
    return seen


def _remember_detection(conn, signature: str) -> None:
    entries = store.get_memory(conn, "detections.recent")
    if not isinstance(entries, list):
        entries = []
    entries.append({"sig": signature, "ts": time.time()})
    store.set_memory(conn, "detections.recent", entries[-50:])


def _should_emit_detection(
    conn,
    detection_type: str,
    signature: str,
    cfg: Dict[str, Any],
) -> bool:
    if not cfg.get("enabled", True):
        return True
    now = time.time()
    window_seconds = int(cfg.get("window_seconds", 900))
    max_per_window = int(cfg.get("max_per_window", 1))
    min_occurrences_by_type = cfg.get("min_occurrences_by_type", {})
    if not isinstance(min_occurrences_by_type, dict):
        min_occurrences_by_type = {}
    default_min = int(cfg.get("min_occurrences", 1))
    required = int(min_occurrences_by_type.get(detection_type, default_min))
    backoff_by_type = cfg.get("backoff_minutes_by_type", {})
    if not isinstance(backoff_by_type, dict):
        backoff_by_type = {}
    default_backoff = int(cfg.get("backoff_minutes", 0))

    suppressed = store.get_memory(conn, "detections.suppressed_until") or {}
    if not isinstance(suppressed, dict):
        suppressed = {}
    suppressed_until = suppressed.get(signature)
    if isinstance(suppressed_until, (int, float)) and now < float(suppressed_until):
        return False

    occurrences = store.get_memory(conn, "detections.occurrences") or {}
    if not isinstance(occurrences, dict):
        occurrences = {}
    record = occurrences.get(signature) if isinstance(occurrences.get(signature), dict) else {}
    first_ts = record.get("first_ts")
    count = record.get("count", 0)
    if not isinstance(first_ts, (int, float)) or now - float(first_ts) > window_seconds:
        first_ts = now
        count = 0
    count = int(count) + 1
    occurrences[signature] = {"first_ts": first_ts, "count": count}
    store.set_memory(conn, "detections.occurrences", occurrences)
    if count < required:
        return False

    emissions = store.get_memory(conn, "detections.emissions") or {}
    if not isinstance(emissions, dict):
        emissions = {}
    history = emissions.get(signature)
    if not isinstance(history, list):
        history = []
    history = [ts for ts in history if isinstance(ts, (int, float)) and now - ts <= window_seconds]
    if len(history) >= max_per_window:
        emissions[signature] = history
        store.set_memory(conn, "detections.emissions", emissions)
        return False
    history.append(now)
    emissions[signature] = history
    store.set_memory(conn, "detections.emissions", emissions)
    occurrences[signature] = {"first_ts": now, "count": 0}
    store.set_memory(conn, "detections.occurrences", occurrences)

    backoff = int(backoff_by_type.get(detection_type, default_backoff))
    if backoff > 0:
        suppressed[signature] = now + backoff * 60
        store.set_memory(conn, "detections.suppressed_until", suppressed)
    return True


def _event_payload(row: Any) -> Dict[str, Any]:
    try:
        payload_raw = row["payload_json"]
    except Exception:
        payload_raw = None
    if isinstance(payload_raw, str):
        try:
            return json.loads(payload_raw)
        except Exception:
            return {}
    if isinstance(payload_raw, dict):
        return payload_raw
    return {}


def _build_detections_from_events(conn, events: List[Any]) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []
    detection_cfg = _load_detection_config(conn)
    for row in events:
        try:
            event_id = row["id"]
            source = row["source"]
            event_type = row["type"]
            severity = row["severity"]
        except Exception:
            continue
        if not isinstance(event_type, str):
            continue
        if severity not in {"warn", "error", "bad", "med"} and not event_type.endswith("failed"):
            continue
        payload = _event_payload(row)
        summary = payload.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            summary = f"{event_type.replace('.', ' ')} detected"
        detection_type = f"{source}.{event_type}"
        signature = f"{detection_type}:{summary}"
        if not _should_emit_detection(conn, detection_type, signature, detection_cfg):
            continue
        detections.append(
            {
                "event_id": event_id,
                "source": source,
                "detection_type": detection_type,
                "severity": severity,
                "summary": summary,
                "details": {"event_type": event_type, "payload": payload},
                "signature": signature,
            }
        )
    return detections


def _build_proactive_detections(
    conn,
    ha_summary: Dict[str, Any],
    network_snapshot: Dict[str, Any],
) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []
    detection_cfg = _load_detection_config(conn)
    now = datetime.now(timezone.utc)

    pending = store.count_proposals_by_status(conn).get("pending", 0)
    if pending >= 5:
        summary = f"Proposal backlog ({pending} pending)"
        detection_type = "system.proactive.proposals"
        signature = f"{detection_type}:{pending}"
        if _should_emit_detection(conn, detection_type, signature, detection_cfg):
            detections.append(
                {
                    "event_id": None,
                    "source": "system",
                    "detection_type": detection_type,
                    "severity": "warn",
                    "summary": summary,
                    "details": {"pending_proposals": pending},
                    "signature": signature,
                }
            )

    alerts = _recent_alerts(conn)
    alert_counts = alerts.get("counts") or {}
    alert_total = sum(alert_counts.values()) if isinstance(alert_counts, dict) else 0
    if alert_total >= 1:
        summary = f"Active alerts ({alert_total} in last 6h)"
        detection_type = "system.proactive.alerts"
        signature = f"{detection_type}:{alert_total}"
        if _should_emit_detection(conn, detection_type, signature, detection_cfg):
            detections.append(
                {
                    "event_id": None,
                    "source": "system",
                    "detection_type": detection_type,
                    "severity": "warn",
                    "summary": summary,
                    "details": {"alert_counts": alert_counts, "last_alert_ts": alerts.get("last_ts")},
                    "signature": signature,
                }
            )

    last_scan = store.get_memory(conn, "network.discovery.last_ts")
    last_scan_dt = _normalize_ts(last_scan) if isinstance(last_scan, str) else None
    if last_scan_dt:
        age_seconds = (now - last_scan_dt).total_seconds()
        if age_seconds >= 1800:
            summary = "Network discovery stale"
            detection_type = "system.proactive.network_scan"
            signature = f"{detection_type}:{int(age_seconds // 60)}"
            if _should_emit_detection(conn, detection_type, signature, detection_cfg):
                detections.append(
                    {
                        "event_id": None,
                        "source": "system",
                        "detection_type": detection_type,
                        "severity": "warn",
                        "summary": summary,
                        "details": {"age_seconds": age_seconds},
                        "signature": signature,
                    }
                )

    people_home = ha_summary.get("people_home") or []
    if isinstance(people_home, list) and not people_home:
        summary = "House appears empty"
        detection_type = "system.proactive.empty_house"
        signature = detection_type
        if _should_emit_detection(conn, detection_type, signature, detection_cfg):
            detections.append(
                {
                    "event_id": None,
                    "source": "system",
                    "detection_type": detection_type,
                    "severity": "info",
                    "summary": summary,
                    "details": {"people_home": 0},
                    "signature": signature,
                }
            )

    return detections

def _allowlisted_action(policy: policy_mod.Policy, action_type: str, params: Dict[str, Any]) -> bool:
    allowlist = policy_mod.allowlist_for_action(policy, action_type)
    if not allowlist:
        return True
    if action_type == "system.restart_service":
        allowed = allowlist.get("services", [])
        return params.get("service") in allowed
    if action_type == "homeassistant.service":
        allowed = allowlist.get("domains", [])
        return params.get("domain") in allowed
    return True


def _notify_homeassistant(conn, title: str, message: str) -> None:
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return
    config = module_config.load_config(str(config_path))
    modules_cfg = config.get("modules", {}) if isinstance(config, dict) else {}
    ha_cfg = modules_cfg.get("homeassistant.observer", {}) if isinstance(modules_cfg, dict) else {}
    base_url = ha_cfg.get("base_url")
    token_env = ha_cfg.get("token_env", "PUMPKIN_HA_TOKEN")
    token = os.getenv(token_env)
    if not (isinstance(base_url, str) and base_url.strip() and token):
        return
    payload = {"title": title, "message": message, "notification_id": "pumpkin-core"}
    try:
        ha_client.call_service(base_url, token, "persistent_notification", "create", payload, 10)
    except Exception:
        return


def _apply_autonomous_action(
    conn,
    policy: policy_mod.Policy,
    action_type: str,
    action_params: Dict[str, Any],
    proposal_id: int | None,
) -> Dict[str, Any]:
    if not _allowlisted_action(policy, action_type, action_params):
        return {"status": "blocked", "reason": "not allowlisted"}
    action_id = store.insert_action(
        conn,
        proposal_id=proposal_id,
        action_type=action_type,
        params=action_params,
        status="started",
        policy_hash=policy.policy_hash,
    )
    try:
        result = execute_action(action_type, action_params, str(settings.audit_path()))
        store.finish_action(conn, action_id, "succeeded", result=result)
        verification_status = "verified" if result else "unknown"
        store.insert_outcome(conn, action_id, "succeeded", {"result": result})
        return {
            "status": "succeeded",
            "action_id": action_id,
            "result": result,
            "verification_status": verification_status,
        }
    except Exception as exc:
        store.finish_action(conn, action_id, "failed", result={"error": str(exc)})
        store.insert_outcome(conn, action_id, "failed", {"error": str(exc)})
        return {"status": "failed", "action_id": action_id, "error": str(exc)}


def _score_decision(
    detection: Dict[str, Any],
    action_type: str,
    lane: str,
    mode: str,
) -> Dict[str, Any]:
    severity = str(detection.get("severity") or "info").lower()
    base_risk = {"info": 0.2, "warn": 0.5, "warning": 0.5, "error": 0.6, "critical": 0.8}.get(
        severity, 0.4
    )
    lane_risk = {"A": -0.1, "B": 0.1, "C": 0.25}.get(lane, 0.0)
    mode_risk = {"OBSERVER": 0.0, "OPERATOR": 0.0, "STEWARD": 0.05}.get(mode, 0.0)
    risk = min(1.0, max(0.0, base_risk + lane_risk + mode_risk))

    details = detection.get("details") if isinstance(detection.get("details"), dict) else {}
    raw_confidence = details.get("confidence") or details.get("score")
    if isinstance(raw_confidence, (int, float)):
        confidence = min(1.0, max(0.0, float(raw_confidence)))
    else:
        confidence = {"info": 0.6, "warn": 0.7, "warning": 0.7, "error": 0.75, "critical": 0.8}.get(
            severity, 0.65
        )

    reversible_map = {
        "notify.local": 0.95,
        "notify.ha": 0.9,
        "homeassistant.service": 0.7,
        "homeassistant.script": 0.6,
        "network.discovery": 0.9,
        "code.apply_patch": 0.2,
        "ops.restart": 0.5,
    }
    reversibility = reversible_map.get(action_type, 0.5)

    return {
        "risk": round(risk, 2),
        "confidence": round(confidence, 2),
        "reversibility": round(reversibility, 2),
        "lane": lane,
        "mode": mode,
    }


def _build_reasoning(
    detection: Dict[str, Any],
    lane: str,
    mode: str,
    scores: Dict[str, Any],
    action_type: str,
) -> str:
    summary = detection.get("summary") or "detection"
    severity = detection.get("severity") or "info"
    details = detection.get("details") if isinstance(detection.get("details"), dict) else {}
    event_type = details.get("event_type")
    confidence = scores.get("confidence")
    risk = scores.get("risk")
    reversibility = scores.get("reversibility")
    parts = [
        f"Observed: {summary}.",
        f"Severity {severity}.",
    ]
    if event_type:
        parts.append(f"Signal: {event_type}.")
    parts.append(
        f"Policy lane {lane} in {mode} mode; action {action_type} (risk {risk}, confidence {confidence}, reversibility {reversibility})."
    )
    if lane == "C":
        parts.append("Opening restricted request for safety.")
    elif lane == "B":
        parts.append("Opening proposal for approval.")
    else:
        parts.append("Proceeding with low-risk action or proposal per mode.")
    return " ".join(parts)


def _process_detections(
    conn,
    policy: policy_mod.Policy,
    autonomy_cfg: Dict[str, Any],
    detections: List[Dict[str, Any]],
) -> int:
    mode = _autonomy_mode(conn, autonomy_cfg)
    auto_actions = 0
    for detection in detections:
        action_type = "notify.local"
        action_params = {
            "message": f"{detection['summary']} (severity {detection['severity']})"
        }
        lane = policy_mod.lane_for_action(policy, action_type)
        decision = f"{lane} action"
        reasoning = "Auto-summarized detection requires attention."
        proposal_id = None
        restricted_id = None
        action_id = None
        verification_status = None
        outcome = {}
        scores = _score_decision(detection, action_type, lane, mode)
        reasoning = _build_reasoning(detection, lane, mode, scores, action_type)

        detection_id = store.insert_detection(
            conn,
            detection["source"],
            detection["detection_type"],
            detection["severity"],
            detection["summary"],
            detection["details"],
            event_id=detection.get("event_id"),
        )
        _remember_detection(conn, detection["signature"])

        if lane == "C":
            restricted_id = store.insert_restricted_request(
                conn,
                summary=f"Restricted action needed: {detection['summary']}",
                details={
                    "rationale": reasoning,
                    "action_type": action_type,
                    "action_params": action_params,
                    "detection_id": detection_id,
                },
                risk=0.7,
                expected_outcome="Restricted request requires approval.",
                status="pending",
                policy_hash=policy.policy_hash,
            )
            decision = "Restricted request opened"
            _notify_homeassistant(conn, "Pumpkin restricted request", detection["summary"])
        elif lane == "B":
            proposal_id = store.insert_proposal(
                conn,
                kind="action.request",
                summary=f"Respond to detection: {detection['summary']}",
                details={
                    "rationale": reasoning,
                    "action_type": action_type,
                    "action_params": action_params,
                    "detection_id": detection_id,
                },
                risk=0.3,
                expected_outcome="Detection response executed.",
                status="pending",
                policy_hash=policy.policy_hash,
                needs_new_capability=False,
                capability_request=None,
            )
            decision = "Proposal opened"
            _notify_homeassistant(conn, "Pumpkin proposal", detection["summary"])
        else:
            if _should_auto_execute(mode, lane, autonomy_cfg):
                outcome = _apply_autonomous_action(
                    conn, policy, action_type, action_params, proposal_id
                )
                action_id = outcome.get("action_id")
                verification_status = outcome.get("verification_status")
                if action_id:
                    auto_actions += 1
                _notify_homeassistant(
                    conn,
                    "Pumpkin auto action",
                    f"{detection['summary']} → {outcome.get('status')}",
                )
            else:
                proposal_id = store.insert_proposal(
                    conn,
                    kind="action.request",
                    summary=f"Respond to detection: {detection['summary']}",
                    details={
                        "rationale": reasoning,
                        "action_type": action_type,
                        "action_params": action_params,
                        "detection_id": detection_id,
                    },
                    risk=0.2,
                    expected_outcome="Detection response executed.",
                    status="pending",
                    policy_hash=policy.policy_hash,
                    needs_new_capability=False,
                    capability_request=None,
                )
                decision = "Proposal opened"
                _notify_homeassistant(conn, "Pumpkin proposal", detection["summary"])

        store.insert_decision(
            conn,
            detection_id=detection_id,
            observation=detection["summary"],
            reasoning=reasoning,
            decision=decision,
            action_type=action_type,
            action_id=action_id,
            proposal_id=proposal_id,
            restricted_id=restricted_id,
            verification_status=verification_status,
            evidence={
                "scores": scores,
                "outcome": outcome if isinstance(outcome, dict) else {},
            },
        )
    return auto_actions


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


def _update_world_state(
    conn,
    system_snapshot: Dict[str, Any] | None,
    ha_summary: Dict[str, Any],
    network_snapshot: Dict[str, Any],
    inventory: Dict[str, Any],
    insights_list: List[Dict[str, Any]],
) -> None:
    state = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "system": system_snapshot or {},
        "homeassistant": ha_summary or {},
        "network": network_snapshot or {},
        "inventory": inventory or {},
        "insights": insights_list[:5],
    }
    digest = hashlib.sha256(
        json.dumps(state, sort_keys=True, ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    last_digest = store.get_memory(conn, "world.state_hash")
    if last_digest == digest:
        return
    store.set_memory(conn, "world.state_hash", digest)
    store.set_memory(conn, "world.state", state)
    audit.append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "world.state",
            "ts": state["ts"],
            "digest": digest,
        },
    )


def _auto_curate_ui(conn, network_snapshot: Dict[str, Any]) -> None:
    now = datetime.now(timezone.utc)
    since_ts = (now - timedelta(hours=24)).isoformat()
    hidden = store.get_memory(conn, "ui.hidden_cards") or []
    if not isinstance(hidden, list):
        hidden = []
    hidden_set = {str(item) for item in hidden}

    def count_events(event_type: str) -> int:
        try:
            return int(
                conn.execute(
                    "SELECT count(*) FROM events WHERE type = ? AND ts >= ?",
                    (event_type, since_ts),
                ).fetchone()[0]
            )
        except Exception:
            return 0

    def count_events_like(prefix: str) -> int:
        try:
            return int(
                conn.execute(
                    "SELECT count(*) FROM events WHERE type LIKE ? AND ts >= ?",
                    (prefix, since_ts),
                ).fetchone()[0]
            )
        except Exception:
            return 0

    proposals_pending = store.count_proposals_by_status(conn).get("pending", 0)
    alerts_recent = (
        count_events("face.alert")
        + count_events("behavior.alert")
        + count_events("car.alert")
    )
    network_devices = 0
    if isinstance(network_snapshot, dict):
        devices = network_snapshot.get("devices") or []
        if isinstance(devices, list):
            network_devices = len(devices)
    cameras = store.get_memory(conn, "camera.registry")
    camera_count = len(cameras) if isinstance(cameras, list) else 0
    insights_recent = count_events_like("insight.%")
    try:
        decisions_recent = int(
            conn.execute(
                "SELECT count(*) FROM decisions WHERE ts >= ?",
                (since_ts,),
            ).fetchone()[0]
        )
    except Exception:
        decisions_recent = 0
    try:
        briefings_recent = int(
            conn.execute(
                "SELECT count(*) FROM briefings WHERE ts >= ?",
                (since_ts,),
            ).fetchone()[0]
        )
    except Exception:
        briefings_recent = 0
    recordings_recent = count_events("camera.recorded")

    metrics = {
        "proposals": proposals_pending,
        "alerts": alerts_recent,
        "network": network_devices,
        "cameras": camera_count,
        "insights": insights_recent,
        "decisions": decisions_recent,
        "briefings": briefings_recent,
        "recordings": recordings_recent,
    }
    updated = set(hidden_set)
    for key, value in metrics.items():
        if value <= 0:
            updated.add(key)
        else:
            updated.discard(key)

    updated_list = sorted(updated)
    if set(updated_list) != hidden_set:
        store.set_memory(conn, "ui.hidden_cards", updated_list)
        store.set_memory(conn, "ui.curation.last_ts", now.isoformat())
        store.insert_event(
            conn,
            "system",
            "ui.curation",
            {
                "hidden_cards": updated_list,
                "metrics": metrics,
                "ts": now.isoformat(),
            },
            severity="info",
        )


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def _load_house_empty_cfg() -> Dict[str, Any]:
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return {}
    try:
        config = module_config.load_config(str(config_path))
    except Exception:
        return {}
    modules_cfg = config.get("modules", {}) if isinstance(config, dict) else {}
    if not isinstance(modules_cfg, dict):
        return {}
    cfg = modules_cfg.get("house.empty")
    if not isinstance(cfg, dict):
        cfg = modules_cfg.get("house_empty")
    return cfg if isinstance(cfg, dict) else {}


def _update_house_empty_mode(conn, ha_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    cfg = _load_house_empty_cfg()
    if not cfg or not cfg.get("enabled", False):
        return []
    people_home = ha_summary.get("people_home") if isinstance(ha_summary, dict) else []
    is_empty = not bool(people_home)
    target_state = "empty" if is_empty else "occupied"
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    state = store.get_memory(conn, "house.empty_state")
    if not isinstance(state, dict):
        state = {}
    current_state = state.get("state") if isinstance(state.get("state"), str) else "occupied"

    pending = store.get_memory(conn, "house.empty_pending")
    if not isinstance(pending, dict):
        pending = {}
    pending_state = pending.get("state")
    pending_since = _parse_ts(pending.get("since")) if isinstance(pending.get("since"), str) else None

    if current_state == target_state:
        if pending_state:
            store.set_memory(conn, "house.empty_pending", {})
        return []

    if pending_state != target_state or not pending_since:
        store.set_memory(conn, "house.empty_pending", {"state": target_state, "since": now_iso})
        return []

    min_key = "min_empty_minutes" if target_state == "empty" else "min_occupied_minutes"
    try:
        min_minutes = int(cfg.get(min_key, 5 if target_state == "empty" else 2))
    except (TypeError, ValueError):
        min_minutes = 5 if target_state == "empty" else 2
    if (now - pending_since).total_seconds() < min_minutes * 60:
        return []

    store.set_memory(
        conn,
        "house.empty_state",
        {
            "state": target_state,
            "since": now_iso,
            "people_home": list(people_home) if isinstance(people_home, list) else [],
        },
    )
    store.set_memory(conn, "house.empty_pending", {})

    event_type = "house.empty_mode" if target_state == "empty" else "house.occupied_mode"
    payload = {
        "state": target_state,
        "since": now_iso,
        "people_home": list(people_home) if isinstance(people_home, list) else [],
    }
    return [
        {
            "source": "house",
            "type": event_type,
            "payload": payload,
            "severity": "info",
        }
    ]


def _load_events_since_last(conn) -> List[Any]:
    last_id = store.get_memory(conn, "core.last_event_id")
    if last_id is None:
        last_id = 0
    events = store.fetch_events_since(conn, int(last_id))
    if events:
        store.set_memory(conn, "core.last_event_id", events[-1]["id"])
    return events


def _requeue_orphaned_suggestions(conn, policy_hash: str) -> None:
    if propose.planner_cooldown_active(conn):
        return
    rows = conn.execute(
        """
        SELECT id, details_json FROM proposals
        WHERE status = 'executed'
          AND kind = 'action.request'
          AND json_extract(details_json, '$.suggestion') IS NOT NULL
          AND json_extract(details_json, '$.converted_followup_id') IS NULL
        ORDER BY ts_created DESC
        LIMIT 5
        """
    ).fetchall()
    if not rows:
        return
    now = datetime.now(timezone.utc).isoformat()
    for row in rows:
        proposal_id = row["id"]
        details = json.loads(row["details_json"])
        requeue_count = int(details.get("requeue_count", 0))
        if requeue_count >= 3:
            continue
        details["requeue_count"] = requeue_count + 1
        details["requeued_at"] = now
        store.update_proposal_details(conn, proposal_id, details)
        store.update_proposal_status(conn, proposal_id, "approved")
        audit.append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "proposal.requeued",
                "proposal_id": proposal_id,
                "requeue_count": details["requeue_count"],
                "policy_hash": policy_hash,
            },
        )


def _create_heartbeat(conn, policy_hash: str) -> None:
    store.insert_event(
        conn,
        source="core",
        event_type="heartbeat",
        payload={"policy_hash": policy_hash},
        severity="info",
    )
    store.insert_heartbeat(conn, policy_hash, details={"source": "core"})


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
    last_ts = store.get_memory(conn, "core.last_reflection_ts")
    if isinstance(last_ts, str):
        try:
            parsed = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
            if (datetime.now(timezone.utc) - parsed).total_seconds() < 6 * 3600:
                return False
        except Exception:
            pass
    return _in_quiet_hours(conn)


def _load_snoozed_summaries(conn, days: int = 30) -> set[str]:
    entries = store.get_memory(conn, "proposal.snoozed")
    if not isinstance(entries, list):
        return set()
    cutoff = datetime.now(timezone.utc).timestamp() - (days * 86400)
    kept: List[Dict[str, Any]] = []
    summaries: set[str] = set()
    for item in entries:
        if not isinstance(item, dict):
            continue
        summary = item.get("summary")
        ts = item.get("ts")
        if not isinstance(summary, str) or not summary.strip():
            continue
        try:
            ts_val = datetime.fromisoformat(str(ts)).timestamp()
        except Exception:
            ts_val = cutoff
        if ts_val < cutoff:
            continue
        summaries.add(summary)
        kept.append({"summary": summary, "ts": ts})
    if kept != entries:
        store.set_memory(conn, "proposal.snoozed", kept[-500:])
    return summaries


def _record_proposals(conn, policy: policy_mod.Policy, proposals: List[Dict[str, Any]]) -> None:
    module_install_ids: Dict[str, int] = {}
    ordered = sorted(
        proposals, key=lambda p: 0 if p.get("kind") == "module.install" else 1
    )
    autonomy_cfg = _load_autonomy_config(conn)
    try:
        snooze_days = int(autonomy_cfg.get("proposal_snooze_days", 30))
    except (TypeError, ValueError):
        snooze_days = 30
    snoozed = _load_snoozed_summaries(conn, days=snooze_days)
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
        if summary in snoozed:
            audit.append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "proposal.skipped_snoozed",
                    "summary": summary,
                },
            )
            continue
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


def _execute_approved(conn, policy: policy_mod.Policy, autonomy_cfg: Dict[str, Any]) -> int:
    executed_count = 0
    approved = store.fetch_approved_unexecuted(conn)
    queue = store.get_memory(conn, "approvals.queue") or []
    if not isinstance(queue, list):
        queue = []
    queue_ids = []
    for item in queue:
        if isinstance(item, dict) and isinstance(item.get("id"), int):
            queue_ids.append(item["id"])
    updated_queue = list(queue_ids)
    if queue_ids:
        order = {pid: idx for idx, pid in enumerate(queue_ids)}
        approved = sorted(
            approved,
            key=lambda row: order.get(row["id"], len(order)),
        )
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
    try:
        max_actions = int(autonomy_cfg.get("max_actions_per_loop", 3))
    except (TypeError, ValueError):
        max_actions = 3
    action_cooldowns = autonomy_cfg.get("action_cooldowns_seconds") or {}
    if not isinstance(action_cooldowns, dict):
        action_cooldowns = {}
    try:
        default_cooldown = int(autonomy_cfg.get("default_action_cooldown_seconds", 0))
    except (TypeError, ValueError):
        default_cooldown = 0

    for row in approved:
        if executed_count >= max_actions:
            audit.append_jsonl(
                str(settings.audit_path()),
                {
                    "kind": "action.loop_limit_reached",
                    "max_actions": max_actions,
                    "skipped_count": max(0, len(approved) - executed_count),
                    "policy_hash": policy.policy_hash,
                },
            )
            break
        proposal_id = row["id"]
        details = json.loads(row["details_json"])
        action_type = details.get("action_type")
        action_params = details.get("action_params", {})
        rollback_type = details.get("rollback_action_type")
        rollback_params = details.get("rollback_action_params")
        verify_url = details.get("verify_url")
        force_execute = bool(details.get("force_execute"))

        if not action_type:
            suggestion = details.get("suggestion")
            if suggestion and propose.planner_cooldown_active(conn):
                cooldown_until = propose.planner_cooldown_until(conn)
                if cooldown_until:
                    details["deferred_until"] = cooldown_until.isoformat()
                    store.update_proposal_details(conn, proposal_id, details)
                audit.append_jsonl(
                    str(settings.audit_path()),
                    {
                        "kind": "proposal.deferred",
                        "proposal_id": proposal_id,
                        "reason": "planner_cooldown_active",
                        "cooldown_until": cooldown_until.isoformat() if cooldown_until else None,
                        "policy_hash": policy.policy_hash,
                    },
                )
                continue
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
                details["converted_followup_id"] = new_id
                store.update_proposal_details(conn, proposal_id, details)
                store.update_proposal_status(conn, proposal_id, "executed")
                if proposal_id in updated_queue:
                    updated_queue.remove(proposal_id)
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
            if isinstance(suggestion, str) and suggestion:
                details["conversion_failed"] = "planner_followup_unavailable"
                store.update_proposal_details(conn, proposal_id, details)
            store.update_proposal_status(conn, proposal_id, "failed")
            if proposal_id in updated_queue:
                updated_queue.remove(proposal_id)
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

        if not _ensure_execution_plan(conn, policy, row):
            continue

        cooldown_seconds = 0
        if action_type in action_cooldowns:
            try:
                cooldown_seconds = int(action_cooldowns.get(action_type, 0))
            except (TypeError, ValueError):
                cooldown_seconds = 0
        elif default_cooldown:
            cooldown_seconds = default_cooldown
        if force_execute:
            cooldown_seconds = 0
        if cooldown_seconds > 0:
            cooldown_key = f"action.cooldown:{action_type}"
            if not _cooldown_elapsed(conn, cooldown_key, cooldown_seconds):
                audit.append_jsonl(
                    str(settings.audit_path()),
                    {
                        "kind": "action.skipped_cooldown",
                        "proposal_id": proposal_id,
                        "action_type": action_type,
                        "cooldown_seconds": cooldown_seconds,
                        "policy_hash": policy.policy_hash,
                    },
                )
                _append_recent_memory(
                    conn,
                    "actions.recent",
                    {
                        "ts": datetime.now().isoformat(),
                        "proposal_id": proposal_id,
                        "action_type": action_type,
                        "status": "skipped_cooldown",
                    },
                )
                continue

        try:
            decision = policy_mod.evaluate_action(
                policy, action_type, action_params, risk=row["risk"]
            )
        except Exception as exc:
            store.update_proposal_status(conn, proposal_id, "failed")
            if proposal_id in updated_queue:
                updated_queue.remove(proposal_id)
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
            if proposal_id in updated_queue:
                updated_queue.remove(proposal_id)
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
            store.insert_outcome(conn, action_id, "succeeded", {"result": result})
            store.update_proposal_status(conn, proposal_id, "executed")
            if proposal_id in updated_queue:
                updated_queue.remove(proposal_id)
            if force_execute:
                details.pop("force_execute", None)
                store.update_proposal_details(conn, proposal_id, details)
            _record_action_summary(conn, action_type, "succeeded", proposal_id)
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
            if verify_url:
                verify = act.verify_health(str(verify_url))
                if not verify.get("ok"):
                    audit.append_jsonl(
                        str(settings.audit_path()),
                        {
                            "kind": "action.verify_failed",
                            "action_id": action_id,
                            "proposal_id": proposal_id,
                            "action_type": action_type,
                            "error": verify,
                            "policy_hash": policy.policy_hash,
                        },
                    )
                    raise RuntimeError(f"verification_failed: {verify}")
                audit.append_jsonl(
                    str(settings.audit_path()),
                    {
                        "kind": "action.verify_succeeded",
                        "action_id": action_id,
                        "proposal_id": proposal_id,
                        "action_type": action_type,
                        "policy_hash": policy.policy_hash,
                    },
                )
            if cooldown_seconds > 0:
                _record_cooldown(conn, f"action.cooldown:{action_type}")
                audit.append_jsonl(
                    str(settings.audit_path()),
                    {
                        "kind": "action.cooldown_set",
                        "action_id": action_id,
                        "proposal_id": proposal_id,
                        "action_type": action_type,
                        "cooldown_seconds": cooldown_seconds,
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
            executed_count += 1
        except Exception as exc:
            if isinstance(exc, PatchApplyError):
                result = dict(exc.details)
                result["error_message"] = str(exc)
            else:
                result = {"error": str(exc)}
            store.finish_action(conn, action_id, "failed", result=result)
            store.insert_outcome(conn, action_id, "failed", result)
            store.update_proposal_status(conn, proposal_id, "failed")
            if proposal_id in updated_queue:
                updated_queue.remove(proposal_id)
            if force_execute:
                details.pop("force_execute", None)
                store.update_proposal_details(conn, proposal_id, details)
            _record_action_summary(conn, action_type, "failed", proposal_id, detail="error")
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
            if rollback_type and isinstance(rollback_type, str) and isinstance(rollback_params, dict):
                try:
                    decision = policy_mod.evaluate_action(
                        policy, rollback_type, rollback_params, risk=0.1
                    )
                except Exception as rollback_exc:
                    audit.append_jsonl(
                        str(settings.audit_path()),
                        {
                            "kind": "action.rollback_failed",
                            "proposal_id": proposal_id,
                            "action_type": rollback_type,
                            "error": f"policy_validation_failed: {rollback_exc}",
                            "policy_hash": policy.policy_hash,
                        },
                    )
                    continue
                if decision == "forbid":
                    audit.append_jsonl(
                        str(settings.audit_path()),
                        {
                            "kind": "action.rollback_blocked",
                            "proposal_id": proposal_id,
                            "action_type": rollback_type,
                            "policy_hash": policy.policy_hash,
                        },
                    )
                else:
                    rollback_action_id = store.insert_action(
                        conn,
                        proposal_id=proposal_id,
                        action_type=rollback_type,
                        params=rollback_params,
                        status="started",
                        policy_hash=policy.policy_hash,
                    )
                    try:
                        rollback_result = execute_action(
                            rollback_type, rollback_params, str(settings.audit_path())
                        )
                        store.finish_action(
                            conn, rollback_action_id, "succeeded", result=rollback_result
                        )
                        audit.append_jsonl(
                            str(settings.audit_path()),
                            {
                                "kind": "action.rollback_succeeded",
                                "proposal_id": proposal_id,
                                "action_id": rollback_action_id,
                                "action_type": rollback_type,
                                "policy_hash": policy.policy_hash,
                            },
                        )
                    except Exception as rollback_exc:
                        store.finish_action(
                            conn,
                            rollback_action_id,
                            "failed",
                            result={"error": str(rollback_exc)},
                        )
                        audit.append_jsonl(
                            str(settings.audit_path()),
                            {
                                "kind": "action.rollback_failed",
                                "proposal_id": proposal_id,
                                "action_id": rollback_action_id,
                                "action_type": rollback_type,
                                "error": str(rollback_exc),
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
            executed_count += 1
    if updated_queue != queue_ids:
        store.set_memory(
            conn,
            "approvals.queue",
            [{"id": pid, "ts": None} for pid in updated_queue][-200:],
        )
    return executed_count


def run_once() -> Dict[str, Any]:
    conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
    policy = policy_mod.load_policy(str(settings.policy_path()))
    _record_policy_snapshot_if_changed(conn, policy)
    _seed_bootstrap(conn)
    _ensure_goals(conn)

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
    house_events = _update_house_empty_mode(conn, ha_summary if isinstance(ha_summary, dict) else {})
    if house_events:
        _insert_events(conn, house_events)
    insight_items = insights.build_insights(
        system_snapshot=system_snapshot,
        ha_entities=ha_entities if isinstance(ha_entities, dict) else {},
        ha_summary=ha_summary if isinstance(ha_summary, dict) else {},
        prev_entities=prev_entities if isinstance(prev_entities, dict) else {},
        network_snapshot=network_snapshot if isinstance(network_snapshot, dict) else {},
        prev_network_snapshot=prev_network if isinstance(prev_network, dict) else {},
    )
    insight_items = insights.filter_recent_insights(conn, insight_items)
    insights.record_insights(conn, insight_items)
    new_events = _load_events_since_last(conn)
    event_insights = insights.build_event_insights(new_events)
    event_insights = insights.filter_recent_insights(conn, event_insights)
    insights.record_insights(conn, event_insights)
    all_insights = list(insight_items) + list(event_insights)
    inventory_snapshot = inventory_mod.snapshot(conn)
    _update_world_state(
        conn,
        system_snapshot=system_snapshot,
        ha_summary=ha_summary if isinstance(ha_summary, dict) else {},
        network_snapshot=network_snapshot if isinstance(network_snapshot, dict) else {},
        inventory=inventory_snapshot if isinstance(inventory_snapshot, dict) else {},
        insights_list=all_insights,
    )
    _auto_curate_ui(conn, network_snapshot if isinstance(network_snapshot, dict) else {})
    _update_awareness_snapshot(
        conn,
        ha_summary if isinstance(ha_summary, dict) else {},
        network_snapshot if isinstance(network_snapshot, dict) else {},
    )
    brief_times = insights.briefing_times()
    for idx, briefing_time in enumerate(brief_times):
        insights.maybe_daily_briefing(
            conn,
            ha_summary=ha_summary if isinstance(ha_summary, dict) else {},
            system_snapshot=system_snapshot,
            insights=all_insights,
            in_quiet_hours=_in_quiet_hours(conn),
            briefing_time=briefing_time,
            briefing_key=f"daily-{idx}",
        )
    insights.maybe_event_briefing(
        conn,
        ha_summary=ha_summary if isinstance(ha_summary, dict) else {},
        system_snapshot=system_snapshot,
        insights=all_insights,
        in_quiet_hours=_in_quiet_hours(conn),
    )
    _maybe_hourly_briefing(
        conn,
        ha_summary=ha_summary if isinstance(ha_summary, dict) else {},
        system_snapshot=system_snapshot,
        insights_list=all_insights,
    )
    proposals = propose.build_proposals(new_events, conn)
    if _should_reflect(conn):
        improvement = propose.build_improvement_proposals(conn)
        if improvement:
            proposals.extend(improvement)
        store.set_memory(conn, "core.last_reflection_ts", datetime.now(timezone.utc).isoformat())
    _record_proposals(conn, policy, proposals)
    _update_shopping_list(conn)
    autonomy_cfg = _load_autonomy_config(conn)
    try:
        pulse_interval = int(autonomy_cfg.get("pulse_interval_seconds", 60))
    except (TypeError, ValueError):
        pulse_interval = 60
    _record_pulse(
        conn,
        ha_summary if isinstance(ha_summary, dict) else {},
        network_snapshot if isinstance(network_snapshot, dict) else {},
        len(proposals),
        pulse_interval,
    )

    _append_recent_memory(
        conn,
        "loop.events",
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "new_events": len(new_events),
            "detections": len(detections),
            "auto_actions": auto_actions,
            "pending_proposals": len(proposals),
        },
        limit=60,
    )

    now = time.time()
    last_selfcheck = store.get_memory(conn, "selfcheck.last_ts") or 0
    try:
        last_selfcheck = float(last_selfcheck)
    except (TypeError, ValueError):
        last_selfcheck = 0.0
    if now - last_selfcheck >= settings.selfcheck_interval_seconds():
        selfcheck.run_self_check(conn)
        store.set_memory(conn, "selfcheck.last_ts", now)

    detections = _build_detections_from_events(conn, new_events)
    detections.extend(
        _build_proactive_detections(
            conn,
            ha_summary if isinstance(ha_summary, dict) else {},
            network_snapshot if isinstance(network_snapshot, dict) else {},
        )
    )
    auto_actions = _process_detections(conn, policy, autonomy_cfg, detections)

    _requeue_orphaned_suggestions(conn, policy.policy_hash)
    _cleanup_confirm_plan_proposals(conn, autonomy_cfg)
    _auto_approve_pending_repaired_patches(conn, autonomy_cfg)
    executed_actions = _execute_approved(conn, policy, autonomy_cfg)
    _watchdog_stalled_actions(conn, policy, autonomy_cfg)
    _repair_failed_patches(conn)
    total_executed = store.get_memory(conn, "actions.total_executed") or 0
    try:
        total_executed = int(total_executed)
    except (TypeError, ValueError):
        total_executed = 0
    if executed_actions or auto_actions:
        store.set_memory(conn, "actions.last_executed_ts", datetime.now().isoformat())
    store.set_memory(conn, "actions.last_executed_count", executed_actions + auto_actions)
    store.set_memory(conn, "actions.total_executed", total_executed + executed_actions + auto_actions)
    return {
        "new_event_count": len(new_events),
        "executed_actions": executed_actions + auto_actions,
    }


def run_forever(interval: float) -> None:
    while True:
        info = run_once()
        new_events = info.get("new_event_count", 0) if isinstance(info, dict) else 0
        sleep_seconds = 1.0 if new_events else interval
        time.sleep(sleep_seconds)
