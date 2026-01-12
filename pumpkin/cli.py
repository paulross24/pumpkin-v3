"""Command-line interface for Pumpkin v3."""

from __future__ import annotations

import argparse
import json
import getpass
import os
import socket
from typing import Any, Tuple

from . import core
from . import policy as policy_mod
from . import policy_change
from . import settings
from . import store
from . import propose
from .audit import append_jsonl
from . import module_registry
from pathlib import Path
from . import runbook
from . import module_config_change
from . import module_config
from . import voice_server
from . import act
from .db import init_db


def _conn():
    return init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))


def cmd_status(_: argparse.Namespace) -> None:
    conn = _conn()
    print("Pumpkin v3 status")
    print(f"  db: {settings.db_path()}")
    print(f"  policy: {settings.policy_path()}")
    try:
        conn.execute("SELECT 1").fetchone()
        print("  db reachable: yes")
    except Exception:
        print("  db reachable: no")

    heartbeat = store.latest_heartbeat(conn)
    if heartbeat:
        print(f"  last heartbeat: {heartbeat['ts']}")
    else:
        print("  last heartbeat: none")

    try:
        cfg = module_config.load_config(str(settings.modules_config_path()))
        enabled = cfg.get("enabled", [])
        print(f"  enabled modules: {', '.join(enabled) if enabled else 'none'}")
    except Exception:
        print("  enabled modules: unavailable")

    ha_row = conn.execute(
        "SELECT type, ts FROM events WHERE source = 'homeassistant' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if ha_row:
        status_map = {
            "homeassistant.status": "ok",
            "homeassistant.request_failed": "error",
            "homeassistant.token_missing": "missing token",
            "homeassistant.misconfigured": "misconfigured",
        }
        status = status_map.get(ha_row["type"], ha_row["type"])
        print(f"  last HA ingest: {status} ({ha_row['ts']})")
    else:
        print("  last HA ingest: none")

    try:
        import socket

        sock = socket.create_connection(("127.0.0.1", settings.voice_server_port()), timeout=1)
        sock.close()
        print("  voice server reachable: yes")
    except Exception:
        print("  voice server reachable: no")

    counts = store.count_proposals_by_status(conn)
    if counts:
        for status, count in counts.items():
            print(f"  proposals {status}: {count}")
    else:
        print("  proposals: none")


def cmd_proposals_list(args: argparse.Namespace) -> None:
    conn = _conn()
    rows = store.list_proposals(conn, status=args.status)
    for row in rows:
        print(
            f"{row['id']} {row['status']} kind={row['kind']} risk={row['risk']:.2f} {row['summary']} ({row['ts_created']})"
        )


def cmd_proposals_show(args: argparse.Namespace) -> None:
    conn = _conn()
    row = store.get_proposal(conn, args.proposal_id)
    if not row:
        print("proposal not found")
        return
    print(f"id: {row['id']}")
    print(f"status: {row['status']}")
    print(f"kind: {row['kind']}")
    print(f"risk: {row['risk']}")
    print(f"summary: {row['summary']}")
    print(f"expected_outcome: {row['expected_outcome']}")
    print(f"policy_hash: {row['policy_hash']}")
    print(f"needs_new_capability: {bool(row['needs_new_capability'])}")
    print(f"capability_request: {row['capability_request']}")
    print(f"ai_context_hash: {row['ai_context_hash']}")
    print("details:")
    print(json.dumps(json.loads(row["details_json"]), indent=2))
    events = store.get_proposal_events(conn, args.proposal_id)
    if events:
        print("source events:")
        for event in events:
            print(f"  {event['id']} {event['type']} {event['ts']}")


def cmd_proposals_approve(args: argparse.Namespace) -> None:
    conn = _conn()
    policy = policy_mod.load_policy(str(settings.policy_path()))
    actor = args.actor or getpass.getuser()
    store.insert_approval(
        conn,
        proposal_id=args.proposal_id,
        actor=actor,
        decision="approve",
        reason=args.reason,
        policy_hash=policy.policy_hash,
    )
    store.update_proposal_status(conn, args.proposal_id, "approved")
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "approval.recorded",
            "proposal_id": args.proposal_id,
            "decision": "approve",
            "actor": actor,
            "policy_hash": policy.policy_hash,
        },
    )
    print(f"approved proposal {args.proposal_id}")


def cmd_proposals_reject(args: argparse.Namespace) -> None:
    conn = _conn()
    policy = policy_mod.load_policy(str(settings.policy_path()))
    actor = args.actor or getpass.getuser()
    store.insert_approval(
        conn,
        proposal_id=args.proposal_id,
        actor=actor,
        decision="reject",
        reason=args.reason,
        policy_hash=policy.policy_hash,
    )
    store.update_proposal_status(conn, args.proposal_id, "rejected")
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "approval.recorded",
            "proposal_id": args.proposal_id,
            "decision": "reject",
            "actor": actor,
            "policy_hash": policy.policy_hash,
        },
    )
    print(f"rejected proposal {args.proposal_id}")


def cmd_observe_add(args: argparse.Namespace) -> None:
    conn = _conn()
    payload = {"message": args.message}
    event_id = store.insert_event(
        conn,
        source="manual",
        event_type=f"manual.{args.type}",
        payload=payload,
        severity=args.severity,
    )
    print(f"recorded event {event_id}")


def cmd_daemon(args: argparse.Namespace) -> None:
    interval = args.interval or settings.loop_interval_seconds()
    if args.once:
        core.run_once()
    else:
        core.run_forever(interval)


def _redact_sensitive(data: Any) -> Any:
    if isinstance(data, dict):
        redacted = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            if key_lower in {"secret", "token", "password", "api_key", "access_token"} or key_lower.endswith(
                "_secret"
            ):
                redacted[key] = "<redacted>"
            else:
                redacted[key] = _redact_sensitive(value)
        return redacted
    if isinstance(data, list):
        return [_redact_sensitive(item) for item in data]
    return data


def cmd_planner_context(args: argparse.Namespace) -> None:
    conn = _conn()
    context_pack, _, _ = propose.build_context_pack(conn, event_limit=args.events)
    context_pack = _redact_sensitive(context_pack)
    output = json.dumps(context_pack, indent=2, ensure_ascii=True)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output + "\n")
        print(f"wrote context pack to {args.output}")
    else:
        print(output)


def cmd_planner_replay(args: argparse.Namespace) -> None:
    with open(args.context, "r", encoding="utf-8") as f:
        context_pack = json.load(f)
    try:
        proposals = propose.replay_context_pack(context_pack)
        print(json.dumps({"valid": True, "proposals": proposals}, indent=2))
    except Exception as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, indent=2))


def cmd_policy_current(_: argparse.Namespace) -> None:
    policy = policy_mod.load_policy(str(settings.policy_path()))
    text = settings.policy_path().read_text(encoding="utf-8")
    print(f"path: {settings.policy_path()}")
    print(f"policy_hash: {policy.policy_hash}")
    print(text.rstrip())


def _load_policy_proposal(conn, proposal_id: int) -> dict:
    row = store.get_proposal(conn, proposal_id)
    if not row:
        raise ValueError("proposal not found")
    if row["kind"] != "policy.change":
        raise ValueError("proposal kind is not policy.change")
    details = json.loads(row["details_json"])
    proposed_yaml = details.get("proposed_policy_yaml")
    if not isinstance(proposed_yaml, str):
        raise ValueError("proposal details must include proposed_policy_yaml")
    return {"row": row, "details": details, "proposed_yaml": proposed_yaml}


def cmd_policy_diff(args: argparse.Namespace) -> None:
    conn = _conn()
    current_text = settings.policy_path().read_text(encoding="utf-8")
    proposal = _load_policy_proposal(conn, args.proposal)
    diff = policy_change.policy_diff(current_text, proposal["proposed_yaml"])
    print(diff.rstrip() if diff else "no diff")


def cmd_policy_apply(args: argparse.Namespace) -> None:
    conn = _conn()
    try:
        proposal = _load_policy_proposal(conn, args.proposal)
        row = proposal["row"]
        details = proposal["details"]
        proposed_yaml = proposal["proposed_yaml"]
    except ValueError as exc:
        print(str(exc))
        return

    if not store.approval_exists(conn, row["id"], "approve") or row["status"] != "approved":
        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "policy.apply_blocked",
                "proposal_id": row["id"],
                "reason": "proposal not approved",
                "actor": args.actor,
            },
        )
        print("proposal is not approved")
        return

    current_text = settings.policy_path().read_text(encoding="utf-8")
    lint_errors = policy_change.lint_policy_change(current_text, proposed_yaml, details)
    if lint_errors:
        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "policy.apply_blocked",
                "proposal_id": row["id"],
                "reason": "lint_failed",
                "errors": lint_errors,
                "actor": args.actor,
            },
        )
        print("policy lint failed: " + "; ".join(lint_errors))
        return

    old_hash, new_hash, diff_hash, backup_path, diff_text = policy_change.apply_policy_change(
        str(settings.policy_path()), proposed_yaml
    )
    policy = policy_mod.load_policy(str(settings.policy_path()))
    policy_mod.record_policy_snapshot(conn, policy)
    store.update_proposal_status(conn, row["id"], "executed")

    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "policy.applied",
            "proposal_id": row["id"],
            "actor": args.actor,
            "reason": args.reason,
            "old_hash": old_hash,
            "new_hash": new_hash,
            "diff_hash": diff_hash,
            "backup_path": backup_path,
        },
    )
    print(f"policy applied. backup: {backup_path}")


def cmd_policy_preview(args: argparse.Namespace) -> None:
    conn = _conn()
    proposal = _load_policy_proposal(conn, args.proposal)
    details = proposal["details"]
    proposed_yaml = proposal["proposed_yaml"]
    current_text = settings.policy_path().read_text(encoding="utf-8")
    diff = policy_change.policy_diff(current_text, proposed_yaml)
    lint_errors = policy_change.lint_policy_change(current_text, proposed_yaml, details)
    summary = policy_change.summarize_change(current_text, proposed_yaml)
    print("diff:")
    print(diff.rstrip() if diff else "no diff")
    print("\nlint:")
    if lint_errors:
        for error in lint_errors:
            print(f"- {error}")
    else:
        print("ok")
    print("\nsummary:")
    print(json.dumps(summary, indent=2, ensure_ascii=True))


def cmd_policy_rollback(args: argparse.Namespace) -> None:
    conn = _conn()
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "policy.rollback_started",
            "backup_path": args.backup,
            "actor": args.actor,
            "reason": args.reason,
        },
    )
    try:
        proposal_id = policy_change.find_proposal_for_backup(
            str(settings.audit_path()), args.backup
        )
        row = store.get_proposal(conn, proposal_id)
        if not row:
            raise ValueError("proposal not found for backup")
        if row["kind"] != "policy.change":
            raise ValueError("linked proposal is not policy.change")
        if not store.approval_exists(conn, row["id"], "approve"):
            raise ValueError("proposal not approved")
        details = json.loads(row["details_json"])

        current_text = settings.policy_path().read_text(encoding="utf-8")
        backup_text = Path(args.backup).read_text(encoding="utf-8")
        lint_errors = policy_change.lint_policy_change(current_text, backup_text, details)
        if lint_errors:
            raise ValueError("policy lint failed: " + "; ".join(lint_errors))

        old_hash, new_hash, diff_hash, rollback_backup, diff_text = (
            policy_change.rollback_policy_change(str(settings.policy_path()), args.backup)
        )
        policy = policy_mod.load_policy(str(settings.policy_path()))
        policy_mod.record_policy_snapshot(conn, policy)

        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "policy.rolled_back",
                "proposal_id": row["id"],
                "actor": args.actor,
                "reason": args.reason,
                "old_hash": old_hash,
                "new_hash": new_hash,
                "diff_hash": diff_hash,
                "backup_path": args.backup,
                "rollback_backup_path": rollback_backup,
            },
        )
        print(f"policy rolled back. backup: {rollback_backup}")
    except Exception as exc:
        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "policy.rollback_blocked",
                "backup_path": args.backup,
                "actor": args.actor,
                "reason": str(exc),
            },
        )
        print(f"rollback blocked: {exc}")


def cmd_modules_list(_: argparse.Namespace) -> None:
    registry = module_registry.load_registry(str(settings.modules_registry_path()))
    for module in registry.get("modules", []):
        print(
            f"{module.get('name')} ({module.get('type')}) safety={module.get('safety_level')}"
        )


def cmd_modules_show(args: argparse.Namespace) -> None:
    registry = module_registry.load_registry(str(settings.modules_registry_path()))
    module = module_registry.find_module(registry, args.name)
    print(json.dumps(module, indent=2, ensure_ascii=True))


def cmd_modules_suggest(args: argparse.Namespace) -> None:
    conn = _conn()
    registry = module_registry.load_registry(str(settings.modules_registry_path()))
    module = module_registry.find_module(registry, args.name)
    config = json.loads(args.config) if args.config else {}
    details = {
        "module_name": module.get("name"),
        "rationale": args.reason,
        "config": config,
        "safety_level": module.get("safety_level"),
        "prerequisites": module.get("prerequisites", {}),
        "rollback_plan": args.rollback_plan,
    }
    module_registry.validate_module_install_details(registry, details)
    proposal_id = store.insert_proposal(
        conn,
        kind="module.install",
        summary=f"Install module {module.get('name')}",
        details=details,
        steps=["Review module install", "Apply installation plan"],
        risk=0.4,
        expected_outcome="Module installation is reviewed by human.",
        status="pending",
        policy_hash=policy_mod.load_policy(str(settings.policy_path())).policy_hash,
    )
    print(f"created proposal {proposal_id}")


def cmd_modules_lint_proposal(args: argparse.Namespace) -> None:
    conn = _conn()
    row = store.get_proposal(conn, args.proposal_id)
    if not row:
        print("proposal not found")
        return
    if row["kind"] != "module.install":
        print("proposal kind is not module.install")
        return
    details = json.loads(row["details_json"])
    registry = module_registry.load_registry(str(settings.modules_registry_path()))
    try:
        module_registry.validate_module_install_details(registry, details)
        print("ok")
    except Exception as exc:
        print(f"invalid: {exc}")


def cmd_modules_runbook(args: argparse.Namespace) -> None:
    conn = _conn()
    row = store.get_proposal(conn, args.proposal_id)
    if not row:
        print("proposal not found")
        return
    if row["kind"] != "module.install":
        print("proposal kind is not module.install")
        return
    details = json.loads(row["details_json"])
    registry = module_registry.load_registry(str(settings.modules_registry_path()))
    module = module_registry.find_module(registry, details.get("module_name"))
    runbook_data = runbook.generate_runbook(details, module)
    if args.format == "json":
        output = json.dumps(runbook_data, indent=2, ensure_ascii=True)
        runbook_entry = {"format": "json", "content": runbook_data, "generated_at": runbook_data["generated_at"]}
    else:
        output = runbook.runbook_markdown(runbook_data)
        runbook_entry = {"format": "md", "content": output, "generated_at": runbook_data["generated_at"]}
    details["runbook"] = runbook_entry
    store.update_proposal_details(conn, row["id"], details)
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "runbook.generated",
            "proposal_id": row["id"],
            "module_name": details.get("module_name"),
            "format": args.format,
        },
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output + "\n")
        print(f"wrote runbook to {args.output}")
    else:
        print(output)


def cmd_modules_verify_prereqs(args: argparse.Namespace) -> None:
    conn = _conn()
    row = store.get_proposal(conn, args.proposal_id)
    if not row:
        print("proposal not found")
        return
    if row["kind"] != "module.install":
        print("proposal kind is not module.install")
        return
    details = json.loads(row["details_json"])
    if details.get("module_name") == "homeassistant.observer" and not os.getenv("PUMPKIN_HA_TOKEN"):
        results = {
            "checks": [
                {"check": "env", "name": "PUMPKIN_HA_TOKEN", "status": "missing"}
            ],
            "summary": "missing token",
        }
        print(json.dumps(results, indent=2, ensure_ascii=True))
        return
    results = runbook.verify_prereqs(details)
    print(json.dumps(results, indent=2, ensure_ascii=True))


def cmd_modules_config_show(_: argparse.Namespace) -> None:
    path = settings.modules_config_path()
    text = path.read_text(encoding="utf-8")
    config_hash = module_config_change._hash_text(text)
    print(f"path: {path}")
    print(f"config_hash: {config_hash}")
    print(text.rstrip())


def _load_module_config_proposal(conn, proposal_id: int) -> dict:
    row = store.get_proposal(conn, proposal_id)
    if not row:
        raise ValueError("proposal not found")
    if row["kind"] not in {"module.enable", "module.disable"}:
        raise ValueError("proposal kind is not module.enable/module.disable")
    details = json.loads(row["details_json"])
    return {"row": row, "details": details}


def cmd_modules_config_diff(args: argparse.Namespace) -> None:
    conn = _conn()
    proposal = _load_module_config_proposal(conn, args.proposal)
    row = proposal["row"]
    details = proposal["details"]
    current_text = settings.modules_config_path().read_text(encoding="utf-8")
    proposed_text = module_config_change.build_proposed_config(
        current_text, row["kind"], details
    )
    diff = module_config_change.diff_text(current_text, proposed_text)
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "module.config_previewed",
            "proposal_id": row["id"],
            "old_hash": module_config_change._hash_text(current_text),
            "new_hash": module_config_change._hash_text(proposed_text),
        },
    )
    print(diff.rstrip() if diff else "no diff")


def cmd_modules_enable(args: argparse.Namespace) -> None:
    conn = _conn()
    registry = module_registry.load_registry(str(settings.modules_registry_path()))
    module = module_registry.find_module(registry, args.name)
    config = json.loads(args.config) if args.config else {}
    details = {
        "module_name": module.get("name"),
        "rationale": args.reason,
        "config": config,
    }
    module_config_change.validate_enable_details(registry, details)
    proposal_id = store.insert_proposal(
        conn,
        kind="module.enable",
        summary=f"Enable module {module.get('name')}",
        details=details,
        steps=["Review module config", "Enable module in config", "Restart affected services"],
        risk=0.4,
        expected_outcome="Module enablement is reviewed by human.",
        status="pending",
        policy_hash=policy_mod.load_policy(str(settings.policy_path())).policy_hash,
    )
    print(f"created proposal {proposal_id}")


def cmd_modules_disable(args: argparse.Namespace) -> None:
    conn = _conn()
    registry = module_registry.load_registry(str(settings.modules_registry_path()))
    module = module_registry.find_module(registry, args.name)
    details = {
        "module_name": module.get("name"),
        "rationale": args.reason,
    }
    module_config_change.validate_disable_details(registry, details)
    proposal_id = store.insert_proposal(
        conn,
        kind="module.disable",
        summary=f"Disable module {module.get('name')}",
        details=details,
        steps=["Review impact", "Disable module in config", "Restart affected services"],
        risk=0.2,
        expected_outcome="Module is disabled in configuration.",
        status="pending",
        policy_hash=policy_mod.load_policy(str(settings.policy_path())).policy_hash,
    )
    print(f"created proposal {proposal_id}")


def cmd_modules_config_apply(args: argparse.Namespace) -> None:
    conn = _conn()
    try:
        proposal = _load_module_config_proposal(conn, args.proposal)
        row = proposal["row"]
        details = proposal["details"]
    except ValueError as exc:
        print(str(exc))
        return

    if not store.approval_exists(conn, row["id"], "approve") or row["status"] != "approved":
        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "module.config_apply_blocked",
                "proposal_id": row["id"],
                "reason": "proposal not approved",
                "actor": args.actor,
            },
        )
        print("proposal is not approved")
        return

    registry = module_registry.load_registry(str(settings.modules_registry_path()))
    try:
        if row["kind"] == "module.enable":
            module_config_change.validate_enable_details(registry, details)
        else:
            module_config_change.validate_disable_details(registry, details)
    except Exception as exc:
        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "module.config_apply_blocked",
                "proposal_id": row["id"],
                "reason": str(exc),
                "actor": args.actor,
            },
        )
        print(f"config lint failed: {exc}")
        return

    current_text = settings.modules_config_path().read_text(encoding="utf-8")
    proposed_text = module_config_change.build_proposed_config(
        current_text, row["kind"], details
    )
    old_hash, new_hash, diff_hash, backup_path, diff = module_config_change.apply_module_config_change(
        str(settings.modules_config_path()), proposed_text
    )
    store.update_proposal_status(conn, row["id"], "executed")
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "module.config_applied",
            "proposal_id": row["id"],
            "actor": args.actor,
            "reason": args.reason,
            "old_hash": old_hash,
            "new_hash": new_hash,
            "diff_hash": diff_hash,
            "backup_path": backup_path,
        },
    )
    print(f"config applied. backup: {backup_path}")


def cmd_modules_config_rollback(args: argparse.Namespace) -> None:
    conn = _conn()
    try:
        proposal_id = module_config_change.find_proposal_for_backup(
            str(settings.audit_path()), args.backup
        )
        row = store.get_proposal(conn, proposal_id)
        if not row:
            raise ValueError("proposal not found for backup")
        if row["kind"] not in {"module.enable", "module.disable"}:
            raise ValueError("linked proposal is not module.enable/module.disable")
        if not store.approval_exists(conn, row["id"], "approve"):
            raise ValueError("proposal not approved")
        details = json.loads(row["details_json"])
    except Exception as exc:
        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "module.config_apply_blocked",
                "proposal_id": None,
                "reason": str(exc),
                "actor": args.actor,
            },
        )
        print(f"rollback blocked: {exc}")
        return

    current_text = settings.modules_config_path().read_text(encoding="utf-8")
    backup_text = Path(args.backup).read_text(encoding="utf-8")
    registry = module_registry.load_registry(str(settings.modules_registry_path()))
    try:
        if row["kind"] == "module.enable":
            module_config_change.validate_enable_details(registry, details)
        else:
            module_config_change.validate_disable_details(registry, details)
        module_config_change._validate_no_secrets(
            module_config_change.parse_config(backup_text).get("modules", {}).get(
                details.get("module_name"), {}
            )
        )
    except Exception as exc:
        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "module.config_apply_blocked",
                "proposal_id": row["id"],
                "reason": str(exc),
                "actor": args.actor,
            },
        )
        print(f"rollback blocked: {exc}")
        return

    old_hash, new_hash, diff_hash, rollback_backup, diff = module_config_change.rollback_module_config(
        str(settings.modules_config_path()), args.backup
    )
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "module.config_rolled_back",
            "proposal_id": row["id"],
            "actor": args.actor,
            "reason": args.reason,
            "old_hash": old_hash,
            "new_hash": new_hash,
            "diff_hash": diff_hash,
            "backup_path": args.backup,
            "rollback_backup_path": rollback_backup,
        },
    )
    print(f"config rolled back. backup: {rollback_backup}")


def cmd_voice_server(args: argparse.Namespace) -> None:
    voice_server.run_server(host=args.host, port=args.port)


def cmd_voice_send(args: argparse.Namespace) -> None:
    import urllib.request
    import urllib.error

    payload = {"text": args.text}
    if args.device_id:
        payload["device_id"] = args.device_id
    if args.confidence is not None:
        payload["confidence"] = args.confidence

    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    url = f"http://127.0.0.1:{settings.voice_server_port()}/voice"
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8")
        decoded = json.loads(raw)
        event_id = decoded.get("event_id")
        print(event_id if event_id is not None else raw)
    except urllib.error.HTTPError as exc:
        print(f"error: http_{exc.code}")
    except Exception as exc:
        print(f"error: {exc}")


def cmd_ops_systemd_install(args: argparse.Namespace) -> None:
    commands = [
        "sudo mkdir -p /etc/pumpkin",
        "sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin.service /etc/systemd/system/pumpkin.service",
        "sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin-voice.service /etc/systemd/system/pumpkin-voice.service",
        "sudo systemctl daemon-reload",
        "sudo systemctl enable pumpkin.service",
        "sudo systemctl enable pumpkin-voice.service",
        "sudo systemctl start pumpkin.service",
        "sudo systemctl start pumpkin-voice.service",
        "sudo systemctl status pumpkin.service",
        "sudo systemctl status pumpkin-voice.service",
        "python3 -m pumpkin status",
        "",
        "# uninstall",
        "sudo systemctl disable pumpkin.service",
        "sudo systemctl disable pumpkin-voice.service",
        "sudo systemctl stop pumpkin.service",
        "sudo systemctl stop pumpkin-voice.service",
        "sudo rm /etc/systemd/system/pumpkin.service",
        "sudo rm /etc/systemd/system/pumpkin-voice.service",
        "sudo systemctl daemon-reload",
    ]
    print("\n".join(commands))


def _detect_local_ip() -> str:
    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "localhost"


def cmd_ops_cloudflare_voice(args: argparse.Namespace) -> None:
    hostname = args.hostname
    target = args.target
    if not target:
        target = f"http://{_detect_local_ip()}:{settings.voice_server_port()}"
    tunnel = args.tunnel_name or "<tunnel-name>"
    ingress = "\n".join(
        [
            "ingress:",
            f"  - hostname: {hostname}",
            f"    service: {target}",
            "  - service: http_status:404",
        ]
    )
    commands = [
        "# cloudflared ingress rule (add to config.yml)",
        ingress,
        "",
        "# config path (Proxmox default)",
        "/etc/cloudflared/config.yml",
        "",
        "# note: ensure the hostname rule is above the http_status:404 catch-all",
        "",
        "# DNS route (tunnel name required)",
        f"cloudflared tunnel route dns {tunnel} {hostname}",
        "",
        "# restart cloudflared",
        "sudo systemctl restart cloudflared",
        "sudo systemctl restart cloudflared@tunnel",
        "",
        "# validate ingress on Proxmox",
        "cloudflared tunnel ingress validate --config /etc/cloudflared/config.yml",
        "",
        "# local POST test (no TLS)",
        f"curl -sS -X POST {target}/voice \\",
        "  -H 'Content-Type: application/json' \\",
        "  -d '{\"text\":\"voice test\"}'",
        "",
        "# remote POST test",
        f"curl -sS -X POST https://{hostname}/voice \\",
        "  -H 'Content-Type: application/json' \\",
        "  -d '{\"text\":\"voice test\"}'",
    ]
    print("\n".join(commands))


def _voice_verify_report(allow_subprocess: bool = True) -> dict:
    import subprocess
    import urllib.request
    import urllib.error
    import socket
    from datetime import datetime, timezone

    report = {
        "bind_host": settings.voice_server_host(),
        "bind_port": settings.voice_server_port(),
        "bind_state": "not_running",
        "port_status": "unknown",
        "loopback_post": "error",
        "lan_post": "unknown",
        "lan_ip": None,
        "cloudflare_voice_ready": False,
        "service_status": {},
        "test_marker": None,
    }

    if allow_subprocess:
        services = ["pumpkin.service", "pumpkin-voice.service"]
        for svc in services:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", svc],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    text=True,
                )
                status = result.stdout.strip() or "unknown"
            except Exception:
                status = "unknown"
            report["service_status"][svc] = status
    else:
        report["service_status"] = {
            "pumpkin.service": "unknown",
            "pumpkin-voice.service": "unknown",
        }
        if report["bind_host"] in {"0.0.0.0", "::"}:
            report["bind_state"] = "listening_all_interfaces"
        elif report["bind_host"] in {"127.0.0.1", "localhost"}:
            report["bind_state"] = "listening_localhost_only"

    if allow_subprocess:
        try:
            result = subprocess.run(
                ["ss", "-lnt"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            if result.returncode == 0:
                report["port_status"] = (
                    "listening"
                    if f":{report['bind_port']}" in result.stdout
                    else "not listening"
                )
                if (
                    f"0.0.0.0:{report['bind_port']}" in result.stdout
                    or f"[::]:{report['bind_port']}" in result.stdout
                ):
                    report["bind_state"] = "listening_all_interfaces"
                elif f"127.0.0.1:{report['bind_port']}" in result.stdout:
                    report["bind_state"] = "listening_localhost_only"
        except Exception:
            report["port_status"] = "unknown"

    def _post(url: str) -> str:
        marker = datetime.now(timezone.utc).isoformat()
        report["test_marker"] = marker
        payload = json.dumps({"text": f"hello from ops verify {marker}"}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=2) as resp:
                raw = resp.read().decode("utf-8")
            decoded = json.loads(raw)
            return "ok"
        except urllib.error.HTTPError as exc:
            return f"http_{exc.code}"
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", "")
            if isinstance(reason, ConnectionRefusedError):
                return "connection_refused"
            if isinstance(reason, socket.timeout):
                return "timeout"
            return "error"
        except socket.timeout:
            return "timeout"
        except Exception:
            return "error"

    report["loopback_post"] = _post(f"http://127.0.0.1:{report['bind_port']}/voice")
    lan_ip = _detect_local_ip()
    if lan_ip and lan_ip != "localhost":
        report["lan_ip"] = lan_ip
        report["lan_post"] = _post(f"http://{lan_ip}:{report['bind_port']}/voice")

    report["cloudflare_voice_ready"] = (
        report["bind_state"] == "listening_all_interfaces" and report["lan_post"] == "ok"
    )
    return report


def cmd_ops_verify(_: argparse.Namespace) -> None:
    report = _voice_verify_report()
    print("Pumpkin ops verify")
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "voice.verify_started",
            "host": report["bind_host"],
            "port": report["bind_port"],
        },
    )
    for svc, status in report["service_status"].items():
        unit_path = f"/etc/systemd/system/{svc}"
        unit_present = Path(unit_path).exists()
        if not unit_present:
            print(f"  {svc}: missing")
        else:
            print(f"  {svc}: {status}")

    print(f"  voice.bind.host: {report['bind_host']}")
    print(f"  voice.bind.port: {report['bind_port']}")
    print(f"  voice.bind_state: {report['bind_state']}")
    print(f"  port {report['bind_port']}: {report['port_status']}")
    print(f"  voice POST (loopback): {report['loopback_post']}")
    if report["test_marker"]:
        print(f"  voice test marker: {report['test_marker']}")
    if report["lan_ip"]:
        print(f"  voice POST (lan): {report['lan_post']}")
    else:
        print("  voice POST (lan): unknown")

    if report["port_status"] == "not listening":
        unit_path = "/etc/systemd/system/pumpkin-voice.service"
        if not Path(unit_path).exists():
            print("  hint: install pumpkin-voice.service from deploy/ and enable it")
        else:
            print("  hint: start pumpkin-voice.service or run `python3 -m pumpkin voice server`")
    elif report["bind_state"] == "listening_localhost_only":
        print("  hint: set PUMPKIN_VOICE_HOST=0.0.0.0 to bind all interfaces")
    elif report["lan_post"] == "http_400":
        print("  hint: probe returned http_400; check /voice JSON {\"text\":\"...\"} format")
    elif report["lan_post"] not in {"ok"}:
        print("  hint: verify firewall rules and interface binding")

    print(f"  cloudflare_voice_ready: {str(report['cloudflare_voice_ready']).lower()}")

    if report["lan_ip"]:
        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "voice.lan_probe",
                "host": report["lan_ip"],
                "port": report["bind_port"],
                "result": report["lan_post"],
            },
        )

    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "voice.verify_result",
            "host": report["bind_host"],
            "port": report["bind_port"],
            "bind_state": report["bind_state"],
            "lan_probe_result": report["lan_post"],
            "cloudflare_voice_ready": report["cloudflare_voice_ready"],
        },
    )

    conn = _conn()
    row = conn.execute(
        "SELECT id, ts FROM events WHERE source = 'voice' AND type = 'voice.command' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if row:
        print(f"  last voice.event: id={row['id']} ts={row['ts']}")
    else:
        print("  last voice.event: none")

    kinds = ["capability.offer", "module.install", "action.request"]
    for kind in kinds:
        row = conn.execute(
            "SELECT COUNT(*) as count FROM proposals WHERE status = 'pending' AND kind = ?",
            (kind,),
        ).fetchone()
        count = row["count"] if row else 0
        print(f"  pending {kind}: {count}")


def cmd_ops_cloudflare_voice_check(_: argparse.Namespace) -> None:
    report = _voice_verify_report(allow_subprocess=False)
    ready = report["cloudflare_voice_ready"]
    print(f"cloudflare_voice_ready: {str(ready).lower()}")
    if not ready:
        reasons = [
            f"bind_state={report['bind_state']}",
            f"lan_probe_result={report['lan_post']}",
        ]
        if report["lan_post"] == "http_400":
            reasons.append("probe_format_error=request_body_or_path")
        for svc, status in report["service_status"].items():
            if status != "active":
                reasons.append(f"{svc}={status}")
        print("reasons:")
        for reason in reasons:
            print(f"- {reason}")

    from datetime import datetime, timezone
    marker = datetime.now(timezone.utc).isoformat()
    print(
        "external test:\n"
        "curl -sS -X POST https://voice.rosshome.co.uk/voice \\\n"
        "  -H \"Content-Type: application/json\" \\\n"
        f"  -d '{{\"text\":\"hello from outside {marker}\"}}'"
    )
    print("confirm after test:")
    print("python3 -m pumpkin proposals list | head -n 10")
    print("python3 -m pumpkin ops verify")


def cmd_ops_systemd_status(_: argparse.Namespace) -> None:
    unit_pumpkin = Path("/etc/systemd/system/pumpkin.service")
    unit_voice = Path("/etc/systemd/system/pumpkin-voice.service")
    env_path = Path("/etc/pumpkin/pumpkin.env")

    print("Pumpkin systemd status")
    print(f"  pumpkin.service unit: {'present' if unit_pumpkin.exists() else 'missing'}")
    print(f"  pumpkin-voice.service unit: {'present' if unit_voice.exists() else 'missing'}")
    print(f"  env file: {'present' if env_path.exists() else 'missing'}")

    import subprocess

    for svc in ["pumpkin.service", "pumpkin-voice.service"]:
        status = "unknown"
        enabled = "unknown"
        try:
            result = subprocess.run(
                ["systemctl", "is-active", svc],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                text=True,
            )
            status = result.stdout.strip() or "unknown"
            result = subprocess.run(
                ["systemctl", "is-enabled", svc],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                text=True,
            )
            enabled = result.stdout.strip() or "unknown"
        except Exception:
            status = "unknown"
            enabled = "unknown"
        print(f"  {svc}: active={status} enabled={enabled}")

    try:
        import socket
        sock = socket.create_connection(("127.0.0.1", settings.voice_server_port()), timeout=1)
        sock.close()
        port_status = "listening"
    except Exception:
        port_status = "not listening"
    print(f"  port {settings.voice_server_port()}: {port_status}")

    commands = [
        "sudo mkdir -p /etc/pumpkin",
        "sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin.service /etc/systemd/system/pumpkin.service",
        "sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin-voice.service /etc/systemd/system/pumpkin-voice.service",
        "sudo systemctl daemon-reload",
        "sudo systemctl enable --now pumpkin.service",
        "sudo systemctl enable --now pumpkin-voice.service",
        "sudo systemctl status pumpkin.service",
        "sudo systemctl status pumpkin-voice.service",
    ]
    print("install commands:")
    print("\n".join(commands))


def _apply_approved_actions(limit: int = 10) -> Tuple[int, int]:
    conn = _conn()
    rows = store.fetch_approved_unexecuted(conn)[:limit]
    if not rows:
        print("No approved proposals awaiting execution.")
        return 0, 0
    success = 0
    failed = 0
    audit_path = str(settings.audit_path())
    for row in rows:
        details = json.loads(row["details_json"])
        action_type = details.get("action_type")
        params = details.get("action_params") or {}
        if action_type not in {"code.apply_patch", "notify.local"}:
            print(f"Skipping proposal {row['id']} (unsupported action_type: {action_type})")
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
            success += 1
            print(f"Executed proposal {row['id']} ({row['summary']})")
        except Exception as exc:  # pragma: no cover
            store.finish_action(
                conn, action_id, status="failed", result={"error": str(exc)}
            )
            failed += 1
            print(f"Failed proposal {row['id']}: {exc}")
    return success, failed


def cmd_ops_apply_approved(args: argparse.Namespace) -> None:
    success, failed = _apply_approved_actions(limit=args.limit)
    print(f"Completed: {success} succeeded, {failed} failed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pumpkin")
    sub = parser.add_subparsers(dest="cmd", required=True)

    status = sub.add_parser("status")
    status.set_defaults(func=cmd_status)

    proposals = sub.add_parser("proposals")
    proposals_sub = proposals.add_subparsers(dest="subcmd", required=True)

    proposals_list = proposals_sub.add_parser("list")
    proposals_list.add_argument("--status", choices=["pending", "approved", "rejected", "executed", "failed", "superseded"])  # noqa: E501
    proposals_list.set_defaults(func=cmd_proposals_list)

    proposals_show = proposals_sub.add_parser("show")
    proposals_show.add_argument("proposal_id", type=int)
    proposals_show.set_defaults(func=cmd_proposals_show)

    proposals_approve = proposals_sub.add_parser("approve")
    proposals_approve.add_argument("proposal_id", type=int)
    proposals_approve.add_argument("--reason", default=None)
    proposals_approve.add_argument("--actor", default=None)
    proposals_approve.set_defaults(func=cmd_proposals_approve)

    proposals_reject = proposals_sub.add_parser("reject")
    proposals_reject.add_argument("proposal_id", type=int)
    proposals_reject.add_argument("--reason", default=None)
    proposals_reject.add_argument("--actor", default=None)
    proposals_reject.set_defaults(func=cmd_proposals_reject)

    observe = sub.add_parser("observe")
    observe_sub = observe.add_subparsers(dest="subcmd", required=True)

    observe_add = observe_sub.add_parser("add")
    observe_add.add_argument("--type", default="note")
    observe_add.add_argument("--message", required=True)
    observe_add.add_argument("--severity", default="info")
    observe_add.set_defaults(func=cmd_observe_add)

    daemon = sub.add_parser("daemon")
    daemon.add_argument("--interval", type=float, default=None)
    daemon.add_argument("--once", action="store_true")
    daemon.set_defaults(func=cmd_daemon)

    planner_cmd = sub.add_parser("planner")
    planner_sub = planner_cmd.add_subparsers(dest="subcmd", required=True)

    planner_context = planner_sub.add_parser("context")
    planner_context.add_argument("--events", type=int, default=20)
    planner_context.add_argument("--output", default=None)
    planner_context.set_defaults(func=cmd_planner_context)

    planner_replay = planner_sub.add_parser("replay")
    planner_replay.add_argument("--context", required=True)
    planner_replay.set_defaults(func=cmd_planner_replay)

    policy_cmd = sub.add_parser("policy")
    policy_sub = policy_cmd.add_subparsers(dest="subcmd", required=True)

    policy_current = policy_sub.add_parser("current")
    policy_current.set_defaults(func=cmd_policy_current)

    policy_diff_cmd = policy_sub.add_parser("diff")
    policy_diff_cmd.add_argument("--proposal", type=int, required=True)
    policy_diff_cmd.set_defaults(func=cmd_policy_diff)

    policy_apply_cmd = policy_sub.add_parser("apply")
    policy_apply_cmd.add_argument("--proposal", type=int, required=True)
    policy_apply_cmd.add_argument("--actor", required=True)
    policy_apply_cmd.add_argument("--reason", required=True)
    policy_apply_cmd.set_defaults(func=cmd_policy_apply)

    policy_preview_cmd = policy_sub.add_parser("preview")
    policy_preview_cmd.add_argument("--proposal", type=int, required=True)
    policy_preview_cmd.set_defaults(func=cmd_policy_preview)

    policy_rollback_cmd = policy_sub.add_parser("rollback")
    policy_rollback_cmd.add_argument("--backup", required=True)
    policy_rollback_cmd.add_argument("--actor", required=True)
    policy_rollback_cmd.add_argument("--reason", required=True)
    policy_rollback_cmd.set_defaults(func=cmd_policy_rollback)

    modules_cmd = sub.add_parser("modules")
    modules_sub = modules_cmd.add_subparsers(dest="subcmd", required=True)

    modules_list = modules_sub.add_parser("list")
    modules_list.set_defaults(func=cmd_modules_list)

    modules_show = modules_sub.add_parser("show")
    modules_show.add_argument("name")
    modules_show.set_defaults(func=cmd_modules_show)

    modules_suggest = modules_sub.add_parser("suggest")
    modules_suggest.add_argument("name")
    modules_suggest.add_argument("--reason", required=True)
    modules_suggest.add_argument("--config", default=None)
    modules_suggest.add_argument(
        "--rollback-plan",
        default="Disable module and remove related config entries.",
    )
    modules_suggest.set_defaults(func=cmd_modules_suggest)

    modules_lint = modules_sub.add_parser("lint-proposal")
    modules_lint.add_argument("proposal_id", type=int)
    modules_lint.set_defaults(func=cmd_modules_lint_proposal)

    modules_runbook = modules_sub.add_parser("runbook")
    modules_runbook.add_argument("--proposal", dest="proposal_id", type=int, required=True)
    modules_runbook.add_argument("--output", default=None)
    modules_runbook.add_argument("--format", choices=["md", "json"], default="md")
    modules_runbook.set_defaults(func=cmd_modules_runbook)

    modules_verify = modules_sub.add_parser("verify-prereqs")
    modules_verify.add_argument("--proposal", dest="proposal_id", type=int, required=True)
    modules_verify.set_defaults(func=cmd_modules_verify_prereqs)

    modules_config_cmd = modules_sub.add_parser("config")
    modules_config_sub = modules_config_cmd.add_subparsers(dest="subcmd", required=True)

    modules_config_show = modules_config_sub.add_parser("show")
    modules_config_show.set_defaults(func=cmd_modules_config_show)

    modules_config_diff = modules_config_sub.add_parser("diff")
    modules_config_diff.add_argument("--proposal", type=int, required=True)
    modules_config_diff.set_defaults(func=cmd_modules_config_diff)

    modules_config_apply = modules_config_sub.add_parser("apply")
    modules_config_apply.add_argument("--proposal", type=int, required=True)
    modules_config_apply.add_argument("--actor", required=True)
    modules_config_apply.add_argument("--reason", required=True)
    modules_config_apply.set_defaults(func=cmd_modules_config_apply)

    modules_config_rollback = modules_config_sub.add_parser("rollback")
    modules_config_rollback.add_argument("--backup", required=True)
    modules_config_rollback.add_argument("--actor", required=True)
    modules_config_rollback.add_argument("--reason", required=True)
    modules_config_rollback.set_defaults(func=cmd_modules_config_rollback)

    modules_enable = modules_sub.add_parser("enable")
    modules_enable.add_argument("--name", required=True)
    modules_enable.add_argument("--reason", required=True)
    modules_enable.add_argument("--config", default=None)
    modules_enable.set_defaults(func=cmd_modules_enable)

    modules_disable = modules_sub.add_parser("disable")
    modules_disable.add_argument("--name", required=True)
    modules_disable.add_argument("--reason", required=True)
    modules_disable.set_defaults(func=cmd_modules_disable)

    voice_cmd = sub.add_parser("voice")
    voice_sub = voice_cmd.add_subparsers(dest="subcmd", required=True)

    voice_server_cmd = voice_sub.add_parser("server")
    voice_server_cmd.add_argument("--host", default="0.0.0.0")
    voice_server_cmd.add_argument("--port", type=int, default=None)
    voice_server_cmd.set_defaults(func=cmd_voice_server)

    voice_send_cmd = voice_sub.add_parser("send")
    voice_send_cmd.add_argument("text")
    voice_send_cmd.add_argument("--device-id", default=None)
    voice_send_cmd.add_argument("--confidence", type=float, default=None)
    voice_send_cmd.set_defaults(func=cmd_voice_send)

    ops_cmd = sub.add_parser("ops")
    ops_sub = ops_cmd.add_subparsers(dest="subcmd", required=True)

    ops_systemd = ops_sub.add_parser("systemd-install")
    ops_systemd.add_argument("--mode", choices=["print"], default="print")
    ops_systemd.set_defaults(func=cmd_ops_systemd_install)

    ops_cloudflare = ops_sub.add_parser("cloudflare-voice")
    ops_cloudflare.add_argument("--hostname", default="voice.rosshome.co.uk")
    ops_cloudflare.add_argument("--target", default=None)
    ops_cloudflare.add_argument("--tunnel-name", default=None)
    ops_cloudflare.set_defaults(func=cmd_ops_cloudflare_voice)

    ops_cloudflare_check = ops_sub.add_parser("cloudflare-voice-check")
    ops_cloudflare_check.set_defaults(func=cmd_ops_cloudflare_voice_check)

    ops_systemd_status = ops_sub.add_parser("systemd-status")
    ops_systemd_status.set_defaults(func=cmd_ops_systemd_status)

    ops_apply = ops_sub.add_parser("apply-approved")
    ops_apply.add_argument("--limit", type=int, default=10)
    ops_apply.set_defaults(func=cmd_ops_apply_approved)

    ops_verify = ops_sub.add_parser("verify")
    ops_verify.set_defaults(func=cmd_ops_verify)

    return parser


def main(argv: Any = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
