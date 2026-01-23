"""Action execution."""

from __future__ import annotations

import json
from typing import Any, Dict, List

import os
import subprocess
import urllib.request

from . import settings
from . import store
from . import module_config
from . import observe
from .db import init_db, utc_now_iso

from .audit import append_jsonl


ACTION_METADATA = {
    "notify.local": {
        "description": "Emit a local notification into the audit log.",
        "verification": "Confirm the notification entry exists in the audit log.",
        "rollback": "No rollback needed; the message is informational.",
    },
    "code.apply_patch": {
        "description": "Apply a unified diff patch to an allowed repository root.",
        "verification": "Verify patch applied cleanly and service health is OK.",
        "rollback": "Revert the patch or restore from backup if needed.",
    },
    "network.deep_scan": {
        "description": "Run a deep port scan on a single host and record findings.",
        "verification": "Check deep scan results in network discovery memory.",
        "rollback": "No rollback needed; scan is read-only.",
    },
    "network.mark_useful": {
        "description": "Mark a discovered device as useful for downstream modules.",
        "verification": "Confirm device appears in network.discovery.useful list.",
        "rollback": "Remove the entry from network.discovery.useful.",
    },
    "proposal.confirm_plan": {
        "description": "Mark a proposal execution plan as confirmed.",
        "verification": "Confirm proposal details show execution_plan_confirmed=true.",
        "rollback": "Re-open the plan by clearing the confirmation flag.",
    },
    "proposal.retry_execute": {
        "description": "Retry a stalled proposal by forcing a single execution attempt.",
        "verification": "Confirm an action is created and proposal executes or fails.",
        "rollback": "Clear the force_execute flag on the proposal.",
    },
}


def notify_local(message: str, audit_path: str) -> Dict[str, Any]:
    entry = {
        "kind": "notify.local",
        "message": message,
    }
    append_jsonl(audit_path, entry)
    print(f"[notify.local] {message}")
    return {"delivered": True}


def execute_action(
    action_type: str, params: Dict[str, Any], audit_path: str
) -> Dict[str, Any]:
    if action_type == "notify.local":
        return notify_local(params.get("message", ""), audit_path)
    if action_type == "code.apply_patch":
        return apply_patch_action(params, audit_path)
    if action_type == "network.deep_scan":
        return network_deep_scan(params, audit_path)
    if action_type == "network.mark_useful":
        return network_mark_useful(params, audit_path)
    if action_type == "proposal.confirm_plan":
        return confirm_plan_action(params, audit_path)
    if action_type == "proposal.retry_execute":
        return retry_execute_action(params, audit_path)
    raise ValueError(f"unsupported action_type: {action_type}")


def apply_patch_action(params: Dict[str, Any], audit_path: str) -> Dict[str, Any]:
    patch_text = params.get("patch")
    repo_root = params.get("repo_root")
    if not isinstance(patch_text, str) or not patch_text.strip():
        raise ValueError("patch_missing")
    if not isinstance(repo_root, str) or not repo_root.strip():
        raise ValueError("repo_root_missing")

    allowed_roots = _allowed_roots()
    if not _path_allowed(repo_root, allowed_roots):
        raise ValueError("repo_root_not_allowed")

    _validate_patch_paths(patch_text, repo_root, allowed_roots)
    strip_level = 1 if _patch_uses_prefixes(patch_text) else 0
    result = subprocess.run(
        ["patch", f"-p{strip_level}", "-N", "-r", "-"],
        input=patch_text.encode("utf-8"),
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(f"patch_failed: {result.stderr.decode('utf-8', 'ignore')}")
    append_jsonl(
        audit_path,
        {
            "kind": "code.apply_patch",
            "repo_root": repo_root,
            "files": _patch_files(patch_text),
        },
    )
    return {"applied": True, "repo_root": repo_root}


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


def network_deep_scan(params: Dict[str, Any], audit_path: str) -> Dict[str, Any]:
    ip = params.get("ip")
    ports = params.get("ports")
    if not isinstance(ip, str) or not ip.strip():
        raise ValueError("ip_missing")
    ports_payload = ports if isinstance(ports, list) else []
    ports_list = []
    for item in ports_payload:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            ports_list.append(port)
    if not ports_list:
        ports_list = [22, 80, 81, 443, 554, 8000, 8080, 8081, 8123, 8443, 8554, 9000, 9443]

    conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
    module_cfg = _load_network_module_cfg()
    timeout_seconds = float(module_cfg.get("deep_scan_timeout_seconds", 0.2))
    max_workers = int(module_cfg.get("deep_scan_workers", 128))
    active_cfg = module_cfg.get("active") if isinstance(module_cfg.get("active"), dict) else {}

    state = store.get_memory(conn, "network.discovery.deep_scan")
    if not isinstance(state, dict):
        state = {"jobs": {}}
    jobs = state.get("jobs")
    if not isinstance(jobs, dict):
        jobs = {}
        state["jobs"] = jobs

    job = jobs.get(ip, {})
    job.update(
        {
            "ip": ip.strip(),
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
    jobs[ip] = job
    store.set_memory(conn, "network.discovery.deep_scan", state)

    try:
        result = observe.deep_scan_host(
            ip=ip.strip(),
            ports=ports_list,
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
        raise
    finally:
        jobs[ip] = job
        store.set_memory(conn, "network.discovery.deep_scan", state)

    append_jsonl(
        audit_path,
        {
            "kind": "network.deep_scan",
            "ip": ip.strip(),
            "open_ports": job.get("open_ports", []),
        },
    )
    return {"ok": True, "job": job}


def network_mark_useful(params: Dict[str, Any], audit_path: str) -> Dict[str, Any]:
    ip = params.get("ip")
    label = params.get("label")
    note = params.get("note")
    if not isinstance(ip, str) or not ip.strip():
        raise ValueError("ip_missing")
    if label is not None and not isinstance(label, str):
        raise ValueError("label_invalid")
    if note is not None and not isinstance(note, str):
        raise ValueError("note_invalid")
    conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
    item = {
        "ip": ip.strip(),
        "label": (label or "useful").strip(),
        "note": (note or "").strip(),
        "ts": utc_now_iso(),
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
    append_jsonl(audit_path, {"kind": "network.mark_useful", "ip": item["ip"], "label": item["label"]})
    return {"ok": True, "marked": item}


def confirm_plan_action(params: Dict[str, Any], audit_path: str) -> Dict[str, Any]:
    proposal_id = params.get("proposal_id")
    if not isinstance(proposal_id, int):
        raise ValueError("proposal_id_missing")
    conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
    row = store.get_proposal(conn, proposal_id)
    if not row:
        raise ValueError("proposal_not_found")
    try:
        details = json.loads(row["details_json"])
    except Exception:
        details = {}
    details["execution_plan_confirmed"] = True
    store.update_proposal_details(conn, proposal_id, details)
    store.insert_event(
        conn,
        source="core",
        event_type="proposal.plan_confirmed",
        payload={"proposal_id": proposal_id},
        severity="info",
    )
    append_jsonl(
        audit_path,
        {
            "kind": "proposal.plan_confirmed",
            "proposal_id": proposal_id,
        },
    )
    return {"ok": True, "proposal_id": proposal_id}


def retry_execute_action(params: Dict[str, Any], audit_path: str) -> Dict[str, Any]:
    proposal_id = params.get("proposal_id")
    if not isinstance(proposal_id, int):
        raise ValueError("proposal_id_missing")
    conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
    row = store.get_proposal(conn, proposal_id)
    if not row:
        raise ValueError("proposal_not_found")
    try:
        details = json.loads(row["details_json"])
    except Exception:
        details = {}
    if details.get("execution_plan_confirmed") is not True:
        raise ValueError("execution_plan_not_confirmed")
    if not details.get("action_type"):
        raise ValueError("action_type_missing")
    details["force_execute"] = True
    details["retry_requested_at"] = utc_now_iso()
    store.update_proposal_details(conn, proposal_id, details)
    store.insert_event(
        conn,
        source="core",
        event_type="proposal.retry_requested",
        payload={"proposal_id": proposal_id},
        severity="info",
    )
    append_jsonl(
        audit_path,
        {
            "kind": "proposal.retry_requested",
            "proposal_id": proposal_id,
        },
    )
    return {"ok": True, "proposal_id": proposal_id}


def verify_health(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.getcode()
            return {"ok": code == 200, "status_code": code}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _allowed_roots() -> List[str]:
    return [os.path.realpath(path) for path in settings.code_assistant_roots()]


def _path_allowed(path: str, allowed_roots: List[str]) -> bool:
    target = os.path.realpath(path)
    for root in allowed_roots:
        if target == root or target.startswith(root + os.sep):
            return True
    return False


def _patch_uses_prefixes(patch_text: str) -> bool:
    for line in patch_text.splitlines():
        if line.startswith("+++ b/") or line.startswith("--- a/"):
            return True
    return False


def _patch_files(patch_text: str) -> List[str]:
    files: List[str] = []
    for line in patch_text.splitlines():
        if line.startswith("+++ ") or line.startswith("--- "):
            path = line[4:].split("\t")[0].strip()
            if path == "/dev/null":
                continue
            if path.startswith("a/") or path.startswith("b/"):
                path = path[2:]
            files.append(path)
    return files


def _validate_patch_paths(patch_text: str, repo_root: str, allowed_roots: List[str]) -> None:
    root = os.path.realpath(repo_root)
    for path in _patch_files(patch_text):
        if os.path.isabs(path):
            target = os.path.realpath(path)
        else:
            target = os.path.realpath(os.path.join(root, path))
        if not _path_allowed(target, allowed_roots):
            raise ValueError(f"patch_path_not_allowed: {path}")
