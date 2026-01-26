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
from . import ha_client
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
    "homeassistant.service": {
        "description": "Call a Home Assistant service with a payload.",
        "verification": "Confirm the Home Assistant service call succeeds.",
        "rollback": "Call the opposite service if needed (manual).",
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
    if action_type == "homeassistant.service":
        return homeassistant_service_action(params, audit_path)
    raise ValueError(f"unsupported action_type: {action_type}")


class PatchApplyError(RuntimeError):
    def __init__(self, message: str, details: Dict[str, Any]) -> None:
        super().__init__(message)
        self.details = details


def apply_patch_action(params: Dict[str, Any], audit_path: str) -> Dict[str, Any]:
    patch_text = params.get("patch")
    repo_root = params.get("repo_root")
    if not isinstance(patch_text, str) or not patch_text.strip():
        raise PatchApplyError("patch_missing", {"error": "patch_missing"})
    if not isinstance(repo_root, str) or not repo_root.strip():
        raise PatchApplyError("repo_root_missing", {"error": "repo_root_missing"})

    allowed_roots = _allowed_roots()
    if not _path_allowed(repo_root, allowed_roots):
        raise PatchApplyError(
            "repo_root_not_allowed",
            {"error": "repo_root_not_allowed", "repo_root": repo_root},
        )

    _validate_patch_paths(patch_text, repo_root, allowed_roots)
    _validate_protected_patch_paths(patch_text, repo_root)
    file_pairs = _patch_file_pairs(patch_text)
    missing = _find_missing_patch_files(repo_root, file_pairs)
    if missing:
        raise PatchApplyError(
            "patch_missing_files",
            {"error": "patch_missing_files", "files": missing, "repo_root": repo_root},
        )

    if not _looks_like_unified_diff(patch_text):
        raise PatchApplyError(
            "patch_invalid_format",
            {"error": "patch_invalid_format", "repo_root": repo_root},
        )
    strip_level = 1 if _patch_uses_prefixes(patch_text) else 0
    dry_run = subprocess.run(
        ["patch", "--dry-run", f"-p{strip_level}", "-N", "-r", "-"],
        input=patch_text.encode("utf-8"),
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if dry_run.returncode != 0:
        stderr = dry_run.stderr.decode("utf-8", "ignore")
        raise PatchApplyError(
            "patch_dry_run_failed",
            {
                "error": "patch_dry_run_failed",
                "stderr": stderr.strip(),
                "repo_root": repo_root,
                "strip_level": strip_level,
                "files": _patch_files(patch_text),
            },
        )
    result = subprocess.run(
        ["patch", f"-p{strip_level}", "-N", "-r", "-"],
        input=patch_text.encode("utf-8"),
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "ignore")
        raise PatchApplyError(
            "patch_failed",
            {
                "error": "patch_failed",
                "stderr": stderr.strip(),
                "repo_root": repo_root,
                "strip_level": strip_level,
                "files": _patch_files(patch_text),
            },
        )
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


def _load_homeassistant_module_cfg() -> Dict[str, Any]:
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return {}
    try:
        config = module_config.load_config(str(config_path))
    except Exception:
        return {}
    modules_cfg = config.get("modules", {}) if isinstance(config, dict) else {}
    module_cfg = modules_cfg.get("homeassistant.observer", {})
    if not isinstance(module_cfg, dict):
        module_cfg = modules_cfg.get("homeassistant", {})
    return module_cfg if isinstance(module_cfg, dict) else {}


def _load_autonomy_cfg() -> Dict[str, Any]:
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return {}
    try:
        config = module_config.load_config(str(config_path))
    except Exception:
        return {}
    module_cfg = config.get("modules", {}).get("autonomy", {})
    return module_cfg if isinstance(module_cfg, dict) else {}


def _normalize_path(path: str) -> str:
    return os.path.normpath(os.path.abspath(path))


def _validate_protected_patch_paths(patch_text: str, repo_root: str) -> None:
    cfg = _load_autonomy_cfg()
    protected = cfg.get("protected_patch_paths", [])
    if not isinstance(protected, list) or not protected:
        return
    protected_paths = []
    for entry in protected:
        if isinstance(entry, str) and entry.strip():
            protected_paths.append(_normalize_path(os.path.join(repo_root, entry)))
    if not protected_paths:
        return
    for rel_path in _patch_files(patch_text):
        abs_path = _normalize_path(os.path.join(repo_root, rel_path))
        for protected_path in protected_paths:
            if abs_path == protected_path or abs_path.startswith(protected_path + os.sep):
                raise PatchApplyError(
                    "patch_protected_path",
                    {
                        "error": "patch_protected_path",
                        "path": rel_path,
                        "repo_root": repo_root,
                    },
                )


def homeassistant_service_action(params: Dict[str, Any], audit_path: str) -> Dict[str, Any]:
    domain = params.get("domain")
    service = params.get("service")
    payload = params.get("payload") if isinstance(params.get("payload"), dict) else {}
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("domain_missing")
    if not isinstance(service, str) or not service.strip():
        raise ValueError("service_missing")
    cfg = _load_homeassistant_module_cfg()
    base_url = cfg.get("base_url")
    token_env = cfg.get("token_env", "PUMPKIN_HA_TOKEN")
    token = os.getenv(token_env)
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("ha_base_url_missing")
    if not isinstance(token, str) or not token.strip():
        raise ValueError("ha_token_missing")
    result = ha_client.call_service(
        base_url=base_url,
        token=token,
        domain=str(domain).strip(),
        service=str(service).strip(),
        payload=payload,
        timeout=settings.ha_request_timeout_seconds(),
    )
    if not result.get("ok"):
        raise ValueError(f"ha_service_failed:{result.get('error')}")
    append_jsonl(
        audit_path,
        {
            "kind": "homeassistant.service",
            "domain": str(domain).strip(),
            "service": str(service).strip(),
            "payload": payload,
        },
    )
    return {"ok": True, "result": result.get("result")}


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


def _patch_file_pairs(patch_text: str) -> List[Dict[str, str]]:
    pairs: List[Dict[str, str]] = []
    old_path = None
    for line in patch_text.splitlines():
        if line.startswith("--- "):
            old_path = line[4:].split("\t")[0].strip()
        elif line.startswith("+++ "):
            new_path = line[4:].split("\t")[0].strip()
            pairs.append({"old": old_path or "", "new": new_path})
            old_path = None
    return pairs


def _find_missing_patch_files(repo_root: str, pairs: List[Dict[str, str]]) -> List[str]:
    missing: List[str] = []
    root = os.path.realpath(repo_root)
    for pair in pairs:
        old_path = pair.get("old", "")
        new_path = pair.get("new", "")
        if old_path == "/dev/null":
            continue
        target = old_path
        if target.startswith("a/") or target.startswith("b/"):
            target = target[2:]
        if not target:
            continue
        real_path = os.path.realpath(os.path.join(root, target))
        if not os.path.exists(real_path):
            missing.append(target)
    return missing


def _looks_like_unified_diff(patch_text: str) -> bool:
    has_old = False
    has_new = False
    for line in patch_text.splitlines():
        if line.startswith("--- "):
            has_old = True
        if line.startswith("+++ "):
            has_new = True
        if has_old and has_new:
            return True
    return False


def _validate_patch_paths(patch_text: str, repo_root: str, allowed_roots: List[str]) -> None:
    root = os.path.realpath(repo_root)
    for path in _patch_files(patch_text):
        if os.path.isabs(path):
            target = os.path.realpath(path)
        else:
            target = os.path.realpath(os.path.join(root, path))
        if not _path_allowed(target, allowed_roots):
            raise ValueError(f"patch_path_not_allowed: {path}")
