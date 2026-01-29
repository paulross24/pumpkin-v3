"""Self-audit helpers for Pumpkin."""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from . import settings, module_config, store, ha_client, observe, policy as policy_mod


def _http_json(
    url: str,
    method: str = "GET",
    payload: Dict[str, Any] | None = None,
    timeout: float = 5.0,
    headers: Dict[str, str] | None = None,
) -> Tuple[int, Dict[str, Any]]:
    data = None
    merged_headers: Dict[str, str] = {}
    if headers:
        merged_headers.update(headers)
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        merged_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=merged_headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # type: ignore[arg-type]
        raw = resp.read().decode("utf-8")
        return resp.getcode(), json.loads(raw)


def _voice_checks(host: str, port: int) -> List[Dict[str, Any]]:
    base = f"http://{host}:{port}"
    results: List[Dict[str, Any]] = []
    ingest_payload = {
        "schema_version": 1,
        "request_id": f"selfcheck-{int(time.time())}",
        "text": "selfcheck ping",
        "source": "selfcheck",
        "device": "selfcheck",
    }
    ingest_headers: Dict[str, str] = {}
    ingest_key = os.getenv("PUMPKIN_INGEST_KEY")
    if ingest_key:
        ingest_headers["X-Pumpkin-Key"] = ingest_key
    tests = [
        ("root", "GET", "/", None, ["service", "version", "endpoints"]),
        ("health", "GET", "/health", None, ["status"]),
        ("config", "GET", "/config", None, ["service", "http"]),
        ("openapi", "GET", "/openapi.json", None, ["openapi", "paths"]),
        ("ingest", "POST", "/ingest", ingest_payload, ["accepted", "request_id"]),
    ]
    for name, method, path, payload, expected_keys in tests:
        try:
            headers = ingest_headers if name == "ingest" else None
            status, body = _http_json(base + path, method=method, payload=payload, timeout=5.0, headers=headers)
            ok = status == 200 and all(k in body for k in expected_keys)
            results.append({"check": f"voice.{name}", "ok": ok, "status": status, "body_keys": list(body.keys())})
        except Exception as exc:
            results.append(
                {
                    "check": f"voice.{name}",
                    "ok": False,
                    "error": type(exc).__name__,
                    "detail": getattr(exc, "reason", None) or str(exc),
                }
            )
    return results


def _pick_test_entity(conn) -> str | None:
    cfg = module_config.load_config(str(settings.modules_config_path()))
    observer = cfg.get("modules", {}).get("homeassistant.observer", {}) if isinstance(cfg, dict) else {}
    preferred = observer.get("self_check_entity")
    if isinstance(preferred, str) and preferred:
        return preferred
    entities = store.get_memory(conn, "homeassistant.entities") or {}
    if not isinstance(entities, dict):
        return None
    for domain in ("light", "switch"):
        for eid in entities:
            if isinstance(eid, str) and eid.startswith(domain + "."):
                return eid
    return None


def _ha_toggle(conn) -> Dict[str, Any]:
    cfg = module_config.load_config(str(settings.modules_config_path()))
    observer = cfg.get("modules", {}).get("homeassistant.observer", {}) if isinstance(cfg, dict) else {}
    base_url = observer.get("base_url")
    token_env = observer.get("token_env", "PUMPKIN_HA_TOKEN")
    token = os.getenv(token_env)
    if not base_url or not token:
        return {"check": "ha.toggle", "ok": False, "error": "ha_credentials_missing"}
    entity_id = _pick_test_entity(conn)
    if not entity_id:
        return {"check": "ha.toggle", "ok": False, "error": "no_test_entity"}
    domain = entity_id.split(".", 1)[0]
    service = "toggle"
    payload = {"entity_id": entity_id}
    start = time.time()
    result = ha_client.call_service(
        base_url=base_url,
        token=token,
        domain=domain,
        service=service,
        payload=payload,
        timeout=settings.ha_request_timeout_seconds(),
    )
    elapsed = round(time.time() - start, 3)
    return {
        "check": "ha.toggle",
        "ok": bool(result.get("ok")),
        "entity_id": entity_id,
        "elapsed": elapsed,
        "error": result.get("error"),
    }


def _network_discovery_check(conn) -> Dict[str, Any]:
    cfg = module_config.load_config(str(settings.modules_config_path()))
    module_cfg = cfg.get("modules", {}).get("network.discovery", {}) if isinstance(cfg, dict) else {}
    scan_interval = int(module_cfg.get("scan_interval_seconds", settings.selfcheck_interval_seconds()))
    rows = store.list_events(conn, limit=1, event_type="network.discovery")
    if not rows:
        return {"check": "network.discovery", "ok": False, "error": "no_snapshot"}
    last_ts = rows[0]["ts"]
    try:
        parsed = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
    except Exception:
        return {"check": "network.discovery", "ok": False, "error": "invalid_timestamp", "last_seen": last_ts}
    age_seconds = max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())
    threshold = max(60, scan_interval * 2)
    ok = age_seconds <= threshold
    return {
        "check": "network.discovery",
        "ok": ok,
        "last_seen": last_ts,
        "age_seconds": round(age_seconds, 1),
        "threshold_seconds": threshold,
    }


def _clean(value):
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def run_self_check(conn) -> Dict[str, Any]:
    host = os.getenv("PUMPKIN_VOICE_HOST", settings.voice_server_host() or "127.0.0.1")
    if not host or host == "0.0.0.0":
        host = "127.0.0.1"
    port = int(os.getenv("PUMPKIN_VOICE_PORT", settings.voice_server_port() or 9000))
    results: List[Dict[str, Any]] = []
    results.extend(_voice_checks(host, port))
    results.append(_ha_toggle(conn))
    results.append(_network_discovery_check(conn))
    failures = [r for r in results if not r.get("ok")]
    severity = "info" if not failures else "warn"
    cleaned_results = _clean(results)
    store.insert_event(
        conn,
        source="selfcheck",
        event_type="selfcheck.run",
        payload={"results": cleaned_results},
        severity=severity,
    )
    if failures:
        _maybe_raise_proposal(conn, _clean(failures))
        _self_heal(conn, failures)
    return {"results": cleaned_results, "failures": _clean(failures)}


def _maybe_raise_proposal(conn, failures: List[Dict[str, Any]]) -> None:
    key = "selfcheck.failure.count"
    last_key = "selfcheck.failure.last_ts"
    count = store.get_memory(conn, key) or 0
    try:
        count = int(count)
    except Exception:
        count = 0
    last_ts = store.get_memory(conn, last_key) or 0
    now = int(time.time())
    if last_ts and now - int(last_ts) > 6 * 3600:
        count = 0
    count += 1
    store.set_memory(conn, key, count)
    store.set_memory(conn, last_key, now)
    if count < 2:
        return
    summary = "Self-check failures detected"
    playbook = _build_playbook(failures)
    details = {
        "failures": failures[:5],
        "action_type": "ops.investigate",
        "action_params": {"log_type": "selfcheck"},
        "rationale": "Self-check failures repeated; apply the playbook to restore health.",
        "implementation": "Follow the playbook steps in order and verify the checks.",
        "verification": "Re-run selfcheck and confirm failures are cleared.",
        "rollback_plan": "Revert any recent config changes or restart affected services.",
        "playbook": playbook,
    }
    policy = policy_mod.load_policy(str(settings.policy_path()))
    proposal_id = store.insert_proposal(
        conn,
        kind="selfcheck.failure",
        summary=summary,
        details=details,
        steps=playbook or [
            "Review selfcheck events",
            "Inspect HA connectivity and voice endpoints",
            "Apply fix then re-run selfcheck",
        ],
        risk=0.3,
        expected_outcome="Self-check passes again.",
        status="pending",
        policy_hash=policy.policy_hash,
        needs_new_capability=False,
        capability_request=None,
    )
    store.insert_event(
        conn,
        source="selfcheck",
        event_type="selfcheck.proposal_created",
        payload={"proposal_id": proposal_id, "failures": failures[:5]},
        severity="info",
    )


def _build_playbook(failures: List[Dict[str, Any]]) -> List[str]:
    steps: List[str] = []
    checks = [f.get("check", "") for f in failures if isinstance(f, dict)]
    if any(str(check).startswith("voice.") for check in checks):
        steps.extend(
            [
                "Confirm pumpkin-voice.service is active.",
                "Run: curl -i http://127.0.0.1:9000/health",
                "Restart pumpkin-voice.service if needed.",
            ]
        )
    if any(str(check).startswith("ha.") for check in checks):
        steps.extend(
            [
                "Verify PUMPKIN_HA_TOKEN is set in /etc/pumpkin/pumpkin.env.",
                "Test HA reachability from core host.",
                "Restart pumpkin.service after token/config changes.",
            ]
        )
    if any(str(check).startswith("voice.") or str(check).startswith("ha.") for check in checks):
        steps.append("Re-run: python3 -m pumpkin ops selfcheck")
    # Deduplicate while preserving order
    seen = set()
    unique_steps = []
    for step in steps:
        if step not in seen:
            seen.add(step)
            unique_steps.append(step)
    return unique_steps[:8]


def _self_heal(conn, failures: List[Dict[str, Any]]) -> None:
    cfg = module_config.load_config(str(settings.modules_config_path()))
    module_cfg = cfg.get("modules", {}).get("selfheal", {}) if isinstance(cfg, dict) else {}
    if not isinstance(module_cfg, dict):
        module_cfg = {}
    if not module_cfg.get("enabled", True):
        return
    cooldown_seconds = int(module_cfg.get("cooldown_seconds", 300))
    max_actions = int(module_cfg.get("max_actions_per_run", 1))
    last_action_ts = store.get_memory(conn, "selfheal.last_action_ts") or 0
    try:
        last_action_ts = float(last_action_ts)
    except (TypeError, ValueError):
        last_action_ts = 0.0
    now = time.time()
    if now - last_action_ts < cooldown_seconds:
        return

    checks = [f.get("check", "") for f in failures if isinstance(f, dict)]
    actions: List[Dict[str, Any]] = []
    if any(str(check).startswith("voice.") for check in checks):
        if module_cfg.get("restart_voice", True):
            actions.append({"action": "restart_service", "service": "pumpkin-voice.service"})
    if any(str(check).startswith("ha.") for check in checks):
        if module_cfg.get("reset_ha_cooldown", True):
            actions.append({"action": "reset_cooldown", "key": "ha.request"})
        if module_cfg.get("probe_ha", True):
            actions.append({"action": "ha_probe"})
    if any(str(check).startswith("network.discovery") for check in checks):
        if module_cfg.get("rescan_network", True):
            actions.append({"action": "network_discovery"})
    if module_cfg.get("restart_core", False) and len(failures) >= 3:
        actions.append({"action": "restart_service", "service": "pumpkin.service"})

    if not actions:
        return

    performed = 0
    for item in actions:
        if performed >= max_actions:
            break
        action = item.get("action")
        if action == "restart_service":
            ok, detail = _restart_service(item.get("service", ""))
        elif action == "reset_cooldown":
            key = item.get("key", "")
            ok = bool(key)
            detail = f"key={key}" if key else "missing_key"
            if ok:
                store.set_memory(conn, key, 0)
        elif action == "ha_probe":
            ok, detail = _probe_homeassistant(conn)
        elif action == "network_discovery":
            ok, detail = _run_network_discovery(conn)
        else:
            continue
        performed += 1
        store.insert_event(
            conn,
            source="selfheal",
            event_type="selfheal.action",
            payload={"action": action, "ok": ok, "detail": detail},
            severity="info" if ok else "warn",
        )

    if performed:
        store.set_memory(conn, "selfheal.last_action_ts", now)


def _restart_service(service: str) -> Tuple[bool, str]:
    if not service:
        return False, "missing_service"
    cmd = ["systemctl", "restart", service]
    try:
        if os.geteuid() == 0:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, "systemctl"
        try:
            subprocess.run(["sudo", "-n", *cmd], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, "sudo"
        except Exception:
            return False, "insufficient_permissions"
    except Exception as exc:
        return False, f"restart_failed:{type(exc).__name__}"


def _run_network_discovery(conn) -> Tuple[bool, str]:
    cfg = module_config.load_config(str(settings.modules_config_path()))
    module_cfg = cfg.get("modules", {}).get("network.discovery", {}) if isinstance(cfg, dict) else {}
    if not isinstance(module_cfg, dict):
        return False, "missing_config"
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
    fast_ports = module_cfg.get("fast_ports", [])
    fast_timeout_seconds = module_cfg.get("fast_timeout_seconds")
    active = module_cfg.get("active", {})
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
    store.set_memory(conn, "network.discovery.snapshot", snapshot)
    store.insert_event(
        conn,
        source="network",
        event_type="network.discovery",
        payload=snapshot,
        severity="info",
    )
    store.set_memory(conn, "network.discovery", time.time())
    return True, f"device_count={snapshot.get('device_count', 0)}"


def _probe_homeassistant(conn) -> Tuple[bool, str]:
    cfg = module_config.load_config(str(settings.modules_config_path()))
    observer = cfg.get("modules", {}).get("homeassistant.observer", {}) if isinstance(cfg, dict) else {}
    base_url = observer.get("base_url")
    token_env = observer.get("token_env", "PUMPKIN_HA_TOKEN")
    token = os.getenv(token_env)
    if not base_url or not token:
        return False, "missing_base_url_or_token"
    url = base_url.rstrip("/") + "/"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:  # type: ignore[arg-type]
            ok = 200 <= resp.status < 500
    except Exception as exc:
        return False, f"probe_failed:{type(exc).__name__}"
    if ok:
        store.set_memory(conn, "ha.request", 0)
        store.insert_event(
            conn,
            source="homeassistant",
            event_type="homeassistant.probe_ok",
            payload={"base_url": base_url},
            severity="info",
        )
    return ok, "probe_ok" if ok else "probe_bad_status"
