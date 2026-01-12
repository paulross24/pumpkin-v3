"""Self-audit helpers for Pumpkin."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

from . import settings, module_config, store, ha_client, policy as policy_mod


def _http_json(url: str, method: str = "GET", payload: Dict[str, Any] | None = None, timeout: float = 5.0) -> Tuple[int, Dict[str, Any]]:
    data = None
    headers: Dict[str, str] = {}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # type: ignore[arg-type]
        raw = resp.read().decode("utf-8")
        return resp.getcode(), json.loads(raw)


def _voice_checks(host: str, port: int) -> List[Dict[str, Any]]:
    base = f"http://{host}:{port}"
    results: List[Dict[str, Any]] = []
    tests = [
        ("root", "GET", "/", None, ["service", "version", "endpoints"]),
        ("health", "GET", "/health", None, ["status"]),
        ("config", "GET", "/config", None, ["service", "http"]),
        ("openapi", "GET", "/openapi.json", None, ["openapi", "paths"]),
        ("ingest", "POST", "/ingest", {"text": "self check", "source": "selfcheck", "device": "self"}, ["status", "received"]),
    ]
    for name, method, path, payload, expected_keys in tests:
        try:
            status, body = _http_json(base + path, method=method, payload=payload, timeout=5.0)
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
    details = {
        "failures": failures[:5],
        "action_type": "ops.investigate",
        "action_params": {"log_type": "selfcheck"},
    }
    policy = policy_mod.load_policy(str(settings.policy_path()))
    proposal_id = store.insert_proposal(
        conn,
        kind="selfcheck.failure",
        summary=summary,
        details=details,
        steps=["Review selfcheck events", "Inspect HA connectivity and voice endpoints", "Apply fix then re-run selfcheck"],
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
