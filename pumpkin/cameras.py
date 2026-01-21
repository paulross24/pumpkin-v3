"""Camera registry helpers for Pumpkin v3."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from . import observe, store


@dataclass
class CameraAuth:
    user: Optional[str]
    password: Optional[str]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _camera_key(camera: Dict[str, Any]) -> str:
    if camera.get("id"):
        return str(camera["id"])
    if camera.get("ip"):
        return f"ip:{camera['ip']}"
    return f"camera:{id(camera)}"


def load_registry(conn) -> List[Dict[str, Any]]:
    registry = store.get_memory(conn, "camera.registry")
    if not isinstance(registry, list):
        return []
    return [item for item in registry if isinstance(item, dict)]


def save_registry(conn, registry: List[Dict[str, Any]]) -> None:
    store.set_memory(conn, "camera.registry", registry[-200:])


def _merge_camera(base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in updates.items():
        if value is None:
            continue
        merged[key] = value
    if not merged.get("created_ts"):
        merged["created_ts"] = _now_iso()
    merged["updated_ts"] = _now_iso()
    return merged


def _auth_from_env(auth_env: Dict[str, Any]) -> CameraAuth:
    user_env = auth_env.get("user")
    pass_env = auth_env.get("pass")
    user = os.getenv(str(user_env)) if user_env else None
    password = os.getenv(str(pass_env)) if pass_env else None
    return CameraAuth(user=user, password=password)


def _masked_url(url: str) -> str:
    if "@" not in url or "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    creds, host = rest.split("@", 1)
    if ":" in creds:
        user = creds.split(":", 1)[0]
        return f"{scheme}://{user}:***@{host}"
    return f"{scheme}://***@{host}"


def _probe_rtsp_url(
    ip: str,
    port: int,
    paths: Iterable[str],
    timeout_seconds: float,
    max_bytes: int,
    auth: Optional[CameraAuth],
) -> Optional[str]:
    auth_header = None
    if auth and auth.user and auth.password:
        auth_header = observe.basic_auth_header(auth.user, auth.password)
    results = observe.rtsp_probe_paths(
        ip=ip,
        port=port,
        paths=paths,
        timeout=timeout_seconds,
        max_bytes=max_bytes,
        auth_header=auth_header,
    )
    for result in results:
        if not isinstance(result, dict):
            continue
        status = str(result.get("status", "")).lower()
        if status.startswith("rtsp/") and "200" in status:
            path = result.get("path")
            if isinstance(path, str):
                return f"rtsp://{ip}:{port}{path}"
    return None


def sync_registry(
    conn,
    module_cfg: Dict[str, Any],
    network_snapshot: Dict[str, Any],
    useful: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    registry = load_registry(conn)
    registry_by_key = {_camera_key(cam): cam for cam in registry}

    configured = module_cfg.get("cameras", [])
    if isinstance(configured, list):
        for entry in configured:
            if not isinstance(entry, dict):
                continue
            key = _camera_key(entry)
            registry_by_key[key] = _merge_camera(registry_by_key.get(key, {}), entry)

    known_ips = {
        cam.get("ip")
        for cam in registry_by_key.values()
        if isinstance(cam, dict) and isinstance(cam.get("ip"), str)
    }

    useful_ips = {
        item.get("ip")
        for item in useful
        if isinstance(item, dict) and item.get("label") == "camera"
    }
    devices = network_snapshot.get("devices", []) if isinstance(network_snapshot, dict) else []
    if isinstance(devices, list):
        for device in devices:
            if not isinstance(device, dict):
                continue
            ip = device.get("ip")
            if not isinstance(ip, str):
                continue
            if ip in known_ips:
                continue
            if ip not in useful_ips:
                continue
            key = f"ip:{ip}"
            hints = device.get("hints", [])
            services = device.get("services", [])
            rtsp_url = None
            if isinstance(services, list):
                for service in services:
                    if isinstance(service, dict) and service.get("type") == "rtsp":
                        rtsp_url = service.get("url")
                        break
            candidate = {
                "id": f"camera-{ip}",
                "label": "camera",
                "source": "rtsp" if rtsp_url else "network",
                "ip": ip,
                "rtsp_url": rtsp_url,
                "hints": hints,
                "enabled": True,
                "auto_probe": True,
            }
            registry_by_key[key] = _merge_camera(registry_by_key.get(key, {}), candidate)

    registry = list(registry_by_key.values())

    timeout_seconds = float(module_cfg.get("timeout_seconds", 8))
    max_bytes = int(module_cfg.get("max_rtsp_bytes", 2048))
    for cam in registry:
        if not isinstance(cam, dict):
            continue
        if cam.get("enabled") is not True:
            continue
        if cam.get("rtsp_url"):
            continue
        if not cam.get("auto_probe"):
            continue
        ip = cam.get("ip")
        if not isinstance(ip, str):
            continue
        port = int(cam.get("rtsp_port", 554))
        paths = cam.get("rtsp_paths") or []
        if not isinstance(paths, list) or not paths:
            paths = observe.DEFAULT_RTSP_PATHS
        auth_env = cam.get("auth_env")
        auth = _auth_from_env(auth_env) if isinstance(auth_env, dict) else None
        rtsp_url = _probe_rtsp_url(
            ip=ip,
            port=port,
            paths=paths,
            timeout_seconds=timeout_seconds,
            max_bytes=max_bytes,
            auth=auth,
        )
        if rtsp_url:
            cam["rtsp_url"] = rtsp_url
            cam["rtsp_url_masked"] = _masked_url(rtsp_url)
            cam["last_probe_ts"] = _now_iso()
        else:
            cam["last_probe_ts"] = _now_iso()
            cam["rtsp_url"] = None

    save_registry(conn, registry)
    return registry


def build_rtsp_url(camera: Dict[str, Any]) -> Optional[str]:
    url = camera.get("rtsp_url")
    if not isinstance(url, str) or not url.strip():
        return None
    if "{" not in url:
        return url
    auth_env = camera.get("auth_env")
    auth = _auth_from_env(auth_env) if isinstance(auth_env, dict) else None
    return url.format(user=auth.user or "", password=auth.password or "")


def record_event(conn, event_type: str, payload: Dict[str, Any], severity: str = "info") -> None:
    store.insert_event(conn, source="vision", event_type=event_type, payload=payload, severity=severity)
