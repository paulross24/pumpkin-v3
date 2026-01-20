"""Face recognition pipeline for Pumpkin v3."""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib import request, error

from . import cameras as cameras_mod
from . import settings, store


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _capture_dir() -> Path:
    path = settings.data_dir() / "camera_captures"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _mask_url(url: str) -> str:
    if "@" not in url or "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    creds, host = rest.split("@", 1)
    if ":" in creds:
        user = creds.split(":", 1)[0]
        return f"{scheme}://{user}:***@{host}"
    return f"{scheme}://***@{host}"


def _capture_rtsp(url: str, timeout_seconds: float, ffmpeg_path: str) -> Optional[bytes]:
    cmd = [
        ffmpeg_path,
        "-hide_banner",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-stimeout",
        str(int(timeout_seconds * 1_000_000)),
        "-i",
        url,
        "-frames:v",
        "1",
        "-f",
        "image2pipe",
        "-vcodec",
        "mjpeg",
        "-",
    ]
    try:
        result = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds + 5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout:
        return None
    return result.stdout


def _save_snapshot(camera_id: str, payload: bytes) -> Optional[Path]:
    if not payload:
        return None
    capture_dir = _capture_dir()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    name = f"{camera_id}-{stamp}.jpg"
    path = capture_dir / name
    path.write_bytes(payload)
    return path


def _compreface_recognize(image_bytes: bytes, provider: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    endpoint = provider.get("endpoint")
    api_key_env = provider.get("api_key_env")
    if not endpoint or not api_key_env:
        return None
    api_key = os.getenv(str(api_key_env))
    if not api_key:
        return None
    boundary = f"----pumpkin-{uuid.uuid4().hex}"
    body = (
        f"--{boundary}\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"frame.jpg\"\r\n"
        "Content-Type: image/jpeg\r\n\r\n"
    ).encode("utf-8") + image_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "x-api-key": api_key,
    }
    req = request.Request(endpoint, data=body, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=provider.get("timeout_seconds", 6)) as resp:
            payload = resp.read()
    except error.URLError:
        return None
    try:
        data = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        return None
    result = data.get("result") if isinstance(data, dict) else None
    if not isinstance(result, list) or not result:
        return None
    candidate = result[0]
    subjects = candidate.get("subjects") if isinstance(candidate, dict) else None
    if not isinstance(subjects, list) or not subjects:
        return None
    subject = subjects[0]
    return {
        "name": subject.get("subject"),
        "confidence": subject.get("similarity"),
    }


def _recognize_face(image_bytes: bytes, provider: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not provider:
        return None
    provider_type = provider.get("type", "none")
    if provider_type == "compreface":
        return _compreface_recognize(image_bytes, provider)
    return None


def run_face_recognition(conn, module_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not module_cfg.get("enabled", False):
        return events

    network_snapshot = store.get_memory(conn, "network.discovery.snapshot") or {}
    useful = store.get_memory(conn, "network.discovery.useful") or []
    cameras = cameras_mod.sync_registry(conn, module_cfg, network_snapshot, useful)

    max_cameras = int(module_cfg.get("max_cameras_per_run", 1))
    timeout_seconds = float(module_cfg.get("timeout_seconds", 8))
    ffmpeg_path = str(module_cfg.get("ffmpeg_path", "ffmpeg"))
    provider = module_cfg.get("provider", {})
    min_confidence = float(provider.get("min_confidence", 0.7)) if isinstance(provider, dict) else 0.7

    processed = 0
    for cam in cameras:
        if processed >= max_cameras:
            break
        if not isinstance(cam, dict) or cam.get("enabled") is not True:
            continue
        camera_id = cam.get("id") or cam.get("ip") or "camera"
        rtsp_url = cameras_mod.build_rtsp_url(cam)
        if not rtsp_url:
            events.append(
                {
                    "source": "vision",
                    "type": "camera.stream_missing",
                    "payload": {"camera_id": camera_id, "label": cam.get("label")},
                    "severity": "warn",
                }
            )
            continue
        frame = _capture_rtsp(rtsp_url, timeout_seconds, ffmpeg_path)
        if not frame:
            events.append(
                {
                    "source": "vision",
                    "type": "camera.capture_failed",
                    "payload": {"camera_id": camera_id, "rtsp_url": _mask_url(rtsp_url)},
                    "severity": "warn",
                }
            )
            continue
        snapshot_path = _save_snapshot(str(camera_id), frame)
        recognition = _recognize_face(frame, provider if isinstance(provider, dict) else {})
        if recognition and recognition.get("name") and recognition.get("confidence") is not None:
            if float(recognition["confidence"]) >= min_confidence:
                events.append(
                    {
                        "source": "vision",
                        "type": "person.recognized",
                        "payload": {
                            "camera_id": camera_id,
                            "label": cam.get("label"),
                            "name": recognition.get("name"),
                            "confidence": recognition.get("confidence"),
                            "snapshot_path": str(snapshot_path) if snapshot_path else None,
                        },
                        "severity": "info",
                    }
                )
            else:
                events.append(
                    {
                        "source": "vision",
                        "type": "face.unknown",
                        "payload": {
                            "camera_id": camera_id,
                            "label": cam.get("label"),
                            "snapshot_path": str(snapshot_path) if snapshot_path else None,
                        },
                        "severity": "info",
                    }
                )
        else:
            events.append(
                {
                    "source": "vision",
                    "type": "face.unknown",
                    "payload": {
                        "camera_id": camera_id,
                        "label": cam.get("label"),
                        "snapshot_path": str(snapshot_path) if snapshot_path else None,
                    },
                    "severity": "info",
                }
            )
        processed += 1

    if events:
        store.set_memory(conn, "vision.last", {"ts": _now_iso(), "events": events[-10:]})
    return events
