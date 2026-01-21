"""Face recognition pipeline for Pumpkin v3."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib import request, error
from urllib.parse import quote

from . import act
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
    if not isinstance(result, list):
        return None
    if not result:
        return {"face_detected": False}
    candidate = result[0]
    box = candidate.get("box") if isinstance(candidate, dict) else None
    if isinstance(box, dict):
        box = {
            "x_min": box.get("x_min"),
            "y_min": box.get("y_min"),
            "x_max": box.get("x_max"),
            "y_max": box.get("y_max"),
        }
    subjects = candidate.get("subjects") if isinstance(candidate, dict) else None
    if not isinstance(subjects, list):
        return None
    if not subjects:
        return {"face_detected": True, "name": None, "confidence": None, "box": box}
    subject = subjects[0]
    return {
        "name": subject.get("subject"),
        "confidence": subject.get("similarity"),
        "face_detected": True,
        "box": box,
    }


def _compreface_enroll(image_bytes: bytes, subject: str, provider: Dict[str, Any]) -> Dict[str, Any]:
    endpoint = provider.get("endpoint")
    api_key_env = provider.get("api_key_env")
    if not endpoint or not api_key_env:
        return {"ok": False, "error": "provider_not_configured"}
    api_key = os.getenv(str(api_key_env))
    if not api_key:
        return {"ok": False, "error": "missing_api_key"}
    if not subject:
        return {"ok": False, "error": "missing_subject"}
    base = endpoint.rsplit("/", 1)[0]
    enroll_url = f"{base}/subjects/{quote(subject)}/add"
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
    req = request.Request(enroll_url, data=body, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=provider.get("timeout_seconds", 6)) as resp:
            payload = resp.read()
    except error.URLError as exc:
        return {"ok": False, "error": "request_failed", "detail": str(exc)}
    try:
        data = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        data = {"raw": payload.decode("utf-8", errors="replace")}
    return {"ok": True, "response": data}


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
    disabled_alerts = store.get_memory(conn, "vision.alerts.disabled") or []
    if not isinstance(disabled_alerts, list):
        disabled_alerts = []
    disabled_set = {str(item) for item in disabled_alerts}
    false_positives = store.get_memory(conn, "vision.false_positives") or []
    if not isinstance(false_positives, list):
        false_positives = []
    false_positive_set = {str(item) for item in false_positives}

    max_cameras = int(module_cfg.get("max_cameras_per_run", 1))
    timeout_seconds = float(module_cfg.get("timeout_seconds", 8))
    ffmpeg_path = str(module_cfg.get("ffmpeg_path", "ffmpeg"))
    provider = module_cfg.get("provider", {})
    min_confidence = float(provider.get("min_confidence", 0.7)) if isinstance(provider, dict) else 0.7

    def _emit_unknown_alert(camera_id: str, label: Optional[str], snapshot_path: Optional[Path], enabled: bool) -> None:
        if not enabled:
            return
        message = f"Unknown face detected"
        if label:
            message = f"Unknown face detected at {label}"
        events.append(
            {
                "source": "vision",
                "type": "face.alert",
                "payload": {
                    "message": message,
                    "camera_id": camera_id,
                    "label": label,
                    "snapshot_path": str(snapshot_path) if snapshot_path else None,
                    "report_url": "/ui/network",
                },
                "severity": "warn",
            }
        )
        try:
            act.notify_local(message, str(settings.audit_path()))
        except Exception:
            pass

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
        snapshot_hash = hashlib.sha256(frame).hexdigest() if frame else None
        recognition = _recognize_face(frame, provider if isinstance(provider, dict) else {})
        face_box = recognition.get("box") if isinstance(recognition, dict) else None
        if snapshot_hash and snapshot_hash in false_positive_set:
            events.append(
                {
                    "source": "vision",
                    "type": "face.false_positive",
                    "payload": {
                        "camera_id": camera_id,
                        "label": cam.get("label"),
                        "snapshot_path": str(snapshot_path) if snapshot_path else None,
                        "snapshot_hash": snapshot_hash,
                        "face_box": face_box,
                    },
                    "severity": "info",
                }
            )
            processed += 1
            continue
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
                            "snapshot_hash": snapshot_hash,
                            "face_box": face_box,
                        },
                        "severity": "info",
                    }
                )
            else:
                face_detected = bool(recognition.get("face_detected")) if isinstance(recognition, dict) else False
                if face_detected:
                    unknown_payload = {
                        "camera_id": camera_id,
                        "label": cam.get("label"),
                        "snapshot_path": str(snapshot_path) if snapshot_path else None,
                        "snapshot_hash": snapshot_hash,
                        "face_box": face_box,
                    }
                    events.append(
                        {
                            "source": "vision",
                            "type": "face.unknown",
                            "payload": unknown_payload,
                            "severity": "info",
                        }
                    )
                    _emit_unknown_alert(
                        camera_id,
                        cam.get("label"),
                        snapshot_path,
                        bool(cam.get("alert_unknown_faces", True)) and camera_id not in disabled_set,
                    )
        else:
            face_detected = bool(recognition.get("face_detected")) if isinstance(recognition, dict) else False
            if face_detected:
                unknown_payload = {
                    "camera_id": camera_id,
                    "label": cam.get("label"),
                    "snapshot_path": str(snapshot_path) if snapshot_path else None,
                    "snapshot_hash": snapshot_hash,
                    "face_box": face_box,
                }
                events.append(
                    {
                        "source": "vision",
                        "type": "face.unknown",
                        "payload": unknown_payload,
                        "severity": "info",
                    }
                )
                _emit_unknown_alert(
                    camera_id,
                    cam.get("label"),
                    snapshot_path,
                    bool(cam.get("alert_unknown_faces", True)) and camera_id not in disabled_set,
                )
        processed += 1

    if events:
        store.set_memory(conn, "vision.last", {"ts": _now_iso(), "events": events[-10:]})
    return events
