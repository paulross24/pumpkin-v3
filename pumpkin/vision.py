"""Face recognition pipeline for Pumpkin v3."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
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
from . import module_config
from . import presence


def _load_ha_people(conn) -> List[Dict[str, Any]]:
    summary = store.get_memory(conn, "homeassistant.summary")
    if isinstance(summary, dict):
        people = summary.get("people")
        if isinstance(people, list):
            return [item for item in people if isinstance(item, dict)]
    entities = store.get_memory(conn, "homeassistant.entities")
    people = []
    if isinstance(entities, dict):
        for entity_id, payload in entities.items():
            if not isinstance(entity_id, str) or not entity_id.startswith("person."):
                continue
            if not isinstance(payload, dict):
                continue
            attributes = payload.get("attributes", {}) if isinstance(payload.get("attributes"), dict) else {}
            name = attributes.get("friendly_name") or entity_id
            people.append({"entity_id": entity_id, "name": str(name), "state": payload.get("state")})
    return people


def _match_ha_person(name: str, people: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not name:
        return None
    needle = name.strip().lower()
    for person in people:
        pname = str(person.get("name") or "").strip().lower()
        entity_id = str(person.get("entity_id") or "")
        entity_tail = entity_id.split(".", 1)[-1].lower() if "." in entity_id else entity_id.lower()
        if needle == pname or needle == entity_id.lower() or needle == entity_tail:
            return person
    return None


def _load_smart_alerts_cfg() -> Dict[str, Any]:
    config_path = settings.modules_config_path()
    if not config_path.exists():
        return {}
    try:
        config = module_config.load_config(str(config_path))
    except Exception:
        return {}
    modules_cfg = config.get("modules", {}) if isinstance(config, dict) else {}
    cfg = modules_cfg.get("smart_alerts") if isinstance(modules_cfg, dict) else {}
    return cfg if isinstance(cfg, dict) else {}


def _alert_requires_empty(kind: str, cfg: Dict[str, Any]) -> bool:
    if not cfg or not cfg.get("enabled", True):
        return False
    if kind == "unknown_face":
        return bool(cfg.get("unknown_faces_when_empty", True))
    if kind == "dog_behavior":
        return bool(cfg.get("dog_behavior_when_empty", True))
    return False


def _alert_allowed(conn, kind: str, cfg: Dict[str, Any]) -> bool:
    if not _alert_requires_empty(kind, cfg):
        return True
    return presence.is_house_empty(conn)


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
        "info",
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


def _capture_audio_level_db(url: str, seconds: float, ffmpeg_path: str) -> Optional[float]:
    cmd = [
        ffmpeg_path,
        "-hide_banner",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-t",
        str(seconds),
        "-i",
        url,
        "-vn",
        "-af",
        "astats=metadata=1:reset=1",
        "-f",
        "null",
        "-",
    ]
    try:
        result = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=seconds + 5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    stderr = result.stderr.decode("utf-8", errors="ignore")
    matches = re.findall(r"RMS level dB:\\s*([-\\d\\.]+)", stderr)
    if not matches:
        matches = re.findall(r"Peak level dB:\\s*([-\\d\\.]+)", stderr)
    levels = []
    for item in matches:
        try:
            levels.append(float(item))
        except ValueError:
            continue
    return max(levels) if levels else None


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
    # CompreFace enroll uses /faces with subject as query parameter.
    enroll_url = f"{base}/faces?subject={quote(subject)}"
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
    except error.HTTPError as exc:
        try:
            payload = exc.read()
        except Exception:
            payload = b""
        detail = payload.decode("utf-8", errors="replace") if payload else ""
        return {
            "ok": False,
            "error": "compreface_error",
            "status": getattr(exc, "code", None),
            "detail": detail or str(exc),
        }
    except error.URLError as exc:
        return {"ok": False, "error": "request_failed", "detail": str(exc)}
    try:
        data = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        data = {"raw": payload.decode("utf-8", errors="replace")}
    return {"ok": True, "response": data}


def _load_llm_config(conn) -> Dict[str, Any]:
    api_key = store.get_memory(conn, "llm.openai_api_key") or os.getenv("PUMPKIN_OPENAI_API_KEY")
    model = store.get_memory(conn, "llm.openai_model") or os.getenv("PUMPKIN_OPENAI_MODEL", "gpt-4o-mini")
    base_url = store.get_memory(conn, "llm.openai_base_url") or os.getenv(
        "PUMPKIN_OPENAI_BASE_URL", "https://api.openai.com/v1/chat/completions"
    )
    return {"api_key": api_key, "model": model, "base_url": base_url}


def _call_openai_vision_json(prompt: str, image_bytes: bytes, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    api_key = cfg.get("api_key")
    if not api_key:
        return None
    model = cfg.get("model") or "gpt-4o-mini"
    base_url = cfg.get("base_url") or "https://api.openai.com/v1/chat/completions"
    image_b64 = base64.b64encode(image_bytes).decode("ascii")
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You analyze home camera images for dog behavior. Respond with strict JSON only.",
            },
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{image_b64}"},
                    },
                ],
            },
        ],
        "temperature": 0.2,
        "max_tokens": 220,
    }
    req = request.Request(
        base_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
    except Exception:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return None
    try:
        content = data["choices"][0]["message"]["content"]
    except Exception:
        return None
    content = content.strip()
    if not content:
        return None
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        match = re.search(r"\\{.*\\}", content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                return None
    return None


def _behavior_prompt(dog_names: List[str], forbidden_objects: List[str], countertop_watch: bool) -> str:
    dog_list = ", ".join(dog_names) if dog_names else "unknown"
    object_list = ", ".join(forbidden_objects) if forbidden_objects else "none"
    countertop_text = "yes" if countertop_watch else "no"
    return (
        "Inspect the image for dog misbehavior. "
        f"Known dog names: {dog_list}. "
        f"Forbidden objects: {object_list}. "
        f"Countertop watching enabled: {countertop_text}. "
        "Return JSON with keys: alert (bool), reasons (list), description (string), dog_name (string or null). "
        "Reasons can include: chewing, wrong_object, counter_surfing, destructive_play. "
        "If unsure, set alert false."
    )


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
    behavior_state = store.get_memory(conn, "vision.behavior.last_alerts") or {}
    if not isinstance(behavior_state, dict):
        behavior_state = {}

    max_cameras = int(module_cfg.get("max_cameras_per_run", 1))
    timeout_seconds = float(module_cfg.get("timeout_seconds", 8))
    ffmpeg_path = str(module_cfg.get("ffmpeg_path", "ffmpeg"))
    provider = module_cfg.get("provider", {})
    behavior_cfg = module_cfg.get("behavior", {}) if isinstance(module_cfg.get("behavior"), dict) else {}
    behavior_enabled = bool(behavior_cfg.get("enabled", False))
    min_confidence = float(provider.get("min_confidence", 0.7)) if isinstance(provider, dict) else 0.7
    api_key_env = provider.get("api_key_env") if isinstance(provider, dict) else None
    provider_configured = bool(
        isinstance(provider, dict)
        and provider.get("type") == "compreface"
        and provider.get("endpoint")
        and api_key_env
        and os.getenv(str(api_key_env))
    )
    stats = {
        "ts": _now_iso(),
        "provider_configured": provider_configured,
        "cameras_total": len(cameras),
        "cameras_processed": 0,
        "captures_ok": 0,
        "captures_failed": 0,
        "faces_detected": 0,
        "recognized": 0,
        "unknown": 0,
        "no_faces": 0,
        "last_error": None,
        "snapshots": [],
    }

    def _emit_unknown_alert(
        camera_id: str,
        label: Optional[str],
        snapshot_path: Optional[Path],
        enabled: bool,
        snapshot_hash: Optional[str],
        face_box: Optional[Dict[str, Any]],
    ) -> None:
        if not enabled:
            return
        if not _alert_allowed(conn, "unknown_face", smart_cfg):
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
                    "snapshot_hash": snapshot_hash,
                    "face_box": face_box,
                    "report_url": "/ui/vision",
                },
                "severity": "warn",
            }
        )
        try:
            act.notify_local(message, str(settings.audit_path()))
        except Exception:
            pass

    processed = 0
    subject_map = store.get_memory(conn, "vision.subject_person_map") or {}
    if not isinstance(subject_map, dict):
        subject_map = {}
    ha_people = _load_ha_people(conn)
    llm_cfg = _load_llm_config(conn) if behavior_enabled else {}
    smart_cfg = _load_smart_alerts_cfg()
    alert_cooldown = int(behavior_cfg.get("alert_cooldown_minutes", 30))
    behavior_camera_ids = behavior_cfg.get("camera_ids") or []
    if not isinstance(behavior_camera_ids, list):
        behavior_camera_ids = []
    behavior_camera_ids = [str(item) for item in behavior_camera_ids if item]
    dog_names = behavior_cfg.get("dog_names") or []
    if not isinstance(dog_names, list):
        dog_names = []
    dog_names = [str(item) for item in dog_names if item]
    forbidden_objects = behavior_cfg.get("forbidden_objects") or []
    if not isinstance(forbidden_objects, list):
        forbidden_objects = []
    forbidden_objects = [str(item) for item in forbidden_objects if item]
    countertop_watch = bool(behavior_cfg.get("countertop_watch", False))
    visual_cfg = behavior_cfg.get("visual") or {}
    if not isinstance(visual_cfg, dict):
        visual_cfg = {}
    audio_cfg = behavior_cfg.get("bark_audio") or {}
    if not isinstance(audio_cfg, dict):
        audio_cfg = {}
    behavior_alert_allowed = _alert_allowed(conn, "dog_behavior", smart_cfg)
    for cam in cameras:
        if processed >= max_cameras:
            break
        if not isinstance(cam, dict) or cam.get("enabled") is not True:
            continue
        camera_id = cam.get("id") or cam.get("ip") or "camera"
        rtsp_url = cameras_mod.build_rtsp_url(cam)
        if not rtsp_url:
            stats["cameras_processed"] = processed + 1
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
            stats["captures_failed"] += 1
            stats["last_error"] = {"camera_id": camera_id, "error": "capture_failed"}
            stats["cameras_processed"] = processed + 1
            events.append(
                {
                    "source": "vision",
                    "type": "camera.capture_failed",
                    "payload": {"camera_id": camera_id, "rtsp_url": _mask_url(rtsp_url)},
                    "severity": "warn",
                }
            )
            continue
        stats["captures_ok"] += 1
        snapshot_path = _save_snapshot(str(camera_id), frame)
        snapshot_hash = hashlib.sha256(frame).hexdigest() if frame else None
        if snapshot_path:
            stats["snapshots"].append(
                {
                    "camera_id": camera_id,
                    "label": cam.get("label"),
                    "snapshot_path": str(snapshot_path),
                    "snapshot_hash": snapshot_hash,
                }
            )
            stats["snapshots"] = stats["snapshots"][-5:]
        recognition = _recognize_face(frame, provider if isinstance(provider, dict) else {})
        face_box = recognition.get("box") if isinstance(recognition, dict) else None
        face_detected = bool(recognition.get("face_detected")) if isinstance(recognition, dict) else False
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
            if face_detected:
                stats["faces_detected"] += 1
                stats["unknown"] += 1
            else:
                stats["no_faces"] += 1
            processed += 1
            continue
        if recognition and recognition.get("name") and recognition.get("confidence") is not None:
            if float(recognition["confidence"]) >= min_confidence:
                subject = recognition.get("name")
                match = None
                if isinstance(subject, str) and subject in subject_map:
                    match = subject_map.get(subject)
                if not match and isinstance(subject, str):
                    match = _match_ha_person(subject, ha_people)
                    if match:
                        subject_map[subject] = {
                            "entity_id": match.get("entity_id"),
                            "name": match.get("name"),
                        }
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
                            "ha_person_id": match.get("entity_id") if isinstance(match, dict) else None,
                            "ha_person_name": match.get("name") if isinstance(match, dict) else None,
                        },
                        "severity": "info",
                    }
                )
                stats["faces_detected"] += 1
                stats["recognized"] += 1
            else:
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
                    stats["faces_detected"] += 1
                    stats["unknown"] += 1
                    _emit_unknown_alert(
                        camera_id,
                        cam.get("label"),
                        snapshot_path,
                        bool(cam.get("alert_unknown_faces", True)) and camera_id not in disabled_set,
                        snapshot_hash,
                        face_box,
                    )
                else:
                    stats["no_faces"] += 1
        else:
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
                stats["faces_detected"] += 1
                stats["unknown"] += 1
                _emit_unknown_alert(
                    camera_id,
                    cam.get("label"),
                    snapshot_path,
                    bool(cam.get("alert_unknown_faces", True)) and camera_id not in disabled_set,
                    snapshot_hash,
                    face_box,
                )
            else:
                stats["no_faces"] += 1
        if behavior_enabled:
            if not behavior_alert_allowed:
                stats["cameras_processed"] = processed + 1
                processed += 1
                continue
            allowed = True
            if behavior_camera_ids and str(camera_id) not in behavior_camera_ids:
                allowed = False
            if allowed:
                last_ts = behavior_state.get(str(camera_id))
                if isinstance(last_ts, str):
                    try:
                        last_dt = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
                        delta = datetime.now(timezone.utc) - last_dt
                        if delta.total_seconds() < alert_cooldown * 60:
                            allowed = False
                    except ValueError:
                        pass
            if allowed:
                reasons: List[str] = []
                description = None
                dog_name = None
                if audio_cfg.get("enabled", False):
                    audio_seconds = float(audio_cfg.get("seconds", 2))
                    threshold_db = float(audio_cfg.get("threshold_db", -20.0))
                    level_db = _capture_audio_level_db(rtsp_url, audio_seconds, ffmpeg_path)
                    if level_db is not None and level_db >= threshold_db:
                        reasons.append(f"barking (audio {level_db:.1f} dB)")
                if visual_cfg.get("enabled", False) and llm_cfg.get("api_key"):
                    prompt = _behavior_prompt(dog_names, forbidden_objects, countertop_watch)
                    analysis = _call_openai_vision_json(prompt, frame, llm_cfg)
                    if isinstance(analysis, dict) and analysis.get("alert") is True:
                        analysis_reasons = analysis.get("reasons")
                        if isinstance(analysis_reasons, list):
                            for item in analysis_reasons:
                                if item:
                                    reasons.append(str(item))
                        description = analysis.get("description") if analysis.get("description") else description
                        dog_name = analysis.get("dog_name") if analysis.get("dog_name") else dog_name
                if reasons:
                    message = "Dog behavior alert"
                    if cam.get("label"):
                        message = f"Dog behavior alert at {cam.get('label')}"
                    if dog_name:
                        message += f" ({dog_name})"
                    message += f": {', '.join(reasons)}"
                    events.append(
                        {
                            "source": "vision",
                            "type": "behavior.alert",
                            "payload": {
                                "message": message,
                                "camera_id": camera_id,
                                "label": cam.get("label"),
                                "snapshot_path": str(snapshot_path) if snapshot_path else None,
                                "snapshot_hash": snapshot_hash,
                                "reasons": reasons,
                                "description": description,
                                "dog_name": dog_name,
                                "report_url": "/ui/vision",
                            },
                            "severity": "warn",
                        }
                    )
                    behavior_state[str(camera_id)] = _now_iso()
                    try:
                        act.notify_local(message, str(settings.audit_path()))
                    except Exception:
                        pass
        stats["cameras_processed"] = processed + 1
        processed += 1

    if subject_map:
        store.set_memory(conn, "vision.subject_person_map", subject_map)
    if behavior_enabled:
        store.set_memory(conn, "vision.behavior.last_alerts", behavior_state)
    store.set_memory(conn, "vision.stats", stats)
    if events:
        store.set_memory(conn, "vision.last", {"ts": _now_iso(), "events": events[-10:]})
    return events
