"""Camera recording module for Pumpkin v3."""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone, timedelta
import base64
import json
from urllib import error as url_error
from urllib import request
from pathlib import Path
from typing import Any, Dict, List

from . import cameras as cameras_mod
from . import settings
from . import store


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _recording_dir(camera_id: str) -> Path:
    stamp = datetime.now(timezone.utc)
    return (
        settings.data_dir()
        / "camera_recordings"
        / camera_id
        / stamp.strftime("%Y")
        / stamp.strftime("%m")
        / stamp.strftime("%d")
    )


def _record_segment(
    rtsp_url: str,
    output_path: Path,
    duration_seconds: int,
    ffmpeg_path: str,
) -> Dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        args = [
            ffmpeg_path,
            "-hide_banner",
            "-loglevel",
            "error",
            "-rtsp_transport",
            "tcp",
            "-i",
            rtsp_url,
            "-t",
            str(duration_seconds),
            "-an",
            "-c",
            "copy",
            "-reset_timestamps",
            "1",
            "-y",
            str(output_path),
        ]
        subprocess.run(args, check=True, timeout=duration_seconds + 15)
    except subprocess.TimeoutExpired as exc:
        return {"status": "failed", "error": "timeout", "detail": str(exc)}
    except subprocess.CalledProcessError as exc:
        # Fallback to a safe transcode when stream copy fails.
        try:
            args = [
                ffmpeg_path,
                "-hide_banner",
                "-loglevel",
                "error",
                "-rtsp_transport",
                "tcp",
                "-i",
                rtsp_url,
                "-t",
                str(duration_seconds),
                "-an",
                "-c:v",
                "libx264",
                "-preset",
                "veryfast",
                "-movflags",
                "+faststart",
                "-y",
                str(output_path),
            ]
            subprocess.run(args, check=True, timeout=duration_seconds + 25)
        except Exception as exc2:
            return {"status": "failed", "error": "ffmpeg_failed", "detail": f"{exc} | fallback: {exc2}"}
    return {"status": "ok"}


def _capture_frame(output_path: Path, ffmpeg_path: str, sample_seconds: int) -> bytes | None:
    args = [
        ffmpeg_path,
        "-hide_banner",
        "-loglevel",
        "error",
        "-ss",
        str(sample_seconds),
        "-i",
        str(output_path),
        "-frames:v",
        "1",
        "-f",
        "image2pipe",
        "-vcodec",
        "mjpeg",
        "pipe:1",
    ]
    try:
        result = subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    except Exception:
        return None
    return result.stdout if result.stdout else None


def _capture_frame_scaled(output_path: Path, ffmpeg_path: str, sample_seconds: int, width: int = 512) -> bytes | None:
    args = [
        ffmpeg_path,
        "-hide_banner",
        "-loglevel",
        "error",
        "-ss",
        str(sample_seconds),
        "-i",
        str(output_path),
        "-frames:v",
        "1",
        "-vf",
        f"scale={width}:-1",
        "-f",
        "image2pipe",
        "-vcodec",
        "png",
        "pipe:1",
    ]
    try:
        result = subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    except Exception:
        return None
    return result.stdout if result.stdout else None


def _capture_frame_gray(output_path: Path, ffmpeg_path: str, sample_seconds: int, size: int = 32) -> bytes | None:
    args = [
        ffmpeg_path,
        "-hide_banner",
        "-loglevel",
        "error",
        "-ss",
        str(sample_seconds),
        "-i",
        str(output_path),
        "-frames:v",
        "1",
        "-vf",
        f"scale={size}:{size}:flags=area,format=gray",
        "-f",
        "rawvideo",
        "pipe:1",
    ]
    try:
        result = subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    except Exception:
        return None
    return result.stdout if result.stdout else None


def _capture_rtsp_gray(rtsp_url: str, ffmpeg_path: str, sample_seconds: int, size: int = 32) -> bytes | None:
    args = [
        ffmpeg_path,
        "-hide_banner",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-ss",
        str(sample_seconds),
        "-i",
        rtsp_url,
        "-frames:v",
        "1",
        "-vf",
        f"scale={size}:{size}:flags=area,format=gray",
        "-f",
        "rawvideo",
        "pipe:1",
    ]
    try:
        result = subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    except Exception:
        return None
    return result.stdout if result.stdout else None


def _motion_detected(conn, camera_id: str, frame_bytes: bytes | None, threshold: float) -> bool:
    if not frame_bytes:
        return False
    last_key = f"camera.recording.motion_last_frame.{camera_id}"
    prev_b64 = store.get_memory(conn, last_key)
    prev = None
    if isinstance(prev_b64, str):
        try:
            prev = base64.b64decode(prev_b64.encode("ascii"))
        except Exception:
            prev = None
    store.set_memory(conn, last_key, base64.b64encode(frame_bytes).decode("ascii"))
    if prev is None or len(prev) != len(frame_bytes):
        return True
    diff = sum(abs(a - b) for a, b in zip(prev, frame_bytes))
    diff_ratio = diff / (len(frame_bytes) * 255.0)
    if diff_ratio >= threshold:
        store.set_memory(conn, f"camera.recording.motion_last_hit.{camera_id}", _now_iso())
        return True
    return False


def _load_llm_config(conn) -> Dict[str, Any]:
    provider = store.get_memory(conn, "llm.provider") or os.getenv("PUMPKIN_LLM_PROVIDER", "openai")
    api_key = store.get_memory(conn, "llm.openai_api_key") or os.getenv("PUMPKIN_OPENAI_API_KEY")
    model = store.get_memory(conn, "llm.openai_model") or os.getenv("PUMPKIN_OPENAI_MODEL", "gpt-4o-mini")
    base_url = store.get_memory(conn, "llm.openai_base_url") or os.getenv(
        "PUMPKIN_OPENAI_BASE_URL", "https://api.openai.com/v1/chat/completions"
    )
    ollama_url = store.get_memory(conn, "llm.ollama_url") or os.getenv("PUMPKIN_OLLAMA_URL", "http://127.0.0.1:11434")
    ollama_model = store.get_memory(conn, "llm.ollama_model") or os.getenv("PUMPKIN_OLLAMA_MODEL", "llava")
    return {
        "provider": provider,
        "api_key": api_key,
        "model": model,
        "base_url": base_url,
        "ollama_url": ollama_url,
        "ollama_model": ollama_model,
    }


def _call_ollama_vision_json(prompt: str, image_bytes: bytes, cfg: Dict[str, Any]) -> Dict[str, Any]:
    url = cfg.get("ollama_url") or "http://127.0.0.1:11434"
    model = cfg.get("ollama_model") or "llava"
    image_b64 = base64.b64encode(image_bytes).decode("ascii")
    use_generate = str(model).lower().startswith("moondream")
    if use_generate:
        payload = {
            "model": model,
            "prompt": prompt,
            "images": [image_b64],
            "stream": False,
        }
    else:
        payload = {
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                    "images": [image_b64],
                }
            ],
            "stream": False,
        }
    try:
        data = json.dumps(payload).encode("utf-8")
        endpoint = "/api/generate" if use_generate else "/api/chat"
        req = request.Request(
            f"{url.rstrip('/')}{endpoint}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode("utf-8")
    except url_error.HTTPError as exc:
        return {"error": "ollama_http_error", "detail": str(exc)}
    except Exception as exc:
        return {"error": "ollama_request_failed", "detail": str(exc)}
    try:
        data = json.loads(raw)
        if use_generate:
            content = data.get("response")
        else:
            content = data.get("message", {}).get("content")
        if not content:
            return {"error": "ollama_empty_response", "detail": raw[:200]}
        try:
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                return parsed
            return {
                "summary": str(content).strip()[:300],
                "objects": [],
                "activity": None,
                "confidence": 0.4,
                "note": "ollama_non_object_json",
            }
        except Exception:
            return {
                "summary": content.strip(),
                "objects": [],
                "activity": None,
                "confidence": 0.4,
                "note": "ollama_text_fallback",
            }
    except Exception:
        return {"error": "ollama_parse_failed", "detail": raw[:200]}


def _call_openai_vision_json(prompt: str, image_bytes: bytes, cfg: Dict[str, Any]) -> Dict[str, Any]:
    api_key = cfg.get("api_key")
    if not api_key:
        return {"error": "openai_api_key_missing"}
    model = cfg.get("model") or "gpt-4o-mini"
    base_url = cfg.get("base_url") or "https://api.openai.com/v1/chat/completions"
    image_b64 = base64.b64encode(image_bytes).decode("ascii")
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You describe home camera frames. Respond with strict JSON only.",
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
            data = json.loads(resp.read().decode("utf-8"))
    except url_error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            detail = str(exc)
        return {"error": f"openai_http_{getattr(exc, 'code', 'error')}", "detail": detail}
    except url_error.URLError as exc:
        return {"error": "openai_request_failed", "detail": str(exc)}
    except json.JSONDecodeError:
        return {"error": "openai_invalid_json"}
    try:
        content = data["choices"][0]["message"]["content"]
    except Exception:
        return {"error": "openai_response_missing_content"}
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {"error": "openai_response_invalid_json", "raw": content}


def _heuristic_description(conn, camera_id: str, frame_bytes: bytes) -> Dict[str, Any]:
    last_key = f"camera.recording.last_frame.{camera_id}"
    prev_b64 = store.get_memory(conn, last_key)
    prev = None
    if isinstance(prev_b64, str):
        try:
            prev = base64.b64decode(prev_b64.encode("ascii"))
        except Exception:
            prev = None
    # store current frame
    store.set_memory(conn, last_key, base64.b64encode(frame_bytes).decode("ascii"))
    if not frame_bytes:
        return {"summary": "no frame data", "activity": "unknown", "confidence": 0.1}

    # compute mean brightness and diff
    mean_val = sum(frame_bytes) / max(1, len(frame_bytes))
    diff_ratio = None
    if prev and len(prev) == len(frame_bytes):
        diff = sum(abs(a - b) for a, b in zip(prev, frame_bytes))
        diff_ratio = diff / (len(frame_bytes) * 255.0)

    activity = "still"
    confidence = 0.4
    if diff_ratio is None:
        activity = "unknown"
        confidence = 0.2
    elif diff_ratio > 0.2:
        activity = "high movement"
        confidence = min(0.9, 0.5 + diff_ratio)
    elif diff_ratio > 0.08:
        activity = "moderate movement"
        confidence = min(0.8, 0.4 + diff_ratio)
    else:
        activity = "low movement"
        confidence = max(0.3, 0.2 + diff_ratio)

    lighting = "normal"
    if mean_val < 40:
        lighting = "dark"
    elif mean_val > 200:
        lighting = "bright"

    summary = f"{activity}; lighting {lighting}"
    return {"summary": summary, "activity": activity, "confidence": round(confidence, 2)}


def _recent_recognized_names(
    conn, camera_id: str, window_seconds: int = 600, max_names: int = 3
) -> List[str]:
    names: List[str] = []
    rows = store.list_events(conn, limit=200, source="vision", event_type="person.recognized")
    if not rows:
        return names
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    for row in rows:
        try:
            payload = json.loads(row["payload_json"]) if row.get("payload_json") else {}
        except Exception:
            payload = {}
        if str(payload.get("camera_id")) != str(camera_id):
            continue
        ts_raw = row.get("ts")
        if isinstance(ts_raw, str):
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except ValueError:
                ts = None
        else:
            ts = None
        if ts and ts < cutoff:
            continue
        name = payload.get("ha_person_name") or payload.get("name")
        if isinstance(name, str) and name and name not in names:
            names.append(name)
        if len(names) >= max_names:
            break
    return names


def _cleanup_old(recording_root: Path, retention_hours: int) -> int:
    if retention_hours <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(hours=retention_hours)
    removed = 0
    if not recording_root.exists():
        return 0
    for path in recording_root.rglob("*.mp4"):
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except Exception:
            continue
        if mtime < cutoff:
            try:
                path.unlink()
                removed += 1
            except Exception:
                continue
    return removed


def run_recording(conn, module_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not module_cfg.get("enabled", True):
        return events
    camera_id = module_cfg.get("camera_id") or "kitchen-cam"
    duration_seconds = int(module_cfg.get("segment_seconds", 60))
    retention_hours = int(module_cfg.get("retention_hours", 24))
    ffmpeg_path = str(module_cfg.get("ffmpeg_path", "ffmpeg"))
    describe_enabled = bool(module_cfg.get("describe_enabled", False))
    describe_sample_seconds = int(module_cfg.get("describe_sample_seconds", 1))
    describe_fallback = bool(module_cfg.get("describe_fallback", True))
    describe_include_people = bool(module_cfg.get("describe_include_people", True))
    describe_people_window = int(module_cfg.get("describe_people_window_seconds", 600))
    describe_people_max = int(module_cfg.get("describe_people_max", 3))
    motion_only = bool(module_cfg.get("motion_only", False))
    motion_threshold = float(module_cfg.get("motion_threshold", 0.08))
    motion_sample_seconds = int(module_cfg.get("motion_sample_seconds", 1))
    motion_grace_seconds = int(module_cfg.get("motion_grace_seconds", 10))
    describe_prompt = module_cfg.get(
        "describe_prompt",
        "Describe what is happening in this camera frame. Return JSON: {\"summary\": str, \"objects\": [str], \"activity\": str, \"confidence\": float}.",
    )

    registry = cameras_mod.load_registry(conn)
    rtsp_url = None
    label = None
    for cam in registry:
        if str(cam.get("id") or cam.get("ip")) == str(camera_id):
            label = cam.get("label")
            rtsp_url = cameras_mod.build_rtsp_url(cam)
            break
    if not rtsp_url:
        events.append(
            {
                "source": "vision",
                "type": "camera.recording_missing",
                "payload": {"camera_id": camera_id, "error": "rtsp_url_missing"},
                "severity": "warn",
            }
        )
        return events

    if motion_only:
        motion_frame = _capture_rtsp_gray(rtsp_url, ffmpeg_path, motion_sample_seconds)
        has_motion = _motion_detected(conn, str(camera_id), motion_frame, motion_threshold)
        if not has_motion:
            last_hit = store.get_memory(conn, f"camera.recording.motion_last_hit.{camera_id}")
            if last_hit:
                try:
                    last_dt = datetime.fromisoformat(str(last_hit))
                    age = (datetime.now(timezone.utc) - last_dt).total_seconds()
                    if age <= motion_grace_seconds:
                        has_motion = True
                except Exception:
                    has_motion = False
        if not has_motion:
            events.append(
                {
                    "source": "vision",
                    "type": "camera.recording_idle",
                    "payload": {"camera_id": camera_id, "label": label, "reason": "no_motion"},
                    "severity": "info",
                }
            )
            return events

    start_ts = _now_iso()
    output_dir = _recording_dir(str(camera_id))
    filename = f"{camera_id}-{start_ts.replace(':', '').replace('-', '')}.mp4"
    output_path = output_dir / filename
    result = _record_segment(rtsp_url, output_path, duration_seconds, ffmpeg_path)
    if result.get("status") != "ok":
        events.append(
            {
                "source": "vision",
                "type": "camera.recording_failed",
                "payload": {
                    "camera_id": camera_id,
                    "label": label,
                    "error": result.get("error"),
                    "detail": result.get("detail"),
                },
                "severity": "warn",
            }
        )
        return events

    size_bytes = None
    try:
        size_bytes = output_path.stat().st_size
    except Exception:
        size_bytes = None

    description_payload: Dict[str, Any] = {}
    if describe_enabled:
        frame = _capture_frame_scaled(output_path, ffmpeg_path, describe_sample_seconds, width=512)
        if frame:
            if describe_include_people:
                names = _recent_recognized_names(
                    conn,
                    str(camera_id),
                    window_seconds=describe_people_window,
                    max_names=describe_people_max,
                )
                if names:
                    names_text = ", ".join(names)
                    describe_prompt = (
                        f"{describe_prompt}\n"
                        f"Known people recently seen on this camera: {names_text}. "
                        "If you can see them, mention by name; otherwise ignore."
                    )
                    description_payload["description_people"] = names
                    description_payload["description_people_source"] = "recent_recognized"
            llm_cfg = _load_llm_config(conn)
            if str(llm_cfg.get("provider", "openai")).lower() == "ollama":
                analysis = _call_ollama_vision_json(describe_prompt, frame, llm_cfg)
            else:
                analysis = _call_openai_vision_json(describe_prompt, frame, llm_cfg)
            if isinstance(analysis, dict) and analysis.get("error"):
                description_payload = {
                    "description_error": analysis.get("error"),
                    "description_error_detail": analysis.get("detail"),
                }
                if describe_fallback:
                    gray = _capture_frame_gray(output_path, ffmpeg_path, describe_sample_seconds)
                    if gray:
                        fallback = _heuristic_description(conn, str(camera_id), gray)
                        description_payload.update(
                            {
                                "description": fallback.get("summary"),
                                "description_activity": fallback.get("activity"),
                                "description_confidence": fallback.get("confidence"),
                                "description_source": "heuristic",
                            }
                        )
            elif isinstance(analysis, dict):
                description_payload = {
                    "description": analysis.get("summary"),
                    "description_objects": analysis.get("objects"),
                    "description_activity": analysis.get("activity"),
                    "description_confidence": analysis.get("confidence"),
                    "description_source": "llm",
                }

    cameras_mod.record_event(
        conn,
        "camera.recorded",
        {
            "camera_id": camera_id,
            "label": label,
            "path": str(output_path),
            "start_ts": start_ts,
            "duration_seconds": duration_seconds,
            "size_bytes": size_bytes,
            **description_payload,
        },
        severity="info",
    )

    _cleanup_old(settings.data_dir() / "camera_recordings" / str(camera_id), retention_hours)
    return events
