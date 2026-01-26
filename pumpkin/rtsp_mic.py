"""RTSP microphone listener for simple voice command ingestion."""

from __future__ import annotations

import io
import json
import math
import os
import re
import subprocess
import tempfile
import time
import wave
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib import error, request

from . import cameras as cameras_mod
from . import store


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_llm_config(conn) -> Dict[str, Any]:
    api_key = store.get_memory(conn, "llm.openai_api_key") or os.getenv("PUMPKIN_OPENAI_API_KEY")
    model = store.get_memory(conn, "llm.openai_audio_model") or os.getenv("PUMPKIN_OPENAI_AUDIO_MODEL", "whisper-1")
    return {"api_key": api_key, "model": model}


def _capture_audio_pcm(
    url: str,
    seconds: float,
    ffmpeg_path: str,
    sample_rate: int,
    channels: int,
) -> Optional[bytes]:
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
        "-ac",
        str(channels),
        "-ar",
        str(sample_rate),
        "-f",
        "s16le",
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
    if result.returncode != 0 or not result.stdout:
        return None
    return result.stdout


def _pcm_rms_db(pcm: bytes) -> Optional[float]:
    if not pcm:
        return None
    if len(pcm) < 4:
        return None
    sample_count = len(pcm) // 2
    total = 0.0
    for i in range(0, len(pcm), 2):
        sample = int.from_bytes(pcm[i : i + 2], "little", signed=True)
        total += sample * sample
    if sample_count == 0:
        return None
    rms = math.sqrt(total / sample_count)
    if rms <= 0:
        return None
    db = 20.0 * math.log10(rms / 32768.0)
    return db


def _pcm_to_wav_bytes(pcm: bytes, sample_rate: int, channels: int) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(pcm)
    return buf.getvalue()


def _openai_transcribe_audio(audio_bytes: bytes, model: str, api_key: str) -> Optional[str]:
    boundary = f"----pumpkin-{int(time.time())}"
    fields = []
    fields.append(
        f"--{boundary}\r\n"
        "Content-Disposition: form-data; name=\"model\"\r\n\r\n"
        f"{model}\r\n"
    )
    fields.append(
        f"--{boundary}\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"audio.wav\"\r\n"
        "Content-Type: audio/wav\r\n\r\n"
    )
    body = "".join(fields).encode("utf-8") + audio_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")
    req = request.Request(
        "https://api.openai.com/v1/audio/transcriptions",
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=25) as resp:
            raw = resp.read()
    except error.URLError:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return None
    text = data.get("text")
    if isinstance(text, str):
        return text.strip()
    return None


def _post_ask(payload: Dict[str, Any], async_flag: bool) -> bool:
    data = dict(payload)
    if async_flag:
        data["async"] = True
    req = request.Request(
        "http://127.0.0.1:9000/ask",
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as resp:
            resp.read()
            return resp.status == 200
    except Exception:
        return False


def _contains_wake_word(text: str, wake_words: List[str]) -> bool:
    hay = text.lower()
    for word in wake_words:
        needle = word.strip().lower()
        if not needle:
            continue
        if re.search(rf"\\b{re.escape(needle)}\\b", hay):
            return True
        if len(needle) >= 4 and needle in hay:
            return True
    return False


def _play_wake_beep(cfg: Dict[str, Any]) -> bool:
    if not cfg.get("enabled", False):
        return False
    aplay = cfg.get("aplay_path", "aplay")
    freq_hz = float(cfg.get("frequency_hz", 880.0))
    duration_ms = int(cfg.get("duration_ms", 120))
    volume = float(cfg.get("volume", 0.2))
    if duration_ms <= 0 or freq_hz <= 0:
        return False

    sample_rate = 16000
    samples = int(sample_rate * (duration_ms / 1000.0))
    amplitude = max(0.0, min(1.0, volume)) * 32767.0
    data = bytearray()
    for i in range(samples):
        value = int(amplitude * math.sin(2.0 * math.pi * freq_hz * i / sample_rate))
        data += value.to_bytes(2, byteorder="little", signed=True)

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as tmp:
            wav_path = tmp.name
            with wave.open(tmp, "wb") as wav:
                wav.setnchannels(1)
                wav.setsampwidth(2)
                wav.setframerate(sample_rate)
                wav.writeframes(bytes(data))
        subprocess.run([aplay, "-q", wav_path], check=False, timeout=2)
        return True
    except Exception:
        return False


def _find_camera_url(conn, camera_id: Optional[str]) -> Optional[str]:
    if not camera_id:
        return None
    cams = cameras_mod.load_registry(conn)
    for cam in cams:
        if not isinstance(cam, dict):
            continue
        if str(cam.get("id")) == str(camera_id):
            return cameras_mod.build_rtsp_url(cam)
    return None


def run_rtsp_mic(conn, module_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not module_cfg.get("enabled", False):
        return events

    cooldown_seconds = int(module_cfg.get("cooldown_seconds", 15))
    last_ts = store.get_memory(conn, "voice.mic_rtsp.last_ts")
    if isinstance(last_ts, (int, float)):
        if time.time() - float(last_ts) < cooldown_seconds:
            return events

    camera_id = module_cfg.get("camera_id")
    rtsp_url = module_cfg.get("rtsp_url") or _find_camera_url(conn, camera_id)
    if not rtsp_url:
        events.append(
            {
                "source": "voice",
                "type": "voice.mic_error",
                "payload": {"error": "rtsp_url_missing", "camera_id": camera_id},
                "severity": "warn",
            }
        )
        return events

    debug_enabled = bool(module_cfg.get("debug", False))
    capture_seconds = float(module_cfg.get("capture_seconds", 2.5))
    threshold_db = float(module_cfg.get("threshold_db", -28.0))
    sample_rate = int(module_cfg.get("sample_rate", 16000))
    channels = int(module_cfg.get("channels", 1))
    ffmpeg_path = str(module_cfg.get("ffmpeg_path", "ffmpeg"))
    wake_words = module_cfg.get("wake_words") or []
    if not isinstance(wake_words, list):
        wake_words = []
    wake_words = [str(word) for word in wake_words if word]
    min_chars = int(module_cfg.get("min_chars", 4))
    async_flag = bool(module_cfg.get("post_async", True))
    wake_beep_cfg = module_cfg.get("wake_beep", {}) if isinstance(module_cfg.get("wake_beep"), dict) else {}

    pcm = _capture_audio_pcm(rtsp_url, capture_seconds, ffmpeg_path, sample_rate, channels)
    if not pcm:
        if debug_enabled:
            events.append(
                {
                    "source": "voice",
                    "type": "voice.mic_debug",
                    "payload": {
                        "camera_id": camera_id,
                        "stage": "capture",
                        "status": "no_audio",
                    },
                    "severity": "info",
                }
            )
        return events
    level_db = _pcm_rms_db(pcm)
    if level_db is None or level_db < threshold_db:
        if debug_enabled:
            events.append(
                {
                    "source": "voice",
                    "type": "voice.mic_debug",
                    "payload": {
                        "camera_id": camera_id,
                        "stage": "threshold",
                        "status": "below_threshold",
                        "level_db": level_db,
                        "threshold_db": threshold_db,
                    },
                    "severity": "info",
                }
            )
        return events

    llm_cfg = _load_llm_config(conn)
    api_key = llm_cfg.get("api_key")
    if not api_key:
        events.append(
            {
                "source": "voice",
                "type": "voice.mic_error",
                "payload": {"error": "openai_api_key_missing", "camera_id": camera_id},
                "severity": "warn",
            }
        )
        return events

    wav_bytes = _pcm_to_wav_bytes(pcm, sample_rate, channels)
    transcript = _openai_transcribe_audio(wav_bytes, llm_cfg.get("model", "whisper-1"), api_key)
    if not transcript:
        if debug_enabled:
            events.append(
                {
                    "source": "voice",
                    "type": "voice.mic_debug",
                    "payload": {
                        "camera_id": camera_id,
                        "stage": "transcribe",
                        "status": "empty",
                        "level_db": level_db,
                    },
                    "severity": "info",
                }
            )
        return events

    cleaned = " ".join(transcript.split())
    if len(cleaned) < min_chars:
        if debug_enabled:
            events.append(
                {
                    "source": "voice",
                    "type": "voice.mic_debug",
                    "payload": {
                        "camera_id": camera_id,
                        "stage": "min_chars",
                        "status": "too_short",
                        "level_db": level_db,
                        "text": cleaned,
                    },
                    "severity": "info",
                }
            )
        return events
    if wake_words and not _contains_wake_word(cleaned, wake_words):
        if debug_enabled:
            events.append(
                {
                    "source": "voice",
                    "type": "voice.mic_debug",
                    "payload": {
                        "camera_id": camera_id,
                        "stage": "wake_word",
                        "status": "miss",
                        "level_db": level_db,
                        "text": cleaned,
                        "wake_words": wake_words,
                    },
                    "severity": "info",
                }
            )
        return events
    if debug_enabled:
        events.append(
            {
                "source": "voice",
                "type": "voice.mic_debug",
                "payload": {
                    "camera_id": camera_id,
                    "stage": "wake_word",
                    "status": "hit",
                    "level_db": level_db,
                    "text": cleaned,
                },
                "severity": "info",
            }
        )
    _play_wake_beep(wake_beep_cfg)

    payload = {
        "text": cleaned,
        "source": "kitchen_mic",
        "device": camera_id or "kitchen-cam",
        "ts": _now_iso(),
    }
    ok = _post_ask(payload, async_flag)
    events.append(
        {
            "source": "voice",
            "type": "voice.mic_forwarded" if ok else "voice.mic_failed",
            "payload": {
                "camera_id": camera_id,
                "level_db": level_db,
                "text": cleaned,
            },
            "severity": "info" if ok else "warn",
        }
    )
    store.set_memory(conn, "voice.mic_rtsp.last_ts", time.time())
    return events
