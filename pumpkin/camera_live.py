"""Live camera streaming via HLS."""

from __future__ import annotations

import os
import signal
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import quote

from . import cameras as cameras_mod
from . import settings
from . import store


LIVE_ROOT = "camera_live"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _live_dir(camera_id: str) -> Path:
    return settings.data_dir() / LIVE_ROOT / camera_id


def _playlist_path(camera_id: str) -> Path:
    return _live_dir(camera_id) / "index.m3u8"


def _segment_base_url(camera_id: str) -> str:
    return f"/camera/live/segment?camera_id={quote(camera_id)}&file="


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _terminate(pid: int) -> None:
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except Exception:
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass


def _playlist_fresh(path: Path, stale_seconds: int) -> bool:
    if not path.exists():
        return False
    try:
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except Exception:
        return False
    return (datetime.now(timezone.utc) - mtime) <= timedelta(seconds=stale_seconds)


def _load_state(conn) -> Dict[str, Any]:
    state = store.get_memory(conn, "camera.live")
    if not isinstance(state, dict):
        state = {}
    return state


def _save_state(conn, state: Dict[str, Any]) -> None:
    store.set_memory(conn, "camera.live", state)


def _start_live(
    camera_id: str,
    rtsp_url: str,
    segment_seconds: int,
    list_size: int,
    ffmpeg_path: str,
) -> Dict[str, Any]:
    live_dir = _live_dir(camera_id)
    live_dir.mkdir(parents=True, exist_ok=True)
    playlist = _playlist_path(camera_id)
    base_url = _segment_base_url(camera_id)
    segment_pattern = str(live_dir / "seg_%03d.ts")

    args = [
        ffmpeg_path,
        "-hide_banner",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-i",
        rtsp_url,
        "-an",
        "-c:v",
        "copy",
        "-f",
        "hls",
        "-hls_time",
        str(segment_seconds),
        "-hls_list_size",
        str(list_size),
        "-hls_flags",
        "delete_segments+program_date_time",
        "-hls_base_url",
        base_url,
        "-hls_segment_filename",
        segment_pattern,
        "-y",
        str(playlist),
    ]
    proc = subprocess.Popen(
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return {
        "pid": proc.pid,
        "playlist": str(playlist),
        "started_at": _now_iso(),
    }


def ensure_live(conn, module_cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not module_cfg.get("enabled", True):
        return events
    camera_id = str(module_cfg.get("camera_id") or "kitchen-cam")
    segment_seconds = int(module_cfg.get("segment_seconds", 2))
    list_size = int(module_cfg.get("list_size", 6))
    ffmpeg_path = str(module_cfg.get("ffmpeg_path", "ffmpeg"))
    stale_seconds = int(module_cfg.get("stale_seconds", 10))

    registry = cameras_mod.load_registry(conn)
    rtsp_url = None
    label = None
    for cam in registry:
        if str(cam.get("id") or cam.get("ip")) == camera_id:
            label = cam.get("label")
            rtsp_url = cameras_mod.build_rtsp_url(cam)
            break
    if not rtsp_url:
        events.append(
            {
                "source": "vision",
                "type": "camera.live_missing",
                "payload": {"camera_id": camera_id, "error": "rtsp_url_missing"},
                "severity": "warn",
            }
        )
        return events

    state = _load_state(conn)
    cam_state = state.get(camera_id, {}) if isinstance(state.get(camera_id), dict) else {}
    pid = cam_state.get("pid")
    playlist_path = _playlist_path(camera_id)
    alive = isinstance(pid, int) and _pid_alive(pid)
    fresh = _playlist_fresh(playlist_path, stale_seconds)

    if alive and fresh:
        cam_state["last_seen"] = _now_iso()
        state[camera_id] = cam_state
        _save_state(conn, state)
        return events

    if alive:
        _terminate(pid)

    try:
        started = _start_live(camera_id, rtsp_url, segment_seconds, list_size, ffmpeg_path)
        cam_state.update(
            {
                "pid": started["pid"],
                "playlist": started["playlist"],
                "started_at": started["started_at"],
                "label": label,
            }
        )
        state[camera_id] = cam_state
        _save_state(conn, state)
        store.insert_event(
            conn,
            source="vision",
            event_type="camera.live_started",
            payload={
                "camera_id": camera_id,
                "label": label,
                "playlist": started["playlist"],
            },
            severity="info",
        )
    except Exception as exc:
        events.append(
            {
                "source": "vision",
                "type": "camera.live_failed",
                "payload": {
                    "camera_id": camera_id,
                    "label": label,
                    "error": str(exc),
                },
                "severity": "warn",
            }
        )

    return events
