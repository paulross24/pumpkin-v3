"""Camera recording module for Pumpkin v3."""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone, timedelta
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
        "-c",
        "copy",
        "-reset_timestamps",
        "1",
        "-y",
        str(output_path),
    ]
    try:
        subprocess.run(args, check=True, timeout=duration_seconds + 15)
    except subprocess.TimeoutExpired as exc:
        return {"status": "failed", "error": "timeout", "detail": str(exc)}
    except subprocess.CalledProcessError as exc:
        return {"status": "failed", "error": "ffmpeg_failed", "detail": str(exc)}
    return {"status": "ok"}


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
        },
        severity="info",
    )

    _cleanup_old(settings.data_dir() / "camera_recordings" / str(camera_id), retention_hours)
    return events
