"""Basic telemetry collection and logging."""

from __future__ import annotations

import logging
import os
import shutil
from typing import Any, Dict


def _get_cpu_usage() -> float:
    try:
        load1, _, _ = os.getloadavg()
        return round(load1, 2)
    except Exception:
        return 0.0


def _read_meminfo() -> Dict[str, Any]:
    info: Dict[str, Any] = {"total_kb": None, "available_kb": None}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                key = parts[0].strip()
                value = parts[1].strip().split()[0]
                if value.isdigit():
                    if key == "MemTotal":
                        info["total_kb"] = int(value)
                    if key == "MemAvailable":
                        info["available_kb"] = int(value)
    except Exception:
        pass
    return info


def _get_disk_space(path: str = "/") -> Dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
        return {
            "path": path,
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "used_percent": round(usage.used / usage.total, 4) if usage.total else None,
        }
    except Exception:
        return {"path": path}


def collect_health_metrics() -> Dict[str, Any]:
    return {
        "cpu_load_1m": _get_cpu_usage(),
        "memory": _read_meminfo(),
        "disk": _get_disk_space(),
    }


def log_health_metrics(metrics: Dict[str, Any]) -> None:
    logging.info("Health Metrics: %s", metrics)
