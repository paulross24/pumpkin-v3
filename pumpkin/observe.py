"""Observation sources."""

from __future__ import annotations

import os
import shutil
from typing import Any, Dict, List

from . import ha_client
from . import settings

def _read_meminfo() -> Dict[str, int]:
    data: Dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                key = parts[0].strip()
                value = parts[1].strip().split()[0]
                if value.isdigit():
                    data[key] = int(value)
    except FileNotFoundError:
        pass
    return data


def system_snapshot() -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    load1, load5, load15 = os.getloadavg()
    disk = shutil.disk_usage("/")
    disk_used_percent = disk.used / disk.total if disk.total else 0.0
    meminfo = _read_meminfo()

    payload = {
        "loadavg": {"1m": load1, "5m": load5, "15m": load15},
        "disk": {
            "path": "/",
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "free_bytes": disk.free,
            "used_percent": round(disk_used_percent, 4),
        },
        "meminfo_kb": {
            "MemTotal": meminfo.get("MemTotal"),
            "MemAvailable": meminfo.get("MemAvailable"),
        },
    }

    severity = "warn" if disk_used_percent >= 0.9 else "info"
    events.append(
        {
            "source": "system",
            "type": "system.snapshot",
            "payload": payload,
            "severity": severity,
        }
    )

    return events


def homeassistant_snapshot(base_url: str, token: str) -> List[Dict[str, Any]]:
    result = ha_client.fetch_status(
        base_url=base_url, token=token, timeout=settings.ha_request_timeout_seconds()
    )
    if result.get("ok"):
        return [
            {
                "source": "homeassistant",
                "type": "homeassistant.status",
                "payload": {"status": result.get("status")},
                "severity": "info",
            }
        ]

    return [
        {
            "source": "homeassistant",
            "type": "homeassistant.request_failed",
            "payload": {"error": result.get("error")},
            "severity": "warn",
        }
    ]
