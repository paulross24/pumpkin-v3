"""Simple in-memory cache helpers for Home Assistant data."""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional, Tuple


class HACache:
    """Thread-safe TTL cache for HA lookups."""

    def __init__(self, expiration_time: float = 60.0) -> None:
        self._expiration_time = float(expiration_time)
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        now = time.time()
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None
            ts, value = entry
            if now - ts > self._expiration_time:
                self._data.pop(key, None)
                return None
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = (time.time(), value)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


# Global instance for simple sharing across modules
cache = HACache()
