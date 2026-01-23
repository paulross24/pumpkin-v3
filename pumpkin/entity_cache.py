"""Entity-level cache for Home Assistant state lookups."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class EntityCache:
    def __init__(self, ttl: float = 30.0) -> None:
        self._ttl = float(ttl)
        self._data: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        entry = self._data.get(key)
        if not entry:
            return None
        ts, value = entry
        if time.time() - ts > self._ttl:
            self._data.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Dict[str, Any]) -> None:
        self._data[key] = (time.time(), value)

    def clear(self) -> None:
        self._data.clear()


cache = EntityCache()


def fetch_entity_state(
    base_url: str, token: str, entity_id: str, timeout: float
) -> Dict[str, Any]:
    cache_key = f"{base_url.rstrip('/')}/api/states/{entity_id}"
    cached = cache.get(cache_key)
    if cached is not None:
        return {
            "ok": True,
            "state": cached.get("state"),
            "attributes": cached.get("attributes", {}),
        }

    url = base_url.rstrip("/") + f"/api/states/{entity_id}"
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        if isinstance(data, dict):
            cache.set(cache_key, data)
            return {
                "ok": True,
                "state": data.get("state"),
                "attributes": data.get("attributes", {}),
            }
        return {"ok": False, "error": "unexpected_payload"}
    except HTTPError as exc:
        return {"ok": False, "error": f"http_{exc.code}"}
    except URLError:
        return {"ok": False, "error": "url_error"}
    except Exception:
        return {"ok": False, "error": "unknown_error"}
