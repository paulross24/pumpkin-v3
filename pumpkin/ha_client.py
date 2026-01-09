"""Read-only Home Assistant client."""

from __future__ import annotations

import json
from typing import Any, Dict, List
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def fetch_status(base_url: str, token: str, timeout: float) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/api/"
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")

    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        return {"ok": True, "status": data}
    except HTTPError as exc:
        return {"ok": False, "error": f"http_{exc.code}"}
    except URLError as exc:
        return {"ok": False, "error": "url_error"}
    except Exception as exc:
        return {"ok": False, "error": "unknown_error"}


def fetch_entity_state(base_url: str, token: str, entity_id: str, timeout: float) -> Dict[str, Any]:
    url = base_url.rstrip("/") + f"/api/states/{entity_id}"
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        return {"ok": True, "state": data.get("state"), "attributes": data.get("attributes", {})}
    except HTTPError as exc:
        return {"ok": False, "error": f"http_{exc.code}"}
    except URLError as exc:
        return {"ok": False, "error": "url_error"}
    except Exception as exc:
        return {"ok": False, "error": "unknown_error"}


def fetch_states(base_url: str, token: str, timeout: float) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/api/states"
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        if not isinstance(data, list):
            return {"ok": False, "error": "unexpected_payload"}
        return {"ok": True, "states": data}
    except HTTPError as exc:
        return {"ok": False, "error": f"http_{exc.code}"}
    except URLError as exc:
        return {"ok": False, "error": "url_error"}
    except Exception as exc:
        return {"ok": False, "error": "unknown_error"}


def fetch_calendars(base_url: str, token: str, timeout: float) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/api/calendars"
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        if not isinstance(data, list):
            return {"ok": False, "error": "unexpected_payload"}
        return {"ok": True, "calendars": data}
    except HTTPError as exc:
        return {"ok": False, "error": f"http_{exc.code}"}
    except URLError as exc:
        return {"ok": False, "error": "url_error"}
    except Exception as exc:
        return {"ok": False, "error": "unknown_error"}


def fetch_calendar_events(
    base_url: str,
    token: str,
    entity_id: str,
    start: str,
    end: str,
    timeout: float,
) -> Dict[str, Any]:
    params = urlencode({"start": start, "end": end})
    url = base_url.rstrip("/") + f"/api/calendars/{entity_id}?{params}"
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        if not isinstance(data, list):
            return {"ok": False, "error": "unexpected_payload"}
        return {"ok": True, "events": data}
    except HTTPError as exc:
        return {"ok": False, "error": f"http_{exc.code}"}
    except URLError as exc:
        return {"ok": False, "error": "url_error"}
    except Exception as exc:
        return {"ok": False, "error": "unknown_error"}


def call_service(
    base_url: str,
    token: str,
    domain: str,
    service: str,
    payload: Dict[str, Any],
    timeout: float,
) -> Dict[str, Any]:
    url = base_url.rstrip("/") + f"/api/services/{domain}/{service}"
    req = Request(url, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    try:
        with urlopen(req, data=data, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
        decoded = json.loads(raw)
        return {"ok": True, "result": decoded}
    except HTTPError as exc:
        return {"ok": False, "error": f"http_{exc.code}"}
    except URLError as exc:
        return {"ok": False, "error": "url_error"}
    except Exception as exc:
        return {"ok": False, "error": "unknown_error"}


def fetch_areas(base_url: str, token: str, timeout: float) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/api/areas"
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        if not isinstance(data, list):
            return {"ok": False, "error": "unexpected_payload"}
        return {"ok": True, "areas": data}
    except HTTPError as exc:
        return {"ok": False, "error": f"http_{exc.code}"}
    except URLError as exc:
        return {"ok": False, "error": "url_error"}
    except Exception as exc:
        return {"ok": False, "error": "unknown_error"}
