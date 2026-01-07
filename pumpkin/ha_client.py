"""Read-only Home Assistant client."""

from __future__ import annotations

import json
from typing import Any, Dict
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
