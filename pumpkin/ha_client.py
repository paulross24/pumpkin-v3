"""Read-only Home Assistant client."""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from . import entity_cache
from . import ha_cache


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
    return entity_cache.fetch_entity_state(base_url, token, entity_id, timeout)


def fetch_states(base_url: str, token: str, timeout: float) -> Dict[str, Any]:
    cache_key = f"{base_url.rstrip('/')}/api/states"
    cached = ha_cache.cache.get(cache_key)
    if cached is not None:
        return {"ok": True, "states": cached}

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
        ha_cache.cache.set(cache_key, data)
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
            registry = fetch_area_registry_http(base_url, token, timeout)
            if registry.get("ok"):
                return registry
            return fetch_areas_ws(base_url, token, timeout, "unexpected_payload")
        return {"ok": True, "areas": data}
    except HTTPError as exc:
        if exc.code == 404:
            registry = fetch_area_registry_http(base_url, token, timeout)
            if registry.get("ok"):
                return registry
            return fetch_areas_ws(base_url, token, timeout, "http_404")
        return {"ok": False, "error": f"http_{exc.code}"}
    except URLError as exc:
        return {"ok": False, "error": "url_error"}
    except Exception as exc:
        return {"ok": False, "error": "unknown_error"}


def fetch_areas_ws(base_url: str, token: str, timeout: float, fallback_reason: str) -> Dict[str, Any]:
    try:
        sock = _ws_connect(base_url, timeout)
        auth_msg = _ws_read_json(sock, timeout)
        for _ in range(3):
            if isinstance(auth_msg, dict) and auth_msg.get("type") == "auth_required":
                break
            auth_msg = _ws_read_json(sock, timeout)
        if not isinstance(auth_msg, dict) or auth_msg.get("type") != "auth_required":
            return {"ok": False, "error": f"{fallback_reason}:ws_auth_required_missing"}
        _ws_send_json(sock, {"type": "auth", "access_token": token})
        auth_reply = _ws_read_json(sock, timeout)
        if not isinstance(auth_reply, dict) or auth_reply.get("type") != "auth_ok":
            return {"ok": False, "error": f"{fallback_reason}:ws_auth_failed"}
        req_id = 1
        _ws_send_json(sock, {"id": req_id, "type": "config/area_registry/list"})
        for _ in range(5):
            reply = _ws_read_json(sock, timeout)
            if isinstance(reply, dict) and reply.get("id") == req_id:
                if reply.get("success") is True and isinstance(reply.get("result"), list):
                    return {"ok": True, "areas": reply["result"]}
                return {"ok": False, "error": f"{fallback_reason}:ws_result_failed"}
        return {"ok": False, "error": f"{fallback_reason}:ws_no_result"}
    except Exception as exc:
        return {"ok": False, "error": f"{fallback_reason}:ws_error:{type(exc).__name__}"}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def fetch_entity_registry(base_url: str, token: str, timeout: float) -> Dict[str, Any]:
    """Fetch entity registry with area mappings."""
    http_result = fetch_entity_registry_http(base_url, token, timeout)
    if http_result.get("ok"):
        return http_result
    try:
        sock = _ws_connect(base_url, timeout)
        auth_msg = _ws_read_json(sock, timeout)
        for _ in range(3):
            if isinstance(auth_msg, dict) and auth_msg.get("type") == "auth_required":
                break
            auth_msg = _ws_read_json(sock, timeout)
        _ws_send_json(sock, {"type": "auth", "access_token": token})
        auth_reply = _ws_read_json(sock, timeout)
        if not isinstance(auth_reply, dict) or auth_reply.get("type") != "auth_ok":
            return {"ok": False, "error": "ws_auth_failed"}
        req_id = 2
        _ws_send_json(sock, {"id": req_id, "type": "config/entity_registry/list"})
        for _ in range(5):
            reply = _ws_read_json(sock, timeout)
            if isinstance(reply, dict) and reply.get("id") == req_id:
                if reply.get("success") is True and isinstance(reply.get("result"), list):
                    return {"ok": True, "entities": reply["result"]}
                return {"ok": False, "error": "ws_result_failed"}
        return {"ok": False, "error": "ws_no_result"}
    except Exception as exc:
        return {"ok": False, "error": f"ws_error:{type(exc).__name__}"}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def fetch_device_registry(base_url: str, token: str, timeout: float) -> Dict[str, Any]:
    """Fetch device registry to map devices to areas."""
    http_result = fetch_device_registry_http(base_url, token, timeout)
    if http_result.get("ok"):
        return http_result
    try:
        sock = _ws_connect(base_url, timeout)
        auth_msg = _ws_read_json(sock, timeout)
        for _ in range(3):
            if isinstance(auth_msg, dict) and auth_msg.get("type") == "auth_required":
                break
            auth_msg = _ws_read_json(sock, timeout)
        _ws_send_json(sock, {"type": "auth", "access_token": token})
        auth_reply = _ws_read_json(sock, timeout)
        if not isinstance(auth_reply, dict) or auth_reply.get("type") != "auth_ok":
            return {"ok": False, "error": "ws_auth_failed"}
        req_id = 3
        _ws_send_json(sock, {"id": req_id, "type": "config/device_registry/list"})
        for _ in range(5):
            reply = _ws_read_json(sock, timeout)
            if isinstance(reply, dict) and reply.get("id") == req_id:
                if reply.get("success") is True and isinstance(reply.get("result"), list):
                    return {"ok": True, "devices": reply["result"]}
                return {"ok": False, "error": "ws_result_failed"}
        return {"ok": False, "error": "ws_no_result"}
    except Exception as exc:
        return {"ok": False, "error": f"ws_error:{type(exc).__name__}"}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def fetch_area_registry_http(base_url: str, token: str, timeout: float) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/api/config/area_registry"
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
    except URLError:
        return {"ok": False, "error": "url_error"}
    except Exception:
        return {"ok": False, "error": "unknown_error"}


def fetch_entity_registry_http(base_url: str, token: str, timeout: float) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/api/config/entity_registry"
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        if not isinstance(data, list):
            return {"ok": False, "error": "unexpected_payload"}
        return {"ok": True, "entities": data}
    except HTTPError as exc:
        return {"ok": False, "error": f"http_{exc.code}"}
    except URLError:
        return {"ok": False, "error": "url_error"}
    except Exception:
        return {"ok": False, "error": "unknown_error"}


def fetch_device_registry_http(base_url: str, token: str, timeout: float) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/api/config/device_registry"
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        if not isinstance(data, list):
            return {"ok": False, "error": "unexpected_payload"}
        return {"ok": True, "devices": data}
    except HTTPError as exc:
        return {"ok": False, "error": f"http_{exc.code}"}
    except URLError:
        return {"ok": False, "error": "url_error"}
    except Exception:
        return {"ok": False, "error": "unknown_error"}


def _ws_connect(base_url: str, timeout: float) -> socket.socket:
    url = base_url
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    path = "/api/websocket"
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    if scheme == "https":
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    host_header = host
    if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
        host_header = f"{host}:{port}"
    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host_header}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        "",
        "",
    ]
    sock.sendall("\r\n".join(headers).encode("ascii"))
    response = _recv_until(sock, b"\r\n\r\n")
    if not response.startswith(b"HTTP/1.1 101"):
        raise RuntimeError("ws_handshake_failed")
    return sock


def _ws_send_json(sock: socket.socket, payload: Dict[str, Any]) -> None:
    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    _ws_send_frame(sock, data)


def _ws_read_json(sock: socket.socket, timeout: float) -> Optional[Dict[str, Any]]:
    raw = _ws_recv_frame(sock)
    if raw is None:
        return None
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if isinstance(decoded, dict):
        return decoded
    return None


def _ws_send_frame(sock: socket.socket, payload: bytes) -> None:
    length = len(payload)
    header = bytearray()
    header.append(0x81)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header.extend(length.to_bytes(2, "big"))
    else:
        header.append(0x80 | 127)
        header.extend(length.to_bytes(8, "big"))
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + mask + masked)


def _ws_recv_frame(sock: socket.socket) -> Optional[bytes]:
    first_two = _recv_exact(sock, 2)
    if not first_two:
        return None
    b1, b2 = first_two[0], first_two[1]
    opcode = b1 & 0x0F
    if opcode == 0x8:
        return None
    length = b2 & 0x7F
    if length == 126:
        length_bytes = _recv_exact(sock, 2)
        length = int.from_bytes(length_bytes, "big")
    elif length == 127:
        length_bytes = _recv_exact(sock, 8)
        length = int.from_bytes(length_bytes, "big")
    if length == 0:
        return b""
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("ws_connection_closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            break
    return data
