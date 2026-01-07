#!/usr/bin/env python3
"""Self-check for PumpkinVoice HTTP endpoints."""

from __future__ import annotations

import json
import os
import sys
import urllib.request


def _request(url: str, method: str = "GET", payload: dict | None = None) -> tuple[int, dict]:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=5) as resp:
        raw = resp.read().decode("utf-8")
        return resp.getcode(), json.loads(raw)


def _assert_keys(label: str, payload: dict, keys: list[str]) -> None:
    missing = [key for key in keys if key not in payload]
    if missing:
        raise AssertionError(f"{label} missing keys: {missing}")


def main() -> int:
    host = os.getenv("PUMPKIN_VOICE_HOST", "127.0.0.1")
    port = int(os.getenv("PUMPKIN_VOICE_PORT", "9000"))
    base = f"http://{host}:{port}"

    status, payload = _request(f"{base}/")
    if status != 200:
        raise AssertionError("/ status not 200")
    _assert_keys("/", payload, ["service", "version", "endpoints"])

    status, payload = _request(f"{base}/health")
    if status != 200:
        raise AssertionError("/health status not 200")
    _assert_keys("/health", payload, ["status", "host", "port"])

    status, payload = _request(f"{base}/config")
    if status != 200:
        raise AssertionError("/config status not 200")
    _assert_keys("/config", payload, ["service", "http", "features", "build"])

    status, payload = _request(f"{base}/openapi.json")
    if status != 200:
        raise AssertionError("/openapi.json status not 200")
    _assert_keys("/openapi.json", payload, ["openapi", "paths"])

    status, payload = _request(
        f"{base}/ingest",
        method="POST",
        payload={"text": "self check", "source": "self", "device": "local"},
    )
    if status != 200:
        raise AssertionError("/ingest status not 200")
    _assert_keys("/ingest", payload, ["status", "received"])

    print("voice self-check ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
