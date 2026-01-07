"""Voice text input HTTP server."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from . import settings
from . import store
from .audit import append_jsonl
from .db import init_db


MAX_TEXT_LEN = 500
INGEST_LOG_TEXT_LIMIT = 160
OPENAI_TIMEOUT_SECONDS = 15
_last_seen = {}


def _bad_request(handler: BaseHTTPRequestHandler, message: str) -> None:
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "voice.rejected",
            "reason": message,
        },
    )
    payload = json.dumps({"error": message}, ensure_ascii=True).encode("utf-8")
    handler.send_response(400)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def _send_json(handler: BaseHTTPRequestHandler, status: int, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _parse_json(body: bytes) -> Dict[str, Any]:
    try:
        return json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise ValueError("invalid JSON")


def _normalize_text(text: str) -> str:
    return " ".join(text.split())


def _truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _effective_bind(handler: BaseHTTPRequestHandler) -> tuple[str, int]:
    try:
        address = handler.server.server_address
        return address[0], int(address[1])
    except Exception:
        return settings.voice_server_host(), settings.voice_server_port()


def _rate_limited(rate_key: str | None, cooldown: int) -> bool:
    key = rate_key or "unknown"
    now = int(datetime.now(timezone.utc).timestamp())
    history = _last_seen.get(key, [])
    history = [ts for ts in history if (now - ts) < cooldown]
    if len(history) >= 2:
        _last_seen[key] = history
        return True
    history.append(now)
    _last_seen[key] = history
    return False


def _parse_limit(value: str | None, default: int = 25, max_limit: int = 200) -> int:
    if not value:
        return default
    try:
        return min(max(1, int(value)), max_limit)
    except ValueError:
        return default


def _call_openai(
    prompt: str,
    api_key: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
) -> str:
    api_key = api_key or os.getenv("PUMPKIN_OPENAI_API_KEY")
    if not api_key:
        raise ValueError("openai_api_key_missing")
    model = model or os.getenv("PUMPKIN_OPENAI_MODEL", "gpt-4o-mini")
    url = base_url or os.getenv(
        "PUMPKIN_OPENAI_BASE_URL", "https://api.openai.com/v1/chat/completions"
    )
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are Pumpkin, a helpful, calm assistant for a home automation system. "
                    "Be concise, friendly, and clear. If you are unsure, say so."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.6,
    }
    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")
    with urllib.request.urlopen(req, timeout=OPENAI_TIMEOUT_SECONDS) as resp:
        raw = resp.read().decode("utf-8")
    decoded = json.loads(raw)
    choices = decoded.get("choices", [])
    if not choices:
        raise ValueError("openai_empty_response")
    message = choices[0].get("message", {})
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("openai_empty_content")
    return content.strip()


def _latest_event(conn, event_type: str) -> Dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM events WHERE type = ? ORDER BY id DESC LIMIT 1", (event_type,)
    ).fetchone()
    if not row:
        return None
    try:
        payload = json.loads(row["payload_json"])
    except Exception:
        payload = {}
    return {
        "id": row["id"],
        "ts": row["ts"],
        "source": row["source"],
        "type": row["type"],
        "payload": payload,
        "severity": row["severity"],
    }


def _load_llm_config(conn) -> Dict[str, Any]:
    api_key = store.get_memory(conn, "llm.openai_api_key")
    model = store.get_memory(conn, "llm.openai_model")
    base_url = store.get_memory(conn, "llm.openai_base_url")
    return {
        "api_key": api_key or os.getenv("PUMPKIN_OPENAI_API_KEY"),
        "model": model or os.getenv("PUMPKIN_OPENAI_MODEL", "gpt-4o-mini"),
        "base_url": base_url
        or os.getenv("PUMPKIN_OPENAI_BASE_URL", "https://api.openai.com/v1/chat/completions"),
    }


def _latest_errors(conn, limit: int) -> list[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM events WHERE type = ? ORDER BY id DESC LIMIT ?",
        ("android.error", limit),
    ).fetchall()
    errors: list[Dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            payload = {}
        errors.append(
            {
                "id": row["id"],
                "ts": row["ts"],
                "payload": payload,
                "severity": row["severity"],
            }
        )
    return errors


def _summarize_issues(system_snapshot: Dict[str, Any] | None) -> list[Dict[str, Any]]:
    issues: list[Dict[str, Any]] = []
    if not system_snapshot:
        return issues
    disk = system_snapshot.get("disk", {})
    used_percent = disk.get("used_percent")
    if isinstance(used_percent, (float, int)) and used_percent >= 0.9:
        issues.append(
            {
                "kind": "disk_usage_high",
                "message": f"Disk usage is high ({used_percent:.0%}).",
            }
        )
    return issues


class VoiceHandler(BaseHTTPRequestHandler):
    server_version = "PumpkinVoice/0.1"

    def send_response(self, code: int, message: str | None = None) -> None:
        self._response_code = code
        super().send_response(code, message)

    def _log_request(self) -> None:
        status = getattr(self, "_response_code", 0)
        print(f"PumpkinVoice {self.command} {self.path} {status}", flush=True)

    def do_POST(self) -> None:
        try:
            if self.path in {"/voice", "/satellite/voice"}:
                self._handle_voice()
                return
            if self.path == "/ingest":
                self._handle_ingest()
                return
            if self.path == "/ask":
                self._handle_ask()
                return
            if self.path == "/errors":
                self._handle_errors()
                return
            if self.path == "/proposals/approve":
                self._handle_proposal_decision("approved")
                return
            if self.path == "/proposals/reject":
                self._handle_proposal_decision("rejected")
                return
            if self.path == "/llm/config":
                self._handle_llm_config()
                return
            self.send_response(404)
            self.end_headers()
            return
        finally:
            self._log_request()

    def _handle_voice(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)

        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "voice.received",
                "content_length": length,
            },
        )

        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return

        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return

        text = data.get("text")
        if not isinstance(text, str):
            _bad_request(self, "text must be a string")
            return

        text = _normalize_text(text)
        if not text:
            _bad_request(self, "text must not be empty")
            return

        if len(text) > MAX_TEXT_LEN:
            _bad_request(self, "text too long")
            return

        device_id = data.get("device_id")
        if device_id is not None and not isinstance(device_id, str):
            _bad_request(self, "device_id must be a string")
            return
        satellite_id = data.get("satellite_id")
        if satellite_id is not None and not isinstance(satellite_id, str):
            _bad_request(self, "satellite_id must be a string")
            return
        room = data.get("room")
        if room is not None and not isinstance(room, str):
            _bad_request(self, "room must be a string")
            return
        client_ip = self.client_address[0] if self.client_address else None
        rate_key = device_id if isinstance(device_id, str) else client_ip
        if _rate_limited(rate_key, settings.voice_cooldown_seconds()):
            _bad_request(self, "rate_limited")
            return

        payload = {
            "text": text,
            "device_id": device_id,
            "confidence": data.get("confidence"),
            "client_ip": client_ip,
            "satellite_id": satellite_id,
            "room": room,
        }

        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        event_id = store.insert_event(
            conn,
            source="voice",
            event_type="voice.command",
            payload=payload,
            severity="med",
        )

        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "voice.event_created",
                "event_id": event_id,
            },
        )

        _send_json(self, 200, {"event_id": event_id})

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            params = parse_qs(parsed.query)
            if path == "/health":
                _send_json(
                    self,
                    200,
                    {
                        "status": "ok",
                        "host": settings.voice_server_host(),
                        "port": settings.voice_server_port(),
                    },
                )
                return
            if path == "/":
                _send_json(
                    self,
                    200,
                    {
                        "service": "PumpkinVoice",
                        "version": self.server_version,
                        "endpoints": [
                            "GET /",
                            "GET /health",
                            "GET /config",
                            "GET /openapi.json",
                            "GET /proposals",
                            "GET /summary",
                            "GET /errors",
                            "GET /llm/config",
                            "POST /ask",
                            "POST /errors",
                            "POST /proposals/approve",
                            "POST /proposals/reject",
                            "POST /llm/config",
                            "POST /ingest",
                            "POST /voice",
                            "POST /satellite/voice",
                        ],
                    },
                )
                return
            if path == "/config":
                bind_host, bind_port = _effective_bind(self)
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                llm_config = _load_llm_config(conn)
                _send_json(
                    self,
                    200,
                    {
                        "service": {"name": "PumpkinVoice", "version": self.server_version},
                        "http": {
                            "host": bind_host,
                            "port": bind_port,
                        },
                        "llm": {
                            "provider": "openai",
                            "model": llm_config["model"],
                            "enabled": bool(llm_config["api_key"]),
                        },
                        "upstream": {
                            "planner_mode": os.getenv("PUMPKIN_PLANNER_MODE", "stub"),
                            "planner_url": os.getenv("PUMPKIN_PLANNER_URL"),
                        },
                        "features": {
                            "voice_rate_limit_seconds": settings.voice_cooldown_seconds(),
                            "max_text_len": MAX_TEXT_LEN,
                            "ingest_enabled": True,
                        },
                        "build": {
                            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                        },
                    },
                )
                return
            if path == "/proposals":
                status = params.get("status", [None])[0]
                limit = _parse_limit(params.get("limit", [None])[0])
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                rows = store.list_proposals(conn, status=status, limit=limit)
                proposals = []
                for row in rows:
                    try:
                        details = json.loads(row["details_json"])
                    except Exception:
                        details = {}
                    proposals.append(
                        {
                            "id": row["id"],
                            "kind": row["kind"],
                            "summary": row["summary"],
                            "details": details,
                            "risk": row["risk"],
                            "expected_outcome": row["expected_outcome"],
                            "status": row["status"],
                            "needs_new_capability": bool(row["needs_new_capability"]),
                            "capability_request": row["capability_request"],
                            "ai_context_excerpt": row["ai_context_excerpt"],
                            "ts_created": row["ts_created"],
                        }
                    )
                _send_json(
                    self,
                    200,
                    {
                        "count": len(proposals),
                        "proposals": proposals,
                    },
                )
                return
            if path == "/summary":
                status = params.get("status", ["pending"])[0]
                limit = _parse_limit(params.get("limit", [None])[0], default=10)
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                snapshot_event = _latest_event(conn, "system.snapshot")
                heartbeat_event = _latest_event(conn, "heartbeat")
                proposals = store.list_proposals(conn, status=status, limit=limit)
                proposal_items = []
                for row in proposals:
                    proposal_items.append(
                        {
                            "id": row["id"],
                            "kind": row["kind"],
                            "summary": row["summary"],
                            "risk": row["risk"],
                            "status": row["status"],
                            "expected_outcome": row["expected_outcome"],
                            "ts_created": row["ts_created"],
                        }
                    )
                system_snapshot = snapshot_event["payload"] if snapshot_event else None
                issues = _summarize_issues(system_snapshot)
                _send_json(
                    self,
                    200,
                    {
                        "status": "ok",
                        "heartbeat": heartbeat_event,
                        "system_snapshot": system_snapshot,
                        "issues": issues,
                        "proposals": proposal_items,
                        "proposal_count": len(proposal_items),
                    },
                )
                return
            if path == "/errors":
                limit = _parse_limit(params.get("limit", [None])[0], default=5, max_limit=50)
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                errors = _latest_errors(conn, limit)
                _send_json(
                    self,
                    200,
                    {
                        "count": len(errors),
                        "errors": errors,
                    },
                )
                return
            if path == "/llm/config":
                conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
                llm_config = _load_llm_config(conn)
                _send_json(
                    self,
                    200,
                    {
                        "provider": "openai",
                        "model": llm_config["model"],
                        "base_url": llm_config["base_url"],
                        "enabled": bool(llm_config["api_key"]),
                    },
                )
                return
            if path == "/openapi.json":
                _send_json(
                    self,
                    200,
                    {
                        "openapi": "3.0.0",
                        "info": {
                            "title": "PumpkinVoice",
                            "version": self.server_version,
                        },
                        "paths": {
                            "/": {"get": {"summary": "Service metadata"}},
                            "/health": {"get": {"summary": "Health check"}},
                            "/config": {"get": {"summary": "Runtime config"}},
                            "/summary": {
                                "get": {
                                    "summary": "System summary",
                                    "parameters": [
                                        {
                                            "name": "status",
                                            "in": "query",
                                            "schema": {"type": "string"},
                                        },
                                        {
                                            "name": "limit",
                                            "in": "query",
                                            "schema": {"type": "integer"},
                                        },
                                    ],
                                    "responses": {
                                        "200": {
                                            "description": "Summary snapshot",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/errors": {
                                "get": {
                                    "summary": "List recent client error reports",
                                    "parameters": [
                                        {
                                            "name": "limit",
                                            "in": "query",
                                            "schema": {"type": "integer"},
                                        }
                                    ],
                                    "responses": {
                                        "200": {
                                            "description": "Error reports",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/llm/config": {
                                "get": {
                                    "summary": "Get LLM configuration",
                                    "responses": {
                                        "200": {
                                            "description": "LLM config",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/openapi.json": {"get": {"summary": "OpenAPI spec"}},
                            "/proposals": {
                                "get": {
                                    "summary": "List proposals",
                                    "parameters": [
                                        {
                                            "name": "status",
                                            "in": "query",
                                            "schema": {"type": "string"},
                                        },
                                        {
                                            "name": "limit",
                                            "in": "query",
                                            "schema": {"type": "integer"},
                                        },
                                    ],
                                    "responses": {
                                        "200": {
                                            "description": "Proposal list",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/ingest": {
                                "post": {
                                    "summary": "Ingest text payload",
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "text": {"type": "string"},
                                                        "source": {"type": "string"},
                                                        "device": {"type": "string"},
                                                    },
                                                    "required": ["text"],
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Acknowledged",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/ask": {
                                "post": {
                                    "summary": "Ask Pumpkin (LLM)",
                                    "parameters": [
                                        {
                                            "name": "X-Pumpkin-OpenAI-Key",
                                            "in": "header",
                                            "schema": {"type": "string"},
                                        }
                                    ],
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "text": {"type": "string"},
                                                        "source": {"type": "string"},
                                                        "device": {"type": "string"},
                                                        "ts": {"type": "string"},
                                                        "location": {"type": "object"},
                                                    },
                                                    "required": ["text"],
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Answer",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/errors": {
                                "post": {
                                    "summary": "Record client error report",
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "message": {"type": "string"},
                                                        "stack": {"type": "string"},
                                                        "device": {"type": "string"},
                                                        "manufacturer": {"type": "string"},
                                                        "sdk": {"type": "integer"},
                                                        "app": {"type": "string"},
                                                        "ts": {"type": "string"},
                                                    },
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Acknowledged",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/llm/config": {
                                "post": {
                                    "summary": "Set LLM configuration",
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "api_key": {"type": "string"},
                                                        "model": {"type": "string"},
                                                        "base_url": {"type": "string"},
                                                    },
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Updated",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/proposals/approve": {
                                "post": {
                                    "summary": "Approve proposal",
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "integer"},
                                                        "actor": {"type": "string"},
                                                        "reason": {"type": "string"},
                                                    },
                                                    "required": ["id"],
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Decision recorded",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            "/proposals/reject": {
                                "post": {
                                    "summary": "Reject proposal",
                                    "requestBody": {
                                        "required": True,
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "integer"},
                                                        "actor": {"type": "string"},
                                                        "reason": {"type": "string"},
                                                    },
                                                    "required": ["id"],
                                                }
                                            }
                                        },
                                    },
                                    "responses": {
                                        "200": {
                                            "description": "Decision recorded",
                                            "content": {
                                                "application/json": {
                                                    "schema": {"type": "object"}
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                        },
                    },
                )
                return
            self.send_response(404)
            self.end_headers()
            return
        finally:
            self._log_request()

    def _handle_ingest(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        text = data.get("text")
        if not isinstance(text, str):
            _bad_request(self, "text must be a string")
            return
        text = _normalize_text(text)
        if not text:
            _bad_request(self, "text must not be empty")
            return
        source = data.get("source")
        if source is not None and not isinstance(source, str):
            _bad_request(self, "source must be a string")
            return
        device = data.get("device")
        if device is not None and not isinstance(device, str):
            _bad_request(self, "device must be a string")
            return
        truncated = _truncate_text(text, INGEST_LOG_TEXT_LIMIT)
        print(
            "PumpkinVoice ingest "
            f"source={source!r} device={device!r} text={truncated!r}"
        )
        _send_json(
            self,
            200,
            {
                "status": "ok",
                "received": {"text": text, "source": source, "device": device},
            },
        )

    def _handle_ask(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        text = data.get("text")
        if not isinstance(text, str):
            _bad_request(self, "text must be a string")
            return
        text = _normalize_text(text)
        if not text:
            _bad_request(self, "text must not be empty")
            return
        if len(text) > MAX_TEXT_LEN:
            _bad_request(self, "text too long")
            return
        source = data.get("source")
        if source is not None and not isinstance(source, str):
            _bad_request(self, "source must be a string")
            return
        device = data.get("device")
        if device is not None and not isinstance(device, str):
            _bad_request(self, "device must be a string")
            return
        payload = {
            "text": text,
            "source": source,
            "device": device,
            "client_ip": self.client_address[0] if self.client_address else None,
            "ts": data.get("ts"),
            "location": data.get("location"),
        }
        print(
            "PumpkinVoice ask "
            f"source={source!r} device={device!r} text={_truncate_text(text, INGEST_LOG_TEXT_LIMIT)!r}",
            flush=True,
        )
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        store.insert_event(
            conn,
            source="voice",
            event_type="voice.ask",
            payload=payload,
            severity="info",
        )
        llm_config = _load_llm_config(conn)
        api_key = self.headers.get("X-Pumpkin-OpenAI-Key") or llm_config["api_key"]
        try:
            reply = _call_openai(
                text,
                api_key=api_key,
                model=llm_config["model"],
                base_url=llm_config["base_url"],
            )
        except ValueError as exc:
            _send_json(self, 503, {"error": str(exc)})
            return
        except urllib.error.HTTPError as exc:
            _send_json(self, 502, {"error": f"openai_http_{exc.code}"})
            return
        except Exception:
            _send_json(self, 502, {"error": "openai_request_failed"})
            return
        print(
            f"PumpkinVoice ask_reply { _truncate_text(reply, INGEST_LOG_TEXT_LIMIT)!r}",
            flush=True,
        )
        _send_json(self, 200, {"status": "ok", "reply": reply})

    def _handle_errors(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        message = data.get("message")
        stack = data.get("stack")
        if message is not None and not isinstance(message, str):
            _bad_request(self, "message must be a string")
            return
        if stack is not None and not isinstance(stack, str):
            _bad_request(self, "stack must be a string")
            return
        payload = {
            "message": message,
            "stack": stack,
            "device": data.get("device"),
            "manufacturer": data.get("manufacturer"),
            "sdk": data.get("sdk"),
            "app": data.get("app"),
            "ts": data.get("ts"),
            "client_ip": self.client_address[0] if self.client_address else None,
        }
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        event_id = store.insert_event(
            conn,
            source="android",
            event_type="android.error",
            payload=payload,
            severity="warn",
        )
        _send_json(self, 200, {"status": "ok", "event_id": event_id})

    def _handle_proposal_decision(self, decision: str) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        proposal_id = data.get("id")
        if not isinstance(proposal_id, int):
            _bad_request(self, "id must be an integer")
            return
        actor = data.get("actor")
        if actor is not None and not isinstance(actor, str):
            _bad_request(self, "actor must be a string")
            return
        reason = data.get("reason")
        if reason is not None and not isinstance(reason, str):
            _bad_request(self, "reason must be a string")
            return
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        row = store.get_proposal(conn, proposal_id)
        if not row:
            _send_json(self, 404, {"error": "proposal_not_found"})
            return
        policy_hash = row["policy_hash"]
        store.insert_approval(
            conn,
            proposal_id=proposal_id,
            actor=actor or "android",
            decision=decision,
            reason=reason,
            policy_hash=policy_hash,
        )
        store.update_proposal_status(conn, proposal_id, decision)
        _send_json(self, 200, {"status": "ok", "id": proposal_id, "decision": decision})

    def _handle_llm_config(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = _parse_json(body)
        except ValueError:
            _bad_request(self, "invalid JSON")
            return
        if not isinstance(data, dict):
            _bad_request(self, "JSON body must be an object")
            return
        api_key = data.get("api_key")
        model = data.get("model")
        base_url = data.get("base_url")
        if api_key is not None and not isinstance(api_key, str):
            _bad_request(self, "api_key must be a string")
            return
        if model is not None and not isinstance(model, str):
            _bad_request(self, "model must be a string")
            return
        if base_url is not None and not isinstance(base_url, str):
            _bad_request(self, "base_url must be a string")
            return
        conn = init_db(str(settings.db_path()), str(settings.repo_root() / "migrations"))
        if api_key is not None:
            store.set_memory(conn, "llm.openai_api_key", api_key.strip())
        if model is not None:
            store.set_memory(conn, "llm.openai_model", model.strip())
        if base_url is not None:
            store.set_memory(conn, "llm.openai_base_url", base_url.strip())
        llm_config = _load_llm_config(conn)
        _send_json(
            self,
            200,
            {
                "status": "ok",
                "provider": "openai",
                "model": llm_config["model"],
                "base_url": llm_config["base_url"],
                "enabled": bool(llm_config["api_key"]),
            },
        )

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def run_server(host: str | None = None, port: int | None = None) -> None:
    bind_host = host or settings.voice_server_host()
    bind_port = port or settings.voice_server_port()
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "voice.server_starting",
            "host": bind_host,
            "port": bind_port,
        },
    )
    print(f"voice server starting on {bind_host}:{bind_port}")
    try:
        server = ThreadingHTTPServer((bind_host, bind_port), VoiceHandler)
    except Exception as exc:
        append_jsonl(
            str(settings.audit_path()),
            {
                "kind": "voice.server_bind_failed",
                "host": bind_host,
                "port": bind_port,
                "error": str(exc),
            },
        )
        raise
    append_jsonl(
        str(settings.audit_path()),
        {
            "kind": "voice.server_listening",
            "host": bind_host,
            "port": bind_port,
        },
    )
    print(f"voice server listening on {bind_host}:{bind_port}")
    server.serve_forever()
