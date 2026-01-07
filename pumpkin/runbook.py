"""Module install runbook generation and prereq checks."""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from typing import Any, Dict, Tuple
from urllib.parse import urlparse


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_runbook(
    proposal_details: Dict[str, Any], module_entry: Dict[str, Any]
) -> Dict[str, Any]:
    module_name = proposal_details.get("module_name")
    manual_steps = [
        "Review module registry entry and security considerations.",
        "Confirm network access to required services.",
        "Install any required packages (manual, out of band).",
    ]
    if module_name == "homeassistant.observer":
        manual_steps.append("Set PUMPKIN_HA_TOKEN as an environment variable.")

    return {
        "overview": {
            "module_name": module_name,
            "rationale": proposal_details.get("rationale"),
            "description": module_entry.get("description"),
            "safety_level": proposal_details.get("safety_level"),
        },
        "prerequisites": module_entry.get("prerequisites", {}),
        "manual_steps": manual_steps,
        "configuration": {
            "config": proposal_details.get("config", {}),
            "notes": "Apply configuration to Pumpkin module config files once module is installed.",
        },
        "verification": [
            "Start the module process and check logs for successful connection.",
            "Confirm new events appear in Pumpkin event stream.",
        ],
        "rollback": [proposal_details.get("rollback_plan")],
        "generated_at": _utc_now_iso(),
    }


def runbook_markdown(runbook: Dict[str, Any]) -> str:
    prereq = runbook.get("prerequisites", {})
    prereq_lines = []
    for key, value in prereq.items():
        prereq_lines.append(f"- {key}: {value}")

    manual_steps = runbook.get("manual_steps", [])
    config = runbook.get("configuration", {})
    verification = runbook.get("verification", [])
    rollback = runbook.get("rollback", [])

    lines = [
        f"# Module Install Runbook: {runbook.get('overview', {}).get('module_name')}",
        "",
        "## Overview",
        f"- Rationale: {runbook.get('overview', {}).get('rationale')}",
        f"- Description: {runbook.get('overview', {}).get('description')}",
        f"- Safety level: {runbook.get('overview', {}).get('safety_level')}",
        "",
        "## Prerequisites",
        *prereq_lines,
        "",
        "## Manual Steps",
    ]
    for step in manual_steps:
        lines.append(f"- {step}")

    lines.extend(
        [
            "",
            "## Configuration",
            "```json",
            json.dumps(config.get("config", {}), indent=2, ensure_ascii=True),
            "```",
            f"Notes: {config.get('notes')}",
            "",
            "## Verification",
        ]
    )
    for step in verification:
        lines.append(f"- {step}")

    lines.extend(["", "## Rollback"])
    for step in rollback:
        lines.append(f"- {step}")

    lines.append("")
    lines.append(f"Generated at: {runbook.get('generated_at')}")
    return "\n".join(lines)


def verify_prereqs(proposal_details: Dict[str, Any]) -> Dict[str, Any]:
    config = proposal_details.get("config", {})
    base_url = config.get("base_url")
    results: Dict[str, Any] = {"checks": [], "summary": "ok"}

    if not base_url:
        results["checks"].append({"check": "base_url", "status": "missing"})
        results["summary"] = "missing base_url"
        return results

    parsed = urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        results["checks"].append({"check": "base_url", "status": "invalid"})
        results["summary"] = "invalid base_url"
        return results

    try:
        socket.getaddrinfo(host, port)
        results["checks"].append({"check": "dns", "host": host, "status": "ok"})
    except Exception as exc:
        results["checks"].append(
            {"check": "dns", "host": host, "status": "error", "error": str(exc)}
        )
        results["summary"] = "dns_failed"
        return results

    return results
