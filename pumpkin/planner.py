"""Planner interface and implementations."""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from . import settings

@dataclass(frozen=True)
class PlannerResult:
    proposals: List[Dict[str, Any]]
    raw_response: Optional[str] = None


class Planner:
    def generate(self, context_pack: Dict[str, Any], prompt: str) -> PlannerResult:
        raise NotImplementedError


class StubPlanner(Planner):
    def generate(self, context_pack: Dict[str, Any], prompt: str) -> PlannerResult:
        proposals = [
            {
                "kind": "action.request",
                "summary": "Send a local notification (stub planner)",
                "details": {
                    "rationale": "No LLM configured; using stub planner.",
                    "action_type": "notify.local",
                    "action_params": {"message": "Stub planner active; no LLM configured."},
                },
                "risk": 0.3,
                "expected_outcome": "Human sees a local notification about stub planner.",
                "source_event_ids": [],
                "needs_new_capability": False,
                "capability_request": None,
                "steps": ["Emit a local notification"],
            },
            {
                "kind": "hardware.recommendation",
                "summary": "Review hardware capacity (stub planner)",
                "details": {
                    "rationale": "No LLM configured; using stub planner.",
                    "recommendation": "Consider disk capacity planning if growth continues.",
                },
                "risk": 0.1,
                "expected_outcome": "Human reviews a hardware recommendation.",
                "source_event_ids": [],
                "needs_new_capability": False,
                "capability_request": None,
                "steps": ["Review hardware recommendation"],
            },
        ]

        if os.getenv("PUMPKIN_STUB_POLICY_CHANGE") == "1":
            policy_text = context_pack.get("policy", {}).get("policy_text", "")
            if "maxLength: 2600" not in policy_text:
                proposed = policy_text.replace("maxLength: 2500", "maxLength: 2600")
                if proposed != policy_text:
                    proposals.append(
                        {
                            "kind": "policy.change",
                            "summary": "Increase notify.local maxLength to 2600",
                            "details": {
                                "rationale": "Allow slightly longer notification messages.",
                                "proposed_policy_yaml": proposed,
                                "allow_new_actions": False,
                            },
                            "risk": 0.2,
                            "expected_outcome": "Policy allows longer notify.local messages.",
                            "source_event_ids": [],
                            "needs_new_capability": False,
                            "capability_request": None,
                            "steps": ["Review policy diff", "Approve if acceptable"],
                        }
                    )
        if os.getenv("PUMPKIN_STUB_MODULE_INSTALL") == "1":
            modules = context_pack.get("modules_registry", [])
            for module in modules:
                if module.get("name") == "homeassistant.observer":
                    needs_token = True
                    proposals.append(
                        {
                            "kind": "module.install",
                            "summary": "Install Home Assistant observer module",
                            "details": {
                                "module_name": "homeassistant.observer",
                                "rationale": "Enable richer context from Home Assistant.",
                                "config": {
                                    "base_url": "http://192.168.1.140",
                                    "verify_tls": False,
                                },
                                "safety_level": "med",
                                "prerequisites": {
                                    "packages": [],
                                    "services": ["home-assistant"],
                                    "network_access": ["http://192.168.1.140"],
                                },
                                "rollback_plan": "Disable module and remove any config entries.",
                            },
                            "risk": 0.4,
                            "expected_outcome": "Proposal to install HA observer is ready for review.",
                            "source_event_ids": [],
                            "needs_new_capability": needs_token,
                            "capability_request": (
                                "Need a Home Assistant long-lived access token to proceed."
                                if needs_token
                                else None
                            ),
                            "steps": ["Review module details", "Approve if acceptable"],
                        }
                    )
                    break
        return PlannerResult(proposals=proposals)


class MockPlanner(Planner):
    """Deterministic planner used for local testing."""

    def generate(self, context_pack: Dict[str, Any], prompt: str) -> PlannerResult:
        proposals: List[Dict[str, Any]] = []
        events = context_pack.get("recent_events", [])

        for event in events:
            if event.get("source") != "manual":
                continue
            payload = event.get("payload", {})
            message = str(payload.get("message", ""))
            if "notify" in message.lower():
                proposals.append(
                    {
                        "kind": "action.request",
                        "summary": "Send a local notification",
                        "details": {
                            "rationale": "Manual request for notification.",
                            "action_type": "notify.local",
                            "action_params": {"message": message},
                        },
                        "risk": 0.2,
                        "expected_outcome": "A local notification is emitted.",
                        "source_event_ids": [event.get("id")],
                        "needs_new_capability": False,
                        "capability_request": None,
                        "steps": ["Emit a local notification"],
                    }
                )
            if "hardware" in message.lower():
                proposals.append(
                    {
                        "kind": "hardware.recommendation",
                        "summary": "Review hardware capacity",
                        "details": {
                            "rationale": "Manual request for hardware review.",
                            "recommendation": "Consider faster storage or additional disk space.",
                        },
                        "risk": 0.1,
                        "expected_outcome": "Human reviews hardware recommendations.",
                        "source_event_ids": [event.get("id")],
                        "needs_new_capability": False,
                        "capability_request": None,
                        "steps": ["Review hardware recommendation"],
                    }
                )

        return PlannerResult(proposals=proposals)


class HttpPlanner(Planner):
    def __init__(self, url: str, api_key: Optional[str] = None, timeout: int = 20) -> None:
        self.url = url
        self.api_key = api_key
        self.timeout = timeout

    def generate(self, context_pack: Dict[str, Any], prompt: str) -> PlannerResult:
        payload = {
            "prompt": prompt,
            "context_pack": context_pack,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")

        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read().decode("utf-8")
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"planner returned invalid JSON: {exc}")

        proposals = decoded.get("proposals")
        if not isinstance(proposals, list):
            raise ValueError("planner response missing proposals list")
        return PlannerResult(proposals=proposals, raw_response=raw)


class OpenAIPlanner(Planner):
    def __init__(self, api_key: str, model: str, base_url: str, timeout: float) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.timeout = timeout

    def generate(self, context_pack: Dict[str, Any], prompt: str) -> PlannerResult:
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "Return ONLY JSON with a top-level 'proposals' list.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.4,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.base_url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read().decode("utf-8")
        decoded = json.loads(raw)
        choices = decoded.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ValueError("openai response missing choices")
        message = choices[0].get("message", {})
        content = message.get("content")
        if not isinstance(content, str):
            raise ValueError("openai response missing content")
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"openai content invalid JSON: {exc}")
        proposals = parsed.get("proposals")
        if not isinstance(proposals, list):
            raise ValueError("openai response missing proposals list")
        return PlannerResult(proposals=proposals, raw_response=content)


def load_planner() -> Planner:
    mode = os.getenv("PUMPKIN_PLANNER_MODE", "stub")
    if mode == "stub":
        return StubPlanner()
    if mode == "mock":
        return MockPlanner()
    if mode == "http":
        url = os.getenv("PUMPKIN_PLANNER_URL")
        if not url:
            raise ValueError("PUMPKIN_PLANNER_URL is required for http planner")
        api_key = os.getenv("PUMPKIN_PLANNER_API_KEY")
        return HttpPlanner(url=url, api_key=api_key, timeout=settings.planner_timeout_seconds())
    if mode == "openai":
        api_key = os.getenv("PUMPKIN_OPENAI_API_KEY")
        if not api_key:
            raise ValueError("PUMPKIN_OPENAI_API_KEY is required for openai planner")
        model = os.getenv("PUMPKIN_OPENAI_MODEL", "gpt-4o-mini")
        base_url = os.getenv("PUMPKIN_OPENAI_BASE_URL", "https://api.openai.com/v1/chat/completions")
        return OpenAIPlanner(
            api_key=api_key,
            model=model,
            base_url=base_url,
            timeout=settings.planner_timeout_seconds(),
        )
    raise ValueError(f"unknown planner mode: {mode}")
