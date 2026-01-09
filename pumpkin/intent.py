"""Interpret user requests for capability mapping."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def classify_intent(text: str) -> Dict[str, Any]:
    normalized = " ".join(text.strip().lower().split())
    if not normalized or len(normalized) < 4:
        return {"classification": "ambiguous", "intent": normalized}

    if any(token in normalized for token in ["help", "do something", "fix it"]):
        return {"classification": "ambiguous", "intent": normalized}

    if any(
        token in normalized
        for token in [
            "what do you remember about me",
            "what do you know about me",
            "what do you remember",
            "what do you know",
        ]
    ):
        return {
            "classification": "supported",
            "intent": normalized,
            "intent_type": "memory.query",
        }

    if any(
        token in normalized
        for token in ["forget me", "forget my info", "forget my data", "erase me"]
    ):
        return {
            "classification": "supported",
            "intent": normalized,
            "intent_type": "memory.forget",
        }

    if any(token in normalized for token in ["notify", "remind", "tell me"]):
        return {"classification": "supported", "intent": normalized}

    if any(
        token in normalized
        for token in [
            "turn",
            "switch",
            "light",
            "lamp",
            "thermostat",
            "camera",
            "tv",
            "lock",
            "door",
            "home assistant",
            "homeassistant",
        ]
    ):
        return {"classification": "unsupported", "intent": normalized}

    return {"classification": "unsupported", "intent": normalized}


def parse_affirmation(text: str) -> Optional[str]:
    normalized = " ".join(text.strip().lower().split())
    if normalized in {"yes", "yep", "yeah", "sure", "ok", "okay", "please do"}:
        return "yes"
    if normalized in {"no", "nope", "nah", "don't", "do not"}:
        return "no"
    return None


def parse_preference(text: str) -> Optional[Dict[str, str]]:
    normalized = " ".join(text.strip().split())
    lowered = normalized.lower()
    if "my preference is " in lowered:
        value = normalized[lowered.find("my preference is ") + len("my preference is ") :].strip()
        if value:
            return {"key": "general", "value": value}
    if lowered.startswith("i prefer "):
        value = normalized[len("i prefer ") :].strip()
        if value:
            return {"key": "general", "value": value}
    return None


def suggest_modules(text: str, registry_summary: List[Dict[str, Any]]) -> List[str]:
    normalized = " ".join(text.strip().lower().split())
    suggestions = []

    match_groups = [
        {
            "tokens": ["music", "audio", "play", "playback", "speaker", "playlist"],
        },
        {
            "tokens": ["face", "recognition", "camera", "vision"],
        },
        {
            "tokens": [
                "light",
                "lamp",
                "switch",
                "thermostat",
                "sensor",
                "tv",
                "lock",
                "door",
                "home",
                "home assistant",
                "homeassistant",
            ],
        },
    ]

    for module in registry_summary:
        name = (module.get("name") or "").lower()
        desc = (module.get("description") or "").lower()
        for group in match_groups:
            if not any(token in normalized for token in group["tokens"]):
                continue
            if any(token in name or token in desc for token in group["tokens"]):
                suggestions.append(module.get("name"))
                break

    return [s for s in suggestions if s]
