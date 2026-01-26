"""Presence helpers shared across modules."""

from __future__ import annotations

from typing import Any, Dict

from . import store


def _load_house_empty_state(conn) -> Dict[str, Any]:
    state = store.get_memory(conn, "house.empty_state")
    if isinstance(state, dict) and state.get("state") in {"empty", "occupied"}:
        return state
    return {}


def is_house_empty(conn) -> bool:
    state = _load_house_empty_state(conn)
    if state.get("state") == "empty":
        return True
    if state.get("state") == "occupied":
        return False
    summary = store.get_memory(conn, "homeassistant.summary")
    if isinstance(summary, dict):
        people_home = summary.get("people_home") or []
        return not bool(people_home)
    return False
