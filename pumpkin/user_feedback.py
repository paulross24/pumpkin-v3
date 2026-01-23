"""User feedback logging helpers."""

from __future__ import annotations

import logging
from typing import Optional


def log_feedback(user_id: Optional[str], feedback: str, log_path: str = "user_feedback.log") -> None:
    cleaned = feedback.strip()
    if not cleaned:
        return
    logging.info("User feedback received: %s", cleaned)
    entry = f"{user_id}: {cleaned}\n" if user_id else f"{cleaned}\n"
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(entry)


def categorize_feedback(feedback: str) -> str:
    lowered = feedback.lower()
    if "issue" in lowered or "bug" in lowered or "problem" in lowered:
        return "issue"
    if "suggestion" in lowered or "idea" in lowered or "request" in lowered:
        return "suggestion"
    return "general"


def process_feedback(feedback: str, user_id: Optional[str] = None) -> str:
    log_feedback(user_id, feedback)
    category = categorize_feedback(feedback)
    if category == "issue":
        logging.warning("User reported an issue: %s", feedback)
    elif category == "suggestion":
        logging.info("User made a suggestion: %s", feedback)
    return category
