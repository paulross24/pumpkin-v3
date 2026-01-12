"""Helper functions for building and validating LLM prompts/responses."""

from __future__ import annotations

from typing import Callable


def generate_prompt(user_input: str) -> str:
    return f"User said: {user_input}. How can I assist you further?"


def validate_response(response: str) -> bool:
    if not isinstance(response, str):
        return False
    return len(response.strip()) >= 10


def process_user_input(user_input: str, llm_callable: Callable[[str], str]) -> str:
    prompt = generate_prompt(user_input)
    response = llm_callable(prompt)
    if validate_response(response):
        return response
    return "I'm sorry, I didn't understand that. Can you please rephrase?"
