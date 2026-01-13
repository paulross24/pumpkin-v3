"""Lightweight local context retrieval."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, List


_STOPWORDS = {
    "the",
    "and",
    "for",
    "that",
    "this",
    "with",
    "you",
    "your",
    "have",
    "has",
    "from",
    "what",
    "when",
    "where",
    "who",
    "why",
    "how",
    "are",
    "is",
    "was",
    "were",
    "can",
    "could",
    "should",
    "would",
    "will",
    "please",
    "pumpkin",
}


def _extract_keywords(query: str, max_terms: int = 6) -> List[str]:
    words = re.findall(r"[a-zA-Z0-9]{3,}", query.lower())
    keywords = [word for word in words if word not in _STOPWORDS]
    return keywords[:max_terms]


def _read_tail(path: Path, max_bytes: int = 200_000, max_lines: int = 2000) -> List[str]:
    if not path.exists():
        return []
    data = path.read_bytes()
    if len(data) > max_bytes:
        data = data[-max_bytes:]
    text = data.decode("utf-8", errors="ignore")
    lines = text.splitlines()
    return lines[-max_lines:]


def _matches(line: str, keywords: Iterable[str]) -> bool:
    lowered = line.lower()
    return any(word in lowered for word in keywords)


def search_audit(audit_path: Path, query: str, max_results: int = 5) -> List[Dict[str, str]]:
    keywords = _extract_keywords(query)
    if not keywords:
        return []
    results: List[Dict[str, str]] = []
    for line in _read_tail(audit_path):
        if _matches(line, keywords):
            results.append({"source": "audit", "snippet": line[:400]})
            if len(results) >= max_results:
                break
    return results


def search_file(path: Path, query: str, max_results: int = 3) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    keywords = _extract_keywords(query)
    if not keywords:
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []
    results: List[Dict[str, str]] = []
    for line in lines:
        if _matches(line, keywords):
            results.append({"source": str(path), "snippet": line[:400]})
            if len(results) >= max_results:
                break
    return results


def retrieve_context(query: str, audit_path: Path, config_paths: Iterable[Path], max_results: int = 5) -> List[Dict[str, str]]:
    if not isinstance(query, str) or not query.strip():
        return []
    results: List[Dict[str, str]] = []
    results.extend(search_audit(audit_path, query, max_results=max_results))
    if len(results) >= max_results:
        return results[:max_results]
    for path in config_paths:
        results.extend(search_file(path, query, max_results=max_results))
        if len(results) >= max_results:
            break
    return results[:max_results]
