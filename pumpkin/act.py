"""Action execution."""

from __future__ import annotations

from typing import Any, Dict, List

import os
import subprocess
import urllib.request

from . import settings

from .audit import append_jsonl


ACTION_METADATA = {
    "notify.local": {
        "description": "Emit a local notification into the audit log.",
        "verification": "Confirm the notification entry exists in the audit log.",
        "rollback": "No rollback needed; the message is informational.",
    },
    "code.apply_patch": {
        "description": "Apply a unified diff patch to an allowed repository root.",
        "verification": "Verify patch applied cleanly and service health is OK.",
        "rollback": "Revert the patch or restore from backup if needed.",
    },
}


def notify_local(message: str, audit_path: str) -> Dict[str, Any]:
    entry = {
        "kind": "notify.local",
        "message": message,
    }
    append_jsonl(audit_path, entry)
    print(f"[notify.local] {message}")
    return {"delivered": True}


def execute_action(
    action_type: str, params: Dict[str, Any], audit_path: str
) -> Dict[str, Any]:
    if action_type == "notify.local":
        return notify_local(params.get("message", ""), audit_path)
    if action_type == "code.apply_patch":
        return apply_patch_action(params, audit_path)
    raise ValueError(f"unsupported action_type: {action_type}")


def apply_patch_action(params: Dict[str, Any], audit_path: str) -> Dict[str, Any]:
    patch_text = params.get("patch")
    repo_root = params.get("repo_root")
    if not isinstance(patch_text, str) or not patch_text.strip():
        raise ValueError("patch_missing")
    if not isinstance(repo_root, str) or not repo_root.strip():
        raise ValueError("repo_root_missing")

    allowed_roots = _allowed_roots()
    if not _path_allowed(repo_root, allowed_roots):
        raise ValueError("repo_root_not_allowed")

    _validate_patch_paths(patch_text, repo_root, allowed_roots)
    strip_level = 1 if _patch_uses_prefixes(patch_text) else 0
    result = subprocess.run(
        ["patch", f"-p{strip_level}", "-N", "-r", "-"],
        input=patch_text.encode("utf-8"),
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(f"patch_failed: {result.stderr.decode('utf-8', 'ignore')}")
    append_jsonl(
        audit_path,
        {
            "kind": "code.apply_patch",
            "repo_root": repo_root,
            "files": _patch_files(patch_text),
        },
    )
    return {"applied": True, "repo_root": repo_root}


def verify_health(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.getcode()
            return {"ok": code == 200, "status_code": code}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _allowed_roots() -> List[str]:
    return [os.path.realpath(path) for path in settings.code_assistant_roots()]


def _path_allowed(path: str, allowed_roots: List[str]) -> bool:
    target = os.path.realpath(path)
    for root in allowed_roots:
        if target == root or target.startswith(root + os.sep):
            return True
    return False


def _patch_uses_prefixes(patch_text: str) -> bool:
    for line in patch_text.splitlines():
        if line.startswith("+++ b/") or line.startswith("--- a/"):
            return True
    return False


def _patch_files(patch_text: str) -> List[str]:
    files: List[str] = []
    for line in patch_text.splitlines():
        if line.startswith("+++ ") or line.startswith("--- "):
            path = line[4:].split("\t")[0].strip()
            if path == "/dev/null":
                continue
            if path.startswith("a/") or path.startswith("b/"):
                path = path[2:]
            files.append(path)
    return files


def _validate_patch_paths(patch_text: str, repo_root: str, allowed_roots: List[str]) -> None:
    root = os.path.realpath(repo_root)
    for path in _patch_files(patch_text):
        if os.path.isabs(path):
            target = os.path.realpath(path)
        else:
            target = os.path.realpath(os.path.join(root, path))
        if not _path_allowed(target, allowed_roots):
            raise ValueError(f"patch_path_not_allowed: {path}")
