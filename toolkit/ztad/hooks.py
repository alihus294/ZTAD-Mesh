from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from .commands import split_hook_command, validate_command
from .control_plane import detect_control_plane_changes, scan_patch_text
from .orchestrator import ContinuityStore
from .util import load_data

MUTATING_PLATFORM_WORDS = {
    "create", "update", "delete", "remove", "send", "publish", "deploy", "release",
    "push", "merge", "approve", "grant", "revoke", "rotate", "write", "execute",
}
NETWORK_TOOL_WORDS = {"web", "browser", "fetch", "http", "search", "curl", "request"}
SENSITIVE_PERMISSION_WORDS = {
    "unrestricted", "full disk", "all files", "production", "credential", "secret", "token",
    "network", "internet", "admin", "administrator", "root", "bypass", "disable sandbox",
}


def _plugin_root() -> Path:
    value = os.getenv("PLUGIN_ROOT")
    if value:
        return Path(value).resolve()
    return Path(__file__).resolve().parents[2]


def _cwd(payload: dict[str, Any]) -> Path:
    raw = payload.get("cwd") or os.getcwd()
    return Path(str(raw)).resolve()


def _active_db(cwd: Path) -> Path | None:
    explicit = os.getenv("ZTAD_CONTINUITY_DB")
    if explicit:
        path = Path(explicit).resolve()
        return path if path.is_file() else None
    for root in (cwd, *cwd.parents):
        candidate = root / ".delivery" / "ztad" / "continuity.db"
        if candidate.is_file():
            return candidate
    return None


def _active(cwd: Path) -> bool:
    return _active_db(cwd) is not None or os.getenv("ZTAD_ENFORCE_HOOKS") == "1"


def _deny(reason: str, *, event: str = "PreToolUse") -> dict[str, Any]:
    if event == "PermissionRequest":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": "deny", "message": reason},
            }
        }
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _allow_context(text: str, event: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}}


def _extract_paths(tool_name: str, tool_input: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("path", "file_path", "filepath", "target", "destination", "directory", "cwd", "root"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            values.append(value)
    if tool_name.casefold() in {"apply_patch", "edit", "write"}:
        patch = tool_input.get("patch") or tool_input.get("input") or tool_input.get("content")
        if isinstance(patch, str):
            for line in patch.splitlines():
                if line.startswith(("+++ ", "--- ")):
                    raw = line[4:].split("\t", 1)[0]
                    if raw != "/dev/null":
                        values.append(raw[2:] if raw.startswith(("a/", "b/")) else raw)
    return values


def _tool_words(tool_name: str) -> set[str]:
    return {item for item in re.split(r"[^a-z0-9]+", tool_name.casefold()) if item}


def _permission_text(payload: dict[str, Any]) -> str:
    parts = [str(payload.get(key, "")) for key in ("permission", "reason", "description", "message")]
    tool_input = payload.get("tool_input") or payload.get("toolInput") or {}
    if isinstance(tool_input, dict):
        parts.extend(str(value) for value in tool_input.values() if isinstance(value, (str, int, float, bool)))
    return " ".join(parts).casefold()


def _pretool(payload: dict[str, Any], *, permission_request: bool = False) -> dict[str, Any] | None:
    event = "PermissionRequest" if permission_request else "PreToolUse"
    cwd = _cwd(payload)
    if not _active(cwd):
        return None
    tool_name = str(payload.get("tool_name") or payload.get("toolName") or "")
    tool_input = payload.get("tool_input") or payload.get("toolInput") or {}
    if not isinstance(tool_input, dict):
        return _deny("Malformed tool input", event=event)
    words = _tool_words(tool_name)
    if permission_request:
        text = _permission_text(payload)
        if any(word in text for word in SENSITIVE_PERMISSION_WORDS):
            return _deny("ZTAD denies broad, secret-bearing, production, network, or sandbox-bypass permissions; use a pre-authorized narrow controller.", event=event)
    compact_name = tool_name.casefold()
    if (words & NETWORK_TOOL_WORDS or any(word in compact_name for word in NETWORK_TOOL_WORDS)) and os.getenv("ZTAD_NETWORK_ALLOWED") != "1":
        return _deny("ZTAD network policy is deny-by-default for model sessions.", event=event)
    if words & MUTATING_PLATFORM_WORDS and ("mcp" in words or "github" in words or "deploy" in words or "production" in words):
        return _deny("Direct platform mutation is prohibited; use the evidence-gated platform adapter.", event=event)
    root = _plugin_root()
    if words & {"bash", "shell", "powershell", "command", "exec", "terminal"}:
        command = tool_input.get("command") or tool_input.get("cmd")
        if not isinstance(command, str):
            return _deny("Shell tool input lacks a string command", event=event)
        try:
            argv = split_hook_command(command)
        except ValueError as exc:
            return _deny(f"ZTAD blocked non-atomic shell input: {exc}", event=event)
        policy = load_data(root / "policies" / "command-policy.yaml")
        result = validate_command(argv, policy, workspace_root=cwd)
        if not result["allowed"]:
            return _deny("ZTAD command policy: " + "; ".join(result["reasons"]), event=event)
    paths = _extract_paths(tool_name, tool_input)
    if paths:
        path_policy = load_data(root / "policies" / "path-policy.yaml")
        try:
            control = detect_control_plane_changes(paths, path_policy)
        except ValueError as exc:
            return _deny(f"ZTAD rejected unsafe path: {exc}", event=event)
        if control["blocked"]:
            return _deny("ZTAD protected-path boundary: " + "; ".join(item["code"] for item in control["findings"]), event=event)
    patch = tool_input.get("patch") or tool_input.get("input")
    if isinstance(patch, str) and words & {"apply_patch", "edit", "write"}:
        findings = scan_patch_text(patch)
        if any(item.get("severity") == "BLOCK" for item in findings):
            return _deny("ZTAD patch boundary: " + "; ".join(str(item.get("code")) for item in findings), event=event)
    return None


def handle_hook(event: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    if event == "SessionStart":
        return _allow_context(
            "ZTAD Mesh is explicit-only. Hooks are guardrails, not proof of complete enforcement. When invoked, use durable state, adaptive routing, isolated worktrees, exact-SHA evidence, and task-local containment.",
            event,
        )
    if event == "PreToolUse":
        return _pretool(payload)
    if event == "PermissionRequest":
        return _pretool(payload, permission_request=True)
    if event == "PostToolUse":
        if not _active(_cwd(payload)):
            return None
        tool_name = str(payload.get("tool_name") or payload.get("toolName") or "")
        if _tool_words(tool_name) & {"apply_patch", "edit", "write", "bash", "shell", "powershell", "exec"}:
            return _allow_context(
                "A mutating tool completed. Recompute the diff, risk, scope, test-integrity and evidence bindings before any approval or transition.",
                event,
            )
        return None
    if event == "SubagentStart":
        agent_type = str(payload.get("agent_type") or payload.get("agentType") or "unknown")
        return _allow_context(
            f"ZTAD role isolation applies to subagent '{agent_type}'. A session may not approve a SHA it implemented, and model text is never machine evidence.",
            event,
        )
    if event == "SubagentStop":
        return _allow_context("Record the subagent result in durable state before using it; do not infer success from session completion.", event)
    if event in {"Stop", "SessionEnd"}:
        # Never create a stop-hook loop. Durable continuity belongs to the scheduler
        # service, not to repeatedly blocking one interactive session from ending.
        return None
    return None


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    if len(argv) != 1:
        print(json.dumps({"error": "usage: ztad_hook.py <EVENT>"}))
        return 2
    event = argv[0]
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("Hook input must be an object")
        output = handle_hook(event, payload)
        if output is not None:
            json.dump(output, sys.stdout, sort_keys=True)
            sys.stdout.write("\n")
        return 0
    except Exception as exc:
        if event in {"PreToolUse", "PermissionRequest"}:
            json.dump(_deny(f"ZTAD hook failed closed: {exc}", event=event), sys.stdout, sort_keys=True)
            sys.stdout.write("\n")
            return 0
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
