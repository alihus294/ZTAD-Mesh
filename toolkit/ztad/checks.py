from __future__ import annotations

import json
import os
import platform
import re
import sys
import tempfile
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

from .commands import validate_command
from .repository import GitRepository
from .schema_validation import validate_file
from .util import atomic_write, load_data, run_command, run_command_bytes, sha256_bytes, sha256_file, sha256_json, utc_now

BASE_ENV_ALLOWLIST = {
    "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
}
SENSITIVE_NAME = re.compile(r"(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|API_KEY|ACCESS_KEY|SESSION|COOKIE)", re.I)
REDACTION_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+|basic\s+)?[^\s]+"),
    re.compile(r"(?i)((?:token|secret|password|passwd|api[_-]?key|access[_-]?key)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
)


def _redact(text: str) -> str:
    result = text
    for pattern in REDACTION_PATTERNS:
        result = pattern.sub(r"\1<redacted>" if pattern.groups else "<redacted>", result)
    return result


def _safe_environment(config: dict[str, Any]) -> tuple[dict[str, str], list[str], Path]:
    requested = config.get("environment_allowlist", []) or []
    if not isinstance(requested, list) or not all(isinstance(item, str) and item for item in requested):
        raise ValueError("environment_allowlist must be an array of non-empty names")
    if any(SENSITIVE_NAME.search(name) for name in requested):
        raise ValueError("Sensitive environment variables cannot be passed to local checks")
    names = BASE_ENV_ALLOWLIST | set(requested)
    env = {name: os.environ[name] for name in sorted(names) if name in os.environ}
    isolated_home = Path(tempfile.mkdtemp(prefix="ztad-check-home-"))
    for child in ("config", "cache", "data", "tmp"):
        (isolated_home / child).mkdir(mode=0o700, exist_ok=True)
    env.update({
        "CI": "true",
        "NO_COLOR": "1",
        "FORCE_COLOR": "0",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "HOME": str(isolated_home),
        "USERPROFILE": str(isolated_home),
        "XDG_CONFIG_HOME": str(isolated_home / "config"),
        "XDG_CACHE_HOME": str(isolated_home / "cache"),
        "XDG_DATA_HOME": str(isolated_home / "data"),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "PIP_CONFIG_FILE": os.devnull,
        "npm_config_userconfig": str(isolated_home / "config" / "npmrc"),
        "NPM_CONFIG_USERCONFIG": str(isolated_home / "config" / "npmrc"),
        "AWS_EC2_METADATA_DISABLED": "true",
    })
    return env, sorted(env), isolated_home


def _safe_cwd(repo: Path, relative: str) -> Path:
    target = (repo / relative).resolve()
    try:
        target.relative_to(repo.resolve())
    except ValueError as exc:
        raise ValueError(f"Check cwd escapes repository: {relative}") from exc
    if not target.is_dir():
        raise ValueError(f"Check cwd is not a directory: {relative}")
    return target


def _toolchain_fingerprint(config_path: Path, command_policy_path: Path) -> str:
    packages: dict[str, str] = {}
    try:
        from importlib.metadata import version
        for name in ("PyYAML", "jsonschema", "cryptography"):
            try:
                packages[name] = version(name)
            except Exception:
                packages[name] = "not-installed"
    except Exception:
        pass
    return sha256_json({
        "python": sys.version,
        "platform": platform.platform(),
        "config_hash": sha256_file(config_path),
        "command_policy_hash": sha256_file(command_policy_path),
        "packages": packages,
    })


def _worktree_state(repo: GitRepository) -> dict[str, Any]:
    """Capture a stable Git worktree state without exposing file contents.

    The state includes tracked modifications and untracked paths. It is used to
    fail closed when a supposedly verification-only command mutates the
    repository. A command that mutates and restores the exact state is outside
    this detector's claim boundary and still requires an external disposable
    sandbox.
    """
    result = run_command_bytes(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=repo.root,
        check=True,
    )
    entries = [item for item in result.stdout.split(b"\x00") if item]
    return {
        "sha256": sha256_bytes(result.stdout),
        "entry_count": len(entries),
    }


def run_checks(
    repo_path: Path | str,
    *,
    base: str,
    head: str,
    contract_path: Path,
    config_path: Path,
    command_policy_path: Path,
    policy_bundle_hash: str,
    output_dir: Path,
    selected_ids: set[str] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    repo = GitRepository(repo_path)
    base_sha = repo.rev_parse(base)
    head_sha = repo.rev_parse(head)
    if repo.current_head() != head_sha:
        raise ValueError("Checks must run on a checkout whose HEAD equals the requested head SHA")
    schema_path = Path(__file__).resolve().parents[2] / "schemas/check-config.schema.json"
    schema_errors = validate_file(config_path, schema_path)
    if schema_errors:
        raise ValueError("Invalid check configuration: " + "; ".join(schema_errors))
    config = load_data(config_path)
    command_policy = load_data(command_policy_path)
    if not isinstance(config, dict) or config.get("configured") is not True:
        raise ValueError("Check configuration is not explicitly reviewed and configured")
    if not isinstance(command_policy, dict):
        raise ValueError("Command policy must be a mapping")
    configured_ids = {str(item["id"]) for item in config["checks"]}
    if selected_ids is not None and selected_ids - configured_ids:
        raise ValueError("Unknown selected check ids: " + ", ".join(sorted(selected_ids - configured_ids)))

    contract_hash = sha256_file(contract_path)
    toolchain_hash = _toolchain_fingerprint(config_path, command_policy_path)
    env: dict[str, str] = {}
    env_names: list[str] = []
    isolated_home: Path | None = None
    results: list[dict[str, Any]] = []
    any_repository_mutation = False

    try:
        env, env_names, isolated_home = _safe_environment(config)
        for item in config["checks"]:
            check_id = str(item["id"])
            if selected_ids is not None and check_id not in selected_ids:
                continue
            argv = item["argv"]
            validation = validate_command(argv, command_policy, workspace_root=repo.root)
            if not validation["allowed"]:
                results.append({"check_id": check_id, "status": "POLICY_BLOCKED", "validation": validation})
                continue
            cwd = _safe_cwd(repo.root, str(item["cwd"]))
            timeout = int(item.get("timeout_seconds", 300))
            if dry_run:
                results.append({
                    "check_id": check_id,
                    "status": "DRY_RUN",
                    "argv": argv,
                    "cwd": str(cwd),
                    "command_id": validation["command_id"],
                })
                continue

            before_state = _worktree_state(repo)
            started = utc_now()
            monotonic_start = time.monotonic()
            proc = run_command(argv, cwd=cwd, timeout=timeout, env=env, inherit_env=False, check=False)
            ended = utc_now()
            duration_ms = int((time.monotonic() - monotonic_start) * 1000)
            after_state = _worktree_state(repo)
            repository_mutated = before_state["sha256"] != after_state["sha256"]
            any_repository_mutation = any_repository_mutation or repository_mutated

            combined = _redact((proc.stdout or "") + "\n--- STDERR ---\n" + (proc.stderr or ""))
            encoded = combined.encode("utf-8", errors="replace")
            max_output = int(config.get("max_output_bytes", 2_000_000))
            if max_output < 10_000 or max_output > 20_000_000:
                raise ValueError("max_output_bytes must be between 10,000 and 20,000,000")
            truncated = len(encoded) > max_output
            if truncated:
                encoded = encoded[:max_output] + b"\n<output truncated by ZTAD>\n"

            if repository_mutated and proc.returncode != 0:
                status = "FAILED_AND_REPOSITORY_MUTATED"
            elif repository_mutated:
                status = "REPOSITORY_MUTATED"
            else:
                status = "PASSED" if proc.returncode == 0 else "FAILED"

            evidence_id = f"ev-local-{check_id.lower().replace('_', '-')}-{head_sha[:12]}-{uuid.uuid4().hex[:10]}"
            evidence = {
                "evidence_id": evidence_id,
                "type": str(item["evidence_type"]),
                "trust_level": "E2",
                "producer": "tool:ztad-local-check-runner",
                "repository": str(repo.root),
                "change_contract_hash": contract_hash,
                "base_sha": base_sha,
                "head_sha": head_sha,
                "policy_bundle_hash": policy_bundle_hash,
                "toolchain_hash": toolchain_hash,
                "environment": "local",
                "command_id": validation["command_id"],
                "exit_code": proc.returncode,
                "status": status,
                "output_hash": sha256_bytes(encoded),
                "artifact_digest": None,
                "created_at": ended,
                "expires_at": None,
                "invalidated_by": [],
                "signature_or_attestation": None,
                "metadata": {
                    "check_id": check_id,
                    "argv": argv,
                    "cwd": str(cwd.relative_to(repo.root)),
                    "started_at": started,
                    "ended_at": ended,
                    "duration_ms": duration_ms,
                    "timeout_seconds": timeout,
                    "output_truncated": truncated,
                    "environment_names_included": env_names,
                    "stdout_stderr_tail": encoded.decode("utf-8", errors="replace")[-4000:],
                    "repository_mutated": repository_mutated,
                    "worktree_before_hash": before_state["sha256"],
                    "worktree_after_hash": after_state["sha256"],
                    "worktree_before_entries": before_state["entry_count"],
                    "worktree_after_entries": after_state["entry_count"],
                    "claim_boundary": "Local E2 evidence is never merge- or release-authoritative; mutation detection compares Git state before and after the command.",
                },
            }
            output_dir.mkdir(parents=True, exist_ok=True)
            evidence_path = output_dir / f"{evidence_id}.json"
            atomic_write(evidence_path, (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8"))
            results.append({
                "check_id": check_id,
                "status": status,
                "exit_code": proc.returncode,
                "repository_mutated": repository_mutated,
                "evidence_id": evidence_id,
                "evidence_path": str(evidence_path),
            })
            if status != "PASSED" and bool(item.get("fail_fast", True)):
                break

        if not results:
            raise ValueError("No checks were selected")
        blocked_statuses = {
            "FAILED",
            "FAILED_AND_REPOSITORY_MUTATED",
            "REPOSITORY_MUTATED",
            "POLICY_BLOCKED",
        }
        blocked = any(item["status"] in blocked_statuses for item in results)
        return {
            "schema_version": 1,
            "repository": str(repo.root),
            "base_sha": base_sha,
            "head_sha": head_sha,
            "dry_run": dry_run,
            "repository_mutated": False if dry_run else any_repository_mutation,
            "blocked": blocked,
            "results": results,
            "decision": "CONTAIN_TASK_AND_CONTINUE_QUEUE" if blocked else ("DRY_RUN_ONLY" if dry_run else "CONTINUE"),
            "execution_boundary": {
                "home_isolated": True,
                "credentials_inherited": False,
                "network_isolation": "EXTERNAL_SANDBOX_REQUIRED",
                "repository_mutation_detection": "GIT_STATE_DELTA",
            },
            "claim_boundary": "ZTAD isolates HOME and credential configuration and detects persistent Git-state mutation, but network/process/filesystem isolation and disposable checkout enforcement must be provided by the external sandbox or protected CI runner.",
        }
    finally:
        if isolated_home is not None:
            shutil.rmtree(isolated_home, ignore_errors=True)


def classify_check_history(records: list[dict[str, Any]], check_id: str, head_sha: str) -> dict[str, Any]:
    """Classify repeated results without treating fail-then-pass as a clean pass."""
    matching: list[dict[str, Any]] = []
    for record in records:
        metadata = record.get("metadata", {}) if isinstance(record, dict) else {}
        record_check = metadata.get("check_id") or metadata.get("configured_check_id")
        command_id = record.get("command_id") if isinstance(record, dict) else None
        if record.get("head_sha") != head_sha:
            continue
        if check_id not in {record_check, command_id}:
            continue
        matching.append(record)
    matching.sort(key=lambda item: str(item.get("created_at", "")))
    statuses = [str(item.get("status", "UNKNOWN")) for item in matching]
    passed = any(status == "PASSED" for status in statuses)
    failed_statuses = {"FAILED", "FAILED_AND_REPOSITORY_MUTATED", "REPOSITORY_MUTATED", "POLICY_BLOCKED"}
    failed = any(status in failed_statuses for status in statuses)
    if failed and passed:
        classification = "FLAKY_OR_ENVIRONMENT_DEPENDENT"
        blocking = True
    elif failed:
        classification = "CONSISTENT_FAILURE"
        blocking = True
    elif passed:
        classification = "CONSISTENT_PASS" if len(statuses) == 1 or all(status == "PASSED" for status in statuses) else "INCONCLUSIVE"
        blocking = classification != "CONSISTENT_PASS"
    else:
        classification = "NO_MATCHING_EVIDENCE"
        blocking = True
    return {
        "check_id": check_id,
        "head_sha": head_sha,
        "classification": classification,
        "blocking": blocking,
        "statuses": statuses,
        "evidence_ids": [str(item.get("evidence_id")) for item in matching],
        "claim_boundary": "A fail-then-pass history is not a clean pass.",
    }
