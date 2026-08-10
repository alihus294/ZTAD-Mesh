from __future__ import annotations

import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .bundle import validate_bundle
from .util import utc_now


def _command(argv: list[str], *, timeout: int = 30) -> dict[str, Any]:
    try:
        proc = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False, shell=False)
        return {
            "available": proc.returncode == 0,
            "argv": argv,
            "exit_code": proc.returncode,
            "stdout": (proc.stdout or "")[-2000:],
            "stderr": (proc.stderr or "")[-2000:],
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "argv": argv, "error": f"{type(exc).__name__}: {exc}"}


def _python_packages() -> dict[str, Any]:
    requirements = {"PyYAML": "6.0.3", "jsonschema": "4.26.0"}
    result: dict[str, Any] = {}
    for name, minimum in requirements.items():
        try:
            version = importlib.metadata.version(name)
            result[name] = {"installed": True, "version": version, "minimum_expected": minimum}
        except importlib.metadata.PackageNotFoundError:
            result[name] = {"installed": False, "version": None, "minimum_expected": minimum}
    try:
        cryptography = importlib.metadata.version("cryptography")
        result["cryptography"] = {"installed": True, "version": cryptography, "required_range": ">=50.0.0,<51"}
    except importlib.metadata.PackageNotFoundError:
        result["cryptography"] = {"installed": False, "version": None, "required_range": ">=50.0.0,<51"}
    return result


def _plugin_state() -> dict[str, Any]:
    if shutil.which("codex") is None:
        return {"checked": False, "reason": "codex_not_found"}
    result = _command(["codex", "plugin", "list", "--json"])
    if not result.get("available"):
        return {"checked": False, "reason": "plugin_list_unavailable", "command": result}
    try:
        payload = json.loads(result.get("stdout") or "{}")
    except json.JSONDecodeError:
        return {"checked": False, "reason": "plugin_list_invalid_json", "command": result}
    installed = payload.get("installed", payload if isinstance(payload, list) else [])
    matches = [
        item for item in installed or [] if isinstance(item, dict) and item.get("name") == "zero-trust-agentic-delivery"
    ]
    return {"checked": True, "installed_matches": matches, "installed_and_enabled": any(item.get("enabled", True) for item in matches)}


def audit_host_acceptance(
    *,
    plugin_root: Path,
    repository: Path | None = None,
    inspect_codex_plugin_state: bool = True,
) -> dict[str, Any]:
    plugin_root = plugin_root.resolve()
    bundle = validate_bundle(plugin_root)
    git = _command(["git", "--version"]) if shutil.which("git") else {"available": False, "reason": "not_found"}
    codex = _command(["codex", "--version"]) if shutil.which("codex") else {"available": False, "reason": "not_found"}
    codex_exec = _command(["codex", "exec", "--help"]) if codex.get("available") else {"available": False, "reason": "codex_unavailable"}
    gh = _command(["gh", "--version"]) if shutil.which("gh") else {"available": False, "reason": "not_found"}
    python_ok = sys.version_info >= (3, 11)
    package_state = _python_packages()
    cryptography_version = package_state["cryptography"].get("version") or "0"
    try:
        crypto_parts = tuple(int(part) for part in cryptography_version.split(".")[:3])
    except ValueError:
        crypto_parts = (0,)
    signing_ready = (50, 0, 0) <= crypto_parts < (51, 0, 0)
    hooks_trust = os.getenv("ZTAD_HOOKS_TRUSTED") == "1"
    plugin = _plugin_state() if inspect_codex_plugin_state else {"checked": False, "reason": "disabled_by_caller"}
    repo = None
    if repository is not None:
        repo_path = repository.resolve()
        repo = {
            "path": str(repo_path),
            "exists": repo_path.is_dir(),
            "git_repository": (repo_path / ".git").exists(),
            "continuity_database": str(repo_path / ".delivery/ztad/continuity.db"),
        }
    mode = "ADVISORY_ONLY"
    blockers: list[str] = []
    if not bundle.get("valid"):
        blockers.append("plugin_bundle_invalid")
    if not git.get("available"):
        blockers.append("git_unavailable")
    if not python_ok:
        blockers.append("python_below_3_11")
    if not blockers:
        mode = "LOCAL_VERIFICATION_ONLY"
    if mode == "LOCAL_VERIFICATION_ONLY" and codex_exec.get("available") and hooks_trust:
        mode = "GOVERNED_LOCAL_DEVELOPMENT"
    # GitHub CLI presence is not proof of authentication, repository access,
    # branch protection, merge queue, required checks or least-privilege tokens.
    # Remote governance can only be raised by a separate GitHub audit that emits
    # authoritative platform evidence, never by this local probe.
    return {
        "generated_at": utc_now(),
        "plugin_root": str(plugin_root),
        "bundle": bundle,
        "python": {"executable": sys.executable, "version": sys.version.split()[0], "supported": python_ok, "packages": package_state, "signing_ready": signing_ready},
        "git": git,
        "codex": codex,
        "codex_exec": codex_exec,
        "codex_plugin_state": plugin,
        "github_cli": gh,
        "github_remote_governance_verified": False,
        "hooks": {
            "trusted_attestation_env": hooks_trust,
            "claim_boundary": "The host must explicitly trust plugin hooks; file presence alone is not activation evidence.",
        },
        "repository": repo,
        "maximum_verified_mode": mode,
        "blockers": blockers,
        "claim_boundary": "This is a non-mutating local probe. GitHub CLI presence never raises the mode; Remote branch protection, merge queue, deployment and runtime health require authoritative platform evidence.",
    }
