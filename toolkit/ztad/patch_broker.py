from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .control_plane import detect_control_plane_changes, inspect_git_object_modes, scan_patch_text
from .repository import GitRepository
from .util import run_command

MAX_PATCH_BYTES = 5_000_000


def _isolated_git_env(home: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "true",
        "LC_ALL": "C",
    }


def validate_patch(
    repo: GitRepository,
    patch_path: Path,
    *,
    expected_base: str,
    path_policy: dict[str, Any],
) -> dict[str, Any]:
    if patch_path.is_symlink() or not patch_path.is_file():
        return {"valid": False, "findings": [{"code": "PATCH_NOT_REGULAR_FILE", "severity": "BLOCK", "path": str(patch_path)}]}
    size = patch_path.stat().st_size
    if size == 0:
        return {"valid": False, "findings": [{"code": "EMPTY_PATCH", "severity": "BLOCK", "path": str(patch_path)}]}
    if size > MAX_PATCH_BYTES:
        return {"valid": False, "findings": [{"code": "PATCH_TOO_LARGE", "severity": "BLOCK", "path": str(patch_path), "bytes": str(size)}]}

    patch_text = patch_path.read_text(encoding="utf-8", errors="replace")
    findings = scan_patch_text(patch_text)
    base_sha = repo.rev_parse(expected_base)
    if findings and any(item.get("severity") == "BLOCK" for item in findings):
        return {"valid": False, "base_sha": base_sha, "findings": findings}

    with tempfile.TemporaryDirectory(prefix="ztad-patch-") as temp_dir:
        temp = Path(temp_dir)
        isolated_home = temp / "home"
        isolated_home.mkdir(mode=0o700)
        env = _isolated_git_env(isolated_home)
        work = temp / "repo"
        run_command(
            ["git", "-c", "protocol.file.allow=always", "clone", "--no-local", "--no-checkout", "--", str(repo.root), str(work)],
            timeout=120,
            env=env,
            inherit_env=False,
        )
        run_command(["git", "-c", "core.hooksPath=/dev/null", "checkout", "--detach", base_sha], cwd=work, env=env, inherit_env=False)
        copied_patch = temp / "change.patch"
        shutil.copyfile(patch_path, copied_patch)
        check = run_command(
            ["git", "-c", "core.hooksPath=/dev/null", "apply", "--check", "--whitespace=error-all", "--", str(copied_patch)],
            cwd=work,
            env=env,
            inherit_env=False,
            check=False,
        )
        if check.returncode != 0:
            findings.append({"code": "PATCH_APPLY_CHECK_FAILED", "severity": "BLOCK", "path": None, "message": (check.stderr or check.stdout)[-1000:]})
            return {"valid": False, "base_sha": base_sha, "findings": findings}
        run_command(
            ["git", "-c", "core.hooksPath=/dev/null", "apply", "--index", "--whitespace=error-all", "--", str(copied_patch)],
            cwd=work,
            env=env,
            inherit_env=False,
        )
        staged = run_command(["git", "diff", "--cached", "--quiet"], cwd=work, env=env, inherit_env=False, check=False)
        if staged.returncode == 0:
            findings.append({"code": "PATCH_HAS_NO_EFFECT", "severity": "BLOCK", "path": None, "message": "Patch applies but produces no staged change."})
            return {"valid": False, "base_sha": base_sha, "findings": findings}
        if staged.returncode not in {0, 1}:
            findings.append({"code": "PATCH_STAGE_INSPECTION_FAILED", "severity": "BLOCK", "path": None})
            return {"valid": False, "base_sha": base_sha, "findings": findings}
        run_command(
            [
                "git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
                "-c", "user.name=ZTAD Patch Broker", "-c", "user.email=ztad@invalid",
                "commit", "--no-verify", "-m", "validated patch",
            ],
            cwd=work,
            env=env,
            inherit_env=False,
        )
        validated_repo = GitRepository(work)
        head_sha = validated_repo.current_head()
        changed = validated_repo.changed_paths(base_sha, head_sha)
        paths = [item.path for item in changed]
        control = detect_control_plane_changes(paths, path_policy)
        findings.extend(control["findings"])
        findings.extend(inspect_git_object_modes(validated_repo, head_sha, paths))
        blocked = any(item.get("severity") == "BLOCK" for item in findings)
        escalation = any(item.get("severity") == "ESCALATE" for item in findings)
        return {
            "valid": not blocked,
            "requires_escalation": escalation,
            "base_sha": base_sha,
            "validated_head_sha": head_sha,
            "changed_paths": paths,
            "findings": findings,
            "claim_boundary": "Patch validation proves bounded applicability and path/mode policy only; it does not prove behavioral correctness.",
        }
