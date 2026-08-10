from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .repository import GitRepository
from .path_security import any_path_matches, filesystem_case_insensitive, normalize_repo_path
from .util import load_data


@dataclass(frozen=True)
class ControlPlaneFinding:
    code: str
    severity: str
    path: str | None
    message: str

    def to_dict(self) -> dict[str, str | None]:
        return {"code": self.code, "severity": self.severity, "path": self.path, "message": self.message}


def protected_paths(paths: Iterable[str], policy: dict[str, Any]) -> list[str]:
    patterns = policy.get("protected_paths", []) or []
    case_insensitive = bool(policy.get("case_insensitive_paths", filesystem_case_insensitive()))
    return sorted({path for path in paths if any_path_matches(path, patterns, case_insensitive=case_insensitive)})


def prohibited_paths(paths: Iterable[str], policy: dict[str, Any]) -> list[str]:
    patterns = policy.get("prohibited_patch_paths", []) or []
    case_insensitive = bool(policy.get("case_insensitive_paths", filesystem_case_insensitive()))
    return sorted({path for path in paths if any_path_matches(path, patterns, case_insensitive=case_insensitive)})


def detect_control_plane_changes(paths: Iterable[str], policy: dict[str, Any]) -> dict[str, Any]:
    case_insensitive = bool(policy.get("case_insensitive_paths", filesystem_case_insensitive()))
    normalized = sorted({normalize_repo_path(path, case_insensitive=case_insensitive) for path in paths})
    protected = protected_paths(normalized, policy)
    prohibited = prohibited_paths(normalized, policy)
    app = [path for path in normalized if path not in protected and path not in prohibited]
    findings: list[ControlPlaneFinding] = []
    for path in prohibited:
        findings.append(
            ControlPlaneFinding(
                code="PROHIBITED_PATCH_PATH",
                severity="BLOCK",
                path=path,
                message="The patch touches a prohibited repository or Git-control path.",
            )
        )
    for path in protected:
        findings.append(
            ControlPlaneFinding(
                code="PROTECTED_PATH_CHANGED",
                severity="BLOCK",
                path=path,
                message="Protected delivery or agent-control asset changed; use a separate high-risk control-plane PR.",
            )
        )
    if protected and app:
        findings.append(
            ControlPlaneFinding(
                code="MIXED_CONTROL_AND_APPLICATION_CHANGE",
                severity="BLOCK",
                path=None,
                message="Application and control-plane changes are combined in one change.",
            )
        )
    return {
        "protected_paths": protected,
        "prohibited_paths": prohibited,
        "application_paths": app,
        "blocked": any(item.severity == "BLOCK" for item in findings),
        "findings": [item.to_dict() for item in findings],
    }


def inspect_git_object_modes(repo: GitRepository, head: str, changed_paths: Iterable[str]) -> list[dict[str, str]]:
    modes = repo.ls_tree_modes(head)
    findings: list[dict[str, str]] = []
    for path in changed_paths:
        mode = modes.get(path)
        if mode == "120000":
            findings.append({"code": "SYMLINK_CHANGED", "severity": "BLOCK", "path": path})
        elif mode == "160000":
            findings.append({"code": "SUBMODULE_CHANGED", "severity": "BLOCK", "path": path})
        elif mode and mode not in {"100644", "100755"}:
            findings.append({"code": "UNEXPECTED_GIT_MODE", "severity": "BLOCK", "path": path, "mode": mode})
    return findings


def scan_patch_text(patch_text: str) -> list[dict[str, str | None]]:
    findings: list[dict[str, str | None]] = []
    if "GIT binary patch" in patch_text or re.search(r"^Binary files .* differ$", patch_text, re.MULTILINE):
        findings.append({"code": "BINARY_PATCH", "severity": "BLOCK", "path": None, "message": "Binary patches require isolated protected-controller handling."})
    for line in patch_text.splitlines():
        if line.startswith(("+++ ", "--- ")):
            raw = line[4:].split("\t", 1)[0]
            if raw == "/dev/null":
                continue
            if raw.startswith(("a/", "b/")):
                raw = raw[2:]
            path = raw.replace("\\", "/")
            parts = path.split("/")
            if path.startswith("/") or ".." in parts or ".git" in parts:
                findings.append({"code": "UNSAFE_PATCH_PATH", "severity": "BLOCK", "path": path, "message": "Patch contains an unsafe path."})
    if re.search(r"^new file mode 120000$|^old mode 120000$", patch_text, re.MULTILINE):
        findings.append({"code": "SYMLINK_MODE_CHANGE", "severity": "BLOCK", "path": None, "message": "Symlink creation or modification is prohibited."})
    if re.search(r"^new file mode 160000$|^old mode 160000$", patch_text, re.MULTILINE):
        findings.append({"code": "SUBMODULE_MODE_CHANGE", "severity": "BLOCK", "path": None, "message": "Submodule changes are prohibited."})
    if re.search(r"^old mode 100644\nnew mode 100755$", patch_text, re.MULTILINE):
        findings.append({"code": "EXECUTABLE_BIT_ADDED", "severity": "ESCALATE", "path": None, "message": "Executable permission was added."})
    return findings


def load_path_policy(path: Path) -> dict[str, Any]:
    data = load_data(path)
    if not isinstance(data, dict):
        raise ValueError("Path policy must be a mapping")
    return data
