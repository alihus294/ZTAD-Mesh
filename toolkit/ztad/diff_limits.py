from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from .repository import GitRepository


IGNORED_NAMES = {
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
    "poetry.lock", "uv.lock", "Cargo.lock", "go.sum",
}
GENERATED_MARKERS = ("/generated/", "/dist/", "/build/", ".min.js", ".map")


def is_counted_path(path: str) -> bool:
    normalized = "/" + path.replace("\\", "/")
    if PurePosixPath(path).name in IGNORED_NAMES:
        return False
    if any(marker in normalized for marker in GENERATED_MARKERS):
        return False
    return True


def evaluate_diff_limits(repo: GitRepository, base: str, head: str, risk: str, policy: dict[str, Any]) -> dict[str, Any]:
    limits = policy.get(risk, {}) or policy.get("default", {}) or {}
    changed = repo.changed_paths(base, head)
    stats = repo.numstat(base, head)
    counted_files = sorted({item.path for item in changed if is_counted_path(item.path)})
    logical_loc = sum((item.additions or 0) + (item.deletions or 0) for item in stats if is_counted_path(item.path))
    binary_files = [item.path for item in stats if item.binary]
    max_files = int(limits.get("max_files", 10_000))
    max_loc = int(limits.get("max_logical_loc", 10_000_000))
    violations: list[str] = []
    if len(counted_files) > max_files:
        violations.append(f"file_count {len(counted_files)} exceeds {max_files}")
    if logical_loc > max_loc:
        violations.append(f"logical_loc {logical_loc} exceeds {max_loc}")
    if binary_files and not limits.get("allow_binary", False):
        violations.append("binary changes are not permitted in this risk envelope")
    return {
        "risk": risk,
        "passed": not violations,
        "counted_files": counted_files,
        "file_count": len(counted_files),
        "logical_loc": logical_loc,
        "binary_files": binary_files,
        "violations": violations,
        "decision": "CONTINUE" if not violations else "SPLIT_OR_ESCALATE",
    }
