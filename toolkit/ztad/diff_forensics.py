from __future__ import annotations

"""Machine-generated Git diff inventories for authoritative diff forensics."""

import copy
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import RepositoryError
from .repository import GitRepository
from .util import canonical_json, safe_relative_path, sha256_bytes, sha256_file


@dataclass(frozen=True)
class GitDiffInventory:
    base_sha: str
    candidate_sha: str
    diff_hash: str
    files: tuple[dict[str, Any], ...]

    @property
    def inventory_hash(self) -> str:
        return sha256_bytes(canonical_json(self.to_dict(include_hash=False)))

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "base_sha": self.base_sha,
            "candidate_sha": self.candidate_sha,
            "diff_hash": self.diff_hash,
            "files": [copy.deepcopy(item) for item in self.files],
        }
        if include_hash:
            result["inventory_hash"] = self.inventory_hash
        return result


def _inventory(repo: GitRepository, base_sha: str, candidate_sha: str) -> GitDiffInventory:
    resolved_base = repo.rev_parse(base_sha)
    resolved_candidate = repo.rev_parse(candidate_sha)
    changed = repo.changed_paths(resolved_base, resolved_candidate)
    files = tuple(
        {
            "path": item.path,
            "status": item.status,
            "old_path": item.old_path,
        }
        for item in changed
    )
    return GitDiffInventory(
        base_sha=resolved_base,
        candidate_sha=resolved_candidate,
        diff_hash=sha256_bytes(repo.diff_bytes(resolved_base, resolved_candidate)),
        files=files,
    )


def collect_git_diff_inventory(repository_root: Path | str, *, base_sha: str, candidate_sha: str) -> dict[str, Any]:
    """Enumerate every changed path from Git for two immutable revisions."""

    return _inventory(GitRepository(repository_root), base_sha, candidate_sha).to_dict()


def collect_worktree_diff_inventory(repository_root: Path | str, *, base_sha: str) -> dict[str, Any]:
    """Enumerate a candidate working tree, including untracked files.

    A working tree is represented by a deterministic candidate identity rather
    than being misreported as a commit.  Protected CI must replace that
    identity with the exact commit SHA before a terminal gate.
    """

    repo = GitRepository(repository_root)
    resolved_base = repo.rev_parse(base_sha)
    changed = repo.worktree_changed_paths(resolved_base)
    base_modes = repo.ls_tree_modes(resolved_base)

    def filesystem_material(relative_path: str) -> dict[str, Any]:
        safe = safe_relative_path(relative_path)
        absolute = repo.root.joinpath(*safe.split("/"))
        try:
            info = os.lstat(absolute)
        except FileNotFoundError:
            return {
                "kind": "absent",
                "mode": None,
                "filesystem_mode": None,
                "content_hash": None,
            }
        except OSError as exc:
            raise RepositoryError(f"Unable to inspect changed path: {safe}") from exc
        filesystem_mode = format(stat.S_IMODE(info.st_mode), "04o")
        if stat.S_ISLNK(info.st_mode):
            try:
                target = os.readlink(absolute)
            except OSError as exc:
                raise RepositoryError(f"Unable to read symlink identity: {safe}") from exc
            return {
                "kind": "symlink",
                "mode": "120000",
                "filesystem_mode": filesystem_mode,
                "content_hash": sha256_bytes(os.fsencode(target)),
            }
        if stat.S_ISREG(info.st_mode):
            try:
                content_hash = sha256_file(absolute)
            except OSError as exc:
                raise RepositoryError(f"Unable to read changed path: {safe}") from exc
            return {
                "kind": "file",
                "mode": "100755" if info.st_mode & stat.S_IXUSR else "100644",
                "filesystem_mode": filesystem_mode,
                "content_hash": content_hash,
            }
        raise RepositoryError(f"Unsupported changed filesystem object: {safe}")

    files: list[dict[str, Any]] = []
    for item in sorted(
        changed,
        key=lambda value: (
            str(value.get("path") or ""),
            str(value.get("old_path") or ""),
            str(value.get("status") or ""),
        ),
    ):
        path = str(item["path"])
        old_path = str(item["old_path"]) if item.get("old_path") else None
        base_path = old_path or path
        base_content_hash: str | None = None
        if base_path in base_modes:
            try:
                base_content_hash = sha256_bytes(repo.show_bytes(resolved_base, base_path))
            except RepositoryError:
                # A submodule or other non-blob entry still has an authoritative
                # mode and is covered by the Git diff layer hashes below.
                base_content_hash = None
        final = filesystem_material(path)
        files.append(
            {
                "path": path,
                "status": item["status"],
                "old_path": old_path,
                "base_mode": base_modes.get(base_path),
                "base_content_hash": base_content_hash,
                "working_tree_kind": final["kind"],
                "working_tree_mode": final["mode"],
                "working_tree_filesystem_mode": final["filesystem_mode"],
                "working_tree_content_hash": final["content_hash"],
            }
        )

    diff_layers = {
        "head_to_index": sha256_bytes(repo.staged_diff_bytes()),
        "index_to_worktree": sha256_bytes(repo.unstaged_diff_bytes()),
        "head_to_worktree": sha256_bytes(repo.worktree_diff_bytes(resolved_base)),
    }
    fingerprint_material = {
        "fingerprint_version": 2,
        "base_sha": resolved_base,
        "diff_layers": diff_layers,
        "files": files,
    }
    # The hash is over canonical relative-path records and all three Git
    # materializations.  It therefore does not depend on checkout location,
    # enumeration order, or filesystem timestamps.
    diff_hash = sha256_bytes(canonical_json(fingerprint_material))
    candidate_sha = "working-tree:" + sha256_bytes(
        canonical_json(
            {
                "fingerprint_version": 2,
                "base_sha": resolved_base,
                "diff_hash": diff_hash,
                "files": files,
            }
        )
    )
    return GitDiffInventory(
        base_sha=resolved_base,
        candidate_sha=candidate_sha,
        diff_hash=diff_hash,
        files=tuple(copy.deepcopy(files)),
    ).to_dict()


def validate_git_inventory(inventory: Any) -> list[str]:
    if not isinstance(inventory, dict):
        return ["DIFF_FORENSICS_PASS requires a machine-generated Git inventory"]
    errors: list[str] = []
    for field in ("base_sha", "candidate_sha", "diff_hash", "inventory_hash", "files"):
        if field not in inventory:
            errors.append(f"Git diff inventory requires {field}")
    files = inventory.get("files")
    if not isinstance(files, list):
        errors.append("Git diff inventory files must be an array")
        return sorted(set(errors))
    seen: set[str] = set()
    for index, item in enumerate(files):
        if not isinstance(item, dict) or not item.get("path"):
            errors.append(f"Git diff inventory file {index} is invalid")
            continue
        path = str(item["path"])
        try:
            safe_relative_path(path)
        except ValueError:
            errors.append(f"Git diff inventory path is unsafe: {path}")
        if path in seen:
            errors.append(f"Git diff inventory contains a duplicate path: {path}")
        seen.add(path)
        old_path = item.get("old_path")
        if old_path is not None:
            try:
                safe_relative_path(str(old_path))
            except ValueError:
                errors.append(f"Git diff inventory old path is unsafe: {old_path}")
        if not str(item.get("status") or ""):
            errors.append(f"Git diff inventory status is required for {path}")
    expected_hash = sha256_bytes(canonical_json({key: inventory.get(key) for key in ("base_sha", "candidate_sha", "diff_hash", "files")}))
    if inventory.get("inventory_hash") != expected_hash:
        errors.append("Git diff inventory hash is invalid")
    return sorted(set(errors))


def compare_git_inventory(metadata: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    errors = validate_git_inventory(actual)
    errors.extend(validate_git_inventory(metadata.get("git_inventory")))
    if errors:
        return sorted(set(errors))
    if metadata.get("git_inventory") != actual:
        errors.append("DIFF_FORENSICS_PASS metadata does not match the machine-generated Git inventory")
    return sorted(set(errors))
