from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from .repository import GitRepository
from .util import run_command, run_command_bytes, safe_relative_path, sha256_file


def _canonical_patch_bytes(path: Path) -> bytes:
    """Recover canonical LF patch framing after Windows text-mode transport."""

    return path.read_bytes().replace(b"\r\n", b"\n")


class WorktreeManager:
    """Create disposable detached worktrees beneath a repository-local managed root."""

    def __init__(self, repo: GitRepository, root: Path | None = None):
        self.repo = repo
        self.root = (root or repo.root / ".delivery" / "ztad" / "worktrees").resolve()
        try:
            self.root.relative_to(repo.root.resolve())
        except ValueError as exc:
            raise ValueError("Worktree root must remain inside the repository") from exc
        self.root.mkdir(parents=True, exist_ok=True)

    def create(self, node_id: str, base_sha: str) -> Path:
        name = safe_relative_path(node_id).replace("/", "-")
        target = (self.root / name).resolve()
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("Unsafe worktree path") from exc
        if target.exists():
            raise FileExistsError(f"Managed worktree already exists: {target}")
        run_command(
            [
                "git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=",
                "worktree", "add", "--detach", "--no-checkout", str(target), self.repo.rev_parse(base_sha),
            ],
            cwd=self.repo.root,
            timeout=120,
        )
        run_command(
            ["git", "-c", "core.hooksPath=/dev/null", "checkout", "--detach", self.repo.rev_parse(base_sha)],
            cwd=target,
            timeout=120,
        )
        return target

    def apply_patches(self, worktree: Path, patches: list[Path]) -> dict[str, object]:
        applied: list[dict[str, str]] = []
        with tempfile.TemporaryDirectory(prefix="ztad-apply-") as temp_dir:
            canonical_root = Path(temp_dir)
            for index, patch in enumerate(patches):
                resolved = patch.resolve()
                if not resolved.is_file() or resolved.is_symlink():
                    raise ValueError(f"Patch artifact must be a regular file: {patch}")
                canonical = canonical_root / f"{index}.patch"
                canonical.write_bytes(_canonical_patch_bytes(resolved))
                run_command(
                    ["git", "-c", "core.hooksPath=/dev/null", "apply", "--check", "--binary", str(canonical)],
                    cwd=worktree, timeout=120,
                )
                run_command(
                    ["git", "-c", "core.hooksPath=/dev/null", "apply", "--index", "--binary", "--whitespace=nowarn", str(canonical)],
                    cwd=worktree, timeout=120,
                )
                applied.append({"path": str(resolved), "sha256": sha256_file(resolved)})
        return {"applied": applied, "count": len(applied)}

    def patch(self, worktree: Path, base_sha: str, output: Path) -> dict[str, object]:
        status = run_command(
            ["git", "-c", "core.hooksPath=/dev/null", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=worktree,
            timeout=120,
        ).stdout.split("\x00")
        untracked: list[str] = []
        for entry in status:
            if not entry:
                continue
            if entry.startswith("?? "):
                untracked.append(safe_relative_path(entry[3:]))
        if untracked:
            run_command(
                ["git", "-c", "core.hooksPath=/dev/null", "add", "--intent-to-add", "--", *untracked],
                cwd=worktree,
                timeout=120,
            )
        result = run_command_bytes(
            ["git", "-c", "core.hooksPath=/dev/null", "diff", "--binary", "--no-ext-diff", "--no-textconv", self.repo.rev_parse(base_sha), "--"],
            cwd=worktree,
            timeout=120,
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(result.stdout)
        names = run_command(
            ["git", "-c", "core.hooksPath=/dev/null", "diff", "--name-only", "-z", self.repo.rev_parse(base_sha), "--"],
            cwd=worktree,
            timeout=120,
        ).stdout.split("\x00")
        paths = sorted(safe_relative_path(item) for item in names if item)
        return {"patch_path": str(output), "changed_paths": paths, "has_changes": bool(result.stdout)}

    def materialize_candidate(self, worktree: Path, base_sha: str, *, message: str = "ZTAD deterministic candidate") -> str:
        """Create a deterministic detached commit for the staged/working candidate.

        Identical trees over the same parent produce the same SHA across isolated
        worktrees. This gives reviewers, checks and approvals one exact subject.
        """
        base = self.repo.rev_parse(base_sha)
        run_command(["git", "-c", "core.hooksPath=/dev/null", "add", "-A", "--"], cwd=worktree, timeout=120)
        tree = run_command(["git", "write-tree"], cwd=worktree, timeout=120).stdout.strip()
        base_tree = run_command(["git", "rev-parse", f"{base}^{{tree}}"], cwd=worktree, timeout=120).stdout.strip()
        if tree == base_tree:
            raise ValueError("Candidate tree is identical to the base tree")
        env = {
            "GIT_AUTHOR_NAME": "ZTAD Candidate Controller",
            "GIT_AUTHOR_EMAIL": "ztad-candidate@example.invalid",
            "GIT_COMMITTER_NAME": "ZTAD Candidate Controller",
            "GIT_COMMITTER_EMAIL": "ztad-candidate@example.invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
        }
        candidate = run_command(
            ["git", "-c", "commit.gpgSign=false", "commit-tree", tree, "-p", base, "-m", message],
            cwd=worktree, timeout=120, env=env, inherit_env=True,
        ).stdout.strip()
        if not candidate or len(candidate) not in {40, 64}:
            raise ValueError("Git did not return a valid candidate commit SHA")
        run_command(["git", "-c", "core.hooksPath=/dev/null", "reset", "--hard", candidate], cwd=worktree, timeout=120)
        return candidate

    def remove(self, worktree: Path) -> None:
        result = run_command(
            ["git", "-c", "core.hooksPath=/dev/null", "worktree", "remove", "--force", str(worktree)],
            cwd=self.repo.root,
            timeout=120,
            check=False,
        )
        if result.returncode != 0 and worktree.exists():
            shutil.rmtree(worktree, ignore_errors=True)
        run_command(["git", "worktree", "prune"], cwd=self.repo.root, timeout=60, check=False)
