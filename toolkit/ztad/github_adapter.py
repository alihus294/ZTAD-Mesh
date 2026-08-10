from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .util import run_command

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


@dataclass(frozen=True)
class GitHubActionResult:
    operation: str
    success: bool
    exit_code: int
    payload: dict[str, Any] | None
    stdout: str
    stderr: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "success": self.success,
            "exit_code": self.exit_code,
            "payload": self.payload,
            "stdout": self.stdout[-2000:],
            "stderr": self.stderr[-2000:],
        }


class GitHubCliAdapter:
    """Explicitly gated GitHub CLI adapter.

    Read operations are available by default. Mutating operations require an
    adapter instance constructed with ``allow_write=True``. This is only a
    transport adapter: remote policy, authentication, branch protection and
    least-privilege credentials must be proven separately by platform evidence.
    """

    def __init__(self, *, repo_slug: str, allow_write: bool = False, executor: Callable[..., Any] = run_command):
        if not REPO_RE.fullmatch(repo_slug):
            raise ValueError("repo_slug must be owner/repository")
        self.repo_slug = repo_slug
        self.allow_write = allow_write
        self.executor = executor

    @staticmethod
    def _safe_branch(value: str) -> str:
        if (
            not value
            or value.startswith("-")
            or value.endswith("/")
            or "//" in value
            or ".." in value
            or value.endswith(".lock")
            or not BRANCH_RE.fullmatch(value)
        ):
            raise ValueError("Unsafe branch name")
        return value

    @staticmethod
    def _safe_body_file(raw: str) -> str:
        if not raw or "\x00" in raw:
            raise ValueError("Invalid pull-request body file")
        path = Path(raw).expanduser()
        if path.is_symlink() or not path.is_file():
            raise ValueError("Pull-request body file must be a regular non-symlink file")
        return str(path.resolve())

    def probe(self) -> dict[str, Any]:
        return {
            "available": shutil.which("gh") is not None,
            "repo_slug": self.repo_slug,
            "write_enabled": self.allow_write,
            "claim_boundary": "CLI presence is not proof of authentication, repository access, protected rules or least-privilege credentials.",
        }

    def _run(self, operation: str, argv: list[str], *, expect_json: bool = True) -> GitHubActionResult:
        proc = self.executor(argv, timeout=120, check=False)
        payload = None
        if expect_json and (proc.stdout or "").strip():
            try:
                parsed = json.loads(proc.stdout)
                payload = parsed if isinstance(parsed, dict) else {"value": parsed}
            except json.JSONDecodeError:
                payload = None
        return GitHubActionResult(
            operation,
            proc.returncode == 0,
            proc.returncode,
            payload,
            proc.stdout or "",
            proc.stderr or "",
        )

    def view_pull_request(self, number: int) -> GitHubActionResult:
        if number < 1:
            raise ValueError("pull request number must be positive")
        return self._run(
            "view_pull_request",
            [
                "gh", "pr", "view", str(number), "--repo", self.repo_slug,
                "--json", "number,state,headRefOid,baseRefName,mergeStateStatus,statusCheckRollup,url",
            ],
        )

    def create_pull_request(self, *, head: str, base: str, title: str, body_file: str) -> GitHubActionResult:
        if not self.allow_write:
            raise PermissionError("GitHub write operations are disabled")
        head = self._safe_branch(head)
        base = self._safe_branch(base)
        title = title.strip()
        if not title or len(title) > 256 or any(ord(ch) < 32 and ch not in "\t" for ch in title):
            raise ValueError("Pull-request title must be non-empty, bounded and free of control characters")
        body_path = self._safe_body_file(body_file)

        # `gh pr create` returns a URL as text; it does not provide the same
        # stable JSON fields as `gh pr view`. Create first, then query the exact
        # created PR through the documented JSON-capable read command.
        created = self._run(
            "create_pull_request",
            [
                "gh", "pr", "create", "--repo", self.repo_slug,
                "--head", head, "--base", base, "--title", title,
                "--body-file", body_path,
            ],
            expect_json=False,
        )
        if not created.success:
            return created
        url = (created.stdout or "").strip().splitlines()[-1] if (created.stdout or "").strip() else ""
        if not url.startswith("https://"):
            return GitHubActionResult(
                "create_pull_request", False, 1, None, created.stdout,
                (created.stderr + "\nGitHub CLI did not return a pull-request URL").strip(),
            )
        viewed = self._run(
            "create_pull_request",
            ["gh", "pr", "view", url, "--repo", self.repo_slug, "--json", "number,url,headRefOid,baseRefName,state"],
        )
        return GitHubActionResult(
            "create_pull_request",
            viewed.success,
            viewed.exit_code,
            viewed.payload,
            created.stdout + viewed.stdout,
            "\n".join(part for part in (created.stderr, viewed.stderr) if part),
        )

    def enable_auto_merge(self, number: int, *, merge: bool = True) -> GitHubActionResult:
        if not self.allow_write:
            raise PermissionError("GitHub write operations are disabled")
        if number < 1:
            raise ValueError("pull request number must be positive")
        strategy = "--merge" if merge else "--squash"
        return self._run(
            "enable_auto_merge",
            ["gh", "pr", "merge", str(number), "--repo", self.repo_slug, "--auto", strategy],
            expect_json=False,
        )
