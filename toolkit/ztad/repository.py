from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .errors import RepositoryError
from .util import run_command, run_command_bytes, safe_relative_path


@dataclass(frozen=True)
class ChangedPath:
    status: str
    path: str
    old_path: str | None = None


@dataclass(frozen=True)
class NumStat:
    path: str
    additions: int | None
    deletions: int | None
    binary: bool


class GitRepository:
    """Read a local Git repository through a constrained, non-interactive Git boundary.

    The wrapper disables user/system configuration, hooks, fsmonitor, replacement
    objects, pagers, credential prompts, and optional locks. It performs no fetch,
    push, clone, submodule, or remote execution.
    """

    _CONFIG = (
        "-c", f"core.hooksPath={os.devnull}",
        "-c", "core.fsmonitor=false",
        "-c", "core.untrackedCache=false",
        "-c", "credential.helper=",
        "-c", "core.pager=cat",
        "-c", "pager.branch=false",
        "-c", "pager.diff=false",
        "-c", "pager.log=false",
        "-c", "pager.show=false",
    )

    def __init__(self, root: Path | str):
        requested = Path(root).resolve()
        if not requested.exists() or not requested.is_dir():
            raise RepositoryError(f"Repository path does not exist or is not a directory: {requested}")
        self._env = self._safe_git_env()
        result = self._run(["rev-parse", "--show-toplevel"], cwd=requested, check=False)
        if result.returncode != 0:
            raise RepositoryError(f"Not a Git repository: {requested}")
        self.root = Path(result.stdout.strip()).resolve()
        if not self.root.is_dir():
            raise RepositoryError(f"Git top level is not a directory: {self.root}")

    @staticmethod
    def _safe_git_env() -> dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "LC_ALL": "C",
            "LANG": "C",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "true",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_ATTR_NOSYSTEM": "1",
        }
        for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TMPDIR", "TMP", "TEMP"):
            if name in os.environ:
                env[name] = os.environ[name]
        return env

    @classmethod
    def _git_argv(cls, args: Sequence[str]) -> list[str]:
        return ["git", *cls._CONFIG, *args]

    def _run(self, args: Sequence[str], *, cwd: Path | None = None, check: bool = True, timeout: int = 60):
        return run_command(
            self._git_argv(args),
            cwd=cwd or getattr(self, "root", None),
            env=self._env,
            inherit_env=False,
            check=check,
            timeout=timeout,
        )

    def _run_bytes(self, args: Sequence[str], *, cwd: Path | None = None, check: bool = True, timeout: int = 60):
        return run_command_bytes(
            self._git_argv(args),
            cwd=cwd or self.root,
            env=self._env,
            inherit_env=False,
            check=check,
            timeout=timeout,
        )

    def rev_parse(self, revision: str) -> str:
        if not revision or revision.startswith("-") or any(value in revision for value in ("\x00", "\n", "\r")):
            raise RepositoryError(f"Unsafe revision: {revision!r}")
        result = self._run(["rev-parse", "--verify", f"{revision}^{{commit}}"])
        sha = result.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40,64}", sha):
            raise RepositoryError(f"Unexpected revision output: {sha!r}")
        return sha

    def current_head(self) -> str:
        return self.rev_parse("HEAD")

    def merge_base(self, base: str, head: str) -> str:
        result = self._run(["merge-base", self.rev_parse(base), self.rev_parse(head)])
        sha = result.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40,64}", sha):
            raise RepositoryError("Unable to determine merge base")
        return sha

    def changed_paths(self, base: str, head: str) -> list[ChangedPath]:
        result = self._run(["diff", "--name-status", "-z", "--find-renames", self.rev_parse(base), self.rev_parse(head), "--"])
        fields = result.stdout.split("\x00")
        if fields and fields[-1] == "":
            fields.pop()
        changed: list[ChangedPath] = []
        index = 0
        while index < len(fields):
            status = fields[index]
            index += 1
            if status.startswith(("R", "C")):
                if index + 1 >= len(fields):
                    raise RepositoryError("Malformed git diff name-status output")
                old_path = safe_relative_path(fields[index])
                new_path = safe_relative_path(fields[index + 1])
                index += 2
                changed.append(ChangedPath(status=status, path=new_path, old_path=old_path))
            else:
                if index >= len(fields):
                    raise RepositoryError("Malformed git diff name-status output")
                changed.append(ChangedPath(status=status, path=safe_relative_path(fields[index])))
                index += 1
        return changed

    def numstat(self, base: str, head: str) -> list[NumStat]:
        result = self._run(["diff", "--numstat", "-z", self.rev_parse(base), self.rev_parse(head), "--"])
        fields = result.stdout.split("\x00")
        if fields and fields[-1] == "":
            fields.pop()
        stats: list[NumStat] = []
        for field in fields:
            parts = field.split("\t", 2)
            if len(parts) != 3:
                continue
            added_raw, deleted_raw, path_raw = parts
            binary = added_raw == "-" or deleted_raw == "-"
            stats.append(
                NumStat(
                    path=safe_relative_path(path_raw),
                    additions=None if binary else int(added_raw),
                    deletions=None if binary else int(deleted_raw),
                    binary=binary,
                )
            )
        return stats

    def diff(self, base: str, head: str, paths: Iterable[str] | None = None, unified: int = 3) -> str:
        if unified < 0 or unified > 10000:
            raise RepositoryError("Diff context must be between 0 and 10000 lines")
        argv = ["diff", f"--unified={unified}", "--no-ext-diff", "--no-textconv", self.rev_parse(base), self.rev_parse(head), "--"]
        if paths:
            argv.extend(safe_relative_path(path) for path in paths)
        return self._run(argv).stdout

    def show_bytes(self, revision: str, path: str) -> bytes:
        result = self._run_bytes(["show", f"{self.rev_parse(revision)}:{safe_relative_path(path)}"], check=False)
        if result.returncode != 0:
            raise RepositoryError(f"File not found at {revision}: {path}")
        return result.stdout

    def show_text(self, revision: str, path: str) -> str:
        return self.show_bytes(revision, path).decode("utf-8", errors="replace")

    def ls_tree_modes(self, revision: str) -> dict[str, str]:
        result = self._run(["ls-tree", "-r", "-z", self.rev_parse(revision)])
        entries: dict[str, str] = {}
        for record in result.stdout.split("\x00"):
            if not record:
                continue
            try:
                meta, path_raw = record.split("\t", 1)
                mode, _type, _sha = meta.split(" ", 2)
            except ValueError as exc:
                raise RepositoryError("Malformed git ls-tree output") from exc
            entries[safe_relative_path(path_raw)] = mode
        return entries

    def remote_urls(self) -> list[str]:
        result = self._run(["remote", "-v"], check=False)
        if result.returncode != 0:
            return []
        return sorted({parts[1] for line in result.stdout.splitlines() if len(parts := line.split()) >= 2})

    def status_porcelain(self) -> list[str]:
        result = self._run(["status", "--porcelain=v1", "-z", "--untracked-files=normal"])
        return [item for item in result.stdout.split("\x00") if item]
