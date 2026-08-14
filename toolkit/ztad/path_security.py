from __future__ import annotations

import fnmatch
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Iterable

_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_UNC = re.compile(r"^(?:\\\\|//)")


def is_link_like(path: Path) -> bool:
    """Return whether *path* is a symlink or filesystem reparse point."""
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        return bool(reparse_point and attributes & reparse_point)
    except FileNotFoundError:
        return False
    except OSError:
        return True


def normalize_repo_path(raw: str, *, case_insensitive: bool = False) -> str:
    """Normalize a repository-relative path without touching the filesystem.

    The function intentionally rejects traversal and absolute path spellings. It
    uses NFC normalization and forward slashes so policy matching is stable on
    Windows, macOS, and Linux.
    """
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValueError("Path must be a non-empty NUL-free string")
    value = unicodedata.normalize("NFC", raw.strip()).replace("\\", "/")
    if value.startswith("/") or _DRIVE.match(value) or _UNC.match(value):
        raise ValueError(f"Absolute or drive-qualified path is prohibited: {raw}")
    parts: list[str] = []
    for part in value.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError(f"Path traversal is prohibited: {raw}")
        parts.append(part)
    if not parts:
        raise ValueError("Path resolves to repository root rather than a file")
    normalized = "/".join(parts)
    return normalized.casefold() if case_insensitive else normalized


def filesystem_case_insensitive(platform_name: str | None = None) -> bool:
    platform_name = (platform_name or os.name).lower()
    return platform_name in {"nt", "windows", "win32", "darwin", "mac", "macos"}


def _pattern_variants(pattern: str) -> set[str]:
    pattern = unicodedata.normalize("NFC", pattern).replace("\\", "/")
    if pattern.startswith("./"):
        pattern = pattern[2:]
    pattern = pattern.lstrip("/")
    variants = {pattern}
    # Python fnmatch("pytest.ini", "**/pytest.ini") is false. Policy authors
    # generally expect **/ to include the repository root, so add that variant.
    while pattern.startswith("**/"):
        pattern = pattern[3:]
        variants.add(pattern)
    return variants


def path_matches(path: str, pattern: str, *, case_insensitive: bool = False) -> bool:
    candidate = normalize_repo_path(path, case_insensitive=case_insensitive)
    patterns = _pattern_variants(pattern)
    if case_insensitive:
        patterns = {item.casefold() for item in patterns}
    return any(fnmatch.fnmatchcase(candidate, item) for item in patterns)


def any_path_matches(path: str, patterns: Iterable[str], *, case_insensitive: bool = False) -> bool:
    return any(path_matches(path, pattern, case_insensitive=case_insensitive) for pattern in patterns)


def resolve_within(
    root: Path,
    raw: str,
    *,
    allow_nonexistent: bool = True,
    extra_roots: Iterable[Path] = (),
) -> Path:
    """Resolve *raw* and prove it remains under root or explicitly allowed roots."""
    root = root.resolve()
    candidate_raw = Path(raw)
    if _DRIVE.match(raw) or _UNC.match(raw):
        # A Windows-qualified path is never interpreted as repository-relative
        # on a non-Windows host. Rejecting it avoids C:/... becoming a literal
        # child directory when validation runs on Linux CI.
        raise ValueError(f"Drive-qualified or UNC path is prohibited: {raw}")
    if candidate_raw.is_absolute():
        candidate = candidate_raw.resolve(strict=not allow_nonexistent)
    else:
        candidate = (root / candidate_raw).resolve(strict=not allow_nonexistent)
    roots = [root, *(item.resolve() for item in extra_roots)]
    for allowed in roots:
        try:
            candidate.relative_to(allowed)
            return candidate
        except ValueError:
            continue
    raise ValueError(f"Path escapes allowed roots: {raw}")


def command_path_token(raw: str) -> bool:
    """Conservative heuristic for argv values that are likely filesystem paths."""
    if not raw or raw == "-":
        return False
    if raw.startswith(("http://", "https://")):
        return False
    return (
        raw.startswith((".", "/", "\\", "~"))
        or _DRIVE.match(raw) is not None
        or _UNC.match(raw) is not None
        or "/" in raw
        or "\\" in raw
        or raw.endswith((".py", ".js", ".ts", ".json", ".toml", ".yaml", ".yml", ".xml", ".csproj", ".sln"))
    )


@dataclass(frozen=True)
class PathPolicyResult:
    protected: bool
    prohibited: bool
    normalized: str
    matched_protected: tuple[str, ...]
    matched_prohibited: tuple[str, ...]


def evaluate_policy_path(
    raw: str,
    *,
    protected_patterns: Iterable[str],
    prohibited_patterns: Iterable[str],
    case_insensitive: bool,
) -> PathPolicyResult:
    normalized = normalize_repo_path(raw, case_insensitive=case_insensitive)
    protected = tuple(
        p for p in protected_patterns if path_matches(raw, p, case_insensitive=case_insensitive)
    )
    prohibited = tuple(
        p for p in prohibited_patterns if path_matches(raw, p, case_insensitive=case_insensitive)
    )
    return PathPolicyResult(bool(protected), bool(prohibited), normalized, protected, prohibited)
