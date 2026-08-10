from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

import yaml

from .errors import ConfigurationError, RepositoryError


MAX_STRUCTURED_FILE_BYTES = 20 * 1024 * 1024
MAX_STRUCTURED_NESTING = 128
MAX_STRUCTURED_NODES = 1_000_000


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON value is prohibited: {value}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key is prohibited: {key}")
        result[key] = value
    return result


class _UniqueKeySafeLoader(yaml.SafeLoader):
    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise yaml.composer.ComposerError(
                "while composing a structured control file",
                event.start_mark,
                "YAML aliases are prohibited",
                event.start_mark,
            )
        return super().compose_node(parent, index)


def _construct_unique_mapping(loader: _UniqueKeySafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError("while constructing a mapping", node.start_mark, "unhashable mapping key", key_node.start_mark) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError("while constructing a mapping", node.start_mark, f"duplicate key: {key!r}", key_node.start_mark)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


def _enforce_structured_limits(value: Any) -> Any:
    stack: list[tuple[Any, int]] = [(value, 0)]
    seen_containers: set[int] = set()
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_STRUCTURED_NODES:
            raise ValueError(f"Structured input exceeds {MAX_STRUCTURED_NODES} nodes")
        if depth > MAX_STRUCTURED_NESTING:
            raise ValueError(f"Structured input exceeds nesting depth {MAX_STRUCTURED_NESTING}")
        if isinstance(node, dict):
            identity = id(node)
            if identity in seen_containers:
                raise ValueError("Shared or recursive structured containers are prohibited")
            seen_containers.add(identity)
            for key, child in node.items():
                if not isinstance(key, str):
                    raise ValueError("Structured mapping keys must be strings")
                stack.append((child, depth + 1))
        elif isinstance(node, list):
            identity = id(node)
            if identity in seen_containers:
                raise ValueError("Shared or recursive structured containers are prohibited")
            seen_containers.add(identity)
            stack.extend((child, depth + 1) for child in node)
        elif node is None or isinstance(node, (str, bool, int)):
            continue
        elif isinstance(node, float):
            if not (float("-inf") < node < float("inf")):
                raise ValueError("Non-finite numeric values are prohibited")
        else:
            raise ValueError(f"Unsupported structured value type: {type(node).__name__}")
    return value


def strict_json_loads(text: str) -> Any:
    return _enforce_structured_limits(json.loads(
        text,
        object_pairs_hook=_unique_json_object,
        parse_constant=_reject_json_constant,
    ))


def strict_yaml_loads(text: str) -> Any:
    try:
        return _enforce_structured_limits(yaml.load(text, Loader=_UniqueKeySafeLoader))
    except yaml.YAMLError as exc:
        raise ValueError(str(exc)) from exc


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def hash_directory(root: Path, *, exclude: Iterable[str] = ()) -> str:
    ignored = set(exclude)
    entries: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in ignored or any(rel.startswith(item.rstrip("/") + "/") for item in ignored):
            continue
        entries.append({"path": rel, "sha256": sha256_file(path)})
    return sha256_json(entries)


def sha256_tree(root: Path, *, excluded_names: Iterable[str] = ()) -> str:
    """Compatibility wrapper that hashes regular files by stable relative path and content."""
    return hash_directory(root, exclude=excluded_names)


def load_data(path: Path) -> Any:
    if not path.exists():
        raise ConfigurationError(f"Missing file: {path}")
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError(f"Structured input must be a regular non-symlink file: {path}")
    size = path.stat().st_size
    if size > MAX_STRUCTURED_FILE_BYTES:
        raise ConfigurationError(f"Structured input exceeds {MAX_STRUCTURED_FILE_BYTES} bytes: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigurationError(f"Structured input must be UTF-8: {path}") from exc
    suffix = path.suffix.lower()
    try:
        if suffix in {".yaml", ".yml"}:
            return strict_yaml_loads(text)
        return strict_json_loads(text)
    except (yaml.YAMLError, json.JSONDecodeError, ValueError) as exc:
        raise ConfigurationError(f"Invalid structured file {path}: {exc}") from exc


def dump_json(value: Any, path: Path | None = None) -> str:
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    if path is not None:
        atomic_write(path, text.encode("utf-8"))
    return text


def dump_yaml(value: Any, path: Path | None = None) -> str:
    text = yaml.safe_dump(value, sort_keys=False, allow_unicode=True)
    if path is not None:
        atomic_write(path, text.encode("utf-8"))
    return text


def atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def safe_relative_path(raw: str) -> str:
    normalized = raw.replace("\\", "/")
    if "\x00" in normalized:
        raise ValueError("NUL byte in path")
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or re.match(r"^[A-Za-z]:", normalized):
        raise ValueError(f"Absolute path is not allowed: {raw}")
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError(f"Unsafe path segment: {raw}")
    return candidate.as_posix()


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _merged_env(overrides: dict[str, str] | None, *, inherit_env: bool = True) -> dict[str, str]:
    result = os.environ.copy() if inherit_env else {}
    if overrides:
        result.update({str(key): str(value) for key, value in overrides.items()})
    return result


def run_command(
    argv: Sequence[str], *, cwd: Path | None = None, timeout: int = 60,
    env: dict[str, str] | None = None, inherit_env: bool = True, check: bool = True,
) -> subprocess.CompletedProcess[str]:
    if not argv or not all(isinstance(arg, str) and "\x00" not in arg for arg in argv):
        raise ValueError("argv must be a non-empty sequence of NUL-free strings")
    try:
        result = subprocess.run(list(argv), cwd=str(cwd) if cwd else None, env=_merged_env(env, inherit_env=inherit_env), capture_output=True,
                                text=True, errors="replace", timeout=timeout, shell=False, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepositoryError(f"Command failed to execute: {argv[0]}: {exc}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-2000:]
        raise RepositoryError(f"Command failed ({result.returncode}): {' '.join(argv)}\n{detail}")
    return result


def run_command_bytes(
    argv: Sequence[str], *, cwd: Path | None = None, timeout: int = 60,
    env: dict[str, str] | None = None, inherit_env: bool = True, check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    if not argv or not all(isinstance(arg, str) and "\x00" not in arg for arg in argv):
        raise ValueError("argv must be a non-empty sequence of NUL-free strings")
    try:
        result = subprocess.run(list(argv), cwd=str(cwd) if cwd else None, env=_merged_env(env, inherit_env=inherit_env), capture_output=True,
                                text=False, timeout=timeout, shell=False, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepositoryError(f"Command failed to execute: {argv[0]}: {exc}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).decode("utf-8", errors="replace")[-2000:]
        raise RepositoryError(f"Command failed ({result.returncode}): {' '.join(argv)}\n{detail}")
    return result


def unique_preserve_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set(); result: list[str] = []
    for item in items:
        if item not in seen:
            result.append(item); seen.add(item)
    return result


def redact_url_credentials(url: str) -> str:
    return re.sub(r"(https?://)[^/@]+@", r"\1<redacted>@", url)


def walk_regular_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())
