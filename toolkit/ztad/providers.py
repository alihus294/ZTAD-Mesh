from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, Sequence, Mapping

from .schema_validation import validate_instance
from .util import atomic_write, canonical_json, load_data, sha256_bytes, utc_now

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
# Double quotes are retained for argv quoting by ``list2cmdline``; shell
# metacharacters and control characters are rejected before the shim is used.
_CMD_UNSAFE_CHARS = frozenset("&|<>^()%!")


def _command_argv(argv: Sequence[str]) -> list[str]:
    """Resolve command shims without enabling shell interpolation."""
    if not argv:
        raise ValueError("Provider argv must not be empty")
    resolved = shutil.which(argv[0]) or argv[0]
    command = [resolved, *argv[1:]]
    if os.name == "nt" and Path(resolved).suffix.casefold() in {".cmd", ".bat"}:
        if any(
            any(ord(character) < 32 or character in _CMD_UNSAFE_CHARS for character in item)
            for item in command
        ):
            raise ValueError("Windows command shim arguments contain prohibited shell metacharacters")
        comspec = os.environ.get("COMSPEC") or shutil.which("cmd.exe") or "cmd.exe"
        return [comspec, "/d", "/s", "/c", subprocess.list2cmdline(command)]
    return command


def _safe_run_id(value: str | None) -> str:
    run_id = value or f"run-{uuid.uuid4()}"
    if not _RUN_ID_RE.fullmatch(run_id):
        raise ValueError("Provider run_id must be a bounded path-free identifier")
    return run_id


@dataclass(frozen=True)
class ProviderRunRequest:
    task_id: str
    role: str
    registry_id: str
    model: str
    reasoning_effort: str
    sandbox: str
    prompt: str
    output_schema: Path
    cwd: Path
    timeout_seconds: int = 1800
    run_id: str | None = None
    artifact_dir: Path | None = None


@dataclass(frozen=True)
class ProviderRunResult:
    run_id: str
    provider: str
    task_id: str
    role: str
    registry_id: str
    model: str
    session_id: str | None
    started_at: str
    completed_at: str
    exit_code: int
    success: bool
    output: dict[str, Any] | None
    output_hash: str | None
    stdout_hash: str
    stderr_hash: str
    input_tokens: int | None
    output_tokens: int | None
    errors: tuple[str, ...]
    argv: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "provider": self.provider,
            "task_id": self.task_id,
            "role": self.role,
            "registry_id": self.registry_id,
            "model": self.model,
            "session_id": self.session_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "exit_code": self.exit_code,
            "success": self.success,
            "output": self.output,
            "output_hash": self.output_hash,
            "stdout_hash": self.stdout_hash,
            "stderr_hash": self.stderr_hash,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "errors": list(self.errors),
            "argv": list(self.argv),
        }


class ProviderAdapter(Protocol):
    name: str

    def probe(self) -> dict[str, Any]: ...
    def run(self, request: ProviderRunRequest) -> ProviderRunResult: ...


def _safe_provider_env(extra_names: Sequence[str] = ()) -> dict[str, str]:
    allow = {
        "PATH", "HOME", "USERPROFILE", "CODEX_HOME", "SYSTEMROOT", "WINDIR", "COMSPEC",
        "PATHEXT", "TMP", "TEMP", "TMPDIR", "LANG", "LC_ALL", "TERM", "COLORTERM",
    }
    allow.update(extra_names)
    return {name: value for name, value in os.environ.items() if name in allow}


def _default_provider_artifact_root(cwd: Path) -> Path:
    cwd_key = os.path.abspath(cwd)
    run_key = hashlib.sha256(cwd_key.encode("utf-8")).hexdigest()[:32]
    return Path(tempfile.gettempdir()) / "ztad-provider-runs" / run_key


def _prepare_run_artifacts(root: Path, run_id: str) -> tuple[Path, Path, Path]:
    """Create a non-symlink run directory and reject stale/replayed artifacts."""
    root = Path(os.path.abspath(root))
    current = root
    while True:
        if current.is_symlink():
            raise ValueError(f"Provider output path has a symlink ancestor: {current}")
        if current.parent == current:
            break
        current = current.parent
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Provider output root must be a regular non-symlink directory")
    output_path = root / f"{run_id}.result.json"
    event_path = root / f"{run_id}.events.jsonl"
    for path in (output_path, event_path):
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError("Provider artifact path escapes output root") from exc
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"Provider run artifact already exists: {path}")
    return root, output_path, event_path

def _walk_event(value: Any) -> tuple[str | None, int | None, int | None]:
    session = None
    input_tokens = None
    output_tokens = None
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                key_lower = str(key).lower()
                if session is None and key_lower in {"thread_id", "threadid", "session_id", "sessionid"} and isinstance(child, str):
                    session = child
                if key_lower in {"input_tokens", "inputtokens"} and isinstance(child, int):
                    input_tokens = child
                if key_lower in {"output_tokens", "outputtokens"} and isinstance(child, int):
                    output_tokens = child
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
    return session, input_tokens, output_tokens


def parse_jsonl_metadata(text: str) -> dict[str, Any]:
    session_id = None
    input_tokens = 0
    output_tokens = 0
    saw_input = False
    saw_output = False
    invalid_lines = 0
    for raw in text.splitlines():
        if not raw.strip():
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            invalid_lines += 1
            continue
        session, incoming, outgoing = _walk_event(event)
        session_id = session_id or session
        if incoming is not None:
            input_tokens = max(input_tokens, incoming)
            saw_input = True
        if outgoing is not None:
            output_tokens = max(output_tokens, outgoing)
            saw_output = True
    return {
        "session_id": session_id,
        "input_tokens": input_tokens if saw_input else None,
        "output_tokens": output_tokens if saw_output else None,
        "invalid_jsonl_lines": invalid_lines,
    }


class CodexExecProvider:
    name = "codex"

    def __init__(
        self,
        *,
        executable: str = "codex",
        output_dir: Path | None = None,
        ignore_user_config: bool = True,
        ignore_rules: bool = True,
    ):
        self.executable = executable
        self.output_dir = output_dir
        self.ignore_user_config = ignore_user_config
        self.ignore_rules = ignore_rules

    def probe(self) -> dict[str, Any]:
        resolved = shutil.which(self.executable)
        if not resolved:
            return {"available": False, "provider": self.name, "reason": "executable_not_found"}
        proc = subprocess.run(_command_argv([resolved, "--version"]), text=True, capture_output=True, check=False, timeout=30, shell=False)
        return {
            "available": proc.returncode == 0,
            "provider": self.name,
            "executable": resolved,
            "version": (proc.stdout or proc.stderr).strip(),
            "exit_code": proc.returncode,
        }

    def _argv(self, request: ProviderRunRequest, output_path: Path) -> list[str]:
        argv = [
            self.executable, "exec", "--model", request.model, "--sandbox", request.sandbox,
            "--json", "--output-schema", str(request.output_schema),
            "--output-last-message", str(output_path), "--ephemeral",
        ]
        if self.ignore_user_config:
            argv.append("--ignore-user-config")
        if self.ignore_rules:
            argv.append("--ignore-rules")
        argv += ["-c", f'model_reasoning_effort="{request.reasoning_effort}"', "-"]
        return _command_argv(argv)

    def run(self, request: ProviderRunRequest) -> ProviderRunResult:
        run_id = _safe_run_id(request.run_id)
        root = request.artifact_dir or self.output_dir or _default_provider_artifact_root(request.cwd)
        _, output_path, event_path = _prepare_run_artifacts(root, run_id)
        argv = self._argv(request, output_path)
        started = utc_now()
        errors: list[str] = []
        try:
            proc = subprocess.run(
                argv,
                cwd=request.cwd,
                input=request.prompt,
                text=True,
                capture_output=True,
                timeout=request.timeout_seconds,
                check=False,
                shell=False,
                env=_safe_provider_env(),
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or "" if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr or "" if isinstance(exc.stderr, str) else ""
            exit_code = 124
            errors.append("provider_timeout")
        except OSError as exc:
            stdout = ""
            stderr = str(exc)
            exit_code = 127
            errors.append("provider_unavailable")
        atomic_write(event_path, stdout.encode("utf-8"), mode=0o600)
        output: dict[str, Any] | None = None
        if output_path.is_file() and not output_path.is_symlink():
            try:
                parsed = load_data(output_path)
                if isinstance(parsed, dict):
                    output = parsed
                else:
                    errors.append("provider_output_is_not_object")
            except Exception as exc:
                errors.append(f"provider_output_invalid:{exc}")
        else:
            errors.append("provider_output_missing")
        if output is not None:
            try:
                schema = load_data(request.output_schema)
                if not isinstance(schema, dict):
                    errors.append("output_schema_is_not_object")
                else:
                    errors.extend(f"schema:{item}" for item in validate_instance(output, schema))
            except Exception as exc:
                errors.append(f"schema_validation_failed:{exc}")
        meta = parse_jsonl_metadata(stdout)
        if meta["invalid_jsonl_lines"]:
            errors.append(f"invalid_jsonl_lines:{meta['invalid_jsonl_lines']}")
        success = exit_code == 0 and output is not None and not errors
        return ProviderRunResult(
            run_id=run_id,
            provider=self.name,
            task_id=request.task_id,
            role=request.role,
            registry_id=request.registry_id,
            model=request.model,
            session_id=meta["session_id"],
            started_at=started,
            completed_at=utc_now(),
            exit_code=exit_code,
            success=success,
            output=output,
            output_hash=sha256_bytes(canonical_json(output)) if output is not None else None,
            stdout_hash=sha256_bytes(stdout.encode()),
            stderr_hash=sha256_bytes(stderr.encode()),
            input_tokens=meta["input_tokens"],
            output_tokens=meta["output_tokens"],
            errors=tuple(sorted(set(errors))),
            argv=tuple(argv),
        )


class GenericStructuredCommandProvider:
    """Config-driven structured provider adapter with no shell interpolation.

    This adapter makes multi-provider execution possible without hard-coding an
    unstable third-party CLI contract. The operator must host-accept an exact
    executable and an argv template. Prompts are sent on stdin, outputs are read
    from a dedicated JSON file and validated locally.
    """

    def __init__(
        self,
        *,
        name: str,
        executable: str,
        argv_template: Sequence[str],
        output_dir: Path | None = None,
        allowed_environment_names: Sequence[str] = (),
        version_argv: Sequence[str] = ("--version",),
    ):
        if not name or name == "codex":
            raise ValueError("Generic provider requires a unique non-codex name")
        if not executable or not argv_template:
            raise ValueError("Executable and argv_template are required")
        forbidden = {";", "&&", "||", "|", ">", "<", "`", "$("}
        for item in argv_template:
            if any(token in item for token in forbidden):
                raise ValueError("Shell syntax is prohibited in provider argv templates")
        self.name = name
        self.executable = executable
        self.argv_template = tuple(argv_template)
        self.output_dir = output_dir
        self.allowed_environment_names = tuple(allowed_environment_names)
        self.version_argv = tuple(version_argv)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], *, output_dir: Path | None = None) -> "GenericStructuredCommandProvider":
        allowed = {"name", "executable", "argv_template", "allowed_environment_names", "version_argv"}
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ValueError("Unknown generic provider keys: " + ", ".join(unknown))
        return cls(
            name=str(value["name"]), executable=str(value["executable"]),
            argv_template=tuple(str(x) for x in value["argv_template"]),
            output_dir=output_dir,
            allowed_environment_names=tuple(str(x) for x in value.get("allowed_environment_names", [])),
            version_argv=tuple(str(x) for x in value.get("version_argv", ["--version"])),
        )

    def probe(self) -> dict[str, Any]:
        resolved = shutil.which(self.executable)
        if not resolved:
            return {"available": False, "provider": self.name, "reason": "executable_not_found"}
        try:
            proc = subprocess.run(
                _command_argv([resolved, *self.version_argv]), text=True, capture_output=True, check=False,
                timeout=30, shell=False, env=_safe_provider_env(self.allowed_environment_names),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"available": False, "provider": self.name, "reason": f"{type(exc).__name__}:{exc}"}
        return {
            "available": proc.returncode == 0, "provider": self.name, "executable": resolved,
            "version": (proc.stdout or proc.stderr).strip(), "exit_code": proc.returncode,
        }

    def _argv(self, request: ProviderRunRequest, output_path: Path) -> list[str]:
        values = {
            "model": request.model, "reasoning": request.reasoning_effort,
            "sandbox": request.sandbox, "output": str(output_path),
            "schema": str(request.output_schema), "task_id": request.task_id,
            "role": request.role,
        }
        result = [self.executable]
        for item in self.argv_template:
            try:
                rendered = item.format_map(values)
            except KeyError as exc:
                raise ValueError(f"Unsupported provider template placeholder: {exc}") from exc
            if "\x00" in rendered or "\n" in rendered or "\r" in rendered:
                raise ValueError("Provider argv contains prohibited control characters")
            result.append(rendered)
        return _command_argv(result)

    def run(self, request: ProviderRunRequest) -> ProviderRunResult:
        run_id = _safe_run_id(request.run_id)
        root = request.artifact_dir or self.output_dir or _default_provider_artifact_root(request.cwd)
        _, output_path, event_path = _prepare_run_artifacts(root, run_id)
        argv = self._argv(request, output_path)
        started = utc_now()
        errors: list[str] = []
        try:
            proc = subprocess.run(
                argv, cwd=request.cwd, input=request.prompt, text=True, capture_output=True,
                timeout=request.timeout_seconds, check=False, shell=False,
                env=_safe_provider_env(self.allowed_environment_names),
            )
            stdout, stderr, exit_code = proc.stdout or "", proc.stderr or "", proc.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            exit_code = 124
            errors.append("provider_timeout")
        except OSError as exc:
            stdout, stderr, exit_code = "", str(exc), 127
            errors.append("provider_unavailable")
        atomic_write(event_path, stdout.encode("utf-8"), mode=0o600)
        output: dict[str, Any] | None = None
        if output_path.is_file() and not output_path.is_symlink():
            try:
                parsed = load_data(output_path)
                if isinstance(parsed, dict):
                    output = parsed
                else:
                    errors.append("provider_output_is_not_object")
            except Exception as exc:
                errors.append(f"provider_output_invalid:{exc}")
        else:
            errors.append("provider_output_missing")
        if output is not None:
            try:
                schema = load_data(request.output_schema)
                errors.extend(f"schema:{item}" for item in validate_instance(output, schema))
            except Exception as exc:
                errors.append(f"schema_validation_failed:{exc}")
        meta = parse_jsonl_metadata(stdout)
        if meta["invalid_jsonl_lines"]:
            errors.append(f"invalid_jsonl_lines:{meta['invalid_jsonl_lines']}")
        success = exit_code == 0 and output is not None and not errors
        return ProviderRunResult(
            run_id=run_id, provider=self.name, task_id=request.task_id, role=request.role,
            registry_id=request.registry_id, model=request.model, session_id=meta["session_id"],
            started_at=started, completed_at=utc_now(), exit_code=exit_code, success=success,
            output=output, output_hash=sha256_bytes(canonical_json(output)) if output is not None else None,
            stdout_hash=sha256_bytes(stdout.encode()), stderr_hash=sha256_bytes(stderr.encode()),
            input_tokens=meta["input_tokens"], output_tokens=meta["output_tokens"],
            errors=tuple(sorted(set(errors))), argv=tuple(argv),
        )


class MockProvider:
    """Deterministic test/provider adapter. It never executes a shell command."""

    def __init__(self, name: str = "mock", responses: list[dict[str, Any]] | None = None):
        self.name = name
        self.responses = list(responses or [])
        self.calls: list[ProviderRunRequest] = []

    def probe(self) -> dict[str, Any]:
        return {"available": True, "provider": self.name, "version": "mock"}

    def run(self, request: ProviderRunRequest) -> ProviderRunResult:
        self.calls.append(request)
        response = self.responses.pop(0) if self.responses else {}
        output = response.get("output")
        errors = tuple(response.get("errors", []))
        success = bool(response.get("success", output is not None and not errors))
        return ProviderRunResult(
            run_id=request.run_id or f"run-{uuid.uuid4()}", provider=self.name,
            task_id=request.task_id, role=request.role, registry_id=request.registry_id,
            model=request.model, session_id=response.get("session_id", f"mock-session-{len(self.calls)}"),
            started_at=utc_now(), completed_at=utc_now(), exit_code=int(response.get("exit_code", 0 if success else 1)),
            success=success, output=output,
            output_hash=sha256_bytes(canonical_json(output)) if output is not None else None,
            stdout_hash=sha256_bytes(b""), stderr_hash=sha256_bytes(b""),
            input_tokens=response.get("input_tokens"), output_tokens=response.get("output_tokens"),
            errors=errors, argv=("mock",),
        )


class ProviderRegistry:
    def __init__(self, providers: Sequence[ProviderAdapter]):
        self._providers = {provider.name: provider for provider in providers}
        if len(self._providers) != len(providers):
            raise ValueError("Duplicate provider name")

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))

    def has(self, name: str) -> bool:
        return name in self._providers

    def get(self, name: str) -> ProviderAdapter:
        try:
            return self._providers[name]
        except KeyError as exc:
            raise LookupError(f"Provider is not configured: {name}") from exc

    def probe_all(self) -> dict[str, Any]:
        return {name: provider.probe() for name, provider in sorted(self._providers.items())}
