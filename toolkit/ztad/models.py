from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .util import load_data, sha256_bytes, canonical_json, utc_now
from .schema_validation import validate_instance
from .providers import parse_jsonl_metadata

VALID_ROLES = {"worker", "supervisor", "closure"}


@dataclass(frozen=True)
class ModelRole:
    role: str
    model: str
    reasoning_effort: str
    sandbox: str
    max_attempts: int
    fallback_models: tuple[str, ...]


@dataclass(frozen=True)
class ModelRunSpec:
    run_id: str
    task_id: str
    role: str
    model: str
    reasoning_effort: str
    sandbox: str
    prompt_path: Path
    output_schema: Path
    output_path: Path
    event_log_path: Path
    ephemeral: bool = True


class ModelRoutingPolicy:
    def __init__(self, data: dict[str, Any]):
        self.data = data
        self.roles: dict[str, ModelRole] = {}
        raw_roles = data.get("roles", {}) if isinstance(data, dict) else {}
        for role in VALID_ROLES:
            value = raw_roles.get(role)
            if not isinstance(value, dict):
                raise ValueError(f"Missing model role configuration: {role}")
            self.roles[role] = ModelRole(
                role=role,
                model=str(value["model"]),
                reasoning_effort=str(value.get("reasoning_effort", "medium")),
                sandbox=str(value.get("sandbox", "read-only")),
                max_attempts=int(value.get("max_attempts", 1)),
                fallback_models=tuple(str(item) for item in value.get("fallback_models", []) or []),
            )
        if self.roles["worker"].sandbox != "workspace-write":
            raise ValueError("Worker role must use workspace-write sandbox")
        if self.roles["supervisor"].sandbox != "read-only" or self.roles["closure"].sandbox != "read-only":
            raise ValueError("Supervisor and closure roles must be read-only")
        if self.roles["worker"].model == self.roles["supervisor"].model and not data.get("allow_same_model_different_sessions", False):
            raise ValueError("Worker and supervisor models must differ unless explicitly allowed")

    @classmethod
    def from_file(cls, path: Path) -> "ModelRoutingPolicy":
        value = load_data(path)
        if not isinstance(value, dict):
            raise ValueError("Model routing policy must be a mapping")
        return cls(value)

    def role(self, name: str) -> ModelRole:
        if name not in self.roles:
            raise ValueError(f"Unknown model role: {name}")
        return self.roles[name]


def build_codex_exec_argv(spec: ModelRunSpec, *, codex_executable: str = "codex") -> list[str]:
    argv = [
        codex_executable,
        "exec",
        "--model",
        spec.model,
        "--sandbox",
        spec.sandbox,
        "--json",
        "--output-schema",
        str(spec.output_schema),
        "--output-last-message",
        str(spec.output_path),
    ]
    if spec.ephemeral:
        argv.append("--ephemeral")
    argv.extend(["--ignore-user-config", "--ignore-rules"])
    # Reasoning effort is set as a one-run config override rather than changing
    # persistent Codex configuration.
    argv += ["-c", f'model_reasoning_effort="{spec.reasoning_effort}"', "-"]
    return argv


def make_run_spec(
    *,
    task_id: str,
    role: ModelRole,
    prompt_path: Path,
    output_schema: Path,
    output_dir: Path,
) -> ModelRunSpec:
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = f"run-{uuid.uuid4()}"
    return ModelRunSpec(
        run_id=run_id,
        task_id=task_id,
        role=role.role,
        model=role.model,
        reasoning_effort=role.reasoning_effort,
        sandbox=role.sandbox,
        prompt_path=prompt_path,
        output_schema=output_schema,
        output_path=output_dir / f"{run_id}.result.json",
        event_log_path=output_dir / f"{run_id}.events.jsonl",
    )


def execute_codex_run(
    spec: ModelRunSpec,
    *,
    cwd: Path,
    codex_executable: str = "codex",
    timeout_seconds: int = 1800,
) -> dict[str, Any]:
    """Execute a role-isolated Codex run without mutating persistent settings.

    The caller is responsible for providing a disposable worktree for a worker
    role. Supervisor and closure roles are forced read-only by the routing
    policy. This adapter intentionally does not accept credentials or arbitrary
    environment overrides.
    """
    prompt = spec.prompt_path.read_text(encoding="utf-8")
    argv = build_codex_exec_argv(spec, codex_executable=codex_executable)
    started = utc_now()
    proc = subprocess.run(
        argv,
        cwd=cwd,
        input=prompt,
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    spec.event_log_path.write_text(proc.stdout or "", encoding="utf-8")
    output = None
    validation_errors: list[str] = []
    if spec.output_path.is_file() and not spec.output_path.is_symlink():
        try:
            output = json.loads(spec.output_path.read_text(encoding="utf-8"))
            schema = load_data(spec.output_schema)
            if not isinstance(output, dict):
                validation_errors.append("provider_output_is_not_object")
            elif not isinstance(schema, dict):
                validation_errors.append("output_schema_is_not_object")
            else:
                validation_errors.extend(validate_instance(output, schema))
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            output = None
            validation_errors.append(f"provider_output_invalid:{type(exc).__name__}")
    else:
        validation_errors.append("provider_output_missing")
    metadata = parse_jsonl_metadata(proc.stdout or "")
    if metadata["invalid_jsonl_lines"]:
        validation_errors.append(f"invalid_jsonl_lines:{metadata['invalid_jsonl_lines']}")
    return {
        "run_id": spec.run_id,
        "task_id": spec.task_id,
        "role": spec.role,
        "model": spec.model,
        "sandbox": spec.sandbox,
        "reasoning_effort": spec.reasoning_effort,
        "argv": argv,
        "cwd": str(cwd.resolve()),
        "started_at": started,
        "completed_at": utc_now(),
        "exit_code": proc.returncode,
        "stdout_hash": sha256_bytes((proc.stdout or "").encode()),
        "stderr_hash": sha256_bytes((proc.stderr or "").encode()),
        "output": output,
        "output_hash": sha256_bytes(canonical_json(output)) if output is not None else None,
        "session_id": metadata["session_id"],
        "input_tokens": metadata["input_tokens"],
        "output_tokens": metadata["output_tokens"],
        "validation_errors": sorted(set(validation_errors)),
        "success": proc.returncode == 0 and output is not None and not validation_errors,
    }


def execute_role_with_fallback(
    *,
    task_id: str,
    role: ModelRole,
    prompt_path: Path,
    output_schema: Path,
    output_dir: Path,
    cwd: Path,
    codex_executable: str = "codex",
    timeout_seconds: int = 1800,
    executor=execute_codex_run,
) -> dict[str, Any]:
    """Run the configured role and automatically fail over model-by-model.

    Every attempt receives a fresh ephemeral run identifier and output files.
    The caller still validates the structured model output and records the run
    in the durable store; model success is never treated as CI evidence.
    """

    attempts: list[dict[str, Any]] = []
    models = (role.model, *role.fallback_models)
    limit = max(1, role.max_attempts)
    sequence = list(models[:limit])
    if not sequence:
        sequence = [role.model]
    for model in sequence:
        attempt_role = replace(role, model=model)
        spec = make_run_spec(
            task_id=task_id,
            role=attempt_role,
            prompt_path=prompt_path,
            output_schema=output_schema,
            output_dir=output_dir,
        )
        try:
            result = executor(
                spec,
                cwd=cwd,
                codex_executable=codex_executable,
                timeout_seconds=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            result = {
                "run_id": spec.run_id,
                "task_id": task_id,
                "role": role.role,
                "model": model,
                "success": False,
                "failure_class": "MODEL_TIMEOUT",
                "error": str(exc),
            }
        except OSError as exc:
            result = {
                "run_id": spec.run_id,
                "task_id": task_id,
                "role": role.role,
                "model": model,
                "success": False,
                "failure_class": "MODEL_PROVIDER_UNAVAILABLE",
                "error": str(exc),
            }
        attempts.append(result)
        if result.get("success"):
            return {
                "success": True,
                "selected_model": model,
                "attempt_count": len(attempts),
                "attempts": attempts,
                "result": result,
            }
    return {
        "success": False,
        "selected_model": None,
        "attempt_count": len(attempts),
        "attempts": attempts,
        "failure_class": str(attempts[-1].get("failure_class", "MODEL_UNAVAILABLE")),
        "error": str(attempts[-1].get("error", "All configured model attempts failed")),
    }
