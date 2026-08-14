from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Sequence

from .schema_validation import load_strict_model_schema, validate_instance
from .util import canonical_json, sha256_bytes, utc_now


def _request_fingerprint(request: Any) -> str:
    try:
        schema_hash = sha256_bytes(request.output_schema.read_bytes()) if request.output_schema.is_file() and not request.output_schema.is_symlink() else None
    except OSError:
        schema_hash = None
    return sha256_bytes(canonical_json({
        "task_id": request.task_id, "role": request.role, "registry_id": request.registry_id,
        "model": request.model, "reasoning_effort": request.reasoning_effort, "sandbox": request.sandbox,
        "prompt_hash": sha256_bytes(request.prompt.encode("utf-8")),
        "output_schema": str(request.output_schema), "output_schema_hash": schema_hash,
        "cwd": os.path.abspath(request.cwd),
    }))


def _sidecars(root: Path, run_id: str) -> tuple[Path, Path]:
    stderr_path = root / f"{run_id}.stderr.txt"
    receipt_path = root / f"{run_id}.receipt.json"
    for path in (stderr_path, receipt_path):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"Provider run artifact already exists: {path}")
    return stderr_path, receipt_path


def _receipt(p: Any, path: Path, *, request: Any, provider: str, run_id: str, started: str, completed: str,
             exit_code: int, output_hash: str | None, stdout_hash: str, stderr_hash: str,
             request_fingerprint: str, errors: Sequence[str]) -> str:
    record = {
        "schema_version": 1,
        "authority": "LOCAL_NON_AUTHORITATIVE",
        "can_grant_merge_release_or_production": False,
        "request_fingerprint": request_fingerprint,
        "provider": provider, "run_id": run_id, "task_id": request.task_id, "role": request.role,
        "registry_id": request.registry_id, "model": request.model,
        "started_at": started, "completed_at": completed, "exit_code": exit_code,
        "output_hash": output_hash, "stdout_hash": stdout_hash, "stderr_hash": stderr_hash,
        "errors": sorted(set(str(item) for item in errors)),
    }
    encoded = canonical_json(record)
    p.atomic_write(path, encoded, mode=0o600)
    return sha256_bytes(encoded)


def _preflight_or_result(p: Any, self: Any, request: Any, run_id: str, event_path: Path,
                         stderr_path: Path, receipt_path: Path, started: str, request_fingerprint: str):
    try:
        schema = load_strict_model_schema(request.output_schema)
        return schema, None
    except Exception as exc:
        error = f"invalid_json_schema:{type(exc).__name__}:{exc}"
        p.atomic_write(event_path, b"", mode=0o600)
        p.atomic_write(stderr_path, error.encode("utf-8"), mode=0o600)
        completed = utc_now(); stdout_hash = sha256_bytes(b""); stderr_hash = sha256_bytes(error.encode("utf-8"))
        receipt_hash = _receipt(
            p, receipt_path, request=request, provider=self.name, run_id=run_id, started=started,
            completed=completed, exit_code=78, output_hash=None, stdout_hash=stdout_hash,
            stderr_hash=stderr_hash, request_fingerprint=request_fingerprint, errors=[error],
        )
        return None, p.ProviderRunResult(
            run_id=run_id, provider=self.name, task_id=request.task_id, role=request.role,
            registry_id=request.registry_id, model=request.model, session_id=None,
            started_at=started, completed_at=completed, exit_code=78, success=False,
            output=None, output_hash=None, stdout_hash=stdout_hash, stderr_hash=stderr_hash,
            input_tokens=None, output_tokens=None, errors=(error,), argv=(),
            request_fingerprint=request_fingerprint, receipt_hash=receipt_hash,
        )


def _finish(p: Any, self: Any, request: Any, *, run_id: str, argv: Sequence[str], started: str,
            stdout: str, stderr: str, exit_code: int, errors: list[str], schema: dict[str, Any],
            output_path: Path, event_path: Path, stderr_path: Path, receipt_path: Path,
            request_fingerprint: str):
    p.atomic_write(event_path, stdout.encode("utf-8"), mode=0o600)
    p.atomic_write(stderr_path, stderr.encode("utf-8"), mode=0o600)
    output = None
    if output_path.is_file() and not output_path.is_symlink():
        try:
            parsed = p.load_data(output_path)
            if isinstance(parsed, dict): output = parsed
            else: errors.append("provider_output_is_not_object")
        except Exception as exc: errors.append(f"provider_output_invalid:{exc}")
    else:
        errors.append("provider_output_missing")
    if output is not None:
        # Test/orchestration role aliases are normalized only at the provider boundary.
        # The canonical model schema remains intentionally narrow and strict.
        from .agent_output import normalize_agent_role
        if "agent_role" in output:
            output = dict(output)
            output["agent_role"] = normalize_agent_role(output.get("agent_role"))
        errors.extend(f"schema:{item}" for item in validate_instance(output, schema))
    meta = p.parse_jsonl_metadata(stdout)
    if meta["invalid_jsonl_lines"]: errors.append(f"invalid_jsonl_lines:{meta['invalid_jsonl_lines']}")
    completed = utc_now(); output_hash = sha256_bytes(canonical_json(output)) if output is not None else None
    stdout_hash = sha256_bytes(stdout.encode("utf-8")); stderr_hash = sha256_bytes(stderr.encode("utf-8")); unique = tuple(sorted(set(errors)))
    receipt_hash = _receipt(
        p, receipt_path, request=request, provider=self.name, run_id=run_id, started=started,
        completed=completed, exit_code=exit_code, output_hash=output_hash, stdout_hash=stdout_hash,
        stderr_hash=stderr_hash, request_fingerprint=request_fingerprint, errors=unique,
    )
    return p.ProviderRunResult(
        run_id=run_id, provider=self.name, task_id=request.task_id, role=request.role,
        registry_id=request.registry_id, model=request.model, session_id=meta["session_id"],
        started_at=started, completed_at=completed, exit_code=exit_code,
        success=exit_code == 0 and output is not None and not unique, output=output,
        output_hash=output_hash, stdout_hash=stdout_hash, stderr_hash=stderr_hash,
        input_tokens=meta["input_tokens"], output_tokens=meta["output_tokens"], errors=unique,
        argv=tuple(argv), request_fingerprint=request_fingerprint, receipt_hash=receipt_hash,
    )


def codex_run(self: Any, request: Any):
    from . import providers as p
    run_id = p._safe_run_id(request.run_id); root = request.artifact_dir or self.output_dir or p._default_provider_artifact_root(request.cwd)
    root, output_path, event_path = p._prepare_run_artifacts(root, run_id); stderr_path, receipt_path = _sidecars(root, run_id)
    started = utc_now(); fingerprint = _request_fingerprint(request)
    schema, early = _preflight_or_result(p, self, request, run_id, event_path, stderr_path, receipt_path, started, fingerprint)
    if early is not None: return early
    argv = self._argv(request, output_path); errors: list[str] = []
    try:
        proc = subprocess.run(argv, cwd=request.cwd, input=request.prompt, text=True, capture_output=True, timeout=request.timeout_seconds, check=False, shell=False, env=p._safe_provider_env())
        stdout, stderr, exit_code = proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""; stderr = exc.stderr if isinstance(exc.stderr, str) else ""; exit_code = 124; errors.append("provider_timeout")
    except OSError as exc:
        stdout, stderr, exit_code = "", str(exc), 127; errors.append("provider_unavailable")
    return _finish(p, self, request, run_id=run_id, argv=argv, started=started, stdout=stdout, stderr=stderr, exit_code=exit_code, errors=errors, schema=schema, output_path=output_path, event_path=event_path, stderr_path=stderr_path, receipt_path=receipt_path, request_fingerprint=fingerprint)


def generic_run(self: Any, request: Any):
    from . import providers as p
    run_id = p._safe_run_id(request.run_id); root = request.artifact_dir or self.output_dir or p._default_provider_artifact_root(request.cwd)
    root, output_path, event_path = p._prepare_run_artifacts(root, run_id); stderr_path, receipt_path = _sidecars(root, run_id)
    started = utc_now(); fingerprint = _request_fingerprint(request)
    schema, early = _preflight_or_result(p, self, request, run_id, event_path, stderr_path, receipt_path, started, fingerprint)
    if early is not None: return early
    argv = self._argv(request, output_path); errors: list[str] = []
    try:
        proc = subprocess.run(argv, cwd=request.cwd, input=request.prompt, text=True, capture_output=True, timeout=request.timeout_seconds, check=False, shell=False, env=p._safe_provider_env(self.allowed_environment_names))
        stdout, stderr, exit_code = proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""; stderr = exc.stderr if isinstance(exc.stderr, str) else ""; exit_code = 124; errors.append("provider_timeout")
    except OSError as exc:
        stdout, stderr, exit_code = "", str(exc), 127; errors.append("provider_unavailable")
    return _finish(p, self, request, run_id=run_id, argv=argv, started=started, stdout=stdout, stderr=stderr, exit_code=exit_code, errors=errors, schema=schema, output_path=output_path, event_path=event_path, stderr_path=stderr_path, receipt_path=receipt_path, request_fingerprint=fingerprint)


def install_provider_contracts(provider_module: Any) -> None:
    provider_module.CodexExecProvider.run = codex_run
    provider_module.GenericStructuredCommandProvider.run = generic_run
