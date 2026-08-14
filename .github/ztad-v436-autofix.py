from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8", newline="\n")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    if new in text and old not in text:
        return
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{rel}: expected one occurrence of {old!r}, found {count}")
    write(rel, text.replace(old, new, 1))


def replace_section(rel: str, class_name: str, next_class: str, new_run: str) -> None:
    text = read(rel)
    class_start = text.index(class_name)
    run_start = text.index("    def run(self, request: ProviderRunRequest) -> ProviderRunResult:\n", class_start)
    section_end = text.index(next_class, run_start)
    prefix = text[:run_start]
    suffix = text[section_end:]
    write(rel, prefix + new_run.rstrip() + "\n\n\n" + suffix)


# Provider strict-schema preflight and durable local execution receipt.
replace_once(
    "toolkit/ztad/providers.py",
    "from .schema_validation import validate_instance\n",
    "from .schema_validation import load_strict_model_schema, validate_instance\n",
)

old_prepare = '''def _prepare_run_artifacts(root: Path, run_id: str) -> tuple[Path, Path, Path]:
    """Create a non-symlink run directory and reject stale/replayed artifacts."""
    root = Path(os.path.abspath(root))
    current = root
    while True:
        if is_link_like(current):
            raise ValueError(f"Provider output path has a symlink or reparse-point ancestor: {current}")
        if current.parent == current:
            break
        current = current.parent
    root.mkdir(parents=True, exist_ok=True)
    if is_link_like(root) or not root.is_dir():
        raise ValueError("Provider output root must be a regular non-link directory")
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
'''
new_prepare = '''def _prepare_run_artifacts(root: Path, run_id: str) -> tuple[Path, Path, Path]:
    """Create a non-symlink run directory and reject stale/replayed artifacts."""
    root = Path(os.path.abspath(root))
    current = root
    while True:
        if is_link_like(current):
            raise ValueError(f"Provider output path has a symlink or reparse-point ancestor: {current}")
        if current.parent == current:
            break
        current = current.parent
    root.mkdir(parents=True, exist_ok=True)
    if is_link_like(root) or not root.is_dir():
        raise ValueError("Provider output root must be a regular non-link directory")
    output_path = root / f"{run_id}.result.json"
    event_path = root / f"{run_id}.events.jsonl"
    stderr_path = root / f"{run_id}.stderr.txt"
    receipt_path = root / f"{run_id}.receipt.json"
    for path in (output_path, event_path, stderr_path, receipt_path):
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError("Provider artifact path escapes output root") from exc
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"Provider run artifact already exists: {path}")
    return root, output_path, event_path


def _provider_request_fingerprint(request: ProviderRunRequest) -> str:
    schema_bytes = request.output_schema.read_bytes() if request.output_schema.is_file() else b""
    payload = {
        "task_id": request.task_id,
        "role": request.role,
        "registry_id": request.registry_id,
        "model": request.model,
        "reasoning_effort": request.reasoning_effort,
        "sandbox": request.sandbox,
        "prompt_sha256": sha256_bytes(request.prompt.encode("utf-8")),
        "schema_sha256": sha256_bytes(schema_bytes),
        "cwd": os.path.abspath(request.cwd),
    }
    return sha256_bytes(canonical_json(payload))


def _persist_provider_sidecars(
    *, root: Path, run_id: str, request: ProviderRunRequest, provider: str,
    stdout: str, stderr: str, exit_code: int, errors: Sequence[str], output_hash: str | None,
) -> str:
    fingerprint = _provider_request_fingerprint(request)
    stderr_path = root / f"{run_id}.stderr.txt"
    receipt_path = root / f"{run_id}.receipt.json"
    atomic_write(stderr_path, stderr.encode("utf-8"), mode=0o600)
    receipt = {
        "schema_version": 1,
        "evidence_class": "LOCAL_PROVIDER_EXECUTION",
        "authoritative_approval": False,
        "run_id": run_id,
        "provider": provider,
        "task_id": request.task_id,
        "role": request.role,
        "registry_id": request.registry_id,
        "model": request.model,
        "request_fingerprint": fingerprint,
        "prompt_sha256": sha256_bytes(request.prompt.encode("utf-8")),
        "output_schema_sha256": sha256_bytes(request.output_schema.read_bytes()) if request.output_schema.is_file() else None,
        "exit_code": exit_code,
        "output_hash": output_hash,
        "stdout_hash": sha256_bytes(stdout.encode("utf-8")),
        "stderr_hash": sha256_bytes(stderr.encode("utf-8")),
        "errors": sorted(set(errors)),
    }
    atomic_write(receipt_path, canonical_json(receipt) + b"\n", mode=0o600)
    return fingerprint
'''
replace_once("toolkit/ztad/providers.py", old_prepare, new_prepare)

codex_run = '''    def run(self, request: ProviderRunRequest) -> ProviderRunResult:
        run_id = _safe_run_id(request.run_id)
        root = request.artifact_dir or self.output_dir or _default_provider_artifact_root(request.cwd)
        artifact_root, output_path, event_path = _prepare_run_artifacts(root, run_id)
        started = utc_now()
        errors: list[str] = []
        try:
            schema = load_strict_model_schema(request.output_schema)
        except Exception as exc:
            stderr = f"{type(exc).__name__}:{exc}"
            errors.append(f"invalid_output_schema:{stderr}")
            event = canonical_json({"event": "schema_preflight_failed", "run_id": run_id}) + b"\n"
            atomic_write(event_path, event, mode=0o600)
            _persist_provider_sidecars(
                root=artifact_root, run_id=run_id, request=request, provider=self.name,
                stdout=event.decode("utf-8"), stderr=stderr, exit_code=2, errors=errors, output_hash=None,
            )
            return ProviderRunResult(
                run_id=run_id, provider=self.name, task_id=request.task_id, role=request.role,
                registry_id=request.registry_id, model=request.model, session_id=None,
                started_at=started, completed_at=utc_now(), exit_code=2, success=False,
                output=None, output_hash=None, stdout_hash=sha256_bytes(event),
                stderr_hash=sha256_bytes(stderr.encode("utf-8")), input_tokens=None,
                output_tokens=None, errors=tuple(errors), argv=(),
            )
        argv = self._argv(request, output_path)
        try:
            proc = subprocess.run(
                argv, cwd=request.cwd, input=request.prompt, text=True, capture_output=True,
                timeout=request.timeout_seconds, check=False, shell=False, env=_safe_provider_env(),
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
            errors.extend(f"schema:{item}" for item in validate_instance(output, schema))
        meta = parse_jsonl_metadata(stdout)
        if meta["invalid_jsonl_lines"]:
            errors.append(f"invalid_jsonl_lines:{meta['invalid_jsonl_lines']}")
        output_hash = sha256_bytes(canonical_json(output)) if output is not None else None
        _persist_provider_sidecars(
            root=artifact_root, run_id=run_id, request=request, provider=self.name,
            stdout=stdout, stderr=stderr, exit_code=exit_code, errors=errors, output_hash=output_hash,
        )
        success = exit_code == 0 and output is not None and not errors
        return ProviderRunResult(
            run_id=run_id, provider=self.name, task_id=request.task_id, role=request.role,
            registry_id=request.registry_id, model=request.model, session_id=meta["session_id"],
            started_at=started, completed_at=utc_now(), exit_code=exit_code, success=success,
            output=output, output_hash=output_hash, stdout_hash=sha256_bytes(stdout.encode()),
            stderr_hash=sha256_bytes(stderr.encode()), input_tokens=meta["input_tokens"],
            output_tokens=meta["output_tokens"], errors=tuple(sorted(set(errors))), argv=tuple(argv),
        )'''
replace_section(
    "toolkit/ztad/providers.py",
    "class CodexExecProvider:",
    "class GenericStructuredCommandProvider:",
    codex_run,
)

generic_run = '''    def run(self, request: ProviderRunRequest) -> ProviderRunResult:
        run_id = _safe_run_id(request.run_id)
        root = request.artifact_dir or self.output_dir or _default_provider_artifact_root(request.cwd)
        artifact_root, output_path, event_path = _prepare_run_artifacts(root, run_id)
        started = utc_now()
        errors: list[str] = []
        try:
            schema = load_strict_model_schema(request.output_schema)
        except Exception as exc:
            stderr = f"{type(exc).__name__}:{exc}"
            errors.append(f"invalid_output_schema:{stderr}")
            event = canonical_json({"event": "schema_preflight_failed", "run_id": run_id}) + b"\n"
            atomic_write(event_path, event, mode=0o600)
            _persist_provider_sidecars(
                root=artifact_root, run_id=run_id, request=request, provider=self.name,
                stdout=event.decode("utf-8"), stderr=stderr, exit_code=2, errors=errors, output_hash=None,
            )
            return ProviderRunResult(
                run_id=run_id, provider=self.name, task_id=request.task_id, role=request.role,
                registry_id=request.registry_id, model=request.model, session_id=None,
                started_at=started, completed_at=utc_now(), exit_code=2, success=False,
                output=None, output_hash=None, stdout_hash=sha256_bytes(event),
                stderr_hash=sha256_bytes(stderr.encode("utf-8")), input_tokens=None,
                output_tokens=None, errors=tuple(errors), argv=(),
            )
        argv = self._argv(request, output_path)
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
            errors.extend(f"schema:{item}" for item in validate_instance(output, schema))
        meta = parse_jsonl_metadata(stdout)
        if meta["invalid_jsonl_lines"]:
            errors.append(f"invalid_jsonl_lines:{meta['invalid_jsonl_lines']}")
        output_hash = sha256_bytes(canonical_json(output)) if output is not None else None
        _persist_provider_sidecars(
            root=artifact_root, run_id=run_id, request=request, provider=self.name,
            stdout=stdout, stderr=stderr, exit_code=exit_code, errors=errors, output_hash=output_hash,
        )
        success = exit_code == 0 and output is not None and not errors
        return ProviderRunResult(
            run_id=run_id, provider=self.name, task_id=request.task_id, role=request.role,
            registry_id=request.registry_id, model=request.model, session_id=meta["session_id"],
            started_at=started, completed_at=utc_now(), exit_code=exit_code, success=success,
            output=output, output_hash=output_hash, stdout_hash=sha256_bytes(stdout.encode()),
            stderr_hash=sha256_bytes(stderr.encode()), input_tokens=meta["input_tokens"],
            output_tokens=meta["output_tokens"], errors=tuple(sorted(set(errors))), argv=tuple(argv),
        )'''
replace_section(
    "toolkit/ztad/providers.py",
    "class GenericStructuredCommandProvider:",
    "class MockProvider:",
    generic_run,
)

# Role aliases are normalized at the model boundary, never added to the canonical schema.
runtime = read("toolkit/ztad/mesh_runtime.py")
marker = "_ROLE_TO_AGENT_ROLE = {"
if "def _normalize_agent_role(" not in runtime:
    mapping_end = runtime.index("}\n\n\nclass MeshRuntime", runtime.index(marker)) + 2
    runtime = runtime[:mapping_end] + '''\n\n\ndef _normalize_agent_role(value: str) -> str:\n    return _ROLE_TO_AGENT_ROLE.get(value, value)\n''' + runtime[mapping_end:]
old_role = '        agent_role = str(metadata.get("agent_role") or _ROLE_TO_AGENT_ROLE.get(node["role"], "planner"))\n'
new_role = '        raw_agent_role = str(metadata.get("agent_role") or node["role"])\n        agent_role = _normalize_agent_role(raw_agent_role)\n'
if old_role in runtime:
    runtime = runtime.replace(old_role, new_role, 1)
elif new_role not in runtime:
    raise SystemExit("mesh_runtime.py: agent-role boundary anchor missing")
write("toolkit/ztad/mesh_runtime.py", runtime)

# Autonomous operating contract is part of the skill, not only documentation around it.
skill_rel = "skills/zero-trust-delivery/SKILL.md"
skill = read(skill_rel)
autonomy = '''\n## Autonomous continuation contract\n\n- Continue all safe local work until no runnable local action remains; routine choices do not require operator confirmation.\n- A missing local report or evidence file is created as `LOCAL_UNTRUSTED` evidence bound to the exact task and candidate SHA. It never satisfies a protected/platform evidence gate.\n- If the original worktree is dirty or its branch differs from protected main, preserve it byte-for-byte and create a clean isolated worktree from the protected ref. Transfer only task-scoped files from an explicit allowlist; never stage, commit, reset, clean, or push user work from the original tree.\n- Provider and check retries are bounded. Never repeat the same known-failing attempt with identical inputs; use changed evidence, a bounded alternate qualified provider, or a deterministic local path.\n- Missing external credentials, signatures, attestations, hosted checks, deployment authority, runtime health, or protected approval do not stop unrelated local repair. Prepare the exact protected request and evidence bundle and continue locally.\n- Model output is advisory E0 evidence. It cannot approve merge, sign a release, attest an artifact, authorize deployment, or assert production health.\n- Every model result must remain bound to task identity, exact base/head SHA, context/evidence hashes and the persisted provider request fingerprint. Insufficient evidence returns an explicit escalation/unknown state instead of success.\n- Any package mutation requires a new release identity when the previous version is immutable, synchronized live-version surfaces, changelog entry, regenerated deterministic package manifests/fingerprints, and revalidation before release.\n\n## Isolated repair procedure\n\n1. Record protected ref and exact protected SHA.\n2. Preserve the original worktree and create a clean isolated worktree/branch at that SHA.\n3. Record an explicit transfer allowlist; do not copy unrelated local changes.\n4. Reproduce each blocker once. A second attempt requires materially changed inputs or route.\n5. Apply the smallest root-cause fix and a regression test.\n6. Run local deterministic gates, then protected hosted gates through the platform path only.\n7. Generate local restore/rollback/observation/SBOM evidence where possible, clearly marked local; protected signatures, attestations, staging/production rehearsals and runtime health remain external until actually observed.\n8. Build one candidate SHA/fingerprint. All approvals, manifests, artifacts and evidence must name that exact subject. A changed candidate invalidates stale approval/evidence.\n9. Stop only at a genuinely protected action the current principal cannot perform, and leave the exact next protected action plus its evidence request.\n'''
if "## Autonomous continuation contract" not in skill:
    skill = skill.rstrip() + "\n" + autonomy
write(skill_rel, skill)

# 4.3.5 is immutable. This package mutation is 4.3.6.
replace_once("VERSION", "4.3.5\n", "4.3.6\n")
replace_once(".codex-plugin/plugin.json", '"version": "4.3.5"', '"version": "4.3.6"')
replace_once("toolkit/pyproject.toml", 'version = "4.3.5"', 'version = "4.3.6"')
replace_once("toolkit/ztad/__init__.py", '__version__ = "4.3.5"', '__version__ = "4.3.6"')
replace_once(".github/ISSUE_TEMPLATE/bug_report.yml", "placeholder: 4.3.5", "placeholder: 4.3.6")
replace_once("README.md", "# Zero-Trust Agentic Delivery Mesh 4.3.5", "# Zero-Trust Agentic Delivery Mesh 4.3.6")
replace_once("README.md", "## What 4.3.5 implements", "## What 4.3.6 implements")
replace_once("QUICKSTART.md", "# ZTAD Mesh 4.3.5 Quick Start", "# ZTAD Mesh 4.3.6 Quick Start")
replace_once("QUICKSTART.md", "`v4.3.5` GitHub Release", "`v4.3.6` GitHub Release")
plugin_doc = read("docs/PLUGIN_INSTALLATION.md")
if "4.3.6" not in plugin_doc:
    plugin_doc = plugin_doc.replace("4.3.5", "4.3.6")
write("docs/PLUGIN_INSTALLATION.md", plugin_doc)
replace_once("traceability/TRACEABILITY_MATRIX.md", "# ZTAD Mesh 4.3.5 Traceability Matrix", "# ZTAD Mesh 4.3.6 Traceability Matrix")
for rel in [
    "docs/ARCHITECTURE.md", "docs/EVALS.md", "docs/LIMITATIONS.md", "docs/CONTROL_COVERAGE.md",
    "docs/HOST_ACCEPTANCE.md", "docs/CAPABILITY_MATRIX.md", "docs/FINAL_OPERATING_POLICY.md",
    "docs/MODEL_SELECTION.md", "docs/OPERATING_GUIDE.md", "docs/VALIDATION_REPORT.md",
    "references/MASTER_PLAN.md",
]:
    text = read(rel)
    lines = text.splitlines()
    if lines and "4.3.5" in lines[0]:
        lines[0] = lines[0].replace("4.3.5", "4.3.6")
        write(rel, "\n".join(lines) + "\n")

changelog = read("CHANGELOG.md")
if "## 4.3.6 — 2026-08-14" not in changelog:
    entry = '''## 4.3.6 — 2026-08-14\n\n- Made the zero-trust-delivery skill continue safe local work autonomously across missing local evidence, dirty/divergent worktrees, bounded provider failures, and missing external approvals without conflating local evidence with protected evidence.\n- Repaired the agent-result structured-output schema for strict model validation: closed every object, made optional fields explicitly nullable and required, and kept role aliases outside the canonical schema.\n- Added strict model-schema preflight before provider execution so invalid schemas fail locally and no longer produce a misleading `provider_output_missing` blocker.\n- Persisted provider stderr plus a local execution receipt containing exit code, hashes, errors, and a request fingerprint bound to the exact prompt/schema/task/model inputs.\n- Normalized test-role aliases such as `test_designer` at the runtime boundary without weakening canonical agent-role validation.\n- Added regressions for strict nested schemas, provider preflight/receipt behavior, and role normalization.\n- Preserved the v4.3 routing, approval, actual-risk escalation, deterministic packaging and hard Sol `HIGH` reasoning ceiling; model output remains non-authoritative.\n- Preserved immutable `v4.3.5` and all prior releases unchanged.\n\n'''
    changelog = changelog.replace("# Changelog\n\n", "# Changelog\n\n" + entry, 1)
write("CHANGELOG.md", changelog)

# Focused regression tests.
test = r'''from __future__ import annotations

import json
from pathlib import Path

import pytest

from ztad.mesh_runtime import _normalize_agent_role
from ztad.providers import CodexExecProvider, GenericStructuredCommandProvider, ProviderRunRequest
from ztad.schema_validation import load_strict_model_schema, validate_strict_model_schema


def test_agent_result_schema_is_strict_model_compatible() -> None:
    root = Path(__file__).resolve().parents[1]
    schema = load_strict_model_schema(root / "schemas" / "agent-result.schema.json")
    assert validate_strict_model_schema(schema) == []


def test_nested_alternative_object_cannot_escape_strict_contract() -> None:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"value": {"anyOf": [{"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]}, {"type": "null"}]}},
        "required": ["value"],
    }
    errors = validate_strict_model_schema(schema)
    assert any("additionalProperties=false" in item for item in errors)


@pytest.mark.parametrize("kind", ["codex", "generic"])
def test_invalid_model_schema_fails_before_provider_and_persists_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    schema_path = tmp_path / "invalid.schema.json"
    schema_path.write_text(json.dumps({
        "type": "object",
        "properties": {"x": {"type": "string"}},
        "required": ["x"],
    }), encoding="utf-8")
    called = False

    def forbidden_run(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("provider subprocess must not execute for an invalid strict schema")

    monkeypatch.setattr("ztad.providers.subprocess.run", forbidden_run)
    artifacts = tmp_path / "artifacts"
    if kind == "codex":
        provider = CodexExecProvider(executable="never-run")
    else:
        provider = GenericStructuredCommandProvider(name="generic", executable="never-run", argv_template=("--output", "{output}"))
    request = ProviderRunRequest(
        task_id="TASK-STRICT", role="test_designer", registry_id="gpt-test",
        model="gpt-test", reasoning_effort="high", sandbox="read-only", prompt="bound prompt",
        output_schema=schema_path, cwd=tmp_path, run_id=f"strict-{kind}", artifact_dir=artifacts,
    )
    result = provider.run(request)
    assert called is False
    assert result.success is False
    assert result.exit_code == 2
    assert any(item.startswith("invalid_output_schema:") for item in result.errors)
    assert "provider_output_missing" not in result.errors
    assert (artifacts / f"strict-{kind}.events.jsonl").is_file()
    assert (artifacts / f"strict-{kind}.stderr.txt").is_file()
    receipt = json.loads((artifacts / f"strict-{kind}.receipt.json").read_text(encoding="utf-8"))
    assert receipt["task_id"] == "TASK-STRICT"
    assert receipt["request_fingerprint"].startswith("sha256:")
    assert receipt["authoritative_approval"] is False
    assert receipt["exit_code"] == 2


def test_test_role_alias_is_normalized_only_at_boundary() -> None:
    assert _normalize_agent_role("test_designer") == "planner"
    assert _normalize_agent_role("independent_reviewer") == "independent_reviewer"
'''
write("tests/test_v436_autonomous_delivery.py", test)

print("ZTAD v4.3.6 deterministic repair staged")
