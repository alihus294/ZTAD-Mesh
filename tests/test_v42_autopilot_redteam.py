from __future__ import annotations

import ast
import json
import time
from pathlib import Path

import pytest

from conftest import init_git_repo, valid_contract
from ztad.autopilot import prepare_autopilot, submit_prepared_autopilot
from ztad.mesh_plan import build_mesh_plan
from ztad.mesh_runtime import MeshRuntime
from ztad.mesh_store import MeshNodeSpec, MeshStore
from ztad.model_router import AdaptiveModelRouter
from ztad.orchestrator import ContinuityStore
from ztad.providers import MockProvider, ProviderRegistry
from ztad.repository import GitRepository
from ztad.repository_index import assess_context_sufficiency, build_repository_index
from ztad.util import sha256_file
from ztad.worktrees import WorktreeManager

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/agent-result.schema.json"


def _catalog() -> dict:
    return {
        "routing": {"minimum_quality_by_risk": {"R0": 0.1, "R2": 0.1}, "frontier_role_quality_floor": 0.1},
        "models": [{
            "registry_id": "mock-frontier", "provider": "mock", "model": "mock",
            "tier": "frontier", "enabled": True, "reasoning_efforts": ["high"],
            "sandboxes": ["read-only", "workspace-write"], "reliability": 1.0,
            "cost_index": 0.1, "latency_index": 0.1, "max_parallel": 8,
            "task_quality": {"default": 1.0, "review": 1.0, "implementation": 1.0},
        }],
    }


def _write_contract(repo: Path, *, components: list[str] | None = None) -> tuple[Path, dict]:
    contract = valid_contract(risk="R2", components=components or ["src/component.py"])
    path = repo / ".delivery" / "change-contract.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(contract, indent=2), encoding="utf-8")
    return path, contract


def test_mesh_runtime_has_no_duplicate_method_definitions():
    tree = ast.parse((ROOT / "toolkit/ztad/mesh_runtime.py").read_text(encoding="utf-8"))
    runtime = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "MeshRuntime")
    names = [node.name for node in runtime.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    assert duplicates == []


def test_autopilot_dry_run_is_non_mutating_and_plan_is_index_first(tmp_path):
    repo, _ = init_git_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    (repo / "src/component.py").write_text("VALUE = 1\n", encoding="utf-8")
    contract_path, _ = _write_contract(repo)
    before = sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*"))
    prep = prepare_autopilot(
        repository=repo,
        contract_path=contract_path,
        contract_schema=ROOT / "schemas/change-contract.schema.json",
        risk_policy=ROOT / "policies/risk-policy.yaml",
        output_schema=str(SCHEMA),
        command_policy=str(ROOT / "policies/command-policy.yaml"),
    )
    after = sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*"))
    assert before == after
    indexers = [node for node in prep.plan.nodes if node.role == "repository_indexer"]
    scouts = [node for node in prep.plan.nodes if node.role == "context_scout"]
    assert len(indexers) == 1
    assert scouts and all(indexers[0].node_id in node.dependencies for node in scouts)


def test_autopilot_persistence_is_idempotent_and_task_scoped(tmp_path):
    repo, _ = init_git_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    (repo / "src/component.py").write_text("VALUE = 1\n", encoding="utf-8")
    contract_path, contract = _write_contract(repo)
    prep = prepare_autopilot(
        repository=repo,
        contract_path=contract_path,
        contract_schema=ROOT / "schemas/change-contract.schema.json",
        risk_policy=ROOT / "policies/risk-policy.yaml",
        output_schema=str(SCHEMA),
        command_policy=str(ROOT / "policies/command-policy.yaml"),
        plan_output=f".delivery/ztad/tasks/task-a/mesh-plan.json",
        prompt_root=f".delivery/ztad/tasks/task-a/prompts",
        task_id="task-a",
    )
    first = submit_prepared_autopilot(preparation=prep, contract=contract, title="Feature")
    second = submit_prepared_autopilot(preparation=prep, contract=contract, title="Feature")
    assert first["submitted_nodes"] == second["submitted_nodes"] == len(prep.plan.nodes)
    assert second["task"]["idempotent_replay"] is True
    assert Path(prep.plan_output).is_file()
    assert len(MeshStore(Path(prep.mesh_database)).list_nodes(task_id="task-a")) == len(prep.plan.nodes)


def test_dependency_context_is_hash_verified_and_explicitly_truncated(tmp_path):
    repo, base = init_git_repo(tmp_path / "repo")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(repository=str(repo), title="x", contract=valid_contract(), risk="R0", task_id="task", idempotency_key="task")
    mesh = MeshStore(tmp_path / "mesh.db")
    prompt = repo / "p.md"
    prompt.write_text("x", encoding="utf-8")
    specs = []
    dependencies = []
    for index in range(3):
        node_id = f"dep-{index}"
        dependencies.append(node_id)
        specs.append(MeshNodeSpec.create(
            node_id=node_id, task_id=task["task_id"], title=node_id, task_family="review",
            role="supervisor", risk="R0", write_access=False, scopes=(), prompt_path="p.md",
            output_schema=str(SCHEMA), idempotency_key=node_id,
        ))
    specs.append(MeshNodeSpec.create(
        node_id="consumer", task_id=task["task_id"], title="consumer", task_family="review",
        role="supervisor", risk="R0", write_access=False, scopes=(), prompt_path="p.md",
        output_schema=str(SCHEMA), dependencies=dependencies, idempotency_key="consumer",
    ))
    mesh.submit_graph(specs)
    output_root = tmp_path / "outputs"
    output_root.mkdir()
    for index, dep in enumerate(dependencies):
        path = output_root / f"{dep}.json"
        path.write_text(json.dumps({"value": "x" * 100, "index": index}), encoding="utf-8")
        mesh.register_artifact(node_id=dep, artifact_type="MODEL_RESULT", path=str(path), sha256=sha256_file(path), metadata={})
    runtime = MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(_catalog()), providers=ProviderRegistry([MockProvider()]),
        worker_id="worker", output_root=output_root,
    )
    context = runtime._dependency_result_context("consumer", maximum_items=1, maximum_bytes=10_000)
    assert len(context["items"]) == 1
    assert context["truncated"] is True
    assert len(context["omitted"]) == 2
    # Tampering must be caught before prompt construction.
    (output_root / "dep-0.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        runtime._dependency_result_context("consumer")


def test_candidate_sha_is_identical_across_independent_worktrees(tmp_path):
    repo, base = init_git_repo(tmp_path / "repo")
    manager = WorktreeManager(GitRepository(repo))
    candidates = []
    for name in ("one", "two"):
        worktree = manager.create(name, base)
        try:
            (worktree / "same.py").write_text("VALUE = 1\n", encoding="utf-8")
            candidates.append(manager.materialize_candidate(worktree, base))
        finally:
            manager.remove(worktree)
    assert candidates[0] == candidates[1]


def test_high_risk_context_reports_dynamic_import_gap(tmp_path):
    repo, _ = init_git_repo(tmp_path / "repo")
    (repo / "loader.py").write_text("import importlib\nname = input()\nimportlib.import_module(name)\n", encoding="utf-8")
    import subprocess
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "dynamic"], cwd=repo, check=True, capture_output=True)
    index = build_repository_index(GitRepository(repo), "HEAD")
    result = assess_context_sufficiency(index, changed_paths=["loader.py"], included_paths=["loader.py"], risk="R3")
    assert index.dynamic_gaps
    assert result["sufficient"] is False
    assert result["requested_action"] == "REQUEST_CONTEXT_EXPANSION"


def test_mesh_service_is_time_bounded_and_does_not_spin(tmp_path):
    repo, _ = init_git_repo(tmp_path / "repo")
    runtime = MeshRuntime(
        repository=repo, mesh_store=MeshStore(tmp_path / "mesh.db"),
        continuity_store=ContinuityStore(tmp_path / "continuity.db"),
        router=AdaptiveModelRouter(_catalog()), providers=ProviderRegistry([MockProvider()]),
        worker_id="service", output_root=tmp_path / "outputs",
    )
    started = time.monotonic()
    result = runtime.serve(maximum_seconds=0.03, poll_seconds=0.005, status_interval_seconds=0.01)
    elapsed = time.monotonic() - started
    assert elapsed >= 0.02
    assert elapsed < 1
    assert result["totals"]["ticks"] >= 1
    assert result["totals"]["claimed"] == 0

from ztad.model_benchmark import BenchmarkCase, ModelBenchmarkRunner
from ztad.providers import ProviderRunRequest, ProviderRunResult
from ztad.util import canonical_json, sha256_bytes, utc_now


def _agent_output(request: ProviderRunRequest, *, task_id: str | None = None) -> dict:
    import ast as _ast
    envelope = _ast.literal_eval(request.prompt.split("ZTAD_IMMUTABLE_ENVELOPE\n", 1)[1].splitlines()[0])
    role = envelope["agent_role"]
    if role == "implementer":
        result_type, action = "IMPLEMENTATION_PROPOSAL", "VALIDATE_PATCH"
    elif role in {"independent_reviewer", "release_advisor"}:
        result_type, action = "NO_BLOCKING_FINDINGS_IN_REVIEWED_SCOPE", "CONTINUE_POLICY_EVALUATION"
    else:
        result_type, action = "PLAN_READY", "VALIDATE_PLAN"
    return {
        "schema_version": 1,
        "task_id": task_id or request.task_id,
        "agent_role": role,
        "model_registry_id": request.registry_id,
        "prompt_version": envelope["prompt_version"],
        "base_sha": envelope["base_sha"],
        "head_sha": envelope["head_sha"],
        "context_id": envelope["context_id"],
        "result_type": result_type,
        "claims": [], "findings": [], "files_read": [], "files_not_read": [],
        "uncertainties": [], "tested_scope": [], "untested_scope": [], "known_unknowns": [],
        "requested_action": action, "risk_escalation": None, "patch_path": None,
    }


class _BadMetadataProvider:
    name = "bad"
    def probe(self): return {"available": True, "provider": self.name}
    def run(self, request: ProviderRunRequest) -> ProviderRunResult:
        output = _agent_output(request)
        return ProviderRunResult(
            run_id="bad-run", provider=self.name, task_id="wrong-task", role=request.role,
            registry_id=request.registry_id, model=request.model, session_id="bad-session",
            started_at=utc_now(), completed_at=utc_now(), exit_code=0, success=True,
            output=output, output_hash=sha256_bytes(canonical_json(output)),
            stdout_hash=sha256_bytes(b""), stderr_hash=sha256_bytes(b""),
            input_tokens=1, output_tokens=1, errors=(), argv=("mock",),
        )


class _GoodProvider:
    name = "good"
    def __init__(self): self.calls = 0
    def probe(self): return {"available": True, "provider": self.name}
    def run(self, request: ProviderRunRequest) -> ProviderRunResult:
        self.calls += 1
        output = _agent_output(request)
        return ProviderRunResult(
            run_id=f"good-{self.calls}", provider=self.name, task_id=request.task_id, role=request.role,
            registry_id=request.registry_id, model=request.model, session_id=f"good-session-{self.calls}",
            started_at=utc_now(), completed_at=utc_now(), exit_code=0, success=True,
            output=output, output_hash=sha256_bytes(canonical_json(output)),
            stdout_hash=sha256_bytes(b""), stderr_hash=sha256_bytes(b""),
            input_tokens=1, output_tokens=1, errors=(), argv=("mock",),
        )


def _two_provider_catalog() -> dict:
    models = []
    for provider, registry in (("bad", "bad-model"), ("good", "good-model")):
        models.append({
            "registry_id": registry, "provider": provider, "model": registry, "tier": "frontier",
            "enabled": True, "reasoning_efforts": ["high"], "sandboxes": ["read-only", "workspace-write"],
            "reliability": 1.0, "cost_index": 0.1 if provider == "bad" else 0.2,
            "latency_index": 0.1, "max_parallel": 2,
            "task_quality": {"default": 1.0, "review": 1.0},
        })
    return {"routing": {"minimum_quality_by_risk": {"R2": 0.1}, "frontier_role_quality_floor": 0.1}, "models": models}


def test_provider_metadata_mismatch_is_rejected_and_fallback_runs(tmp_path):
    repo, base = init_git_repo(tmp_path / "repo")
    (repo / "prompt.md").write_text("review", encoding="utf-8")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(repository=str(repo), title="review", contract=valid_contract(risk="R2"), risk="R2", task_id="task", idempotency_key="task")
    mesh = MeshStore(tmp_path / "mesh.db")
    mesh.submit_graph([MeshNodeSpec.create(
        node_id="review", task_id=task["task_id"], title="review", task_family="review",
        role="supervisor", risk="R2", write_access=False, scopes=(), prompt_path="prompt.md",
        output_schema=str(SCHEMA), metadata={"base_sha": base, "head_sha": base, "context_id": "sha256:" + "c" * 64},
        idempotency_key="review",
    )])
    good = _GoodProvider()
    runtime = MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(_two_provider_catalog()),
        providers=ProviderRegistry([_BadMetadataProvider(), good]), worker_id="worker", output_root=tmp_path / "runs",
    )
    result = runtime.run_once().to_dict()
    assert result["succeeded"] == 1
    first = result["results"][0]["route_attempts"][0]
    assert "provider_result_task_id_mismatch" in first["validation_errors"]
    assert good.calls == 1


class _WrongBenchmarkSubjectProvider:
    name = "mock"
    def probe(self): return {"available": True, "provider": self.name}
    def run(self, request: ProviderRunRequest) -> ProviderRunResult:
        required = json.loads(request.prompt.split("BENCHMARK_REQUIRED_SUBJECT\n", 1)[1].splitlines()[0])
        output = {
            "schema_version": 1, "task_id": "wrong", "agent_role": required["agent_role"],
            "model_registry_id": required["model_registry_id"], "prompt_version": required["prompt_version"],
            "base_sha": required["base_sha"], "head_sha": required["head_sha"], "context_id": required["context_id"],
            "result_type": "PLAN_READY", "claims": [], "findings": [], "files_read": [], "files_not_read": [],
            "uncertainties": [], "tested_scope": [], "untested_scope": [], "known_unknowns": [],
            "requested_action": "VALIDATE_PLAN", "risk_escalation": None, "patch_path": None,
        }
        return ProviderRunResult(
            run_id="bench", provider=self.name, task_id=request.task_id, role=request.role,
            registry_id=request.registry_id, model=request.model, session_id="bench-session",
            started_at=utc_now(), completed_at=utc_now(), exit_code=0, success=True,
            output=output, output_hash=sha256_bytes(canonical_json(output)), stdout_hash=sha256_bytes(b""),
            stderr_hash=sha256_bytes(b""), input_tokens=1, output_tokens=1, errors=(), argv=("mock",),
        )


def test_benchmark_rejects_subject_mismatch_instead_of_promoting_model(tmp_path):
    catalog = _catalog()
    case = BenchmarkCase(
        case_id="subject", task_family="review", role="supervisor", risk="R2", prompt="Review",
        output_schema=SCHEMA, assertions={"result_type_in": ["PLAN_READY"]},
    )
    report = ModelBenchmarkRunner(
        AdaptiveModelRouter(catalog), ProviderRegistry([_WrongBenchmarkSubjectProvider()])
    ).run([case], cwd=tmp_path)
    measured = report["results"][0]["cases"][0]
    assert measured["success"] is False
    assert measured["score"] == 0.0
    assert any("task_id" in error for error in measured["errors"])


def test_stale_benchmark_rows_are_not_used_after_catalog_or_suite_change(tmp_path):
    store = MeshStore(tmp_path / "mesh.db")
    store.record_model_performance(
        registry_id="m", task_family="review", success=True, quality=1.0, latency=1.0, cost=1.0,
        catalog_hash="sha256:old", benchmark_suite_hash="sha256:suite-old",
    )
    assert store.performance_overrides("review", catalog_hash="sha256:new") == {}
    assert store.performance_overrides("review", catalog_hash="sha256:old", benchmark_suite_hash="sha256:suite-new") == {}
    store.record_model_performance(
        registry_id="m", task_family="review", success=True, quality=0.8, latency=2.0, cost=0.5,
        catalog_hash="sha256:new", benchmark_suite_hash="sha256:suite-new",
    )
    current = store.performance_overrides("review", catalog_hash="sha256:new", benchmark_suite_hash="sha256:suite-new")
    assert current["m"]["runs"] == 1.0
    assert current["m"]["quality"] == pytest.approx(0.8)

class _TrailingWhitespaceProvider:
    name = "mock"
    def __init__(self):
        self.review_calls = 0
    def probe(self): return {"available": True, "provider": self.name}
    def run(self, request: ProviderRunRequest) -> ProviderRunResult:
        if request.role == "worker":
            target = request.cwd / "src/component.py"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("VALUE = 2   \n", encoding="utf-8")
        if request.role == "supervisor":
            self.review_calls += 1
        output = _agent_output(request)
        return ProviderRunResult(
            run_id=f"run-{len(output['task_id'])}-{time.time_ns()}", provider=self.name,
            task_id=request.task_id, role=request.role, registry_id=request.registry_id,
            model=request.model, session_id=f"session-{time.time_ns()}",
            started_at=utc_now(), completed_at=utc_now(), exit_code=0, success=True,
            output=output, output_hash=sha256_bytes(canonical_json(output)),
            stdout_hash=sha256_bytes(b""), stderr_hash=sha256_bytes(b""),
            input_tokens=1, output_tokens=1, errors=(), argv=("mock",),
        )


def test_non_succeeded_dependency_never_unlocks_review(tmp_path):
    mesh = MeshStore(tmp_path / "mesh.db")
    mesh.submit_graph([
        MeshNodeSpec.create(
            node_id="check", task_id="task", title="check", task_family="verification",
            role="check_runner", risk="R2", write_access=False, scopes=(),
            prompt_path="unused.md", output_schema=str(SCHEMA), priority=100,
        ),
        MeshNodeSpec.create(
            node_id="review", task_id="task", title="review", task_family="review",
            role="supervisor", risk="R2", write_access=False, scopes=(),
            prompt_path="unused.md", output_schema=str(SCHEMA), priority=90,
            dependencies=("check",),
        ),
    ])
    claimed = mesh.claim_ready("check-owner", limit=1)
    assert [node["node_id"] for node in claimed] == ["check"]
    finished = mesh.finish_node(
        "check", owner="check-owner", success=False, run_id="check-run",
        registry_id="deterministic-check-runner", provider="local",
        error="machine_checks_blocked", quarantine=True,
    )
    assert finished["state"] == "QUARANTINED"
    assert mesh.get_node("review")["state"] == "READY"
    assert mesh.claim_ready("review-owner", limit=8) == []


def test_failed_machine_check_blocks_all_review_nodes(tmp_path):
    import subprocess

    repo, _ = init_git_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    (repo / "src/component.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "component"], cwd=repo, check=True, capture_output=True)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()

    output_root = tmp_path / "outputs"
    output_root.mkdir()
    (repo / "src/component.py").write_text("VALUE = 2   \n", encoding="utf-8")
    patch_path = output_root / "integrated.patch"
    patch_path.write_bytes(subprocess.check_output(
        ["git", "diff", "--binary", base, "--", "src/component.py"], cwd=repo
    ))
    assert patch_path.stat().st_size > 0
    subprocess.run(["git", "reset", "--hard", base], cwd=repo, check=True, capture_output=True)

    config = repo / ".delivery/ztad/config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({
        "schema_version": 1, "configured": True, "environment_allowlist": [],
        "checks": [{
            "id": "diff-check", "argv": ["git", "diff", "--check", "HEAD^", "HEAD"],
            "cwd": ".", "timeout_seconds": 60,
            "evidence_type": "LOCAL_DIFF_CHECK", "fail_fast": True,
        }],
    }), encoding="utf-8")

    contract = valid_contract(risk="R2", components=["src/component.py"])
    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(
        repository=str(repo), title="bad whitespace", contract=contract, risk="R2",
        task_id="task", idempotency_key="task",
    )
    mesh = MeshStore(tmp_path / "mesh.db")
    nodes = [
        MeshNodeSpec.create(
            node_id="integrated", task_id=task["task_id"], title="integrated patch",
            task_family="integration", role="patch_integrator", risk="R2",
            write_access=False, scopes=("src/component.py",), prompt_path="unused.md",
            output_schema=str(SCHEMA), priority=100, metadata={"base_sha": base},
        ),
        MeshNodeSpec.create(
            node_id="machine-check", task_id=task["task_id"], title="machine check",
            task_family="verification", role="check_runner", risk="R2",
            write_access=False, scopes=("src/component.py",), prompt_path="unused.md",
            output_schema=str(SCHEMA), priority=90, dependencies=("integrated",),
            metadata={
                "base_sha": base, "max_attempts": 1,
                "check_config": ".delivery/ztad/config.json",
                "command_policy": str(ROOT / "policies/command-policy.yaml"),
                "risk_policy": str(ROOT / "policies/risk-policy.yaml"),
            },
        ),
    ]
    for dimension in ("scope", "correctness", "tests"):
        nodes.append(MeshNodeSpec.create(
            node_id=f"review-{dimension}", task_id=task["task_id"],
            title=f"{dimension} review", task_family="review", role="supervisor",
            risk="R2", write_access=False, scopes=("src/component.py",),
            prompt_path="unused.md", output_schema=str(SCHEMA), priority=80,
            dependencies=("machine-check",),
        ))
    mesh.submit_graph(nodes)

    claimed = mesh.claim_ready("fixture-owner", limit=1)
    assert [node["node_id"] for node in claimed] == ["integrated"]
    mesh.finish_node(
        "integrated", owner="fixture-owner", success=True, run_id="fixture-integration",
        registry_id="deterministic-integrator", provider="local",
    )
    mesh.register_artifact(
        node_id="integrated", artifact_type="COMBINED_PATCH",
        path=str(patch_path.resolve()), sha256=sha256_file(patch_path),
        metadata={"base_sha": base, "fixture": True},
    )

    provider = _TrailingWhitespaceProvider()
    runtime = MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(_catalog()), providers=ProviderRegistry([provider]),
        worker_id="worker", output_root=output_root, global_parallel_cap=8,
    )
    runtime.run_once()

    check = mesh.get_node("machine-check")
    reviews = [mesh.get_node(f"review-{dimension}") for dimension in ("scope", "correctness", "tests")]
    assert check["state"] == "QUARANTINED"
    assert check["last_error"] == "machine_checks_blocked"
    assert all(node["state"] == "READY" for node in reviews)
    assert mesh.claim_ready("review-owner", limit=8) == []
    assert provider.review_calls == 0

def test_write_mesh_plan_rejects_output_escape_and_conflict_without_partial_write(tmp_path):
    from ztad.mesh_plan import write_mesh_plan
    repo, _ = init_git_repo(tmp_path / "repo")
    contract = valid_contract(components=["src/component.py"])
    plan = build_mesh_plan(
        task_id="task", risk="R1", contract=contract,
        prompt_root=".delivery/ztad/tasks/task/prompts", output_schema=str(SCHEMA),
        maximum_parallel_writers=1, maximum_plan_candidates=1,
    )
    with pytest.raises(ValueError, match="escapes repository"):
        write_mesh_plan(plan, repository=repo, output_file=tmp_path / "outside.json")
    assert not (repo / ".delivery/ztad/tasks/task/prompts").exists()

    conflict = repo / next(iter(plan.prompt_files))
    conflict.parent.mkdir(parents=True, exist_ok=True)
    conflict.write_text("user content", encoding="utf-8")
    output = repo / ".delivery/ztad/tasks/task/plan.json"
    with pytest.raises(ValueError, match="Refusing to overwrite"):
        write_mesh_plan(plan, repository=repo, output_file=output)
    assert not output.exists()
    assert conflict.read_text(encoding="utf-8") == "user content"


def _single_mesh_node(store: MeshStore, *, node_id: str = "node", state: str = "READY") -> dict:
    store.submit_graph([MeshNodeSpec.create(
        node_id=node_id, task_id="task", title=node_id, task_family="review",
        role="supervisor", risk="R2", write_access=False, scopes=(),
        prompt_path="prompt.md", output_schema=str(SCHEMA), idempotency_key=node_id,
    )])
    if state != "READY":
        conn = store._connect()
        try:
            conn.execute("UPDATE mesh_nodes SET state=? WHERE node_id=?", (state, node_id))
        finally:
            conn.close()
    return store.get_node(node_id)


def test_reactivate_quarantined_requires_new_condition_without_resetting_attempts(tmp_path):
    store = MeshStore(tmp_path / "mesh.db")
    _single_mesh_node(store, state="QUARANTINED")
    conn = store._connect()
    try:
        conn.execute("UPDATE mesh_nodes SET attempts=4,last_error='blocked' WHERE node_id='node'")
    finally:
        conn.close()

    with pytest.raises(ValueError, match="Only a quarantined"):
        ready_store = MeshStore(tmp_path / "ready.db")
        _single_mesh_node(ready_store)
        ready_store.reactivate_quarantined("node", change_token="credential-v2", reason="credential restored")

    reactivated = store.reactivate_quarantined(
        "node", change_token="credential-v2", reason="The previously missing credential was provisioned"
    )
    assert reactivated["state"] == "RETRY_READY"
    assert reactivated["attempts"] == 4
    assert reactivated["last_error"] is None
    assert reactivated["metadata"]["last_reactivation_token"] == "credential-v2"

    conn = store._connect()
    try:
        conn.execute("UPDATE mesh_nodes SET state='QUARANTINED' WHERE node_id='node'")
    finally:
        conn.close()
    with pytest.raises(ValueError, match="already used"):
        store.reactivate_quarantined("node", change_token="credential-v2", reason="replay")


def test_mesh_status_distinguishes_runnable_delayed_and_quarantined(tmp_path):
    from datetime import datetime, timedelta, timezone

    store = MeshStore(tmp_path / "mesh.db")
    for node_id in ("ready", "delayed", "quarantined"):
        _single_mesh_node(store, node_id=node_id)
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    conn = store._connect()
    try:
        conn.execute("UPDATE mesh_nodes SET state='RETRY_READY',next_run_at=? WHERE node_id='delayed'", (future,))
        conn.execute("UPDATE mesh_nodes SET state='QUARANTINED' WHERE node_id='quarantined'")
    finally:
        conn.close()

    status = store.status()
    assert status["ready"] == 2
    assert status["runnable_now"] == 1
    assert status["delayed_retry"] == 1
    assert status["quarantined"] == 1
    claimed = store.claim_ready("worker", limit=8, lease_seconds=30)
    assert [node["node_id"] for node in claimed] == ["ready"]


def test_actual_diff_risk_escalation_is_contained_before_review(tmp_path):
    from ztad.repository import GitRepository

    repo, base = init_git_repo(tmp_path / "repo")
    config = repo / ".delivery/ztad/config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({
        "schema_version": 1, "configured": True, "environment_allowlist": [],
        "checks": [{
            "id": "diff-check", "argv": ["git", "diff", "--check", "HEAD^", "HEAD"],
            "cwd": ".", "timeout_seconds": 60, "evidence_type": "LOCAL_DIFF_CHECK", "fail_fast": True,
        }],
    }), encoding="utf-8")
    output_root = tmp_path / "runs"
    output_root.mkdir()
    manager = WorktreeManager(GitRepository(repo))
    worktree = manager.create("source", base)
    try:
        migration = worktree / "migrations/001.sql"
        migration.parent.mkdir(parents=True)
        migration.write_text("DROP TABLE customers;\n", encoding="utf-8")
        patch_path = output_root / "migration.patch"
        assert manager.patch(worktree, base, patch_path)["has_changes"]
    finally:
        manager.remove(worktree)

    contract = valid_contract(risk="R3", components=["migrations"])
    contract["scope"]["data_migration_expected"] = True
    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(
        repository=str(repo), title="migration", contract=contract, risk="R3", idempotency_key="migration",
    )
    mesh = MeshStore(tmp_path / "mesh.db")
    mesh.submit_graph([
        MeshNodeSpec.create(
            node_id="writer", task_id=task["task_id"], title="writer", task_family="implementation",
            role="worker", risk="R3", write_access=True, scopes=("migrations/**",), prompt_path="prompt.md",
            output_schema=str(SCHEMA), idempotency_key="writer",
        ),
        MeshNodeSpec.create(
            node_id="checks", task_id=task["task_id"], title="checks", task_family="verification",
            role="check_runner", risk="R3", write_access=False, scopes=("migrations/**",), prompt_path="prompt.md",
            output_schema=str(SCHEMA), dependencies=("writer",), metadata={
                "base_sha": base, "check_config": ".delivery/ztad/config.json",
                "command_policy": str(ROOT / "policies/command-policy.yaml"),
                "risk_policy": str(ROOT / "policies/risk-policy.yaml"),
            }, idempotency_key="checks",
        ),
        MeshNodeSpec.create(
            node_id="review", task_id=task["task_id"], title="review", task_family="review",
            role="supervisor", risk="R3", write_access=False, scopes=("migrations/**",), prompt_path="prompt.md",
            output_schema=str(SCHEMA), dependencies=("checks",), idempotency_key="review",
        ),
    ])
    claimed = mesh.claim_ready("seed", limit=1)
    assert claimed[0]["node_id"] == "writer"
    mesh.register_artifact(
        node_id="writer", artifact_type="PATCH", path=str(patch_path), sha256=sha256_file(patch_path),
        metadata={"base_sha": base, "changed_paths": ["migrations/001.sql"]},
    )
    mesh.finish_node("writer", owner="seed", success=True, run_id="seed", registry_id="seed", provider="local")
    runtime = MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(_catalog()), providers=ProviderRegistry([MockProvider()]),
        worker_id="mesh", output_root=output_root,
    )
    result = runtime.run_once().to_dict()
    assert result["quarantined"] == 1, result
    check = result["results"][0]
    assert check["risk_escalated"] is True
    assert check["actual_risk"]["risk"] == "R4"
    assert check["state"] == "QUARANTINED"
    assert mesh.get_node("review")["state"] == "READY"
    assert mesh.status()["blocked_by_dependencies"] >= 1


def test_python_source_has_no_duplicate_definitions_or_literal_dict_keys():
    issues = []
    source_roots = [ROOT / "toolkit/ztad", ROOT / "scripts"]
    for source_root in source_roots:
        for path in sorted(source_root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            module_names = [
                node.name for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            ]
            for name in sorted(set(module_names)):
                if module_names.count(name) > 1:
                    issues.append(f"{path.relative_to(ROOT)}:duplicate-module-definition:{name}")
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    names = [
                        item.name for item in node.body
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    ]
                    for name in sorted(set(names)):
                        if names.count(name) > 1:
                            issues.append(f"{path.relative_to(ROOT)}:{node.name}:duplicate-method:{name}")
                if isinstance(node, ast.Dict):
                    seen = set()
                    for key in node.keys:
                        if isinstance(key, ast.Constant) and isinstance(key.value, (str, int, float, bytes)):
                            marker = (type(key.value).__name__, key.value)
                            if marker in seen:
                                issues.append(
                                    f"{path.relative_to(ROOT)}:{getattr(node, 'lineno', '?')}:duplicate-literal-key:{key.value!r}"
                                )
                            seen.add(marker)
    assert issues == []


def test_check_runner_blocked_report_cannot_be_recorded_as_success(monkeypatch, tmp_path):
    """Directly guard the machine-check decision branch.

    This isolates the authoritative check result from downstream routing so a
    later failure cannot accidentally mask a mutated success branch.
    """
    import subprocess
    import ztad.mesh_runtime as mesh_runtime_module

    repo, _ = init_git_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    (repo / "src/component.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "component"], cwd=repo, check=True, capture_output=True)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()

    continuity = ContinuityStore(tmp_path / "continuity.db")
    contract = valid_contract(risk="R2", components=["src/component.py"])
    task = continuity.submit_task(
        repository=str(repo), title="blocked checks", contract=contract,
        risk="R2", task_id="task-check", idempotency_key="task-check",
    )
    prompt = repo / "prompt.md"
    prompt.write_text("check", encoding="utf-8")
    mesh = MeshStore(tmp_path / "mesh.db")
    mesh.submit_graph([
        MeshNodeSpec.create(
            node_id="worker", task_id=task["task_id"], title="worker",
            task_family="implementation", role="worker", risk="R2",
            write_access=True, scopes=("src/component.py",), prompt_path="prompt.md",
            output_schema=str(SCHEMA), metadata={"base_sha": base, "head_sha": base},
            idempotency_key="worker",
        ),
        MeshNodeSpec.create(
            node_id="checks", task_id=task["task_id"], title="checks",
            task_family="verification", role="check_runner", risk="R2",
            write_access=False, scopes=(), prompt_path="prompt.md",
            output_schema=str(SCHEMA), dependencies=("worker",), metadata={
                "base_sha": base,
                "check_config": ".delivery/ztad/config.json",
                "command_policy": str(ROOT / "policies/command-policy.yaml"),
            }, idempotency_key="checks",
        ),
    ])
    # Seed a real patch artifact and make the worker dependency successful.
    output_root = tmp_path / "outputs"
    output_root.mkdir()
    patch = output_root / "change.patch"
    patch.write_text(
        "diff --git a/src/component.py b/src/component.py\n"
        "index 7f8f011..536f387 100644\n"
        "--- a/src/component.py\n"
        "+++ b/src/component.py\n"
        "@@ -1 +1 @@\n"
        "-VALUE = 1\n"
        "+VALUE = 2\n",
        encoding="utf-8",
    )
    mesh.register_artifact(
        node_id="worker", artifact_type="PATCH", path=str(patch),
        sha256=sha256_file(patch), metadata={"base_sha": base},
    )
    claimed_workers = mesh.claim_ready(owner="seed", limit=1, lease_seconds=60)
    assert claimed_workers and claimed_workers[0]["node_id"] == "worker"
    mesh.finish_node(
        "worker", owner="seed", success=True, run_id="seed", registry_id="seed", provider="local"
    )

    config = repo / ".delivery/ztad/config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({
        "schema_version": 1, "configured": True, "environment_allowlist": [], "checks": []
    }), encoding="utf-8")

    monkeypatch.setattr(mesh_runtime_module, "run_checks", lambda *args, **kwargs: {
        "blocked": True,
        "decision": "BLOCK",
        "results": [],
        "claim_boundary": "synthetic blocked report",
    })
    runtime = MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(_catalog()), providers=ProviderRegistry([MockProvider()]),
        worker_id="check-owner", output_root=output_root,
    )
    claimed_nodes = mesh.claim_ready(owner="check-owner", limit=1, lease_seconds=60)
    assert claimed_nodes and claimed_nodes[0]["node_id"] == "checks"
    result = runtime._execute_check_runner(claimed_nodes[0])
    assert result["success"] is False
    assert result["validation_errors"] == ["machine_checks_blocked"]
    assert mesh.get_node("checks")["state"] != "SUCCEEDED"
