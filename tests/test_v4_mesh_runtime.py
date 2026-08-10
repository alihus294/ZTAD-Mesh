from __future__ import annotations

import json
from pathlib import Path

from ztad.mesh_runtime import MeshRuntime
from ztad.mesh_store import MeshNodeSpec, MeshStore
from ztad.model_router import AdaptiveModelRouter
from ztad.orchestrator import ContinuityStore
from ztad.providers import MockProvider, ProviderRegistry, ProviderRunResult
from ztad.util import canonical_json, sha256_bytes, utc_now

from conftest import init_git_repo, valid_contract


def catalog(provider="mock"):
    return {
        "routing": {"minimum_quality_by_risk": {"R1": 0.7, "R2": 0.8}, "frontier_role_quality_floor": 0.9, "global_parallel_cap": 8},
        "models": [
            {"registry_id": "mock-e", "provider": provider, "model": "economy", "tier": "economy", "reasoning_efforts": ["medium"], "sandboxes": ["read-only", "workspace-write"], "task_quality": {"repository_navigation": 0.9, "implementation": 0.85}, "reliability": 0.95, "cost_index": 0.2, "latency_index": 0.2, "max_parallel": 8},
            {"registry_id": "mock-f", "provider": provider, "model": "frontier", "tier": "frontier", "reasoning_efforts": ["high"], "sandboxes": ["read-only", "workspace-write"], "task_quality": {"review": 0.98, "implementation": 0.95}, "reliability": 0.98, "cost_index": 1.0, "latency_index": 0.8, "max_parallel": 4},
        ],
    }


def agent_output(task_id, base_sha, context_id, role="independent_reviewer"):
    return {
        "schema_version": 1,
        "task_id": task_id,
        "agent_role": role,
        "model_registry_id": "mock-f",
        "prompt_version": "mesh-v1",
        "base_sha": base_sha,
        "head_sha": base_sha,
        "context_id": context_id,
        "result_type": "NO_BLOCKING_FINDINGS_IN_REVIEWED_SCOPE" if role != "implementer" else "IMPLEMENTATION_PROPOSAL",
        "claims": [], "findings": [], "files_read": [], "files_not_read": [],
        "uncertainties": [], "tested_scope": [], "untested_scope": [], "known_unknowns": [],
        "requested_action": "CONTINUE_POLICY_EVALUATION" if role != "implementer" else "VALIDATE_PATCH",
        "risk_escalation": None, "patch_path": None,
    }


def setup_runtime(tmp_path, provider):
    repo_path, base = init_git_repo(tmp_path / "repo")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(
        repository=str(repo_path), title="task", contract=valid_contract(risk="R2"),
        risk="R2", idempotency_key="task",
    )
    mesh = MeshStore(tmp_path / "mesh.db")
    runtime = MeshRuntime(
        repository=repo_path, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(catalog(provider.name)), providers=ProviderRegistry([provider]),
        worker_id="runner", output_root=tmp_path / "runs", global_parallel_cap=4,
    )
    return repo_path, base, task, mesh, continuity, runtime


def test_mesh_runtime_connects_router_provider_validation_and_durable_run(tmp_path):
    context_id = "sha256:" + "c" * 64
    provider = MockProvider(responses=[])
    repo_path, base, task, mesh, continuity, runtime = setup_runtime(tmp_path, provider)
    provider.responses.append({"success": True, "session_id": "review-session", "output": agent_output(task["task_id"], base, context_id)})
    prompt = repo_path / "prompt.md"; prompt.write_text("review", encoding="utf-8")
    mesh.submit_graph([MeshNodeSpec.create(
        node_id="review", task_id=task["task_id"], title="review", task_family="review",
        role="supervisor", risk="R2", write_access=False, scopes=(), prompt_path="prompt.md",
        output_schema=str(Path(__file__).resolve().parents[1] / "schemas/agent-result.schema.json"),
        metadata={"base_sha": base, "head_sha": base, "context_id": context_id}, idempotency_key="review",
    )])
    result = runtime.run_once().to_dict()
    assert result["succeeded"] == 1, result
    assert mesh.get_node("review")["state"] == "SUCCEEDED"
    assert continuity.list_tasks()[0]["task_id"] == task["task_id"]
    # Session/model run was registered automatically, not supplied later by a caller.
    conn = continuity._connect()
    try:
        row = conn.execute("SELECT * FROM model_runs WHERE task_id=?", (task["task_id"],)).fetchone()
        assert row["session_id"] == "review-session"
        assert row["status"] == "COMPLETED"
    finally:
        conn.close()


def test_mesh_runtime_rejects_invalid_agent_envelope(tmp_path):
    provider = MockProvider(responses=[{"success": True, "session_id": "s", "output": {"wrong": True}}])
    repo_path, base, task, mesh, continuity, runtime = setup_runtime(tmp_path, provider)
    prompt = repo_path / "prompt.md"; prompt.write_text("review", encoding="utf-8")
    mesh.submit_graph([MeshNodeSpec.create(
        node_id="review", task_id=task["task_id"], title="review", task_family="review",
        role="supervisor", risk="R2", write_access=False, scopes=(), prompt_path="prompt.md",
        output_schema=str(Path(__file__).resolve().parents[1] / "schemas/agent-result.schema.json"),
        metadata={"base_sha": base, "head_sha": base, "context_id": "sha256:" + "c" * 64}, idempotency_key="review",
    )])
    result = runtime.run_once().to_dict()
    assert result["failed"] == 1
    assert mesh.get_node("review")["state"] == "RETRY_READY"
    assert result["results"][0]["validation_errors"]


class WritingProvider:
    name = "writer"
    def __init__(self, relative_path: str): self.relative_path = relative_path
    def probe(self): return {"available": True}
    def run(self, request):
        target = request.cwd / self.relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("value = 1\n", encoding="utf-8")
        output = agent_output(request.task_id, request.cwd.joinpath('.git').exists() and "a"*40 or "a"*40, "placeholder", role="implementer")
        # Runtime validates exact fields supplied in node metadata; tests patch them below through request prompt parsing is irrelevant.
        envelope_text = request.prompt.split("ZTAD_IMMUTABLE_ENVELOPE\n", 1)[1].splitlines()[0]
        envelope = __import__('ast').literal_eval(envelope_text)
        output["base_sha"] = envelope["base_sha"]
        output["head_sha"] = envelope["head_sha"]
        output["context_id"] = envelope["context_id"]
        output["task_id"] = envelope["task_id"]
        output["model_registry_id"] = request.registry_id
        return ProviderRunResult(
            run_id="write-run", provider=self.name, task_id=request.task_id, role=request.role,
            registry_id=request.registry_id, model=request.model, session_id="write-session",
            started_at=utc_now(), completed_at=utc_now(), exit_code=0, success=True, output=output,
            output_hash=sha256_bytes(canonical_json(output)), stdout_hash=sha256_bytes(b""), stderr_hash=sha256_bytes(b""),
            input_tokens=10, output_tokens=10, errors=(), argv=("writer",),
        )


def writer_catalog():
    return {"routing": {"minimum_quality_by_risk": {"R2": 0.8}}, "models": [{
        "registry_id": "writer", "provider": "writer", "model": "writer", "tier": "balanced",
        "reasoning_efforts": ["medium"], "sandboxes": ["workspace-write"],
        "task_quality": {"implementation": 0.9}, "reliability": 1.0, "cost_index": 0.1, "latency_index": 0.1,
    }]}


def test_write_node_uses_isolated_worktree_and_scope_gate(tmp_path):
    provider = WritingProvider("src/orders/service.py")
    repo_path, base = init_git_repo(tmp_path / "repo")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(repository=str(repo_path), title="t", contract=valid_contract(risk="R2"), risk="R2", idempotency_key="t")
    mesh = MeshStore(tmp_path / "mesh.db")
    prompt = repo_path / "prompt.md"; prompt.write_text("implement", encoding="utf-8")
    mesh.submit_graph([MeshNodeSpec.create(
        node_id="write", task_id=task["task_id"], title="write", task_family="implementation", role="worker", risk="R2",
        write_access=True, scopes=("src/orders/**",), prompt_path="prompt.md",
        output_schema=str(Path(__file__).resolve().parents[1] / "schemas/agent-result.schema.json"),
        metadata={"base_sha": base, "head_sha": base, "context_id": "sha256:" + "c"*64}, idempotency_key="write",
    )])
    runtime = MeshRuntime(repository=repo_path, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(writer_catalog()), providers=ProviderRegistry([provider]), worker_id="w", output_root=tmp_path/"runs")
    result = runtime.run_once().to_dict()
    assert result["succeeded"] == 1, result
    assert not (repo_path / "src/orders/service.py").exists(), "main worktree was mutated"
    assert result["results"][0]["changed_paths"] == ["src/orders/service.py"]


def test_write_node_outside_scope_is_contained(tmp_path):
    provider = WritingProvider("src/billing/service.py")
    repo_path, base = init_git_repo(tmp_path / "repo")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(repository=str(repo_path), title="t", contract=valid_contract(risk="R2"), risk="R2", idempotency_key="t")
    mesh = MeshStore(tmp_path / "mesh.db")
    prompt = repo_path / "prompt.md"; prompt.write_text("implement", encoding="utf-8")
    mesh.submit_graph([MeshNodeSpec.create(
        node_id="write", task_id=task["task_id"], title="write", task_family="implementation", role="worker", risk="R2",
        write_access=True, scopes=("src/orders/**",), prompt_path="prompt.md",
        output_schema=str(Path(__file__).resolve().parents[1] / "schemas/agent-result.schema.json"),
        metadata={"base_sha": base, "head_sha": base, "context_id": "sha256:" + "c"*64}, idempotency_key="write",
    )])
    runtime = MeshRuntime(repository=repo_path, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(writer_catalog()), providers=ProviderRegistry([provider]), worker_id="w", output_root=tmp_path/"runs")
    result = runtime.run_once().to_dict()
    assert result["failed"] == 1
    assert any("scope_violation" in item for item in result["results"][0]["validation_errors"])
    assert not (repo_path / "src/billing/service.py").exists()
