from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

from ztad.approval_controller import issue_supervisor_approval_evidence
from ztad.context import build_context_manifest
from ztad.crypto import generate_ed25519_keypair
from ztad.host_acceptance import audit_host_acceptance
from ztad.loop_guard import AttemptFingerprint
from ztad.mesh_plan import build_mesh_plan, write_mesh_plan
from ztad.mesh_runtime import MeshRuntime
from ztad.mesh_store import MeshNodeSpec, MeshStore
from ztad.model_router import AdaptiveModelRouter
from ztad.orchestrator import ContinuityStore
from ztad.providers import (
    GenericStructuredCommandProvider,
    ProviderRegistry,
    ProviderRunRequest,
    ProviderRunResult,
)
from ztad.repository import GitRepository
from ztad.util import canonical_json, sha256_bytes, utc_now

from conftest import init_git_repo, valid_contract

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/agent-result.schema.json"


def _catalog(provider: str) -> dict:
    return {
        "routing": {"minimum_quality_by_risk": {"R2": 0.8}, "frontier_role_quality_floor": 0.9},
        "models": [
            {
                "registry_id": "writer-model", "provider": provider, "model": "writer", "tier": "balanced",
                "reasoning_efforts": ["medium"], "sandboxes": ["workspace-write", "read-only"],
                "task_quality": {"implementation": 0.9, "default": 0.9}, "reliability": 1.0,
                "cost_index": 0.1, "latency_index": 0.1, "max_parallel": 4,
            },
            {
                "registry_id": "frontier-model", "provider": provider, "model": "frontier", "tier": "frontier",
                "reasoning_efforts": ["high"], "sandboxes": ["read-only", "workspace-write"],
                "task_quality": {"review": 0.98, "default": 0.96}, "reliability": 1.0,
                "cost_index": 1.0, "latency_index": 0.8, "max_parallel": 2,
            },
        ],
    }


def _output(request: ProviderRunRequest, envelope: dict, role: str) -> dict:
    return {
        "schema_version": 1,
        "task_id": request.task_id,
        "agent_role": role,
        "model_registry_id": request.registry_id,
        "prompt_version": envelope["prompt_version"],
        "base_sha": envelope["base_sha"],
        "head_sha": envelope["head_sha"],
        "context_id": envelope["context_id"],
        "result_type": "IMPLEMENTATION_PROPOSAL" if role == "implementer" else "NO_BLOCKING_FINDINGS_IN_REVIEWED_SCOPE",
        "claims": [], "findings": [], "files_read": [], "files_not_read": [],
        "uncertainties": [], "tested_scope": [], "untested_scope": [], "known_unknowns": [],
        "requested_action": "VALIDATE_PATCH" if role == "implementer" else "CONTINUE_POLICY_EVALUATION",
        "risk_escalation": None, "patch_path": None,
    }


class IntegrationAwareProvider:
    name = "integration-aware"

    def __init__(self):
        self.review_saw_integrated = False
        self.calls = 0

    def probe(self):
        return {"available": True, "provider": self.name}

    def run(self, request: ProviderRunRequest) -> ProviderRunResult:
        self.calls += 1
        envelope = ast.literal_eval(request.prompt.split("ZTAD_IMMUTABLE_ENVELOPE\n", 1)[1].splitlines()[0])
        role = envelope["agent_role"]
        if request.role == "worker":
            target = request.cwd / ("src/a/value.py" if "src/a/**" in envelope["allowed_scopes"] else "src/b/value.py")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("VALUE = 1\n", encoding="utf-8")
        if request.role == "supervisor":
            self.review_saw_integrated = (request.cwd / "src/a/value.py").exists() and (request.cwd / "src/b/value.py").exists()
            if not self.review_saw_integrated:
                return ProviderRunResult(
                    run_id="review-missing", provider=self.name, task_id=request.task_id, role=request.role,
                    registry_id=request.registry_id, model=request.model, session_id="review-missing",
                    started_at=utc_now(), completed_at=utc_now(), exit_code=1, success=False, output=None,
                    output_hash=None, stdout_hash=sha256_bytes(b""), stderr_hash=sha256_bytes(b"missing"),
                    input_tokens=1, output_tokens=1, errors=("integrated_patch_not_visible",), argv=("mock",),
                )
        output = _output(request, envelope, role)
        return ProviderRunResult(
            run_id=f"run-{request.role}-{self.calls}", provider=self.name, task_id=request.task_id,
            role=request.role, registry_id=request.registry_id, model=request.model,
            session_id=f"session-{request.role}-{self.calls}", started_at=utc_now(), completed_at=utc_now(),
            exit_code=0, success=True, output=output, output_hash=sha256_bytes(canonical_json(output)),
            stdout_hash=sha256_bytes(b""), stderr_hash=sha256_bytes(b""), input_tokens=10, output_tokens=10,
            errors=(), argv=("mock",),
        )


def test_mesh_plan_maximizes_only_independent_writes(tmp_path):
    contract = valid_contract(risk="R4")
    contract["scope"]["expected_components"] = ["src/a", "src/b", "src/c", "tests"]
    plan = build_mesh_plan(task_id="TASK-1", risk="R4", contract=contract, maximum_parallel_writers=3)
    writers = [node for node in plan.nodes if node.role == "worker"]
    integrators = [node for node in plan.nodes if node.role == "patch_integrator"]
    reviewers = [node for node in plan.nodes if node.task_family == "review"]
    assert len(writers) == 3
    assert len(integrators) == 1
    assert len(reviewers) >= 7
    roots = [{scope.removesuffix("/**") for scope in node.scopes} for node in writers]
    assert all(left.isdisjoint(right) for i, left in enumerate(roots) for right in roots[i + 1 :])
    output = tmp_path / "repo" / ".delivery/ztad/mesh-plan.json"
    (tmp_path / "repo").mkdir()
    written = write_mesh_plan(plan, repository=tmp_path / "repo", output_file=output)
    assert written["node_count"] == len(plan.nodes)
    assert output.is_file()


def test_enriched_context_includes_reverse_dependency_and_sufficiency(tmp_path):
    repo_path, base = init_git_repo(tmp_path / "repo")
    (repo_path / "src").mkdir()
    (repo_path / "src/core.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo_path / "src/user.py").write_text("from .core import VALUE\n", encoding="utf-8")
    (repo_path / "tests").mkdir()
    (repo_path / "tests/test_core.py").write_text("from src.core import VALUE\n", encoding="utf-8")
    import subprocess
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True)
    subprocess.run(["git", "commit", "-m", "graph"], cwd=repo_path, check=True, capture_output=True)
    graph_base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_path, text=True).strip()
    (repo_path / "src/core.py").write_text("VALUE = 2\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True)
    subprocess.run(["git", "commit", "-m", "change"], cwd=repo_path, check=True, capture_output=True)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_path, text=True).strip()
    manifest = build_context_manifest(
        GitRepository(repo_path), graph_base, head, "R3",
        contract_hash="sha256:" + "a" * 64, policy_hash="sha256:" + "b" * 64,
        max_files_by_risk={"R3": 30},
    )
    paths = {item["path"] for item in manifest["included"]}
    assert "src/core.py" in paths
    assert "src/user.py" in paths
    assert manifest["repository_index_hash"]
    assert manifest["context_sufficiency"] is not None


def test_patch_integration_is_visible_to_review_model(tmp_path):
    repo_path, base = init_git_repo(tmp_path / "repo")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    contract = valid_contract(risk="R2")
    contract["scope"]["expected_components"] = ["src/a", "src/b"]
    task = continuity.submit_task(repository=str(repo_path), title="t", contract=contract, risk="R2", idempotency_key="t")
    mesh = MeshStore(tmp_path / "mesh.db")
    for name in ("write-a", "write-b", "integrate", "review"):
        (repo_path / f"{name}.md").write_text(name, encoding="utf-8")
    context = "sha256:" + "c" * 64
    common = {"base_sha": base, "head_sha": base, "context_id": context, "prompt_version": "mesh-v1"}
    specs = [
        MeshNodeSpec.create(node_id="write-a", task_id=task["task_id"], title="a", task_family="implementation", role="worker", risk="R2", write_access=True, scopes=("src/a/**",), prompt_path="write-a.md", output_schema=str(SCHEMA), metadata={**common, "agent_role": "implementer"}, idempotency_key="a"),
        MeshNodeSpec.create(node_id="write-b", task_id=task["task_id"], title="b", task_family="implementation", role="worker", risk="R2", write_access=True, scopes=("src/b/**",), prompt_path="write-b.md", output_schema=str(SCHEMA), metadata={**common, "agent_role": "implementer"}, idempotency_key="b"),
        MeshNodeSpec.create(node_id="integrate", task_id=task["task_id"], title="i", task_family="integration", role="patch_integrator", risk="R2", write_access=False, scopes=("src/a/**", "src/b/**"), prompt_path="integrate.md", output_schema=str(SCHEMA), metadata=common, dependencies=("write-a", "write-b"), idempotency_key="i"),
        MeshNodeSpec.create(node_id="review", task_id=task["task_id"], title="r", task_family="review", role="supervisor", risk="R2", write_access=False, scopes=("src/a/**", "src/b/**"), prompt_path="review.md", output_schema=str(SCHEMA), metadata={**common, "agent_role": "independent_reviewer", "consume_dependency_patches": True}, dependencies=("integrate",), idempotency_key="r"),
    ]
    mesh.submit_graph(specs)
    provider = IntegrationAwareProvider()
    runtime = MeshRuntime(
        repository=repo_path, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(_catalog(provider.name)), providers=ProviderRegistry([provider]),
        worker_id="runner", output_root=tmp_path / "runs", global_parallel_cap=1,
    )
    result = runtime.run_until_idle(maximum_ticks=10, idle_rounds=1)
    assert result["mesh_status"]["states"].get("SUCCEEDED") == 4, result
    assert provider.review_saw_integrated
    assert len(mesh.list_artifacts(artifact_type="PATCH")) == 2
    assert len(mesh.list_artifacts(artifact_type="COMBINED_PATCH")) == 1
    assert not (repo_path / "src/a/value.py").exists()


def test_approval_derived_from_stored_run_identity(tmp_path):
    store = ContinuityStore(tmp_path / "continuity.db")
    task = store.submit_task(repository="owner/repo", title="t", contract=valid_contract(risk="R2"), risk="R2", idempotency_key="t")
    head = "a" * 40
    store.record_model_run(
        task_id=task["task_id"], role="supervisor", model_id="frontier", prompt_version="p",
        context_hash="sha256:" + "c" * 64, status="COMPLETED", session_id="real-session",
        reasoning_effort="high", head_sha=head, output_hash="sha256:" + "d" * 64, run_id="review-run",
    )
    store.register_evidence(
        evidence_id="ci", task_id=task["task_id"], head_sha=head, evidence_type="protected_ci",
        trust_level="E4", status="PASSED", producer="ci", payload={"authoritative_record_validated": True},
    )
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    generate_ed25519_keypair(private, public)
    subject = {
        "repository": "owner/repo", "change_contract_hash": "sha256:" + "b" * 64,
        "base_sha": "c" * 40, "head_sha": head, "policy_bundle_hash": "sha256:" + "e" * 64,
        "toolchain_hash": "sha256:" + "f" * 64,
    }
    result = issue_supervisor_approval_evidence(
        store=store, task_id=task["task_id"], reviewer_run_id="review-run",
        head_sha=head, diff_hash="sha256:" + "1" * 64, evidence_refs=["ci"],
        approval_type="STRONG_SUPERVISOR_TECHNICAL_APPROVAL", subject=subject,
        private_key_path=private, key_id="k", output_path=tmp_path / "approval.json",
    )
    assert result["approval"]["session_id"] == "real-session"
    with pytest.raises(KeyError):
        issue_supervisor_approval_evidence(
            store=store, task_id=task["task_id"], reviewer_run_id="invented",
            head_sha=head, diff_hash="sha256:" + "1" * 64, evidence_refs=["ci"],
            approval_type="STRONG_SUPERVISOR_TECHNICAL_APPROVAL", subject=subject,
            private_key_path=private, key_id="k",
        )


def test_generic_provider_rejects_shell_templates_and_validates_output(tmp_path):
    with pytest.raises(ValueError):
        GenericStructuredCommandProvider(name="bad", executable="x", argv_template=["--x;rm"])
    script = tmp_path / "provider.py"
    script.write_text(
        "import json,sys\nout=sys.argv[1]\np=json.load(sys.stdin) if False else {}\njson.dump({'ok': True},open(out,'w'))\n",
        encoding="utf-8",
    )
    provider = GenericStructuredCommandProvider(
        name="generic", executable=sys.executable, argv_template=[str(script), "{output}"],
    )
    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object","required":["ok"],"properties":{"ok":{"const":true}},"additionalProperties":false}', encoding="utf-8")
    result = provider.run(ProviderRunRequest(
        task_id="t", role="planner", registry_id="g", model="m", reasoning_effort="medium",
        sandbox="read-only", prompt="prompt", output_schema=schema, cwd=tmp_path,
    ))
    assert result.success, result
    invalid_script = tmp_path / "invalid-provider.py"
    invalid_script.write_text(
        "import json,sys\njson.dump({'ok': False},open(sys.argv[1],'w'))\n",
        encoding="utf-8",
    )
    invalid_provider = GenericStructuredCommandProvider(
        name="generic-invalid", executable=sys.executable,
        argv_template=[str(invalid_script), "{output}"],
    )
    invalid = invalid_provider.run(ProviderRunRequest(
        task_id="t", role="planner", registry_id="g", model="m", reasoning_effort="medium",
        sandbox="read-only", prompt="prompt", output_schema=schema, cwd=tmp_path,
    ))
    assert not invalid.success
    assert any(item.startswith("schema:") for item in invalid.errors)


def test_attempt_fingerprint_distinguishes_alternative_model():
    common = dict(task_id="t", strategy_hash="s", prompt_hash="p", context_hash="c", head_sha="h", diff_hash="d", failing_evidence_hash="f")
    first = AttemptFingerprint(**common, provider="a", model="m1")
    second = AttemptFingerprint(**common, provider="b", model="m2")
    assert first.signature != second.signature


def test_host_acceptance_never_promotes_from_gh_presence(monkeypatch, tmp_path):
    monkeypatch.setenv("ZTAD_HOOKS_TRUSTED", "1")
    result = audit_host_acceptance(plugin_root=ROOT, repository=tmp_path, inspect_codex_plugin_state=False)
    assert result["maximum_verified_mode"] != "GOVERNED_PULL_REQUEST_CANDIDATE"
    assert result["github_remote_governance_verified"] is False


def test_model_benchmark_scores_cases_and_can_feed_history(tmp_path):
    from ztad.model_benchmark import BenchmarkCase, ModelBenchmarkRunner
    from ztad.providers import MockProvider

    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object","required":["result_type"],"properties":{"result_type":{"type":"string"}},"additionalProperties":true}', encoding="utf-8")
    provider = MockProvider(name="mock", responses=[{
        "success": True,
        "output": {"result_type": "PLAN_READY", "requested_action": "VALIDATE_PLAN", "findings": []},
    }])
    router = AdaptiveModelRouter({
        "routing": {"minimum_quality_by_risk": {"R1": 0.7}},
        "models": [{
            "registry_id": "m", "provider": "mock", "model": "m", "tier": "economy",
            "reasoning_efforts": ["medium"], "sandboxes": ["read-only"],
            "task_quality": {"repository_navigation": 0.9}, "reliability": 1.0,
            "cost_index": 0.1, "latency_index": 0.1,
        }],
    })
    case = BenchmarkCase(
        case_id="c", task_family="repository_navigation", role="context_scout", risk="R1",
        prompt="p", output_schema=schema,
        assertions={"result_type_in": ["PLAN_READY"], "requested_action_in": ["VALIDATE_PLAN"], "max_findings": 0},
    )
    result = ModelBenchmarkRunner(router, ProviderRegistry([provider])).run([case], cwd=tmp_path)
    assert result["results"][0]["quality"] == 1.0
    assert result["results"][0]["reliability"] == 1.0


def test_normalize_repo_path_rejects_direct_and_nested_traversal():
    from ztad.path_security import normalize_repo_path

    for value in ("../escape.py", "a/../../escape.py", r"..\\escape.py", r"safe\\..\\..\\escape.py"):
        with pytest.raises(ValueError, match="traversal"):
            normalize_repo_path(value)
