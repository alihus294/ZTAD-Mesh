from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path

import pytest

from conftest import init_git_repo, valid_contract
from ztad.mesh_runtime import MeshRuntime
from ztad.mesh_store import MeshNodeSpec, MeshStore
from ztad.model_router import AdaptiveModelRouter
from ztad.orchestrator import ContinuityStore
from ztad.providers import ProviderRegistry
from ztad.util import sha256_file

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/agent-result.schema.json"
CATALOG = ROOT / "policies/model-catalog.yaml"


def _runtime(repo: Path, mesh: MeshStore, continuity: ContinuityStore, tmp_path: Path) -> MeshRuntime:
    return MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter.from_file(CATALOG), providers=ProviderRegistry([]),
        worker_id="test-worker", output_root=tmp_path / "outputs",
    )


def _prepare_integrated_patch(tmp_path: Path, *, content: str, risk: str = "R0"):
    repo, _ = init_git_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    (repo / "src/component.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "component"], cwd=repo, check=True, capture_output=True)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    output_root = tmp_path / "outputs"
    output_root.mkdir()
    (repo / "src/component.py").write_text(content, encoding="utf-8")
    patch = output_root / "combined.patch"
    patch.write_bytes(subprocess.check_output(["git", "diff", "--binary", base, "--", "src/component.py"], cwd=repo))
    subprocess.run(["git", "reset", "--hard", base], cwd=repo, check=True, capture_output=True)
    config = repo / ".delivery/ztad/config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({
        "schema_version": 1, "configured": True, "environment_allowlist": [],
        "checks": [{
            "id": "diff-check", "argv": ["git", "diff", "--check", "HEAD^", "HEAD"],
            "cwd": ".", "timeout_seconds": 60, "evidence_type": "LOCAL_DIFF_CHECK", "fail_fast": True,
        }],
    }), encoding="utf-8")
    contract = valid_contract(risk=risk, components=["src/component.py"])
    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(repository=str(repo), title="runtime control", contract=contract, risk=risk, task_id="parent", idempotency_key="parent")
    mesh = MeshStore(tmp_path / "mesh.db")
    mesh.submit_graph([
        MeshNodeSpec.create(
            node_id="integrated", task_id=task["task_id"], title="integrated", task_family="integration",
            role="patch_integrator", risk=risk, write_access=False, scopes=("src/component.py",),
            prompt_path="unused.md", output_schema=str(SCHEMA), priority=100,
        ),
        MeshNodeSpec.create(
            node_id="check", task_id=task["task_id"], title="check", task_family="verification",
            role="check_runner", risk=risk, write_access=False, scopes=("src/component.py",),
            prompt_path="unused.md", output_schema=str(SCHEMA), priority=90, dependencies=("integrated",),
            metadata={
                "base_sha": base, "max_attempts": 1,
                "check_config": ".delivery/ztad/config.json",
                "command_policy": str(ROOT / "policies/command-policy.yaml"),
                "risk_policy": str(ROOT / "policies/risk-policy.yaml"),
            },
        ),
        MeshNodeSpec.create(
            node_id="guard", task_id=task["task_id"], title="guard", task_family="review",
            role="supervisor", risk=risk, write_access=False, scopes=("src/component.py",),
            prompt_path="unused.md", output_schema=str(SCHEMA), priority=80, dependencies=("check",),
        ),
    ])
    claimed = mesh.claim_ready("fixture", limit=1)
    assert claimed[0]["node_id"] == "integrated"
    mesh.finish_node("integrated", owner="fixture", success=True, run_id="fixture", registry_id="deterministic-integrator", provider="local")
    mesh.register_artifact(
        node_id="integrated", artifact_type="COMBINED_PATCH", path=str(patch.resolve()), sha256=sha256_file(patch),
        metadata={
            "source_models": [{
                "registry_id": "codex-luna", "provider": "codex", "model": "gpt-5.6-luna",
                "task_family": "implementation", "node_id": "worker",
            }],
        },
    )
    return repo, base, mesh, continuity


def test_machine_check_failure_scores_writer_from_downstream_evidence(tmp_path):
    repo, _, mesh, continuity = _prepare_integrated_patch(tmp_path, content="VALUE = 2   \n", risk="R0")
    runtime = _runtime(repo, mesh, continuity, tmp_path)
    tick = runtime.run_once(maximum_nodes=1)
    result = tick.results[0]
    assert result["node_id"] == "check"
    assert result["success"] is False
    assert mesh.get_node("guard")["state"] == "READY"
    perf = mesh.performance_overrides("implementation", catalog_hash=runtime.router.catalog_hash if hasattr(runtime.router, "catalog_hash") else None)
    if not perf:
        perf = mesh.performance_overrides("implementation")
    assert perf["codex-luna"]["quality"] == pytest.approx(0.0)
    assert perf["codex-luna"]["reliability"] == pytest.approx(0.0)


def test_machine_check_success_promotes_writer_only_after_checks(tmp_path):
    repo, _, mesh, continuity = _prepare_integrated_patch(tmp_path, content="VALUE = 2\n", risk="R0")
    runtime = _runtime(repo, mesh, continuity, tmp_path)
    tick = runtime.run_once(maximum_nodes=1)
    result = tick.results[0]
    assert result["node_id"] == "check"
    assert result["success"] is True
    perf = mesh.performance_overrides("implementation")
    assert perf["codex-luna"]["quality"] == pytest.approx(1.0)
    assert perf["codex-luna"]["reliability"] == pytest.approx(1.0)


def test_actual_risk_escalation_auto_submits_full_r3_replan_and_blocks_guard(tmp_path, monkeypatch):
    repo, _, mesh, continuity = _prepare_integrated_patch(tmp_path, content="VALUE = 2\n", risk="R0")

    class ForcedRisk:
        risk = "R3"
        def to_dict(self):
            return {"risk": "R3", "reasons": ["forced test escalation"]}

    monkeypatch.setattr("ztad.mesh_runtime.classify_repository_change", lambda *args, **kwargs: ForcedRisk())
    runtime = _runtime(repo, mesh, continuity, tmp_path)
    tick = runtime.run_once(maximum_nodes=1)
    result = tick.results[0]
    assert result["success"] is False
    assert result["state"] == "QUARANTINED"
    assert result["risk_escalated"] is True
    assert result["replan"]["risk"] == "R3"
    assert result["replan"]["execution_mode"] == "FULL_MESH"
    assert mesh.get_node("guard")["state"] == "READY"
    assert mesh.claim_ready("guard-attempt", limit=20) != [mesh.get_node("guard")]
    child_id = result["replan"]["child_task_id"]
    child = continuity.get_task(child_id)
    assert child["risk"] == "R3"
    child_nodes = mesh.list_nodes(task_id=child_id)
    roles = {node["role"] for node in child_nodes}
    assert {"architecture_advisor", "plan_adjudicator", "check_runner", "supervisor", "release_advisor"} <= roles
    sol_cap = runtime.router.policy["maximum_reasoning_effort_by_registry"]["codex-sol"]
    assert sol_cap == "high"


def test_structured_controller_never_allows_p0_p1_to_silently_continue(tmp_path):
    repo, _ = init_git_repo(tmp_path / "repo")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    contract = valid_contract(risk="R0", components=["README.md"])
    task = continuity.submit_task(repository=str(repo), title="finding", contract=contract, risk="R0", task_id="parent", idempotency_key="parent")
    mesh = MeshStore(tmp_path / "mesh.db")
    mesh.submit_graph([MeshNodeSpec.create(
        node_id="guard", task_id=task["task_id"], title="guard", task_family="review", role="supervisor",
        risk="R0", write_access=False, scopes=("README.md",), prompt_path="unused.md", output_schema=str(SCHEMA),
        metadata={"mandatory_final_guard": True},
    )])
    runtime = _runtime(repo, mesh, continuity, tmp_path)
    node = mesh.get_node("guard")
    control = runtime._structured_control(node, {
        "result_type": "PROPOSED_FINDINGS", "requested_action": "VERIFY_FINDINGS",
        "findings": [{"finding_id": "F-001", "severity": "P1", "title": "blocking", "description": "must verify", "verification_status": "PROPOSED"}],
    })
    assert control["force_quarantine"] is True
    assert control["errors"]
    assert control["replan"]["reason"] == "BLOCKING_FINAL_GUARD_FINDINGS"
    replan = runtime._submit_replan(
        node=node, target_risk=control["replan"]["target_risk"], reason=control["replan"]["reason"],
        details=control["replan"]["details"], consume_repair_cycle=True,
    )
    assert replan is not None
    child = continuity.get_task(replan["child_task_id"])
    assert child["contract"]["budget"]["max_repair_cycles"] == contract["budget"]["max_repair_cycles"] - 1
    decisions = child["contract"]["governance"]["human_decisions"]
    assert decisions[-1]["reason"] == "BLOCKING_FINAL_GUARD_FINDINGS"


def test_runtime_source_has_no_premature_schema_valid_quality_one_learning():
    source = (ROOT / "toolkit/ztad/mesh_runtime.py").read_text(encoding="utf-8")
    assert "quality = 1.0 if result.success and not errors" not in source
    assert "latency=latency" not in source
    assert "cost=max(0.01, token_cost)" not in source


def test_all_cli_benchmark_persistence_uses_normalized_indices():
    source = (ROOT / "toolkit/ztad/cli.py").read_text(encoding="utf-8")
    assert 'latency=float(case["latency_seconds"])' not in source
    assert "100000.0" not in source[source.find('if command == "model-benchmark"'):source.find('if command == "provider-probe"')]
