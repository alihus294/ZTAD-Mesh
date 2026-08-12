from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import init_git_repo, valid_contract
from ztad.cli import (
    _benchmark_cache_metadata,
    _provider_capability_fingerprint,
    build_parser,
    execute,
)
from ztad.mesh_plan import build_mesh_plan
from ztad.mesh_runtime import MeshRuntime
from ztad.mesh_store import MeshNodeSpec, MeshStore
from ztad.model_router import AdaptiveModelRouter
from ztad.orchestrator import ContinuityStore
from ztad.providers import MockProvider, ProviderRegistry

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/agent-result.schema.json"
CATALOG = ROOT / "policies/model-catalog.yaml"


def test_performance_override_is_shadowed_until_two_observations(tmp_path):
    store = MeshStore(tmp_path / "mesh.db")
    kwargs = dict(
        registry_id="codex-luna", task_family="implementation", success=True,
        quality=1.0, latency=0.35, cost=0.25, catalog_hash="sha256:catalog",
        benchmark_suite_hash="sha256:context",
    )
    store.record_model_performance(**kwargs)
    assert store.performance_overrides(
        "implementation", catalog_hash="sha256:catalog", benchmark_suite_hash="sha256:context", minimum_runs=2
    ) == {}
    store.record_model_performance(**kwargs)
    current = store.performance_overrides(
        "implementation", catalog_hash="sha256:catalog", benchmark_suite_hash="sha256:context", minimum_runs=2
    )
    assert current["codex-luna"]["runs"] == 2.0


def test_provider_fingerprint_and_benchmark_cache_are_deterministic_and_provider_bound():
    one = ProviderRegistry([MockProvider(name="mock-a")])
    two = ProviderRegistry([MockProvider(name="mock-b")])
    assert _provider_capability_fingerprint(one) == _provider_capability_fingerprint(one)
    assert _provider_capability_fingerprint(one) != _provider_capability_fingerprint(two)
    cases = []
    first = _benchmark_cache_metadata(cases, one)
    second = _benchmark_cache_metadata(cases, two)
    assert first["benchmark_suite_hash"] == second["benchmark_suite_hash"]
    assert first["provider_executable_fingerprint"] != second["provider_executable_fingerprint"]
    assert first["benchmark_cache_hash"] != second["benchmark_cache_hash"]


def test_fast_path_rejects_contract_that_forbids_all_implementation_runs():
    contract = valid_contract(risk="R0")
    contract["budget"]["max_implementation_runs"] = 0
    with pytest.raises(ValueError, match="at least one implementation run"):
        build_mesh_plan(task_id="budget-r0", risk="R0", contract=contract)


def test_default_writer_cap_does_not_exceed_mesh_policy():
    import inspect
    import yaml
    from ztad import autopilot, mesh_plan

    policy = yaml.safe_load((ROOT / "policies/mesh-policy.yaml").read_text())
    cap = int(policy["parallelism"]["write_cap"])
    assert inspect.signature(mesh_plan.build_mesh_plan).parameters["maximum_parallel_writers"].default <= cap
    assert inspect.signature(autopilot.prepare_autopilot).parameters["maximum_parallel_writers"].default <= cap
    parser = build_parser()
    args = parser.parse_args(["mesh-plan", "--task-id", "x", "--risk", "R0", "--contract", "x.json"])
    assert args.max_parallel_writers <= cap


def test_continuity_phase_tracks_mesh_without_auto_granting_merge_ready(tmp_path):
    repo, _ = init_git_repo(tmp_path / "repo")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    contract = valid_contract(risk="R0", components=["README.md"])
    continuity.submit_task(repository=str(repo), title="phase", contract=contract, risk="R0", task_id="task", idempotency_key="task")
    mesh = MeshStore(tmp_path / "mesh.db")
    runtime = MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter.from_file(CATALOG), providers=ProviderRegistry([]),
        worker_id="phase-test", output_root=tmp_path / "runs",
    )
    base = dict(task_id="task", risk="R0", metadata={})
    sequence = [
        ("index", "repository_indexer", "PLANNING"),
        ("worker", "worker", "WORKER_IMPLEMENTING"),
        ("check", "check_runner", "MACHINE_CHECKS"),
        ("guard", "supervisor", "SUPERVISOR_REVIEW"),
    ]
    for node_id, role, expected in sequence:
        node = {**base, "node_id": node_id, "role": role}
        assert runtime._sync_continuity_phase(node) == expected
        assert continuity.get_task("task")["state"] == expected
    assert continuity.get_task("task")["state"] != "MERGE_READY"


def test_mesh_plan_dry_run_shows_exact_low_risk_catalog_routes_without_mutation(tmp_path):
    repo, _ = init_git_repo(tmp_path / "repo")
    contract = valid_contract(risk="R0", components=["README.md"])
    contract_path = repo / "contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    before = sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*"))
    args = build_parser().parse_args([
        "mesh-plan", "--repo", str(repo), "--task-id", "DRY-R0", "--risk", "R0",
        "--contract", str(contract_path), "--catalog", str(CATALOG), "--dry-run",
    ])
    result, code = execute(args)
    after = sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*"))
    assert code == 0
    assert result["repository_mutated"] is False
    assert result["route_preview"]["model_call_count"] == 2
    selected = [(item["role"], item["selected"]["registry_id"], item["selected"]["reasoning_effort"]) for item in result["route_preview"]["nodes"]]
    assert selected[0][0:2] == ("worker", "codex-luna")
    assert selected[1][0:2] == ("supervisor", "codex-sol")
    assert selected[1][2] in {"medium", "high"}
    assert before == after


def test_model_catalog_requires_two_observations_before_override_and_sol_cap_is_high():
    router = AdaptiveModelRouter.from_file(CATALOG)
    assert int(router.policy["minimum_observations_for_override"]) == 2
    assert router.policy["maximum_reasoning_effort_by_registry"]["codex-sol"] == "high"
