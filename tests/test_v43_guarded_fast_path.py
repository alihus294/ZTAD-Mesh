from __future__ import annotations

from pathlib import Path

import pytest

from conftest import valid_contract
from ztad.mesh_plan import build_mesh_plan
from ztad.model_benchmark import _score_output
from ztad.model_router import AdaptiveModelRouter, TaskProfile
from ztad.util import load_data

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "policies/model-catalog.yaml"


def _plan(risk: str):
    return build_mesh_plan(task_id=f"shape-{risk.lower()}", risk=risk, contract=valid_contract(risk=risk))


def _model_nodes(plan):
    return [node for node in plan.nodes if node.role not in {"repository_indexer", "patch_integrator", "check_runner"}]


@pytest.mark.parametrize("risk", ["R0", "R1"])
def test_low_risk_guarded_fast_path_is_exactly_two_model_calls(risk):
    plan = _plan(risk)
    payload = plan.to_dict()
    assert len(plan.nodes) == 5
    assert payload["execution_mode"] == "GUARDED_FAST_PATH"
    assert payload["model_call_count"] == 2
    assert payload["intended_model_usage"] == {"codex-luna": 1, "codex-sol": 1}
    roles = [node.role for node in plan.nodes]
    assert roles == ["repository_indexer", "worker", "patch_integrator", "check_runner", "supervisor"]
    assert not any(node.role in {"plan_adjudicator", "release_advisor", "architecture_advisor", "test_designer", "context_scout"} for node in plan.nodes)


def test_r2_is_bounded_to_seven_nodes_and_four_model_calls():
    plan = _plan("R2")
    payload = plan.to_dict()
    assert len(plan.nodes) == 7
    assert payload["execution_mode"] == "BOUNDED_MESH"
    assert payload["model_call_count"] == 4
    assert payload["intended_model_usage"] == {"codex-luna": 1, "codex-terra": 3}
    assert sum(node.role == "focused_reviewer" for node in plan.nodes) == 2
    assert not any(node.role in {"plan_adjudicator", "release_advisor", "architecture_advisor"} for node in plan.nodes)


@pytest.mark.parametrize("risk", ["R3", "R4"])
def test_high_risk_retains_full_mesh(risk):
    plan = _plan(risk)
    payload = plan.to_dict()
    roles = {node.role for node in plan.nodes}
    assert payload["execution_mode"] == "FULL_MESH"
    assert {"repository_indexer", "architecture_advisor", "plan_adjudicator", "test_designer", "worker", "patch_integrator", "check_runner", "supervisor", "release_advisor"} <= roles
    assert payload["model_call_count"] > 4


def test_luna_is_primary_r2_worker_and_terra_is_fail_safe_fallback():
    router = AdaptiveModelRouter.from_file(CATALOG)
    profile = TaskProfile(
        task_family="implementation", role="worker", risk="R2",
        complexity=2, preferred_registry_id="codex-luna", maximum_reasoning_effort="high",
    )
    first = router.route(profile)
    assert first.candidate.registry_id == "codex-luna"
    fallback = router.route(profile, unavailable_registry_ids={"codex-luna"})
    assert fallback.candidate.registry_id == "codex-terra"


@pytest.mark.parametrize("risk,complexity,ambiguity,failures", [
    ("R0", 1, 0, 0), ("R2", 5, 3, 3), ("R3", 5, 5, 3), ("R4", 5, 5, 9),
])
def test_sol_can_never_exceed_high_reasoning(risk, complexity, ambiguity, failures):
    router = AdaptiveModelRouter.from_file(CATALOG)
    decision = router.route(TaskProfile(
        task_family="review", role="supervisor", risk=risk,
        complexity=complexity, ambiguity=ambiguity, prior_failures=failures,
        preferred_registry_id="codex-sol",
    ))
    assert decision.candidate.registry_id == "codex-sol"
    assert decision.reasoning_effort in {"none", "low", "medium", "high"}
    assert decision.reasoning_effort != "xhigh"
    assert decision.reasoning_effort != "max"
    assert decision.reasoning_effort != "ultra"


def test_catalog_defense_in_depth_removes_sol_efforts_above_high():
    catalog = load_data(CATALOG)
    sol = next(item for item in catalog["models"] if item["registry_id"] == "codex-sol")
    assert set(sol["reasoning_efforts"]) <= {"none", "low", "medium", "high"}
    assert catalog["routing"]["maximum_reasoning_effort_by_registry"]["codex-sol"] == "high"


def test_benchmark_abstention_cannot_score_as_capability_success():
    output = {"result_type": "INSUFFICIENT_CONTEXT", "requested_action": "REQUEST_CONTEXT_EXPANSION", "findings": []}
    scored = _score_output(output, {
        "result_type_in": ["PLAN_READY", "INSUFFICIENT_CONTEXT"],
        "requested_action_in": ["VALIDATE_PLAN", "REQUEST_CONTEXT_EXPANSION"],
        "max_findings": 0,
    })
    assert scored["score"] <= 0.25
