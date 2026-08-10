from __future__ import annotations

import json

import pytest
from pathlib import Path

from ztad.model_router import AdaptiveModelRouter, TaskProfile
from ztad.providers import CodexExecProvider, ProviderRunRequest, ProviderRegistry, parse_jsonl_metadata

ROOT = Path(__file__).resolve().parents[1]


def test_router_uses_economy_for_low_risk_navigation():
    router = AdaptiveModelRouter.from_file(ROOT / "policies/model-catalog.yaml")
    decision = router.route(TaskProfile("repository_navigation", "worker", "R1", complexity=1))
    assert decision.candidate.registry_id == "codex-luna"
    assert decision.sandbox == "workspace-write"


def test_router_requires_frontier_for_supervisor_and_sensitive_risk():
    router = AdaptiveModelRouter.from_file(ROOT / "policies/model-catalog.yaml")
    for profile in (
        TaskProfile("review", "supervisor", "R2", complexity=2),
        TaskProfile("security", "security_reviewer", "R3", complexity=4),
        TaskProfile("database", "worker", "R4", complexity=4),
    ):
        decision = router.route(profile)
        assert decision.candidate.tier == "frontier"
        assert decision.candidate.model == "gpt-5.6-sol"


def test_router_quality_floor_prevents_cheap_model_for_normal_feature():
    router = AdaptiveModelRouter.from_file(ROOT / "policies/model-catalog.yaml")
    decision = router.route(TaskProfile("implementation", "worker", "R2", complexity=3))
    assert decision.candidate.registry_id in {"codex-terra", "codex-sol"}
    assert decision.candidate.registry_id != "codex-luna"


def test_router_uses_provider_diversity_when_candidates_are_equivalent():
    catalog = {
        "routing": {"minimum_quality_by_risk": {"R2": 0.8}, "frontier_role_quality_floor": 0.9},
        "models": [
            {"registry_id": "a", "provider": "p1", "model": "m1", "tier": "frontier", "reasoning_efforts": ["high"], "sandboxes": ["read-only"], "task_quality": {"review": 0.95}, "reliability": 0.95, "cost_index": 0.5, "latency_index": 0.5},
            {"registry_id": "b", "provider": "p2", "model": "m2", "tier": "frontier", "reasoning_efforts": ["high"], "sandboxes": ["read-only"], "task_quality": {"review": 0.95}, "reliability": 0.95, "cost_index": 0.5, "latency_index": 0.5},
        ],
    }
    router = AdaptiveModelRouter(catalog)
    decision = router.route(TaskProfile("review", "supervisor", "R2", required_provider_diversity=True), previous_provider="p1")
    assert decision.candidate.provider == "p2"


def test_maximum_useful_parallelism_is_bounded():
    router = AdaptiveModelRouter.from_file(ROOT / "policies/model-catalog.yaml")
    assert router.maximum_useful_parallelism(independent_units=100) == 8
    assert router.maximum_useful_parallelism(independent_units=3) == 3
    assert router.maximum_useful_parallelism(independent_units=0) == 0


def test_jsonl_parser_extracts_session_and_usage():
    text = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "thread-1"}),
        json.dumps({"type": "usage", "usage": {"input_tokens": 100, "output_tokens": 20}}),
    ])
    assert parse_jsonl_metadata(text) == {
        "session_id": "thread-1", "input_tokens": 100, "output_tokens": 20, "invalid_jsonl_lines": 0,
    }


def test_codex_provider_locally_rejects_schema_invalid_output(tmp_path, monkeypatch):
    schema = tmp_path / "schema.json"
    schema.write_text(json.dumps({"type": "object", "required": ["ok"], "properties": {"ok": {"const": True}}, "additionalProperties": False}), encoding="utf-8")

    def fake_run(argv, **kwargs):
        output_path = Path(argv[argv.index("--output-last-message") + 1])
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps({"ok": False}), encoding="utf-8")
        class Result:
            returncode = 0
            stdout = json.dumps({"thread_id": "s-1"}) + "\n"
            stderr = ""
        return Result()

    monkeypatch.setattr("ztad.providers.subprocess.run", fake_run)
    provider = CodexExecProvider(executable="codex", output_dir=tmp_path / "runs")
    result = provider.run(ProviderRunRequest(
        task_id="t", role="supervisor", registry_id="x", model="m", reasoning_effort="high",
        sandbox="read-only", prompt="p", output_schema=schema, cwd=tmp_path,
    ))
    assert not result.success
    assert any(item.startswith("schema:") for item in result.errors)
    assert result.session_id == "s-1"


def test_provider_registry_rejects_duplicate_names():
    class P:
        name = "same"
        def probe(self): return {}
        def run(self, request): raise NotImplementedError
    try:
        ProviderRegistry([P(), P()])
    except ValueError as exc:
        assert "Duplicate" in str(exc)
    else:
        raise AssertionError("duplicate providers were accepted")


def test_provider_rejects_replayed_run_artifact(tmp_path, monkeypatch):
    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object"}', encoding="utf-8")
    output_dir = tmp_path / "runs"
    output_dir.mkdir()
    (output_dir / "fixed.result.json").write_text('{"stale":true}', encoding="utf-8")

    def must_not_run(*args, **kwargs):
        raise AssertionError("provider process must not run when a stale artifact exists")

    monkeypatch.setattr("ztad.providers.subprocess.run", must_not_run)
    provider = CodexExecProvider(executable="codex", output_dir=output_dir)
    with pytest.raises(FileExistsError, match="already exists"):
        provider.run(ProviderRunRequest(
            task_id="t", role="supervisor", registry_id="x", model="m", reasoning_effort="high",
            sandbox="read-only", prompt="p", output_schema=schema, cwd=tmp_path, run_id="fixed",
        ))


def test_provider_artifacts_can_be_forced_outside_worktree(tmp_path, monkeypatch):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    artifact_dir = tmp_path / "controller-artifacts"
    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object","required":["ok"],"properties":{"ok":{"const":true}},"additionalProperties":false}', encoding="utf-8")
    observed = {}

    def fake_run(argv, **kwargs):
        output_path = Path(argv[argv.index("--output-last-message") + 1])
        observed["output_path"] = output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text('{"ok":true}', encoding="utf-8")
        class Result:
            returncode = 0
            stdout = json.dumps({"thread_id": "session"}) + "\n"
            stderr = ""
        return Result()

    monkeypatch.setattr("ztad.providers.subprocess.run", fake_run)
    result = CodexExecProvider(executable="codex").run(ProviderRunRequest(
        task_id="t", role="worker", registry_id="x", model="m", reasoning_effort="medium",
        sandbox="workspace-write", prompt="p", output_schema=schema, cwd=worktree,
        artifact_dir=artifact_dir,
    ))
    assert result.success
    assert observed["output_path"].is_relative_to(artifact_dir.resolve())
    assert not list(worktree.rglob("*.result.json"))
    assert not (worktree / ".delivery").exists()


def test_preferred_provider_is_a_preference_not_a_single_point_of_failure():
    catalog = {
        "routing": {"minimum_quality_by_risk": {"R2": 0.8}, "frontier_role_quality_floor": 0.9},
        "models": [
            {"registry_id": "preferred", "provider": "p1", "model": "m1", "tier": "frontier", "reasoning_efforts": ["high"], "sandboxes": ["read-only"], "task_quality": {"review": 0.95}, "reliability": 0.95, "cost_index": 0.2, "latency_index": 0.2},
            {"registry_id": "fallback", "provider": "p2", "model": "m2", "tier": "frontier", "reasoning_efforts": ["high"], "sandboxes": ["read-only"], "task_quality": {"review": 0.95}, "reliability": 0.95, "cost_index": 0.3, "latency_index": 0.3},
        ],
    }
    router = AdaptiveModelRouter(catalog)
    profile = TaskProfile("review", "supervisor", "R2", preferred_provider="p1")
    assert router.route(profile).candidate.provider == "p1"
    assert router.route(profile, unavailable_registry_ids={"preferred"}).candidate.provider == "p2"


@pytest.mark.parametrize("field,value", [
    ("tier", "magic"),
    ("reasoning_efforts", ["infinite"]),
    ("sandboxes", ["danger-full-access"]),
    ("reliability", 1.5),
    ("cost_index", 0),
    ("max_parallel", 1000),
])
def test_router_rejects_unsafe_or_nonsensical_catalog_values(field, value):
    item = {
        "registry_id": "m", "provider": "p", "model": "model", "tier": "frontier",
        "reasoning_efforts": ["high"], "sandboxes": ["read-only"],
        "task_quality": {"default": 0.9}, "reliability": 0.9,
        "cost_index": 1.0, "latency_index": 1.0, "max_parallel": 1,
    }
    item[field] = value
    with pytest.raises(ValueError):
        AdaptiveModelRouter({"models": [item]})


def test_benchmark_artifacts_default_to_temporary_directory(tmp_path):
    from ztad.model_benchmark import BenchmarkCase, ModelBenchmarkRunner
    from ztad.providers import ProviderRunResult

    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object"}', encoding="utf-8")
    observed = {}

    class BenchmarkProvider:
        name = "bench"

        def probe(self):
            return {"available": True}

        def run(self, request):
            observed["artifact_dir"] = request.artifact_dir
            assert request.artifact_dir is not None
            assert not request.artifact_dir.is_relative_to(tmp_path.resolve())
            return ProviderRunResult(
                run_id="run", provider="bench", task_id=request.task_id, role=request.role,
                registry_id=request.registry_id, model=request.model, session_id="session",
                started_at="2026-08-10T00:00:00Z", completed_at="2026-08-10T00:00:01Z",
                exit_code=0, success=True, output={}, output_hash=None,
                stdout_hash="sha256:" + "a" * 64, stderr_hash="sha256:" + "b" * 64,
                input_tokens=1, output_tokens=1, errors=(), argv=("bench",),
            )

    router = AdaptiveModelRouter({
        "models": [{
            "registry_id": "bench-model", "provider": "bench", "model": "m",
            "tier": "balanced", "reasoning_efforts": ["medium"],
            "sandboxes": ["read-only"], "task_quality": {"review": 0.9},
            "reliability": 0.9, "cost_index": 1.0, "latency_index": 1.0,
            "max_parallel": 1,
        }]
    })
    case = BenchmarkCase(
        case_id="c", task_family="review", role="planner", risk="R1",
        prompt="Return an object", output_schema=schema, assertions={},
    )
    result = ModelBenchmarkRunner(router, ProviderRegistry([BenchmarkProvider()])).run([case], cwd=tmp_path)
    assert result["results"][0]["case_count"] == 1
    assert not (tmp_path / ".delivery").exists()
    assert observed["artifact_dir"] is not None
    assert not observed["artifact_dir"].exists(), "temporary benchmark artifacts must be cleaned"
