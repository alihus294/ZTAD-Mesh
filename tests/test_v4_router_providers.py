from __future__ import annotations

import json

import pytest
from pathlib import Path

import ztad.providers as providers
from ztad.model_benchmark import BenchmarkCase, benchmark_suite_hash
from ztad.model_router import AdaptiveModelRouter, TaskProfile
from ztad.providers import CodexExecProvider, ProviderRunRequest, ProviderRegistry, _command_argv, _prepare_run_artifacts, parse_jsonl_metadata

ROOT = Path(__file__).resolve().parents[1]


def _provider_output_path(argv):
    if "--output-last-message" in argv:
        return Path(argv[argv.index("--output-last-message") + 1])
    command_line = argv[-1]
    marker = "--output-last-message "
    raw = command_line.split(marker, 1)[1].split(" --ephemeral", 1)[0].strip()
    return Path(raw[1:-1] if raw.startswith('"') and raw.endswith('"') else raw)


def test_windows_command_shim_is_wrapped_without_shell_interpolation(monkeypatch):
    monkeypatch.setattr(providers, "_PLATFORM_NAME", "nt")
    monkeypatch.setattr(
        "ztad.providers.shutil.which",
        lambda value: "C:\\Tools\\codex.CMD" if value == "codex" else None,
    )
    argv = _command_argv(["codex", "--version"])
    assert argv[1:3] == ["/d", "/s"]
    assert argv[3] == "/c"
    assert argv[4].startswith("C:\\Tools\\codex.CMD")
    assert "--version" in argv[4]
    path_argv = _command_argv(["codex", "--output-schema", r"C:\\Repo (test)\\schema.json"])
    assert "Repo (test)" in path_argv[4]
    with pytest.raises(ValueError, match="metacharacters"):
        _command_argv(["codex", "bad&value"])


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


def test_sol_reasoning_ceiling_overrides_profile_and_catalog_effort():
    router = AdaptiveModelRouter({
        "models": [{
            "registry_id": "codex-sol", "provider": "codex", "model": "gpt-5.6-sol",
            "tier": "frontier", "reasoning_efforts": ["high", "ultra"], "sandboxes": ["read-only"],
            "task_quality": {"review": 0.95}, "reliability": 0.95,
            "cost_index": 1.0, "latency_index": 1.0, "max_parallel": 1,
        }],
    })
    decision = router.route(TaskProfile("review", "supervisor", "R4", maximum_reasoning_effort="ultra"))
    assert decision.reasoning_effort == "high"


def test_router_quality_floor_allows_benchmarked_luna_for_r2_and_falls_back_safely():
    router = AdaptiveModelRouter.from_file(ROOT / "policies/model-catalog.yaml")
    profile = TaskProfile("implementation", "worker", "R2", complexity=3, preferred_registry_id="codex-luna")
    decision = router.route(profile)
    assert decision.candidate.registry_id == "codex-luna"
    fallback = router.route(profile, unavailable_registry_ids={"codex-luna"})
    assert fallback.candidate.registry_id == "codex-terra"


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
        output_path = _provider_output_path(argv)
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


def test_provider_rejects_symlink_artifact_root(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")
    with pytest.raises(ValueError, match="symlink"):
        _prepare_run_artifacts(link, "fixed")


def test_provider_artifacts_can_be_forced_outside_worktree(tmp_path, monkeypatch):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    artifact_dir = tmp_path / "controller-artifacts"
    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object","required":["ok"],"properties":{"ok":{"const":true}},"additionalProperties":false}', encoding="utf-8")
    observed = {}

    def fake_run(argv, **kwargs):
        output_path = _provider_output_path(argv)
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


def test_provider_default_artifacts_are_external_to_worktree(tmp_path, monkeypatch):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object","required":["ok"],"properties":{"ok":{"const":true}},"additionalProperties":false}', encoding="utf-8")
    observed = {}

    def fake_run(argv, **kwargs):
        output_path = _provider_output_path(argv)
        observed["output_path"] = output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text('{"ok":true}', encoding="utf-8")
        class Result:
            returncode = 0
            stdout = json.dumps({"thread_id": "session"}) + "\n"
            stderr = ""
        return Result()

    monkeypatch.setattr("ztad.providers.subprocess.run", fake_run)
    monkeypatch.setattr("ztad.providers.tempfile.gettempdir", lambda: str(tmp_path))
    result = CodexExecProvider(executable="codex").run(ProviderRunRequest(
        task_id="t", role="worker", registry_id="x", model="m", reasoning_effort="medium",
        sandbox="workspace-write", prompt="p", output_schema=schema, cwd=worktree, run_id="default-external",
    ))
    assert result.success
    assert observed["output_path"].is_relative_to(tmp_path / "ztad-provider-runs")
    assert not observed["output_path"].is_relative_to(worktree)
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
    ("cost_index", float("nan")),
    ("latency_index", float("inf")),
    ("reliability", True),
    ("cost_index", True),
    ("latency_index", True),
    ("task_quality", {"default": True}),
    ("max_parallel", 1000),
    ("max_parallel", "2"),
    ("enabled", "false"),
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


def test_benchmark_suite_hash_binds_schema_content_not_checkout_path(tmp_path):
    first_schema = tmp_path / "one" / "schema.json"
    second_schema = tmp_path / "two" / "schema.json"
    first_schema.parent.mkdir()
    second_schema.parent.mkdir()
    first_schema.write_text('{"type":"object"}', encoding="utf-8")
    second_schema.write_text('{"type":"object"}', encoding="utf-8")
    first = BenchmarkCase("case", "review", "planner", "R1", "prompt", first_schema, {})
    second = BenchmarkCase("case", "review", "planner", "R1", "prompt", second_schema, {})
    assert benchmark_suite_hash([first]) == benchmark_suite_hash([second])
