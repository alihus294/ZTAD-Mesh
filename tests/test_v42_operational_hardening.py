from __future__ import annotations

import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ztad.github_adapter import GitHubCliAdapter
from ztad.mesh_runtime import MeshRuntime
from ztad.mesh_store import MeshNodeSpec, MeshStore
from ztad.model_router import AdaptiveModelRouter
from ztad.orchestrator import ContinuityStore
from ztad.platform import audit_github
from ztad.providers import ProviderRegistry, ProviderRunResult
from ztad.util import canonical_json, sha256_bytes, utc_now

from conftest import init_git_repo, valid_contract

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/agent-result.schema.json"


def _output(request, *, result_type="PLAN_READY", requested_action="VALIDATE_PLAN", marker=None):
    envelope = ast.literal_eval(request.prompt.split("ZTAD_IMMUTABLE_ENVELOPE\n", 1)[1].splitlines()[0])
    role_map = {
        "worker": "implementer", "supervisor": "independent_reviewer",
        "context_scout": "planner", "architecture_advisor": "architecture_advisor",
        "plan_adjudicator": "architecture_advisor", "release_advisor": "release_advisor",
    }
    claims = []
    if marker:
        claims.append({
            "claim": marker,
            "claim_type": "PROPOSAL",
            "source_sha": envelope["head_sha"],
            "verification_status": "UNVERIFIED",
            "evidence_ref": None,
        })
    return {
        "schema_version": 1,
        "task_id": request.task_id,
        "agent_role": role_map.get(request.role, "planner"),
        "model_registry_id": request.registry_id,
        "prompt_version": envelope["prompt_version"],
        "base_sha": envelope["base_sha"],
        "head_sha": envelope["head_sha"],
        "context_id": envelope["context_id"],
        "result_type": result_type,
        "claims": claims,
        "findings": [],
        "files_read": [],
        "files_not_read": [],
        "uncertainties": [],
        "tested_scope": [],
        "untested_scope": [],
        "known_unknowns": [],
        "requested_action": requested_action,
        "risk_escalation": None,
        "patch_path": None,
    }


def _result(provider, request, *, success=True, output=None, errors=()):
    output = output if output is not None else _output(request)
    return ProviderRunResult(
        run_id=f"{provider}-run-{request.role}", provider=provider, task_id=request.task_id,
        role=request.role, registry_id=request.registry_id, model=request.model,
        session_id=f"{provider}-session-{request.role}", started_at=utc_now(), completed_at=utc_now(),
        exit_code=0 if success else 1, success=success, output=output if success else None,
        output_hash=sha256_bytes(canonical_json(output)) if success else None,
        stdout_hash=sha256_bytes(b""), stderr_hash=sha256_bytes(b""),
        input_tokens=10, output_tokens=10, errors=tuple(errors), argv=(provider,),
    )


def _catalog(*providers):
    models = []
    for index, provider in enumerate(providers):
        models.append({
            "registry_id": f"model-{provider}", "provider": provider, "model": f"model-{provider}",
            "tier": "frontier", "reasoning_efforts": ["high"],
            "sandboxes": ["read-only", "workspace-write"],
            "task_quality": {"repository_navigation": 0.98, "architecture": 0.98, "review": 0.98, "default": 0.98},
            "reliability": 0.99 - index * 0.01, "cost_index": 0.2 + index * 0.1,
            "latency_index": 0.2 + index * 0.1, "max_parallel": 4,
        })
    return {"routing": {"minimum_quality_by_risk": {"R2": 0.8}, "frontier_role_quality_floor": 0.9}, "models": models}


class CapturingProvider:
    name = "capture"

    def __init__(self):
        self.prompts = []

    def probe(self):
        return {"available": True}

    def run(self, request):
        self.prompts.append((request.role, request.prompt))
        marker = "SCOUT_DISCOVERY_EVENT_CONSUMER" if request.role == "context_scout" else None
        return _result(self.name, request, output=_output(request, marker=marker))


def test_dependency_model_results_are_hash_validated_and_forwarded(tmp_path):
    repo, base = init_git_repo(tmp_path / "repo")
    prompt = repo / "prompt.md"
    prompt.write_text("work", encoding="utf-8")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(
        repository=str(repo), title="context", contract=valid_contract(risk="R2"),
        risk="R2", idempotency_key="context",
    )
    mesh = MeshStore(tmp_path / "mesh.db")
    context_id = "sha256:" + "c" * 64
    mesh.submit_graph([
        MeshNodeSpec.create(
            node_id="scout", task_id=task["task_id"], title="scout",
            task_family="repository_navigation", role="context_scout", risk="R2",
            write_access=False, scopes=(), prompt_path="prompt.md", output_schema=str(SCHEMA),
            metadata={"base_sha": base, "head_sha": base, "context_id": context_id},
            idempotency_key="scout",
        ),
        MeshNodeSpec.create(
            node_id="planner", task_id=task["task_id"], title="planner",
            task_family="architecture", role="architecture_advisor", risk="R2",
            write_access=False, scopes=(), prompt_path="prompt.md", output_schema=str(SCHEMA),
            metadata={"base_sha": base, "head_sha": base, "context_id": context_id},
            dependencies=("scout",), idempotency_key="planner",
        ),
    ])
    provider = CapturingProvider()
    runtime = MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(_catalog(provider.name)), providers=ProviderRegistry([provider]),
        worker_id="mesh", output_root=tmp_path / "runs",
    )
    assert runtime.run_once().succeeded == 1
    assert runtime.run_once().succeeded == 1
    planner_prompt = next(text for role, text in provider.prompts if role == "architecture_advisor")
    assert "ZTAD_DEPENDENCY_RESULTS" in planner_prompt
    assert "SCOUT_DISCOVERY_EVENT_CONSUMER" in planner_prompt
    artifacts = mesh.list_artifacts(node_id="scout", artifact_type="MODEL_RESULT")
    assert len(artifacts) == 1


class FailingProvider:
    name = "first"
    def probe(self): return {"available": True}
    def run(self, request): return _result(self.name, request, success=False, errors=("provider_failed",))


class SucceedingProvider:
    name = "second"
    def __init__(self): self.calls = 0
    def probe(self): return {"available": True}
    def run(self, request):
        self.calls += 1
        return _result(self.name, request, output=_output(request, result_type="NO_BLOCKING_FINDINGS_IN_REVIEWED_SCOPE", requested_action="CONTINUE_POLICY_EVALUATION"))


def test_runtime_falls_back_to_next_quality_qualified_provider(tmp_path):
    repo, base = init_git_repo(tmp_path / "repo")
    (repo / "prompt.md").write_text("review", encoding="utf-8")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(repository=str(repo), title="review", contract=valid_contract(risk="R2"), risk="R2", idempotency_key="r")
    mesh = MeshStore(tmp_path / "mesh.db")
    context_id = "sha256:" + "d" * 64
    mesh.submit_graph([MeshNodeSpec.create(
        node_id="review", task_id=task["task_id"], title="review", task_family="review",
        role="supervisor", risk="R2", write_access=False, scopes=(), prompt_path="prompt.md",
        output_schema=str(SCHEMA), metadata={"base_sha": base, "head_sha": base, "context_id": context_id},
        idempotency_key="review",
    )])
    second = SucceedingProvider()
    runtime = MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(_catalog("first", "second")),
        providers=ProviderRegistry([FailingProvider(), second]), worker_id="mesh", output_root=tmp_path / "runs",
    )
    result = runtime.run_once().to_dict()
    assert result["succeeded"] == 1, result
    attempts = result["results"][0]["route_attempts"]
    assert [item["run"]["provider"] for item in attempts] == ["first", "second"]
    assert second.calls == 1


def test_github_pr_creation_uses_documented_create_then_json_view(tmp_path):
    body = tmp_path / "body.md"
    body.write_text("body", encoding="utf-8")
    calls = []

    def executor(argv, **kwargs):
        calls.append(argv)
        if argv[:3] == ["gh", "pr", "create"]:
            return SimpleNamespace(returncode=0, stdout="https://github.com/owner/repo/pull/7\n", stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"number": 7, "url": "https://github.com/owner/repo/pull/7", "headRefOid": "a" * 40, "baseRefName": "main", "state": "OPEN"}),
            stderr="",
        )

    adapter = GitHubCliAdapter(repo_slug="owner/repo", allow_write=True, executor=executor)
    result = adapter.create_pull_request(head="feature/safe", base="main", title="Feature", body_file=str(body))
    assert result.success
    assert result.payload["number"] == 7
    assert "--json" not in calls[0]
    assert calls[1][:3] == ["gh", "pr", "view"]
    with pytest.raises(ValueError):
        adapter.create_pull_request(head="-danger", base="main", title="x", body_file=str(body))
    with pytest.raises(ValueError):
        adapter.create_pull_request(head="feature", base="main", title="x", body_file=str(tmp_path / "missing.md"))


def test_github_audit_is_conservative_and_reads_all_required_controls(monkeypatch):
    monkeypatch.setattr("ztad.platform.shutil.which", lambda name: "/usr/bin/gh")
    calls = []

    def fake(endpoint):
        calls.append(endpoint)
        if endpoint.endswith("/branches/main/protection"):
            return ({
                "required_status_checks": {"checks": [{"context": "ci"}]},
                "required_pull_request_reviews": {"dismiss_stale_reviews": True, "require_last_push_approval": True},
            }, None)
        if endpoint.endswith("/rulesets"):
            return ([{"id": 1}], None)
        if endpoint.endswith("/rulesets/1"):
            return ({"rules": [{"type": "merge_queue"}]}, None)
        if endpoint.endswith("/environments"):
            return ({"environments": [{"name": "production"}]}, None)
        if endpoint.endswith("/environments/production"):
            return ({"protection_rules": [{"type": "required_reviewers"}]}, None)
        if endpoint.endswith("/actions/permissions"):
            return ({"enabled": True, "allowed_actions": "selected"}, None)
        if endpoint.endswith("/actions/oidc/customization/sub"):
            return ({"use_default": False, "include_claim_keys": ["repo", "context"]}, None)
        raise AssertionError(endpoint)

    monkeypatch.setattr("ztad.platform._gh_json", fake)
    report = audit_github("owner/repo", "main")
    assert report["controls"]["merge_queue"]["status"] == "VERIFIED_ACTIVE"
    assert report["controls"]["production_environment"]["status"] == "VERIFIED_ACTIVE"
    assert report["controls"]["required_checks"]["status"] == "VERIFIED_ACTIVE"
    assert report["controls"]["oidc"]["status"] == "CONFIGURED_NOT_VERIFIED"
    assert len(calls) == 7


def test_github_audit_does_not_turn_api_errors_into_absence(monkeypatch):
    monkeypatch.setattr("ztad.platform.shutil.which", lambda name: "/usr/bin/gh")
    monkeypatch.setattr("ztad.platform._gh_json", lambda endpoint: (None, "forbidden"))
    report = audit_github("owner/repo")
    assert report["controls"]
    assert all(item["status"] == "UNAVAILABLE_OR_UNAUTHORIZED" for item in report["controls"].values())
    with pytest.raises(ValueError):
        audit_github("owner/repo", "../main")

class ExplodingProvider:
    name = "first"
    def probe(self): return {"available": True}
    def run(self, request): raise RuntimeError("adapter crashed")


def test_runtime_contains_provider_adapter_exception_and_still_falls_back(tmp_path):
    repo, base = init_git_repo(tmp_path / "repo")
    (repo / "prompt.md").write_text("review", encoding="utf-8")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(repository=str(repo), title="review", contract=valid_contract(risk="R2"), risk="R2", idempotency_key="r2")
    mesh = MeshStore(tmp_path / "mesh.db")
    context_id = "sha256:" + "e" * 64
    mesh.submit_graph([MeshNodeSpec.create(
        node_id="review-exception", task_id=task["task_id"], title="review", task_family="review",
        role="supervisor", risk="R2", write_access=False, scopes=(), prompt_path="prompt.md",
        output_schema=str(SCHEMA), metadata={"base_sha": base, "head_sha": base, "context_id": context_id},
        idempotency_key="review-exception",
    )])
    second = SucceedingProvider()
    runtime = MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(_catalog("first", "second")),
        providers=ProviderRegistry([ExplodingProvider(), second]), worker_id="mesh", output_root=tmp_path / "runs",
    )
    result = runtime.run_once().to_dict()
    assert result["succeeded"] == 1, result
    first = result["results"][0]["route_attempts"][0]
    assert any("provider_adapter_exception" in error for error in first["validation_errors"])


def test_mesh_node_and_provider_run_identifiers_cannot_escape_managed_paths(tmp_path):
    from ztad.providers import MockProvider, ProviderRunRequest
    with pytest.raises(ValueError, match="path-free"):
        MeshNodeSpec.create(
            node_id="../escape", task_id="task", title="x", task_family="review", role="supervisor",
            risk="R2", write_access=False, scopes=(), prompt_path="p", output_schema="s",
        )
    request = ProviderRunRequest(
        task_id="task", role="supervisor", registry_id="m", model="m", reasoning_effort="high",
        sandbox="read-only", prompt="x", output_schema=SCHEMA, cwd=tmp_path, run_id="../escape",
    )
    # Mock does not create paths; real file-producing adapters must reject the ID.
    from ztad.providers import CodexExecProvider
    provider = CodexExecProvider(executable="missing", output_dir=tmp_path)
    with pytest.raises(ValueError, match="path-free"):
        provider.run(request)

def test_machine_checks_and_review_share_one_deterministic_candidate_sha(tmp_path):
    from ztad.repository import GitRepository
    from ztad.worktrees import WorktreeManager
    from ztad.util import sha256_file

    repo, base = init_git_repo(tmp_path / "repo")
    # Reviewed local check configuration. It is intentionally non-mutating.
    config = repo / ".delivery/ztad/config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({
        "schema_version": 1, "configured": True, "environment_allowlist": [],
        "checks": [{
            "id": "diff-check", "argv": ["git", "diff", "--check", "HEAD^", "HEAD"],
            "cwd": ".", "timeout_seconds": 60, "evidence_type": "LOCAL_DIFF_CHECK", "fail_fast": True,
        }],
    }), encoding="utf-8")
    # Create a patch artifact beneath the runtime-managed output root.
    output_root = tmp_path / "runs"
    output_root.mkdir()
    manager = WorktreeManager(GitRepository(repo))
    worktree = manager.create("patch-source", base)
    try:
        (worktree / "feature.py").write_text("value = 1\n", encoding="utf-8")
        patch_path = output_root / "writer.patch"
        patch_info = manager.patch(worktree, base, patch_path)
        assert patch_info["has_changes"]
    finally:
        manager.remove(worktree)

    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(
        repository=str(repo), title="checked", contract=valid_contract(risk="R2", components=["feature.py"]),
        risk="R2", idempotency_key="checked",
    )
    mesh = MeshStore(tmp_path / "mesh.db")
    context_id = "sha256:" + "f" * 64
    mesh.submit_graph([
        MeshNodeSpec.create(
            node_id="writer-artifact", task_id=task["task_id"], title="writer", task_family="implementation",
            role="worker", risk="R2", write_access=True, scopes=("feature.py",), prompt_path="prompt.md",
            output_schema=str(SCHEMA), metadata={"base_sha": base, "head_sha": base, "context_id": context_id},
            idempotency_key="writer-artifact",
        ),
        MeshNodeSpec.create(
            node_id="machine-checks", task_id=task["task_id"], title="checks", task_family="verification",
            role="check_runner", risk="R2", write_access=False, scopes=("feature.py",), prompt_path="prompt.md",
            output_schema=str(SCHEMA), dependencies=("writer-artifact",),
            metadata={
                "base_sha": base, "head_sha": base, "context_id": context_id,
                "check_config": ".delivery/ztad/config.json",
                "command_policy": str(ROOT / "policies/command-policy.yaml"),
            }, idempotency_key="machine-checks",
        ),
        MeshNodeSpec.create(
            node_id="review-checked", task_id=task["task_id"], title="review", task_family="review",
            role="supervisor", risk="R2", write_access=False, scopes=("feature.py",), prompt_path="prompt.md",
            output_schema=str(SCHEMA), dependencies=("machine-checks",),
            metadata={
                "base_sha": base, "head_sha": base, "context_id": context_id,
                "consume_dependency_patches": True,
            }, idempotency_key="review-checked",
        ),
    ])
    # Seed the already-completed implementation artifact.
    claimed = mesh.claim_ready("seed", limit=1)
    assert claimed[0]["node_id"] == "writer-artifact"
    mesh.register_artifact(
        node_id="writer-artifact", artifact_type="PATCH", path=str(patch_path),
        sha256=sha256_file(patch_path), metadata={"base_sha": base, "changed_paths": ["feature.py"]},
    )
    mesh.finish_node("writer-artifact", owner="seed", success=True, run_id="seed-run", registry_id="seed", provider="local")
    (repo / "prompt.md").write_text("review", encoding="utf-8")

    provider = CapturingProvider()
    runtime = MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter(_catalog(provider.name)), providers=ProviderRegistry([provider]),
        worker_id="mesh", output_root=output_root,
    )
    check_tick = runtime.run_once().to_dict()
    assert check_tick["succeeded"] == 1, check_tick
    candidate_sha = check_tick["results"][0]["candidate_sha"]
    assert candidate_sha != base
    review_tick = runtime.run_once().to_dict()
    assert review_tick["succeeded"] == 1, review_tick
    assert review_tick["results"][0]["run"]["output"]["head_sha"] == candidate_sha
    evidence = continuity.list_evidence(task_id=task["task_id"], head_sha=candidate_sha)
    assert any(item["evidence_type"] == "LOCAL_DIFF_CHECK" and item["status"] == "PASSED" for item in evidence)
