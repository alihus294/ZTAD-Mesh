from __future__ import annotations

import json
from pathlib import Path

import pytest

from ztad.github_adapter import GitHubCliAdapter
from ztad.hooks import handle_hook
from ztad.host_acceptance import audit_host_acceptance
from ztad.orchestrator import ContinuityStore, TRANSITIONS
from ztad.progressive_delivery import MetricPolicy, ProgressiveDeliveryController
from ztad.scheduler import ContinuousScheduler, RegisteredEvidenceTransitionGate
from ztad.util import load_data

ROOT = Path(__file__).resolve().parents[1]


def test_hardcoded_and_policy_state_machines_are_identical():
    policy = load_data(ROOT / "policies/state-machine.yaml")
    from_policy = {state: set(values) for state, values in policy["transitions"].items()}
    assert TRANSITIONS == from_policy


def test_default_scheduler_preserves_full_release_sequence():
    expected = {
        "MERGE_READY": "MERGE_QUEUED", "MERGE_QUEUED": "MERGED", "MERGED": "ARTIFACT_VERIFIED",
        "ARTIFACT_VERIFIED": "STAGING", "STAGING": "CANARY", "CANARY": "PRODUCTION_VERIFIED",
        "PRODUCTION_VERIFIED": "DONE",
    }
    for source, target in expected.items():
        assert ContinuousScheduler._default_success_state(source, "supervisor") == target


def test_registered_evidence_gate_requires_validation_mark_for_authoritative_records(tmp_path):
    store = ContinuityStore(tmp_path / "continuity.db")
    task = store.submit_task(repository="repo", title="release", contract={"goal": "x"}, risk="R2", idempotency_key="t")
    policy = load_data(ROOT / "policies/state-machine.yaml")
    gate = RegisteredEvidenceTransitionGate(store, policy)
    head = "a" * 40
    for evidence_type in ("SIGNED_BUILD", "SBOM", "PROVENANCE_VERIFIED"):
        store.register_evidence(
            evidence_id=f"bad-{evidence_type}", task_id=task["task_id"], head_sha=head,
            evidence_type=evidence_type, trust_level="E4", status="PASSED", producer="ci",
            payload={},
        )
    denied = gate.evaluate(task, "ARTIFACT_VERIFIED", {"head_sha": head})
    assert not denied["allowed"]
    assert denied["rejected_evidence_ids"]
    # Fresh task/IDs because evidence identifiers are immutable.
    task2 = store.submit_task(repository="repo", title="release2", contract={"goal": "y"}, risk="R2", idempotency_key="t2")
    for evidence_type in ("SIGNED_BUILD", "SBOM", "PROVENANCE_VERIFIED"):
        store.register_evidence(
            evidence_id=f"good-{evidence_type}", task_id=task2["task_id"], head_sha=head,
            evidence_type=evidence_type, trust_level="E4", status="PASSED", producer="ci",
            payload={"authoritative_record_validated": True},
        )
    allowed = gate.evaluate(task2, "ARTIFACT_VERIFIED", {"head_sha": head})
    assert allowed["allowed"], allowed


def test_hooks_deny_network_direct_platform_mutation_and_broad_permission(tmp_path, monkeypatch):
    ContinuityStore(tmp_path / ".delivery/ztad/continuity.db")
    monkeypatch.chdir(tmp_path)
    network = handle_hook("PreToolUse", {"cwd": str(tmp_path), "tool_name": "WebFetch", "tool_input": {"url": "https://example.invalid"}})
    assert network["hookSpecificOutput"]["permissionDecision"] == "deny"
    platform = handle_hook("PreToolUse", {"cwd": str(tmp_path), "tool_name": "mcp__github__merge_pull_request", "tool_input": {"number": 1}})
    assert platform["hookSpecificOutput"]["permissionDecision"] == "deny"
    permission = handle_hook("PermissionRequest", {"cwd": str(tmp_path), "reason": "need unrestricted network and production credentials"})
    assert permission["hookSpecificOutput"]["decision"]["behavior"] == "deny"


def test_posttool_context_and_stop_do_not_loop(tmp_path):
    ContinuityStore(tmp_path / ".delivery/ztad/continuity.db")
    post = handle_hook("PostToolUse", {"cwd": str(tmp_path), "tool_name": "Write", "tool_input": {}})
    assert "Recompute the diff" in post["hookSpecificOutput"]["additionalContext"]
    assert handle_hook("Stop", {"cwd": str(tmp_path)}) is None
    assert handle_hook("SessionEnd", {"cwd": str(tmp_path)}) is None


def test_host_acceptance_is_non_mutating_and_never_claims_remote_controls(tmp_path):
    before = {path.relative_to(ROOT).as_posix(): path.stat().st_mtime_ns for path in ROOT.rglob("*") if path.is_file()}
    result = audit_host_acceptance(plugin_root=ROOT, repository=tmp_path, inspect_codex_plugin_state=False)
    after = {path.relative_to(ROOT).as_posix(): path.stat().st_mtime_ns for path in ROOT.rglob("*") if path.is_file()}
    assert before == after
    assert result["maximum_verified_mode"] in {"ADVISORY_ONLY", "LOCAL_VERIFICATION_ONLY", "GOVERNED_LOCAL_DEVELOPMENT", "GOVERNED_PULL_REQUEST_CANDIDATE"}
    assert "Remote branch protection" in result["claim_boundary"]


class Deployment:
    def __init__(self, metrics): self._metrics = list(metrics); self.rollbacks = 0; self.deploys = []
    def deploy(self, **kwargs): self.deploys.append(kwargs); return {"success": True, **kwargs}
    def rollback(self, **kwargs): self.rollbacks += 1; return {"success": True, **kwargs}
    def metrics(self, **kwargs): return self._metrics.pop(0)


def healthy(): return {"conclusive": True, "error_rate": 0.001, "latency_ratio": 1.05, "transaction_success": 0.999}
def unhealthy(): return {"conclusive": True, "error_rate": 0.2, "latency_ratio": 2.0, "transaction_success": 0.7}
def inconclusive(): return {"conclusive": False, "error_rate": 0.0, "latency_ratio": 1.0, "transaction_success": 1.0}


def test_progressive_delivery_promotes_healthy_and_rolls_back_unhealthy_or_inconclusive():
    policy = MetricPolicy(0.01, 1.2, 0.99, maximum_inconclusive_rounds=1)
    adapter = Deployment([healthy(), healthy(), healthy()])
    result = ProgressiveDeliveryController(adapter, policy, steps=(1, 50, 100)).run(artifact_digest="new", stable_artifact_digest="old")
    assert result["decision"] == "PROMOTED"
    adapter = Deployment([unhealthy()])
    result = ProgressiveDeliveryController(adapter, policy, steps=(1, 100)).run(artifact_digest="new", stable_artifact_digest="old")
    assert result["decision"] == "ROLLED_BACK"
    assert adapter.rollbacks == 1
    adapter = Deployment([inconclusive(), inconclusive()])
    result = ProgressiveDeliveryController(adapter, policy, steps=(1, 100)).run(artifact_digest="new", stable_artifact_digest="old")
    assert result["decision"] == "ROLLED_BACK"


def test_github_adapter_is_read_only_by_default_and_builds_atomic_argv():
    calls = []
    class Result:
        returncode = 0
        stdout = json.dumps({"number": 1, "state": "OPEN"})
        stderr = ""
    def executor(argv, **kwargs): calls.append(argv); return Result()
    adapter = GitHubCliAdapter(repo_slug="owner/repo", executor=executor)
    viewed = adapter.view_pull_request(1)
    assert viewed.success
    assert calls[0][:3] == ["gh", "pr", "view"]
    with pytest.raises(PermissionError):
        adapter.create_pull_request(head="feature", base="main", title="x", body_file="body.md")
