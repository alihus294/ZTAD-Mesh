from __future__ import annotations

import concurrent.futures
import json
import sqlite3
from pathlib import Path

import pytest

from ztad.ledger import append_record, create_checkpoint, verify_ledger
from ztad.models import (
    ModelRoutingPolicy,
    build_codex_exec_argv,
    execute_role_with_fallback,
    make_run_spec,
)
from ztad.orchestrator import ContinuityStore, decide_failure
from ztad.scheduler import ContinuousScheduler
from ztad.util import load_data
from ztad.approval_controller import issue_supervisor_approval_evidence
from ztad.crypto import generate_ed25519_keypair, verify_evidence_signature

ROOT = Path(__file__).resolve().parents[1]


def test_ledger_concurrent_writers_are_serialized(tmp_path):
    ledger = tmp_path / "ledger.sqlite3"

    def write(index: int):
        return append_record(ledger, {"index": index}, idempotency_key=f"write-{index}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        records = list(pool.map(write, range(128)))
    assert len({record["sequence"] for record in records}) == 128
    verified = verify_ledger(ledger)
    assert verified["valid"], verified
    assert verified["records"] == 128


def test_ledger_idempotency_and_checkpoint_detect_tail_deletion(tmp_path):
    ledger = tmp_path / "ledger.sqlite3"
    first = append_record(ledger, {"event": "a"}, idempotency_key="same")
    replay = append_record(ledger, {"event": "a"}, idempotency_key="same")
    assert replay["sequence"] == first["sequence"]
    assert replay["idempotent_replay"] is True
    append_record(ledger, {"event": "b"}, idempotency_key="b")
    checkpoint = tmp_path / "checkpoint.json"
    create_checkpoint(ledger, checkpoint)
    assert verify_ledger(ledger, checkpoint_path=checkpoint)["valid"]
    conn = sqlite3.connect(ledger)
    conn.execute("DELETE FROM ledger_entries WHERE sequence=(SELECT MAX(sequence) FROM ledger_entries)")
    conn.commit()
    conn.close()
    assert not verify_ledger(ledger, checkpoint_path=checkpoint)["valid"]


def _submit(store: ContinuityStore, title: str, priority: int = 0):
    task = store.submit_task(
        repository="repo", title=title, contract={"goal": title}, risk="R2",
        priority=priority, idempotency_key=f"key:{title}",
    )
    return task


def test_concurrent_claims_do_not_duplicate_tasks(tmp_path):
    store = ContinuityStore(tmp_path / "continuity.db")
    for index in range(40):
        _submit(store, f"task-{index}", priority=index)

    def claim(index: int):
        task = store.claim_next(f"worker-{index}", lease_seconds=30)
        return task["task_id"] if task else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        claimed = [item for item in pool.map(claim, range(40)) if item]
    assert len(claimed) == 40
    assert len(set(claimed)) == 40
    assert store.verify_event_chain()["valid"]


def test_task_failure_is_contained_and_next_task_remains_runnable(tmp_path):
    store = ContinuityStore(tmp_path / "continuity.db")
    first = _submit(store, "first", priority=100)
    second = _submit(store, "second", priority=1)
    claimed = store.claim_next("worker-a")
    assert claimed["task_id"] == first["task_id"]
    routed = store.record_failure(
        claimed["task_id"], role="worker", failure_class="CODE_FAILURE", error="broken",
        actor="test", idempotency_key="failure-1",
    )
    assert routed["task"]["state"] == "AUTO_REPAIR"
    next_task = store.claim_next("worker-b")
    assert next_task is not None
    # The failed task may be reclaimed for repair, but the system still has a
    # second runnable task and no global stop state.
    status = store.system_status()
    assert status["globally_blocked"] is False
    assert len(store.list_tasks()) == 2


def test_expired_lease_is_recovered(tmp_path, monkeypatch):
    store = ContinuityStore(tmp_path / "continuity.db")
    task = _submit(store, "lease")
    claimed = store.claim_next("dead", lease_seconds=-1)
    assert claimed["task_id"] == task["task_id"]
    assert store.recover_expired_leases() == 1
    recovered = store.get_task(task["task_id"])
    assert recovered["state"] == "WAITING_RETRY"
    assert recovered["lease_owner"] is None


def test_failure_ladder_changes_strategy_and_quarantines_late_failure():
    assert decide_failure(failure_class="CODE_FAILURE", role="worker", worker_attempts=1, supervisor_attempts=0, total_attempts=1).next_state == "AUTO_REPAIR"
    assert decide_failure(failure_class="CODE_FAILURE", role="worker", worker_attempts=2, supervisor_attempts=0, total_attempts=2).next_state == "AUTO_REPLAN"
    assert decide_failure(failure_class="CODE_FAILURE", role="worker", worker_attempts=3, supervisor_attempts=0, total_attempts=3).next_state == "SUPERVISOR_TAKEOVER"
    assert decide_failure(failure_class="CODE_FAILURE", role="worker", worker_attempts=4, supervisor_attempts=0, total_attempts=4).next_state == "CLEAN_RECONSTRUCTION"
    assert decide_failure(failure_class="CODE_FAILURE", role="worker", worker_attempts=5, supervisor_attempts=0, total_attempts=5).next_state == "QUARANTINED"
    assert decide_failure(failure_class="MODEL_TIMEOUT", role="worker", worker_attempts=1, supervisor_attempts=0, total_attempts=1).next_state == "WAITING_RETRY"
    assert decide_failure(failure_class="MISSING_CREDENTIAL", role="worker", worker_attempts=1, supervisor_attempts=0, total_attempts=1).next_state == "WAITING_EXTERNAL_DEPENDENCY"


def test_same_session_cannot_implement_and_approve_same_sha(tmp_path):
    store = ContinuityStore(tmp_path / "continuity.db")
    task = _submit(store, "approval")
    store.record_model_run(
        task_id=task["task_id"], role="worker", model_id="cheap", prompt_version="v1",
        context_hash="sha256:x", status="COMPLETED", session_id="session-1", head_sha="abc",
    )
    store.register_evidence(
        evidence_id="ci-1", task_id=task["task_id"], head_sha="abc",
        evidence_type="protected_ci", trust_level="E4", status="PASSED",
        producer="github-actions", payload={"check": "unit"},
    )
    with pytest.raises(PermissionError):
        store.record_approval(
            task_id=task["task_id"], role="supervisor", session_id="session-1", head_sha="abc",
            diff_hash="sha256:d", evidence_refs=["ci-1"], decision="APPROVE",
        )
    approval = store.record_approval(
        task_id=task["task_id"], role="supervisor", session_id="session-2", head_sha="abc",
        diff_hash="sha256:d", evidence_refs=["ci-1"], decision="APPROVE",
    )
    assert approval["decision"] == "APPROVE"


def test_approval_rejects_invented_stale_and_weak_evidence(tmp_path):
    store = ContinuityStore(tmp_path / "continuity.db")
    task = _submit(store, "evidence")
    with pytest.raises(ValueError, match="Unknown evidence"):
        store.record_approval(
            task_id=task["task_id"], role="supervisor", session_id="review-1",
            head_sha="abc", diff_hash="sha256:d", evidence_refs=["invented"],
            decision="APPROVE",
        )
    store.register_evidence(
        evidence_id="weak", task_id=task["task_id"], head_sha="abc",
        evidence_type="model_claim", trust_level="E1", status="PASSED", producer="model",
    )
    with pytest.raises(ValueError, match="E3"):
        store.record_approval(
            task_id=task["task_id"], role="supervisor", session_id="review-2",
            head_sha="abc", diff_hash="sha256:d", evidence_refs=["weak"], decision="APPROVE",
        )
    store.register_evidence(
        evidence_id="ci", task_id=task["task_id"], head_sha="abc",
        evidence_type="protected_ci", trust_level="E4", status="PASSED", producer="ci",
    )
    approval = store.record_approval(
        task_id=task["task_id"], role="supervisor", session_id="review-3",
        head_sha="abc", diff_hash="sha256:d", evidence_refs=["ci"], decision="APPROVE",
    )
    assert store.validate_approval(
        approval["approval_id"], current_head_sha="abc", current_diff_hash="sha256:d"
    )["valid"]
    invalid = store.validate_approval(
        approval["approval_id"], current_head_sha="new", current_diff_hash="sha256:d"
    )
    assert not invalid["valid"]
    assert any("stale" in item.lower() for item in invalid["errors"])


def test_supervisor_takeover_requires_fresh_closure_reviewer(tmp_path):
    store = ContinuityStore(tmp_path / "continuity.db")
    task = _submit(store, "takeover")
    store.record_model_run(
        task_id=task["task_id"], role="supervisor_takeover", model_id="strong",
        prompt_version="v2", context_hash="sha256:x", status="COMPLETED",
        session_id="takeover-session", head_sha="abc",
    )
    store.register_evidence(
        evidence_id="ci-takeover", task_id=task["task_id"], head_sha="abc",
        evidence_type="protected_ci", trust_level="E4", status="PASSED", producer="ci",
    )
    with pytest.raises(PermissionError, match="closure"):
        store.record_approval(
            task_id=task["task_id"], role="supervisor", session_id="other-supervisor",
            head_sha="abc", diff_hash="sha256:d", evidence_refs=["ci-takeover"],
            decision="APPROVE",
        )
    with pytest.raises(PermissionError, match="implementing session"):
        store.record_approval(
            task_id=task["task_id"], role="closure", session_id="takeover-session",
            head_sha="abc", diff_hash="sha256:d", evidence_refs=["ci-takeover"],
            decision="APPROVE",
        )
    approval = store.record_approval(
        task_id=task["task_id"], role="closure", session_id="fresh-closure",
        head_sha="abc", diff_hash="sha256:d", evidence_refs=["ci-takeover"],
        decision="APPROVE",
    )
    assert approval["role"] == "closure"


def test_external_dependency_is_retried_without_global_stop(tmp_path, monkeypatch):
    store = ContinuityStore(tmp_path / "continuity.db")
    task = _submit(store, "external")
    store.record_failure(
        task["task_id"], role="worker", failure_class="MISSING_CREDENTIAL",
        error="not provisioned", actor="test", idempotency_key="external-1",
    )
    conn = sqlite3.connect(store.path)
    conn.execute(
        "UPDATE tasks SET next_run_at='2000-01-01T00:00:00Z' WHERE task_id=?",
        (task["task_id"],),
    )
    conn.commit()
    conn.close()
    claimed = store.claim_next("retry-worker")
    assert claimed is not None
    assert claimed["task_id"] == task["task_id"]
    assert claimed["state"] == "READY"


def test_model_routing_builds_role_isolated_commands(tmp_path):
    routing = ModelRoutingPolicy.from_file(ROOT / "policies/model-routing.yaml")
    prompt = tmp_path / "prompt.md"
    schema = tmp_path / "schema.json"
    prompt.write_text("work", encoding="utf-8")
    schema.write_text('{"type":"object"}', encoding="utf-8")
    worker = make_run_spec(task_id="t", role=routing.role("worker"), prompt_path=prompt, output_schema=schema, output_dir=tmp_path / "out")
    supervisor = make_run_spec(task_id="t", role=routing.role("supervisor"), prompt_path=prompt, output_schema=schema, output_dir=tmp_path / "out")
    worker_argv = build_codex_exec_argv(worker)
    supervisor_argv = build_codex_exec_argv(supervisor)
    assert "workspace-write" in worker_argv
    assert "read-only" in supervisor_argv
    assert "--ephemeral" in worker_argv and "--ephemeral" in supervisor_argv
    assert routing.role("worker").model != routing.role("supervisor").model


def test_worker_model_fallback_changes_model_and_continues(tmp_path):
    routing = ModelRoutingPolicy.from_file(ROOT / "policies/model-routing.yaml")
    prompt = tmp_path / "prompt.md"
    schema = tmp_path / "schema.json"
    prompt.write_text("work", encoding="utf-8")
    schema.write_text('{"type":"object"}', encoding="utf-8")
    calls: list[str] = []

    def fake_executor(spec, **kwargs):
        calls.append(spec.model)
        if len(calls) == 1:
            return {"run_id": spec.run_id, "model": spec.model, "success": False, "failure_class": "MODEL_UNAVAILABLE", "error": "down"}
        return {"run_id": spec.run_id, "model": spec.model, "success": True, "output": {"ok": True}}

    result = execute_role_with_fallback(
        task_id="t", role=routing.role("worker"), prompt_path=prompt,
        output_schema=schema, output_dir=tmp_path / "out", cwd=tmp_path,
        executor=fake_executor,
    )
    assert result["success"] is True
    assert result["attempt_count"] == 2
    assert calls == ["gpt-5.6-luna", "gpt-5.6-terra"]


def test_approval_controller_signs_only_after_store_validation(tmp_path):
    store = ContinuityStore(tmp_path / "continuity.db")
    task = _submit(store, "controller")
    store.register_evidence(
        evidence_id="ci-controller", task_id=task["task_id"], head_sha="a" * 40,
        evidence_type="protected_ci", trust_level="E4", status="PASSED", producer="ci",
    )
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_ed25519_keypair(private, public)
    subject = {
        "repository": "owner/repo",
        "change_contract_hash": "sha256:" + "b" * 64,
        "base_sha": "c" * 40,
        "head_sha": "a" * 40,
        "policy_bundle_hash": "sha256:" + "d" * 64,
        "toolchain_hash": "sha256:" + "e" * 64,
    }
    issued = issue_supervisor_approval_evidence(
        store=store, task_id=task["task_id"], role="supervisor",
        session_id="review-session", head_sha="a" * 40,
        diff_hash="sha256:" + "f" * 64, evidence_refs=["ci-controller"],
        approval_type="STRONG_SUPERVISOR_MERGE_APPROVAL", subject=subject,
        private_key_path=private, key_id="controller-key",
    )
    roots = {"keys": {"controller-key": {
        "status": "ACTIVE", "public_key_pem": public.read_text(encoding="utf-8"),
        "allowed_trust_levels": ["E6"],
        "allowed_producers": ["platform:approval-controller"],
        "allowed_types": ["STRONG_SUPERVISOR_MERGE_APPROVAL"],
        "allowed_environments": ["supervisor-approval-controller"],
    }}}
    assert verify_evidence_signature(issued["signed_evidence"], roots) == []
    assert issued["signed_evidence"]["metadata"]["underlying_evidence_refs"] == ["ci-controller"]
    with pytest.raises(ValueError, match="Unknown evidence"):
        issue_supervisor_approval_evidence(
            store=store, task_id=task["task_id"], role="supervisor",
            session_id="another-session", head_sha="a" * 40,
            diff_hash="sha256:" + "f" * 64, evidence_refs=["invented"],
            approval_type="STRONG_SUPERVISOR_MERGE_APPROVAL", subject=subject,
            private_key_path=private, key_id="controller-key",
        )


class FakeRunner:
    def __init__(self):
        self.calls = 0

    def run(self, task, role):
        self.calls += 1
        if task["title"] == "bad":
            return {"success": False, "run_id": f"r-{self.calls}", "failure_class": "CODE_FAILURE", "error": "bad"}
        return {"success": True, "run_id": f"r-{self.calls}"}


def test_scheduler_contains_failure_instead_of_global_stop(tmp_path):
    store = ContinuityStore(tmp_path / "continuity.db")
    _submit(store, "bad", priority=10)
    _submit(store, "good", priority=1)
    scheduler = ContinuousScheduler(store, FakeRunner(), worker_id="scheduler-1")
    first = scheduler.tick()
    assert first.action == "CONTAINED_FAILURE"
    second = scheduler.tick()
    assert second.action in {"ADVANCED", "CONTAINED_FAILURE"}
    assert store.system_status()["globally_blocked"] is False


def test_scheduler_advances_ready_through_planning(tmp_path):
    store = ContinuityStore(tmp_path / "continuity.db")
    task = _submit(store, "good")
    scheduler = ContinuousScheduler(store, FakeRunner(), worker_id="scheduler-2")
    result = scheduler.tick()
    assert result.action == "ADVANCED"
    assert result.task_id == task["task_id"]
    assert result.state == "PLANNING"
