from __future__ import annotations

import concurrent.futures
from pathlib import Path

import pytest

from ztad.loop_guard import AttemptFingerprint, ProgressSnapshot
from ztad.mesh_store import MeshNodeSpec, MeshStore


def node(node_id: str, *, deps=(), write=False, scopes=(), task_id="task"):
    return MeshNodeSpec.create(
        node_id=node_id, task_id=task_id, title=node_id, task_family="implementation",
        role="worker" if write else "supervisor", risk="R2", write_access=write,
        scopes=scopes, prompt_path="prompt.md", output_schema="schema.json", dependencies=deps,
        idempotency_key=f"key:{node_id}", metadata={"complexity": 2},
    )


def test_mesh_rejects_cycles_and_unknown_dependencies(tmp_path):
    store = MeshStore(tmp_path / "mesh.db")
    with pytest.raises(ValueError, match="cycle"):
        store.submit_graph([node("a", deps=("b",)), node("b", deps=("a",))])
    with pytest.raises(ValueError, match="unknown"):
        store.submit_graph([node("a", deps=("missing",))])


def test_mesh_dependencies_and_scope_locks_are_transactional(tmp_path):
    store = MeshStore(tmp_path / "mesh.db")
    store.submit_graph([
        node("plan"),
        node("write-a", deps=("plan",), write=True, scopes=("src/orders/**",)),
        node("write-b", deps=("plan",), write=True, scopes=("src/orders/service.py",)),
        node("write-c", deps=("plan",), write=True, scopes=("src/users/**",)),
    ])
    claimed = store.claim_ready("owner", limit=4)
    assert [item["node_id"] for item in claimed] == ["plan"]
    store.finish_node("plan", owner="owner", success=True, run_id="r", registry_id="m", provider="p")
    claimed = store.claim_ready("owner-2", limit=4)
    ids = {item["node_id"] for item in claimed}
    assert "write-c" in ids
    assert len(ids & {"write-a", "write-b"}) == 1
    assert len(ids) == 2


def test_concurrent_mesh_claims_never_duplicate_nodes(tmp_path):
    store = MeshStore(tmp_path / "mesh.db")
    store.submit_graph([node(f"n-{i}") for i in range(60)])

    def claim(index: int):
        items = store.claim_ready(f"owner-{index}", limit=1)
        return items[0]["node_id"] if items else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        claimed = [item for item in pool.map(claim, range(60)) if item]
    assert len(claimed) == 60
    assert len(set(claimed)) == 60


def test_expired_mesh_lease_is_recovered(tmp_path):
    store = MeshStore(tmp_path / "mesh.db")
    store.submit_graph([node("n")])
    assert store.claim_ready("dead", lease_seconds=-1)
    assert store.recover_expired() == 1
    assert store.get_node("n")["state"] == "RETRY_READY"


def _fingerprint(suffix: str) -> AttemptFingerprint:
    return AttemptFingerprint(
        task_id="task", strategy_hash=f"s-{suffix}", prompt_hash="p", context_hash="c",
        head_sha="a" * 40, diff_hash="d", failing_evidence_hash="f",
    )


def _snapshot(*, failures=2, findings=1, unknowns=1, evidence=1, strategy="s-a", provider="p", model="m"):
    return ProgressSnapshot(
        failing_checks=failures, blocking_findings=findings, unknowns=unknowns,
        evidence_count=evidence, strategy_hash=strategy, context_hash="c",
        provider=provider, model=model,
    )


def test_attempt_guard_rejects_identical_retry_and_detects_no_progress(tmp_path):
    store = MeshStore(tmp_path / "mesh.db")
    store.submit_graph([node("n")])
    first = store.record_attempt(node_id="n", fingerprint=_fingerprint("a"), snapshot=_snapshot())
    assert first["progress"]
    with pytest.raises(ValueError, match="Repeated attempt"):
        store.record_attempt(node_id="n", fingerprint=_fingerprint("a"), snapshot=_snapshot())
    no_progress = store.record_attempt(
        node_id="n", fingerprint=_fingerprint("b"),
        snapshot=_snapshot(strategy="s-a"),
    )
    assert not no_progress["progress"]
    assert no_progress["decision"] == "NO_PROGRESS_CYCLE_ESCALATE"
    progress = store.record_attempt(
        node_id="n", fingerprint=_fingerprint("c"),
        snapshot=_snapshot(failures=1, strategy="s-c"),
    )
    assert progress["progress"]


def test_model_performance_is_aggregated_for_router(tmp_path):
    store = MeshStore(tmp_path / "mesh.db")
    store.record_model_performance(registry_id="m", task_family="review", success=True, quality=0.9, latency=1.0, cost=0.5)
    store.record_model_performance(registry_id="m", task_family="review", success=False, quality=0.5, latency=3.0, cost=1.5)
    result = store.performance_overrides("review")["m"]
    assert result["quality"] == pytest.approx(0.7)
    assert result["reliability"] == pytest.approx(0.5)
    assert result["latency_index"] == pytest.approx(2.0)
    assert result["cost_index"] == pytest.approx(1.0)
