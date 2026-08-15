from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .orchestrator import ContinuityStore
from .state_machine import gate_requirements


class RoleRunner(Protocol):
    def run(self, task: dict[str, Any], role: str) -> dict[str, Any]: ...


class TransitionGate(Protocol):
    def evaluate(self, task: dict[str, Any], requested_state: str, result: dict[str, Any]) -> dict[str, Any]: ...


class RegisteredEvidenceTransitionGate:
    """Deterministic transition gate over evidence already registered by controllers.

    E3+ records must carry payload.authoritative_record_validated=true. This gate
    deliberately refuses to treat raw model output as transition evidence.
    """

    def __init__(self, store: ContinuityStore, policy: dict[str, Any]):
        self.store = store
        self.policy = policy

    @staticmethod
    def _rank(level: str) -> int:
        try:
            return int(level.removeprefix("E"))
        except ValueError:
            return -1

    def evaluate(self, task: dict[str, Any], requested_state: str, result: dict[str, Any]) -> dict[str, Any]:
        requirements = gate_requirements(self.policy, requested_state, task["risk"])
        minimum = self._rank(requirements["minimum_trust"])
        head_sha = str(result.get("head_sha") or "")
        records = self.store.list_evidence(task_id=task["task_id"], head_sha=head_sha or None)
        valid_types: set[str] = set()
        valid_approvals: set[str] = set()
        rejected: list[str] = []
        for record in records:
            affirmative = record["status"] in {"PASSED", "APPROVED"}
            authoritative = self._rank(record["trust_level"]) < 3 or bool(record.get("payload", {}).get("authoritative_record_validated"))
            if affirmative and self._rank(record["trust_level"]) >= minimum and authoritative:
                valid_types.add(record["evidence_type"])
                if record["evidence_type"].startswith("STRONG_SUPERVISOR_"):
                    valid_approvals.add(record["evidence_type"])
            else:
                rejected.append(record["evidence_id"])
        missing_evidence = sorted(set(requirements["required_evidence"]) - valid_types)
        missing_approvals = sorted(set(requirements["required_approvals"]) - valid_approvals)
        return {
            "allowed": not missing_evidence and not missing_approvals,
            "requested_state": requested_state,
            "minimum_trust": requirements["minimum_trust"],
            "valid_evidence_types": sorted(valid_types),
            "missing_evidence": missing_evidence,
            "missing_approvals": missing_approvals,
            "rejected_evidence_ids": rejected,
            "claim_boundary": "Only controller-registered and validation-marked evidence can advance the durable scheduler.",
        }


@dataclass(frozen=True)
class TickResult:
    worker_id: str
    action: str
    task_id: str | None
    state: str | None
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "action": self.action,
            "task_id": self.task_id,
            "state": self.state,
            "detail": self.detail,
        }


class ContinuousScheduler:
    """One-tick durable scheduler with task-local containment.

    The runner performs work. An optional transition gate validates evidence before
    state advancement. Production use must configure a gate; ungated mode is for
    local simulation and backward-compatible tests only.
    """

    def __init__(
        self,
        store: ContinuityStore,
        runner: RoleRunner,
        *,
        worker_id: str,
        transition_gate: TransitionGate | None = None,
    ):
        self.store = store
        self.runner = runner
        self.worker_id = worker_id
        self.transition_gate = transition_gate

    @staticmethod
    def role_for_state(state: str) -> str:
        if state in {
            "READY", "PLANNING", "SUPERVISOR_REVIEW", "AUTO_REPLAN", "SUPERVISOR_TAKEOVER",
            "MERGE_READY", "MERGE_QUEUED", "MERGED", "ARTIFACT_VERIFIED", "STAGING", "CANARY",
            "PRODUCTION_VERIFIED", "ROLLBACK",
        }:
            return "supervisor"
        if state == "CLOSURE_REVIEW":
            return "closure"
        return "worker"

    def tick(self) -> TickResult:
        self.store.recover_expired_leases()
        task = self.store.claim_next(self.worker_id)
        if task is None:
            return TickResult(self.worker_id, "IDLE_NO_RUNNABLE_TASK", None, None, {})
        role = self.role_for_state(task["state"])
        try:
            result = self.runner.run(task, role)
        except Exception as exc:
            result = {"success": False, "failure_class": "MODEL_PROVIDER_UNAVAILABLE", "error": str(exc)}
        if result.get("success"):
            requested = str(result.get("next_state") or self._default_success_state(task["state"], role))
            if task.get("authoritative_bug_lifecycle") and requested == "DONE":
                requested = "INTERNAL_EXECUTION_COMPLETE"
            gate_result = self.transition_gate.evaluate(task, requested, result) if self.transition_gate else {
                "allowed": True,
                "claim_boundary": "Ungated scheduler mode is not production-authoritative.",
            }
            if not gate_result.get("allowed"):
                routed = self.store.record_failure(
                    task["task_id"], role=role, failure_class="EVIDENCE_MISSING",
                    error="Transition gate rejected advancement: " + str(gate_result),
                    actor=f"scheduler:{self.worker_id}",
                    idempotency_key=f"gate:{result.get('run_id', task['task_id'])}:{requested}:{task['version']}",
                )
                return TickResult(
                    self.worker_id, "TRANSITION_BLOCKED_CONTAINED", task["task_id"],
                    routed["task"]["state"], {"gate": gate_result, "run": result},
                )
            updated = self.store.transition(
                task["task_id"], requested, expected_version=task["version"],
                actor=f"scheduler:{self.worker_id}",
                idempotency_key=f"success:{result.get('run_id', task['task_id'])}:{requested}",
                release_lease=True,
            )
            return TickResult(self.worker_id, "ADVANCED", task["task_id"], updated["state"], {"run": result, "gate": gate_result})
        failure_class = str(result.get("failure_class", "UNKNOWN"))
        routed = self.store.record_failure(
            task["task_id"], role=role, failure_class=failure_class,
            error=str(result.get("error", "model run failed")),
            actor=f"scheduler:{self.worker_id}",
            idempotency_key=f"failure:{result.get('run_id', task['task_id'])}:{failure_class}:{task['version']}",
        )
        updated = routed["task"]
        return TickResult(self.worker_id, "CONTAINED_FAILURE", task["task_id"], updated["state"], routed["decision"] | result)

    @staticmethod
    def _default_success_state(state: str, role: str) -> str:
        mapping = {
            "READY": "PLANNING",
            "PLANNING": "WORKER_IMPLEMENTING",
            "WORKER_IMPLEMENTING": "MACHINE_CHECKS",
            "AUTO_REPAIR": "MACHINE_CHECKS",
            "AUTO_REPLAN": "WORKER_IMPLEMENTING",
            "SUPERVISOR_TAKEOVER": "CLOSURE_REVIEW",
            "CLEAN_RECONSTRUCTION": "PLANNING",
            "MACHINE_CHECKS": "SUPERVISOR_REVIEW",
            "SUPERVISOR_REVIEW": "MERGE_READY",
            "CLOSURE_REVIEW": "MERGE_READY",
            "MERGE_READY": "MERGE_QUEUED",
            "MERGE_QUEUED": "MERGED",
            "MERGED": "ARTIFACT_VERIFIED",
            "ARTIFACT_VERIFIED": "STAGING",
            "STAGING": "CANARY",
            "CANARY": "PRODUCTION_VERIFIED",
            "PRODUCTION_VERIFIED": "DONE",
            "ROLLBACK": "ROLLED_BACK_RETRYABLE",
        }
        return mapping.get(state, "SUPERVISOR_REVIEW" if role == "worker" else "WORKER_IMPLEMENTING")
