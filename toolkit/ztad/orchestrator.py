from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .util import canonical_json, sha256_bytes, utc_now

RUNNABLE_STATES = {
    "READY", "PLANNING", "WORKER_IMPLEMENTING", "MACHINE_CHECKS", "SUPERVISOR_REVIEW",
    "AUTO_REPAIR", "AUTO_REPLAN", "SUPERVISOR_TAKEOVER", "CLOSURE_REVIEW",
    "CLEAN_RECONSTRUCTION", "MERGE_READY", "MERGE_QUEUED", "MERGED",
    "ARTIFACT_VERIFIED", "STAGING", "CANARY", "PRODUCTION_VERIFIED", "ROLLBACK",
}
DELAYED_STATES = {"WAITING_RETRY", "WAITING_EXTERNAL_DEPENDENCY", "QUARANTINED", "ROLLED_BACK_RETRYABLE"}
TERMINAL_STATES = {"DONE", "INTERNAL_EXECUTION_COMPLETE", "CANCELLED", "SUPERSEDED"}

# This table mirrors policies/state-machine.yaml. Packaging validation compares
# both representations so the durable store cannot silently diverge from policy.
TRANSITIONS: dict[str, set[str]] = {
    "BACKLOG": {"READY", "CANCELLED", "SUPERSEDED"},
    "READY": {"PLANNING", "WORKER_IMPLEMENTING", "WAITING_EXTERNAL_DEPENDENCY", "CANCELLED"},
    "PLANNING": {"WORKER_IMPLEMENTING", "AUTO_REPLAN", "WAITING_RETRY", "QUARANTINED"},
    "WORKER_IMPLEMENTING": {"MACHINE_CHECKS", "AUTO_REPAIR", "AUTO_REPLAN", "SUPERVISOR_TAKEOVER", "WAITING_RETRY", "QUARANTINED"},
    "MACHINE_CHECKS": {"SUPERVISOR_REVIEW", "AUTO_REPAIR", "AUTO_REPLAN", "WAITING_RETRY", "QUARANTINED"},
    "SUPERVISOR_REVIEW": {"MERGE_READY", "AUTO_REPAIR", "AUTO_REPLAN", "SUPERVISOR_TAKEOVER", "WAITING_RETRY", "QUARANTINED"},
    "AUTO_REPAIR": {"WORKER_IMPLEMENTING", "MACHINE_CHECKS", "AUTO_REPLAN", "SUPERVISOR_TAKEOVER", "WAITING_RETRY", "QUARANTINED"},
    "AUTO_REPLAN": {"WORKER_IMPLEMENTING", "SUPERVISOR_TAKEOVER", "CLEAN_RECONSTRUCTION", "WAITING_RETRY", "QUARANTINED"},
    "SUPERVISOR_TAKEOVER": {"MACHINE_CHECKS", "CLOSURE_REVIEW", "CLEAN_RECONSTRUCTION", "WAITING_RETRY", "QUARANTINED"},
    "CLOSURE_REVIEW": {"MERGE_READY", "AUTO_REPAIR", "AUTO_REPLAN", "CLEAN_RECONSTRUCTION", "QUARANTINED"},
    "CLEAN_RECONSTRUCTION": {"PLANNING", "WORKER_IMPLEMENTING", "WAITING_RETRY", "QUARANTINED"},
    "WAITING_RETRY": {"WORKER_IMPLEMENTING", "AUTO_REPLAN", "SUPERVISOR_TAKEOVER", "CLEAN_RECONSTRUCTION", "QUARANTINED", "CANCELLED"},
    "WAITING_EXTERNAL_DEPENDENCY": {"READY", "AUTO_REPLAN", "QUARANTINED", "CANCELLED"},
    "QUARANTINED": {"AUTO_REPLAN", "CLEAN_RECONSTRUCTION", "WAITING_RETRY", "CANCELLED", "SUPERSEDED"},
    "MERGE_READY": {"MERGE_QUEUED", "STAGING", "WAITING_RETRY", "QUARANTINED"},
    "MERGE_QUEUED": {"MERGED", "AUTO_REPLAN", "WAITING_RETRY", "QUARANTINED"},
    "MERGED": {"ARTIFACT_VERIFIED", "ROLLBACK", "QUARANTINED"},
    "ARTIFACT_VERIFIED": {"STAGING", "CANARY", "ROLLBACK", "QUARANTINED"},
    "STAGING": {"CANARY", "PRODUCTION_VERIFIED", "ROLLBACK", "WAITING_RETRY", "QUARANTINED"},
    "CANARY": {"PRODUCTION_VERIFIED", "ROLLBACK", "WAITING_RETRY", "QUARANTINED"},
    "ROLLBACK": {"ROLLED_BACK_RETRYABLE", "DONE", "QUARANTINED"},
    "ROLLED_BACK_RETRYABLE": {"AUTO_REPLAN", "CLEAN_RECONSTRUCTION", "WAITING_RETRY", "QUARANTINED"},
    "PRODUCTION_VERIFIED": {"INTERNAL_EXECUTION_COMPLETE", "DONE", "ROLLBACK"},
    "INTERNAL_EXECUTION_COMPLETE": set(),
    "DONE": set(), "CANCELLED": set(), "SUPERSEDED": set(),
}

TRANSIENT_FAILURES = {
    "MODEL_TIMEOUT", "MODEL_RATE_LIMIT", "MODEL_UNAVAILABLE", "CI_UNAVAILABLE",
    "MODEL_PROVIDER_UNAVAILABLE", "NETWORK_TRANSIENT", "LEASE_EXPIRED",
    "LOCK_CONTENTION", "RUNNER_UNAVAILABLE",
}
EXTERNAL_FAILURES = {
    "MISSING_CREDENTIAL", "EXTERNAL_DEPENDENCY", "BUSINESS_DECISION_REQUIRED",
    "SERVICE_PERMISSION_MISSING", "ENVIRONMENT_NOT_PROVISIONED",
}
NON_RETRYABLE_FAILURES = {
    "POLICY_VIOLATION", "SECRET_EXPOSURE_ATTEMPT", "DESTRUCTIVE_UNREVERSIBLE",
    "CONTROL_PLANE_CORRUPTION", "EVIDENCE_FABRICATION", "REQUIREMENT_CONTRADICTION",
}


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _future(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _event_hash(event: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(event))


@dataclass(frozen=True)
class FailureDecision:
    next_state: str
    retry_after_seconds: int
    strategy_delta: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "next_state": self.next_state,
            "retry_after_seconds": self.retry_after_seconds,
            "strategy_delta": self.strategy_delta,
            "reason": self.reason,
        }


def decide_failure(
    *,
    failure_class: str,
    role: str,
    worker_attempts: int,
    supervisor_attempts: int,
    total_attempts: int,
    base_backoff_seconds: int = 30,
) -> FailureDecision:
    failure_class = failure_class.upper()
    role = role.lower()
    if failure_class in NON_RETRYABLE_FAILURES:
        return FailureDecision("QUARANTINED", 3600, 1, "Unsafe or logically non-retryable failure was contained")
    if failure_class in EXTERNAL_FAILURES:
        return FailureDecision("WAITING_EXTERNAL_DEPENDENCY", 900, 0, "External prerequisite is absent; other tasks remain schedulable")
    if failure_class in TRANSIENT_FAILURES:
        exponent = min(total_attempts, 8)
        return FailureDecision("WAITING_RETRY", min(base_backoff_seconds * (2 ** exponent), 3600), 0, "Transient failure scheduled with bounded exponential backoff")
    if role == "worker":
        if worker_attempts <= 1:
            return FailureDecision("AUTO_REPAIR", 0, 0, "First worker failure receives a targeted repair pass")
        if worker_attempts == 2:
            return FailureDecision("AUTO_REPLAN", 0, 1, "Repeated worker failure changes the strategy")
        if worker_attempts == 3:
            return FailureDecision("SUPERVISOR_TAKEOVER", 0, 1, "Strong supervisor takes over implementation")
        if worker_attempts == 4:
            return FailureDecision("CLEAN_RECONSTRUCTION", 0, 1, "Rebuild from a clean baseline with a new strategy")
        return FailureDecision("QUARANTINED", 1800, 1, "Repeated failure is contained while the scheduler continues other work")
    if role in {"supervisor", "closure"}:
        if supervisor_attempts <= 1:
            return FailureDecision("AUTO_REPLAN", 0, 1, "Fresh supervisor context must re-plan")
        if supervisor_attempts == 2:
            return FailureDecision("CLEAN_RECONSTRUCTION", 0, 1, "Review failure triggers clean reconstruction")
        return FailureDecision("QUARANTINED", 1800, 1, "Repeated strong-model failure is contained")
    return FailureDecision("WAITING_RETRY", min(base_backoff_seconds * (2 ** min(total_attempts, 8)), 3600), 0, "Unknown execution role receives a bounded retry")


class ContinuityStore:
    """Transactional durable state for a never-idle task scheduler.

    SQLite is the portable single-node implementation. WAL, BEGIN IMMEDIATE,
    versioned updates, leases, and idempotency keys prevent the concurrency
    corruption found in ZTAD 1.x. Multi-host deployments should use the same
    schema semantics on PostgreSQL or a durable workflow engine.
    """

    def __init__(self, path: Path):
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def _initialize(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    repository TEXT NOT NULL,
                    title TEXT NOT NULL,
                    contract_json TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL,
                    strategy_version INTEGER NOT NULL DEFAULT 1,
                    total_attempts INTEGER NOT NULL DEFAULT 0,
                    worker_attempts INTEGER NOT NULL DEFAULT 0,
                    supervisor_attempts INTEGER NOT NULL DEFAULT 0,
                    next_run_at TEXT,
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    version INTEGER NOT NULL DEFAULT 1,
                    last_failure_class TEXT,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_schedulable
                    ON tasks(state,next_run_at,lease_expires_at,priority,created_at);
                CREATE TABLE IF NOT EXISTS task_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    record_hash TEXT NOT NULL UNIQUE,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE TABLE IF NOT EXISTS model_runs (
                    run_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    session_id TEXT,
                    model_id TEXT NOT NULL,
                    reasoning_effort TEXT,
                    prompt_version TEXT NOT NULL,
                    context_hash TEXT NOT NULL,
                    head_sha TEXT,
                    status TEXT NOT NULL,
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    output_hash TEXT,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS idx_model_runs_task ON model_runs(task_id,role,status);
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    head_sha TEXT NOT NULL,
                    diff_hash TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(task_id,role,session_id,head_sha,diff_hash),
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE TABLE IF NOT EXISTS evidence_registry (
                    evidence_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    head_sha TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    trust_level TEXT NOT NULL,
                    status TEXT NOT NULL,
                    producer TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    record_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_task_sha
                    ON evidence_registry(task_id,head_sha,status,trust_level);
                """
            )
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(evidence_registry)").fetchall()}
            if "payload_json" not in columns:
                conn.execute("ALTER TABLE evidence_registry ADD COLUMN payload_json TEXT NOT NULL DEFAULT '{}'")
        finally:
            conn.close()

    def _append_event_tx(
        self,
        conn: sqlite3.Connection,
        *,
        task_id: str,
        event_type: str,
        payload: dict[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any]:
        existing = conn.execute(
            "SELECT * FROM task_events WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
        if existing:
            return self._event_row(existing) | {"idempotent_replay": True}
        prev = conn.execute(
            "SELECT record_hash FROM task_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = prev["record_hash"] if prev else "sha256:" + "0" * 64
        created_at = _iso_now()
        payload_json = canonical_json(payload).decode("utf-8")
        cursor = conn.execute(
            """INSERT INTO task_events(task_id,idempotency_key,event_type,created_at,previous_hash,payload_json,record_hash)
               VALUES(?,?,?,?,?,?,?)""",
            (task_id, idempotency_key, event_type, created_at, previous_hash, payload_json, "PENDING"),
        )
        sequence = int(cursor.lastrowid)
        material = {
            "sequence": sequence,
            "task_id": task_id,
            "idempotency_key": idempotency_key,
            "event_type": event_type,
            "created_at": created_at,
            "previous_hash": previous_hash,
            "payload": payload,
        }
        record_hash = _event_hash(material)
        conn.execute("UPDATE task_events SET record_hash=? WHERE sequence=?", (record_hash, sequence))
        return material | {"record_hash": record_hash, "idempotent_replay": False}

    @staticmethod
    def _task_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["contract"] = json.loads(result.pop("contract_json"))
        result["authoritative_bug_lifecycle"] = bool(
            result["contract"].get("authoritative_bug_lifecycle")
            or result["contract"].get("bug_lifecycle_case_id")
            or result["contract"].get("protocol") == "WorkshopOS-Fail-Closed-Bug-to-Production-v1"
        )
        return result

    @staticmethod
    def _event_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["payload"] = json.loads(result.pop("payload_json"))
        return result

    def submit_task(
        self,
        *,
        repository: str,
        title: str,
        contract: dict[str, Any],
        risk: str,
        priority: int = 0,
        idempotency_key: str | None = None,
        task_id: str | None = None,
    ) -> dict[str, Any]:
        if risk not in {"R0", "R1", "R2", "R3", "R4"}:
            raise ValueError("Unknown risk")
        task_id = task_id or f"task-{uuid.uuid4()}"
        idempotency_key = idempotency_key or sha256_bytes(canonical_json({"repository": repository, "title": title, "contract": contract}))
        now = _iso_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT * FROM tasks WHERE idempotency_key=?", (idempotency_key,)).fetchone()
            if existing:
                conn.execute("COMMIT")
                return self._task_row(existing) | {"idempotent_replay": True}
            conn.execute(
                """INSERT INTO tasks(task_id,idempotency_key,repository,title,contract_json,risk,priority,state,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (task_id, idempotency_key, repository, title, canonical_json(contract).decode("utf-8"), risk, priority, "READY", now, now),
            )
            self._append_event_tx(
                conn, task_id=task_id, event_type="TASK_SUBMITTED",
                payload={"state": "READY", "risk": risk, "priority": priority},
                idempotency_key=f"submit:{idempotency_key}",
            )
            conn.execute("COMMIT")
            return self.get_task(task_id) | {"idempotent_replay": False}
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def get_task(self, task_id: str) -> dict[str, Any]:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise KeyError(task_id)
            return self._task_row(row)
        finally:
            conn.close()

    def list_tasks(self, states: Iterable[str] | None = None) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            if states:
                states_list = sorted(set(states))
                placeholders = ",".join("?" for _ in states_list)
                rows = conn.execute(
                    f"SELECT * FROM tasks WHERE state IN ({placeholders}) ORDER BY priority DESC,created_at",
                    states_list,
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM tasks ORDER BY priority DESC,created_at").fetchall()
            return [self._task_row(row) for row in rows]
        finally:
            conn.close()

    def recover_expired_leases(self) -> int:
        now = _iso_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT * FROM tasks WHERE lease_expires_at IS NOT NULL AND lease_expires_at <= ?",
                (now,),
            ).fetchall()
            count = 0
            for row in rows:
                task = self._task_row(row)
                conn.execute(
                    """UPDATE tasks SET state='WAITING_RETRY',next_run_at=?,lease_owner=NULL,lease_expires_at=NULL,
                       last_failure_class='LEASE_EXPIRED',last_error='Worker lease expired',version=version+1,updated_at=?
                       WHERE task_id=? AND version=?""",
                    (_future(5), now, task["task_id"], task["version"]),
                )
                self._append_event_tx(
                    conn, task_id=task["task_id"], event_type="LEASE_RECOVERED",
                    payload={"previous_owner": task["lease_owner"], "previous_state": task["state"]},
                    idempotency_key=f"lease-recovered:{task['task_id']}:{task['version']}",
                )
                count += 1
            conn.execute("COMMIT")
            return count
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def _promote_due_tx(self, conn: sqlite3.Connection, now: str) -> None:
        due = conn.execute(
            """SELECT task_id,state,version FROM tasks
               WHERE state IN ('WAITING_RETRY','WAITING_EXTERNAL_DEPENDENCY','QUARANTINED','ROLLED_BACK_RETRYABLE')
                 AND next_run_at IS NOT NULL AND next_run_at <= ?""",
            (now,),
        ).fetchall()
        for row in due:
            if row["state"] == "WAITING_EXTERNAL_DEPENDENCY":
                target = "READY"
            elif row["state"] in {"QUARANTINED", "ROLLED_BACK_RETRYABLE"}:
                target = "AUTO_REPLAN"
            else:
                target = "WORKER_IMPLEMENTING"
            conn.execute(
                "UPDATE tasks SET state=?,next_run_at=NULL,version=version+1,updated_at=? WHERE task_id=? AND version=?",
                (target, now, row["task_id"], row["version"]),
            )
            self._append_event_tx(
                conn, task_id=row["task_id"], event_type="DELAY_EXPIRED",
                payload={"from": row["state"], "to": target},
                idempotency_key=f"delay-expired:{row['task_id']}:{row['version']}",
            )

    def claim_next(self, worker_id: str, *, lease_seconds: int = 300) -> dict[str, Any] | None:
        now = _iso_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._promote_due_tx(conn, now)
            states = sorted(RUNNABLE_STATES)
            placeholders = ",".join("?" for _ in states)
            row = conn.execute(
                f"""SELECT * FROM tasks
                    WHERE state IN ({placeholders})
                      AND (next_run_at IS NULL OR next_run_at <= ?)
                      AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                    ORDER BY priority DESC, created_at ASC LIMIT 1""",
                (*states, now, now),
            ).fetchone()
            if not row:
                conn.execute("COMMIT")
                return None
            task = self._task_row(row)
            expires = _future(lease_seconds)
            changed = conn.execute(
                """UPDATE tasks SET lease_owner=?,lease_expires_at=?,version=version+1,updated_at=?
                   WHERE task_id=? AND version=?""",
                (worker_id, expires, now, task["task_id"], task["version"]),
            ).rowcount
            if changed != 1:
                conn.execute("ROLLBACK")
                return None
            self._append_event_tx(
                conn, task_id=task["task_id"], event_type="TASK_CLAIMED",
                payload={"worker_id": worker_id, "lease_expires_at": expires, "state": task["state"]},
                idempotency_key=f"claim:{task['task_id']}:{task['version'] + 1}:{worker_id}",
            )
            conn.execute("COMMIT")
            return self.get_task(task["task_id"])
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def heartbeat(self, task_id: str, worker_id: str, *, lease_seconds: int = 300) -> dict[str, Any]:
        now = _iso_now()
        expires = _future(lease_seconds)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise KeyError(task_id)
            if row["lease_owner"] != worker_id:
                raise PermissionError("Lease owner mismatch")
            conn.execute(
                "UPDATE tasks SET lease_expires_at=?,version=version+1,updated_at=? WHERE task_id=? AND version=?",
                (expires, now, task_id, row["version"]),
            )
            self._append_event_tx(
                conn, task_id=task_id, event_type="LEASE_HEARTBEAT",
                payload={"worker_id": worker_id, "lease_expires_at": expires},
                idempotency_key=f"heartbeat:{task_id}:{row['version'] + 1}",
            )
            conn.execute("COMMIT")
            return self.get_task(task_id)
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def transition(
        self,
        task_id: str,
        requested_state: str,
        *,
        actor: str,
        expected_version: int | None = None,
        payload: dict[str, Any] | None = None,
        release_lease: bool = False,
        next_run_at: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if requested_state not in TRANSITIONS:
            raise ValueError(f"Unknown state: {requested_state}")
        now = _iso_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise KeyError(task_id)
            task = self._task_row(row)
            if expected_version is not None and task["version"] != expected_version:
                raise RuntimeError("Optimistic concurrency conflict")
            if task.get("authoritative_bug_lifecycle") and requested_state == "DONE":
                raise PermissionError(
                    "Internal scheduler DONE is not a bug-lifecycle closure; use the authoritative lifecycle"
                )
            if requested_state not in TRANSITIONS.get(task["state"], set()):
                raise ValueError(f"Transition {task['state']} -> {requested_state} is not allowed")
            lease_owner = None if release_lease else task["lease_owner"]
            lease_expires = None if release_lease else task["lease_expires_at"]
            changed = conn.execute(
                """UPDATE tasks SET state=?,next_run_at=?,lease_owner=?,lease_expires_at=?,version=version+1,updated_at=?
                   WHERE task_id=? AND version=?""",
                (requested_state, next_run_at, lease_owner, lease_expires, now, task_id, task["version"]),
            ).rowcount
            if changed != 1:
                raise RuntimeError("Optimistic concurrency conflict")
            event_payload = {"from": task["state"], "to": requested_state, "actor": actor, **(payload or {})}
            self._append_event_tx(
                conn, task_id=task_id, event_type="STATE_TRANSITION", payload=event_payload,
                idempotency_key=idempotency_key or f"transition:{task_id}:{task['version']}:{requested_state}",
            )
            conn.execute("COMMIT")
            return self.get_task(task_id)
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def record_failure(
        self,
        task_id: str,
        *,
        role: str,
        failure_class: str,
        error: str,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT * FROM task_events WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if existing:
                conn.execute("COMMIT")
                return {"task": self.get_task(task_id), "decision": self._event_row(existing)["payload"].get("decision"), "idempotent_replay": True}
            row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise KeyError(task_id)
            task = self._task_row(row)
            total = task["total_attempts"] + 1
            worker = task["worker_attempts"] + (1 if role.lower() == "worker" else 0)
            supervisor = task["supervisor_attempts"] + (1 if role.lower() in {"supervisor", "closure"} else 0)
            decision = decide_failure(
                failure_class=failure_class,
                role=role,
                worker_attempts=worker,
                supervisor_attempts=supervisor,
                total_attempts=total,
            )
            next_run = _future(decision.retry_after_seconds) if decision.retry_after_seconds else None
            conn.execute(
                """UPDATE tasks SET state=?,strategy_version=strategy_version+?,total_attempts=?,worker_attempts=?,
                   supervisor_attempts=?,next_run_at=?,lease_owner=NULL,lease_expires_at=NULL,last_failure_class=?,
                   last_error=?,version=version+1,updated_at=? WHERE task_id=? AND version=?""",
                (
                    decision.next_state, decision.strategy_delta, total, worker, supervisor, next_run,
                    failure_class.upper(), error[:4000], _iso_now(), task_id, task["version"],
                ),
            )
            self._append_event_tx(
                conn, task_id=task_id, event_type="FAILURE_ROUTED",
                payload={
                    "role": role, "failure_class": failure_class.upper(), "error": error[:1000],
                    "decision": decision.to_dict(), "actor": actor,
                },
                idempotency_key=idempotency_key,
            )
            conn.execute("COMMIT")
            return {"task": self.get_task(task_id), "decision": decision.to_dict(), "idempotent_replay": False}
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def record_model_run(
        self,
        *,
        task_id: str,
        role: str,
        model_id: str,
        prompt_version: str,
        context_hash: str,
        status: str,
        session_id: str | None = None,
        reasoning_effort: str | None = None,
        head_sha: str | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        output_hash: str | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        run_id = run_id or f"run-{uuid.uuid4()}"
        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO model_runs(run_id,task_id,role,session_id,model_id,reasoning_effort,prompt_version,
                   context_hash,head_sha,status,input_tokens,output_tokens,output_hash,created_at,completed_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    run_id, task_id, role, session_id, model_id, reasoning_effort, prompt_version,
                    context_hash, head_sha, status, input_tokens, output_tokens, output_hash,
                    _iso_now(), _iso_now() if status in {"COMPLETED", "FAILED"} else None,
                ),
            )
            return dict(conn.execute("SELECT * FROM model_runs WHERE run_id=?", (run_id,)).fetchone())
        finally:
            conn.close()

    def get_model_run(self, run_id: str) -> dict[str, Any]:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM model_runs WHERE run_id=?", (run_id,)).fetchone()
            if not row:
                raise KeyError(run_id)
            return dict(row)
        finally:
            conn.close()

    def list_model_runs(self, *, task_id: str, role: str | None = None, head_sha: str | None = None) -> list[dict[str, Any]]:
        clauses = ["task_id=?"]
        values: list[Any] = [task_id]
        if role is not None:
            clauses.append("role=?")
            values.append(role)
        if head_sha is not None:
            clauses.append("head_sha=?")
            values.append(head_sha)
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM model_runs WHERE " + " AND ".join(clauses) + " ORDER BY created_at,run_id", values
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def register_evidence(
        self,
        *,
        evidence_id: str,
        task_id: str,
        head_sha: str,
        evidence_type: str,
        trust_level: str,
        status: str,
        producer: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Register immutable, SHA-bound evidence before model approval.

        Evidence identifiers are idempotent but immutable: replaying the same
        record succeeds, while reusing an identifier for different material is
        rejected. This prevents a model from approving against invented or
        stale CI identifiers.
        """

        trust_levels = {f"E{index}" for index in range(7)}
        if trust_level not in trust_levels:
            raise ValueError("Unknown evidence trust level")
        if status not in {"PASSED", "APPROVED", "FAILED", "INCONCLUSIVE", "REVOKED"}:
            raise ValueError("Unknown evidence status")
        material = {
            "evidence_id": evidence_id,
            "task_id": task_id,
            "head_sha": head_sha,
            "evidence_type": evidence_type,
            "trust_level": trust_level,
            "status": status,
            "producer": producer,
            "payload": payload or {},
        }
        record_hash = sha256_bytes(canonical_json(material))
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT * FROM evidence_registry WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
            if existing:
                if existing["record_hash"] != record_hash:
                    raise ValueError("Evidence identifier already exists with different material")
                conn.execute("COMMIT")
                return dict(existing) | {"idempotent_replay": True}
            if not conn.execute("SELECT 1 FROM tasks WHERE task_id=?", (task_id,)).fetchone():
                raise KeyError(task_id)
            conn.execute(
                """INSERT INTO evidence_registry(
                       evidence_id,task_id,head_sha,evidence_type,trust_level,status,producer,payload_json,record_hash,created_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    evidence_id, task_id, head_sha, evidence_type, trust_level,
                    status, producer, canonical_json(payload or {}).decode("utf-8"), record_hash, _iso_now(),
                ),
            )
            conn.execute("COMMIT")
            row = conn.execute(
                "SELECT * FROM evidence_registry WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
            return dict(row) | {"idempotent_replay": False}
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def list_evidence(self, *, task_id: str, head_sha: str | None = None) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            if head_sha is None:
                rows = conn.execute(
                    "SELECT * FROM evidence_registry WHERE task_id=? ORDER BY created_at,evidence_id", (task_id,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM evidence_registry WHERE task_id=? AND head_sha=? ORDER BY created_at,evidence_id",
                    (task_id, head_sha),
                ).fetchall()
            result: list[dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                item["payload"] = json.loads(item.pop("payload_json", "{}") or "{}")
                result.append(item)
            return result
        finally:
            conn.close()

    @staticmethod
    def _evidence_rank(trust_level: str) -> int:
        try:
            return int(trust_level.removeprefix("E"))
        except ValueError as exc:
            raise ValueError("Invalid evidence trust level") from exc

    def record_approval(
        self,
        *,
        task_id: str,
        role: str,
        session_id: str,
        head_sha: str,
        diff_hash: str,
        evidence_refs: list[str],
        decision: str,
    ) -> dict[str, Any]:
        if decision not in {"APPROVE", "REPAIR", "REPLAN", "TAKEOVER", "ROLLBACK", "QUARANTINE"}:
            raise ValueError("Unsupported approval decision")
        # Enforce separation: a session that implemented the same SHA cannot be
        # the independent approver.
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conflict = conn.execute(
                """SELECT 1 FROM model_runs WHERE task_id=? AND session_id=? AND head_sha=?
                   AND role IN ('worker','supervisor_takeover') AND status='COMPLETED' LIMIT 1""",
                (task_id, session_id, head_sha),
            ).fetchone()
            if conflict and role in {"supervisor", "closure"} and decision == "APPROVE":
                raise PermissionError("The implementing session cannot independently approve the same SHA")

            takeover = conn.execute(
                """SELECT 1 FROM model_runs WHERE task_id=? AND head_sha=?
                   AND role='supervisor_takeover' AND status='COMPLETED' LIMIT 1""",
                (task_id, head_sha),
            ).fetchone()
            if takeover and decision == "APPROVE" and role != "closure":
                raise PermissionError("A fresh closure reviewer must approve a SHA implemented during supervisor takeover")

            normalized_refs = sorted(set(evidence_refs))
            if decision == "APPROVE":
                if not normalized_refs:
                    raise ValueError("Approval requires registered evidence")
                placeholders = ",".join("?" for _ in normalized_refs)
                rows = conn.execute(
                    f"""SELECT * FROM evidence_registry
                        WHERE evidence_id IN ({placeholders})""",
                    normalized_refs,
                ).fetchall()
                by_id = {row["evidence_id"]: row for row in rows}
                missing = [ref for ref in normalized_refs if ref not in by_id]
                if missing:
                    raise ValueError(f"Unknown evidence references: {', '.join(missing)}")
                invalid = [
                    ref for ref, row in by_id.items()
                    if row["task_id"] != task_id
                    or row["head_sha"] != head_sha
                    or row["status"] != "PASSED"
                    or self._evidence_rank(row["trust_level"]) < 3
                ]
                if invalid:
                    raise ValueError(
                        "Approval evidence must be PASSED, E3+, and bound to the exact task and head SHA: "
                        + ", ".join(sorted(invalid))
                    )
            approval_id = f"approval-{uuid.uuid4()}"
            conn.execute(
                """INSERT INTO approvals(approval_id,task_id,role,session_id,head_sha,diff_hash,evidence_refs_json,decision,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (approval_id, task_id, role, session_id, head_sha, diff_hash, json.dumps(normalized_refs), decision, _iso_now()),
            )
            conn.execute("COMMIT")
            return dict(conn.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone())
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def record_approval_from_run(
        self,
        *,
        reviewer_run_id: str,
        head_sha: str,
        diff_hash: str,
        evidence_refs: list[str],
        decision: str,
    ) -> dict[str, Any]:
        """Record a decision using immutable reviewer-run identity from the store.

        Callers cannot invent role/session/task values. The run must be complete,
        bound to the exact SHA, and represent a review-capable role.
        """
        run = self.get_model_run(reviewer_run_id)
        if run["status"] != "COMPLETED":
            raise ValueError("Reviewer run is not completed")
        if run.get("head_sha") != head_sha:
            raise ValueError("Reviewer run head SHA mismatch")
        if run["role"] not in {
            "supervisor", "closure", "security_reviewer", "data_reviewer",
            "release_advisor", "plan_adjudicator",
        }:
            raise PermissionError("Model run role is not authorized to issue this decision")
        if not run.get("session_id"):
            raise ValueError("Reviewer run lacks a durable session identity")
        approval = self.record_approval(
            task_id=run["task_id"], role=run["role"], session_id=run["session_id"],
            head_sha=head_sha, diff_hash=diff_hash, evidence_refs=evidence_refs, decision=decision,
        )
        return approval | {"reviewer_run_id": reviewer_run_id, "reviewer_model_id": run["model_id"]}

    def validate_approval(
        self,
        approval_id: str,
        *,
        current_head_sha: str,
        current_diff_hash: str,
    ) -> dict[str, Any]:
        """Revalidate an approval immediately before a governed transition."""

        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
            if not row:
                raise KeyError(approval_id)
            approval = dict(row)
            refs = json.loads(approval["evidence_refs_json"])
            errors: list[str] = []
            if approval["head_sha"] != current_head_sha:
                errors.append("Approval head SHA is stale")
            if approval["diff_hash"] != current_diff_hash:
                errors.append("Approval diff hash is stale")
            for evidence_id in refs:
                evidence = conn.execute(
                    "SELECT * FROM evidence_registry WHERE evidence_id=?", (evidence_id,)
                ).fetchone()
                if not evidence:
                    errors.append(f"Evidence disappeared: {evidence_id}")
                    continue
                if evidence["task_id"] != approval["task_id"] or evidence["head_sha"] != current_head_sha:
                    errors.append(f"Evidence is stale or cross-task: {evidence_id}")
                if evidence["status"] != "PASSED" or self._evidence_rank(evidence["trust_level"]) < 3:
                    errors.append(f"Evidence is no longer authoritative: {evidence_id}")
            return {"valid": not errors, "approval": approval, "evidence_refs": refs, "errors": errors}
        finally:
            conn.close()

    def system_status(self) -> dict[str, Any]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT state,COUNT(*) AS count FROM tasks GROUP BY state").fetchall()
            counts = {row["state"]: int(row["count"]) for row in rows}
            runnable = sum(counts.get(state, 0) for state in RUNNABLE_STATES)
            delayed = sum(counts.get(state, 0) for state in DELAYED_STATES)
            terminal = sum(counts.get(state, 0) for state in TERMINAL_STATES)
            return {
                "database": str(self.path),
                "states": counts,
                "runnable_tasks": runnable,
                "delayed_or_quarantined_tasks": delayed,
                "terminal_tasks": terminal,
                "never_idle_semantics": "The scheduler claims another runnable task when one task is delayed or quarantined.",
                "globally_blocked": runnable == 0 and delayed == 0 and sum(counts.values()) > terminal,
            }
        finally:
            conn.close()

    def verify_event_chain(self) -> dict[str, Any]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM task_events ORDER BY sequence").fetchall()
            errors: list[str] = []
            previous = "sha256:" + "0" * 64
            expected = 1
            for row in rows:
                event = self._event_row(row)
                if event["sequence"] != expected:
                    errors.append(f"Sequence gap at {event['sequence']}; expected {expected}")
                if event["previous_hash"] != previous:
                    errors.append(f"Previous hash mismatch at {event['sequence']}")
                material = {k: v for k, v in event.items() if k != "record_hash"}
                if _event_hash(material) != event["record_hash"]:
                    errors.append(f"Record hash mismatch at {event['sequence']}")
                previous = event["record_hash"]
                expected += 1
            return {"valid": not errors, "events": len(rows), "head_hash": previous, "errors": errors}
        finally:
            conn.close()
