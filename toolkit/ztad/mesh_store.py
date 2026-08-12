from __future__ import annotations

import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .loop_guard import AttemptFingerprint, ProgressSnapshot, evaluate_progress
from .util import canonical_json, sha256_bytes

MESH_RUNNABLE_STATES = {"READY", "RETRY_READY"}
MESH_TERMINAL_STATES = {"SUCCEEDED", "FAILED", "QUARANTINED", "CANCELLED", "SUPERSEDED"}
MESH_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _future(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _scope_root(pattern: str) -> str:
    value = pattern.replace("\\", "/").strip("/").casefold()
    parts = []
    for part in value.split("/"):
        if any(char in part for char in "*?["):
            break
        parts.append(part)
    return "/".join(parts) or "*"


def _scopes_overlap(left: str, right: str) -> bool:
    if "*" in {left, right}:
        return True
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


@dataclass(frozen=True)
class MeshNodeSpec:
    node_id: str
    task_id: str
    title: str
    task_family: str
    role: str
    risk: str
    write_access: bool
    scopes: tuple[str, ...]
    prompt_path: str
    output_schema: str
    metadata: dict[str, Any]
    priority: int = 0
    dependencies: tuple[str, ...] = ()
    idempotency_key: str | None = None

    @classmethod
    def create(
        cls,
        *,
        task_id: str,
        title: str,
        task_family: str,
        role: str,
        risk: str,
        write_access: bool,
        scopes: Iterable[str],
        prompt_path: str,
        output_schema: str,
        priority: int = 0,
        metadata: dict[str, Any] | None = None,
        dependencies: Iterable[str] = (),
        node_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> "MeshNodeSpec":
        node_id = node_id or f"node-{uuid.uuid4()}"
        if not MESH_ID_RE.fullmatch(node_id):
            raise ValueError("Mesh node_id must be a bounded path-free identifier")
        if not task_id or len(task_id) > 256 or "\x00" in task_id:
            raise ValueError("Mesh task_id is invalid")
        if not title.strip() or len(title) > 512:
            raise ValueError("Mesh node title is invalid")
        if not task_family or not role:
            raise ValueError("Mesh task_family and role are required")
        return cls(
            node_id=node_id, task_id=task_id, title=title, task_family=task_family,
            role=role, risk=risk, write_access=write_access,
            scopes=tuple(sorted(set(scopes))), prompt_path=prompt_path,
            output_schema=output_schema, metadata=dict(metadata or {}), priority=priority,
            dependencies=tuple(sorted(set(dependencies))), idempotency_key=idempotency_key,
        )


class MeshStore:
    """Transactional DAG, lease, scope-lock, attempt, and model-performance store."""

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
                CREATE TABLE IF NOT EXISTS mesh_nodes (
                    node_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    task_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    task_family TEXT NOT NULL,
                    role TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    write_access INTEGER NOT NULL,
                    scopes_json TEXT NOT NULL,
                    prompt_path TEXT NOT NULL,
                    output_schema TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL,
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    next_run_at TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    version INTEGER NOT NULL DEFAULT 1,
                    selected_registry_id TEXT,
                    selected_provider TEXT,
                    last_run_id TEXT,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_mesh_ready
                    ON mesh_nodes(state,next_run_at,lease_expires_at,priority,created_at);
                CREATE TABLE IF NOT EXISTS mesh_dependencies (
                    node_id TEXT NOT NULL,
                    depends_on TEXT NOT NULL,
                    PRIMARY KEY(node_id,depends_on),
                    FOREIGN KEY(node_id) REFERENCES mesh_nodes(node_id) ON DELETE CASCADE,
                    FOREIGN KEY(depends_on) REFERENCES mesh_nodes(node_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS mesh_scope_locks (
                    scope_root TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    PRIMARY KEY(scope_root,node_id),
                    FOREIGN KEY(node_id) REFERENCES mesh_nodes(node_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_scope_locks_expiry ON mesh_scope_locks(expires_at);
                CREATE TABLE IF NOT EXISTS mesh_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    signature TEXT NOT NULL UNIQUE,
                    strategy_hash TEXT NOT NULL,
                    prompt_hash TEXT NOT NULL,
                    context_hash TEXT NOT NULL,
                    head_sha TEXT NOT NULL,
                    diff_hash TEXT NOT NULL,
                    failing_evidence_hash TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    failing_checks INTEGER NOT NULL,
                    blocking_findings INTEGER NOT NULL,
                    unknowns INTEGER NOT NULL,
                    evidence_count INTEGER NOT NULL,
                    progress_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(node_id) REFERENCES mesh_nodes(node_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_attempts_node ON mesh_attempts(node_id,created_at);
                CREATE TABLE IF NOT EXISTS model_performance (
                    registry_id TEXT NOT NULL,
                    task_family TEXT NOT NULL,
                    runs INTEGER NOT NULL,
                    successes INTEGER NOT NULL,
                    quality_sum REAL NOT NULL,
                    latency_sum REAL NOT NULL,
                    cost_sum REAL NOT NULL,
                    catalog_hash TEXT,
                    benchmark_suite_hash TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(registry_id,task_family)
                );
                CREATE TABLE IF NOT EXISTS provider_health (
                    provider TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    consecutive_failures INTEGER NOT NULL,
                    retry_after TEXT,
                    detail_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mesh_artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(node_id,artifact_type,sha256),
                    FOREIGN KEY(node_id) REFERENCES mesh_nodes(node_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_mesh_artifacts_node
                    ON mesh_artifacts(node_id,artifact_type,created_at);
                """
            )
            performance_columns = {row[1] for row in conn.execute("PRAGMA table_info(model_performance)").fetchall()}
            if "catalog_hash" not in performance_columns:
                conn.execute("ALTER TABLE model_performance ADD COLUMN catalog_hash TEXT")
            if "benchmark_suite_hash" not in performance_columns:
                conn.execute("ALTER TABLE model_performance ADD COLUMN benchmark_suite_hash TEXT")
        finally:
            conn.close()

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["write_access"] = bool(item["write_access"])
        item["scopes"] = json.loads(item.pop("scopes_json"))
        item["metadata"] = json.loads(item.pop("metadata_json"))
        return item

    @staticmethod
    def _validate_acyclic(nodes: Iterable[MeshNodeSpec]) -> None:
        specs = {node.node_id: node for node in nodes}
        graph = {node.node_id: set(node.dependencies) for node in specs.values()}
        for node_id, deps in graph.items():
            unknown = deps - set(specs)
            if unknown:
                raise ValueError(f"Node {node_id} has unknown dependencies: {sorted(unknown)}")
            if node_id in deps:
                raise ValueError("A node cannot depend on itself")
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in visiting:
                raise ValueError("Mesh graph contains a cycle")
            if node_id in visited:
                return
            visiting.add(node_id)
            for dep in graph[node_id]:
                visit(dep)
            visiting.remove(node_id)
            visited.add(node_id)

        for node_id in graph:
            visit(node_id)

    def submit_graph(self, nodes: Iterable[MeshNodeSpec]) -> list[dict[str, Any]]:
        items = list(nodes)
        if not items:
            return []
        self._validate_acyclic(items)
        now = _now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            for node in items:
                if node.risk not in {"R0", "R1", "R2", "R3", "R4"}:
                    raise ValueError(f"Unknown risk: {node.risk}")
                key = node.idempotency_key or sha256_bytes(canonical_json({
                    "task_id": node.task_id, "title": node.title, "family": node.task_family,
                    "role": node.role, "scopes": node.scopes, "dependencies": node.dependencies, "metadata": node.metadata,
                }))
                existing = conn.execute("SELECT node_id FROM mesh_nodes WHERE idempotency_key=?", (key,)).fetchone()
                if existing and existing["node_id"] != node.node_id:
                    raise ValueError("Idempotency key belongs to another node")
                conn.execute(
                    """INSERT OR IGNORE INTO mesh_nodes(
                       node_id,idempotency_key,task_id,title,task_family,role,risk,write_access,scopes_json,
                       prompt_path,output_schema,metadata_json,priority,state,created_at,updated_at
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        node.node_id, key, node.task_id, node.title, node.task_family, node.role, node.risk,
                        int(node.write_access), json.dumps(list(node.scopes), sort_keys=True), node.prompt_path,
                        node.output_schema, json.dumps(node.metadata, sort_keys=True), node.priority, "READY", now, now,
                    ),
                )
            for node in items:
                for dep in node.dependencies:
                    conn.execute(
                        "INSERT OR IGNORE INTO mesh_dependencies(node_id,depends_on) VALUES(?,?)",
                        (node.node_id, dep),
                    )
            conn.execute("COMMIT")
            return [self.get_node(node.node_id) for node in items]
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def get_node(self, node_id: str) -> dict[str, Any]:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM mesh_nodes WHERE node_id=?", (node_id,)).fetchone()
            if not row:
                raise KeyError(node_id)
            item = self._row(row)
            deps = conn.execute("SELECT depends_on FROM mesh_dependencies WHERE node_id=? ORDER BY depends_on", (node_id,)).fetchall()
            item["dependencies"] = [row["depends_on"] for row in deps]
            return item
        finally:
            conn.close()

    def list_nodes(self, *, task_id: str | None = None) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM mesh_nodes WHERE (? IS NULL OR task_id=?) ORDER BY priority DESC,created_at,node_id",
                (task_id, task_id),
            ).fetchall()
            return [self.get_node(row["node_id"]) for row in rows]
        finally:
            conn.close()

    def recover_expired(self) -> int:
        now = _now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT node_id FROM mesh_nodes WHERE state='RUNNING' AND lease_expires_at IS NOT NULL AND lease_expires_at<=?",
                (now,),
            ).fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE mesh_nodes SET state='RETRY_READY',lease_owner=NULL,lease_expires_at=NULL,last_error='lease_expired',version=version+1,updated_at=? WHERE node_id=?",
                    (now, row["node_id"]),
                )
                conn.execute("DELETE FROM mesh_scope_locks WHERE node_id=?", (row["node_id"],))
            conn.execute("DELETE FROM mesh_scope_locks WHERE expires_at<=?", (now,))
            conn.execute("COMMIT")
            return len(rows)
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def _dependencies_satisfied(self, conn: sqlite3.Connection, node_id: str) -> bool:
        row = conn.execute(
            """SELECT COUNT(*) AS blocked FROM mesh_dependencies d
               JOIN mesh_nodes n ON n.node_id=d.depends_on
               WHERE d.node_id=? AND n.state!='SUCCEEDED'""",
            (node_id,),
        ).fetchone()
        return int(row["blocked"]) == 0

    def _can_lock(self, conn: sqlite3.Connection, roots: list[str]) -> bool:
        existing = [row["scope_root"] for row in conn.execute("SELECT scope_root FROM mesh_scope_locks WHERE expires_at>?", (_now(),)).fetchall()]
        return not any(_scopes_overlap(root, held) for root in roots for held in existing)

    def claim_ready(self, owner: str, *, limit: int = 1, lease_seconds: int = 300) -> list[dict[str, Any]]:
        if limit < 1:
            return []
        now = _now()
        expires = _future(lease_seconds)
        conn = self._connect()
        claimed: list[str] = []
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM mesh_scope_locks WHERE expires_at<=?", (now,))
            candidates = conn.execute(
                """SELECT * FROM mesh_nodes
                   WHERE state IN ('READY','RETRY_READY')
                     AND (next_run_at IS NULL OR next_run_at<=?)
                     AND (lease_expires_at IS NULL OR lease_expires_at<=?)
                   ORDER BY priority DESC,created_at,node_id""",
                (now, now),
            ).fetchall()
            for row in candidates:
                if len(claimed) >= limit:
                    break
                if not self._dependencies_satisfied(conn, row["node_id"]):
                    continue
                scopes = json.loads(row["scopes_json"])
                roots = sorted({_scope_root(item) for item in scopes}) if row["write_access"] else []
                if roots and not self._can_lock(conn, roots):
                    continue
                changed = conn.execute(
                    """UPDATE mesh_nodes SET state='RUNNING',lease_owner=?,lease_expires_at=?,version=version+1,updated_at=?
                       WHERE node_id=? AND version=?""",
                    (owner, expires, now, row["node_id"], row["version"]),
                ).rowcount
                if changed != 1:
                    continue
                for root in roots:
                    conn.execute(
                        "INSERT INTO mesh_scope_locks(scope_root,node_id,owner,expires_at) VALUES(?,?,?,?)",
                        (root, row["node_id"], owner, expires),
                    )
                claimed.append(row["node_id"])
            conn.execute("COMMIT")
            return [self.get_node(node_id) for node_id in claimed]
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def finish_node(
        self,
        node_id: str,
        *,
        owner: str,
        success: bool,
        run_id: str,
        registry_id: str,
        provider: str,
        error: str | None = None,
        retry_after_seconds: int = 0,
        quarantine: bool = False,
    ) -> dict[str, Any]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM mesh_nodes WHERE node_id=?", (node_id,)).fetchone()
            if not row:
                raise KeyError(node_id)
            if row["lease_owner"] != owner:
                raise PermissionError("Only the lease owner can finish a mesh node")
            if success:
                state, next_run = "SUCCEEDED", None
            elif quarantine:
                state, next_run = "QUARANTINED", _future(max(retry_after_seconds, 1800))
            else:
                state = "RETRY_READY" if retry_after_seconds <= 0 else "RETRY_READY"
                next_run = _future(retry_after_seconds) if retry_after_seconds else None
            conn.execute(
                """UPDATE mesh_nodes SET state=?,next_run_at=?,lease_owner=NULL,lease_expires_at=NULL,
                   attempts=attempts+1,selected_registry_id=?,selected_provider=?,last_run_id=?,last_error=?,
                   version=version+1,updated_at=? WHERE node_id=?""",
                (state, next_run, registry_id, provider, run_id, (error or "")[:4000] or None, _now(), node_id),
            )
            conn.execute("DELETE FROM mesh_scope_locks WHERE node_id=?", (node_id,))
            conn.execute("COMMIT")
            return self.get_node(node_id)
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def record_attempt(
        self,
        *,
        node_id: str,
        fingerprint: AttemptFingerprint,
        snapshot: ProgressSnapshot,
    ) -> dict[str, Any]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM mesh_attempts WHERE signature=?", (fingerprint.signature,)).fetchone():
                raise ValueError("Repeated attempt signature: no new strategy, context, diff, or failing evidence")
            previous = conn.execute(
                "SELECT * FROM mesh_attempts WHERE node_id=? ORDER BY created_at DESC,attempt_id DESC LIMIT 1",
                (node_id,),
            ).fetchone()
            previous_snapshot = None
            if previous:
                previous_snapshot = ProgressSnapshot(
                    failing_checks=int(previous["failing_checks"]), blocking_findings=int(previous["blocking_findings"]),
                    unknowns=int(previous["unknowns"]), evidence_count=int(previous["evidence_count"]),
                    strategy_hash=previous["strategy_hash"], context_hash=previous["context_hash"],
                    provider=previous["provider"], model=previous["model"],
                )
            progress = evaluate_progress(previous_snapshot, snapshot)
            attempt_id = f"attempt-{uuid.uuid4()}"
            conn.execute(
                """INSERT INTO mesh_attempts(
                   attempt_id,node_id,signature,strategy_hash,prompt_hash,context_hash,head_sha,diff_hash,
                   failing_evidence_hash,provider,model,failing_checks,blocking_findings,unknowns,evidence_count,
                   progress_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    attempt_id, node_id, fingerprint.signature, fingerprint.strategy_hash,
                    fingerprint.prompt_hash, fingerprint.context_hash, fingerprint.head_sha,
                    fingerprint.diff_hash, fingerprint.failing_evidence_hash, snapshot.provider,
                    snapshot.model, snapshot.failing_checks, snapshot.blocking_findings,
                    snapshot.unknowns, snapshot.evidence_count, json.dumps(progress, sort_keys=True), _now(),
                ),
            )
            conn.execute("COMMIT")
            return {"attempt_id": attempt_id, "signature": fingerprint.signature, **progress}
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def direct_dependencies(self, node_id: str) -> list[str]:
        conn = self._connect()
        try:
            if not conn.execute("SELECT 1 FROM mesh_nodes WHERE node_id=?", (node_id,)).fetchone():
                raise KeyError(node_id)
            return [
                row["depends_on"] for row in conn.execute(
                    "SELECT depends_on FROM mesh_dependencies WHERE node_id=? ORDER BY depends_on", (node_id,)
                ).fetchall()
            ]
        finally:
            conn.close()

    def dependency_closure(self, node_id: str) -> list[str]:
        """Return transitive dependencies in deterministic topological order."""
        conn = self._connect()
        try:
            if not conn.execute("SELECT 1 FROM mesh_nodes WHERE node_id=?", (node_id,)).fetchone():
                raise KeyError(node_id)
            rows = conn.execute("SELECT node_id,depends_on FROM mesh_dependencies").fetchall()
            graph: dict[str, list[str]] = {}
            for row in rows:
                graph.setdefault(row["node_id"], []).append(row["depends_on"])
            ordered: list[str] = []
            visited: set[str] = set()

            def visit(current: str) -> None:
                for dependency in sorted(graph.get(current, [])):
                    if dependency in visited:
                        continue
                    visit(dependency)
                    visited.add(dependency)
                    ordered.append(dependency)

            visit(node_id)
            return ordered
        finally:
            conn.close()

    def register_artifact(
        self,
        *,
        node_id: str,
        artifact_type: str,
        path: str,
        sha256: str,
        metadata: dict[str, Any] | None = None,
        artifact_id: str | None = None,
    ) -> dict[str, Any]:
        if not artifact_type or not path or not sha256.startswith("sha256:"):
            raise ValueError("Artifact type, path and sha256 are required")
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            node = conn.execute("SELECT task_id FROM mesh_nodes WHERE node_id=?", (node_id,)).fetchone()
            if not node:
                raise KeyError(node_id)
            existing = conn.execute(
                "SELECT * FROM mesh_artifacts WHERE node_id=? AND artifact_type=? AND sha256=?",
                (node_id, artifact_type, sha256),
            ).fetchone()
            if existing:
                conn.execute("COMMIT")
                item = dict(existing)
                item["metadata"] = json.loads(item.pop("metadata_json"))
                return item | {"idempotent_replay": True}
            artifact_id = artifact_id or f"artifact-{uuid.uuid4()}"
            conn.execute(
                """INSERT INTO mesh_artifacts(artifact_id,node_id,task_id,artifact_type,path,sha256,metadata_json,created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (artifact_id, node_id, node["task_id"], artifact_type, path, sha256, json.dumps(metadata or {}, sort_keys=True), _now()),
            )
            conn.execute("COMMIT")
            row = conn.execute("SELECT * FROM mesh_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
            item = dict(row)
            item["metadata"] = json.loads(item.pop("metadata_json"))
            return item | {"idempotent_replay": False}
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def list_artifacts(
        self, *, node_id: str | None = None, task_id: str | None = None, artifact_type: str | None = None
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        values: list[Any] = []
        for column, value in (("node_id", node_id), ("task_id", task_id), ("artifact_type", artifact_type)):
            if value is not None:
                clauses.append(f"{column}=?")
                values.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM mesh_artifacts" + where + " ORDER BY created_at,artifact_id", values
            ).fetchall()
            result: list[dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                item["metadata"] = json.loads(item.pop("metadata_json"))
                result.append(item)
            return result
        finally:
            conn.close()

    def dependency_artifacts(
        self, node_id: str, *, artifact_types: Iterable[str] = ("COMBINED_PATCH", "PATCH"),
        transitive: bool = True,
    ) -> list[dict[str, Any]]:
        dependencies = self.dependency_closure(node_id) if transitive else self.direct_dependencies(node_id)
        allowed = set(artifact_types)
        artifacts: list[dict[str, Any]] = []
        for dependency in dependencies:
            candidates = [
                item for item in self.list_artifacts(node_id=dependency) if item["artifact_type"] in allowed
            ]
            latest_by_type: dict[str, dict[str, Any]] = {}
            for item in candidates:
                latest_by_type[item["artifact_type"]] = item
            artifacts.extend(latest_by_type[key] for key in sorted(latest_by_type))
        if allowed & {"COMBINED_PATCH", "PATCH"}:
            combined = [item for item in artifacts if item["artifact_type"] == "COMBINED_PATCH"]
            if combined:
                return [combined[-1]]
        return artifacts

    def record_model_performance(
        self,
        *,
        registry_id: str,
        task_family: str,
        success: bool,
        quality: float,
        latency: float,
        cost: float,
        catalog_hash: str | None = None,
        benchmark_suite_hash: str | None = None,
    ) -> None:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT catalog_hash,benchmark_suite_hash FROM model_performance WHERE registry_id=? AND task_family=?",
                (registry_id, task_family),
            ).fetchone()
            if existing and catalog_hash is not None and existing["catalog_hash"] != catalog_hash:
                conn.execute("DELETE FROM model_performance WHERE registry_id=? AND task_family=?", (registry_id, task_family))
                existing = None
            if existing and benchmark_suite_hash is not None and existing["benchmark_suite_hash"] != benchmark_suite_hash:
                conn.execute("DELETE FROM model_performance WHERE registry_id=? AND task_family=?", (registry_id, task_family))
                existing = None
            conn.execute(
                """INSERT INTO model_performance(
                       registry_id,task_family,runs,successes,quality_sum,latency_sum,cost_sum,
                       catalog_hash,benchmark_suite_hash,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(registry_id,task_family) DO UPDATE SET
                     runs=runs+1,successes=successes+excluded.successes,
                     quality_sum=quality_sum+excluded.quality_sum,
                     latency_sum=latency_sum+excluded.latency_sum,
                     cost_sum=cost_sum+excluded.cost_sum,
                     catalog_hash=COALESCE(excluded.catalog_hash,catalog_hash),
                     benchmark_suite_hash=COALESCE(excluded.benchmark_suite_hash,benchmark_suite_hash),
                     updated_at=excluded.updated_at""",
                (registry_id, task_family, 1, int(success), quality, latency, cost, catalog_hash, benchmark_suite_hash, _now()),
            )
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def performance_overrides(
        self, task_family: str, *, catalog_hash: str | None = None, benchmark_suite_hash: str | None = None,
        minimum_runs: int = 1,
    ) -> dict[str, dict[str, float]]:
        if minimum_runs < 1:
            raise ValueError("minimum_runs must be at least 1")
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM model_performance WHERE task_family=?", (task_family,)).fetchall()
            result: dict[str, dict[str, float]] = {}
            for row in rows:
                if catalog_hash is not None and row["catalog_hash"] != catalog_hash:
                    continue
                if benchmark_suite_hash is not None and row["benchmark_suite_hash"] != benchmark_suite_hash:
                    continue
                runs = max(1, int(row["runs"]))
                if runs < minimum_runs:
                    continue
                result[row["registry_id"]] = {
                    "quality": float(row["quality_sum"]) / runs,
                    "reliability": float(row["successes"]) / runs,
                    "latency_index": max(0.01, float(row["latency_sum"]) / runs),
                    "cost_index": max(0.01, float(row["cost_sum"]) / runs),
                    "runs": float(runs),
                }
            return result
        finally:
            conn.close()

    def reactivate_quarantined(
        self, node_id: str, *, change_token: str, reason: str
    ) -> dict[str, Any]:
        """Reactivate one contained node only after a verifiable condition changed.

        The token is stored in node metadata and cannot be replayed. Attempts are not
        reset, so an unchanged failure returns to quarantine quickly instead of looping.
        """
        if not change_token or len(change_token) > 512 or any(ord(ch) < 32 for ch in change_token):
            raise ValueError("change_token must be a bounded printable value")
        if not reason.strip() or len(reason) > 1000:
            raise ValueError("reactivation reason is required and bounded")
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM mesh_nodes WHERE node_id=?", (node_id,)).fetchone()
            if not row:
                raise KeyError(node_id)
            if row["state"] != "QUARANTINED":
                raise ValueError("Only a quarantined node can be reactivated")
            metadata = json.loads(row["metadata_json"])
            if metadata.get("last_reactivation_token") == change_token:
                raise ValueError("Reactivation change_token was already used")
            metadata.update({
                "last_reactivation_token": change_token,
                "last_reactivation_reason": reason.strip(),
                "last_reactivated_at": _now(),
            })
            conn.execute(
                """UPDATE mesh_nodes SET state='RETRY_READY',next_run_at=NULL,last_error=NULL,
                   metadata_json=?,version=version+1,updated_at=? WHERE node_id=?""",
                (json.dumps(metadata, sort_keys=True), _now(), node_id),
            )
            conn.execute("COMMIT")
            return self.get_node(node_id)
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def status(self) -> dict[str, Any]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT state,COUNT(*) AS count FROM mesh_nodes GROUP BY state").fetchall()
            states = {row["state"]: int(row["count"]) for row in rows}
            blocked_deps = int(conn.execute(
                """SELECT COUNT(DISTINCT d.node_id) AS count FROM mesh_dependencies d
                   JOIN mesh_nodes n ON n.node_id=d.depends_on WHERE n.state!='SUCCEEDED'"""
            ).fetchone()["count"])
            now = _now()
            runnable_now = int(conn.execute(
                """SELECT COUNT(*) AS count FROM mesh_nodes
                   WHERE state IN ('READY','RETRY_READY') AND (next_run_at IS NULL OR next_run_at<=?)""",
                (now,),
            ).fetchone()["count"])
            delayed_retry = int(conn.execute(
                """SELECT COUNT(*) AS count FROM mesh_nodes
                   WHERE state='RETRY_READY' AND next_run_at>?""", (now,),
            ).fetchone()["count"])
            return {
                "database": str(self.path),
                "states": states,
                "ready": sum(states.get(item, 0) for item in MESH_RUNNABLE_STATES),
                "runnable_now": runnable_now,
                "delayed_retry": delayed_retry,
                "quarantined": states.get("QUARANTINED", 0),
                "running": states.get("RUNNING", 0),
                "blocked_by_dependencies": blocked_deps,
                "terminal": sum(states.get(item, 0) for item in MESH_TERMINAL_STATES),
                "active_scope_locks": int(conn.execute("SELECT COUNT(*) AS count FROM mesh_scope_locks WHERE expires_at>?", (now,)).fetchone()["count"]),
            }
        finally:
            conn.close()
