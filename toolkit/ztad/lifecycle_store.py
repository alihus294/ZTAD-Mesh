from __future__ import annotations

"""Controller-owned, append-only authoritative lifecycle storage."""

import copy
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .bug_protocol import VALID_DOMAINS
from .controller_context import (
    LIFECYCLE_CONTROLLER_ID,
    LIFECYCLE_CONTROLLER_TYPE,
    ControllerRuntimeContext,
    validate_controller_identity,
)
from .evidence import validate_evidence_record
from .risk import RISK_ORDER, RISK_TO_CLASS
from .subject import (
    MATERIAL_SUBJECT_FIELDS,
    apply_subject_update,
    material_subject_changes,
    subject_fingerprint,
    subject_from_record,
    validate_subject_epoch_transition,
    validate_subject,
)
from .util import canonical_json, sha256_bytes, utc_now
from .trust import TrustRootAuthority, is_host_accepted_trust_roots, trust_root_payload

GENESIS_HASH = "sha256:" + "0" * 64
CODE_LIFECYCLE = (
    "UNVERIFIED_REPORT",
    "SOURCE_OF_TRUTH_RESOLVED",
    "ISSUE_CLASSIFIED",
    "BUG_REPRODUCED",
    "ROOT_CAUSE_PROVEN",
    "BLAST_RADIUS_MAPPED",
    "CHANGE_PLANNED",
    "PATCH_IMPLEMENTED",
    "REGRESSION_TEST_PROVEN",
    "TARGETED_VALIDATION_PASS",
    "REGRESSION_VALIDATION_PASS",
    "DIFF_FORENSICS_PASS",
    "INDEPENDENT_REVIEW_PASS",
    "CI_PASS",
    "STAGING_PASS",
    "READY_FOR_OWNER_RELEASE",
    "PRODUCTION_RELEASED",
    "POST_DEPLOY_VERIFIED",
    "CLOSED",
)
AUTHORITATIVE_STATES = CODE_LIFECYCLE + ("RESOLVED_NO_CODE",)
STATE_TRANSITIONS = {current: next_state for current, next_state in zip(CODE_LIFECYCLE, CODE_LIFECYCLE[1:])}
TERMINAL_STATES = {"CLOSED", "RESOLVED_NO_CODE"}
PROTECTED_TRANSITION_STATES = {
    "READY_FOR_OWNER_RELEASE",
    "PRODUCTION_RELEASED",
    "POST_DEPLOY_VERIFIED",
    "CLOSED",
    "RESOLVED_NO_CODE",
    "ROLLBACK_REQUIRED",
}
TRANSITION_AUTHORIZATION_TYPE = "LIFECYCLE_TRANSITION_AUTHORIZATION"
TRANSITION_AUTHORIZATION_PRODUCER = "platform:lifecycle-controller"
ALLOWED_TRANSITIONS = {state: {next_state} for state, next_state in STATE_TRANSITIONS.items()}
ALLOWED_TRANSITIONS["ISSUE_CLASSIFIED"].add("RESOLVED_NO_CODE")
ALLOWED_TRANSITIONS["PRODUCTION_RELEASED"].add("ROLLBACK_REQUIRED")
ALLOWED_TRANSITIONS["POST_DEPLOY_VERIFIED"].add("ROLLBACK_REQUIRED")
ALLOWED_TRANSITIONS["ROLLBACK_REQUIRED"] = {"CHANGE_PLANNED", "CLOSED"}
ALLOWED_TRANSITIONS["CLOSED"] = set()
ALLOWED_TRANSITIONS["RESOLVED_NO_CODE"] = set()
SUBJECT_ALIAS_FIELDS = {"base_sha", "head_sha", "diff_hash"}
SUBJECT_MUTATION_FIELDS = set(MATERIAL_SUBJECT_FIELDS) | SUBJECT_ALIAS_FIELDS | {
    "subject_epoch",
    "subject_version",
    "subject_fingerprint",
    "subject_mutations",
    "historical_evidence_refs",
    "evidence_refs",
    "state",
    "resume_state",
    "blocked_target",
    "blockers",
    "final_state",
    "authoritative_lifecycle",
    "authority_store",
    "store_version",
    "store_record_hash",
    "store_binding",
}
LIFECYCLE_MUTATION_FIELDS = {
    "state",
    "last_completed_state",
    "resume_state",
    "blocked_target",
    "blockers",
    "risk",
    "risk_class",
    "risk_history",
    "evidence_refs",
    "final_state",
    "closure_class",
    "internal_execution_complete",
    "scheduler_state",
}


def _hash(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


EVENT_COMMITMENT_VERSION = 1


def event_commitment_material(event: dict[str, Any]) -> dict[str, Any]:
    """Return the event material that a signed transition commits to.

    The append-only hash and local MAC are derived values.  The signed
    transition authorization commits to every other event field, including
    the global sequence and predecessor hash.  This lets an independent
    bundle verifier detect an attacker who rewrites an early event and then
    recomputes the visible hash chain.
    """

    material = copy.deepcopy(event)
    for field in ("transition_authorization", "record_hash", "record_mac"):
        material.pop(field, None)
    material["event_commitment_version"] = EVENT_COMMITMENT_VERSION
    return material


def event_commitment(event: dict[str, Any]) -> str:
    return _hash(event_commitment_material(event))


class LifecycleStore:
    """Durable authority for one or more authoritative bug lifecycles.

    JSON lifecycle files can be exported for humans and interoperability, but
    every authoritative read and write goes through this store.  The event
    chain is global, monotonic, and checked on every read that requests
    verification.  Stale versions are rejected inside one immediate SQLite
    transaction.
    """

    def __init__(
        self,
        path: Path,
        *,
        authority_trust_roots: TrustRootAuthority | dict[str, Any] | None = None,
        controller_context: ControllerRuntimeContext | None = None,
    ):
        self.path = Path(path).resolve()
        self.authority_trust_roots = copy.deepcopy(authority_trust_roots)
        self.controller_context = controller_context or ControllerRuntimeContext.local_unverified()
        identity_errors = validate_controller_identity(self.controller_context)
        if identity_errors:
            raise PermissionError("Invalid lifecycle controller context: " + "; ".join(identity_errors))
        self.store_binding = "sha256:" + hashlib.sha256(
            str(self.path).casefold().encode("utf-8")
        ).hexdigest()
        self.seal_path = self.path.with_name(self.path.name + ".seal")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seal_key = self._load_or_create_seal_key()
        self._initialize()

    def _load_or_create_seal_key(self) -> bytes:
        if self.seal_path.is_symlink():
            raise PermissionError("Lifecycle seal key must not be a symlink")
        if self.seal_path.exists():
            if not self.seal_path.is_file():
                raise PermissionError("Lifecycle seal key must be a regular file")
            value = self.seal_path.read_bytes()
            if len(value) != 32:
                raise PermissionError("Lifecycle seal key has an invalid length")
            return value
        value = secrets.token_bytes(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(self.seal_path, flags, 0o600)
        try:
            os.write(descriptor, value)
        finally:
            os.close(descriptor)
        return value

    def _event_mac(self, record_hash: str) -> str:
        return "hmac-sha256:" + hmac.new(self._seal_key, record_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    def _authority_roots_payload(self) -> dict[str, Any] | None:
        return trust_root_payload(self.authority_trust_roots)

    def _authority_roots_are_host_accepted(self) -> bool:
        return is_host_accepted_trust_roots(self.authority_trust_roots)

    def _validate_accepted_evidence(
        self,
        records: Iterable[dict[str, Any]],
        *,
        case_id: str,
        subject: dict[str, Any],
        required_evidence: Iterable[str],
        accepted_evidence: Iterable[str],
    ) -> list[dict[str, Any]]:
        required = {str(item) for item in required_evidence}
        accepted = [str(item) for item in accepted_evidence]
        if len(accepted) != len(set(accepted)):
            raise PermissionError("Protected lifecycle evidence IDs must be unique")
        by_id: dict[str, dict[str, Any]] = {}
        for record in records:
            if not isinstance(record, dict) or not record.get("evidence_id"):
                raise PermissionError("Protected lifecycle evidence records must contain evidence_id")
            evidence_id = str(record["evidence_id"])
            if evidence_id in by_id:
                raise PermissionError("Protected lifecycle evidence IDs must be unique")
            by_id[evidence_id] = copy.deepcopy(record)
            if str(record.get("lifecycle_case_id") or "") != case_id:
                raise PermissionError(
                    "Protected lifecycle evidence must be bound to the exact lifecycle case"
                )
        missing = sorted(set(accepted) - set(by_id))
        if missing:
            raise PermissionError("Protected lifecycle transition references missing evidence: " + ", ".join(missing))
        validated: list[dict[str, Any]] = []
        for evidence_id in accepted:
            record = by_id[evidence_id]
            errors = validate_evidence_record(
                record,
                subject=subject,
                minimum_trust="E3",
                trust_roots=self.authority_trust_roots,
                require_authoritative_signature=True,
                require_affirmative_status=True,
            )
            if errors:
                raise PermissionError(
                    "Invalid protected lifecycle evidence " + evidence_id + ": " + "; ".join(errors)
                )
            if required and str(record.get("type") or "") not in required:
                raise PermissionError(
                    "Protected lifecycle evidence type is not required for this transition: "
                    + str(record.get("type") or "")
                )
            validated.append(record)
        return validated

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def _initialize(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS lifecycle_cases (
                    case_id TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    subject_epoch INTEGER NOT NULL,
                    state_json TEXT NOT NULL,
                    current_hash TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lifecycle_store_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lifecycle_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    actor TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    prior_state TEXT NOT NULL,
                    requested_state TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    required_evidence_json TEXT NOT NULL,
                    accepted_evidence_json TEXT NOT NULL,
                    rejected_evidence_json TEXT NOT NULL,
                    subject_json TEXT NOT NULL,
                    subject_epoch INTEGER NOT NULL,
                    subject_fingerprint TEXT NOT NULL,
                    policy_hash TEXT,
                    toolchain_hash TEXT,
                    risk_snapshot_json TEXT NOT NULL,
                    domain_snapshot_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    current_record_hash TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    record_hash TEXT NOT NULL UNIQUE,
                    record_mac TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES lifecycle_cases(case_id)
                );
                CREATE INDEX IF NOT EXISTS lifecycle_events_case ON lifecycle_events(case_id, sequence);
                CREATE TRIGGER IF NOT EXISTS lifecycle_events_no_update
                BEFORE UPDATE ON lifecycle_events
                BEGIN
                    SELECT RAISE(ABORT, 'lifecycle_events is append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS lifecycle_events_no_delete
                BEFORE DELETE ON lifecycle_events
                BEGIN
                    SELECT RAISE(ABORT, 'lifecycle_events is append-only');
                END;
                """
            )
            columns = {
                str(row["name"])
                for row in conn.execute("PRAGMA table_info(lifecycle_events)").fetchall()
            }
            if "record_mac" not in columns:
                conn.execute("ALTER TABLE lifecycle_events ADD COLUMN record_mac TEXT NOT NULL DEFAULT ''")
            existing_binding = conn.execute(
                "SELECT value FROM lifecycle_store_metadata WHERE key='store_binding'"
            ).fetchone()
            if existing_binding is None:
                conn.execute(
                    "INSERT INTO lifecycle_store_metadata(key,value) VALUES('store_binding',?)",
                    (self.store_binding,),
                )
            elif existing_binding["value"] != self.store_binding:
                # Keep the database open so a caller can inspect the failure,
                # but every verified read will reject this replayed database.
                pass
        finally:
            conn.close()

    @staticmethod
    def _snapshot(row: sqlite3.Row) -> dict[str, Any]:
        value = json.loads(row["state_json"])
        value["authority_store"] = "controller-owned-sqlite"
        value["authoritative_lifecycle"] = True
        value["store_version"] = int(row["version"])
        value["store_record_hash"] = row["current_hash"]
        return value

    @staticmethod
    def _event(row: sqlite3.Row) -> dict[str, Any]:
        try:
            parsed = json.loads(row["record_json"])
        except (TypeError, json.JSONDecodeError):
            parsed = {"_malformed_record_json": True}
        result = parsed if isinstance(parsed, dict) else {"_malformed_record_json": True}
        result["sequence"] = int(row["sequence"])
        result["record_hash"] = row["record_hash"]
        result["record_mac"] = row["record_mac"]
        return result

    def _resolve_actor(self, actor: str | None) -> str:
        identity_errors = validate_controller_identity(self.controller_context, actor=actor)
        if identity_errors:
            raise PermissionError("Lifecycle actor is not derived from the controller runtime: " + "; ".join(identity_errors))
        return self.controller_context.actor

    def _validate_transition_authorization(
        self,
        authorization: dict[str, Any] | None,
        *,
        case_id: str,
        expected_version: int,
        current_record_hash: str,
        next_record_hash: str,
        requested_state: str,
        decision: str,
        actor: str,
        idempotency_key: str,
        subject: dict[str, Any],
        required_evidence: Iterable[str],
        accepted_evidence: Iterable[str],
        rejected_evidence: Iterable[str] = (),
        policy_hash: str | None = None,
        toolchain_hash: str | None = None,
    ) -> None:
        required_evidence = list(required_evidence)
        accepted_evidence = list(accepted_evidence)
        rejected_evidence = list(rejected_evidence)
        if requested_state in PROTECTED_TRANSITION_STATES and not accepted_evidence:
            raise PermissionError(
                "Protected lifecycle transitions require accepted authoritative evidence"
            )
        if not isinstance(authorization, dict):
            raise PermissionError(
                "Protected lifecycle transitions require a signed controller authorization"
            )
        required_fields = {
            "evidence_id", "type", "trust_level", "producer", "repository",
            "created_at", "invalidated_by", "status", "metadata",
        }
        missing_fields = sorted(field for field in required_fields if field not in authorization)
        if missing_fields:
            raise PermissionError(
                "Lifecycle controller authorization is incomplete: " + ", ".join(missing_fields)
            )
        errors = validate_evidence_record(
            authorization,
            subject=subject,
            minimum_trust="E6",
            trust_roots=self.authority_trust_roots,
            require_authoritative_signature=True,
            require_affirmative_status=True,
        )
        if errors:
            raise PermissionError("Invalid lifecycle controller authorization: " + "; ".join(errors))
        if not self._authority_roots_are_host_accepted():
            raise PermissionError("Protected lifecycle authorization requires host-accepted trust-root custody")
        if authorization.get("type") != TRANSITION_AUTHORIZATION_TYPE:
            raise PermissionError("Lifecycle authorization has an unsupported type")
        if authorization.get("producer") != TRANSITION_AUTHORIZATION_PRODUCER:
            raise PermissionError("Lifecycle authorization has an unauthorized producer")
        if not str(authorization.get("evidence_id") or "").startswith("ev-"):
            raise PermissionError("Lifecycle authorization evidence_id is invalid")
        metadata = authorization.get("metadata") if isinstance(authorization.get("metadata"), dict) else {}
        for field in ("event_commitment", "event_occurred_at"):
            if not isinstance(metadata.get(field), str) or not metadata.get(field):
                raise PermissionError(
                    "Lifecycle controller authorization must commit to its immutable event material"
                )
        identity_errors = validate_controller_identity(
            self.controller_context,
            actor=actor,
            authorization_metadata=metadata,
        )
        if identity_errors:
            raise PermissionError("Lifecycle controller identity is not authenticated: " + "; ".join(identity_errors))
        expected = {
            "case_id": case_id,
            "expected_version": expected_version,
            "current_record_hash": current_record_hash,
            "next_record_hash": next_record_hash,
            "requested_state": requested_state,
            "decision": decision,
            "actor": actor,
            "idempotency_key": idempotency_key,
            "subject_fingerprint": subject_fingerprint(subject),
            "subject_epoch": int(subject.get("subject_epoch") or 0),
            "required_evidence": sorted(set(required_evidence)),
            "accepted_evidence": sorted(set(accepted_evidence)),
            "rejected_evidence": sorted(set(rejected_evidence)),
            "policy_hash": policy_hash,
            "toolchain_hash": toolchain_hash,
            "controller_id": self.controller_context.controller_id,
            "controller_type": self.controller_context.controller_type,
            "identity_source": self.controller_context.identity_source,
            "authentication_mechanism": self.controller_context.authentication_mechanism,
        }
        mismatches = [
            field for field, value in expected.items()
            if metadata.get(field) != value
        ]
        if mismatches:
            raise PermissionError(
                "Lifecycle controller authorization is not bound to this exact transition: "
                + ", ".join(sorted(mismatches))
            )

    @staticmethod
    def _validate_risk_and_domains(current: dict[str, Any], next_state: dict[str, Any]) -> None:
        domains = next_state.get("domains")
        if domains is not None:
            if not isinstance(domains, list) or any(not isinstance(item, str) or not item.strip() for item in domains):
                raise ValueError("Lifecycle domains must be a unique list")
            if len(domains) != len({item.upper() for item in domains}):
                raise ValueError("Lifecycle domains must be a unique list")
            normalized = {str(item).upper() for item in domains}
            unknown = sorted(normalized - VALID_DOMAINS)
            if unknown:
                raise ValueError("Unknown lifecycle domain: " + ", ".join(unknown))
        current_risk = current.get("risk")
        next_risk = next_state.get("risk")
        for label, value in (("current", current_risk), ("next", next_risk)):
            if value is not None and (not isinstance(value, str) or value not in RISK_ORDER):
                raise ValueError(f"Unknown {label} lifecycle risk: {value}")
        if current_risk is not None and next_risk is not None and RISK_ORDER[next_risk] < RISK_ORDER[current_risk]:
            raise PermissionError("Lifecycle risk downgrade is prohibited")
        risk_class = next_state.get("risk_class")
        if risk_class is not None and (not isinstance(risk_class, str) or risk_class not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}):
            raise ValueError("Unknown lifecycle risk class")
        if risk_class is not None and next_risk is None:
            raise ValueError("Lifecycle risk_class requires a lifecycle risk")
        if next_risk is not None and risk_class is not None and RISK_TO_CLASS[next_risk] != risk_class:
            raise PermissionError("Lifecycle risk and risk_class are inconsistent")
        if next_risk is not None and domains and any(str(item).upper() in (VALID_DOMAINS - {"GENERAL"}) for item in domains):
            if RISK_ORDER[next_risk] < RISK_ORDER["R3"]:
                raise PermissionError("High-risk lifecycle domains require at least R3")
        history = next_state.get("risk_history") or []
        if not isinstance(history, list):
            raise ValueError("Lifecycle risk_history must be a list")
        for item in history:
            if not isinstance(item, dict):
                raise ValueError("Lifecycle risk_history entries must be objects")
            value = item.get("risk")
            if value is not None and (not isinstance(value, str) or value not in RISK_ORDER):
                raise ValueError("Unknown risk in lifecycle risk_history")
            if value is not None and next_risk is not None and RISK_ORDER[value] > RISK_ORDER[next_risk]:
                raise PermissionError("Lifecycle risk is lower than its recorded risk history")
    def initialize(self, record: dict[str, Any], *, actor: str | None = None, idempotency_key: str | None = None) -> dict[str, Any]:
        if not isinstance(record, dict) or not record.get("case_id"):
            raise ValueError("Lifecycle record with case_id is required")
        actor = self._resolve_actor(actor)
        if str(record.get("state") or "") != "UNVERIFIED_REPORT":
            raise ValueError("Authoritative lifecycle initialization must begin at UNVERIFIED_REPORT")
        case_id = str(record["case_id"])
        result = copy.deepcopy(record)
        result["authoritative_lifecycle"] = True
        result["authority_store"] = "controller-owned-sqlite"
        result.setdefault("subject_epoch", 0)
        result["subject_version"] = max(int(result.get("subject_version") or 1), 1)
        result.setdefault("last_completed_state", "UNVERIFIED_REPORT")
        result.setdefault("final_state", None)
        result.setdefault("closure_class", None)
        self._validate_risk_and_domains({}, result)
        subject_errors = validate_subject(
            result,
            require_merge_provenance=bool(result.get("merged_main_sha")),
        ).errors
        if subject_errors:
            raise ValueError("Invalid lifecycle subject: " + "; ".join(subject_errors))
        result["subject_fingerprint"] = subject_fingerprint(result)
        idempotency_key = idempotency_key or f"initialize:{case_id}:{result['subject_fingerprint']}"
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT * FROM lifecycle_cases WHERE case_id=?", (case_id,)).fetchone()
            if existing:
                current = self._snapshot(existing)
                existing_state = json.loads(existing["state_json"])
                if _hash(existing_state) != existing["current_hash"]:
                    raise RuntimeError("Lifecycle current record hash is invalid")
                if existing_state != result:
                    raise RuntimeError("Lifecycle initialization key was reused for a different initial state")
                conn.execute("COMMIT")
                return current | {"idempotent_replay": True}
            state_json = canonical_json(result).decode("utf-8")
            current_hash = _hash(result)
            conn.execute(
                "INSERT INTO lifecycle_cases(case_id,version,subject_epoch,state_json,current_hash,updated_at) VALUES(?,?,?,?,?,?)",
                (case_id, 1, int(result.get("subject_epoch") or 0), state_json, current_hash, utc_now()),
            )
            self._append_event_tx(
                conn,
                case_id=case_id,
                idempotency_key=idempotency_key,
                actor=actor,
                prior_state="<GENESIS>",
                requested_state=str(result.get("state") or "UNVERIFIED_REPORT"),
                decision="INITIALIZED",
                required_evidence=[],
                accepted_evidence=[],
                rejected_evidence=[],
                state=result,
                current_record_hash=current_hash,
                policy_hash=result.get("policy_bundle_hash"),
                toolchain_hash=result.get("toolchain_hash"),
            )
            conn.execute("COMMIT")
            return self.get(case_id, verify=True)
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def get(self, case_id: str, *, verify: bool = True) -> dict[str, Any]:
        if verify:
            report = self.verify_event_chain(case_id=case_id)
            if not report["valid"]:
                raise RuntimeError("Lifecycle event chain verification failed: " + "; ".join(report["errors"]))
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM lifecycle_cases WHERE case_id=?", (case_id,)).fetchone()
            if not row:
                raise KeyError(case_id)
            return self._snapshot(row)
        finally:
            conn.close()

    def export(self, case_id: str, *, verify: bool = True) -> dict[str, Any]:
        """Return a verified human/interoperability export without making it authoritative."""

        snapshot = self.get(case_id, verify=verify)
        snapshot["lifecycle_events"] = self.events(case_id)
        snapshot["lifecycle_export"] = True
        snapshot["claim_boundary"] = "This JSON is an export; the controller-owned SQLite ledger remains authoritative."
        return snapshot

    def transition(
        self,
        case_id: str,
        state: dict[str, Any],
        *,
        actor: str | None = None,
        expected_version: int,
        requested_state: str,
        decision: str,
        required_evidence: Iterable[str] = (),
        accepted_evidence: Iterable[str] = (),
        accepted_evidence_records: Iterable[dict[str, Any]] = (),
        rejected_evidence: Iterable[str] = (),
        policy_hash: str | None = None,
        toolchain_hash: str | None = None,
        risk_snapshot: dict[str, Any] | None = None,
        domain_snapshot: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        transition_authorization: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        actor = self._resolve_actor(actor)
        if not isinstance(state, dict) or state.get("case_id") != case_id:
            raise ValueError("Transition state case_id mismatch")
        next_state = copy.deepcopy(state)
        next_state.pop("idempotent_replay", None)
        next_state["authoritative_lifecycle"] = True
        next_state["authority_store"] = "controller-owned-sqlite"
        if str(next_state.get("state") or "") in AUTHORITATIVE_STATES:
            next_state["last_completed_state"] = str(next_state.get("state"))
        next_state["subject_fingerprint"] = subject_fingerprint(next_state)
        accepted_evidence_records = list(accepted_evidence_records)
        current_record_hash = _hash(next_state)
        idempotency_key = idempotency_key or f"transition:{case_id}:{expected_version}:{requested_state}:{current_record_hash}"
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            current_row = conn.execute("SELECT * FROM lifecycle_cases WHERE case_id=?", (case_id,)).fetchone()
            if not current_row:
                raise KeyError(case_id)
            current = self._snapshot(current_row)
            if int(current_row["version"]) != expected_version:
                raise RuntimeError("Optimistic concurrency conflict: stale lifecycle version")
            try:
                current_json = json.loads(current_row["state_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise RuntimeError("Lifecycle current state JSON is invalid") from exc
            if _hash(current_json) != current_row["current_hash"]:
                raise RuntimeError("Lifecycle current record hash is invalid")
            current_state = str(current.get("state") or "")
            next_state_name = str(next_state.get("state") or "")
            if next_state_name not in AUTHORITATIVE_STATES and next_state_name not in {"BLOCKED", "ROLLBACK_REQUIRED"}:
                raise ValueError("Unknown authoritative lifecycle state")
            if requested_state not in AUTHORITATIVE_STATES and requested_state != "ROLLBACK_REQUIRED":
                raise ValueError("Requested lifecycle state is not authoritative")
            subject_binding = decision in {"SUBJECT_BOUND", "ARTIFACT_BOUND", "SUBJECT_MUTATION_INVALIDATED_DOWNSTREAM"}
            if decision not in {
                "PROCEED",
                "BLOCKED",
                "ROLLBACK_REQUIRED",
                "SUBJECT_BOUND",
                "ARTIFACT_BOUND",
                "SUBJECT_MUTATION_INVALIDATED_DOWNSTREAM",
            }:
                raise ValueError("Unknown lifecycle transition decision")
            current_subject_errors = validate_subject(
                current,
                require_merge_provenance=bool(current.get("merged_main_sha")),
            ).errors
            next_subject_errors = validate_subject(
                next_state,
                require_merge_provenance=bool(next_state.get("merged_main_sha")),
            ).errors
            if current_subject_errors:
                raise ValueError("Current lifecycle subject is invalid: " + "; ".join(current_subject_errors))
            if next_subject_errors:
                raise ValueError("Next lifecycle subject is invalid: " + "; ".join(next_subject_errors))
            self._validate_risk_and_domains(current, next_state)
            current_subject = subject_from_record(current)
            next_subject = subject_from_record(next_state)
            subject_changes = material_subject_changes(current_subject, next_subject)
            epoch_errors = validate_subject_epoch_transition(current, next_state)
            if epoch_errors:
                raise PermissionError("Invalid subject_epoch transition: " + "; ".join(epoch_errors))
            if subject_changes and not subject_binding:
                raise PermissionError("Material subject changes require an explicit subject-binding decision")
            if next_state.get("base_sha") not in {None, next_subject.get("protected_base_sha")}:
                raise PermissionError("Legacy base_sha is inconsistent with protected_base_sha")
            if next_state.get("head_sha") not in {None, next_subject.get("merged_main_sha") or next_subject.get("pr_head_sha")}:
                raise PermissionError("Legacy head_sha is inconsistent with the active subject revision")
            if next_state.get("diff_hash") not in {None, next_subject.get("reviewed_diff_hash")}:
                raise PermissionError("Legacy diff_hash is inconsistent with reviewed_diff_hash")
            if next_subject.get("subject_version") != current_subject.get("subject_version"):
                raise PermissionError("subject_version is controller-owned and cannot be changed directly")
            if not subject_changes and next_subject.get("subject_epoch") != current_subject.get("subject_epoch"):
                raise PermissionError("subject_epoch may change only with a material subject mutation")
            if subject_binding:
                changed_keys = {
                    key
                    for key in set(current) | set(next_state)
                    if current.get(key) != next_state.get(key)
                }
                unexpected = sorted(changed_keys - SUBJECT_MUTATION_FIELDS)
                if unexpected:
                    raise PermissionError("Subject binding attempted to mutate non-subject lifecycle fields: " + ", ".join(unexpected))
                if subject_changes:
                    if int(next_subject.get("subject_epoch") or 0) != int(current_subject.get("subject_epoch") or 0) + 1:
                        raise PermissionError("Material subject mutation must increment subject_epoch exactly once")
                    if next_state.get("subject_fingerprint") != subject_fingerprint(next_state):
                        raise PermissionError("Subject mutation fingerprint is invalid")
                    if next_state.get("evidence_refs") not in ({}, None):
                        raise PermissionError("Material subject mutation must clear current evidence references")
                    mutations = next_state.get("subject_mutations") if isinstance(next_state.get("subject_mutations"), list) else []
                    if not mutations or set(mutations[-1].get("changed_fields") or []) != set(subject_changes):
                        raise PermissionError("Subject mutation history does not describe the exact changed fields")
                elif next_state != current:
                    raise PermissionError("Subject binding without a material subject change must be a no-op")
                old_refs = current.get("evidence_refs") if isinstance(current.get("evidence_refs"), dict) else {}
                new_history = next_state.get("historical_evidence_refs") if isinstance(next_state.get("historical_evidence_refs"), dict) else {}
                missing_archived = sorted({
                    str(ref)
                    for refs in old_refs.values()
                    for ref in (refs or [])
                    if str(ref) not in {str(item) for item in (new_history.get("__all__", []) or [])}
                    and not any(str(ref) in {str(item) for item in (history_refs or [])} for history_refs in new_history.values())
                })
                if missing_archived:
                    raise PermissionError("Subject mutation must archive all incompatible evidence references")
            else:
                changed_keys = {
                    key
                    for key in set(current) | set(next_state)
                    if current.get(key) != next_state.get(key)
                }
                unexpected = sorted(changed_keys - LIFECYCLE_MUTATION_FIELDS - {"authoritative_lifecycle", "authority_store", "store_version", "store_record_hash"})
                if unexpected:
                    raise PermissionError("Lifecycle transition attempted to mutate unbound fields: " + ", ".join(unexpected))
            if subject_binding and next_state_name not in {current_state, "BLOCKED", "ROLLBACK_REQUIRED"}:
                raise PermissionError("Subject binding may not advance the authoritative lifecycle")
            if next_state_name in AUTHORITATIVE_STATES:
                if next_state.get("last_completed_state") != next_state_name:
                    raise PermissionError("Lifecycle last_completed_state must match the requested state")
                logical_current = current_state
                if current_state == "BLOCKED":
                    logical_current = str(current.get("resume_state") or "")
                allowed_next = ALLOWED_TRANSITIONS.get(logical_current, set())
                if not subject_binding and decision != "PROCEED":
                    raise PermissionError("Authoritative lifecycle advancement requires a PROCEED decision")
                if requested_state != next_state_name or (not subject_binding and requested_state not in allowed_next):
                    if subject_binding and requested_state != current_state:
                        raise PermissionError("Subject binding may not advance the authoritative lifecycle")
                if not subject_binding and requested_state not in allowed_next:
                    raise PermissionError("Lifecycle store cannot bypass the authoritative transition order")
            elif next_state_name == "ROLLBACK_REQUIRED":
                if not subject_binding and decision != "ROLLBACK_REQUIRED":
                    raise PermissionError("Rollback lifecycle writes require a rollback controller decision")
            elif next_state_name == "BLOCKED" and not subject_binding:
                if decision != "BLOCKED":
                    raise PermissionError("Blocked lifecycle writes require a blocking controller decision")
            if next_state_name == "BLOCKED" and decision not in {"BLOCKED", "SUBJECT_BOUND", "ARTIFACT_BOUND", "SUBJECT_MUTATION_INVALIDATED_DOWNSTREAM"}:
                raise PermissionError("Blocked lifecycle writes require a blocking controller decision")
            if next_state_name == "BLOCKED":
                resume_state = str(next_state.get("resume_state") or "")
                logical_current = str(current.get("resume_state") or "") if current_state == "BLOCKED" else current_state
                if resume_state not in CODE_LIFECYCLE:
                    raise PermissionError("Blocked lifecycle state requires a valid resume_state")
                if logical_current not in CODE_LIFECYCLE:
                    raise PermissionError("Blocked lifecycle state has an invalid current state")
                if CODE_LIFECYCLE.index(resume_state) > CODE_LIFECYCLE.index(logical_current):
                    raise PermissionError("Blocked lifecycle state cannot resume at a future state")
            if next_state_name == "ROLLBACK_REQUIRED" and decision not in {"ROLLBACK_REQUIRED", "SUBJECT_MUTATION_INVALIDATED_DOWNSTREAM"}:
                raise PermissionError("Rollback lifecycle writes require a rollback controller decision")
            if next_state_name in TERMINAL_STATES:
                if next_state.get("final_state") != next_state_name:
                    raise PermissionError("Terminal lifecycle state must declare the same final_state")
                if next_state_name == "RESOLVED_NO_CODE":
                    if next_state.get("closure_class") != "RESOLVED_NO_CODE":
                        raise PermissionError("RESOLVED_NO_CODE must declare its closure class")
                    if "RESOLVED_NO_CODE_PROVEN" not in {str(item) for item in required_evidence}:
                        raise PermissionError("RESOLVED_NO_CODE requires its authoritative evidence type")
                elif next_state_name == "CLOSED":
                    if current_state == "POST_DEPLOY_VERIFIED" and next_state.get("closure_class") != "CODE_FIX":
                        raise PermissionError("Code-fix closure must declare CODE_FIX")
                    if current_state == "ROLLBACK_REQUIRED" and next_state.get("closure_class") != "ROLLBACK_CLOSURE":
                        raise PermissionError("Rollback closure must declare ROLLBACK_CLOSURE")
            elif next_state.get("final_state") not in {None, ""} or next_state.get("closure_class") not in {None, ""}:
                raise PermissionError("Non-terminal lifecycle states cannot declare a closure")
            if int(next_state.get("subject_epoch") or 0) < int(current.get("subject_epoch") or 0):
                raise PermissionError("Lifecycle subject_epoch cannot decrease")
            if next_state_name in PROTECTED_TRANSITION_STATES:
                accepted_records = self._validate_accepted_evidence(
                    accepted_evidence_records,
                    case_id=case_id,
                    subject=next_subject,
                    required_evidence=required_evidence,
                    accepted_evidence=accepted_evidence,
                )
                self._validate_transition_authorization(
                    transition_authorization,
                    case_id=case_id,
                    expected_version=expected_version,
                    current_record_hash=current_row["current_hash"],
                    next_record_hash=current_record_hash,
                    requested_state=requested_state,
                    decision=decision,
                    actor=actor,
                    idempotency_key=idempotency_key,
                    subject=next_subject,
                    required_evidence=required_evidence,
                    accepted_evidence=accepted_evidence,
                    rejected_evidence=rejected_evidence,
                    policy_hash=policy_hash or next_state.get("policy_bundle_hash"),
                    toolchain_hash=toolchain_hash or next_state.get("toolchain_hash"),
                )
            else:
                accepted_records = []
            existing = conn.execute("SELECT * FROM lifecycle_events WHERE idempotency_key=?", (idempotency_key,)).fetchone()
            if existing:
                existing_event = self._event(existing)
                expected_existing = {
                    "case_id": case_id,
                    "actor": actor,
                    "prior_state": str(current.get("state")),
                    "requested_state": requested_state,
                    "decision": decision,
                    "required_evidence": sorted(set(required_evidence)),
                    "accepted_evidence": sorted(set(accepted_evidence)),
                    "rejected_evidence": sorted(set(rejected_evidence)),
                    "subject": next_subject,
                    "subject_epoch": int(next_subject.get("subject_epoch") or 0),
                    "subject_fingerprint": subject_fingerprint(next_subject),
                    "policy_hash": policy_hash or next_state.get("policy_bundle_hash"),
                    "toolchain_hash": toolchain_hash or next_state.get("toolchain_hash"),
                    "current_record_hash": current_record_hash,
                    "state": next_state,
                    "transition_authorization": transition_authorization,
                    "accepted_evidence_records": accepted_records,
                }
                mismatches = [
                    field for field, value in expected_existing.items()
                    if existing_event.get(field) != value
                ]
                if mismatches:
                    raise RuntimeError(
                        "idempotency key was reused for a different lifecycle request: "
                        + ", ".join(sorted(mismatches))
                    )
                conn.execute("COMMIT")
                return self.get(case_id, verify=True) | {"idempotent_replay": True}
            self._append_event_tx(
                conn,
                case_id=case_id,
                idempotency_key=idempotency_key,
                actor=actor,
                prior_state=str(current.get("state")),
                requested_state=requested_state,
                decision=decision,
                required_evidence=list(required_evidence),
                accepted_evidence=list(accepted_evidence),
                rejected_evidence=list(rejected_evidence),
                state=next_state,
                current_record_hash=current_record_hash,
                policy_hash=policy_hash or next_state.get("policy_bundle_hash"),
                toolchain_hash=toolchain_hash or next_state.get("toolchain_hash"),
                risk_snapshot=risk_snapshot or {"risk": next_state.get("risk"), "risk_class": next_state.get("risk_class")},
                domain_snapshot=domain_snapshot or {"domains": next_state.get("domains", [])},
                transition_authorization=transition_authorization,
                accepted_evidence_records=accepted_records,
            )
            update_cursor = conn.execute(
                "UPDATE lifecycle_cases SET version=?,subject_epoch=?,state_json=?,current_hash=?,updated_at=? WHERE case_id=? AND version=?",
                (
                    expected_version + 1,
                    int(next_state.get("subject_epoch") or subject_from_record(next_state).get("subject_epoch") or 0),
                    canonical_json(next_state).decode("utf-8"),
                    current_record_hash,
                    utc_now(),
                    case_id,
                    expected_version,
                ),
            )
            if update_cursor.rowcount != 1:
                raise RuntimeError("Optimistic concurrency conflict: lifecycle update was not applied")
            conn.execute("COMMIT")
            return self.get(case_id, verify=True) | {"idempotent_replay": False}
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def mutate_subject(
        self,
        case_id: str,
        updates: dict[str, Any],
        *,
        reason: str,
        actor: str | None = None,
        expected_version: int,
    ) -> dict[str, Any]:
        """Apply a subject mutation through the same optimistic ledger path."""

        current = self.get(case_id, verify=True)
        if int(current.get("store_version", 0)) != expected_version:
            raise RuntimeError("Optimistic concurrency conflict: stale lifecycle version")
        updated = apply_subject_update(current, updates, reason=reason)
        return self.transition(
            case_id,
            updated,
            actor=actor,
            expected_version=expected_version,
            requested_state=str(updated.get("blocked_target") or updated.get("state")),
            decision="SUBJECT_MUTATION_INVALIDATED_DOWNSTREAM",
            required_evidence=[],
            accepted_evidence=[],
            rejected_evidence=list(updated.get("historical_evidence_refs", {}).keys()),
            policy_hash=updated.get("policy_bundle_hash"),
            toolchain_hash=updated.get("toolchain_hash"),
        )

    def _build_event_material(
        self,
        *,
        case_id: str,
        idempotency_key: str,
        actor: str,
        prior_state: str,
        requested_state: str,
        decision: str,
        required_evidence: list[str],
        accepted_evidence: list[str],
        rejected_evidence: list[str],
        accepted_evidence_records: list[dict[str, Any]] | None,
        state: dict[str, Any],
        current_record_hash: str,
        policy_hash: str | None,
        toolchain_hash: str | None,
        risk_snapshot: dict[str, Any] | None,
        domain_snapshot: dict[str, Any] | None,
        transition_authorization: dict[str, Any] | None,
        occurred_at: str,
        previous_hash: str,
        sequence: int,
    ) -> dict[str, Any]:
        subject = subject_from_record(state)
        material = {
            "case_id": case_id,
            "idempotency_key": idempotency_key,
            "actor": actor,
            "occurred_at": occurred_at,
            "prior_state": prior_state,
            "requested_state": requested_state,
            "decision": decision,
            "required_evidence": sorted(set(required_evidence)),
            "accepted_evidence": sorted(set(accepted_evidence)),
            "accepted_evidence_records": [
                copy.deepcopy(item)
                for item in sorted(accepted_evidence_records or [], key=lambda value: str(value.get("evidence_id") or ""))
            ],
            "rejected_evidence": sorted(set(rejected_evidence)),
            "subject": subject,
            "subject_epoch": int(subject.get("subject_epoch") or 0),
            "subject_fingerprint": subject_fingerprint(subject),
            "policy_hash": policy_hash,
            "toolchain_hash": toolchain_hash,
            "risk_snapshot": risk_snapshot or {},
            "domain_snapshot": domain_snapshot or {},
            "transition_authorization": copy.deepcopy(transition_authorization),
            "controller_identity": self.controller_context.event_identity(),
            "store_binding": self.store_binding,
            "previous_hash": previous_hash,
            "current_record_hash": current_record_hash,
            "state": copy.deepcopy(state),
            "sequence": sequence,
        }
        return material

    def prepare_transition_authorization(
        self,
        case_id: str,
        state: dict[str, Any],
        *,
        expected_version: int,
        requested_state: str,
        decision: str,
        actor: str | None = None,
        required_evidence: Iterable[str] = (),
        accepted_evidence: Iterable[str] = (),
        accepted_evidence_records: Iterable[dict[str, Any]] = (),
        rejected_evidence: Iterable[str] = (),
        policy_hash: str | None = None,
        toolchain_hash: str | None = None,
        risk_snapshot: dict[str, Any] | None = None,
        domain_snapshot: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        event_occurred_at: str | None = None,
    ) -> dict[str, Any]:
        """Prepare the signed event commitment without mutating the store.

        A controller must sign the returned commitment and timestamp before
        calling ``transition``.  The store recomputes both values while it
        holds its write transaction, so model input cannot replace the event
        after authorization.
        """

        actor = self._resolve_actor(actor)
        if not isinstance(state, dict) or state.get("case_id") != case_id:
            raise ValueError("Transition state case_id mismatch")
        next_state = copy.deepcopy(state)
        next_state.pop("idempotent_replay", None)
        next_state["authoritative_lifecycle"] = True
        next_state["authority_store"] = "controller-owned-sqlite"
        if str(next_state.get("state") or "") in AUTHORITATIVE_STATES:
            next_state["last_completed_state"] = str(next_state.get("state"))
        next_state["subject_fingerprint"] = subject_fingerprint(next_state)
        required_evidence = list(required_evidence)
        accepted_evidence = list(accepted_evidence)
        rejected_evidence = list(rejected_evidence)
        accepted_evidence_records = list(accepted_evidence_records)
        current_record_hash = _hash(next_state)
        idempotency_key = idempotency_key or f"transition:{case_id}:{expected_version}:{requested_state}:{current_record_hash}"
        occurred_at = event_occurred_at or utc_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            current_row = conn.execute("SELECT * FROM lifecycle_cases WHERE case_id=?", (case_id,)).fetchone()
            if not current_row:
                raise KeyError(case_id)
            if int(current_row["version"]) != int(expected_version):
                raise RuntimeError("Optimistic concurrency conflict: stale lifecycle version")
            previous = conn.execute("SELECT record_hash FROM lifecycle_events ORDER BY sequence DESC LIMIT 1").fetchone()
            previous_hash = previous["record_hash"] if previous else GENESIS_HASH
            sequence_row = conn.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence FROM lifecycle_events"
            ).fetchone()
            sequence = int(sequence_row["next_sequence"])
            material = self._build_event_material(
                case_id=case_id,
                idempotency_key=idempotency_key,
                actor=actor,
                prior_state=str(json.loads(current_row["state_json"]).get("state") or ""),
                requested_state=requested_state,
                decision=decision,
                required_evidence=required_evidence,
                accepted_evidence=accepted_evidence,
                rejected_evidence=rejected_evidence,
                accepted_evidence_records=accepted_evidence_records,
                state=next_state,
                current_record_hash=current_record_hash,
                policy_hash=policy_hash or next_state.get("policy_bundle_hash"),
                toolchain_hash=toolchain_hash or next_state.get("toolchain_hash"),
                risk_snapshot=risk_snapshot or {"risk": next_state.get("risk"), "risk_class": next_state.get("risk_class")},
                domain_snapshot=domain_snapshot or {"domains": next_state.get("domains", [])},
                transition_authorization=None,
                occurred_at=occurred_at,
                previous_hash=previous_hash,
                sequence=sequence,
            )
            return {
                "case_id": case_id,
                "expected_version": int(expected_version),
                "idempotency_key": idempotency_key,
                "event_occurred_at": occurred_at,
                "event_sequence": sequence,
                "event_previous_hash": previous_hash,
                "event_commitment": event_commitment(material),
                "current_record_hash": current_record_hash,
            }
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            conn.close()

    def _append_event_tx(
        self,
        conn: sqlite3.Connection,
        *,
        case_id: str,
        idempotency_key: str,
        actor: str,
        prior_state: str,
        requested_state: str,
        decision: str,
        required_evidence: list[str],
        accepted_evidence: list[str],
        rejected_evidence: list[str],
        accepted_evidence_records: list[dict[str, Any]] | None = None,
        state: dict[str, Any],
        current_record_hash: str,
        policy_hash: str | None,
        toolchain_hash: str | None,
        risk_snapshot: dict[str, Any] | None = None,
        domain_snapshot: dict[str, Any] | None = None,
        transition_authorization: dict[str, Any] | None = None,
        occurred_at: str | None = None,
    ) -> dict[str, Any]:
        previous = conn.execute("SELECT record_hash FROM lifecycle_events ORDER BY sequence DESC LIMIT 1").fetchone()
        previous_hash = previous["record_hash"] if previous else GENESIS_HASH
        sequence_row = conn.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence FROM lifecycle_events"
        ).fetchone()
        sequence = int(sequence_row["next_sequence"])
        event_time = occurred_at or utc_now()
        if transition_authorization is not None:
            authorization_metadata = transition_authorization.get("metadata") if isinstance(transition_authorization.get("metadata"), dict) else {}
            event_time = str(authorization_metadata.get("event_occurred_at") or "")
            if not event_time or transition_authorization.get("created_at") != event_time:
                raise PermissionError("Lifecycle authorization timestamp is not bound to its event")
        material = self._build_event_material(
            case_id=case_id,
            idempotency_key=idempotency_key,
            actor=actor,
            prior_state=prior_state,
            requested_state=requested_state,
            decision=decision,
            required_evidence=required_evidence,
            accepted_evidence=accepted_evidence,
            rejected_evidence=rejected_evidence,
            accepted_evidence_records=accepted_evidence_records,
            state=state,
            current_record_hash=current_record_hash,
            policy_hash=policy_hash,
            toolchain_hash=toolchain_hash,
            risk_snapshot=risk_snapshot,
            domain_snapshot=domain_snapshot,
            transition_authorization=transition_authorization,
            occurred_at=event_time,
            previous_hash=previous_hash,
            sequence=sequence,
        )
        if transition_authorization is not None:
            metadata = transition_authorization.get("metadata") if isinstance(transition_authorization.get("metadata"), dict) else {}
            if metadata.get("event_commitment") != event_commitment(material):
                raise PermissionError("Lifecycle authorization is not bound to the exact event material")
        record_hash = _hash(material)
        record_mac = self._event_mac(record_hash)
        payload_json = canonical_json(material).decode("utf-8")
        conn.execute(
            """INSERT INTO lifecycle_events(sequence,case_id,idempotency_key,actor,occurred_at,prior_state,requested_state,decision,required_evidence_json,accepted_evidence_json,rejected_evidence_json,subject_json,subject_epoch,subject_fingerprint,policy_hash,toolchain_hash,risk_snapshot_json,domain_snapshot_json,previous_hash,current_record_hash,record_json,record_hash,record_mac)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                sequence,
                case_id,
                idempotency_key,
                actor,
                material["occurred_at"],
                prior_state,
                requested_state,
                decision,
                json.dumps(material["required_evidence"], sort_keys=True),
                json.dumps(material["accepted_evidence"], sort_keys=True),
                json.dumps(material["rejected_evidence"], sort_keys=True),
                canonical_json(material["subject"]).decode("utf-8"),
                material["subject_epoch"],
                material["subject_fingerprint"],
                policy_hash,
                toolchain_hash,
                canonical_json(material["risk_snapshot"]).decode("utf-8"),
                canonical_json(material["domain_snapshot"]).decode("utf-8"),
                previous_hash,
                current_record_hash,
                payload_json,
                record_hash,
                record_mac,
            ),
        )
        return material | {"record_hash": record_hash, "record_mac": record_mac}

    def events(self, case_id: str | None = None) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            if case_id is None:
                rows = conn.execute("SELECT * FROM lifecycle_events ORDER BY sequence").fetchall()
            else:
                rows = conn.execute("SELECT * FROM lifecycle_events WHERE case_id=? ORDER BY sequence", (case_id,)).fetchall()
            return [self._event(row) for row in rows]
        finally:
            conn.close()

    def verify_event_chain(self, *, case_id: str | None = None) -> dict[str, Any]:
        conn = self._connect()
        errors: list[str] = []
        try:
            binding_row = conn.execute(
                "SELECT value FROM lifecycle_store_metadata WHERE key='store_binding'"
            ).fetchone()
            if binding_row is None or binding_row["value"] != self.store_binding:
                errors.append("Lifecycle database store binding does not match this task")
            rows = conn.execute("SELECT * FROM lifecycle_events ORDER BY sequence").fetchall()
            previous_hash = GENESIS_HASH
            expected_sequence = 1
            checked = 0
            latest_by_case: dict[str, dict[str, Any]] = {}
            history_by_case: dict[str, list[dict[str, Any]]] = {}
            for row in rows:
                event = self._event(row)
                checked += 1
                event_case_id = str(event.get("case_id") or "")
                case_history = history_by_case.setdefault(event_case_id, [])
                stored_json_fields: dict[str, Any] = {}
                for field in (
                    "required_evidence",
                    "accepted_evidence",
                    "rejected_evidence",
                    "subject",
                    "risk_snapshot",
                    "domain_snapshot",
                ):
                    column = field + "_json"
                    try:
                        stored_json_fields[field] = json.loads(row[column])
                    except (TypeError, json.JSONDecodeError):
                        stored_json_fields[field] = None
                        errors.append(f"event {event['sequence']}: stored {column} is invalid JSON")
                scalar_fields = {
                    "case_id": row["case_id"],
                    "idempotency_key": row["idempotency_key"],
                    "actor": row["actor"],
                    "occurred_at": row["occurred_at"],
                    "prior_state": row["prior_state"],
                    "requested_state": row["requested_state"],
                    "decision": row["decision"],
                    "subject_epoch": int(row["subject_epoch"]),
                    "subject_fingerprint": row["subject_fingerprint"],
                    "policy_hash": row["policy_hash"],
                    "toolchain_hash": row["toolchain_hash"],
                    "previous_hash": row["previous_hash"],
                    "current_record_hash": row["current_record_hash"],
                }
                for field, stored_value in scalar_fields.items():
                    if event.get(field) != stored_value:
                        errors.append(f"event {event['sequence']}: stored {field} column mismatch")
                for field, stored_value in stored_json_fields.items():
                    if event.get(field) != stored_value:
                        errors.append(f"event {event['sequence']}: stored {field} column mismatch")
                event_subject = event.get("subject") if isinstance(event.get("subject"), dict) else {}
                event_state = event.get("state") if isinstance(event.get("state"), dict) else {}
                if event_subject != subject_from_record(event_state):
                    errors.append(f"event {event['sequence']}: subject does not match state snapshot")
                if event.get("subject_fingerprint") != subject_fingerprint(event_subject):
                    errors.append(f"event {event['sequence']}: subject fingerprint mismatch")
                try:
                    if int(event.get("subject_epoch", 0) or 0) != int(event_subject.get("subject_epoch", 0) or 0):
                        errors.append(f"event {event['sequence']}: subject epoch mismatch")
                except (TypeError, ValueError):
                    errors.append(f"event {event['sequence']}: subject epoch is invalid")
                if event.get("current_record_hash") != _hash(event_state):
                    errors.append(f"event {event['sequence']}: current record hash mismatch")
                if event.get("actor") != LIFECYCLE_CONTROLLER_ID:
                    errors.append(f"event {event['sequence']}: unauthorized controller actor")
                controller_identity = event.get("controller_identity")
                if not isinstance(controller_identity, dict):
                    errors.append(f"event {event['sequence']}: controller identity is missing")
                else:
                    if controller_identity.get("controller_id") != LIFECYCLE_CONTROLLER_ID:
                        errors.append(f"event {event['sequence']}: controller identity is not protected")
                    if controller_identity.get("controller_type") != LIFECYCLE_CONTROLLER_TYPE:
                        errors.append(f"event {event['sequence']}: controller type is not protected")
                if event.get("store_binding") != self.store_binding:
                    errors.append(f"event {event['sequence']}: store binding mismatch")
                accepted_records = event.get("accepted_evidence_records")
                if not isinstance(accepted_records, list):
                    errors.append(f"event {event['sequence']}: accepted evidence snapshots are missing")
                    accepted_records = []
                if state_name := str(event_state.get("state") or ""):
                    if state_name in PROTECTED_TRANSITION_STATES and case_history:
                        try:
                            self._validate_accepted_evidence(
                                accepted_records,
                                case_id=event_case_id,
                                subject=event_subject,
                                required_evidence=event.get("required_evidence") or [],
                                accepted_evidence=event.get("accepted_evidence") or [],
                            )
                        except (PermissionError, ValueError) as exc:
                            errors.append(f"event {event['sequence']}: invalid accepted evidence snapshots: {exc}")
                state_name = str(event_state.get("state") or "")
                requested_state = str(event.get("requested_state") or "")
                decision = str(event.get("decision") or "")
                if not case_history:
                    if (
                        event.get("prior_state") != "<GENESIS>"
                        or state_name != "UNVERIFIED_REPORT"
                        or requested_state != "UNVERIFIED_REPORT"
                        or decision != "INITIALIZED"
                    ):
                        errors.append(f"event {event['sequence']}: invalid lifecycle initialization")
                else:
                    prior = case_history[-1]
                    prior_state = str((prior.get("state") or {}).get("state") or "")
                    prior_snapshot = prior.get("state") if isinstance(prior.get("state"), dict) else {}
                    errors.extend(
                        f"event {event['sequence']}: {item}"
                        for item in validate_subject_epoch_transition(prior_snapshot, event_state)
                    )
                    if event.get("prior_state") != prior_state:
                        errors.append(f"event {event['sequence']}: prior state does not match case history")
                    logical_prior = str((prior.get("state") or {}).get("resume_state") or "") if prior_state == "BLOCKED" else prior_state
                    if decision == "PROCEED":
                        allowed = ALLOWED_TRANSITIONS.get(logical_prior, set())
                        if state_name != requested_state or requested_state not in allowed:
                            errors.append(f"event {event['sequence']}: out-of-order lifecycle advancement")
                    elif decision == "BLOCKED":
                        if state_name != "BLOCKED":
                            errors.append(f"event {event['sequence']}: BLOCKED decision has a non-blocked state")
                    elif decision == "ROLLBACK_REQUIRED":
                        if state_name != "ROLLBACK_REQUIRED":
                            errors.append(f"event {event['sequence']}: rollback decision has a non-rollback state")
                    elif decision in {"SUBJECT_BOUND", "ARTIFACT_BOUND", "SUBJECT_MUTATION_INVALIDATED_DOWNSTREAM"}:
                        if state_name not in {prior_state, "BLOCKED", "ROLLBACK_REQUIRED"}:
                            errors.append(f"event {event['sequence']}: subject binding advanced lifecycle state")
                    else:
                        errors.append(f"event {event['sequence']}: unknown lifecycle decision")
                if state_name in PROTECTED_TRANSITION_STATES:
                    authorization = event.get("transition_authorization")
                    if not case_history:
                        errors.append(f"event {event['sequence']}: protected initialization is invalid")
                    elif not isinstance(authorization, dict):
                        errors.append(f"event {event['sequence']}: protected transition lacks controller authorization")
                    else:
                        prior = case_history[-1]
                        try:
                            self._validate_transition_authorization(
                                authorization,
                                case_id=event_case_id,
                                expected_version=len(case_history),
                                current_record_hash=str(prior.get("current_record_hash") or ""),
                                next_record_hash=str(event.get("current_record_hash") or ""),
                                requested_state=requested_state,
                                decision=decision,
                                actor=str(event.get("actor") or ""),
                                idempotency_key=str(event.get("idempotency_key") or ""),
                                subject=event_subject,
                                required_evidence=event.get("required_evidence") or [],
                                accepted_evidence=event.get("accepted_evidence") or [],
                                rejected_evidence=event.get("rejected_evidence") or [],
                                policy_hash=event.get("policy_hash"),
                                toolchain_hash=event.get("toolchain_hash"),
                            )
                        except (PermissionError, ValueError) as exc:
                            errors.append(f"event {event['sequence']}: invalid controller authorization: {exc}")
                elif event.get("transition_authorization") is not None:
                    errors.append(f"event {event['sequence']}: unexpected controller authorization")
                if event["sequence"] != expected_sequence:
                    errors.append(f"event sequence gap: expected {expected_sequence}, got {event['sequence']}")
                if row["previous_hash"] != previous_hash:
                    errors.append(f"event {event['sequence']}: previous hash mismatch")
                material = dict(event)
                record_hash = material.pop("record_hash")
                record_mac = material.pop("record_mac", None)
                if _hash(material) != record_hash:
                    errors.append(f"event {event['sequence']}: record hash mismatch")
                if row["record_hash"] != record_hash:
                    errors.append(f"event {event['sequence']}: stored hash mismatch")
                if record_mac != row["record_mac"] or not isinstance(record_mac, str) or not hmac.compare_digest(record_mac, self._event_mac(record_hash)):
                    errors.append(f"event {event['sequence']}: record MAC mismatch")
                previous_hash = record_hash
                expected_sequence = event["sequence"] + 1
                latest_by_case[event_case_id] = event
                case_history.append(event)
            case_rows = conn.execute("SELECT * FROM lifecycle_cases").fetchall()
            for row in case_rows:
                case_id_value = str(row["case_id"])
                latest = latest_by_case.get(case_id_value)
                if latest is None:
                    errors.append(f"lifecycle case {case_id_value} has no event")
                    continue
                if row["current_hash"] != latest.get("current_record_hash"):
                    errors.append(f"lifecycle case {case_id_value} current record hash mismatch")
                try:
                    current_state = json.loads(row["state_json"])
                    if _hash(current_state) != row["current_hash"]:
                        errors.append(f"lifecycle case {case_id_value} state record hash mismatch")
                except (TypeError, json.JSONDecodeError) as exc:
                    errors.append(f"lifecycle case {case_id_value} state JSON is invalid: {exc}")
                if int(row["version"]) != int(latest.get("sequence", 0)):
                    # The global sequence is not the case version.  Count the
                    # case events instead, preserving concurrency semantics.
                    count = conn.execute("SELECT COUNT(*) FROM lifecycle_events WHERE case_id=?", (case_id_value,)).fetchone()[0]
                    if int(row["version"]) != int(count):
                        errors.append(f"lifecycle case {case_id_value} version mismatch")
            if case_id is not None and case_id not in latest_by_case:
                errors.append(f"lifecycle case {case_id} has no events")
            return {
                "valid": not errors,
                "case_id": case_id,
                "records": checked,
                "errors": sorted(set(errors)),
                "head_hash": previous_hash,
                "claim_boundary": "Only the verified append-only controller ledger is authoritative; exported JSON is not.",
            }
        finally:
            conn.close()
