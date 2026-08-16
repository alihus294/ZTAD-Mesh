from __future__ import annotations

import sqlite3
import json
from pathlib import Path

import pytest

from ztad.bug_lifecycle import (
    _gate_requirements,
    bind_artifact,
    bind_candidate,
    bind_merge_subject,
)
from ztad.bug_protocol import (
    derive_risk_class,
    validate_blast_radius,
    validate_change_plan,
    validate_classification_record,
    validate_diff_forensics,
    validate_progressive_exposure,
    validate_targeted_validation,
    validate_work_origin,
    validate_rollback_closure,
)
from ztad.crypto import generate_ed25519_keypair, sign_evidence
from ztad.evidence import validate_evidence_record, validate_machine_evidence_provenance
from ztad.evidence_bundle import _subject_lineage_errors, validate_evidence_bundle
from ztad.lifecycle_store import LifecycleStore, _hash
from ztad.risk import classify_risk
from ztad.subject import apply_subject_update, subject_fingerprint, subject_from_record, validate_subject
from ztad.trust import _HOST_ACCEPTANCE_TOKEN, load_host_accepted_trust_roots
from ztad.util import canonical_json, load_data, sha256_bytes, utc_now


ROOT = Path(__file__).resolve().parents[1]
POLICY = load_data(ROOT / "policies/bug-to-production-policy.yaml")
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def _signed_lifecycle_authorization(
    *,
    current: dict,
    next_record: dict,
    target: str,
    decision: str,
    private_key: Path,
    required_evidence: list[str] | tuple[str, ...] = (),
    accepted_evidence: list[str] | tuple[str, ...] = (),
    rejected_evidence: list[str] | tuple[str, ...] = (),
    actor: str = "platform:lifecycle-controller",
    store: LifecycleStore,
    accepted_evidence_records: list[dict] | tuple[dict, ...] = (),
) -> tuple[dict, str]:
    prepared = dict(next_record)
    prepared.pop("idempotent_replay", None)
    prepared["authoritative_lifecycle"] = True
    prepared["authority_store"] = "controller-owned-sqlite"
    prepared["subject_fingerprint"] = subject_fingerprint(prepared)
    next_hash = _hash(prepared)
    preparation = store.prepare_transition_authorization(
        current["case_id"],
        next_record,
        expected_version=int(current["store_version"]),
        requested_state=target,
        decision=decision,
        actor=actor,
        required_evidence=required_evidence,
        accepted_evidence=accepted_evidence,
        accepted_evidence_records=accepted_evidence_records,
        rejected_evidence=rejected_evidence,
    )
    idempotency_key = preparation["idempotency_key"]
    subject = {key: value for key, value in subject_from_record(prepared).items() if value is not None}
    metadata = {
        "case_id": current["case_id"],
        "expected_version": int(current["store_version"]),
        "current_record_hash": current["store_record_hash"],
        "next_record_hash": next_hash,
        "requested_state": target,
        "decision": decision,
        "actor": actor,
        "idempotency_key": idempotency_key,
        "subject_fingerprint": subject_fingerprint(subject),
        "subject_epoch": int(subject.get("subject_epoch") or 0),
        "required_evidence": sorted(set(required_evidence)),
        "accepted_evidence": sorted(set(accepted_evidence)),
        "rejected_evidence": sorted(set(rejected_evidence)),
        "policy_hash": prepared.get("policy_bundle_hash"),
        "toolchain_hash": prepared.get("toolchain_hash"),
        "controller_id": "platform:lifecycle-controller",
        "controller_type": "protected-lifecycle-controller",
        "identity_source": "local-runtime-context",
        "authentication_mechanism": "protected-transition-signature-required",
        "event_commitment": preparation["event_commitment"],
        "event_occurred_at": preparation["event_occurred_at"],
    }
    authorization = {
        "evidence_id": f"ev-transition-{target.lower()}-{current['store_version']}",
        "type": "LIFECYCLE_TRANSITION_AUTHORIZATION",
        "trust_level": "E6",
        "producer": "platform:lifecycle-controller",
        "repository": subject.get("repository") or current.get("repository"),
        "subject_fingerprint": subject_fingerprint(subject),
        **subject,
        "environment": "controller",
        "created_at": preparation["event_occurred_at"],
        "invalidated_by": [],
        "status": "APPROVED",
        "metadata": metadata,
        "signature_or_attestation": None,
    }
    return sign_evidence(authorization, private_key_path=private_key, key_id="lifecycle-key"), idempotency_key


def _bound(tmp_path: Path, state: str = "CHANGE_PLANNED") -> dict:
    contract = tmp_path / "contract.json"
    contract.write_text("{\"change\":\"x\"}\n", encoding="utf-8")
    result = bind_candidate(
        {
            "case_id": "CASE-SUBJECT-001",
            "state": state,
            "last_completed_state": state,
            "repository": "owner/repo",
            "base_sha": "0" * 40,
            "protected_base_sha": "0" * 40,
            "domains": ["GENERAL"],
            "subject_epoch": 0,
            "subject_version": 1,
            "evidence_refs": {"CI": ["ev-ci"]},
        },
        contract_path=contract,
        head_sha="1" * 40,
        diff_hash=DIGEST_A,
        policy_bundle_hash=DIGEST_B,
        toolchain_hash=DIGEST_C,
    )
    result["state"] = state
    result["last_completed_state"] = state
    return result


def test_candidate_mutation_invalidates_ci_and_increments_epoch(tmp_path: Path) -> None:
    record = _bound(tmp_path, state="CI_PASS")
    record["evidence_refs"] = {"PROTECTED_CI": ["ev-ci"]}
    mutated = apply_subject_update(record, {"pr_head_sha": "2" * 40}, reason="test")
    assert mutated["state"] == "BLOCKED"
    assert mutated["resume_state"] == "CHANGE_PLANNED"
    assert mutated["subject_epoch"] == record["subject_epoch"] + 1
    assert mutated["evidence_refs"] == {}
    assert mutated["historical_evidence_refs"]["PROTECTED_CI"] == ["ev-ci"]


def test_artifact_mutation_invalidates_staging_and_production_mutation_requires_rollback(tmp_path: Path) -> None:
    staging = _bound(tmp_path, state="STAGING_PASS")
    staging["artifact_digest"] = DIGEST_A
    changed = bind_artifact(staging, DIGEST_B)
    assert changed["state"] == "BLOCKED"
    assert changed["resume_state"] == "CI_PASS"

    production = _bound(tmp_path, state="PRODUCTION_RELEASED")
    production["artifact_digest"] = DIGEST_A
    production["deployed_revision"] = "1" * 40
    rolled_back = apply_subject_update(production, {"artifact_digest": DIGEST_B}, reason="test")
    assert rolled_back["state"] == "ROLLBACK_REQUIRED"


def test_pr_head_and_merged_main_are_distinct_and_proven(tmp_path: Path) -> None:
    record = _bound(tmp_path)
    merged = bind_merge_subject(
        record,
        merged_main_sha="2" * 40,
        merge_method="SQUASH",
        merge_provenance={
            "pr_head_sha": "1" * 40,
            "reviewed_diff_hash": DIGEST_A,
            "merged_main_sha": "2" * 40,
            "transformation": "protected squash merge",
        },
        post_merge_ci_run_id="run-main-1",
    )
    assert merged["pr_head_sha"] != merged["merged_main_sha"]
    assert merged["head_sha"] == merged["merged_main_sha"]
    assert merged["merge_provenance"]["pr_head_sha"] == "1" * 40


def test_risk_mapping_and_monotonic_floors() -> None:
    assert derive_risk_class(risk="R4", domains=["GENERAL"]) == "CRITICAL"
    assert derive_risk_class(risk="R1", domains=["FINANCIAL"]) == "HIGH"
    assert derive_risk_class(risk="R0", domains=["AUTH_TENANT"]) == "HIGH"


def test_canonical_risk_engine_applies_domain_floor_from_contract() -> None:
    result = classify_risk(
        {
            "title": "Bounded change",
            "scope": {"expected_components": ["app.py"], "domains": ["FINANCIAL"], "data_classification": "C1", "service_criticality": "tier_3"},
            "requirements": {"test_oracles": ["oracle"], "negative_cases": ["denied case"], "assumptions": []},
            "verification": {"test_oracles": ["oracle"], "negative_cases": ["denied case"]},
            "release": {"rollback_strategy": "restore"},
            "governance": {"requested_risk": "R0", "product_owner": "owner", "engineering_owner": "engineer"},
        },
        policy=load_data(ROOT / "policies/bug-to-production-policy.yaml"),
    )
    assert result.risk in {"R3", "R4"}


def test_all_domain_profile_checks_are_unioned_into_the_gate() -> None:
    record = {"risk": "R1", "risk_class": "HIGH", "domains": ["FINANCIAL", "AUTH_TENANT"], "mode": "HOTFIX"}
    _minimum, required = _gate_requirements(POLICY, "TARGETED_VALIDATION_PASS", record)
    assert set(POLICY["domain_profiles"]["FINANCIAL"]["required_checks"]).issubset(required)
    assert set(POLICY["domain_profiles"]["AUTH_TENANT"]["required_checks"]).issubset(required)


def test_classification_blast_plan_targeted_and_diff_require_semantics() -> None:
    assert validate_classification_record(
        {
            "classification": "CONFIRMED_BUG",
            "classification_evidence": ["ev"],
            "expected_behavior": "The charge is idempotent",
            "classification_record": {
            "evidence": ["ev"],
            "reproduction_status": "REPRODUCED",
            "authoritative_expected_behavior": "The charge is idempotent",
            "competing_explanations_tested": ["duplicate request"],
            "environment_findings": ["production-like fixture"],
            "unresolved_ambiguities": [],
            "source_conflicts": [],
            "implementation_justified": True,
            },
        }
    ) == []
    assert validate_blast_radius(
        {
            "direct": ["app.py"],
            "adjacent": ["worker"],
            "security_boundaries": [],
            "data_boundaries": [],
            "coverage": {
                "direct_components": ["app.py"],
                "indirect_components": ["worker"],
                "data_flows": ["charge"],
                "tenant_boundaries": ["tenant"],
                "permissions": ["charge:create"],
                "financial_effects": ["none"],
                "external_providers": ["none"],
                "migration_effects": ["none"],
                "rollout_effects": ["canary"],
                "observability_effects": ["latency"],
                "failure_modes": ["retry"],
                "security_effects": ["none"],
                "privacy_effects": ["none"],
                "backward_compatibility": ["compatible"],
                "unknown_couplings": [],
            },
        }
    )
    assert validate_blast_radius(
        {
            "direct_components": ["app.py"],
            "adjacent_components": ["worker"],
            "callers_callees": ["caller"],
            "api_contracts": ["charge"],
            "database_data_boundaries": ["none"],
            "tenant_auth_boundaries": ["tenant"],
            "financial_zatca_boundaries": ["none"],
            "provider_boundaries": ["none"],
            "concurrency_idempotency_boundaries": ["idempotency"],
            "deployment_infra_boundaries": ["canary"],
            "tests": ["targeted"],
            "observability": ["latency"],
            "migration_rollback_impact": ["none"],
            "invariants": ["no duplicate"],
            "validation_depth": ["semantic"],
        }
    ) == []
    assert validate_change_plan(
        {
            "root_cause_summary": "missing idempotency",
            "intended_fix": "add idempotency key",
            "expected_files": ["app.py"],
            "tests": ["targeted"],
            "forbidden_scope": ["infra"],
            "database_impact": "none",
            "external_side_effects": "none",
            "rollback_or_containment": "restore artifact",
            "file_reasons": {
                "app.py": {
                    "why": "fix duplicate charge",
                    "root_cause_mechanism": "missing idempotency key",
                    "validation": "targeted payment test",
                }
            }
        }
    ) == []
    assert validate_targeted_validation(
        {
            "semantic_case_matrix": [
                {"case": name, "status": "PASS"}
                for name in (
                    "original_reproduction",
                    "normal_case",
                    "nearest_boundary",
                    "invalid_input",
                    "empty_null_missing_input",
                    "repeated_operation",
                    "retry_behavior",
                    "stale_state",
                    "error_path",
                    "idempotency",
                    "financial_duplicate_prevention",
                    "ledger_consistency",
                )
            ],
            "original_reproduction_passed": True,
        },
        risk_class="HIGH",
        domains=["FINANCIAL"],
    ) == []
    assert validate_targeted_validation({}, risk_class="HIGH", domains=["FINANCIAL"])
    assert validate_diff_forensics(
        {
            "complete_changed_file_list": True,
            "actual_changed_files": ["app.py"],
            "allowed_scope": ["app.py"],
            "actual_risk": "R2",
            "actual_domains": ["GENERAL"],
            "analysis_method": "protected diff scanner",
            "files": [{"path": "app.py", "planned": True, "justification": "fix idempotency", "security_impact": "none", "data_domain_impact": "none", "generated": False, "category": "runtime"}],
        }
    ) == []


def test_progressive_critical_exposure_requires_write_and_owner_stop() -> None:
    metadata = {"strategy": "CANARY", "rollback_trigger": "error threshold", "stop_conditions": ["error"], "scope_limit": "one tenant"}
    assert validate_progressive_exposure(metadata, risk_class="CRITICAL")
    assert validate_progressive_exposure(
        metadata | {"write_gate": True, "owner_stop_condition": "owner stops on anomaly", "rollback_trigger_hash": DIGEST_A},
        risk_class="CRITICAL",
    ) == []


def test_fake_machine_evidence_cannot_claim_deterministic_execution() -> None:
    record = {"type": "TARGETED_VALIDATION_PASSED", "producer": "agent:model", "exit_code": 0, "metadata": {}}
    assert validate_machine_evidence_provenance(record)
    domain_record = dict(record, type="FINANCIAL_INVARIANTS_PASSED")
    assert validate_machine_evidence_provenance(domain_record)


def test_terminal_gate_cannot_be_satisfied_by_model_or_local_producer() -> None:
    subject = {
        "repository": "owner/repo",
        "protected_base_sha": "0" * 40,
        "pr_head_sha": "1" * 40,
        "reviewed_diff_hash": DIGEST_A,
        "change_contract_hash": DIGEST_B,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "subject_epoch": 0,
        "subject_version": 1,
        "subject_fingerprint": subject_fingerprint({
            "repository": "owner/repo",
            "protected_base_sha": "0" * 40,
            "pr_head_sha": "1" * 40,
            "reviewed_diff_hash": DIGEST_A,
            "change_contract_hash": DIGEST_B,
            "policy_bundle_hash": DIGEST_B,
            "toolchain_hash": DIGEST_C,
            "subject_epoch": 0,
            "subject_version": 1,
        }),
    }
    record = {
        "evidence_id": "ev-agent-patch-001",
        "type": "CANDIDATE_PATCH_CREATED",
        "trust_level": "E2",
        "producer": "agent:model",
        **subject,
        "base_sha": subject["protected_base_sha"],
        "head_sha": subject["pr_head_sha"],
        "diff_hash": subject["reviewed_diff_hash"],
        "subject_fingerprint": subject_fingerprint(subject),
        "environment": "local",
        "created_at": utc_now(),
        "invalidated_by": [],
        "status": "PASSED",
        "metadata": {},
    }
    bundle = {
        "schema_version": 2,
        "issue_id": "CASE-CLOSED-AGENT-001",
        "original_report": "A confirmed defect.",
        "classification": "CONFIRMED_BUG",
        **subject,
        "base_sha": subject["protected_base_sha"],
        "final_sha": subject["pr_head_sha"],
        "final_state": "CLOSED",
        "closure_class": "CODE_FIX",
        "subject_fingerprint": subject_fingerprint(subject),
        "evidence_records": [record],
        "lifecycle_events": [],
    }
    errors = validate_evidence_bundle(
        bundle,
        bundle_schema=load_data(ROOT / "schemas/evidence-bundle.schema.json"),
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        policy=POLICY,
    )
    assert any("controller or protected platform" in error for error in errors)


def test_lifecycle_store_rejects_non_initial_state_and_non_proceed_decision(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "initial-state.db")
    with pytest.raises(ValueError, match="must begin at UNVERIFIED_REPORT"):
        store.initialize({"case_id": "CASE-LEDGER-INITIAL-001", "state": "CLOSED", "repository": "owner/repo"})
    initial = store.initialize({"case_id": "CASE-LEDGER-INITIAL-002", "state": "UNVERIFIED_REPORT", "repository": "owner/repo"})
    with pytest.raises(PermissionError, match="PROCEED"):
        store.transition(
            "CASE-LEDGER-INITIAL-002",
            dict(initial, state="SOURCE_OF_TRUTH_RESOLVED"),
            actor="platform:lifecycle-controller",
            expected_version=int(initial["store_version"]),
            requested_state="SOURCE_OF_TRUTH_RESOLVED",
            decision="BLOCKED",
        )


def test_lifecycle_store_detects_tampering_and_stale_writes(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "lifecycle.db")
    initial = store.initialize({"case_id": "CASE-LEDGER-001", "state": "UNVERIFIED_REPORT", "repository": "owner/repo", "subject_epoch": 0})
    next_record = dict(initial, state="SOURCE_OF_TRUTH_RESOLVED")
    stored = store.transition(
        "CASE-LEDGER-001",
        next_record,
        actor="platform:lifecycle-controller",
        expected_version=1,
        requested_state="SOURCE_OF_TRUTH_RESOLVED",
        decision="PROCEED",
    )
    with pytest.raises(RuntimeError, match="Optimistic concurrency"):
        store.transition(
            "CASE-LEDGER-001",
            next_record,
            actor="platform:lifecycle-controller",
            expected_version=1,
            requested_state="SOURCE_OF_TRUTH_RESOLVED",
            decision="PROCEED",
        )
    connection = sqlite3.connect(store.path)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("UPDATE lifecycle_events SET requested_state='CLOSED' WHERE sequence=2")
    connection.close()
    assert store.verify_event_chain(case_id="CASE-LEDGER-001")["valid"]
    assert stored["store_version"] == 2


def test_lifecycle_store_rejects_unbound_subject_progression_and_side_effects(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "authority.db")
    initial = store.initialize({
        "case_id": "CASE-LEDGER-002",
        "state": "UNVERIFIED_REPORT",
        "repository": "owner/repo",
        "subject_epoch": 0,
        "subject_version": 1,
    })
    changed = dict(
        initial,
        state="SOURCE_OF_TRUTH_RESOLVED",
        protected_base_sha="0" * 40,
        pr_head_sha="1" * 40,
        reviewed_diff_hash=DIGEST_A,
        change_contract_hash=DIGEST_B,
        policy_bundle_hash=DIGEST_B,
        toolchain_hash=DIGEST_C,
        risk="R4",
    )
    with pytest.raises(PermissionError, match="subject-binding|subject_epoch"):
        store.transition(
            "CASE-LEDGER-002",
            changed,
            actor="platform:lifecycle-controller",
            expected_version=int(initial["store_version"]),
            requested_state="SOURCE_OF_TRUTH_RESOLVED",
            decision="PROCEED",
        )

    bound = dict(initial)
    bound.update({
        "pr_head_sha": "1" * 40,
        "reviewed_diff_hash": DIGEST_A,
        "change_contract_hash": DIGEST_B,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "protected_base_sha": "0" * 40,
        "base_sha": "0" * 40,
        "head_sha": "1" * 40,
        "diff_hash": DIGEST_A,
        "subject_epoch": 1,
        "subject_fingerprint": subject_fingerprint({"repository": "owner/repo", "protected_base_sha": "0" * 40, "pr_head_sha": "1" * 40, "reviewed_diff_hash": DIGEST_A, "change_contract_hash": DIGEST_B, "policy_bundle_hash": DIGEST_B, "toolchain_hash": DIGEST_C, "subject_epoch": 1, "subject_version": 1}),
        "subject_mutations": [{"changed_fields": ["change_contract_hash", "pr_head_sha", "policy_bundle_hash", "reviewed_diff_hash", "toolchain_hash"]}],
        "evidence_refs": {},
        "state": "UNVERIFIED_REPORT",
    })
    with pytest.raises(PermissionError, match="non-subject"):
        store.transition(
            "CASE-LEDGER-002",
            dict(bound, risk="R4"),
            actor="platform:lifecycle-controller",
            expected_version=int(initial["store_version"]),
            requested_state="UNVERIFIED_REPORT",
            decision="SUBJECT_BOUND",
        )


def test_reported_defect_cannot_bypass_lifecycle_but_feature_can() -> None:
    assert validate_work_origin({"origin": "REPORTED_DEFECT"})
    assert validate_work_origin({"origin": "FEATURE"}) == []
    assert validate_work_origin({"origin": "FEATURE", "bug_lifecycle_case_id": "CASE-001"})


def test_lifecycle_store_rejects_blocked_state_that_resumes_in_the_future(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "blocked-future.db")
    initial = store.initialize({
        "case_id": "CASE-BLOCKED-FUTURE-001",
        "state": "UNVERIFIED_REPORT",
        "repository": "owner/repo",
    })
    with pytest.raises(PermissionError, match="future"):
        store.transition(
            initial["case_id"],
            dict(
                initial,
                state="BLOCKED",
                resume_state="PATCH_IMPLEMENTED",
                blocked_target="PATCH_IMPLEMENTED",
                blockers=["forged future resume"],
            ),
            actor="platform:lifecycle-controller",
            expected_version=int(initial["store_version"]),
            requested_state="SOURCE_OF_TRUTH_RESOLVED",
            decision="BLOCKED",
        )


def test_evidence_cannot_bind_a_different_pr_subject() -> None:
    subject = {
        "repository": "owner/repo",
        "protected_base_sha": "0" * 40,
        "pr_head_sha": "1" * 40,
        "reviewed_diff_hash": DIGEST_A,
        "change_contract_hash": DIGEST_B,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "subject_epoch": 2,
        "subject_version": 1,
    }
    evidence = {
        "evidence_id": "ev-wrong-subject-001",
        "type": "PROTECTED_CI",
        "trust_level": "E2",
        "producer": "local:fixture",
        "repository": "owner/repo",
        "base_sha": "0" * 40,
        "head_sha": "2" * 40,
        "diff_hash": DIGEST_C,
        "change_contract_hash": DIGEST_B,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "environment": "local",
        "created_at": utc_now(),
        "invalidated_by": [],
        "status": "PASSED",
        "exit_code": 0,
        "metadata": {},
    }
    errors = validate_evidence_record(evidence, schema=load_data(ROOT / "schemas/evidence.schema.json"), subject=subject, minimum_trust="E2", require_authoritative_signature=False)
    assert any("pr_head_sha" in error or "reviewed_diff_hash" in error for error in errors)


def test_resolved_no_code_bundle_replays_authoritative_lifecycle(tmp_path: Path) -> None:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_ed25519_keypair(private, public)
    roots = {
        "version": 1,
        "keys": {
            "lifecycle-key": {
                "algorithm": "ed25519",
                "public_key_pem": public.read_text(encoding="utf-8"),
                "status": "ACTIVE",
                "allowed_trust_levels": ["E6"],
                "allowed_producers": ["platform:lifecycle-controller"],
                "allowed_types": ["LIFECYCLE_TRANSITION_AUTHORIZATION"],
                "allowed_environments": ["controller"],
            }
        },
    }
    roots["keys"]["validation-key"] = {
        "algorithm": "ed25519",
        "public_key_pem": public.read_text(encoding="utf-8"),
        "status": "ACTIVE",
        "allowed_trust_levels": ["E3"],
        "allowed_producers": ["platform:protected-validation"],
        "allowed_types": ["RESOLVED_NO_CODE_PROVEN"],
        "allowed_environments": ["ci"],
    }
    roots_path = tmp_path / "host-trust-roots.json"
    roots_path.write_text(json.dumps(roots), encoding="utf-8")
    authority = load_host_accepted_trust_roots(
        roots_path,
        accepted_digest=sha256_bytes(canonical_json(roots)),
        acceptance_id="test-host-acceptance",
        host_acceptance_token=_HOST_ACCEPTANCE_TOKEN,
    )
    store = LifecycleStore(tmp_path / "no-code.db", authority_trust_roots=authority)
    initial = store.initialize({
        "case_id": "CASE-NOCODE-001",
        "state": "UNVERIFIED_REPORT",
        "last_completed_state": "UNVERIFIED_REPORT",
        "repository": "owner/repo",
        "protected_base_sha": "0" * 40,
        "pr_head_sha": "1" * 40,
        "reviewed_diff_hash": DIGEST_A,
        "change_contract_hash": DIGEST_B,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "subject_epoch": 0,
        "subject_version": 1,
    })
    def proceed(
        current: dict,
        target: str,
        *,
        accepted: list[str] | tuple[str, ...] = (),
        accepted_records: list[dict] | tuple[dict, ...] = (),
    ) -> dict:
        next_record = dict(current, state=target, last_completed_state=target, resume_state=None, blocked_target=None, blockers=[])
        if target == "RESOLVED_NO_CODE":
            next_record.update(final_state=target, closure_class=target)
        authorization, idempotency_key = _signed_lifecycle_authorization(
            current=current,
            next_record=next_record,
            target=target,
            decision="PROCEED",
            private_key=private,
            required_evidence=["RESOLVED_NO_CODE_PROVEN"] if accepted else [],
            accepted_evidence=accepted,
            store=store,
            accepted_evidence_records=accepted_records,
        ) if accepted else (None, None)
        return store.transition(
            "CASE-NOCODE-001",
            next_record,
            actor="platform:lifecycle-controller",
            expected_version=int(current["store_version"]),
            requested_state=target,
            decision="PROCEED",
            required_evidence=["RESOLVED_NO_CODE_PROVEN"] if accepted else [],
            accepted_evidence=accepted,
            accepted_evidence_records=accepted_records,
            idempotency_key=idempotency_key,
            transition_authorization=authorization,
        )

    source = proceed(initial, "SOURCE_OF_TRUTH_RESOLVED")
    classified = proceed(source, "ISSUE_CLASSIFIED")
    proof = {
        "evidence_id": "ev-no-code-001",
        "type": "RESOLVED_NO_CODE_PROVEN",
        "lifecycle_case_id": "CASE-NOCODE-001",
        "trust_level": "E3",
        "producer": "platform:protected-validation",
        "repository": "owner/repo",
        "base_sha": "0" * 40,
        "head_sha": "1" * 40,
        "diff_hash": DIGEST_A,
        "change_contract_hash": DIGEST_B,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "subject_epoch": 0,
        "subject_version": 1,
        "subject_fingerprint": subject_fingerprint({
            "repository": "owner/repo",
            "protected_base_sha": "0" * 40,
            "pr_head_sha": "1" * 40,
            "reviewed_diff_hash": DIGEST_A,
            "change_contract_hash": DIGEST_B,
            "policy_bundle_hash": DIGEST_B,
            "toolchain_hash": DIGEST_C,
            "subject_epoch": 0,
            "subject_version": 1,
        }),
        "environment": "ci",
        "created_at": utc_now(),
        "invalidated_by": [],
        "status": "PASSED",
        "exit_code": 0,
        "metadata": {"resolution": "expected behavior"},
        "signature_or_attestation": None,
    }
    signed = sign_evidence(proof, private_key_path=private, key_id="validation-key")
    resolved = proceed(
        classified,
        "RESOLVED_NO_CODE",
        accepted=["ev-no-code-001"],
        accepted_records=[signed],
    )
    bundle_subject = {
        "repository": "owner/repo",
        "protected_base_sha": "0" * 40,
        "pr_head_sha": "1" * 40,
        "reviewed_diff_hash": DIGEST_A,
        "change_contract_hash": DIGEST_B,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "subject_epoch": 0,
        "subject_version": 1,
    }
    bundle = {
        "schema_version": 2,
        "issue_id": "CASE-NOCODE-001",
        "original_report": "The reported behavior is expected.",
        "classification": "EXPECTED_BEHAVIOR",
        "repository": "owner/repo",
        "final_state": "RESOLVED_NO_CODE",
        "closure_class": "RESOLVED_NO_CODE",
        **bundle_subject,
        "subject_fingerprint": subject_fingerprint(bundle_subject),
        "evidence_records": [signed],
        "lifecycle_events": store.events(),
        "claim_boundary": "No-code resolution is not a production-fix claim.",
    }
    errors = validate_evidence_bundle(
        bundle,
        bundle_schema=load_data(ROOT / "schemas/evidence-bundle.schema.json"),
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        trust_roots=authority,
        policy=POLICY,
    )
    assert errors == [], errors
    forged_events = [dict(event) for event in bundle["lifecycle_events"]]
    forged_events[-1].pop("transition_authorization", None)
    forged_bundle = dict(bundle, lifecycle_events=forged_events)
    forged_errors = validate_evidence_bundle(
        forged_bundle,
        bundle_schema=load_data(ROOT / "schemas/evidence-bundle.schema.json"),
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        trust_roots=authority,
        policy=POLICY,
    )
    assert any("signed transition authorization" in item for item in forged_errors)
    assert resolved["state"] == "RESOLVED_NO_CODE"

    unsigned = dict(bundle, evidence_records=[dict(signed, signature_or_attestation=None)])
    unsigned_errors = validate_evidence_bundle(
        unsigned,
        bundle_schema=load_data(ROOT / "schemas/evidence-bundle.schema.json"),
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        trust_roots=authority,
        policy=POLICY,
    )
    assert any("signature" in error.lower() or "attestation" in error.lower() for error in unsigned_errors)

    copied = dict(bundle, evidence_records=[dict(signed, lifecycle_case_id="CASE-OTHER-001")])
    copied_errors = validate_evidence_bundle(
        copied,
        bundle_schema=load_data(ROOT / "schemas/evidence-bundle.schema.json"),
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        trust_roots=authority,
        policy=POLICY,
    )
    assert any("another lifecycle case" in error for error in copied_errors)

    wrong_private = tmp_path / "wrong-private.pem"
    wrong_public = tmp_path / "wrong-public.pem"
    generate_ed25519_keypair(wrong_private, wrong_public)
    wrong_root_signed = sign_evidence(proof, private_key_path=wrong_private, key_id="validation-key")
    wrong_root_bundle = dict(bundle, evidence_records=[wrong_root_signed])
    wrong_root_errors = validate_evidence_bundle(
        wrong_root_bundle,
        bundle_schema=load_data(ROOT / "schemas/evidence-bundle.schema.json"),
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        trust_roots=authority,
        policy=POLICY,
    )
    assert any("signature" in error.lower() or "key" in error.lower() for error in wrong_root_errors)

    replaced_epoch = dict(bundle, subject_epoch=1)
    replaced_epoch_errors = validate_evidence_bundle(
        replaced_epoch,
        bundle_schema=load_data(ROOT / "schemas/evidence-bundle.schema.json"),
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        trust_roots=authority,
        policy=POLICY,
    )
    assert any("subject_epoch" in error for error in replaced_epoch_errors)

    changed_ledger_events = [dict(event) for event in bundle["lifecycle_events"]]
    changed_ledger_events[1] = dict(changed_ledger_events[1], subject_epoch=99)
    changed_ledger_bundle = dict(bundle, lifecycle_events=changed_ledger_events)
    changed_ledger_errors = validate_evidence_bundle(
        changed_ledger_bundle,
        bundle_schema=load_data(ROOT / "schemas/evidence-bundle.schema.json"),
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        trust_roots=authority,
        policy=POLICY,
    )
    assert any("record hash" in error.lower() or "subject epoch" in error.lower() for error in changed_ledger_errors)

    wrong_controller_events = [dict(event) for event in bundle["lifecycle_events"]]
    wrong_controller_events[-1] = dict(wrong_controller_events[-1])
    wrong_controller_events[-1]["controller_identity"] = dict(
        wrong_controller_events[-1]["controller_identity"],
        controller_type="unauthorized-controller",
    )
    wrong_controller_bundle = dict(bundle, lifecycle_events=wrong_controller_events)
    wrong_controller_errors = validate_evidence_bundle(
        wrong_controller_bundle,
        bundle_schema=load_data(ROOT / "schemas/evidence-bundle.schema.json"),
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        trust_roots=authority,
        policy=POLICY,
    )
    assert any("controller type" in error.lower() or "record hash" in error.lower() for error in wrong_controller_errors)

    missing_mac_events = [dict(event) for event in bundle["lifecycle_events"]]
    missing_mac_events[-1].pop("record_mac", None)
    missing_mac_bundle = dict(bundle, lifecycle_events=missing_mac_events)
    missing_mac_errors = validate_evidence_bundle(
        missing_mac_bundle,
        bundle_schema=load_data(ROOT / "schemas/evidence-bundle.schema.json"),
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        trust_roots=authority,
        policy=POLICY,
    )
    assert any("record mac" in error.lower() for error in missing_mac_errors)

    rehashed_events = [dict(event) for event in bundle["lifecycle_events"]]
    rehashed_events[0]["occurred_at"] = "2026-08-15T10:00:00Z"
    previous_hash = "sha256:" + "0" * 64
    for event in rehashed_events:
        event["previous_hash"] = previous_hash
        material = dict(event)
        material.pop("record_hash", None)
        material.pop("record_mac", None)
        event["record_hash"] = _hash(material)
        previous_hash = event["record_hash"]
    rehashed_bundle = dict(bundle, lifecycle_events=rehashed_events)
    rehashed_errors = validate_evidence_bundle(
        rehashed_bundle,
        bundle_schema=load_data(ROOT / "schemas/evidence-bundle.schema.json"),
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        trust_roots=authority,
        policy=POLICY,
    )
    assert rehashed_errors, "Rehashing a modified lifecycle ledger must not create a valid terminal claim"


def test_closed_code_fix_bundle_without_gate_replay_is_invalid() -> None:
    bundle = {
        "schema_version": 2,
        "issue_id": "CASE-CLOSED-001",
        "original_report": "A confirmed defect.",
        "classification": "CONFIRMED_BUG",
        "repository": "owner/repo",
        "final_state": "CLOSED",
        "closure_class": "CODE_FIX",
        "subject_fingerprint": subject_fingerprint({"repository": "owner/repo", "subject_epoch": 0, "subject_version": 1}),
        "evidence_records": [],
        "lifecycle_events": [],
    }
    errors = validate_evidence_bundle(
        bundle,
        bundle_schema=load_data(ROOT / "schemas/evidence-bundle.schema.json"),
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        policy=POLICY,
    )
    assert any("missing" in error.lower() for error in errors)
    assert any("lifecycle" in error.lower() for error in errors)


def test_financial_rollback_cannot_close_on_app_health_only() -> None:
    errors = validate_rollback_closure(
        {
            "rollback_completed": True,
            "post_rollback_health_verified": True,
            "stable_artifact_digest": DIGEST_A,
            "rollback_receipt": "receipt-1",
            "domain_checks": [{"type": "APP_HEALTH", "status": "PASS"}],
        },
        domains=["FINANCIAL"],
        policy=POLICY,
    )
    assert any("FINANCIAL_RECONCILIATION_PASSED" in error for error in errors)


def test_raw_lifecycle_store_cannot_reach_release_without_controller_authorization(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "raw-release-bypass.db")
    current = store.initialize({
        "case_id": "CASE-RAW-RELEASE-BYPASS-001",
        "state": "UNVERIFIED_REPORT",
        "repository": "owner/repo",
    })
    for target in (
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
    ):
        if target == "READY_FOR_OWNER_RELEASE":
            with pytest.raises(PermissionError, match="authorization|evidence|actor|runtime"):
                store.transition(
                    current["case_id"],
                    dict(current, state=target),
                    actor="platform:agent-forged",
                    expected_version=current["store_version"],
                    requested_state=target,
                    decision="PROCEED",
                )
            break
        current = store.transition(
            current["case_id"],
            dict(current, state=target),
            actor="platform:lifecycle-controller",
            expected_version=current["store_version"],
            requested_state=target,
            decision="PROCEED",
        )


def test_idempotency_key_reuse_with_different_meaning_is_rejected(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "idempotency-reuse.db")
    current = store.initialize({
        "case_id": "CASE-IDEMPOTENCY-REUSE-001",
        "state": "UNVERIFIED_REPORT",
        "repository": "owner/repo",
    })
    current = store.transition(
        current["case_id"],
        dict(current, state="SOURCE_OF_TRUTH_RESOLVED"),
        actor="platform:lifecycle-controller",
        expected_version=current["store_version"],
        requested_state="SOURCE_OF_TRUTH_RESOLVED",
        decision="PROCEED",
        idempotency_key="same-request-key",
    )
    with pytest.raises((ValueError, RuntimeError), match="idempotency"):
        store.transition(
            current["case_id"],
            dict(current, state="ISSUE_CLASSIFIED"),
            actor="platform:lifecycle-controller",
            expected_version=current["store_version"],
            requested_state="ISSUE_CLASSIFIED",
            decision="PROCEED",
            idempotency_key="same-request-key",
        )


def test_malformed_risk_and_unknown_domain_fail_closed() -> None:
    with pytest.raises(ValueError, match="risk"):
        derive_risk_class(risk="R9", domains=["GENERAL"])
    with pytest.raises(ValueError, match="domain"):
        derive_risk_class(risk="R0", domains=["UNCLASSIFIED"])


def test_e3_evidence_requires_a_real_signature_even_when_gate_floor_is_e2() -> None:
    subject = {
        "repository": "owner/repo",
        "base_sha": "0" * 40,
        "head_sha": "1" * 40,
            "change_contract_hash": DIGEST_B,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "subject_epoch": 0,
        "subject_version": 1,
    }
    record = {
        "evidence_id": "ev-unsigned-e3-001",
        "type": "LOCAL_OBSERVATION",
        "trust_level": "E3",
        "producer": "platform:protected-ci",
        "repository": "owner/repo",
        "base_sha": subject["base_sha"],
        "head_sha": subject["head_sha"],
        "change_contract_hash": DIGEST_A,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "environment": "ci",
        "created_at": utc_now(),
        "invalidated_by": [],
        "status": "PASSED",
        "metadata": {},
    }
    errors = validate_evidence_record(
        record,
        schema=load_data(ROOT / "schemas/evidence.schema.json"),
        subject=subject,
        minimum_trust="E2",
        require_authoritative_signature=False,
    )
    assert any("signature" in error.lower() or "trust root" in error.lower() for error in errors)


def test_machine_provenance_rejects_invalid_time_and_command_binding() -> None:
    subject = {
        "repository": "owner/repo",
        "protected_base_sha": "0" * 40,
        "pr_head_sha": "1" * 40,
        "reviewed_diff_hash": DIGEST_A,
        "change_contract_hash": DIGEST_B,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "subject_epoch": 0,
        "subject_version": 1,
    }
    record = {
        "type": "TARGETED_VALIDATION_PASSED",
        "producer": "controller:test-executor",
        "command_id": "pytest-targeted",
        "exit_code": 0,
        "subject_fingerprint": subject_fingerprint(subject),
        "metadata": {
            "executor_id": "executor:one",
            "command_id": "pytest-other",
            "argv_fingerprint": DIGEST_A,
            "working_directory": "C:/repo",
            "start_at": "2026-08-16T10:00:02Z",
            "end_at": "2026-08-16T10:00:01Z",
            "exit_code": 0,
            "stdout_hash": DIGEST_A,
            "stderr_hash": DIGEST_B,
            "check_configuration_hash": DIGEST_C,
            "toolchain_hash": DIGEST_C,
            "receipt_id": "receipt-one",
            "producer_identity": "controller:test-executor",
            "result_artifact_hash": DIGEST_A,
            "subject_fingerprint": subject_fingerprint(subject),
            "subject_epoch": 0,
        },
    }
    errors = validate_machine_evidence_provenance(record, subject=subject)
    assert any("timestamp" in error.lower() or "end_at" in error for error in errors)
    assert any("command" in error.lower() for error in errors)


def test_deployed_revision_must_match_active_merged_revision() -> None:
    subject = {
        "repository": "owner/repo",
        "protected_base_sha": "0" * 40,
        "pr_head_sha": "1" * 40,
        "reviewed_diff_hash": DIGEST_A,
        "merged_main_sha": "2" * 40,
        "merge_method": "SQUASH",
        "merge_provenance": {
            "pr_head_sha": "1" * 40,
            "reviewed_diff_hash": DIGEST_A,
            "merged_main_sha": "2" * 40,
            "transformation": "protected squash merge",
        },
        "post_merge_ci_run_id": "run-main-1",
        "change_contract_hash": DIGEST_B,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "deployed_revision": "3" * 40,
        "subject_epoch": 0,
        "subject_version": 1,
    }
    assert validate_subject(subject, require_merge_provenance=True).errors


def test_terminal_bundle_rejects_stale_pre_mutation_evidence_lineage() -> None:
    final_subject = {
        "repository": "owner/repo",
        "protected_base_sha": "0" * 40,
        "pr_head_sha": "1" * 40,
        "reviewed_diff_hash": DIGEST_A,
        "change_contract_hash": DIGEST_B,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "artifact_digest": DIGEST_A,
        "subject_epoch": 1,
        "subject_version": 1,
    }
    stale_record = dict(final_subject, artifact_digest=None, subject_epoch=0, subject_fingerprint=None)
    errors = _subject_lineage_errors(stale_record, final_subject, "TARGETED_VALIDATION_PASSED")
    assert any("epoch" in error.lower() or "stale" in error.lower() for error in errors)
