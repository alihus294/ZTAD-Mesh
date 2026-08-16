from __future__ import annotations

from pathlib import Path

import pytest

from ztad.bug_protocol import (
    AUTHORITATIVE_LIFECYCLE,
    continuation_decision,
    red_green_result,
    validate_artifact_chain,
    validate_authoritative_lifecycle_policy,
    validate_authoritative_sources,
    validate_ci_metadata,
    validate_diff_forensics,
    validate_post_deploy_metadata,
    validate_production_release_metadata,
    validate_full_regression_metadata,
    validate_progressive_exposure,
    validate_red_green_evidence,
    validate_staging_metadata,
    validate_test_integrity,
    validate_workshopos_message,
)
from ztad.host_acceptance import audit_host_acceptance
from ztad.orchestrator import ContinuityStore
from ztad.util import load_data


ROOT = Path(__file__).resolve().parents[1]
POLICY = load_data(ROOT / "policies/bug-to-production-policy.yaml")
HEAD = "1" * 40
BASE = "0" * 40
DIFF = "sha256:" + "a" * 64
ARTIFACT = "sha256:" + "b" * 64
RELEASE = "sha256:" + "c" * 64
SBOM = "sha256:" + "d" * 64
PROVENANCE = "sha256:" + "e" * 64
ATTESTATION = "sha256:" + "f" * 64


def _red_green() -> dict:
    return {
        "bad_base_sha": BASE,
        "candidate_head_sha": HEAD,
        "same_oracle": True,
        "bad_result": "FAIL",
        "patched_result": "PASS",
        "oracle_id": "oracle-001",
        "oracle_hash": RELEASE,
        "oracle_command": "pytest tests/test_bug.py",
        "bad_environment": "protected-base",
        "candidate_environment": "isolated-candidate",
        "bad_exit_code": 1,
        "candidate_exit_code": 0,
        "bad_output_hash": SBOM,
        "candidate_output_hash": PROVENANCE,
        "failing_assertion": "assert expected == actual",
        "passing_assertion": "assert expected == actual",
    }


def test_authoritative_policy_order_is_exact_and_machine_checked() -> None:
    assert tuple(POLICY["states"][: len(AUTHORITATIVE_LIFECYCLE)]) == AUTHORITATIVE_LIFECYCLE
    assert validate_authoritative_lifecycle_policy(POLICY) == []


def test_source_conflict_and_weaker_source_order_fail_closed() -> None:
    sources = [
        {"source": "app.py", "authority": "EXECUTABLE_SOURCE", "authority_reason": "runtime behavior", "evidence_ref": "ev-app"},
        {"source": "instructions", "authority": "GOVERNING_INSTRUCTION", "authority_reason": "governing rule", "evidence_ref": "ev-rule"},
    ]
    errors = validate_authoritative_sources(sources, ["conflicting expected behavior"], authority_order=POLICY["authority_order"])
    assert "BLOCKED: SOURCE_CONFLICT" in errors
    assert any("order" in item.lower() for item in errors)


def test_red_green_requires_exact_distinct_subjects_and_same_oracle() -> None:
    metadata = _red_green()
    assert validate_red_green_evidence(metadata, bad_base_sha=BASE, candidate_head_sha=HEAD) == []
    assert red_green_result(metadata, bad_base_sha=BASE, candidate_head_sha=HEAD) == "VALID_RED_GREEN"
    same_sha = dict(metadata, candidate_head_sha=BASE)
    assert red_green_result(same_sha, bad_base_sha=BASE, candidate_head_sha=BASE) == "FLAKY_SAME_SHA"
    assert any("FLAKY_SAME_SHA" in item for item in validate_red_green_evidence(same_sha, bad_base_sha=BASE, candidate_head_sha=BASE))


def test_test_integrity_and_diff_forensics_block_weakening_and_scope_expansion() -> None:
    integrity = validate_test_integrity({"findings": [{"code": "ASSERTION_REMOVED", "severity": "BLOCK"}]})
    assert any("TEST_WEAKENING" in item for item in integrity)
    assert validate_test_integrity({"assertion_weakened": True})
    diff_errors = validate_diff_forensics(
        {"files": [{"path": "unexpected.py", "justification": "not planned"}]},
        planned_files=["planned.py"],
    )
    assert any("scope expansion" in item.lower() for item in diff_errors)


def test_ci_staging_artifact_and_postdeploy_checks_bind_exact_subject() -> None:
    assert validate_ci_metadata(
        {"pr_head_sha": HEAD, "reviewed_diff_hash": DIFF, "workflow_run_id": "run-1", "required_checks": ["ci"], "conclusion": "SUCCESS"},
        head_sha=HEAD,
        diff_hash=DIFF,
    ) == []
    assert validate_staging_metadata(
        {
            "candidate_head_sha": HEAD,
            "artifact_digest": ARTIFACT,
            "environment": "staging",
            "original_symptom_absent": True,
            "expected_behavior_present": True,
            "health_verified": True,
            "affected_workflow_verified": True,
        },
        head_sha=HEAD,
        artifact_digest=ARTIFACT,
    ) == []
    assert validate_artifact_chain(
        {
            "source_sha": HEAD,
            "artifact_digest": ARTIFACT,
            "release_fingerprint": RELEASE,
            "sbom_digest": SBOM,
            "provenance_digest": PROVENANCE,
            "attestation_digest": ATTESTATION,
            "artifact_identity": "owner/repo@" + ARTIFACT,
        },
        head_sha=HEAD,
        artifact_digest=ARTIFACT,
    ) == []
    health = {
        "deployed_artifact_digest": ARTIFACT,
        "original_symptom_absent": True,
        "expected_behavior_present": True,
        "health_verified": True,
        "synthetic_transaction_safe": True,
        "observation_window_complete": True,
        "error_rate": 0,
        "latency": 1,
        "api_errors": 0,
        "queue_health": "ok",
        "database_health": "ok",
        "provider_health": "ok",
        "auth_health": "ok",
        "financial_anomalies": 0,
        "zatca_anomalies": 0,
    }
    assert validate_post_deploy_metadata(health, artifact_digest=ARTIFACT) == []
    assert validate_post_deploy_metadata(dict(health, safety_uncertain=True), artifact_digest=ARTIFACT)


def test_full_regression_production_and_progressive_exposure_are_separate_gates() -> None:
    assert validate_full_regression_metadata(
        {"protected_base_sha": BASE, "candidate_head_sha": HEAD, "test_layers": ["unit", "integration", "full"], "conclusion": "SUCCESS"},
        base_sha=BASE,
        candidate_head_sha=HEAD,
    ) == []
    assert validate_production_release_metadata(
        {
            "reviewed_main_sha": HEAD,
            "deployed_revision": HEAD,
            "artifact_digest": ARTIFACT,
            "environment": "production",
            "workflow_run_id": "run-2",
            "deployment_receipt": "receipt-2",
            "occurred_at": "2026-08-15T10:00:00Z",
            "production_release_id": "release-2",
            "protected_workflow": True,
        },
        head_sha=HEAD,
        artifact_digest=ARTIFACT,
    ) == []
    assert validate_progressive_exposure(
        {
            "strategy": "CANARY",
            "rollback_trigger": "error rate threshold",
            "rollback_trigger_hash": "sha256:" + "1" * 64,
            "stop_conditions": ["health failure"],
            "scope_limit": "one tenant",
            "write_gate": True,
            "owner_stop_condition": "owner stops on anomaly",
        },
        risk_class="CRITICAL",
    ) == []
    assert validate_progressive_exposure({}, risk_class="CRITICAL")


def test_workshopos_destination_is_profile_data_and_browser_tests_need_dummy_data() -> None:
    profile = {"test_only_message_destinations": ["0594269477"]}
    assert validate_workshopos_message("0594269477", profile=profile) == []
    assert validate_workshopos_message("0550000000", profile=profile)
    assert validate_workshopos_message("0594269477", profile=profile, browser_or_e2e=True, uses_dummy_data=False)
    assert validate_workshopos_message("0594269477")


def test_continuation_routes_external_unsafe_and_identical_failures() -> None:
    assert continuation_decision("MISSING_CREDENTIAL")["action"] == "WAITING_EXTERNAL_DEPENDENCY"
    assert continuation_decision("POLICY_VIOLATION")["action"] == "QUARANTINE"
    assert continuation_decision("MODEL_TIMEOUT")["action"] == "AUTO_REPAIR"
    assert continuation_decision("UNKNOWN", previous_attempt_fingerprint="x", current_attempt_fingerprint="x")["action"] == "AUTO_REPLAN"
    assert continuation_decision("UNKNOWN", after_production_exposure=True)["action"] == "ROLLBACK_REQUIRED"


def test_authoritative_scheduler_task_cannot_transition_to_done(tmp_path: Path) -> None:
    store = ContinuityStore(tmp_path / "continuity.db")
    task = store.submit_task(
        repository="owner/repo",
        title="authoritative bug",
        contract={"protocol": "WorkshopOS-Fail-Closed-Bug-to-Production-v1", "origin": "FEATURE"},
        risk="R1",
    )
    with pytest.raises(PermissionError):
        store.transition(task["task_id"], "DONE", actor="test", expected_version=task["version"])


def test_host_probe_reports_unproven_protected_capabilities() -> None:
    report = audit_host_acceptance(plugin_root=ROOT, inspect_codex_plugin_state=False)
    assert report["github_remote_governance_verified"] is False
    assert "protected_production_release" in report["unproven_capabilities"]
