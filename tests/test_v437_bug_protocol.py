from __future__ import annotations

import subprocess
from pathlib import Path

from ztad.bug_lifecycle import (
    _protected_approval_errors,
    advance_bug_lifecycle,
    bind_artifact,
    bind_candidate,
    evaluate_bug_transition,
    initialize_bug_lifecycle,
)
from ztad.problem import initialize_problem_case, problem_case_fingerprint
from ztad.util import load_data, utc_now
from ztad.subject import subject_fingerprint

ROOT = Path(__file__).resolve().parents[1]
POLICY = load_data(ROOT / "policies/bug-to-production-policy.yaml")
LIFECYCLE_SCHEMA = load_data(ROOT / "schemas/bug-lifecycle.schema.json")
EVIDENCE_SCHEMA = load_data(ROOT / "schemas/evidence.schema.json")

EXPECTED_LINEAR = [
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
]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "ZTAD Test")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "base")
    return repo


def _blast_coverage() -> dict:
    return {
        "direct_components": ["app.py"],
        "adjacent_components": ["tests"],
        "callers_callees": ["test oracle"],
        "api_contracts": ["local behavior"],
        "database_data_boundaries": ["none"],
        "tenant_auth_boundaries": ["none"],
        "financial_zatca_boundaries": ["none"],
        "provider_boundaries": ["none"],
        "concurrency_idempotency_boundaries": ["none"],
        "deployment_infra_boundaries": ["none"],
        "tests": ["pytest tests/test_bug.py"],
        "observability": ["test output"],
        "migration_rollback_impact": ["restore prior artifact"],
        "invariants": ["unrelated behavior remains unchanged"],
        "validation_depth": ["base and candidate oracle"],
    }


def _proven_problem_case(tmp_path: Path) -> dict:
    case = initialize_problem_case(
        _repo(tmp_path),
        report="When X happens, Y is wrong.",
        expected_behavior="X must produce Z.",
    )
    base = case["base_sha"]
    case.update({
        "state": "HANDOFF_READY",
        "authoritative_sources": [
            {"source": "app.py", "authority": "EXECUTABLE_SOURCE", "authority_reason": "Executable source is the authoritative implementation behavior for the case.", "evidence_ref": "ev-source"}
        ],
        "classification": "CONFIRMED_BUG",
        "classification_evidence": ["ev-classification"],
        "classification_record": {
            "evidence": ["ev-classification"],
            "reproduction_status": "REPRODUCED",
            "authoritative_expected_behavior": "X must produce Z.",
            "competing_explanations_tested": ["cache hypothesis"],
            "environment_findings": ["local base fixture"],
            "unresolved_ambiguities": [],
            "source_conflicts": [],
            "implementation_justified": True,
        },
        "reproduction": {
            "preconditions": ["base fixture"],
            "action": "run regression",
            "input": None,
            "expected": "Z",
            "actual": "Y",
            "environment": "local",
            "deterministic": True,
            "observed_frequency": "1/1",
            "affected_component": "app.py",
            "evidence_refs": ["ev-red"],
        },
        "root_cause": {
            "trigger": "X",
            "incorrect_state_or_assumption": "wrong branch",
            "propagation": ["app.py"],
            "observable_failure": "Y",
            "affected_source": ["app.py"],
            "evidence_refs": ["ev-root"],
        },
        "rejected_hypotheses": [
            {"hypothesis": "cache", "disposition": "REJECTED", "evidence_refs": ["ev-cache"]}
        ],
        "hypothesis_tests": [
            {"hypothesis": "cache", "test": "invalidate cache and rerun oracle", "result": "cache hypothesis rejected", "evidence_refs": ["ev-cache"]}
        ],
        "blast_radius": {
            "direct": ["app.py"],
            "adjacent": ["tests"],
            "security_boundaries": [],
            "data_boundaries": [],
            "coverage": _blast_coverage(),
        },
        "invariants": ["Unrelated behavior remains unchanged."],
        "risk": "R1",
        "regression_baseline": {
            "base_sha": base,
            "test_or_oracle": "pytest tests/test_bug.py",
            "bad_result": "FAIL",
            "patched_result": None,
            "same_oracle": True,
            "exception_reason": None,
            "evidence_refs": ["ev-red"],
        },
        "change_plan": {
            "root_cause_summary": "wrong branch",
            "intended_fix": "correct the branch condition",
            "expected_files": ["app.py", "tests/test_bug.py"],
            "tests": ["pytest tests/test_bug.py"],
            "forbidden_scope": ["infra/production"],
            "database_impact": "none",
            "external_side_effects": "none",
            "rollback_or_containment": "restore the prior verified artifact",
            "file_reasons": {
                "app.py": {
                    "why": "The faulty branch is in the implementation file.",
                    "root_cause_mechanism": "The branch selects Y instead of Z.",
                    "validation": "The exact regression oracle proves the corrected result.",
                },
                "tests/test_bug.py": {
                    "why": "The regression oracle must encode the reported defect.",
                    "root_cause_mechanism": "The oracle exercises the faulty branch.",
                    "validation": "The same oracle fails on base and passes on candidate.",
                },
            },
        },
    })
    return case


def _bound_lifecycle(tmp_path: Path) -> tuple[dict, dict]:
    case = _proven_problem_case(tmp_path)
    lifecycle = initialize_bug_lifecycle(problem_case=case, policy=POLICY)
    for target in EXPECTED_LINEAR[1:7]:
        lifecycle = advance_bug_lifecycle(
            lifecycle,
            target,
            policy=POLICY,
            lifecycle_schema=LIFECYCLE_SCHEMA,
            problem_case=case,
        )
        assert lifecycle["state"] == target, lifecycle["blockers"]

    contract = tmp_path / "change-contract.json"
    contract.write_text('{"change":"x"}\n', encoding="utf-8")
    lifecycle = bind_candidate(
        lifecycle,
        contract_path=contract,
        head_sha="b" * 40,
        diff_hash="sha256:" + "c" * 64,
        policy_bundle_hash="sha256:" + "d" * 64,
        toolchain_hash="sha256:" + "e" * 64,
    )
    return lifecycle, case


def _evidence(lifecycle: dict, evidence_type: str, *, metadata: dict | None = None) -> dict:
    machine_metadata = {}
    producer = "tool:ztad-test"
    if evidence_type in {
        "REGRESSION_RED_GREEN_PROVEN",
        "TARGETED_VALIDATION_PASSED",
        "FULL_REGRESSION_VALIDATION_PASSED",
        "DIFF_FORENSICS_PASSED",
        "SECURITY_VALIDATION_PASSED",
        "SECRETS_SCAN_PASSED",
        "FAIL_CLOSED_BOUNDARY_PASSED",
    }:
        producer = "controller:test-executor"
        machine_metadata = {
            "executor_id": "executor:test",
            "command_id": "pytest",
            "argv_fingerprint": "sha256:" + "1" * 64,
            "working_directory": str(ROOT),
            "start_at": "2026-08-15T10:00:00Z",
            "end_at": "2026-08-15T10:00:01Z",
            "exit_code": 0,
            "stdout_hash": "sha256:" + "2" * 64,
            "stderr_hash": "sha256:" + "3" * 64,
            "check_configuration_hash": "sha256:" + "4" * 64,
            "toolchain_hash": lifecycle["toolchain_hash"],
            "receipt_id": "receipt:test",
            "producer_identity": "controller:test-executor",
            "result_artifact_hash": "sha256:" + "5" * 64,
            "subject_fingerprint": subject_fingerprint(lifecycle),
            "subject_epoch": int(lifecycle.get("subject_epoch") or 0),
        }
        machine_metadata.update(metadata or {})
    return {
        "evidence_id": "ev-" + evidence_type.lower().replace("_", "-"),
        "type": evidence_type,
        "trust_level": "E2",
        "producer": producer,
        "repository": lifecycle["repository"],
        "change_contract_hash": lifecycle["change_contract_hash"],
        "base_sha": lifecycle["base_sha"],
        "head_sha": lifecycle["head_sha"],
        "diff_hash": lifecycle["diff_hash"],
        "policy_bundle_hash": lifecycle["policy_bundle_hash"],
        "toolchain_hash": lifecycle["toolchain_hash"],
        "subject_epoch": int(lifecycle.get("subject_epoch") or 0),
        "subject_version": int(lifecycle.get("subject_version") or 1),
        "environment": "local",
        "command_id": "pytest",
        "exit_code": 0,
        "status": "PASSED",
        "output_hash": "sha256:" + "f" * 64,
        "artifact_digest": lifecycle.get("artifact_digest"),
        "created_at": utc_now(),
        "expires_at": None,
        "invalidated_by": [],
        "signature_or_attestation": None,
        "metadata": machine_metadata if machine_metadata else (metadata or {}),
    }


def test_policy_exposes_exact_workshopos_bug_lifecycle_and_no_done_state():
    assert POLICY["states"][:19] == EXPECTED_LINEAR
    assert "DONE" not in POLICY["states"]
    assert POLICY["transitions"]["READY_FOR_OWNER_RELEASE"] == ["PRODUCTION_RELEASED", "BLOCKED"]
    assert POLICY["transitions"]["PRODUCTION_RELEASED"] == ["POST_DEPLOY_VERIFIED", "ROLLBACK_REQUIRED"]
    assert POLICY["transitions"]["POST_DEPLOY_VERIFIED"] == ["CLOSED", "ROLLBACK_REQUIRED"]
    assert POLICY["hotfix"]["may_skip_states"] is False


def test_workshopos_profile_binds_canonical_deployment_chain(tmp_path):
    case = _proven_problem_case(tmp_path)
    lifecycle = initialize_bug_lifecycle(
        problem_case=case,
        policy=POLICY,
        profile="workshopos",
        remote_repository="alihus294/WorkshopOS",
    )
    assert lifecycle["canonical_deployment_chain"] == [
        "DEPLOYMENT.md",
        "infra/docs/runbook.md",
        ".github/workflows/deploy.yml",
    ]


def test_problem_phases_are_explicit_before_patch_implementation(tmp_path):
    case = _proven_problem_case(tmp_path)
    lifecycle = initialize_bug_lifecycle(problem_case=case, policy=POLICY)
    assert lifecycle["problem_case_fingerprint"] == problem_case_fingerprint(case)
    for target in EXPECTED_LINEAR[1:7]:
        lifecycle = advance_bug_lifecycle(
            lifecycle,
            target,
            policy=POLICY,
            lifecycle_schema=LIFECYCLE_SCHEMA,
            problem_case=case,
        )
        assert lifecycle["state"] == target
    denied = evaluate_bug_transition(
        lifecycle,
        "REGRESSION_TEST_PROVEN",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        problem_case=case,
        evidence_schema=EVIDENCE_SCHEMA,
    )
    assert not denied["allowed"]
    assert denied["decision"] == "BLOCKED"


def test_patch_and_red_green_are_separate_mandatory_gates(tmp_path):
    lifecycle, case = _bound_lifecycle(tmp_path)
    patch = _evidence(lifecycle, "CANDIDATE_PATCH_CREATED")
    lifecycle = advance_bug_lifecycle(
        lifecycle,
        "PATCH_IMPLEMENTED",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        problem_case=case,
        evidence_records=[patch],
        evidence_schema=EVIDENCE_SCHEMA,
    )
    assert lifecycle["state"] == "PATCH_IMPLEMENTED"

    red_green = _evidence(
        lifecycle,
        "REGRESSION_RED_GREEN_PROVEN",
        metadata={
            "bad_base_sha": lifecycle["base_sha"],
            "candidate_head_sha": lifecycle["head_sha"],
            "same_oracle": True,
            "bad_result": "FAIL",
            "patched_result": "PASS",
            "oracle_id": "test-bug-oracle",
            "oracle_hash": "sha256:" + "1" * 64,
            "oracle_command": "pytest tests/test_bug.py",
            "bad_environment": "base-local",
            "candidate_environment": "candidate-local",
            "bad_exit_code": 1,
            "candidate_exit_code": 0,
            "bad_output_hash": "sha256:" + "2" * 64,
            "candidate_output_hash": "sha256:" + "3" * 64,
            "failing_assertion": "assert expected == actual",
            "passing_assertion": "assert expected == actual",
        },
    )
    lifecycle = advance_bug_lifecycle(
        lifecycle,
        "REGRESSION_TEST_PROVEN",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        problem_case=case,
        evidence_records=[red_green],
        evidence_schema=EVIDENCE_SCHEMA,
    )
    assert lifecycle["state"] == "REGRESSION_TEST_PROVEN"


def test_bad_red_green_routes_to_blocked_instead_of_green(tmp_path):
    lifecycle, case = _bound_lifecycle(tmp_path)
    lifecycle["state"] = "PATCH_IMPLEMENTED"
    lifecycle["last_completed_state"] = "PATCH_IMPLEMENTED"
    bad = _evidence(
        lifecycle,
        "REGRESSION_RED_GREEN_PROVEN",
        metadata={
            "bad_base_sha": lifecycle["base_sha"],
            "candidate_head_sha": lifecycle["head_sha"],
            "same_oracle": False,
            "bad_result": "FAIL",
            "patched_result": "PASS",
        },
    )
    result = advance_bug_lifecycle(
        lifecycle,
        "REGRESSION_TEST_PROVEN",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        problem_case=case,
        evidence_records=[bad],
        evidence_schema=EVIDENCE_SCHEMA,
    )
    assert result["state"] == "BLOCKED"
    assert any("same regression oracle" in item for item in result["blockers"])


def test_internal_done_can_never_close_bug_protocol(tmp_path):
    lifecycle, case = _bound_lifecycle(tmp_path)
    result = evaluate_bug_transition(
        lifecycle,
        "DONE",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        problem_case=case,
    )
    assert not result["allowed"]
    assert result["decision"] == "BLOCKED"


def test_missing_post_deploy_proof_after_production_requires_rollback(tmp_path):
    lifecycle, case = _bound_lifecycle(tmp_path)
    lifecycle = bind_artifact(lifecycle, "sha256:" + "a" * 64)
    lifecycle["state"] = "PRODUCTION_RELEASED"
    lifecycle["last_completed_state"] = "PRODUCTION_RELEASED"
    result = evaluate_bug_transition(
        lifecycle,
        "POST_DEPLOY_VERIFIED",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        problem_case=case,
        evidence_schema=EVIDENCE_SCHEMA,
    )
    assert not result["allowed"]
    assert result["decision"] == "ROLLBACK_REQUIRED"


def test_closed_requires_post_deploy_health_and_observation_proof(tmp_path):
    lifecycle, case = _bound_lifecycle(tmp_path)
    lifecycle = bind_artifact(lifecycle, "sha256:" + "a" * 64)
    lifecycle["state"] = "POST_DEPLOY_VERIFIED"
    lifecycle["last_completed_state"] = "POST_DEPLOY_VERIFIED"
    closed = advance_bug_lifecycle(
        lifecycle,
        "CLOSED",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        problem_case=case,
        evidence_schema=EVIDENCE_SCHEMA,
    )
    assert closed["state"] == "ROLLBACK_REQUIRED"
    assert any("Missing evidence" in item for item in closed["blockers"])


def test_high_risk_domain_profiles_add_mandatory_targeted_evidence():
    gate = POLICY["gates"]["TARGETED_VALIDATION_PASS"]["by_domain"]
    assert "MIGRATION_LEDGER_HISTORY_GUARD_PASSED" in gate["DATABASE"]
    assert {"AUTHZ_TENANT_MATRIX_PASSED", "SERVER_SIDE_AUTHORIZATION_PASSED", "TENANT_CROSSING_DENIED", "ID_TAMPERING_DENIED"}.issubset(gate["AUTH_TENANT"])
    assert {"FINANCIAL_INVARIANTS_PASSED", "IDEMPOTENCY_PASSED", "LEDGER_CONSISTENCY_PASSED", "NO_DUPLICATE_FINANCIAL_SIDE_EFFECT"}.issubset(gate["FINANCIAL"])
    assert {"ZATCA_INVARIANTS_PASSED", "ZATCA_LEGAL_STATE_MACHINE_PASSED", "ZATCA_DUPLICATE_PREVENTION_PASSED", "ZATCA_IMMUTABILITY_PASSED"}.issubset(gate["ZATCA"])
    assert {"PROVIDER_SEMANTICS_PASSED", "PROVIDER_STATE_RECONCILIATION_PASSED", "PROVIDER_IDEMPOTENCY_PASSED", "PROVIDER_SAFE_OUTAGE_PASSED"}.issubset(gate["PROVIDER"])
    assert {"CONCURRENCY_INVARIANTS_PASSED", "PARALLEL_REPRODUCTION_PASSED", "NO_DUPLICATE_DURABLE_SIDE_EFFECT"}.issubset(gate["CONCURRENCY"])
    assert {"SECURITY_VALIDATION_PASSED", "SECRETS_SCAN_PASSED", "FAIL_CLOSED_BOUNDARY_PASSED"}.issubset(gate["SECURITY"])


def test_staging_is_runtime_evidence_and_owner_release_requires_protected_supervisor():
    assert POLICY["gates"]["STAGING_PASS"]["minimum_trust"] == "E5"
    required = POLICY["gates"]["READY_FOR_OWNER_RELEASE"]["required_evidence"]
    assert "PROTECTED_SUPERVISOR_APPROVAL" in required


def test_protected_approvals_require_e6_controller_authority():
    weak = {
        "evidence_id": "ev-weak",
        "type": "PROTECTED_SUPERVISOR_APPROVAL",
        "trust_level": "E5",
        "producer": "platform:github",
        "status": "APPROVED",
    }
    errors = _protected_approval_errors(
        [weak],
        ["ev-weak"],
        evidence_type="PROTECTED_SUPERVISOR_APPROVAL",
        label="Protected supervisor approval",
    )
    assert any("E6" in error for error in errors)

    model = {
        "evidence_id": "ev-model",
        "type": "PROTECTED_RELEASE_AUTHORIZATION",
        "trust_level": "E6",
        "producer": "agent:sol",
        "status": "APPROVED",
    }
    errors = _protected_approval_errors(
        [model],
        ["ev-model"],
        evidence_type="PROTECTED_RELEASE_AUTHORIZATION",
        label="Production release authorization",
    )
    assert any("protected platform/controller" in error for error in errors)

    protected = {
        "evidence_id": "ev-protected",
        "type": "PROTECTED_RELEASE_AUTHORIZATION",
        "trust_level": "E6",
        "producer": "controller:release",
        "status": "APPROVED",
    }
    assert _protected_approval_errors(
        [protected],
        ["ev-protected"],
        evidence_type="PROTECTED_RELEASE_AUTHORIZATION",
        label="Production release authorization",
    ) == []
