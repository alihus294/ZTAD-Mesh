from __future__ import annotations

from pathlib import Path

from ztad.bug_lifecycle import evaluate_bug_transition
from ztad.crypto import generate_ed25519_keypair, sign_evidence
from ztad.subject import subject_fingerprint
from ztad.util import load_data, utc_now

ROOT = Path(__file__).resolve().parents[1]
POLICY = load_data(ROOT / "policies/bug-to-production-policy.yaml")
LIFECYCLE_SCHEMA = load_data(ROOT / "schemas/bug-lifecycle.schema.json")
EVIDENCE_SCHEMA = load_data(ROOT / "schemas/evidence.schema.json")

SHA0 = "0" * 40
SHA1 = "1" * 40
CONTRACT = "sha256:" + "a" * 64
DIFF = "sha256:" + "b" * 64
POLICY_HASH = "sha256:" + "c" * 64
TOOLCHAIN = "sha256:" + "d" * 64
ARTIFACT = "sha256:" + "e" * 64
OUTPUT = "sha256:" + "f" * 64
RELEASE = "sha256:" + "0" * 64
SBOM = "sha256:" + "1" * 64
PROVENANCE = "sha256:" + "2" * 64
ATTESTATION = "sha256:" + "3" * 64


def _lifecycle(state: str, *, domains: list[str] | None = None, risk: str = "R3") -> dict:
    return {
        "schema_version": 1,
        "protocol_version": "WorkshopOS-Fail-Closed-Bug-to-Production-v1",
        "profile": "generic",
        "mode": "NORMAL",
        "case_id": "CASE-EXACT-PROTECTED",
        "state": state,
        "last_completed_state": state,
        "resume_state": None,
        "blocked_target": None,
        "blockers": [],
        "repository": "owner/repo",
        "remote_repository": "owner/repo",
        "problem_case_fingerprint": "sha256:" + "1" * 64,
        "base_sha": SHA0,
        "head_sha": SHA1,
        "diff_hash": DIFF,
        "artifact_digest": ARTIFACT,
        "release_fingerprint": RELEASE,
        "sbom_digest": SBOM,
        "provenance_digest": PROVENANCE,
        "attestation_digest": ATTESTATION,
        "artifact_identity": "owner/repo@" + ARTIFACT,
        "risk": risk,
        "domains": domains or ["GENERAL"],
        "canonical_deployment_chain": [],
        "change_contract_hash": CONTRACT,
        "policy_bundle_hash": POLICY_HASH,
        "toolchain_hash": TOOLCHAIN,
        "evidence_refs": {},
        "final_state": None,
    }


def _record(
    evidence_type: str,
    *,
    trust_level: str,
    producer: str,
    environment: str,
    evidence_id: str,
    status: str = "PASSED",
) -> dict:
    record = {
        "evidence_id": evidence_id,
        "type": evidence_type,
        "trust_level": trust_level,
        "producer": producer,
        "repository": "owner/repo",
        "change_contract_hash": CONTRACT,
        "base_sha": SHA0,
        "head_sha": SHA1,
        "policy_bundle_hash": POLICY_HASH,
        "toolchain_hash": TOOLCHAIN,
        "environment": environment,
        "command_id": None,
        "exit_code": 0,
        "status": status,
        "output_hash": OUTPUT,
        "artifact_digest": ARTIFACT,
        "release_fingerprint": RELEASE,
        "sbom_digest": SBOM,
        "provenance_digest": PROVENANCE,
        "attestation_digest": ATTESTATION,
        "artifact_identity": "owner/repo@" + ARTIFACT,
        "created_at": utc_now(),
        "expires_at": None,
        "invalidated_by": [],
        "signature_or_attestation": None,
        "metadata": {
            "source_sha": SHA1,
            "artifact_digest": ARTIFACT,
            "release_fingerprint": RELEASE,
            "sbom_digest": SBOM,
            "provenance_digest": PROVENANCE,
            "attestation_digest": ATTESTATION,
            "artifact_identity": "owner/repo@" + ARTIFACT,
            "reviewed_main_sha": SHA1,
            "deployed_revision": SHA1,
            "environment": "production",
            "workflow_run_id": "run-protected",
            "deployment_receipt": "receipt-protected",
            "occurred_at": utc_now(),
            "production_release_id": "release-protected",
            "protected_workflow": True,
        },
    }
    record["protected_base_sha"] = SHA0
    record["pr_head_sha"] = SHA1
    record["reviewed_diff_hash"] = DIFF
    record["subject_epoch"] = 0
    record["subject_version"] = 1
    record["subject_fingerprint"] = subject_fingerprint(record)
    if evidence_type in {
        "TARGETED_VALIDATION_PASSED",
        "SECURITY_VALIDATION_PASSED",
        "SECRETS_SCAN_PASSED",
        "FAIL_CLOSED_BOUNDARY_PASSED",
    }:
        record["producer"] = "controller:test-executor"
        record["metadata"].update({
            "executor_id": "executor:protected-test",
            "command_id": "pytest",
            "argv_fingerprint": "sha256:" + "4" * 64,
            "working_directory": str(ROOT),
            "start_at": "2026-08-15T10:00:00Z",
            "end_at": "2026-08-15T10:00:01Z",
            "exit_code": 0,
            "stdout_hash": "sha256:" + "5" * 64,
            "stderr_hash": "sha256:" + "6" * 64,
            "check_configuration_hash": "sha256:" + "7" * 64,
            "toolchain_hash": TOOLCHAIN,
            "receipt_id": "receipt-protected-test",
            "producer_identity": "controller:test-executor",
            "result_artifact_hash": "sha256:" + "8" * 64,
            "subject_fingerprint": record["subject_fingerprint"],
            "subject_epoch": 0,
        })
    if evidence_type == "TARGETED_VALIDATION_PASSED":
        record["metadata"]["semantic_case_matrix"] = [
            {"case": name, "status": "PASS"}
            for name in (
                "original_reproduction", "normal_case", "nearest_boundary", "invalid_input",
                "empty_null_missing_input", "repeated_operation", "retry_behavior", "stale_state", "error_path",
                "authorization_denial", "tenant_crossing_denial", "id_tampering_denial",
                "provider_failure", "provider_reconciliation", "provider_idempotency",
                "idempotency", "financial_duplicate_prevention", "ledger_consistency",
                "database_migration", "database_recovery", "compatibility_matrix",
                "legal_state_machine", "duplicate_prevention", "immutability",
                "concurrency", "no_duplicate_durable_side_effect", "secrets_scan", "fail_closed_boundary",
            )
        ]
        record["metadata"]["original_reproduction_passed"] = True
    return record


def _key(tmp_path: Path, name: str, *, level: str, producer: str, environment: str, types: list[str]):
    private = tmp_path / f"{name}-private.pem"
    public = tmp_path / f"{name}-public.pem"
    generate_ed25519_keypair(private, public)
    root = {
        "algorithm": "ed25519",
        "public_key_pem": public.read_text(encoding="utf-8"),
        "status": "ACTIVE",
        "allowed_trust_levels": [level],
        "allowed_producers": [producer],
        "allowed_types": types,
        "allowed_environments": [environment],
    }
    return private, root


def test_security_domain_is_a_mandatory_targeted_validation_gate():
    lifecycle = _lifecycle("REGRESSION_TEST_PROVEN", domains=["SECURITY"])
    targeted = _record(
        "TARGETED_VALIDATION_PASSED",
        trust_level="E2",
        producer="tool:targeted-checks",
        environment="local",
        evidence_id="ev-targeted-security-001",
    )
    blocked = evaluate_bug_transition(
        lifecycle,
        "TARGETED_VALIDATION_PASS",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        evidence_records=[targeted],
        evidence_schema=EVIDENCE_SCHEMA,
    )
    assert not blocked["allowed"]
    assert "SECURITY_VALIDATION_PASSED" in blocked["missing_evidence_types"]

    security = _record(
        "SECURITY_VALIDATION_PASSED",
        trust_level="E2",
        producer="tool:security-checks",
        environment="local",
        evidence_id="ev-security-validation-001",
    )
    secrets = _record(
        "SECRETS_SCAN_PASSED",
        trust_level="E2",
        producer="tool:security-checks",
        environment="local",
        evidence_id="ev-secrets-scan-001",
    )
    boundary = _record(
        "FAIL_CLOSED_BOUNDARY_PASSED",
        trust_level="E2",
        producer="tool:security-checks",
        environment="local",
        evidence_id="ev-fail-closed-boundary-001",
    )
    permitted = evaluate_bug_transition(
        lifecycle,
        "TARGETED_VALIDATION_PASS",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        evidence_records=[targeted, security, secrets, boundary],
        evidence_schema=EVIDENCE_SCHEMA,
    )
    assert permitted["allowed"], permitted["reasons"]


def test_ready_for_owner_release_rejects_non_e6_supervisor_approval(tmp_path: Path):
    # Use R2 so this test isolates the approval-strength predicate; R3/R4
    # restore/rehearsal requirements are tested separately and remain intact.
    lifecycle = _lifecycle("STAGING_PASS", risk="R2")
    required = POLICY["gates"]["READY_FOR_OWNER_RELEASE"]["required_evidence"]

    build_private, build_root = _key(
        tmp_path,
        "build",
        level="E4",
        producer="platform:protected-build",
        environment="build",
        types=["*"],
    )
    records = []
    for index, typ in enumerate(required, 1):
        status = "APPROVED" if typ == "PROTECTED_SUPERVISOR_APPROVAL" else "PASSED"
        raw = _record(
            typ,
            trust_level="E4",
            producer="platform:protected-build",
            environment="build",
            evidence_id=f"ev-ready-{index:03d}",
            status=status,
        )
        records.append(sign_evidence(raw, private_key_path=build_private, key_id="build-key"))

    roots = {"version": 1, "keys": {"build-key": build_root}}
    result = evaluate_bug_transition(
        lifecycle,
        "READY_FOR_OWNER_RELEASE",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        evidence_records=records,
        evidence_schema=EVIDENCE_SCHEMA,
        trust_roots=roots,
    )
    assert not result["allowed"]
    assert any("E6 protected-controller evidence" in reason for reason in result["reasons"])


def test_ready_for_owner_release_accepts_e6_controller_approval(tmp_path: Path):
    # R2 intentionally avoids conflating the E6 approval test with the
    # additional R3 staged-restore requirement.
    lifecycle = _lifecycle("STAGING_PASS", risk="R2")
    required = POLICY["gates"]["READY_FOR_OWNER_RELEASE"]["required_evidence"]

    build_private, build_root = _key(
        tmp_path,
        "build",
        level="E4",
        producer="platform:protected-build",
        environment="build",
        types=["*"],
    )
    controller_private, controller_root = _key(
        tmp_path,
        "controller",
        level="E6",
        producer="platform:approval-controller",
        environment="approval-controller",
        types=["PROTECTED_SUPERVISOR_APPROVAL"],
    )
    records = []
    counter = 1
    for typ in required:
        if typ == "PROTECTED_SUPERVISOR_APPROVAL":
            raw = _record(
                typ,
                trust_level="E6",
                producer="platform:approval-controller",
                environment="approval-controller",
                evidence_id="ev-protected-supervisor-approval",
                status="APPROVED",
            )
            records.append(sign_evidence(raw, private_key_path=controller_private, key_id="controller-key"))
            continue
        raw = _record(
            typ,
            trust_level="E4",
            producer="platform:protected-build",
            environment="build",
            evidence_id=f"ev-ready-ok-{counter:03d}",
        )
        counter += 1
        records.append(sign_evidence(raw, private_key_path=build_private, key_id="build-key"))

    roots = {"version": 1, "keys": {"build-key": build_root, "controller-key": controller_root}}
    result = evaluate_bug_transition(
        lifecycle,
        "READY_FOR_OWNER_RELEASE",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        evidence_records=records,
        evidence_schema=EVIDENCE_SCHEMA,
        trust_roots=roots,
    )
    assert result["allowed"], result["reasons"]


def test_production_release_requires_e6_authorization_but_runtime_evidence_is_e5(tmp_path: Path):
    # Use R2 to isolate the protected-production-authorization strength from
    # unrelated high-risk domain classification requirements.
    lifecycle = _lifecycle("READY_FOR_OWNER_RELEASE", risk="R2")
    required = POLICY["gates"]["PRODUCTION_RELEASED"]["required_evidence"]

    runtime_private, runtime_root = _key(
        tmp_path,
        "runtime",
        level="E5",
        producer="platform:production-runtime",
        environment="production",
        types=["PRODUCTION_RELEASE_COMPLETED", "EXPECTED_DIGEST_RUNNING", "PROTECTED_RELEASE_AUTHORIZATION"],
    )
    controller_private, controller_root = _key(
        tmp_path,
        "release-controller",
        level="E6",
        producer="platform:approval-controller",
        environment="approval-controller",
        types=["PROTECTED_RELEASE_AUTHORIZATION"],
    )

    bad_records = []
    for index, typ in enumerate(required, 1):
        raw = _record(
            typ,
            trust_level="E5",
            producer="platform:production-runtime",
            environment="production",
            evidence_id=f"ev-production-bad-{index:03d}",
            status="APPROVED" if typ == "PROTECTED_RELEASE_AUTHORIZATION" else "PASSED",
        )
        bad_records.append(sign_evidence(raw, private_key_path=runtime_private, key_id="runtime-key"))
    bad_roots = {"version": 1, "keys": {"runtime-key": runtime_root}}
    rejected = evaluate_bug_transition(
        lifecycle,
        "PRODUCTION_RELEASED",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        evidence_records=bad_records,
        evidence_schema=EVIDENCE_SCHEMA,
        trust_roots=bad_roots,
    )
    assert not rejected["allowed"]
    assert any("E6 protected-controller evidence" in reason for reason in rejected["reasons"])

    good_records = []
    counter = 1
    for typ in required:
        if typ == "PROTECTED_RELEASE_AUTHORIZATION":
            raw = _record(
                typ,
                trust_level="E6",
                producer="platform:approval-controller",
                environment="approval-controller",
                evidence_id="ev-production-release-authorization",
                status="APPROVED",
            )
            good_records.append(sign_evidence(raw, private_key_path=controller_private, key_id="controller-key"))
            continue
        raw = _record(
            typ,
            trust_level="E5",
            producer="platform:production-runtime",
            environment="production",
            evidence_id=f"ev-production-good-{counter:03d}",
        )
        counter += 1
        good_records.append(sign_evidence(raw, private_key_path=runtime_private, key_id="runtime-key"))
    good_roots = {"version": 1, "keys": {"runtime-key": runtime_root, "controller-key": controller_root}}
    permitted = evaluate_bug_transition(
        lifecycle,
        "PRODUCTION_RELEASED",
        policy=POLICY,
        lifecycle_schema=LIFECYCLE_SCHEMA,
        evidence_records=good_records,
        evidence_schema=EVIDENCE_SCHEMA,
        trust_roots=good_roots,
    )
    assert permitted["allowed"], permitted["reasons"]


def test_staging_and_protected_readiness_have_strengthened_trust_floor():
    assert POLICY["gates"]["STAGING_PASS"]["minimum_trust"] == "E5"
    assert "PROTECTED_SUPERVISOR_APPROVAL" in POLICY["gates"]["READY_FOR_OWNER_RELEASE"]["required_evidence"]
