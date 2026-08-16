from pathlib import Path

from ztad.budget import evaluate_budget
from ztad.crypto import generate_ed25519_keypair, sign_evidence
from ztad.release import evaluate_release_readiness
from ztad.state_machine import evaluate_transition_from_records
from ztad.subject import subject_fingerprint
from ztad.util import load_data, sha256_file, utc_now

from conftest import valid_contract

ROOT = Path(__file__).resolve().parents[1]
SHA0 = "0"*40
SHA1 = "1"*40
HASH_B = "sha256:" + "b"*64
HASH_C = "sha256:" + "c"*64


def test_budget_passes_below_threshold():
    policy = load_data(ROOT / "policies/budget-policy.yaml")
    usage = {"implementation_runs":1,"independent_reviews":1,"repair_cycles":0,"closure_reviews":0,"escalation_runs":0,"input_tokens":10000,"output_tokens":1000,"cost":1}
    assert evaluate_budget(policy, usage, "R2")["passed"]


def test_budget_stops_at_eighty_percent():
    policy = load_data(ROOT / "policies/budget-policy.yaml")
    usage = {"implementation_runs":1,"independent_reviews":1,"repair_cycles":0,"closure_reviews":0,"escalation_runs":0,"input_tokens":96000,"output_tokens":1000,"cost":1}
    result = evaluate_budget(policy, usage, "R2")
    assert not result["passed"]
    assert result["circuit_breaker_triggered"]
    assert result["decision"] == "QUARANTINE_TASK_AND_CONTINUE_QUEUE"
    assert result["global_stop"] is False


def test_budget_hard_exceeded():
    policy = load_data(ROOT / "policies/budget-policy.yaml")
    result = evaluate_budget(policy, {"repair_cycles":3}, "R2")
    assert result["hard_exceeded"]


def _state_subject():
    return {
        "repository": "owner/repo",
        "change_contract_hash": "sha256:" + "a" * 64,
        "base_sha": SHA0,
        "head_sha": SHA1,
        "diff_hash": HASH_C,
        "policy_bundle_hash": HASH_B,
        "toolchain_hash": HASH_C,
        "subject_epoch": 0,
        "subject_version": 1,
    }


def _state_record(*, status="PASSED"):
    return {
        "evidence_id": "ev-local-contract-001",
        "type": "CHANGE_CONTRACT_VALID",
        "trust_level": "E2",
        "producer": "tool:contract-validator",
        **_state_subject(),
        "environment": "local",
        "command_id": "validate-contract",
        "exit_code": 0,
        "status": status,
        "output_hash": HASH_C,
        "artifact_digest": None,
        "created_at": utc_now(),
        "expires_at": None,
        "invalidated_by": [],
        "signature_or_attestation": None,
        "metadata": {},
    }


def _state_transition(requested, records=()):
    return evaluate_transition_from_records(
        load_data(ROOT / "policies/state-machine.yaml"),
        current_state="BACKLOG",
        requested_state=requested,
        risk="R1",
        records=records,
        subject=_state_subject(),
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        trust_roots=None,
    )


def test_state_transition_requires_contract_evidence():
    result = _state_transition("READY")
    assert not result["allowed"]
    assert "CHANGE_CONTRACT_VALID" in result["missing_evidence"]


def test_state_transition_passes_with_record_evidence():
    assert _state_transition("READY", [_state_record()])["allowed"]


def test_state_transition_rejects_failed_record_with_success_type():
    result = _state_transition("READY", [_state_record(status="FAILED")])
    assert not result["allowed"]
    assert result["invalid_evidence"]


def test_state_transition_rejects_incomplete_subject():
    subject = _state_subject()
    del subject["toolchain_hash"]
    result = evaluate_transition_from_records(
        load_data(ROOT / "policies/state-machine.yaml"), current_state="BACKLOG", requested_state="READY", risk="R1",
        records=[_state_record()], subject=subject, evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"), trust_roots=None,
    )
    assert not result["allowed"]
    assert "<subject>" in result["invalid_evidence"]


def test_illegal_state_transition_blocks():
    assert not _state_transition("MERGED")["allowed"]


def _signed_records(tmp_path, contract_path, *, types=None):
    private = tmp_path / "private.pem"; public = tmp_path / "public.pem"
    generate_ed25519_keypair(private, public)
    contract_hash = sha256_file(contract_path)
    roots = {"version":1,"keys":{"ci-key":{"algorithm":"ed25519","public_key_pem":public.read_text(),"status":"ACTIVE","allowed_trust_levels":["E3"],"allowed_producers":["platform:protected-ci"],"allowed_types":["*"],"allowed_environments":["ci"]}}}
    default_types = [
        "CHANGE_CONTRACT_VALID", "POLICY_PREFLIGHT_PASSED", "FAST_CI_PASSED",
        "PLATFORM_BRANCH_PROTECTION_VERIFIED", "PLATFORM_REQUIRED_CHECKS_VERIFIED",
        "PLATFORM_STALE_REVIEW_DISMISSAL_VERIFIED",
    ]
    records=[]
    for idx, typ in enumerate(types or default_types,1):
        subject = {"repository":"owner/repo","change_contract_hash":contract_hash,"base_sha":SHA0,"head_sha":SHA1,"policy_bundle_hash":HASH_B,"toolchain_hash":HASH_C,"subject_epoch":0,"subject_version":1}
        fingerprint = subject_fingerprint(subject)
        record={"evidence_id":f"ev-ci-{idx:03d}","type":typ,"trust_level":"E3","producer":"platform:protected-ci","repository":"owner/repo","change_contract_hash":contract_hash,"base_sha":SHA0,"head_sha":SHA1,"policy_bundle_hash":HASH_B,"toolchain_hash":HASH_C,"subject_epoch":0,"subject_version":1,"subject_fingerprint":fingerprint,"environment":"ci","command_id":"ci","exit_code":0,"status":"PASSED","output_hash":HASH_C,"artifact_digest":None,"created_at":utc_now(),"expires_at":None,"invalidated_by":[],"signature_or_attestation":None,"metadata":{}}
        record["metadata"] = {"executor_id":"executor:protected-ci","command_id":"ci","argv_fingerprint":"sha256:" + "1" * 64,"working_directory":str(tmp_path),"start_at":"2026-08-15T10:00:00Z","end_at":"2026-08-15T10:00:01Z","exit_code":0,"stdout_hash":HASH_C,"stderr_hash":HASH_C,"check_configuration_hash":HASH_B,"toolchain_hash":HASH_C,"receipt_id":f"receipt-ci-{idx:03d}","producer_identity":"platform:protected-ci","result_artifact_hash":HASH_C,"subject_fingerprint":fingerprint,"subject_epoch":0}
        records.append(sign_evidence(record, private_key_path=private, key_id="ci-key"))
    return records, roots, private


def _evaluate_merge(contract_path, records, roots, risk="R0"):
    return evaluate_release_readiness(
        repository="owner/repo", contract_path=contract_path, base_sha=SHA0, head_sha=SHA1,
        policy_bundle_hash=HASH_B, toolchain_hash=HASH_C, risk=risk, target="merge",
        evidence_records=records, evidence_schema=load_data(ROOT/"schemas/evidence.schema.json"),
        release_policy=load_data(ROOT/"policies/release-policy.yaml"), trust_roots=roots,
    )


def test_merge_readiness_passes_with_signed_evidence_and_platform(tmp_path):
    import yaml
    contract_path = tmp_path / "contract.yaml"
    contract_path.write_text(yaml.safe_dump(valid_contract()), encoding="utf-8")
    records, roots, _ = _signed_records(tmp_path, contract_path)
    result = _evaluate_merge(contract_path, records, roots)
    assert result["decision"] == "MERGE_ELIGIBLE"


def test_merge_readiness_blocks_missing_platform(tmp_path):
    import yaml
    contract_path = tmp_path / "contract.yaml"
    contract_path.write_text(yaml.safe_dump(valid_contract()), encoding="utf-8")
    records, roots, _ = _signed_records(tmp_path, contract_path, types=["CHANGE_CONTRACT_VALID","POLICY_PREFLIGHT_PASSED","FAST_CI_PASSED"])
    result = _evaluate_merge(contract_path, records, roots)
    assert result["decision"] == "AUTO_GENERATE_EVIDENCE"
    assert "PLATFORM_CONTROLS_NOT_VERIFIED" in result["blockers"]


def test_r2_merge_requires_signed_e6_supervisor_controller_approval(tmp_path):
    import yaml
    contract_path = tmp_path / "contract.yaml"
    contract_path.write_text(yaml.safe_dump(valid_contract(risk="R2", data_class="C2", criticality="tier_1")), encoding="utf-8")
    types = [
        "CHANGE_CONTRACT_VALID", "POLICY_PREFLIGHT_PASSED", "FAST_CI_PASSED",
        "INDEPENDENT_REVIEW_COMPLETED", "EXTENDED_CI_PASSED",
        "PLATFORM_BRANCH_PROTECTION_VERIFIED", "PLATFORM_REQUIRED_CHECKS_VERIFIED",
        "PLATFORM_STALE_REVIEW_DISMISSAL_VERIFIED", "PLATFORM_MERGE_QUEUE_VERIFIED",
    ]
    records, roots, ci_private = _signed_records(tmp_path, contract_path, types=types)
    result = _evaluate_merge(contract_path, records, roots, risk="R2")
    assert result["decision"] == "AUTO_SUPERVISOR_APPROVAL_REQUIRED"
    assert result["missing_approvals"] == ["STRONG_SUPERVISOR_MERGE_APPROVAL"]

    # A CI-signed E3 record carrying an approval-like name must not satisfy the supervisor approval gate.
    fake = {"evidence_id":"ev-ci-fake-approval","type":"STRONG_SUPERVISOR_MERGE_APPROVAL","trust_level":"E3","producer":"platform:protected-ci","repository":"owner/repo","change_contract_hash":sha256_file(contract_path),"base_sha":SHA0,"head_sha":SHA1,"policy_bundle_hash":HASH_B,"toolchain_hash":HASH_C,"subject_epoch":0,"subject_version":1,"environment":"ci","command_id":None,"exit_code":None,"status":"APPROVED","output_hash":HASH_C,"artifact_digest":None,"created_at":utc_now(),"expires_at":None,"invalidated_by":[],"signature_or_attestation":None,"metadata":{}}
    records_with_fake = records + [sign_evidence(fake, private_key_path=ci_private, key_id="ci-key")]
    result = _evaluate_merge(contract_path, records_with_fake, roots, risk="R2")
    assert result["decision"] == "AUTO_SUPERVISOR_APPROVAL_REQUIRED"
    assert "ev-ci-fake-approval" in result["invalid_evidence"]

    controller_private = tmp_path / "controller-private.pem"; controller_public = tmp_path / "controller-public.pem"
    generate_ed25519_keypair(controller_private, controller_public)
    roots["keys"]["controller-key"] = {"algorithm":"ed25519","public_key_pem":controller_public.read_text(),"status":"ACTIVE","allowed_trust_levels":["E6"],"allowed_producers":["platform:approval-controller"],"allowed_types":["STRONG_SUPERVISOR_MERGE_APPROVAL"],"allowed_environments":["supervisor-approval-controller"]}
    approval_subject = {"repository":"owner/repo","change_contract_hash":sha256_file(contract_path),"base_sha":SHA0,"head_sha":SHA1,"policy_bundle_hash":HASH_B,"toolchain_hash":HASH_C,"subject_epoch":0,"subject_version":1}
    approval = {"evidence_id":"ev-supervisor-merge-approval","type":"STRONG_SUPERVISOR_MERGE_APPROVAL","trust_level":"E6","producer":"platform:approval-controller","repository":"owner/repo","change_contract_hash":sha256_file(contract_path),"base_sha":SHA0,"head_sha":SHA1,"policy_bundle_hash":HASH_B,"toolchain_hash":HASH_C,"subject_epoch":0,"subject_version":1,"subject_fingerprint":subject_fingerprint(approval_subject),"environment":"supervisor-approval-controller","command_id":None,"exit_code":None,"status":"APPROVED","output_hash":HASH_C,"artifact_digest":None,"created_at":utc_now(),"expires_at":None,"invalidated_by":[],"signature_or_attestation":None,"metadata":{"approver_role":"merge-owner"}}
    result = _evaluate_merge(contract_path, records + [sign_evidence(approval, private_key_path=controller_private, key_id="controller-key")], roots, risk="R2")
    assert result["decision"] == "MERGE_ELIGIBLE"
    assert result["valid_approval_evidence"]["STRONG_SUPERVISOR_MERGE_APPROVAL"] == ["ev-supervisor-merge-approval"]


def test_staging_evidence_must_bind_exact_artifact_digest(tmp_path):
    import yaml
    contract_path = tmp_path / "contract.yaml"
    contract_path.write_text(yaml.safe_dump(valid_contract()), encoding="utf-8")
    private = tmp_path / "e4-private.pem"
    public = tmp_path / "e4-public.pem"
    generate_ed25519_keypair(private, public)
    contract_hash = sha256_file(contract_path)
    artifact = "sha256:" + "d" * 64
    rollback = "sha256:" + "e" * 64
    roots = {"version": 1, "keys": {"build-key": {
        "algorithm": "ed25519",
        "public_key_pem": public.read_text(),
        "status": "ACTIVE",
        "allowed_trust_levels": ["E4"],
        "allowed_producers": ["platform:protected-build"],
        "allowed_types": ["*"],
        "allowed_environments": ["build"],
    }}}
    records = []
    for idx, typ in enumerate(
        ["RELEASE_MANIFEST_VALID", "ARTIFACT_ATTESTATION_VERIFIED", "SBOM_VERIFIED", "BUILD_PROVENANCE_VERIFIED"],
        1,
    ):
        record = {
            "evidence_id": f"ev-build-{idx:03d}",
            "type": typ,
            "trust_level": "E4",
            "producer": "platform:protected-build",
            "repository": "owner/repo",
            "change_contract_hash": contract_hash,
            "base_sha": SHA0,
            "head_sha": SHA1,
            "policy_bundle_hash": HASH_B,
            "toolchain_hash": HASH_C,
            "environment": "build",
            "command_id": "build",
            "exit_code": 0,
            "status": "PASSED",
            "output_hash": HASH_C,
            # Deliberately wrong: artifact-bearing evidence must bind the exact digest.
            "artifact_digest": None,
            "created_at": utc_now(),
            "expires_at": None,
            "invalidated_by": [],
            "signature_or_attestation": None,
            "metadata": {},
        }
        records.append(sign_evidence(record, private_key_path=private, key_id="build-key"))
    manifest = {
        "schema_version": 1,
        "repository": "owner/repo",
        "change_contract_hash": contract_hash,
        "merged_sha": SHA1,
        "artifact_digest": artifact,
        "rollback_artifact_digest": rollback,
        "build_workflow_sha": SHA0,
        "policy_bundle_hash": HASH_B,
        "toolchain_hash": HASH_C,
        "sbom_digest": HASH_C,
        "provenance_attestation": "attestation-ref",
        "test_evidence_refs": ["ev-build-001"],
        "risk": "R0",
        "created_at": utc_now(),
        "feature_flags": [],
    }
    result = evaluate_release_readiness(
        repository="owner/repo",
        contract_path=contract_path,
        base_sha=SHA0,
        head_sha=SHA1,
        toolchain_hash=HASH_C,
        policy_bundle_hash=HASH_B,
        risk="R0",
        target="staging",
        evidence_records=records,
        evidence_schema=load_data(ROOT / "schemas/evidence.schema.json"),
        release_policy=load_data(ROOT / "policies/release-policy.yaml"),
        trust_roots=roots,
        release_manifest=manifest,
        release_manifest_schema=load_data(ROOT / "schemas/release-manifest.schema.json"),
    )
    assert result["decision"] == "AUTO_REPLAN"
    assert "REQUIRED_EVIDENCE_MISSING" in result["blockers"]
    assert result["invalid_evidence"]
