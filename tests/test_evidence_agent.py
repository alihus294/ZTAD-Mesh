from datetime import datetime, timedelta, timezone
from pathlib import Path

from ztad.agent_output import validate_agent_result
from ztad.crypto import generate_ed25519_keypair, sign_evidence
from ztad.evidence import evaluate_required_evidence, load_evidence_records, validate_evidence_record
from ztad.findings import validate_finding
from ztad.util import load_data, utc_now

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_SCHEMA = load_data(ROOT / "schemas/evidence.schema.json")
AGENT_SCHEMA = load_data(ROOT / "schemas/agent-result.schema.json")
FINDING_SCHEMA = load_data(ROOT / "schemas/finding.schema.json")
SHA0 = "0" * 40
SHA1 = "1" * 40
HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
HASH_C = "sha256:" + "c" * 64


def evidence(*, trust="E2", type="LOCAL_TEST", producer="local-tool:runner", evidence_id="ev-local-test-001"):
    return {
        "evidence_id": evidence_id,
        "type": type,
        "trust_level": trust,
        "producer": producer,
        "repository": "owner/repo",
        "change_contract_hash": HASH_A,
        "base_sha": SHA0,
        "head_sha": SHA1,
        "policy_bundle_hash": HASH_B,
        "toolchain_hash": HASH_C,
        "environment": "local-sandbox" if trust in {"E0", "E1", "E2"} else "ci",
        "command_id": "pytest",
        "exit_code": 0,
        "status": "PASSED",
        "output_hash": HASH_C,
        "artifact_digest": None,
        "created_at": utc_now(),
        "expires_at": None,
        "invalidated_by": [],
        "signature_or_attestation": None,
        "metadata": {},
    }


def subject():
    return {"repository": "owner/repo", "change_contract_hash": HASH_A, "base_sha": SHA0, "head_sha": SHA1, "policy_bundle_hash": HASH_B, "toolchain_hash": HASH_C}


def agent_result():
    return {
        "schema_version": 1,
        "task_id": "FEAT-100",
        "agent_role": "independent_reviewer",
        "model_registry_id": "review-independent",
        "prompt_version": "review-v1",
        "base_sha": SHA0,
        "head_sha": SHA1,
        "context_id": HASH_C,
        "result_type": "NO_BLOCKING_FINDINGS_IN_REVIEWED_SCOPE",
        "claims": [],
        "findings": [],
        "files_read": ["src/app.py"],
        "files_not_read": [],
        "uncertainties": [],
        "tested_scope": ["src/app.py"],
        "untested_scope": [],
        "known_unknowns": [],
        "patch_path": None,
        "requested_action": "CONTINUE_POLICY_EVALUATION",
        "risk_escalation": None,
    }


def test_local_evidence_valid_at_e2():
    assert validate_evidence_record(evidence(), schema=EVIDENCE_SCHEMA, subject=subject(), minimum_trust="E2", require_authoritative_signature=False) == []


def test_subject_mismatch_rejected():
    bad = evidence()
    bad["head_sha"] = "2" * 40
    errors = validate_evidence_record(bad, schema=EVIDENCE_SCHEMA, subject=subject(), minimum_trust="E2", require_authoritative_signature=False)
    assert any("head_sha" in item for item in errors)


def test_agent_cannot_create_authoritative_evidence():
    bad = evidence(trust="E3", producer="agent:reviewer")
    errors = validate_evidence_record(bad, schema=EVIDENCE_SCHEMA, subject=subject(), minimum_trust="E3", require_authoritative_signature=False)
    assert any("Agent-produced" in item for item in errors)


def test_expired_evidence_rejected():
    bad = evidence()
    bad["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    errors = validate_evidence_record(bad, schema=EVIDENCE_SCHEMA, subject=subject(), minimum_trust="E2", require_authoritative_signature=False)
    assert "Evidence is expired" in errors


def test_nonzero_success_rejected():
    bad = evidence()
    bad["exit_code"] = 1
    errors = validate_evidence_record(bad, schema=EVIDENCE_SCHEMA, subject=subject(), minimum_trust="E2", require_authoritative_signature=False)
    assert any("non-zero" in item for item in errors)


def test_duplicate_evidence_ids_fail_required_set():
    first = evidence(type="FAST_CI_PASSED")
    second = evidence(type="FAST_CI_PASSED")
    result = evaluate_required_evidence([first, second], ["FAST_CI_PASSED"], subject=subject(), schema=EVIDENCE_SCHEMA, minimum_trust="E2", require_authoritative_signature=False)
    assert not result["passed"]
    assert result["duplicate_evidence_ids"]


def test_signed_authoritative_evidence(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_ed25519_keypair(private, public)
    record = evidence(trust="E3", producer="platform:protected-ci", evidence_id="ev-ci-fast-001")
    signed = sign_evidence(record, private_key_path=private, key_id="ci-key")
    roots = {"version": 1, "keys": {"ci-key": {"algorithm":"ed25519","public_key_pem":public.read_text(),"status":"ACTIVE","allowed_trust_levels":["E3"],"allowed_producers":["platform:protected-ci"],"allowed_types":["*"],"allowed_environments":["ci"]}}}
    assert validate_evidence_record(signed, schema=EVIDENCE_SCHEMA, subject=subject(), minimum_trust="E3", trust_roots=roots) == []


def test_valid_agent_result():
    assert validate_agent_result(agent_result(), AGENT_SCHEMA) == []


def test_implementer_cannot_self_clear():
    result = agent_result()
    result["agent_role"] = "implementer"
    errors = validate_agent_result(result, AGENT_SCHEMA)
    assert any("cannot independently clear" in item for item in errors)


def test_authoritative_phrase_rejected():
    result = agent_result()
    result["known_unknowns"] = ["all tests passed"]
    errors = validate_agent_result(result, AGENT_SCHEMA)
    assert any("Authoritative phrase" in item for item in errors)


def test_verified_claim_requires_known_evidence():
    result = agent_result()
    result["claims"] = [{"claim":"File exists","claim_type":"REPOSITORY_FACT","source_sha":SHA1,"verification_status":"VERIFIED","evidence_ref":"ev-missing"}]
    errors = validate_agent_result(result, AGENT_SCHEMA, known_evidence_ids=["ev-other"])
    assert any("unknown evidence_ref" in item for item in errors)


def test_result_type_must_match_role_semantics():
    result = agent_result()
    result["agent_role"] = "implementer"
    result["result_type"] = "APPROVAL_RECOMMENDATION"
    errors = validate_agent_result(result, AGENT_SCHEMA)
    assert errors


def test_finding_requires_evidence_and_sha():
    finding = {
        "schema_version": 1,
        "finding_id": "F-1",
        "severity": "P1",
        "category": "security",
        "title": "Scope escape",
        "description": "Writer escaped approved scope.",
        "path": "src/app.py",
        "line": 1,
        "invariant": "Writer remains inside approved scope",
        "evidence_refs": ["ev-local-test-001"],
        "reproduction": "Run scope verifier.",
        "recommended_action": "REPAIR",
        "head_sha": SHA1,
    }
    assert validate_finding(finding, schema=FINDING_SCHEMA, expected_head_sha=SHA1, known_evidence_ids=["ev-local-test-001"])["valid"]


def test_finding_with_wrong_sha_is_rejected():
    finding = {
        "schema_version": 1,
        "finding_id": "F-1",
        "severity": "P1",
        "category": "security",
        "title": "Scope escape",
        "description": "Writer escaped approved scope.",
        "path": "src/app.py",
        "line": 1,
        "invariant": "Writer remains inside approved scope",
        "evidence_refs": ["ev-local-test-001"],
        "reproduction": "Run scope verifier.",
        "recommended_action": "REPAIR",
        "head_sha": SHA0,
    }
    result = validate_finding(finding, schema=FINDING_SCHEMA, expected_head_sha=SHA1, known_evidence_ids=["ev-local-test-001"])
    assert not result["valid"]
    assert any("head SHA" in item for item in result["errors"])
