from pathlib import Path

from ztad.schema_validation import validate_instance
from ztad.util import load_data

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = load_data(ROOT / "schemas/bug-lifecycle.schema.json")


def _record(risk: str, domains: list[str]) -> dict:
    return {
        "schema_version": 1,
        "protocol_version": "WorkshopOS-Fail-Closed-Bug-to-Production-v1",
        "profile": "generic",
        "mode": "NORMAL",
        "case_id": "CASE-DOMAIN-GUARD",
        "state": "CHANGE_PLANNED",
        "last_completed_state": "CHANGE_PLANNED",
        "resume_state": None,
        "blocked_target": None,
        "blockers": [],
        "repository": "owner/repo",
        "remote_repository": "owner/repo",
        "problem_case_fingerprint": "sha256:" + "1" * 64,
        "base_sha": "0" * 40,
        "head_sha": None,
        "diff_hash": None,
        "artifact_digest": None,
        "risk": risk,
        "domains": domains,
        "canonical_deployment_chain": [],
        "change_contract_hash": None,
        "policy_bundle_hash": None,
        "toolchain_hash": None,
        "evidence_refs": {},
        "final_state": None,
    }


def test_r3_and_r4_cannot_remain_general_only():
    for risk in ("R3", "R4"):
        errors = validate_instance(_record(risk, ["GENERAL"]), SCHEMA)
        assert errors, risk


def test_high_risk_specific_domain_satisfies_schema_guard():
    assert not validate_instance(_record("R3", ["SECURITY"]), SCHEMA)
    assert not validate_instance(_record("R4", ["DATABASE"]), SCHEMA)


def test_lower_risk_general_domain_remains_valid():
    assert not validate_instance(_record("R2", ["GENERAL"]), SCHEMA)
