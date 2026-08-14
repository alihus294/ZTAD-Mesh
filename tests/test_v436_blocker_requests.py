from pathlib import Path

import pytest

from ztad.blocker_requests import BLOCKER_CATALOG, prepare_blocker_request
from ztad.schema_validation import validate_instance
from ztad.util import load_data

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = load_data(ROOT / "schemas/blocker-request.schema.json")

SUBJECT = {
    "repository": "owner/repo",
    "base_sha": "0" * 40,
    "head_sha": "1" * 40,
    "artifact_digest": "sha256:" + "a" * 64,
    "change_contract_hash": "sha256:" + "b" * 64,
    "policy_bundle_hash": "sha256:" + "c" * 64,
    "toolchain_hash": "sha256:" + "d" * 64,
}

EXPECTED_BLOCKERS = {
    "missing_release_fingerprint",
    "missing_signed_release_manifest",
    "missing_artifact_attestation_and_sbom",
    "missing_staged_restore_rehearsal",
    "missing_rollback_rehearsal",
    "missing_observation_and_synthetic_transaction",
    "missing_production_runtime_health",
    "missing_protected_supervisor_approval",
    "migration_ledger_history_guard_failure",
    "remote_main_dependency_fix_not_applied",
    "provider_output_missing",
    "invalid_json_schema",
    "local_branch_differs_from_protected_main",
    "dirty_worktree",
}


def test_catalog_covers_every_prior_task_blocker():
    assert set(BLOCKER_CATALOG) == EXPECTED_BLOCKERS


def test_every_blocker_generates_a_strict_non_authoritative_request():
    for blocker in sorted(EXPECTED_BLOCKERS):
        request = prepare_blocker_request(blocker, subject=SUBJECT, reason=f"Observed {blocker}", schema=SCHEMA)
        assert validate_instance(request, SCHEMA) == []
        assert request["authority"] == "LOCAL_NON_AUTHORITATIVE"
        assert request["can_satisfy_gate"] is False
        assert request["request_id"].startswith("REQ-")
        assert request["next_protected_or_local_action"]


def test_protected_requests_do_not_pretend_to_be_the_requested_evidence():
    request = prepare_blocker_request(
        "missing_protected_supervisor_approval",
        subject=SUBJECT,
        reason="Exact candidate lacks protected approval",
        schema=SCHEMA,
    )
    assert request["request_kind"] == "PROTECTED_EVIDENCE"
    assert request["minimum_trust"] == "E6"
    assert request["required_evidence_type"] == "PROTECTED_RELEASE_AUTHORIZATION"
    assert request["can_satisfy_gate"] is False


def test_dirty_worktree_request_points_to_autonomous_isolation():
    request = prepare_blocker_request("dirty_worktree", subject=SUBJECT, reason="User worktree contains changes", schema=SCHEMA)
    assert request["request_kind"] == "LOCAL_REMEDIATION"
    assert request["required_evidence_type"] == "ISOLATED_CLEAN_WORKTREE"
    assert "Preserve" in request["next_protected_or_local_action"]


def test_unknown_blocker_is_rejected():
    with pytest.raises(ValueError, match="Unknown blocker"):
        prepare_blocker_request("invented_blocker", subject=SUBJECT, reason="no", schema=SCHEMA)


def test_subject_must_be_exactly_bindable():
    subject = dict(SUBJECT)
    subject.pop("head_sha")
    with pytest.raises(ValueError, match="missing required keys"):
        prepare_blocker_request("missing_signed_release_manifest", subject=subject, reason="missing", schema=SCHEMA)
