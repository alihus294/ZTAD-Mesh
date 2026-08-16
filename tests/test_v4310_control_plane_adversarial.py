from __future__ import annotations

import copy
import concurrent.futures
import inspect
import json
import os
import shutil
import sqlite3
import subprocess
import threading
from pathlib import Path

import pytest

from ztad.bug_lifecycle import (
    _gate_requirements,
    _collect_authoritative_git_inventory,
    _protocol_gate_errors,
    bind_artifact,
    bind_candidate,
    bind_merge_subject,
    bind_production_subject,
    evaluate_bug_transition,
    initialize_bug_lifecycle,
)
from ztad.bug_protocol import (
    validate_diff_forensics,
    validate_artifact_chain,
    validate_policy_safety,
    validate_rollback_closure,
)
from ztad.controller_context import ControllerRuntimeContext, LIFECYCLE_CONTROLLER_ID, LIFECYCLE_CONTROLLER_TYPE
from ztad.crypto import generate_ed25519_keypair, sign_evidence
from ztad.diff_forensics import collect_git_diff_inventory, collect_worktree_diff_inventory
from ztad.evidence import validate_evidence_record
from ztad.evidence_bundle import validate_evidence_bundle
from ztad.lifecycle_store import LifecycleStore
from ztad.policy_registry import _semantic_policy_errors
from ztad.repository import GitRepository
from ztad.subject import (
    SUBJECT_TRANSITION_POLICY,
    apply_subject_update,
    describe_subject_transition,
    subject_fingerprint,
    subject_from_record,
    subject_epoch_transition_policy,
    validate_subject,
)
from ztad.trust import _HOST_ACCEPTANCE_TOKEN, TrustRootAuthority, load_host_accepted_trust_roots
from ztad.util import canonical_json, load_data, sha256_bytes, utc_now


ROOT = Path(__file__).resolve().parents[1]
POLICY = load_data(ROOT / "policies/bug-to-production-policy.yaml")
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _git_subject_repo(root: Path) -> tuple[str, str, str]:
    root.mkdir()
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "ztad-test@example.invalid")
    _git(root, "config", "user.name", "ZTAD Test")
    (root / "app.py").write_text("return 1\n", encoding="utf-8")
    (root / "settings.yaml").write_text("mode: old\n", encoding="utf-8")
    _git(root, "add", "app.py", "settings.yaml")
    _git(root, "commit", "--quiet", "-m", "base")
    base = _git(root, "rev-parse", "HEAD")
    (root / "app.py").write_text("return 2\n", encoding="utf-8")
    (root / "settings.yaml").write_text("mode: candidate\n", encoding="utf-8")
    _git(root, "add", "app.py", "settings.yaml")
    _git(root, "commit", "--quiet", "-m", "candidate")
    candidate = _git(root, "rev-parse", "HEAD")
    return base, candidate, _git(root, "show", "-s", "--format=%T", candidate)


def _git_worktree_base(root: Path) -> str:
    root.mkdir()
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "ztad-test@example.invalid")
    _git(root, "config", "user.name", "ZTAD Test")
    _git(root, "config", "core.autocrlf", "false")
    (root / "tracked.txt").write_text("base\n", encoding="utf-8")
    (root / "second.txt").write_text("second\n", encoding="utf-8")
    _git(root, "add", "tracked.txt", "second.txt")
    _git(root, "commit", "--quiet", "-m", "base")
    return _git(root, "rev-parse", "HEAD")


def _copy_clean_git_checkout(source: Path, destination: Path) -> None:
    _git(source.parent, "clone", "--quiet", str(source), str(destination))


def _forensic_metadata(inventory: dict) -> dict:
    files = [
        {
            "path": item["path"],
            "planned": True,
            "justification": "The path is required by the reviewed root-cause fix.",
            "security_impact": "reviewed",
            "data_domain_impact": "reviewed",
            "generated": False,
            "category": "runtime",
        }
        for item in inventory["files"]
    ]
    return {
        "complete_changed_file_list": True,
        "actual_changed_files": [item["path"] for item in inventory["files"]],
        "allowed_scope": [item["path"] for item in inventory["files"]],
        "actual_risk": "R3",
        "actual_domains": ["GENERAL"],
        "analysis_method": "machine-generated Git diff inventory",
        "reviewed_diff_hash": inventory["diff_hash"],
        "git_inventory": inventory,
        "files": files,
    }


def _subject_record(*, state: str = "STAGING_PASS") -> dict:
    return {
        "case_id": "CASE-CONTROL-001",
        "state": state,
        "last_completed_state": state,
        "repository": "owner/repo",
        "protected_base_sha": "0" * 40,
        "base_sha": "0" * 40,
        "pr_head_sha": "1" * 40,
        "head_sha": "1" * 40,
        "reviewed_diff_hash": DIGEST_A,
        "diff_hash": DIGEST_A,
        "change_contract_hash": DIGEST_B,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "subject_epoch": 0,
        "subject_version": 1,
        "domains": ["GENERAL"],
        "risk": "R3",
        "risk_class": "HIGH",
        "evidence_refs": {"CI": ["ev-ci"]},
        "artifact_digest": DIGEST_A,
        "final_state": None,
        "closure_class": None,
    }


def _transition_authorization(
    current: dict,
    next_state: dict,
    target: str,
    private_key: Path,
    *,
    store: LifecycleStore,
    accepted_evidence_records: list[dict] | tuple[dict, ...] = (),
) -> tuple[dict, str]:
    prepared = dict(next_state)
    prepared.pop("idempotent_replay", None)
    prepared["authoritative_lifecycle"] = True
    prepared["authority_store"] = "controller-owned-sqlite"
    prepared["subject_fingerprint"] = subject_fingerprint(prepared)
    next_hash = sha256_bytes(canonical_json(prepared))
    preparation = store.prepare_transition_authorization(
        current["case_id"],
        next_state,
        expected_version=int(current["store_version"]),
        requested_state=target,
        decision="PROCEED",
        required_evidence=["RESOLVED_NO_CODE_PROVEN"],
        accepted_evidence=["ev-proof-001"],
        accepted_evidence_records=accepted_evidence_records,
    )
    idempotency_key = preparation["idempotency_key"]
    subject = {key: value for key, value in subject_from_record(prepared).items() if value is not None}
    metadata = {
        "case_id": current["case_id"],
        "expected_version": int(current["store_version"]),
        "current_record_hash": current["store_record_hash"],
        "next_record_hash": next_hash,
        "requested_state": target,
        "decision": "PROCEED",
        "actor": LIFECYCLE_CONTROLLER_ID,
        "idempotency_key": idempotency_key,
        "subject_fingerprint": subject_fingerprint(subject),
        "subject_epoch": int(subject.get("subject_epoch") or 0),
        "required_evidence": ["RESOLVED_NO_CODE_PROVEN"],
        "accepted_evidence": ["ev-proof-001"],
        "rejected_evidence": [],
        "policy_hash": prepared.get("policy_bundle_hash"),
        "toolchain_hash": prepared.get("toolchain_hash"),
        "controller_id": LIFECYCLE_CONTROLLER_ID,
        "controller_type": LIFECYCLE_CONTROLLER_TYPE,
        "identity_source": "local-runtime-context",
        "authentication_mechanism": "protected-transition-signature-required",
        "event_commitment": preparation["event_commitment"],
        "event_occurred_at": preparation["event_occurred_at"],
    }
    authorization = {
        "evidence_id": "ev-transition-resolved-001",
        "type": "LIFECYCLE_TRANSITION_AUTHORIZATION",
        "trust_level": "E6",
        "producer": LIFECYCLE_CONTROLLER_ID,
        "repository": subject["repository"],
        **subject,
        "subject_fingerprint": subject_fingerprint(subject),
        "environment": "controller",
        "created_at": preparation["event_occurred_at"],
        "invalidated_by": [],
        "status": "APPROVED",
        "metadata": metadata,
        "signature_or_attestation": None,
    }
    return sign_evidence(authorization, private_key_path=private_key, key_id="lifecycle-key"), idempotency_key


def test_git_inventory_omitting_one_actual_path_blocks_diff_forensics(tmp_path: Path) -> None:
    base, candidate, _tree = _git_subject_repo(tmp_path / "repo")
    inventory = collect_git_diff_inventory(tmp_path / "repo", base_sha=base, candidate_sha=candidate)
    metadata = _forensic_metadata(inventory)
    assert validate_diff_forensics(
        metadata,
        planned_files=metadata["actual_changed_files"],
        expected_diff_hash=inventory["diff_hash"],
        expected_base_sha=base,
        expected_candidate_sha=candidate,
        actual_git_inventory=inventory,
    ) == []
    omitted = copy.deepcopy(metadata)
    omitted["actual_changed_files"] = omitted["actual_changed_files"][:-1]
    errors = validate_diff_forensics(
        omitted,
        planned_files=metadata["actual_changed_files"],
        expected_diff_hash=inventory["diff_hash"],
        expected_base_sha=base,
        expected_candidate_sha=candidate,
        actual_git_inventory=inventory,
    )
    assert any("Git's changed-file set" in item or "actual_changed_files" in item for item in errors)
    extra = copy.deepcopy(metadata)
    extra["files"].append({
        "path": "forged.py",
        "planned": True,
        "justification": "forged",
        "security_impact": "none",
        "data_domain_impact": "none",
        "generated": False,
        "category": "runtime",
    })
    extra["actual_changed_files"].append("forged.py")
    assert validate_diff_forensics(
        extra,
        planned_files=extra["actual_changed_files"],
        expected_diff_hash=inventory["diff_hash"],
        expected_base_sha=base,
        expected_candidate_sha=candidate,
        actual_git_inventory=inventory,
    )


def test_authoritative_inventory_is_collected_from_the_bound_revisions(tmp_path: Path) -> None:
    base, candidate, _tree = _git_subject_repo(tmp_path / "bound-repo")
    record = {"protected_base_sha": base, "head_sha": candidate}
    actual = _collect_authoritative_git_inventory(record, tmp_path / "bound-repo")
    expected = collect_git_diff_inventory(tmp_path / "bound-repo", base_sha=base, candidate_sha=candidate)
    assert actual == expected
    assert _collect_authoritative_git_inventory(record, tmp_path / "missing-repo") is None


def test_worktree_candidate_fingerprint_is_canonical_and_material_sensitive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original_root = tmp_path / "checkout-a"
    base = _git_worktree_base(original_root)
    copied_root = tmp_path / "checkout-b-with-a-different-absolute-path"
    _copy_clean_git_checkout(original_root, copied_root)

    baseline_a = collect_worktree_diff_inventory(original_root, base_sha=base)
    baseline_b = collect_worktree_diff_inventory(copied_root, base_sha=base)
    assert baseline_a == baseline_b

    os.utime(original_root / "tracked.txt", ns=(1_700_000_000_000_000_000, 1_700_000_001_000_000_000))
    timestamp_only = collect_worktree_diff_inventory(original_root, base_sha=base)
    assert timestamp_only == baseline_a

    (original_root / "tracked.txt").write_text("content mutation\n", encoding="utf-8")
    content_changed = collect_worktree_diff_inventory(original_root, base_sha=base)
    assert content_changed["candidate_sha"] != baseline_a["candidate_sha"]
    assert content_changed["diff_hash"] != baseline_a["diff_hash"]

    renamed_root = tmp_path / "rename-checkout"
    _copy_clean_git_checkout(copied_root, renamed_root)
    _git(renamed_root, "mv", "tracked.txt", "renamed.txt")
    renamed = collect_worktree_diff_inventory(renamed_root, base_sha=base)
    assert any(item["path"] == "renamed.txt" and item["old_path"] == "tracked.txt" for item in renamed["files"])
    assert renamed["candidate_sha"] != baseline_a["candidate_sha"]

    deleted_root = tmp_path / "delete-checkout"
    _copy_clean_git_checkout(copied_root, deleted_root)
    (deleted_root / "tracked.txt").unlink()
    deleted = collect_worktree_diff_inventory(deleted_root, base_sha=base)
    assert any(item["path"] == "tracked.txt" and item["status"] == "D" for item in deleted["files"])
    assert deleted["candidate_sha"] != baseline_a["candidate_sha"]

    untracked_root = tmp_path / "untracked-checkout"
    _copy_clean_git_checkout(copied_root, untracked_root)
    (untracked_root / "required-untracked-control-file.txt").write_text("required\n", encoding="utf-8")
    untracked = collect_worktree_diff_inventory(untracked_root, base_sha=base)
    assert any(item["path"] == "required-untracked-control-file.txt" and item["status"] == "??" for item in untracked["files"])
    assert untracked["candidate_sha"] != baseline_a["candidate_sha"]

    unstaged_root = tmp_path / "unstaged-checkout"
    _copy_clean_git_checkout(copied_root, unstaged_root)
    (unstaged_root / "tracked.txt").write_text("staged-layer-test\n", encoding="utf-8")
    unstaged = collect_worktree_diff_inventory(unstaged_root, base_sha=base)

    staged_root = tmp_path / "staged-checkout"
    _copy_clean_git_checkout(copied_root, staged_root)
    (staged_root / "tracked.txt").write_text("staged-layer-test\n", encoding="utf-8")
    _git(staged_root, "add", "tracked.txt")
    staged = collect_worktree_diff_inventory(staged_root, base_sha=base)
    assert staged["candidate_sha"] != unstaged["candidate_sha"]
    assert staged["diff_hash"] != unstaged["diff_hash"]

    ordered_root = tmp_path / "order-checkout"
    _copy_clean_git_checkout(copied_root, ordered_root)
    (ordered_root / "z-last.txt").write_text("z\n", encoding="utf-8")
    (ordered_root / "a-first.txt").write_text("a\n", encoding="utf-8")
    ordered = collect_worktree_diff_inventory(ordered_root, base_sha=base)
    original = GitRepository.worktree_changed_paths

    def reversed_enumeration(repository: GitRepository, revision: str) -> list[dict[str, str | None]]:
        return list(reversed(original(repository, revision)))

    monkeypatch.setattr(GitRepository, "worktree_changed_paths", reversed_enumeration)
    reordered = collect_worktree_diff_inventory(ordered_root, base_sha=base)
    assert reordered == ordered
    assert all(
        {"path", "status", "old_path", "base_mode", "base_content_hash", "working_tree_kind", "working_tree_mode", "working_tree_filesystem_mode", "working_tree_content_hash"}
        <= set(item)
        for item in ordered["files"]
    )


def test_diff_transition_requires_independent_git_inventory(tmp_path: Path) -> None:
    record = _subject_record(state="CHANGE_PLANNED")
    record["change_contract_hash"] = DIGEST_B
    record["diff_hash"] = DIGEST_A
    reasons = _protocol_gate_errors(
        record,
        "DIFF_FORENSICS_PASS",
        [],
        policy=POLICY,
        problem_case=None,
    )
    assert any("independently collected Git inventory" in item for item in reasons)


def test_controller_actor_is_derived_and_model_text_is_rejected(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "actor.db")
    initial = store.initialize({"case_id": "CASE-ACTOR-001", "state": "UNVERIFIED_REPORT", "repository": "owner/repo"})
    assert store.events()[0]["actor"] == LIFECYCLE_CONTROLLER_ID
    with pytest.raises(PermissionError, match="verified controller attestation"):
        ControllerRuntimeContext(
            controller_id=LIFECYCLE_CONTROLLER_ID,
            controller_type=LIFECYCLE_CONTROLLER_TYPE,
            runtime_instance_id="runtime:model-invented",
            identity_source="model-input",
            authentication_mechanism="model-input",
            authenticated=True,
        )
    with pytest.raises(PermissionError, match="runtime controller boundary"):
        ControllerRuntimeContext(
            controller_id=LIFECYCLE_CONTROLLER_ID,
            controller_type=LIFECYCLE_CONTROLLER_TYPE,
            runtime_instance_id="runtime:model-invented-unverified",
            identity_source="model-input",
            authentication_mechanism="model-input",
            authenticated=False,
        )
    with pytest.raises(PermissionError, match="HOST_CAPABILITY_UNPROVEN"):
        ControllerRuntimeContext.from_verified_attestation(
            {
                "metadata": {
                    "controller_id": LIFECYCLE_CONTROLLER_ID,
                    "controller_type": LIFECYCLE_CONTROLLER_TYPE,
                    "runtime_instance_id": "runtime:model-invented-attestation",
                }
            }
        )
    with pytest.raises(PermissionError, match="runtime controller"):
        store.transition(
            initial["case_id"],
            dict(initial, state="SOURCE_OF_TRUTH_RESOLVED"),
            actor="agent:model-invented-controller",
            expected_version=initial["store_version"],
            requested_state="SOURCE_OF_TRUTH_RESOLVED",
            decision="PROCEED",
        )


def test_self_trusted_or_substituted_roots_cannot_authorize_closure(tmp_path: Path) -> None:
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
                "allowed_trust_levels": ["E3", "E6"],
                "allowed_producers": [LIFECYCLE_CONTROLLER_ID],
                "allowed_types": ["RESOLVED_NO_CODE_PROVEN", "LIFECYCLE_TRANSITION_AUTHORIZATION"],
                "allowed_environments": ["controller"],
            }
        },
    }
    roots_path = tmp_path / "model-roots.json"
    roots_path.write_text(json.dumps(roots), encoding="utf-8")
    with pytest.raises(PermissionError, match="HOST_CAPABILITY_UNPROVEN"):
        load_host_accepted_trust_roots(
            roots_path,
            accepted_digest=sha256_bytes(canonical_json(roots)),
            acceptance_id="model-invented-acceptance",
        )
    store = LifecycleStore(tmp_path / "raw-roots.db", authority_trust_roots=roots)
    initial = store.initialize({
        "case_id": "CASE-ROOT-SUBSTITUTION-001",
        "state": "UNVERIFIED_REPORT",
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
    source = store.transition(
        initial["case_id"],
        dict(initial, state="SOURCE_OF_TRUTH_RESOLVED", last_completed_state="SOURCE_OF_TRUTH_RESOLVED"),
        expected_version=initial["store_version"],
        requested_state="SOURCE_OF_TRUTH_RESOLVED",
        decision="PROCEED",
    )
    classified = store.transition(
        initial["case_id"],
        dict(source, state="ISSUE_CLASSIFIED", last_completed_state="ISSUE_CLASSIFIED"),
        expected_version=source["store_version"],
        requested_state="ISSUE_CLASSIFIED",
        decision="PROCEED",
    )
    next_state = dict(classified, state="RESOLVED_NO_CODE", last_completed_state="RESOLVED_NO_CODE", final_state="RESOLVED_NO_CODE", closure_class="RESOLVED_NO_CODE")
    subject = {key: value for key, value in subject_from_record(next_state).items() if value is not None}
    proof = {
        "evidence_id": "ev-proof-001",
        "type": "RESOLVED_NO_CODE_PROVEN",
        "lifecycle_case_id": "CASE-ROOT-SUBSTITUTION-001",
        "trust_level": "E3",
        "producer": LIFECYCLE_CONTROLLER_ID,
        "repository": subject["repository"],
        **subject,
        "subject_fingerprint": subject_fingerprint(subject),
        "environment": "controller",
        "created_at": utc_now(),
        "invalidated_by": [],
        "status": "PASSED",
        "metadata": {},
        "signature_or_attestation": None,
    }
    signed_proof = sign_evidence(proof, private_key_path=private, key_id="lifecycle-key")
    authorization, idempotency_key = _transition_authorization(
        classified,
        next_state,
        "RESOLVED_NO_CODE",
        private,
        store=store,
        accepted_evidence_records=[signed_proof],
    )
    with pytest.raises(PermissionError, match="host-accepted"):
        store.transition(
            classified["case_id"],
            next_state,
            expected_version=classified["store_version"],
            requested_state="RESOLVED_NO_CODE",
            decision="PROCEED",
            required_evidence=["RESOLVED_NO_CODE_PROVEN"],
            accepted_evidence=["ev-proof-001"],
            accepted_evidence_records=[signed_proof],
            idempotency_key=idempotency_key,
            transition_authorization=authorization,
        )
    with pytest.raises(PermissionError, match="host trust-root loader"):
        TrustRootAuthority(
            _roots=roots,
            source="HOST_ACCEPTED",
            host_accepted=True,
            config_digest=sha256_bytes(canonical_json(roots)),
            acceptance_id="model-invented-acceptance",
        )
    fixture_store = LifecycleStore(
        tmp_path / "fixture-roots.db",
        authority_trust_roots=TrustRootAuthority.from_test_fixture(roots),
    )
    assert fixture_store._authority_roots_are_host_accepted() is False
    with pytest.raises(PermissionError, match="host-accepted authority"):
        TrustRootAuthority.from_host_accepted(
            roots,
            accepted_digest=sha256_bytes(canonical_json(roots)),
            acceptance_id="model-invented-acceptance",
        )


@pytest.mark.parametrize("trust_level", ["E3", "E4", "E5", "E6"])
def test_unsigned_e3_to_e6_evidence_is_rejected(trust_level: str, tmp_path: Path) -> None:
    private = tmp_path / "unused-test-key.pem"
    public = tmp_path / "unused-test-key.pub.pem"
    try:
        generate_ed25519_keypair(private, public)
        roots = {
            "version": 1,
            "keys": {
                "test-key": {
                    "algorithm": "ed25519",
                    "public_key_pem": public.read_text(encoding="utf-8"),
                    "status": "ACTIVE",
                    "allowed_trust_levels": ["E3", "E4", "E5", "E6"],
                    "allowed_producers": ["platform:protected-ci"],
                    "allowed_types": ["PROTECTED_CI"],
                    "allowed_environments": ["ci"],
                }
            },
        }
        subject = _subject_record()
        evidence = {
            "evidence_id": f"ev-unsigned-{trust_level.lower()}-001",
            "type": "PROTECTED_CI",
            "trust_level": trust_level,
            "producer": "platform:protected-ci",
            **{key: value for key, value in subject_from_record(subject).items() if value is not None},
            "subject_fingerprint": subject_fingerprint(subject),
            "environment": "ci",
            "created_at": utc_now(),
            "invalidated_by": [],
            "status": "PASSED",
            "metadata": {},
            "signature_or_attestation": None,
        }
        errors = validate_evidence_record(
            evidence,
            subject=subject,
            minimum_trust=trust_level,
            trust_roots=TrustRootAuthority.from_test_fixture(roots),
            require_authoritative_signature=True,
            require_affirmative_status=True,
        )
        assert any("signature" in item.lower() or "attestation" in item.lower() for item in errors)
    finally:
        for path in (private, public):
            if path.exists():
                path.unlink()


def test_policy_weakening_is_rejected_before_runtime_use() -> None:
    mutations = []
    weakened_r4 = copy.deepcopy(POLICY)
    weakened_r4["risk_classes"]["CRITICAL"] = ["R3"]
    mutations.append(weakened_r4)
    missing_state = copy.deepcopy(POLICY)
    missing_state["states"].remove("DIFF_FORENSICS_PASS")
    mutations.append(missing_state)
    missing_no_code_state = copy.deepcopy(POLICY)
    missing_no_code_state["states"].remove("RESOLVED_NO_CODE")
    mutations.append(missing_no_code_state)
    missing_security = copy.deepcopy(POLICY)
    missing_security["domain_profiles"]["SECURITY"]["required_checks"] = []
    mutations.append(missing_security)
    state_skip = copy.deepcopy(POLICY)
    state_skip["transitions"]["UNVERIFIED_REPORT"] = ["ISSUE_CLASSIFIED"]
    mutations.append(state_skip)
    downgrade = copy.deepcopy(POLICY)
    downgrade["domain_profiles"]["FINANCIAL"]["minimum_risk_class"] = "LOW"
    mutations.append(downgrade)
    missing_rollback_domain = copy.deepcopy(POLICY)
    missing_rollback_domain["gates"]["ROLLBACK_CLOSURE"]["by_domain"].pop("SECURITY")
    mutations.append(missing_rollback_domain)
    for policy in mutations:
        assert validate_policy_safety(policy)
    assert validate_policy_safety(POLICY) == []


def test_declared_model_risk_class_cannot_downgrade_policy_floor(tmp_path: Path) -> None:
    case = {
        "case_id": "CASE-RISK-FLOOR-001",
        "repository": "owner/repo",
        "risk": "R0",
        "risk_class": "LOW",
    }
    lifecycle = initialize_bug_lifecycle(problem_case=case, policy=POLICY, domains=["FINANCIAL"])
    assert lifecycle["risk_class"] == "HIGH"


def test_unconsumed_mandatory_policy_field_fails_wiring() -> None:
    weakened = copy.deepcopy(POLICY)
    weakened["mandatory_fields"].append("unconsumed.control_plane_field")
    errors, _active = _semantic_policy_errors(
        ROOT,
        "bug-to-production-policy.yaml",
        weakened,
        ("ztad.bug_lifecycle", "ztad.bug_protocol", "ztad.evidence_bundle"),
    )
    assert any("has no registered consumer" in error for error in errors)


def test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate() -> None:
    required = {
        "DATABASE": {"MIGRATION_LEDGER_HISTORY_GUARD_PASSED"},
        "AUTH_TENANT": {"AUTHZ_TENANT_MATRIX_PASSED", "SERVER_SIDE_AUTHORIZATION_PASSED", "TENANT_CROSSING_DENIED", "ID_TAMPERING_DENIED"},
        "FINANCIAL": {"FINANCIAL_INVARIANTS_PASSED", "IDEMPOTENCY_PASSED", "LEDGER_CONSISTENCY_PASSED", "NO_DUPLICATE_FINANCIAL_SIDE_EFFECT"},
        "ZATCA": {"ZATCA_INVARIANTS_PASSED", "ZATCA_LEGAL_STATE_MACHINE_PASSED", "ZATCA_DUPLICATE_PREVENTION_PASSED", "ZATCA_IMMUTABILITY_PASSED"},
        "PROVIDER": {"PROVIDER_SEMANTICS_PASSED", "PROVIDER_STATE_RECONCILIATION_PASSED", "PROVIDER_IDEMPOTENCY_PASSED", "PROVIDER_SAFE_OUTAGE_PASSED"},
        "CONCURRENCY": {"CONCURRENCY_INVARIANTS_PASSED", "PARALLEL_REPRODUCTION_PASSED", "NO_DUPLICATE_DURABLE_SIDE_EFFECT"},
        "SECURITY": {"SECURITY_VALIDATION_PASSED", "SECRETS_SCAN_PASSED", "FAIL_CLOSED_BOUNDARY_PASSED"},
    }
    for domain, checks in required.items():
        _minimum, gate_checks = _gate_requirements(
            POLICY,
            "TARGETED_VALIDATION_PASS",
            {"risk": "R3", "risk_class": "HIGH", "domains": [domain]},
        )
        assert checks.issubset(set(gate_checks))
        assert set(POLICY["domain_profiles"][domain]["required_checks"]).issubset(set(gate_checks))


def test_hotfix_cannot_skip_staging_or_domain_gates() -> None:
    assert POLICY["hotfix"]["may_skip_states"] is False
    assert POLICY["hotfix"]["may_reduce_validation_breadth"] is False
    assert POLICY["hotfix"]["minimum_lifecycle"]
    assert set(POLICY["hotfix"]["minimum_lifecycle"]).issuperset(
        {"TARGETED_VALIDATION_PASS", "READY_FOR_OWNER_RELEASE"}
    )
    for domain in ("DATABASE", "AUTH_TENANT", "FINANCIAL", "ZATCA", "PROVIDER", "CONCURRENCY", "SECURITY"):
        _minimum, gate_checks = _gate_requirements(
            POLICY,
            "TARGETED_VALIDATION_PASS",
            {"risk": "R3", "risk_class": "HIGH", "domains": [domain]},
        )
        assert gate_checks


def test_subject_epoch_policy_covers_candidate_contract_policy_toolchain_artifact_and_production() -> None:
    expected = {
        "candidate_identity": {"protected_base_sha", "pr_head_sha", "reviewed_diff_hash"},
        "merge_identity": {"merged_main_sha", "merge_method", "merge_provenance", "post_merge_ci_run_id"},
        "contract_policy_toolchain": {"change_contract_hash", "policy_bundle_hash", "toolchain_hash"},
        "artifact_release": {"artifact_digest", "release_fingerprint", "sbom_digest", "provenance_digest", "attestation_digest", "artifact_identity"},
        "production_identity": {"production_release_id", "deployed_revision"},
    }
    for name, fields in expected.items():
        assert set(SUBJECT_TRANSITION_POLICY[name]["fields"]) == fields
    assert subject_epoch_transition_policy({"artifact_digest"})["earliest_revalidation_state"] == "CI_PASS"
    assert subject_epoch_transition_policy({"deployed_revision"})["earliest_revalidation_state"] == "ROLLBACK_REQUIRED"
    base = _subject_record()
    for updates in (
        {"reviewed_diff_hash": DIGEST_B},
        {"change_contract_hash": DIGEST_A},
        {"policy_bundle_hash": DIGEST_A},
        {"toolchain_hash": DIGEST_A},
        {"artifact_digest": DIGEST_B},
    ):
        updated = apply_subject_update(base, updates, reason="epoch-test")
        assert updated["subject_epoch"] == 1
        assert updated["evidence_refs"] == {}
        assert updated["subject_fingerprint"] == subject_fingerprint(updated)
        description = describe_subject_transition(base, updated)
        assert description["old_epoch"] == 0
        assert description["new_epoch"] == 1
        assert description["evidence_invalidated"]
        assert description["earliest_lifecycle_state_retained"]
    production = _subject_record(state="PRODUCTION_RELEASED")
    production["production_release_id"] = "release-1"
    production["deployed_revision"] = production["pr_head_sha"]
    rolled = apply_subject_update(production, {"production_release_id": "release-2"}, reason="deployment-mutation")
    production_transition = describe_subject_transition(production, rolled)
    assert production_transition["category"] == "production_identity"
    assert production_transition["earliest_lifecycle_state_retained"] == "ROLLBACK_REQUIRED"
    assert rolled["state"] == "ROLLBACK_REQUIRED"
    assert rolled["subject_epoch"] == 1


def test_squash_merge_preserves_pr_a_to_main_c_provenance(tmp_path: Path) -> None:
    root = tmp_path / "git-subject"
    root.mkdir()
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "ztad-test@example.invalid")
    _git(root, "config", "user.name", "ZTAD Test")
    (root / "app.py").write_text("return 1\n", encoding="utf-8")
    _git(root, "add", "app.py")
    _git(root, "commit", "--quiet", "-m", "A")
    base = _git(root, "rev-parse", "HEAD")
    _git(root, "checkout", "-q", "-b", "pr")
    (root / "app.py").write_text("return 2\n", encoding="utf-8")
    _git(root, "commit", "--quiet", "-am", "B")
    pr_head = _git(root, "rev-parse", "HEAD")
    _git(root, "checkout", "-q", "--detach", base)
    (root / "app.py").write_text("return 2\n", encoding="utf-8")
    _git(root, "commit", "--quiet", "-am", "C squash")
    merged = _git(root, "rev-parse", "HEAD")
    assert pr_head != merged
    contract = tmp_path / "contract.json"
    contract.write_text("{\"goal\":\"subject\"}\n", encoding="utf-8")
    candidate = bind_candidate(
        _subject_record(state="CHANGE_PLANNED"),
        contract_path=contract,
        head_sha=pr_head,
        diff_hash=DIGEST_A,
        policy_bundle_hash=DIGEST_B,
        toolchain_hash=DIGEST_C,
    )
    merged_record = bind_merge_subject(
        candidate,
        merged_main_sha=merged,
        merge_method="SQUASH",
        merge_provenance={
            "pr_head_sha": pr_head,
            "reviewed_diff_hash": DIGEST_A,
            "merged_main_sha": merged,
            "transformation": "protected squash merge",
        },
        post_merge_ci_run_id="main-ci-c",
    )
    assert validate_subject(merged_record, require_merge_provenance=True).errors == ()
    assert merged_record["pr_head_sha"] == pr_head
    assert merged_record["merged_main_sha"] == merged
    old_evidence = {
        "evidence_id": "ev-pr-a-001",
        "type": "PROTECTED_CI",
        "trust_level": "E2",
        "producer": "platform:protected-ci",
        "repository": "owner/repo",
        "protected_base_sha": candidate["protected_base_sha"],
        "pr_head_sha": candidate["pr_head_sha"],
        "reviewed_diff_hash": candidate["reviewed_diff_hash"],
        "change_contract_hash": candidate["change_contract_hash"],
        "policy_bundle_hash": candidate["policy_bundle_hash"],
        "toolchain_hash": candidate["toolchain_hash"],
        "subject_epoch": candidate["subject_epoch"],
        "subject_version": candidate["subject_version"],
        "subject_fingerprint": candidate["subject_fingerprint"],
        "environment": "ci",
        "created_at": utc_now(),
        "invalidated_by": [],
        "status": "PASSED",
    }
    assert validate_evidence_record(old_evidence, subject=merged_record, minimum_trust="E2", require_authoritative_signature=False)
    post_merge = dict(old_evidence, evidence_id="ev-main-c-001", head_sha=merged, merged_main_sha=merged, post_merge_ci_run_id="main-ci-c", subject_epoch=merged_record["subject_epoch"], subject_fingerprint=merged_record["subject_fingerprint"])
    post_merge.update({key: value for key, value in subject_from_record(merged_record).items() if value is not None})
    post_merge["created_at"] = utc_now()
    assert validate_evidence_record(post_merge, subject=merged_record, minimum_trust="E2", require_authoritative_signature=False) == []
    artifact = bind_artifact(merged_record, DIGEST_C)
    production = bind_production_subject(artifact, production_release_id="release-c", deployed_revision=merged)
    assert production["deployed_revision"] == merged
    assert validate_evidence_record(
        old_evidence,
        subject=production,
        minimum_trust="E2",
        require_authoritative_signature=False,
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "payload",
        "malformed_payload",
        "hash",
        "fingerprint",
        "actor",
        "delete",
        "reorder",
        "previous_hash",
        "idempotency_key",
        "wrong_case",
        "rollback_event",
    ],
)
def test_lifecycle_database_mutations_are_detectable(mutation: str, tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / f"tamper-{mutation}.db")
    initial = store.initialize({"case_id": f"CASE-TAMPER-{mutation}", "state": "UNVERIFIED_REPORT", "repository": "owner/repo"})
    store.transition(
        initial["case_id"],
        dict(initial, state="SOURCE_OF_TRUTH_RESOLVED"),
        expected_version=initial["store_version"],
        requested_state="SOURCE_OF_TRUTH_RESOLVED",
        decision="PROCEED",
    )
    conn = sqlite3.connect(store.path)
    conn.execute("DROP TRIGGER IF EXISTS lifecycle_events_no_update")
    conn.execute("DROP TRIGGER IF EXISTS lifecycle_events_no_delete")
    if mutation == "payload":
        conn.execute("UPDATE lifecycle_events SET record_json='{}' WHERE sequence=2")
    elif mutation == "malformed_payload":
        conn.execute("UPDATE lifecycle_events SET record_json='{' WHERE sequence=2")
    elif mutation == "hash":
        conn.execute("UPDATE lifecycle_events SET record_hash=? WHERE sequence=2", ("sha256:" + "f" * 64,))
    elif mutation == "fingerprint":
        conn.execute("UPDATE lifecycle_events SET subject_fingerprint=? WHERE sequence=2", ("sha256:" + "f" * 64,))
    elif mutation == "actor":
        conn.execute("UPDATE lifecycle_events SET actor='agent:forged' WHERE sequence=2")
    elif mutation == "delete":
        conn.execute("DELETE FROM lifecycle_events WHERE sequence=2")
    elif mutation == "rollback_event":
        conn.execute("UPDATE lifecycle_events SET requested_state='ROLLBACK_REQUIRED', decision='ROLLBACK_REQUIRED' WHERE sequence=2")
    elif mutation == "previous_hash":
        conn.execute("UPDATE lifecycle_events SET previous_hash=? WHERE sequence=2", ("sha256:" + "e" * 64,))
    elif mutation == "idempotency_key":
        conn.execute("UPDATE lifecycle_events SET idempotency_key='forged-semantics' WHERE sequence=2")
    elif mutation == "wrong_case":
        conn.execute("UPDATE lifecycle_events SET case_id='CASE-OTHER-TASK' WHERE sequence=2")
    else:
        conn.execute("UPDATE lifecycle_events SET sequence=3 WHERE sequence=2")
    conn.commit()
    conn.close()
    assert store.verify_event_chain(case_id=initial["case_id"])["valid"] is False
    with pytest.raises(RuntimeError):
        store.get(initial["case_id"])


def test_lifecycle_duplicate_sequence_write_is_rejected_and_does_not_open_the_store(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "duplicate-sequence.db")
    initial = store.initialize({"case_id": "CASE-DUPLICATE-SEQUENCE", "state": "UNVERIFIED_REPORT", "repository": "owner/repo"})
    store.transition(
        initial["case_id"],
        dict(initial, state="SOURCE_OF_TRUTH_RESOLVED"),
        expected_version=initial["store_version"],
        requested_state="SOURCE_OF_TRUTH_RESOLVED",
        decision="PROCEED",
    )
    conn = sqlite3.connect(store.path)
    conn.execute("DROP TRIGGER IF EXISTS lifecycle_events_no_update")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE lifecycle_events SET sequence=1 WHERE sequence=2")
    conn.rollback()
    conn.close()
    assert store.verify_event_chain(case_id=initial["case_id"])["valid"] is True


def test_lifecycle_export_mutation_cannot_be_reimported_as_authority(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "export-boundary.db")
    initial = store.initialize({"case_id": "CASE-EXPORT-BOUNDARY", "state": "UNVERIFIED_REPORT", "repository": "owner/repo"})
    current = store.transition(
        initial["case_id"],
        dict(initial, state="SOURCE_OF_TRUTH_RESOLVED"),
        expected_version=initial["store_version"],
        requested_state="SOURCE_OF_TRUTH_RESOLVED",
        decision="PROCEED",
    )
    exported = store.export(current["case_id"])
    forged_export = copy.deepcopy(exported)
    forged_export["state"] = "CLOSED"
    forged_export["final_state"] = "CLOSED"
    forged_export["lifecycle_events"][-1]["requested_state"] = "CLOSED"
    assert store.get(current["case_id"])["state"] == "SOURCE_OF_TRUTH_RESOLVED"
    assert store.export(current["case_id"])["state"] == "SOURCE_OF_TRUTH_RESOLVED"
    assert forged_export["state"] == "CLOSED"


def test_subject_mutation_after_gate_evaluation_rejects_stale_prepared_transition(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "subject-toctou.db")
    initial = store.initialize({
        "case_id": "CASE-SUBJECT-TOCTOU",
        "state": "UNVERIFIED_REPORT",
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
    source = store.transition(
        initial["case_id"],
        dict(initial, state="SOURCE_OF_TRUTH_RESOLVED"),
        expected_version=initial["store_version"],
        requested_state="SOURCE_OF_TRUTH_RESOLVED",
        decision="PROCEED",
    )
    classified = store.transition(
        source["case_id"],
        dict(source, state="ISSUE_CLASSIFIED"),
        expected_version=source["store_version"],
        requested_state="ISSUE_CLASSIFIED",
        decision="PROCEED",
    )
    prepared = dict(classified, state="BUG_REPRODUCED", last_completed_state="BUG_REPRODUCED")
    evaluated_version = classified["store_version"]
    mutated = store.mutate_subject(
        classified["case_id"],
        {"change_contract_hash": DIGEST_C},
        reason="gate-evaluation-to-commit race",
        expected_version=evaluated_version,
    )
    assert mutated["subject_epoch"] == classified["subject_epoch"] + 1
    with pytest.raises(RuntimeError, match="stale lifecycle version"):
        store.transition(
            classified["case_id"],
            prepared,
            expected_version=evaluated_version,
            requested_state="BUG_REPRODUCED",
            decision="PROCEED",
        )


def test_lifecycle_database_copy_from_another_task_is_rejected(tmp_path: Path) -> None:
    original = LifecycleStore(tmp_path / "original.db")
    initial = original.initialize({"case_id": "CASE-COPY-001", "state": "UNVERIFIED_REPORT", "repository": "owner/repo"})
    original.transition(
        initial["case_id"],
        dict(initial, state="SOURCE_OF_TRUTH_RESOLVED"),
        expected_version=initial["store_version"],
        requested_state="SOURCE_OF_TRUTH_RESOLVED",
        decision="PROCEED",
    )
    copied_path = tmp_path / "copied.db"
    shutil.copy2(original.path, copied_path)
    copied = LifecycleStore(copied_path)
    with pytest.raises(RuntimeError, match="verification failed"):
        copied.get("CASE-COPY-001")


def test_stale_concurrent_writer_and_wrong_case_binding_are_rejected(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "concurrency.db")
    initial = store.initialize({"case_id": "CASE-CONCURRENT-001", "state": "UNVERIFIED_REPORT", "repository": "owner/repo"})
    barrier = threading.Barrier(2)

    def advance() -> str:
        barrier.wait(timeout=10)
        try:
            store.transition(
                initial["case_id"],
                dict(initial, state="SOURCE_OF_TRUTH_RESOLVED"),
                expected_version=initial["store_version"],
                requested_state="SOURCE_OF_TRUTH_RESOLVED",
                decision="PROCEED",
            )
            return "success"
        except RuntimeError:
            return "stale"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _item: advance(), (1, 2)))
    assert sorted(results) == ["stale", "success"]
    with pytest.raises(ValueError, match="case_id mismatch"):
        store.transition(
            "CASE-OTHER-001",
            dict(initial, state="SOURCE_OF_TRUTH_RESOLVED"),
            expected_version=initial["store_version"],
            requested_state="SOURCE_OF_TRUTH_RESOLVED",
            decision="PROCEED",
        )


def test_lifecycle_store_rejects_invalid_terminal_duplicate_and_future_semantics(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "semantic-guards.db")
    initial = store.initialize({"case_id": "CASE-SEMANTIC-GUARDS-001", "state": "UNVERIFIED_REPORT", "repository": "owner/repo"})
    with pytest.raises(PermissionError, match="bypass|order"):
        store.transition(
            initial["case_id"],
            dict(initial, state="CLOSED", last_completed_state="CLOSED", final_state="CLOSED", closure_class="CODE_FIX"),
            expected_version=initial["store_version"],
            requested_state="CLOSED",
            decision="PROCEED",
        )
    next_state = dict(initial, state="SOURCE_OF_TRUTH_RESOLVED", last_completed_state="SOURCE_OF_TRUTH_RESOLVED")
    with pytest.raises(ValueError, match="case_id mismatch"):
        store.transition(
            "CASE-OTHER-SEMANTICS-001",
            next_state,
            expected_version=initial["store_version"],
            requested_state="SOURCE_OF_TRUTH_RESOLVED",
            decision="PROCEED",
        )
    first = store.transition(
        initial["case_id"],
        next_state,
        expected_version=initial["store_version"],
        requested_state="SOURCE_OF_TRUTH_RESOLVED",
        decision="PROCEED",
        idempotency_key="semantic-duplicate-key",
    )
    assert first["state"] == "SOURCE_OF_TRUTH_RESOLVED"
    with pytest.raises(RuntimeError, match="stale lifecycle version"):
        store.transition(
            initial["case_id"],
            next_state,
            expected_version=initial["store_version"],
            requested_state="SOURCE_OF_TRUTH_RESOLVED",
            decision="PROCEED",
            idempotency_key="semantic-duplicate-key",
        )
    changed_semantics = dict(first, state="ISSUE_CLASSIFIED", last_completed_state="ISSUE_CLASSIFIED")
    with pytest.raises(RuntimeError, match="idempotency key was reused"):
        store.transition(
            initial["case_id"],
            changed_semantics,
            expected_version=first["store_version"],
            requested_state="ISSUE_CLASSIFIED",
            decision="PROCEED",
            idempotency_key="semantic-duplicate-key",
        )


def test_lifecycle_store_rejects_agent_and_local_terminal_attempts(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "terminal-authority.db")
    initial = store.initialize({"case_id": "CASE-TERMINAL-AUTHORITY", "state": "UNVERIFIED_REPORT", "repository": "owner/repo"})
    terminal = dict(
        initial,
        state="CLOSED",
        last_completed_state="CLOSED",
        final_state="CLOSED",
        closure_class="CODE_FIX",
    )
    with pytest.raises(PermissionError, match="actor"):
        store.transition(
            initial["case_id"],
            terminal,
            actor="agent:model",
            expected_version=initial["store_version"],
            requested_state="CLOSED",
            decision="PROCEED",
        )
    with pytest.raises(PermissionError, match="bypass|order"):
        store.transition(
            initial["case_id"],
            terminal,
            actor=LIFECYCLE_CONTROLLER_ID,
            expected_version=initial["store_version"],
            requested_state="CLOSED",
            decision="PROCEED",
        )


def test_artifact_promotion_rejects_rebuild_and_pr_only_or_mutable_identity() -> None:
    valid = {
        "source_sha": "a" * 40,
        "merged_main_sha": "a" * 40,
        "artifact_digest": DIGEST_A,
        "release_fingerprint": DIGEST_B,
        "sbom_digest": DIGEST_C,
        "provenance_digest": DIGEST_A,
        "attestation_digest": DIGEST_B,
        "artifact_identity": "owner/repo@" + DIGEST_A,
    }
    assert validate_artifact_chain(valid, head_sha="b" * 40, merged_main_sha="a" * 40, artifact_digest=DIGEST_A) == []
    for mutation in (
        {"rebuilt_after_validation": True},
        {"mutable_tag_only": True},
        {"source_sha": "b" * 40},
    ):
        assert validate_artifact_chain(
            valid | mutation,
            head_sha="b" * 40,
            merged_main_sha="a" * 40,
            artifact_digest=DIGEST_A,
        )


def test_legacy_subject_and_lifecycle_projections_cannot_claim_store_authority(tmp_path: Path) -> None:
    store = LifecycleStore(tmp_path / "projection-boundary.db")
    initial = store.initialize({"case_id": "CASE-PROJECTION-BOUNDARY", "state": "UNVERIFIED_REPORT", "repository": "owner/repo"})
    projection = bind_artifact(initial, DIGEST_A)
    assert projection["authoritative_lifecycle"] is False
    assert projection["authority_store"] is None
    assert store.get(initial["case_id"]).get("artifact_digest") is None


def test_old_subject_epoch_evidence_cannot_authorize_protected_transition(tmp_path: Path) -> None:
    private = tmp_path / "lifecycle-private.pem"
    public = tmp_path / "lifecycle-public.pem"
    generate_ed25519_keypair(private, public)
    roots = {
        "version": 1,
        "keys": {
            "lifecycle-key": {
                "algorithm": "ed25519",
                "public_key_pem": public.read_text(encoding="utf-8"),
                "status": "ACTIVE",
                "allowed_trust_levels": ["E3", "E6"],
                "allowed_producers": [LIFECYCLE_CONTROLLER_ID],
                "allowed_types": ["RESOLVED_NO_CODE_PROVEN", "LIFECYCLE_TRANSITION_AUTHORIZATION"],
                "allowed_environments": ["controller"],
            }
        },
    }
    roots_path = tmp_path / "accepted-roots.json"
    roots_path.write_text(json.dumps(roots), encoding="utf-8")
    authority = load_host_accepted_trust_roots(
        roots_path,
        accepted_digest=sha256_bytes(canonical_json(roots)),
        acceptance_id="host-epoch-test",
        host_acceptance_token=_HOST_ACCEPTANCE_TOKEN,
    )
    store = LifecycleStore(
        tmp_path / "old-epoch.db",
        authority_trust_roots=authority,
    )
    initial = store.initialize({
        "case_id": "CASE-OLD-EPOCH-001",
        "state": "UNVERIFIED_REPORT",
        "repository": "owner/repo",
        "protected_base_sha": "0" * 40,
        "pr_head_sha": "1" * 40,
        "reviewed_diff_hash": DIGEST_A,
        "change_contract_hash": DIGEST_B,
        "policy_bundle_hash": DIGEST_B,
        "toolchain_hash": DIGEST_C,
        "subject_epoch": 1,
        "subject_version": 1,
    })
    source = store.transition(
        initial["case_id"],
        dict(initial, state="SOURCE_OF_TRUTH_RESOLVED", last_completed_state="SOURCE_OF_TRUTH_RESOLVED"),
        expected_version=initial["store_version"],
        requested_state="SOURCE_OF_TRUTH_RESOLVED",
        decision="PROCEED",
    )
    classified = store.transition(
        initial["case_id"],
        dict(source, state="ISSUE_CLASSIFIED", last_completed_state="ISSUE_CLASSIFIED"),
        expected_version=source["store_version"],
        requested_state="ISSUE_CLASSIFIED",
        decision="PROCEED",
    )
    next_state = dict(
        classified,
        state="RESOLVED_NO_CODE",
        last_completed_state="RESOLVED_NO_CODE",
        final_state="RESOLVED_NO_CODE",
        closure_class="RESOLVED_NO_CODE",
    )
    stale_subject = subject_from_record(next_state)
    stale_subject["subject_epoch"] = 0
    stale_proof = {
        "evidence_id": "ev-old-epoch-001",
        "type": "RESOLVED_NO_CODE_PROVEN",
        "lifecycle_case_id": "CASE-OLD-EPOCH-001",
        "trust_level": "E3",
        "producer": LIFECYCLE_CONTROLLER_ID,
        "repository": stale_subject["repository"],
        **stale_subject,
        "subject_fingerprint": subject_fingerprint(stale_subject),
        "environment": "controller",
        "created_at": utc_now(),
        "invalidated_by": [],
        "status": "PASSED",
        "metadata": {},
        "signature_or_attestation": None,
    }
    signed = sign_evidence(stale_proof, private_key_path=private, key_id="lifecycle-key")
    authorization, idempotency_key = _transition_authorization(
        classified,
        next_state,
        "RESOLVED_NO_CODE",
        private,
        store=store,
        accepted_evidence_records=[signed],
    )
    with pytest.raises(PermissionError, match="subject_epoch|subject mismatch"):
        store.transition(
            classified["case_id"],
            next_state,
            expected_version=classified["store_version"],
            requested_state="RESOLVED_NO_CODE",
            decision="PROCEED",
            required_evidence=["RESOLVED_NO_CODE_PROVEN"],
            accepted_evidence=["ev-old-epoch-001"],
            accepted_evidence_records=[signed],
            idempotency_key=idempotency_key,
            transition_authorization=authorization,
        )


def test_rollback_closure_requires_policy_domain_recovery_union() -> None:
    for domain, check in {
        "DATABASE": "DATABASE_ROLLBACK_CONSISTENCY_VERIFIED",
        "AUTH_TENANT": "AUTHZ_ROLLBACK_MATRIX_PASSED",
        "FINANCIAL": "FINANCIAL_RECONCILIATION_PASSED",
        "ZATCA": "ZATCA_ROLLBACK_STATE_VERIFIED",
        "PROVIDER": "PROVIDER_RECONCILIATION_PASSED",
        "CONCURRENCY": "CONCURRENCY_SIDE_EFFECTS_RECONCILED",
        "SECURITY": "SECURITY_CONTAINMENT_VERIFIED",
    }.items():
        errors = validate_rollback_closure(
            {
                "rollback_completed": True,
                "post_rollback_health_verified": True,
                "stable_artifact_digest": DIGEST_A,
                "rollback_receipt": "receipt",
                "domain_checks": [],
            },
            domains=[domain],
            policy=POLICY,
        )
        assert check in " ".join(errors)


def test_fraudulent_terminal_bundle_shapes_fail_independent_replay() -> None:
    schema = load_data(ROOT / "schemas/evidence-bundle.schema.json")
    evidence_schema = load_data(ROOT / "schemas/evidence.schema.json")
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
    base = {
        "schema_version": 2,
        "issue_id": "CASE-FRAUD-001",
        "original_report": "reported",
        "classification": "CONFIRMED_BUG",
        "repository": "owner/repo",
        "final_state": "CLOSED",
        "closure_class": "CODE_FIX",
        **subject,
        "subject_fingerprint": subject_fingerprint(subject),
        "evidence_records": [],
        "lifecycle_events": [],
    }
    variants = [
        base,
        dict(base, subject_epoch=99),
        dict(base, final_state="CLOSED", lifecycle_events=[{"sequence": 1, "state": {"state": "CLOSED"}}]),
        dict(base, evidence_records=[{"evidence_id": "ev-wrong-trust", "type": "PROTECTED_CI", "trust_level": "E2", "producer": "local:forged"}]),
        dict(base, deployed_revision="2" * 40),
    ]
    for bundle in variants:
        errors = validate_evidence_bundle(
            bundle,
            bundle_schema=schema,
            evidence_schema=evidence_schema,
            policy=POLICY,
        )
        assert errors, bundle

    no_policy_errors = validate_evidence_bundle(
        base,
        bundle_schema=schema,
        evidence_schema=evidence_schema,
        trust_roots=None,
        policy=None,
    )
    assert any("authoritative policy bundle" in error for error in no_policy_errors)

    weakened_policy = copy.deepcopy(POLICY)
    weakened_policy["risk_classes"]["CRITICAL"] = ["R3"]
    policy_errors = validate_evidence_bundle(
        base,
        bundle_schema=schema,
        evidence_schema=evidence_schema,
        policy=weakened_policy,
    )
    assert any("R4" in error and "CRITICAL" in error for error in policy_errors)

    replayed_ci = dict(
        base,
        evidence_records=[
            {
                "evidence_id": "ev-ci-replay-a",
                "type": "PROTECTED_CI",
                "trust_level": "E2",
                "producer": "platform:protected-ci",
                "metadata": {"receipt_id": "receipt-replayed"},
            },
            {
                "evidence_id": "ev-ci-replay-b",
                "type": "REQUIRED_CHECKS_VERIFIED",
                "trust_level": "E2",
                "producer": "platform:protected-ci",
                "metadata": {"receipt_id": "receipt-replayed"},
            },
        ],
    )
    replay_errors = validate_evidence_bundle(
        replayed_ci,
        bundle_schema=schema,
        evidence_schema=evidence_schema,
        policy=POLICY,
    )
    assert any("replayed evidence" in error for error in replay_errors)


def test_deployment_success_cannot_close_bug_without_terminal_lifecycle() -> None:
    schema = load_data(ROOT / "schemas/evidence-bundle.schema.json")
    evidence_schema = load_data(ROOT / "schemas/evidence.schema.json")
    subject = _subject_record(state="CLOSED")
    deployment = {
        "evidence_id": "ev-deployment-success-without-close-001",
        "type": "PRODUCTION_RELEASE_COMPLETED",
        "trust_level": "E5",
        "producer": "platform:production-runtime",
        **{key: value for key, value in subject_from_record(subject).items() if value is not None},
        "subject_fingerprint": subject_fingerprint(subject),
        "environment": "production",
        "created_at": utc_now(),
        "invalidated_by": [],
        "status": "PASSED",
        "metadata": {"deployment": "successful"},
        "signature_or_attestation": None,
    }
    bundle = {
        "schema_version": 2,
        "issue_id": subject["case_id"],
        "original_report": "reported",
        "classification": "CONFIRMED_BUG",
        "repository": subject["repository"],
        "final_state": "CLOSED",
        "closure_class": "CODE_FIX",
        **{key: value for key, value in subject_from_record(subject).items() if value is not None},
        "subject_fingerprint": subject_fingerprint(subject),
        "evidence_records": [deployment],
        "lifecycle_events": [],
    }
    errors = validate_evidence_bundle(
        bundle,
        bundle_schema=schema,
        evidence_schema=evidence_schema,
        policy=POLICY,
    )
    assert any("lifecycle" in error.lower() for error in errors)


def test_packaged_regression_manifest_cannot_shrink() -> None:
    import sys
    sys.path.insert(0, str(ROOT / "scripts"))
    import run_packaged_regressions as packaged

    inventory = packaged.packaged_test_inventory(ROOT)
    assert tuple(inventory) == packaged.PACKAGED_TEST_MANIFEST
    assert packaged.validate_packaged_test_inventory(inventory) == []
    missing_one = inventory[:-1]
    shrinkage_errors = packaged.validate_packaged_test_inventory(missing_one)
    assert any("missing packaged tests" in item for item in shrinkage_errors)
    assert any("inventory changed" in item for item in shrinkage_errors)
    assert set(packaged.LEGACY_INSTALL_CRITICAL_TESTS).issubset(set(packaged.PACKAGED_TEST_MANIFEST))
    assert len(packaged.PACKAGED_TEST_MANIFEST) > len(packaged.LEGACY_INSTALL_CRITICAL_TESTS)
    assert "argv.extend(required_inventory)" in inspect.getsource(packaged._run)


ADVERSARIAL_TRACEABILITY = {
    "candidate fingerprint enumeration order": "tests/test_v4310_control_plane_adversarial.py::test_worktree_candidate_fingerprint_is_canonical_and_material_sensitive",
    "candidate fingerprint absolute checkout path": "tests/test_v4310_control_plane_adversarial.py::test_worktree_candidate_fingerprint_is_canonical_and_material_sensitive",
    "candidate fingerprint timestamp independence": "tests/test_v4310_control_plane_adversarial.py::test_worktree_candidate_fingerprint_is_canonical_and_material_sensitive",
    "candidate fingerprint content sensitivity": "tests/test_v4310_control_plane_adversarial.py::test_worktree_candidate_fingerprint_is_canonical_and_material_sensitive",
    "candidate fingerprint rename sensitivity": "tests/test_v4310_control_plane_adversarial.py::test_worktree_candidate_fingerprint_is_canonical_and_material_sensitive",
    "candidate fingerprint deletion sensitivity": "tests/test_v4310_control_plane_adversarial.py::test_worktree_candidate_fingerprint_is_canonical_and_material_sensitive",
    "candidate fingerprint required untracked sensitivity": "tests/test_v4310_control_plane_adversarial.py::test_worktree_candidate_fingerprint_is_canonical_and_material_sensitive",
    "candidate fingerprint staged and unstaged layers": "tests/test_v4310_control_plane_adversarial.py::test_worktree_candidate_fingerprint_is_canonical_and_material_sensitive",
    "candidate mutation after CI": "tests/test_v4310_fail_closed_adversarial.py::test_candidate_mutation_invalidates_ci_and_increments_epoch",
    "artifact mutation after staging": "tests/test_v4310_fail_closed_adversarial.py::test_artifact_mutation_invalidates_staging_and_production_mutation_requires_rollback",
    "contract mutation after readiness": "tests/test_v4310_control_plane_adversarial.py::test_subject_epoch_policy_covers_candidate_contract_policy_toolchain_artifact_and_production",
    "policy mutation after readiness": "tests/test_v4310_control_plane_adversarial.py::test_subject_epoch_policy_covers_candidate_contract_policy_toolchain_artifact_and_production",
    "toolchain mutation after readiness": "tests/test_v4310_control_plane_adversarial.py::test_subject_epoch_policy_covers_candidate_contract_policy_toolchain_artifact_and_production",
    "PR head A to squash main B": "tests/test_v4310_control_plane_adversarial.py::test_squash_merge_preserves_pr_a_to_main_c_provenance",
    "PR evidence A cannot prove production B": "tests/test_v4310_control_plane_adversarial.py::test_squash_merge_preserves_pr_a_to_main_c_provenance",
    "R4 GENERAL is CRITICAL": "tests/test_v4310_fail_closed_adversarial.py::test_risk_mapping_and_monotonic_floors",
    "domain risk cannot downgrade": "tests/test_v4310_fail_closed_adversarial.py::test_risk_mapping_and_monotonic_floors",
    "FINANCIAL complete evidence union": "tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate",
    "AUTH_TENANT complete evidence union": "tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate",
    "DATABASE complete evidence union": "tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate",
    "ZATCA complete evidence union": "tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate",
    "PROVIDER complete evidence union": "tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate",
    "CONCURRENCY complete evidence union": "tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate",
    "SECURITY complete evidence union": "tests/test_v4310_control_plane_adversarial.py::test_all_high_risk_domain_requirements_are_unioned_into_targeted_gate",
    "progressive exposure uses effective risk": "tests/test_v4310_fail_closed_adversarial.py::test_progressive_critical_exposure_requires_write_and_owner_stop",
    "classification record mandatory": "tests/test_v4310_fail_closed_adversarial.py::test_classification_blast_plan_targeted_and_diff_require_semantics",
    "per-file plan reasons mandatory": "tests/test_v4310_fail_closed_adversarial.py::test_classification_blast_plan_targeted_and_diff_require_semantics",
    "targeted validation metadata mandatory": "tests/test_v4310_fail_closed_adversarial.py::test_classification_blast_plan_targeted_and_diff_require_semantics",
    "complete diff-forensics enumeration": "tests/test_v4310_control_plane_adversarial.py::test_git_inventory_omitting_one_actual_path_blocks_diff_forensics",
    "fake E2 producer rejected": "tests/test_v4310_fail_closed_adversarial.py::test_fake_machine_evidence_cannot_claim_deterministic_execution",
    "controller actor identity cannot be model supplied": "tests/test_v4310_control_plane_adversarial.py::test_controller_actor_is_derived_and_model_text_is_rejected",
    "unsigned E3-E6 rejected": "tests/test_v4310_control_plane_adversarial.py::test_unsigned_e3_to_e6_evidence_is_rejected",
    "trust-root substitution rejected": "tests/test_v4310_control_plane_adversarial.py::test_self_trusted_or_substituted_roots_cannot_authorize_closure",
    "model cannot self-attest controller runtime": "tests/test_v4310_control_plane_adversarial.py::test_controller_actor_is_derived_and_model_text_is_rejected",
    "stale approval rejected": "tests/test_v2_continuity.py::test_approval_rejects_invented_stale_and_weak_evidence",
    "self-review rejected": "tests/test_v2_continuity.py::test_same_session_cannot_implement_and_approve_same_sha",
    "lifecycle event tampering detected": "tests/test_v4310_control_plane_adversarial.py::test_lifecycle_database_mutations_are_detectable",
    "lifecycle event deletion detected": "tests/test_v4310_control_plane_adversarial.py::test_lifecycle_database_mutations_are_detectable",
    "lifecycle event reordering detected": "tests/test_v4310_control_plane_adversarial.py::test_lifecycle_database_mutations_are_detectable",
    "lifecycle previous hash tampering detected": "tests/test_v4310_control_plane_adversarial.py::test_lifecycle_database_mutations_are_detectable",
    "lifecycle duplicate sequence rejected": "tests/test_v4310_control_plane_adversarial.py::test_lifecycle_duplicate_sequence_write_is_rejected_and_does_not_open_the_store",
    "lifecycle idempotency tampering detected": "tests/test_v4310_control_plane_adversarial.py::test_lifecycle_database_mutations_are_detectable",
    "lifecycle wrong case binding detected": "tests/test_v4310_control_plane_adversarial.py::test_lifecycle_database_mutations_are_detectable",
    "rollback lifecycle event tampering detected": "tests/test_v4310_control_plane_adversarial.py::test_lifecycle_database_mutations_are_detectable",
    "stale concurrent write rejected": "tests/test_v4310_control_plane_adversarial.py::test_stale_concurrent_writer_and_wrong_case_binding_are_rejected",
    "altered JSON export cannot become authority": "tests/test_v4310_control_plane_adversarial.py::test_lifecycle_export_mutation_cannot_be_reimported_as_authority",
    "subject mutation gate TOCTOU rejected": "tests/test_v4310_control_plane_adversarial.py::test_subject_mutation_after_gate_evaluation_rejects_stale_prepared_transition",
    "agent cannot create terminal lifecycle": "tests/test_v4310_control_plane_adversarial.py::test_lifecycle_store_rejects_agent_and_local_terminal_attempts",
    "local terminal path cannot bypass protected evidence": "tests/test_v4310_control_plane_adversarial.py::test_lifecycle_store_rejects_agent_and_local_terminal_attempts",
    "CLOSED bundle missing evidence rejected": "tests/test_v4310_fail_closed_adversarial.py::test_closed_code_fix_bundle_without_gate_replay_is_invalid",
    "CLOSED bundle wrong trust rejected": "tests/test_v4310_control_plane_adversarial.py::test_fraudulent_terminal_bundle_shapes_fail_independent_replay",
    "CLOSED field without transition ledger rejected": "tests/test_v4310_fail_closed_adversarial.py::test_closed_code_fix_bundle_without_gate_replay_is_invalid",
    "valid-looking evidence without historical gate rejected": "tests/test_v4310_control_plane_adversarial.py::test_fraudulent_terminal_bundle_shapes_fail_independent_replay",
    "replaced subject_epoch rejected": "tests/test_v4310_fail_closed_adversarial.py::test_resolved_no_code_bundle_replays_authoritative_lifecycle",
    "replayed CI evidence rejected": "tests/test_v4310_control_plane_adversarial.py::test_fraudulent_terminal_bundle_shapes_fail_independent_replay",
    "copied evidence from another task rejected": "tests/test_v4310_fail_closed_adversarial.py::test_resolved_no_code_bundle_replays_authoritative_lifecycle",
    "valid signature from wrong trust root rejected": "tests/test_v4310_fail_closed_adversarial.py::test_resolved_no_code_bundle_replays_authoritative_lifecycle",
    "E6 record from unauthorized controller class rejected": "tests/test_v4310_fail_closed_adversarial.py::test_resolved_no_code_bundle_replays_authoritative_lifecycle",
    "missing postdeploy proof rejected": "tests/test_v4310_control_plane_adversarial.py::test_deployment_success_cannot_close_bug_without_terminal_lifecycle",
    "rollback closure without recovery rejected": "tests/test_v4310_control_plane_adversarial.py::test_rollback_closure_requires_policy_domain_recovery_union",
    "PR SHA cannot be deployed as merged-main after squash": "tests/test_v4310_control_plane_adversarial.py::test_squash_merge_preserves_pr_a_to_main_c_provenance",
    "event ledger changed after evidence creation rejected": "tests/test_v4310_fail_closed_adversarial.py::test_resolved_no_code_bundle_replays_authoritative_lifecycle",
    "validated artifact cannot be rebuilt or retagged": "tests/test_v4310_control_plane_adversarial.py::test_artifact_promotion_rejects_rebuild_and_pr_only_or_mutable_identity",
    "legacy lifecycle projection cannot claim authority": "tests/test_v4310_control_plane_adversarial.py::test_legacy_subject_and_lifecycle_projections_cannot_claim_store_authority",
    "terminal verifier cannot fall back to duplicated policy": "tests/test_v4310_control_plane_adversarial.py::test_fraudulent_terminal_bundle_shapes_fail_independent_replay",
    "RESOLVED_NO_CODE own proof required": "tests/test_v4310_fail_closed_adversarial.py::test_resolved_no_code_bundle_replays_authoritative_lifecycle",
    "database rollback recovery proof": "tests/test_v4310_control_plane_adversarial.py::test_rollback_closure_requires_policy_domain_recovery_union",
    "financial rollback reconciliation": "tests/test_v4310_fail_closed_adversarial.py::test_financial_rollback_cannot_close_on_app_health_only",
    "ZATCA rollback reconciliation": "tests/test_v4310_control_plane_adversarial.py::test_rollback_closure_requires_policy_domain_recovery_union",
    "scheduler DONE cannot close bug": "tests/test_v439_fail_closed_protocol.py::test_authoritative_scheduler_task_cannot_transition_to_done",
    "deployment success cannot close bug": "tests/test_v4310_fail_closed_adversarial.py::test_closed_code_fix_bundle_without_gate_replay_is_invalid",
    "hotfix cannot skip staging": "tests/test_v4310_control_plane_adversarial.py::test_hotfix_cannot_skip_staging_or_domain_gates",
    "hotfix cannot skip domain gates": "tests/test_v4310_control_plane_adversarial.py::test_hotfix_cannot_skip_staging_or_domain_gates",
    "reported defect cannot bypass generic autopilot": "tests/test_v4310_fail_closed_adversarial.py::test_reported_defect_cannot_bypass_lifecycle_but_feature_can",
    "feature path remains valid": "tests/test_v4310_fail_closed_adversarial.py::test_reported_defect_cannot_bypass_lifecycle_but_feature_can",
    "unconsumed mandatory policy field fails wiring": "tests/test_v437_bundle_and_wiring.py::test_v437_bug_lifecycle_policy_is_declared_and_wired",
    "delivery model is source-derived": "tests/test_v4311_delivery_model.py::test_delivery_model_is_derived_from_source_markers",
    "runtime delivery cannot downgrade to package": "tests/test_v4311_delivery_model.py::test_runtime_source_cannot_be_downgraded_to_package_delivery",
    "package-only lifecycle rejects fictional staging": "tests/test_v4311_delivery_model.py::test_package_only_lifecycle_rejects_fictional_staging",
    "package evidence rejects runtime identity": "tests/test_v4311_delivery_model.py::test_package_release_metadata_rejects_runtime_identity",
    "package terminal rejects runtime claim": "tests/test_v4311_delivery_model.py::test_package_terminal_bundle_rejects_manually_added_runtime_claim",
    "hybrid requires both package and runtime paths": "tests/test_v4311_delivery_model.py::test_hybrid_requires_both_relevant_paths",
    "published asset digest must match lifecycle artifact": "tests/test_v4311_delivery_model.py::test_published_asset_digest_must_match_lifecycle_artifact",
    "published asset rebuild substitution rejected": "tests/test_v4311_delivery_model.py::test_published_asset_rebuild_substitution_is_rejected",
    "consumer validation binds packaged artifact": "tests/test_v4311_delivery_model.py::test_consumer_validation_must_use_the_packaged_artifact",
    "consumer source checkout leakage rejected": "tests/test_v4311_delivery_model.py::test_consumer_validation_rejects_source_checkout_leakage",
    "package release cannot claim runtime rollback": "tests/test_v4311_delivery_model.py::test_package_release_does_not_claim_runtime_rollback",
    "runtime delivery requires postdeploy proof": "tests/test_v4311_delivery_model.py::test_runtime_delivery_still_requires_postdeploy_evidence",
}


def test_every_required_adversarial_case_has_a_real_test_mapping() -> None:
    for requirement, reference in ADVERSARIAL_TRACEABILITY.items():
        path_text, function_name = reference.split("::", 1)
        path = ROOT / path_text
        assert path.is_file(), requirement
        source = path.read_text(encoding="utf-8")
        assert f"def {function_name}(" in source, requirement
