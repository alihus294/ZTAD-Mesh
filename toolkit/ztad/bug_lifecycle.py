from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Iterable

from .bug_protocol import (
    AUTHORITATIVE_LIFECYCLE,
    RISK_CLASS_ORDER,
    derive_risk_class,
    infer_domains,
    risk_class_for_level,
    validate_artifact_chain,
    validate_authoritative_sources,
    validate_authoritative_lifecycle_policy,
    validate_policy_safety,
    validate_blast_radius,
    validate_ci_metadata,
    validate_diff_forensics,
    validate_full_regression_metadata,
    validate_post_deploy_metadata,
    validate_synthetic_transaction_metadata,
    validate_observation_window_metadata,
    validate_production_release_metadata,
    validate_progressive_exposure,
    validate_red_green_evidence,
    validate_rollback_closure,
    validate_staging_metadata,
    validate_targeted_validation,
    validate_performance_evidence,
    validate_database_release_sequence,
    validate_test_integrity,
    PROTECTED_APPROVAL_PRODUCERS,
)
from .evidence import TRUST_ORDER, evaluate_required_evidence
from .diff_forensics import collect_git_diff_inventory
from .problem import NON_CODE_CLASSIFICATIONS, problem_case_fingerprint, semantic_errors
from .schema_validation import validate_instance
from .subject import (
    apply_subject_update,
    active_revision,
    material_subject_changes,
    subject_fingerprint,
    subject_from_record,
    validate_subject,
)
from .util import sha256_file
from .lifecycle_store import LifecycleStore

SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

PROBLEM_PHASES = {
    "UNVERIFIED_REPORT": 0,
    "SOURCE_OF_TRUTH_RESOLVED": 1,
    "ISSUE_CLASSIFIED": 2,
    "BUG_REPRODUCED": 3,
    "ROOT_CAUSE_PROVEN": 4,
    "BLAST_RADIUS_MAPPED": 5,
    "CHANGE_PLANNED": 6,
}
PROBLEM_CASE_EQUIVALENTS = {
    "UNVERIFIED_REPORT": 0,
    "SOURCE_OF_TRUTH_RESOLVED": 1,
    "ISSUE_CLASSIFIED": 2,
    "BUG_REPRODUCED": 3,
    "ROOT_CAUSE_PROVEN": 4,
    "BLAST_RADIUS_MAPPED": 5,
    "CHANGE_PLANNED": 6,
    "REGRESSION_BASELINE_PROVEN": 6,
    "HANDOFF_READY": 6,
}
POST_PRODUCTION_STATES = {"PRODUCTION_RELEASED", "POST_DEPLOY_VERIFIED", "ROLLBACK_REQUIRED"}


def _effective_problem_risk_class(
    problem_case: dict[str, Any],
    *,
    domains: Iterable[str],
    policy: dict[str, Any],
) -> str:
    """Use the policy-derived floor and never trust a lower model label."""

    derived = derive_risk_class(
        risk=problem_case.get("risk"),
        domains=domains,
        policy=policy,
    )
    declared = problem_case.get("risk_class")
    if declared is None:
        return derived
    declared_value = str(declared).upper()
    if declared_value not in RISK_CLASS_ORDER:
        raise ValueError("problem_case.risk_class is invalid")
    return max((derived, declared_value), key=RISK_CLASS_ORDER.__getitem__)


def initialize_bug_lifecycle(
    *,
    problem_case: dict[str, Any],
    policy: dict[str, Any],
    profile: str = "generic",
    mode: str = "NORMAL",
    remote_repository: str | None = None,
    domains: Iterable[str] = ("GENERAL",),
) -> dict[str, Any]:
    profiles = policy.get("profiles", {}) or {}
    if profile != "generic" and profile not in profiles:
        raise ValueError(f"Unknown bug protocol profile: {profile}")
    if mode not in {"NORMAL", "HOTFIX"}:
        raise ValueError("mode must be NORMAL or HOTFIX")
    canonical_chain = list(((profiles.get(profile) or {}).get("canonical_deployment_chain") or []))
    normalized_domains = infer_domains(problem_case, domains)
    risk = problem_case.get("risk")
    policy_errors = validate_policy_safety(policy)
    if policy_errors:
        raise ValueError("Unsafe authoritative bug policy: " + "; ".join(policy_errors))
    risk_class = _effective_problem_risk_class(
        problem_case,
        domains=normalized_domains,
        policy=policy,
    )
    return {
        "schema_version": 2,
        "protocol_version": str(policy.get("protocol")),
        "profile": profile,
        "mode": mode,
        "case_id": problem_case["case_id"],
        "state": "UNVERIFIED_REPORT",
        "last_completed_state": "UNVERIFIED_REPORT",
        "resume_state": None,
        "blocked_target": None,
        "blockers": [],
        "repository": problem_case["repository"],
        "remote_repository": remote_repository,
        "problem_case_fingerprint": problem_case_fingerprint(problem_case),
        "base_sha": problem_case.get("base_sha"),
        "protected_base_sha": problem_case.get("base_sha"),
        "head_sha": None,
        "pr_head_sha": None,
        "merged_main_sha": None,
        "reviewed_diff_hash": None,
        "merge_method": None,
        "merge_provenance": None,
        "post_merge_ci_run_id": None,
        "diff_hash": None,
        "artifact_digest": None,
        "risk": risk,
        "risk_class": risk_class,
        "domains": normalized_domains,
        "canonical_deployment_chain": canonical_chain,
        "change_contract_hash": None,
        "policy_bundle_hash": None,
        "toolchain_hash": None,
        "release_fingerprint": None,
        "sbom_digest": None,
        "provenance_digest": None,
        "attestation_digest": None,
        "production_release_id": None,
        "deployed_revision": None,
        "artifact_identity": None,
        "scheduler_state": None,
        "internal_execution_complete": False,
        "authoritative_lifecycle": False,
        "authority_store": None,
        "subject_epoch": 0,
        "subject_version": 1,
        "subject_fingerprint": subject_fingerprint({
            "repository": problem_case["repository"],
            "protected_base_sha": problem_case.get("base_sha"),
            "subject_epoch": 0,
            "subject_version": 1,
        }),
        "subject_mutations": [],
        "historical_evidence_refs": {},
        "risk_history": [{"risk": risk, "risk_class": risk_class, "reason": "initialization"}],
        "evidence_refs": {},
        "final_state": None,
        "closure_class": None,
    }


def initialize_authoritative_bug_lifecycle(
    *,
    store: LifecycleStore,
    problem_case: dict[str, Any],
    policy: dict[str, Any],
    profile: str = "generic",
    mode: str = "NORMAL",
    remote_repository: str | None = None,
    domains: Iterable[str] = ("GENERAL",),
    actor: str | None = None,
) -> dict[str, Any]:
    """Create the controller-owned lifecycle and return its verified snapshot."""

    record = initialize_bug_lifecycle(
        problem_case=problem_case,
        policy=policy,
        profile=profile,
        mode=mode,
        remote_repository=remote_repository,
        domains=domains,
    )
    store.initialize(record, actor=actor)
    return store.export(str(record["case_id"]))


def bind_candidate(
    record: dict[str, Any],
    *,
    contract_path: Path,
    head_sha: str,
    diff_hash: str,
    policy_bundle_hash: str,
    toolchain_hash: str,
    artifact_digest: str | None = None,
) -> dict[str, Any]:
    if not SHA_RE.fullmatch(head_sha):
        raise ValueError("head_sha must be an exact lowercase hexadecimal revision")
    for label, value in (
        ("diff_hash", diff_hash),
        ("policy_bundle_hash", policy_bundle_hash),
        ("toolchain_hash", toolchain_hash),
    ):
        if not DIGEST_RE.fullmatch(value):
            raise ValueError(f"{label} must be a sha256 digest")
    if artifact_digest is not None and not DIGEST_RE.fullmatch(artifact_digest):
        raise ValueError("artifact_digest must be a sha256 digest")
    updates = {
        "change_contract_hash": sha256_file(contract_path),
        "protected_base_sha": record.get("protected_base_sha") or record.get("base_sha"),
        "pr_head_sha": head_sha,
        "reviewed_diff_hash": diff_hash,
        "merged_main_sha": None,
        "merge_method": None,
        "merge_provenance": None,
        "post_merge_ci_run_id": None,
        "policy_bundle_hash": policy_bundle_hash,
        "toolchain_hash": toolchain_hash,
        "artifact_digest": artifact_digest,
        "release_fingerprint": None,
        "sbom_digest": None,
        "provenance_digest": None,
        "attestation_digest": None,
        "production_release_id": None,
        "deployed_revision": None,
        "artifact_identity": None,
    }
    result = apply_subject_update(record, updates, reason="candidate_subject_bound")
    result["base_sha"] = result.get("protected_base_sha")
    result["head_sha"] = result.get("pr_head_sha")
    result["diff_hash"] = result.get("reviewed_diff_hash")
    return _non_authoritative_projection(result)


def bind_artifact(record: dict[str, Any], artifact_digest: str) -> dict[str, Any]:
    if not DIGEST_RE.fullmatch(artifact_digest):
        raise ValueError("artifact_digest must be a sha256 digest")
    return _non_authoritative_projection(
        apply_subject_update(record, {"artifact_digest": artifact_digest}, reason="artifact_identity_bound")
    )


def bind_merge_subject(
    record: dict[str, Any],
    *,
    merged_main_sha: str,
    merge_method: str,
    merge_provenance: dict[str, Any],
    post_merge_ci_run_id: str | None = None,
) -> dict[str, Any]:
    """Bind the authorized PR-to-main transformation without equating SHAs."""

    if not SHA_RE.fullmatch(merged_main_sha):
        raise ValueError("merged_main_sha must be an exact lowercase hexadecimal revision")
    if merge_method not in {"MERGE", "SQUASH", "REBASE", "FAST_FORWARD"}:
        raise ValueError("Unsupported merge_method")
    if not isinstance(merge_provenance, dict):
        raise ValueError("merge_provenance must be an object")
    if not post_merge_ci_run_id or not str(post_merge_ci_run_id).strip():
        raise ValueError("post_merge_ci_run_id is required when binding merged-main subject")
    expected = {
        "pr_head_sha": record.get("pr_head_sha") or record.get("head_sha"),
        "reviewed_diff_hash": record.get("reviewed_diff_hash") or record.get("diff_hash"),
        "merged_main_sha": merged_main_sha,
    }
    for field, value in expected.items():
        if not value or merge_provenance.get(field) != value:
            raise ValueError(f"merge_provenance.{field} must prove the exact reviewed-to-main transformation")
    if not merge_provenance.get("transformation"):
        raise ValueError("merge_provenance.transformation is required")
    result = apply_subject_update(
        record,
        {
            "merged_main_sha": merged_main_sha,
            "merge_method": merge_method,
            "merge_provenance": merge_provenance,
            "post_merge_ci_run_id": post_merge_ci_run_id,
            # A candidate artifact is not the artifact built from the exact
            # merged-main subject.  Force a new post-merge build chain.
            "artifact_digest": None,
            "release_fingerprint": None,
            "sbom_digest": None,
            "provenance_digest": None,
            "attestation_digest": None,
            "artifact_identity": None,
            "production_release_id": None,
            "deployed_revision": None,
        },
        reason="pr_to_merged_main_subject_bound",
    )
    result["head_sha"] = merged_main_sha
    result["merged_main_sha"] = merged_main_sha
    return _non_authoritative_projection(result)


def bind_release_subject(
    record: dict[str, Any],
    *,
    release_fingerprint: str,
    sbom_digest: str,
    provenance_digest: str,
    attestation_digest: str,
    artifact_identity: str,
) -> dict[str, Any]:
    values = {
        "release_fingerprint": release_fingerprint,
        "sbom_digest": sbom_digest,
        "provenance_digest": provenance_digest,
        "attestation_digest": attestation_digest,
    }
    for label, value in values.items():
        if not DIGEST_RE.fullmatch(value):
            raise ValueError(f"{label} must be a sha256 digest")
    if not artifact_identity.strip():
        raise ValueError("artifact_identity is required")
    result = apply_subject_update(
        record,
        values | {"artifact_identity": artifact_identity},
        reason="release_subject_bound",
    )
    return _non_authoritative_projection(result)


def bind_production_subject(
    record: dict[str, Any],
    *,
    production_release_id: str,
    deployed_revision: str,
) -> dict[str, Any]:
    if not production_release_id.strip():
        raise ValueError("production_release_id is required")
    if not SHA_RE.fullmatch(deployed_revision):
        raise ValueError("deployed_revision must be an exact lowercase hexadecimal revision")
    return _non_authoritative_projection(
        apply_subject_update(
            record,
            {"production_release_id": production_release_id, "deployed_revision": deployed_revision},
            reason="production_revision_bound",
        )
    )


def invalidate_evidence_for_subject_change(
    evidence_records: Iterable[dict[str, Any]],
    *,
    old_subject: dict[str, Any],
    new_subject: dict[str, Any],
) -> list[dict[str, Any]]:
    """Mark subject-bound evidence stale instead of allowing silent reuse."""

    if old_subject == new_subject:
        return copy.deepcopy(list(evidence_records))
    changed = sorted(material_subject_changes(old_subject, new_subject))
    result: list[dict[str, Any]] = []
    for record in evidence_records:
        item = copy.deepcopy(record)
        invalidated = list(item.get("invalidated_by") or [])
        marker = "subject_changed"
        if marker not in invalidated:
            invalidated.append(marker)
        item["invalidated_subject_fields"] = changed
        item["invalidated_subject_epoch"] = int(new_subject.get("subject_epoch") or 0)
        item["invalidated_by"] = sorted(set(invalidated))
        result.append(item)
    return result


def _non_authoritative_projection(record: dict[str, Any]) -> dict[str, Any]:
    """Mark compatibility projections as non-authoritative lifecycle views."""

    record["authoritative_lifecycle"] = False
    record["authority_store"] = None
    for field in ("store_version", "store_record_hash", "store_binding"):
        record.pop(field, None)
    return record


def _logical_current(record: dict[str, Any]) -> str:
    if record.get("state") == "BLOCKED":
        return str(record.get("resume_state") or record.get("last_completed_state"))
    return str(record.get("state"))


def _subject(record: dict[str, Any]) -> dict[str, str] | None:
    subject = subject_from_record(record)
    required = (
        "repository",
        "protected_base_sha",
        "pr_head_sha",
        "reviewed_diff_hash",
        "change_contract_hash",
        "policy_bundle_hash",
        "toolchain_hash",
    )
    if any(not subject.get(key) for key in required):
        return None
    errors = validate_subject(subject, require_merge_provenance=bool(subject.get("merged_main_sha"))).errors
    if errors:
        return None
    return {key: value for key, value in subject.items() if value is not None}


def _problem_phase_errors(
    record: dict[str, Any],
    target_state: str,
    problem_case: dict[str, Any] | None,
    *,
    policy: dict[str, Any],
) -> list[str]:
    if target_state not in PROBLEM_PHASES:
        return []
    if problem_case is None:
        return ["problem_case is required for investigation lifecycle transitions"]
    errors: list[str] = []
    if problem_case.get("case_id") != record.get("case_id"):
        errors.append("problem case ID mismatch")
    if problem_case.get("repository") != record.get("repository"):
        errors.append("problem case repository mismatch")
    if record.get("base_sha") and problem_case.get("base_sha") != record.get("base_sha"):
        errors.append("problem case protected base SHA mismatch")
    actual_rank = PROBLEM_CASE_EQUIVALENTS.get(str(problem_case.get("state") or ""), -1)
    target_rank = PROBLEM_PHASES[target_state]
    if actual_rank < target_rank:
        errors.append(
            f"problem case state {problem_case.get('state')!r} does not prove required lifecycle state {target_state}"
        )
    candidate = copy.deepcopy(problem_case)
    candidate["state"] = target_state
    errors.extend(semantic_errors(candidate, target_state=target_state, policy=policy))
    return sorted(set(errors))


def _gate_requirements(policy: dict[str, Any], target_state: str, record: dict[str, Any]) -> tuple[str, list[str]]:
    gate = ((policy.get("gates") or {}).get(target_state) or {})
    minimum = str(gate.get("minimum_trust", "E2"))
    required = set(gate.get("required_evidence", []) or [])
    risk = str(record.get("risk") or "")
    risk_class = str(record.get("risk_class") or risk_class_for_level(risk) or "LOW")
    for risk_key in {risk, risk_class}:
        risk_gate = ((gate.get("by_risk") or {}).get(risk_key)) or []
        if isinstance(risk_gate, dict):
            minimum = max((minimum, str(risk_gate.get("minimum_trust", minimum))), key=lambda value: TRUST_ORDER.get(value, -1))
            required.update(risk_gate.get("required_evidence", []) or [])
            required.update(risk_gate.get("required", []) or [])
        else:
            required.update(risk_gate)
    by_domain = gate.get("by_domain") or {}
    for domain in record.get("domains") or []:
        required.update((by_domain.get(domain) or []))
        profile = ((policy.get("domain_profiles") or {}).get(domain) or {})
        if target_state in {
            "TARGETED_VALIDATION_PASS",
            "REGRESSION_VALIDATION_PASS",
            "STAGING_PASS",
            "READY_FOR_OWNER_RELEASE",
            "PRODUCTION_RELEASED",
            "POST_DEPLOY_VERIFIED",
        }:
            required.update(profile.get("required_checks", []) or [])
        domain_minimum = str(profile.get("minimum_trust", ""))
        if domain_minimum and TRUST_ORDER.get(domain_minimum, -1) > TRUST_ORDER.get(minimum, -1):
            minimum = domain_minimum
    hotfix = policy.get("hotfix") or {}
    if record.get("mode") == "HOTFIX" and hotfix.get("may_reduce_validation_breadth") is False:
        for domain in record.get("domains") or []:
            required.update((((policy.get("domain_profiles") or {}).get(domain) or {}).get("required_checks") or []))
    if record.get("merged_main_sha") and target_state in {
        "STAGING_PASS",
        "READY_FOR_OWNER_RELEASE",
        "PRODUCTION_RELEASED",
        "POST_DEPLOY_VERIFIED",
        "CLOSED",
    }:
        required.add("POST_MERGE_CI_PROVEN")
    progressive = (policy.get("progressive_exposure") or {})
    if target_state == "READY_FOR_OWNER_RELEASE" and risk_class in {"HIGH", "CRITICAL"}:
        configured = progressive.get(risk_class) or []
        if isinstance(configured, dict):
            required.update(configured.get("required_evidence", []) or [])
        else:
            required.update(configured)
    return minimum, sorted(required)


def _red_green_errors(record: dict[str, Any], evidence_records: list[dict[str, Any]]) -> list[str]:
    records = [item for item in evidence_records if item.get("type") == "REGRESSION_RED_GREEN_PROVEN"]
    if not records:
        return []
    errors: list[str] = []
    for item in records:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        errors.extend(
            validate_red_green_evidence(
                metadata,
                bad_base_sha=record.get("base_sha"),
                candidate_head_sha=record.get("head_sha"),
            )
        )
        errors.extend(validate_test_integrity(metadata))
    return sorted(set(errors))


def _independent_review_errors(evidence_records: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for item in evidence_records:
        if item.get("type") != "INDEPENDENT_REVIEW_COMPLETED":
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        implementation_session = metadata.get("implementation_session_id")
        review_session = metadata.get("review_session_id")
        if not implementation_session or not review_session:
            errors.append("Independent review evidence must identify implementation and review sessions")
        elif implementation_session == review_session:
            errors.append("Independent review cannot use the implementation reasoning session")
        if metadata.get("verdict") != "PASS":
            errors.append("Independent review verdict must be PASS")
    return sorted(set(errors))


def _protected_approval_errors(
    evidence_records: list[dict[str, Any]],
    valid_evidence_ids: Iterable[str],
    *,
    evidence_type: str,
    label: str,
) -> list[str]:
    valid_ids = set(valid_evidence_ids)
    records = [
        item
        for item in evidence_records
        if item.get("type") == evidence_type and item.get("evidence_id") in valid_ids
    ]
    if not records:
        return []
    errors: list[str] = []
    for item in records:
        if item.get("trust_level") != "E6":
            errors.append(f"{label} must be E6 protected-controller evidence")
        producer = str(item.get("producer", ""))
        if producer not in PROTECTED_APPROVAL_PRODUCERS:
            errors.append(f"{label} must be produced by a protected platform/controller")
        if str(item.get("status", "")).upper() != "APPROVED":
            errors.append(f"{label} must be explicitly APPROVED")
    return sorted(set(errors))


def _profile_errors(record: dict[str, Any], policy: dict[str, Any], target_state: str) -> list[str]:
    if record.get("profile") == "generic":
        return []
    profile = ((policy.get("profiles") or {}).get(record.get("profile")) or {})
    expected = list(profile.get("canonical_deployment_chain") or [])
    if target_state in {
        "SOURCE_OF_TRUTH_RESOLVED",
        "READY_FOR_OWNER_RELEASE",
        "PRODUCTION_RELEASED",
        "POST_DEPLOY_VERIFIED",
        "CLOSED",
    } and record.get("canonical_deployment_chain") != expected:
        return ["Canonical deployment chain differs from the active repository protocol profile"]
    return []


def _metadata_records(evidence_records: Iterable[dict[str, Any]], evidence_type: str) -> list[dict[str, Any]]:
    return [
        item for item in evidence_records
        if item.get("type") == evidence_type
    ]


def _collect_authoritative_git_inventory(
    record: dict[str, Any],
    repository_root: Path | str | None,
) -> dict[str, Any] | None:
    """Collect the diff inventory from Git at the controller boundary.

    The evidence metadata is a claim.  The lifecycle evaluator receives the
    repository root from the invoking controller and independently derives
    the inventory for the exact protected base and candidate revisions.
    """

    if repository_root is None:
        return None
    base_sha = record.get("protected_base_sha") or record.get("base_sha")
    candidate_sha = record.get("head_sha") or record.get("pr_head_sha")
    if not base_sha or not candidate_sha:
        return None
    try:
        return collect_git_diff_inventory(
            repository_root,
            base_sha=str(base_sha),
            candidate_sha=str(candidate_sha),
        )
    except Exception:
        # The caller receives the fail-closed missing/invalid inventory result;
        # Git and path errors must never be converted into a passing gate.
        return None


def _protocol_gate_errors(
    record: dict[str, Any],
    target_state: str,
    evidence_records: list[dict[str, Any]],
    *,
    policy: dict[str, Any],
    problem_case: dict[str, Any] | None,
    actual_git_inventory: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    if target_state == "REGRESSION_TEST_PROVEN":
        errors.extend(_red_green_errors(record, evidence_records))
        for item in _metadata_records(evidence_records, "REGRESSION_RED_GREEN_PROVEN"):
            errors.extend(validate_performance_evidence(item.get("metadata"))) if str(record.get("classification")) == "PERFORMANCE_REGRESSION" else None
    elif target_state == "TARGETED_VALIDATION_PASS":
        for item in _metadata_records(evidence_records, "TARGETED_VALIDATION_PASSED"):
            errors.extend(validate_targeted_validation(item.get("metadata"), risk_class=record.get("risk_class"), domains=record.get("domains") or []))
    elif target_state == "BLAST_RADIUS_MAPPED" and problem_case is not None:
        errors.extend(validate_blast_radius(problem_case.get("blast_radius"), domains=record.get("domains") or []))
    elif target_state == "CHANGE_PLANNED" and problem_case is not None:
        errors.extend(validate_database_release_sequence((problem_case.get("change_plan") or {}).get("database_release_sequence")))
    elif target_state == "DIFF_FORENSICS_PASS":
        if actual_git_inventory is None:
            errors.append("DIFF_FORENSICS_PASS requires an independently collected Git inventory")
        for item in _metadata_records(evidence_records, "DIFF_FORENSICS_PASSED"):
            errors.extend(
                validate_diff_forensics(
                    item.get("metadata"),
                    planned_files=((problem_case or {}).get("change_plan") or {}).get("expected_files") or [],
                    expected_diff_hash=record.get("diff_hash") or record.get("reviewed_diff_hash"),
                    expected_base_sha=record.get("protected_base_sha") or record.get("base_sha"),
                    expected_candidate_sha=record.get("head_sha") or record.get("pr_head_sha"),
                    actual_git_inventory=actual_git_inventory,
                )
            )
            errors.extend(validate_test_integrity(item.get("metadata")))
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            actual_risk = str(metadata.get("actual_risk") or "").upper()
            current_risk = str(record.get("risk") or "R0").upper()
            risk_order = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}
            if actual_risk in risk_order and current_risk in risk_order and risk_order[actual_risk] > risk_order[current_risk]:
                errors.append("DIFF_FORENSICS_PASS discovered a higher actual risk; lifecycle reclassification is required")
            actual_domains = {str(value).upper() for value in metadata.get("actual_domains") or []}
            current_domains = {str(value).upper() for value in record.get("domains") or []}
            if actual_domains - current_domains:
                errors.append(
                    "DIFF_FORENSICS_PASS discovered domains absent from the lifecycle subject: "
                    + ", ".join(sorted(actual_domains - current_domains))
                )
    elif target_state == "REGRESSION_VALIDATION_PASS":
        for item in _metadata_records(evidence_records, "FULL_REGRESSION_VALIDATION_PASSED"):
            errors.extend(
                validate_full_regression_metadata(
                    item.get("metadata"),
                    base_sha=record.get("base_sha"),
                    candidate_head_sha=record.get("head_sha"),
                )
            )
            errors.extend(validate_test_integrity(item.get("metadata")))
    elif target_state == "CI_PASS":
        for evidence_type in ("PROTECTED_CI", "REQUIRED_CHECKS_VERIFIED", "POST_MERGE_CI_PROVEN"):
            for item in _metadata_records(evidence_records, evidence_type):
                errors.extend(
                    validate_ci_metadata(
                        item.get("metadata"),
                        head_sha=record.get("head_sha"),
                        diff_hash=record.get("diff_hash"),
                        pr_head_sha=record.get("pr_head_sha"),
                        merged_main_sha=record.get("merged_main_sha"),
                        require_post_merge=bool(record.get("merged_main_sha")),
                    )
                )
    elif target_state == "STAGING_PASS":
        if record.get("merged_main_sha"):
            for item in _metadata_records(evidence_records, "POST_MERGE_CI_PROVEN"):
                errors.extend(
                    validate_ci_metadata(
                        item.get("metadata"),
                        head_sha=record.get("head_sha"),
                        diff_hash=record.get("diff_hash"),
                        pr_head_sha=record.get("pr_head_sha"),
                        merged_main_sha=record.get("merged_main_sha"),
                        require_post_merge=True,
                    )
                )
        for evidence_type in ("STAGING_SMOKE_PASSED", "ORIGINAL_PROBLEM_STAGING_VERIFIED"):
            for item in _metadata_records(evidence_records, evidence_type):
                errors.extend(
                    validate_staging_metadata(
                        item.get("metadata"),
                        head_sha=record.get("head_sha"),
                        artifact_digest=record.get("artifact_digest"),
                    )
                )
    elif target_state == "READY_FOR_OWNER_RELEASE":
        for evidence_type in (
            "RELEASE_FINGERPRINT_VERIFIED",
            "SIGNED_RELEASE_MANIFEST",
            "SBOM_VERIFIED",
            "ARTIFACT_ATTESTATION_VERIFIED",
            "BUILD_PROVENANCE_VERIFIED",
        ):
            for item in _metadata_records(evidence_records, evidence_type):
                errors.extend(
                    validate_artifact_chain(
                        item.get("metadata"),
                        head_sha=record.get("head_sha"),
                        artifact_digest=record.get("artifact_digest"),
                        merged_main_sha=record.get("merged_main_sha"),
                    )
                )
        if str(record.get("risk_class") or "") in {"HIGH", "CRITICAL"}:
            for item in _metadata_records(evidence_records, "PROGRESSIVE_EXPOSURE_PLAN"):
                errors.extend(validate_progressive_exposure(item.get("metadata"), risk_class=record.get("risk_class")))
    elif target_state == "PRODUCTION_RELEASED":
        for evidence_type in (
            "PROTECTED_RELEASE_AUTHORIZATION",
            "PRODUCTION_RELEASE_COMPLETED",
            "EXPECTED_DIGEST_RUNNING",
        ):
            for item in _metadata_records(evidence_records, evidence_type):
                if evidence_type == "PROTECTED_RELEASE_AUTHORIZATION":
                    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
                    if metadata.get("subject_epoch") is not None and metadata.get("subject_epoch") != record.get("subject_epoch"):
                        errors.append("Production authorization subject epoch is stale")
                    continue
                errors.extend(
                    validate_production_release_metadata(
                        item.get("metadata"),
                        head_sha=record.get("head_sha"),
                        artifact_digest=record.get("artifact_digest"),
                        merged_main_sha=record.get("merged_main_sha"),
                        pr_head_sha=record.get("pr_head_sha"),
                    )
                )
    elif target_state == "POST_DEPLOY_VERIFIED":
        for item in _metadata_records(evidence_records, "ORIGINAL_PROBLEM_PRODUCTION_VERIFIED"):
            errors.extend(validate_post_deploy_metadata(item.get("metadata"), artifact_digest=record.get("artifact_digest"), deployed_revision=record.get("deployed_revision")))
        for item in _metadata_records(evidence_records, "PRODUCTION_HEALTH"):
            errors.extend(validate_post_deploy_metadata(item.get("metadata"), artifact_digest=record.get("artifact_digest"), deployed_revision=record.get("deployed_revision")))
        for item in _metadata_records(evidence_records, "SYNTHETIC_TRANSACTION"):
            errors.extend(validate_synthetic_transaction_metadata(item.get("metadata")))
        for item in _metadata_records(evidence_records, "OBSERVATION_WINDOW"):
            errors.extend(validate_observation_window_metadata(item.get("metadata")))
    elif target_state == "CLOSED" and _logical_current(record) == "POST_DEPLOY_VERIFIED":
        for item in _metadata_records(evidence_records, "ORIGINAL_PROBLEM_PRODUCTION_VERIFIED"):
            errors.extend(validate_post_deploy_metadata(item.get("metadata"), artifact_digest=record.get("artifact_digest"), deployed_revision=record.get("deployed_revision")))
        for item in _metadata_records(evidence_records, "PRODUCTION_HEALTH"):
            errors.extend(validate_post_deploy_metadata(item.get("metadata"), artifact_digest=record.get("artifact_digest"), deployed_revision=record.get("deployed_revision")))
        for item in _metadata_records(evidence_records, "SYNTHETIC_TRANSACTION"):
            errors.extend(validate_synthetic_transaction_metadata(item.get("metadata")))
        for item in _metadata_records(evidence_records, "OBSERVATION_WINDOW"):
            errors.extend(validate_observation_window_metadata(item.get("metadata")))
    elif target_state == "ROLLBACK_REQUIRED":
        for item in _metadata_records(evidence_records, "ROLLBACK_COMPLETED"):
            errors.extend(validate_rollback_closure(item.get("metadata"), domains=record.get("domains") or [], policy=policy))
    elif target_state == "CLOSED" and _logical_current(record) == "ROLLBACK_REQUIRED":
        for item in _metadata_records(evidence_records, "ROLLBACK_COMPLETED"):
            errors.extend(validate_rollback_closure(item.get("metadata"), domains=record.get("domains") or [], policy=policy))
    if target_state in {"SOURCE_OF_TRUTH_RESOLVED", "ISSUE_CLASSIFIED", "BUG_REPRODUCED", "ROOT_CAUSE_PROVEN", "CHANGE_PLANNED"} and problem_case is not None:
        if target_state == "SOURCE_OF_TRUTH_RESOLVED":
            profile = ((policy.get("profiles") or {}).get(record.get("profile")) or {})
            errors.extend(
                validate_authoritative_sources(
                    problem_case.get("authoritative_sources") or [],
                    problem_case.get("source_conflicts") or [],
                    required_hierarchy=profile.get("deployment_source_hierarchy") or [],
                    authority_order=policy.get("authority_order") or [],
                )
            )
    return sorted(set(errors))


def evaluate_bug_transition(
    record: dict[str, Any],
    target_state: str,
    *,
    policy: dict[str, Any],
    lifecycle_schema: dict[str, Any],
    problem_case: dict[str, Any] | None = None,
    evidence_records: Iterable[dict[str, Any]] = (),
    evidence_schema: dict[str, Any] | None = None,
    trust_roots: dict[str, Any] | None = None,
    repository_root: Path | str | None = None,
) -> dict[str, Any]:
    policy_errors = validate_authoritative_lifecycle_policy(policy)
    if policy_errors:
        return {
            "allowed": False,
            "decision": "BLOCKED",
            "target_state": target_state,
            "reasons": policy_errors,
        }
    schema_errors = validate_instance(record, lifecycle_schema)
    if schema_errors:
        return {"allowed": False, "decision": "BLOCKED", "target_state": target_state, "reasons": schema_errors}

    states = set(policy.get("states", []) or [])
    if target_state not in states:
        return {
            "allowed": False,
            "decision": "BLOCKED",
            "target_state": target_state,
            "reasons": [f"Unknown bug lifecycle state: {target_state}"],
        }

    current = str(record.get("state"))
    logical_current = _logical_current(record)
    allowed_next = set(((policy.get("transitions") or {}).get(current) or []))
    if current == "BLOCKED":
        allowed_next = set(((policy.get("transitions") or {}).get(logical_current) or []))
    reasons: list[str] = []
    reasons.extend(validate_policy_safety(policy))
    if target_state not in allowed_next:
        reasons.append(f"Transition {current} -> {target_state} is not allowed")

    previous_class = str(record.get("risk_class") or risk_class_for_level(record.get("risk")) or "LOW")
    requested_class = previous_class
    if problem_case is not None:
        requested_class = _effective_problem_risk_class(
            problem_case,
            domains=record.get("domains") or [],
            policy=policy,
        )
    if RISK_CLASS_ORDER.get(requested_class, -1) < RISK_CLASS_ORDER.get(previous_class, -1):
        reasons.append("Effective risk downgrade is prohibited")
    for snapshot in record.get("risk_history") or []:
        if isinstance(snapshot, dict) and RISK_CLASS_ORDER.get(str(snapshot.get("risk_class")), -1) > RISK_CLASS_ORDER.get(requested_class, -1):
            reasons.append("Risk history is monotonic and cannot be lowered")

    reasons.extend(_profile_errors(record, policy, target_state))
    reasons.extend(_problem_phase_errors(record, target_state, problem_case, policy=policy))

    records = list(evidence_records)
    actual_git_inventory = (
        _collect_authoritative_git_inventory(record, repository_root)
        if target_state == "DIFF_FORENSICS_PASS"
        else None
    )
    reasons.extend(
        _protocol_gate_errors(
            record,
            target_state,
            records,
            policy=policy,
            problem_case=problem_case,
            actual_git_inventory=actual_git_inventory,
        )
    )
    minimum, required = _gate_requirements(policy, target_state, record)
    valid_evidence: dict[str, list[str]] = {}
    invalid_evidence: dict[str, list[str]] = {}
    missing: list[str] = []
    if required:
        subject = _subject(record)
        if subject is None:
            reasons.append("Exact candidate evidence subject is incomplete")
        elif evidence_schema is None:
            reasons.append("evidence_schema is required for evidence-bearing transitions")
        else:
            evaluated = evaluate_required_evidence(
                records,
                required,
                subject=subject,
                schema=evidence_schema,
                minimum_trust=minimum,
                trust_roots=trust_roots,
                require_authoritative_signature=TRUST_ORDER[minimum] >= TRUST_ORDER["E3"],
            )
            valid_evidence = evaluated["valid_evidence"]
            invalid_evidence = evaluated["invalid_evidence"]
            missing = evaluated["missing_types"]
            if missing:
                reasons.append("Missing evidence: " + ", ".join(missing))
            if evaluated["duplicate_evidence_ids"]:
                reasons.append("Duplicate evidence IDs are prohibited")
            if evaluated.get("duplicate_receipt_ids"):
                reasons.append("Duplicate machine receipt IDs are prohibited")
            if target_state == "REGRESSION_TEST_PROVEN" and not missing:
                reasons.extend(_red_green_errors(record, records))
            if target_state == "INDEPENDENT_REVIEW_PASS" and not missing:
                reasons.extend(_independent_review_errors(records))
            if target_state == "READY_FOR_OWNER_RELEASE" and not missing:
                reasons.extend(
                    _protected_approval_errors(
                        records,
                        valid_evidence.get("PROTECTED_SUPERVISOR_APPROVAL", []),
                        evidence_type="PROTECTED_SUPERVISOR_APPROVAL",
                        label="Protected supervisor approval",
                    )
                )
            if target_state == "PRODUCTION_RELEASED" and not missing:
                reasons.extend(
                    _protected_approval_errors(
                        records,
                        valid_evidence.get("PROTECTED_RELEASE_AUTHORIZATION", []),
                        evidence_type="PROTECTED_RELEASE_AUTHORIZATION",
                        label="Production release authorization",
                    )
                )

    if target_state in {
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
    } and (not record.get("head_sha") or not record.get("diff_hash") or not record.get("change_contract_hash")):
        reasons.append("Exact candidate SHA, diff hash, and Change Contract hash are required")

    if target_state in {"STAGING_PASS", "READY_FOR_OWNER_RELEASE", "PRODUCTION_RELEASED", "POST_DEPLOY_VERIFIED", "CLOSED"}:
        if not record.get("artifact_digest"):
            reasons.append("Exact tested artifact digest is required")

    if target_state == "RESOLVED_NO_CODE":
        if problem_case is None or problem_case.get("classification") not in NON_CODE_CLASSIFICATIONS:
            reasons.append("RESOLVED_NO_CODE requires a proven non-code classification")

    if target_state == "CLOSED":
        if current == "ROLLBACK_REQUIRED":
            minimum, rollback_required = _gate_requirements(policy, "ROLLBACK_CLOSURE", record)
            subject = _subject(record)
            if subject is None or evidence_schema is None:
                reasons.append("Rollback closure requires an exact evidence subject")
            else:
                rollback_eval = evaluate_required_evidence(
                    records,
                    rollback_required,
                    subject=subject,
                    schema=evidence_schema,
                    minimum_trust=minimum,
                    trust_roots=trust_roots,
                    require_authoritative_signature=True,
                )
                if rollback_eval["missing_types"]:
                    reasons.append("Rollback closure missing evidence: " + ", ".join(rollback_eval["missing_types"]))
        elif logical_current != "POST_DEPLOY_VERIFIED":
            reasons.append("A bug cannot close before POST_DEPLOY_VERIFIED")

    production_exposed = logical_current in POST_PRODUCTION_STATES
    decision = "PROCEED" if not reasons else ("ROLLBACK_REQUIRED" if production_exposed else "BLOCKED")
    return {
        "allowed": not reasons,
        "decision": decision,
        "current_state": current,
        "logical_current_state": logical_current,
        "target_state": target_state,
        "reasons": sorted(set(reasons)),
        "required_evidence": required,
        "missing_evidence_types": missing,
        "valid_evidence": valid_evidence,
        "invalid_evidence": invalid_evidence,
        "claim_boundary": (
            "Internal scheduler DONE, model prose, local files, or deployment-command success cannot close "
            "a bug lifecycle. Only POST_DEPLOY_VERIFIED followed by CLOSED can close a code-fix case."
        ),
    }


def advance_bug_lifecycle(
    record: dict[str, Any],
    target_state: str,
    *,
    policy: dict[str, Any],
    lifecycle_schema: dict[str, Any],
    problem_case: dict[str, Any] | None = None,
    evidence_records: Iterable[dict[str, Any]] = (),
    evidence_schema: dict[str, Any] | None = None,
    trust_roots: dict[str, Any] | None = None,
    repository_root: Path | str | None = None,
) -> dict[str, Any]:
    decision = evaluate_bug_transition(
        record,
        target_state,
        policy=policy,
        lifecycle_schema=lifecycle_schema,
        problem_case=problem_case,
        evidence_records=evidence_records,
        evidence_schema=evidence_schema,
        trust_roots=trust_roots,
        repository_root=repository_root,
    )
    result = copy.deepcopy(record)
    if not decision["allowed"]:
        prior = _logical_current(record)
        result["state"] = decision["decision"]
        result["resume_state"] = prior
        result["blocked_target"] = target_state
        result["blockers"] = decision["reasons"]
        result["final_state"] = None
        return _non_authoritative_projection(result)

    result["state"] = target_state
    result["last_completed_state"] = target_state
    result["resume_state"] = None
    result["blocked_target"] = None
    result["blockers"] = []
    if problem_case is not None:
        result["problem_case_fingerprint"] = problem_case_fingerprint(problem_case)
        if problem_case.get("risk") is not None:
            current_class = str(result.get("risk_class") or risk_class_for_level(result.get("risk")) or "LOW")
            candidate_class = _effective_problem_risk_class(
                problem_case,
                domains=result.get("domains") or [],
                policy=policy,
            )
            if RISK_CLASS_ORDER.get(candidate_class, -1) >= RISK_CLASS_ORDER.get(current_class, -1):
                result["risk"] = problem_case.get("risk")
                result["risk_class"] = candidate_class
    history = list(result.get("risk_history") or [])
    history.append({"risk": result.get("risk"), "risk_class": result.get("risk_class"), "state": target_state})
    result["risk_history"] = history
    if decision.get("valid_evidence"):
        evidence_refs = copy.deepcopy(result.get("evidence_refs") or {})
        for evidence_type, refs in decision["valid_evidence"].items():
            current_refs = list(evidence_refs.get(evidence_type) or [])
            evidence_refs[evidence_type] = sorted(set(current_refs + list(refs)))
        result["evidence_refs"] = evidence_refs
    if target_state == "CLOSED":
        result["final_state"] = "CLOSED"
        result["closure_class"] = "ROLLBACK_CLOSURE" if current == "ROLLBACK_REQUIRED" else "CODE_FIX"
    elif target_state == "RESOLVED_NO_CODE":
        result["final_state"] = "RESOLVED_NO_CODE"
        result["closure_class"] = "RESOLVED_NO_CODE"
    else:
        result["final_state"] = None
        result["closure_class"] = None
    return _non_authoritative_projection(result)


def commit_bug_lifecycle_transition(
    store: LifecycleStore,
    record: dict[str, Any],
    target_state: str,
    *,
    expected_version: int,
    actor: str | None = None,
    policy: dict[str, Any],
    lifecycle_schema: dict[str, Any],
    problem_case: dict[str, Any] | None = None,
    evidence_records: Iterable[dict[str, Any]] = (),
    evidence_schema: dict[str, Any] | None = None,
    trust_roots: dict[str, Any] | None = None,
    transition_authorization: dict[str, Any] | None = None,
    repository_root: Path | str | None = None,
) -> dict[str, Any]:
    """Evaluate and atomically commit a transition to the durable authority."""

    authoritative = store.get(str(record.get("case_id")), verify=True)
    if (
        int(expected_version) != int(authoritative.get("store_version", 0))
        or record.get("store_record_hash") != authoritative.get("store_record_hash")
    ):
        raise RuntimeError("Caller lifecycle snapshot is stale or has been modified")

    evidence_records = list(evidence_records)

    decision = evaluate_bug_transition(
        record,
        target_state,
        policy=policy,
        lifecycle_schema=lifecycle_schema,
        problem_case=problem_case,
        evidence_records=evidence_records,
        evidence_schema=evidence_schema,
        trust_roots=trust_roots,
        repository_root=repository_root,
    )
    updated = advance_bug_lifecycle(
        record,
        target_state,
        policy=policy,
        lifecycle_schema=lifecycle_schema,
        problem_case=problem_case,
        evidence_records=evidence_records,
        evidence_schema=evidence_schema,
        trust_roots=trust_roots,
        repository_root=repository_root,
    )
    event_decision = (
        "ROLLBACK_REQUIRED"
        if target_state == "ROLLBACK_REQUIRED"
        else "PROCEED" if decision.get("allowed") else decision.get("decision", "BLOCKED")
    )
    event = store.transition(
        str(record["case_id"]),
        updated,
        actor=actor,
        expected_version=expected_version,
        requested_state=target_state,
        decision=event_decision,
        required_evidence=decision.get("required_evidence", []),
        accepted_evidence=[ref for refs in (decision.get("valid_evidence") or {}).values() for ref in refs],
        accepted_evidence_records=[
            item
            for item in evidence_records
            if str(item.get("evidence_id") or "") in {
                str(ref)
                for refs in (decision.get("valid_evidence") or {}).values()
                for ref in refs
            }
        ],
        rejected_evidence=list((decision.get("invalid_evidence") or {}).keys()),
        policy_hash=record.get("policy_bundle_hash"),
        toolchain_hash=record.get("toolchain_hash"),
        risk_snapshot={"risk": updated.get("risk"), "risk_class": updated.get("risk_class")},
        domain_snapshot={"domains": updated.get("domains", [])},
        transition_authorization=transition_authorization,
    )
    return event | {"decision": decision}
