from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Iterable

from .bug_protocol import (
    AUTHORITATIVE_LIFECYCLE,
    derive_risk_class,
    infer_domains,
    risk_class_for_level,
    validate_artifact_chain,
    validate_authoritative_sources,
    validate_authoritative_lifecycle_policy,
    validate_ci_metadata,
    validate_diff_forensics,
    validate_full_regression_metadata,
    validate_post_deploy_metadata,
    validate_production_release_metadata,
    validate_progressive_exposure,
    validate_red_green_evidence,
    validate_staging_metadata,
    validate_test_integrity,
)
from .evidence import TRUST_ORDER, evaluate_required_evidence
from .problem import NON_CODE_CLASSIFICATIONS, problem_case_fingerprint, semantic_errors
from .schema_validation import validate_instance
from .util import sha256_file

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
PROTECTED_APPROVAL_PRODUCER_PREFIXES = ("controller:", "platform:")


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
    risk_class = problem_case.get("risk_class") or derive_risk_class(risk=risk, domains=normalized_domains)
    return {
        "schema_version": 1,
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
        "head_sha": None,
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
        "authoritative_lifecycle": True,
        "evidence_refs": {},
        "final_state": None,
    }


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
    result = copy.deepcopy(record)
    result["change_contract_hash"] = sha256_file(contract_path)
    result["head_sha"] = head_sha
    result["diff_hash"] = diff_hash
    result["policy_bundle_hash"] = policy_bundle_hash
    result["toolchain_hash"] = toolchain_hash
    result["artifact_digest"] = artifact_digest
    result["release_fingerprint"] = None
    result["sbom_digest"] = None
    result["provenance_digest"] = None
    result["attestation_digest"] = None
    result["production_release_id"] = None
    result["deployed_revision"] = None
    result["artifact_identity"] = None
    result["evidence_refs"] = {}
    return result


def bind_artifact(record: dict[str, Any], artifact_digest: str) -> dict[str, Any]:
    if not DIGEST_RE.fullmatch(artifact_digest):
        raise ValueError("artifact_digest must be a sha256 digest")
    result = copy.deepcopy(record)
    result["artifact_digest"] = artifact_digest
    return result


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
    result = copy.deepcopy(record)
    result.update(values)
    result["artifact_identity"] = artifact_identity
    return result


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
    result = copy.deepcopy(record)
    result["production_release_id"] = production_release_id
    result["deployed_revision"] = deployed_revision
    return result


def invalidate_evidence_for_subject_change(
    evidence_records: Iterable[dict[str, Any]],
    *,
    old_subject: dict[str, Any],
    new_subject: dict[str, Any],
) -> list[dict[str, Any]]:
    """Mark subject-bound evidence stale instead of allowing silent reuse."""

    if old_subject == new_subject:
        return copy.deepcopy(list(evidence_records))
    result: list[dict[str, Any]] = []
    for record in evidence_records:
        item = copy.deepcopy(record)
        invalidated = list(item.get("invalidated_by") or [])
        marker = "subject_changed"
        if marker not in invalidated:
            invalidated.append(marker)
        item["invalidated_by"] = sorted(set(invalidated))
        result.append(item)
    return result


def _logical_current(record: dict[str, Any]) -> str:
    if record.get("state") == "BLOCKED":
        return str(record.get("resume_state") or record.get("last_completed_state"))
    return str(record.get("state"))


def _subject(record: dict[str, Any]) -> dict[str, str] | None:
    required = (
        "repository",
        "change_contract_hash",
        "base_sha",
        "head_sha",
        "policy_bundle_hash",
        "toolchain_hash",
    )
    if any(not record.get(key) for key in required):
        return None
    subject = {key: str(record[key]) for key in required}
    for key in (
        "artifact_digest",
        "release_fingerprint",
        "sbom_digest",
        "provenance_digest",
        "attestation_digest",
        "production_release_id",
        "deployed_revision",
        "artifact_identity",
    ):
        if record.get(key):
            subject[key] = str(record[key])
    return subject


def _problem_phase_errors(record: dict[str, Any], target_state: str, problem_case: dict[str, Any] | None) -> list[str]:
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
    errors.extend(semantic_errors(candidate, target_state=target_state))
    return sorted(set(errors))


def _gate_requirements(policy: dict[str, Any], target_state: str, record: dict[str, Any]) -> tuple[str, list[str]]:
    gate = ((policy.get("gates") or {}).get(target_state) or {})
    minimum = str(gate.get("minimum_trust", "E2"))
    required = set(gate.get("required_evidence", []) or [])
    risk = str(record.get("risk") or "")
    required.update((((gate.get("by_risk") or {}).get(risk)) or []))
    by_domain = gate.get("by_domain") or {}
    for domain in record.get("domains") or []:
        required.update((by_domain.get(domain) or []))
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
        if not producer.startswith(PROTECTED_APPROVAL_PRODUCER_PREFIXES):
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


def _protocol_gate_errors(
    record: dict[str, Any],
    target_state: str,
    evidence_records: list[dict[str, Any]],
    *,
    policy: dict[str, Any],
    problem_case: dict[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    if target_state == "REGRESSION_TEST_PROVEN":
        errors.extend(_red_green_errors(record, evidence_records))
    elif target_state == "DIFF_FORENSICS_PASS":
        for item in _metadata_records(evidence_records, "DIFF_FORENSICS_PASSED"):
            errors.extend(
                validate_diff_forensics(
                    item.get("metadata"),
                    planned_files=((problem_case or {}).get("change_plan") or {}).get("expected_files") or [],
                )
            )
            errors.extend(validate_test_integrity(item.get("metadata")))
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
        for evidence_type in ("PROTECTED_CI", "REQUIRED_CHECKS_VERIFIED"):
            for item in _metadata_records(evidence_records, evidence_type):
                errors.extend(
                    validate_ci_metadata(
                        item.get("metadata"),
                        head_sha=record.get("head_sha"),
                        diff_hash=record.get("diff_hash"),
                    )
                )
    elif target_state == "STAGING_PASS":
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
                errors.extend(
                    validate_production_release_metadata(
                        item.get("metadata"),
                        head_sha=record.get("head_sha"),
                        artifact_digest=record.get("artifact_digest"),
                    )
                )
    elif target_state == "POST_DEPLOY_VERIFIED":
        for item in _metadata_records(evidence_records, "ORIGINAL_PROBLEM_PRODUCTION_VERIFIED"):
            errors.extend(validate_post_deploy_metadata(item.get("metadata"), artifact_digest=record.get("artifact_digest"), deployed_revision=record.get("deployed_revision")))
        for item in _metadata_records(evidence_records, "PRODUCTION_HEALTH"):
            errors.extend(validate_post_deploy_metadata(item.get("metadata"), artifact_digest=record.get("artifact_digest"), deployed_revision=record.get("deployed_revision")))
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
    if target_state not in allowed_next:
        reasons.append(f"Transition {current} -> {target_state} is not allowed")

    reasons.extend(_profile_errors(record, policy, target_state))
    reasons.extend(_problem_phase_errors(record, target_state, problem_case))

    records = list(evidence_records)
    reasons.extend(
        _protocol_gate_errors(
            record,
            target_state,
            records,
            policy=policy,
            problem_case=problem_case,
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
    )
    result = copy.deepcopy(record)
    if not decision["allowed"]:
        prior = _logical_current(record)
        result["state"] = decision["decision"]
        result["resume_state"] = prior
        result["blocked_target"] = target_state
        result["blockers"] = decision["reasons"]
        result["final_state"] = None
        return result

    result["state"] = target_state
    result["last_completed_state"] = target_state
    result["resume_state"] = None
    result["blocked_target"] = None
    result["blockers"] = []
    if problem_case is not None:
        result["problem_case_fingerprint"] = problem_case_fingerprint(problem_case)
        if problem_case.get("risk") is not None:
            result["risk"] = problem_case.get("risk")
            result["risk_class"] = problem_case.get("risk_class") or risk_class_for_level(problem_case.get("risk"))
    if decision.get("valid_evidence"):
        evidence_refs = copy.deepcopy(result.get("evidence_refs") or {})
        for evidence_type, refs in decision["valid_evidence"].items():
            current_refs = list(evidence_refs.get(evidence_type) or [])
            evidence_refs[evidence_type] = sorted(set(current_refs + list(refs)))
        result["evidence_refs"] = evidence_refs
    if target_state == "CLOSED":
        result["final_state"] = "CLOSED"
    elif target_state == "RESOLVED_NO_CODE":
        result["final_state"] = "RESOLVED_NO_CODE"
    else:
        result["final_state"] = None
    return result
