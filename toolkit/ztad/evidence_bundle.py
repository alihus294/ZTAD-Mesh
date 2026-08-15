from __future__ import annotations

import copy
from typing import Any, Iterable

from .bug_protocol import validate_artifact_chain
from .evidence import validate_evidence_record
from .schema_validation import validate_instance
from .util import canonical_json, sha256_bytes


def evidence_subject_from_lifecycle(lifecycle: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "repository",
        "change_contract_hash",
        "base_sha",
        "head_sha",
        "policy_bundle_hash",
        "toolchain_hash",
        "artifact_digest",
        "release_fingerprint",
        "sbom_digest",
        "provenance_digest",
        "attestation_digest",
        "production_release_id",
        "deployed_revision",
        "artifact_identity",
    )
    return {field: lifecycle.get(field) for field in fields if lifecycle.get(field) is not None}


def _bundle_subject(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository": bundle.get("repository"),
        "change_contract_hash": bundle.get("change_contract_hash"),
        "base_sha": bundle.get("base_sha"),
        "head_sha": bundle.get("final_sha"),
        "policy_bundle_hash": bundle.get("policy_bundle_hash"),
        "toolchain_hash": bundle.get("toolchain_hash"),
        "artifact_digest": bundle.get("artifact_digest"),
        "release_fingerprint": bundle.get("release_fingerprint"),
        "sbom_digest": bundle.get("sbom_digest"),
        "provenance_digest": bundle.get("provenance_digest"),
        "attestation_digest": bundle.get("attestation_digest"),
        "production_release_id": bundle.get("production_release_id"),
        "deployed_revision": bundle.get("deployed_revision"),
        "artifact_identity": bundle.get("artifact_identity"),
    }


def subject_fingerprint(lifecycle: dict[str, Any]) -> str:
    subject = _bundle_subject({
        "repository": lifecycle.get("repository"),
        "change_contract_hash": lifecycle.get("change_contract_hash"),
        "base_sha": lifecycle.get("base_sha"),
        "final_sha": lifecycle.get("head_sha"),
        "policy_bundle_hash": lifecycle.get("policy_bundle_hash"),
        "toolchain_hash": lifecycle.get("toolchain_hash"),
        "artifact_digest": lifecycle.get("artifact_digest"),
        "release_fingerprint": lifecycle.get("release_fingerprint"),
        "sbom_digest": lifecycle.get("sbom_digest"),
        "provenance_digest": lifecycle.get("provenance_digest"),
        "attestation_digest": lifecycle.get("attestation_digest"),
        "production_release_id": lifecycle.get("production_release_id"),
        "deployed_revision": lifecycle.get("deployed_revision"),
        "artifact_identity": lifecycle.get("artifact_identity"),
    })
    return sha256_bytes(canonical_json(subject))


def build_evidence_bundle(
    *,
    problem_case: dict[str, Any],
    lifecycle: dict[str, Any],
    evidence_records: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    records = copy.deepcopy(list(evidence_records))
    subject = evidence_subject_from_lifecycle(lifecycle)
    fingerprint = subject_fingerprint(lifecycle)
    red = next((item for item in records if item.get("type") == "REGRESSION_RED_GREEN_PROVEN"), {})
    green = next((item for item in records if item.get("type") == "REGRESSION_RED_GREEN_PROVEN"), {})
    patch = next((item for item in records if item.get("type") == "CANDIDATE_PATCH_CREATED"), {})
    review = next((item for item in records if item.get("type") == "INDEPENDENT_REVIEW_COMPLETED"), {})
    ci = next((item for item in records if item.get("type") == "PROTECTED_CI"), {})
    production = next((item for item in records if item.get("type") == "PRODUCTION_RELEASE_COMPLETED"), {})
    staging = next((item for item in records if item.get("type") == "STAGING_SMOKE_PASSED"), None)
    migration = next((item for item in records if item.get("type") == "MIGRATION_LEDGER_HISTORY_GUARD_PASSED"), None)
    final_state = lifecycle.get("final_state") or lifecycle.get("state")
    change_plan = problem_case.get("change_plan") or {}
    file_reasons = change_plan.get("file_reasons") or {}
    changed_files = [
        {
            "path": str(path),
            "justification": str(file_reasons.get(str(path)) or "Recorded in the approved change plan"),
        }
        for path in change_plan.get("expected_files") or []
    ]
    bundle = {
        "schema_version": 1,
        "issue_id": str(problem_case.get("case_id")),
        "original_report": problem_case.get("original_report_verbatim") or problem_case.get("report"),
        "classification": problem_case.get("classification"),
        "repository": lifecycle.get("repository"),
        "change_contract_hash": lifecycle.get("change_contract_hash"),
        "base_sha": lifecycle.get("base_sha"),
        "final_sha": lifecycle.get("head_sha"),
        "policy_bundle_hash": lifecycle.get("policy_bundle_hash"),
        "toolchain_hash": lifecycle.get("toolchain_hash"),
        "authoritative_sources": problem_case.get("authoritative_sources") or [],
        "source_conflicts": problem_case.get("source_conflicts") or [],
        "unresolved_ambiguities": problem_case.get("unresolved_ambiguities") or [],
        "reproduction": problem_case.get("reproduction") or {},
        "root_cause": problem_case.get("root_cause") or {},
        "blast_radius": problem_case.get("blast_radius") or {},
        "risk": lifecycle.get("risk_class") or lifecycle.get("risk"),
        "change_plan": change_plan,
        "changed_files": changed_files,
        "red_proof": red.get("metadata") or {},
        "green_proof": green.get("metadata") or {},
        "patch": patch.get("metadata") or {},
        "targeted_validation": [item.get("metadata") or {} for item in records if item.get("type") == "TARGETED_VALIDATION_PASSED"],
        "full_regression": [item.get("metadata") or {} for item in records if item.get("type") == "FULL_REGRESSION_VALIDATION_PASSED"],
        "security_tenant_checks": [item.get("metadata") or {} for item in records if item.get("type") in {"SECURITY_VALIDATION_PASSED", "AUTHZ_TENANT_MATRIX_PASSED"}],
        "independent_review": review.get("metadata") or {},
        "ci": ci.get("metadata") or {},
        "production_release": production.get("metadata") or {},
        "staging": staging.get("metadata") if staging else None,
        "migration": migration.get("metadata") if migration else None,
        "release_fingerprint": lifecycle.get("release_fingerprint"),
        "artifact_digest": lifecycle.get("artifact_digest"),
        "sbom_digest": lifecycle.get("sbom_digest"),
        "provenance_digest": lifecycle.get("provenance_digest"),
        "attestation_digest": lifecycle.get("attestation_digest"),
        "production_release_id": lifecycle.get("production_release_id"),
        "deployed_revision": lifecycle.get("deployed_revision"),
        "artifact_identity": lifecycle.get("artifact_identity"),
        "post_deploy_verification": next((item.get("metadata") or {} for item in records if item.get("type") == "ORIGINAL_PROBLEM_PRODUCTION_VERIFIED"), {}),
        "final_state": final_state,
        "subject_fingerprint": fingerprint,
        "evidence_records": records,
        "claim_boundary": "A bundle is a subject-bound record. It does not create protected authority, deployment, or runtime evidence.",
    }
    return bundle


def validate_evidence_bundle(
    bundle: dict[str, Any],
    *,
    bundle_schema: dict[str, Any],
    evidence_schema: dict[str, Any],
    trust_roots: dict[str, Any] | None = None,
) -> list[str]:
    errors = list(validate_instance(bundle, bundle_schema))
    records = bundle.get("evidence_records") or []
    subject = _bundle_subject(bundle)
    if bundle.get("subject_fingerprint") != sha256_bytes(canonical_json(subject)):
        errors.append("Evidence bundle subject_fingerprint is not bound to its subject")
    for item in records:
        errors.extend(validate_evidence_record(item, schema=evidence_schema, subject=subject, minimum_trust="E0", trust_roots=trust_roots, require_authoritative_signature=False))
    errors.extend(validate_artifact_chain({
        "source_sha": bundle.get("final_sha"),
        "artifact_digest": bundle.get("artifact_digest"),
        "release_fingerprint": bundle.get("release_fingerprint"),
        "sbom_digest": bundle.get("sbom_digest"),
        "provenance_digest": bundle.get("provenance_digest"),
        "attestation_digest": bundle.get("attestation_digest"),
        "artifact_identity": bundle.get("artifact_identity"),
    }, head_sha=bundle.get("final_sha"), artifact_digest=bundle.get("artifact_digest")))
    return sorted(set(errors))
