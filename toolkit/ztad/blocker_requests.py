from __future__ import annotations

from typing import Any

from .problem import LOCAL_EVIDENCE_NOTICE
from .schema_validation import validate_instance
from .util import canonical_json, sha256_bytes, utc_now

BLOCKER_CATALOG: dict[str, dict[str, Any]] = {
    "missing_release_fingerprint": {
        "kind": "LOCAL_REMEDIATION", "evidence": "RELEASE_FINGERPRINT_VERIFIED", "trust": "E2",
        "producers": ["local-tool:release-fingerprint"],
        "action": "Generate the deterministic release fingerprint from the exact release manifest, then bind protected artifact evidence to that subject.",
    },
    "missing_signed_release_manifest": {
        "kind": "PROTECTED_EVIDENCE", "evidence": "SIGNED_RELEASE_MANIFEST", "trust": "E4",
        "producers": ["platform:release-signing-controller"],
        "action": "Submit the exact release-fingerprint subject to the protected signing workflow; do not create a local substitute signature.",
    },
    "missing_artifact_attestation_and_sbom": {
        "kind": "PROTECTED_EVIDENCE", "evidence": "ARTIFACT_ATTESTATION_VERIFIED", "trust": "E4",
        "producers": ["platform:protected-build", "platform:artifact-attestation"],
        "action": "Generate/verify the SBOM and provenance/attestation in the protected build path for the exact artifact digest.",
    },
    "missing_staged_restore_rehearsal": {
        "kind": "PROTECTED_EVIDENCE", "evidence": "STAGED_RESTORE_REHEARSAL", "trust": "E4",
        "producers": ["platform:staging-controller"],
        "action": "Run the restore rehearsal in the protected staging environment against the exact release candidate and record exact-subject evidence.",
    },
    "missing_rollback_rehearsal": {
        "kind": "PROTECTED_EVIDENCE", "evidence": "ROLLBACK_REHEARSAL_VERIFIED", "trust": "E4",
        "producers": ["platform:deployment-controller"],
        "action": "Run the protected rollback rehearsal against the exact deployment adapter/artifact and record the observed result.",
    },
    "missing_observation_and_synthetic_transaction": {
        "kind": "PROTECTED_EVIDENCE", "evidence": "OBSERVABILITY_READY", "trust": "E4",
        "producers": ["platform:staging-controller", "platform:runtime-observer"],
        "action": "Configure and execute the approved synthetic transaction/observation policy using synthetic data only; record exact candidate/digest bindings.",
    },
    "missing_production_runtime_health": {
        "kind": "PROTECTED_EVIDENCE", "evidence": "PRODUCTION_HEALTH", "trust": "E5",
        "producers": ["platform:runtime-observer"],
        "action": "After an authorized deployment only, observe the exact running digest and record production health, synthetic transaction, and observation-window evidence.",
    },
    "missing_protected_supervisor_approval": {
        "kind": "PROTECTED_EVIDENCE", "evidence": "PROTECTED_RELEASE_AUTHORIZATION", "trust": "E6",
        "producers": ["platform:approval-controller"],
        "action": "Submit the exact SHA/diff/evidence/artifact subject to the protected approval controller. Model text cannot satisfy this request.",
    },
    "migration_ledger_history_guard_failure": {
        "kind": "LOCAL_REMEDIATION", "evidence": "MIGRATION_LEDGER_HISTORY_VERIFIED", "trust": "E2",
        "producers": ["local-tool:migration-history-guard", "platform:protected-ci"],
        "action": "Run the unchanged migration ledger/history guard from the exact protected base and repair the migration/history root cause; never edit the guard to force green.",
    },
    "remote_main_dependency_fix_not_applied": {
        "kind": "LOCAL_REMEDIATION", "evidence": "DEPENDENCY_AUDIT_PASSED", "trust": "E3",
        "producers": ["local-tool:dependency-audit", "platform:protected-ci"],
        "action": "Apply the minimal dependency fix on a clean protected-base branch, regenerate the package-manager lockfile, run the audit locally, then require protected CI on the exact PR head.",
    },
    "provider_output_missing": {
        "kind": "LOCAL_REMEDIATION", "evidence": "PROVIDER_RESULT_VALIDATED", "trust": "E2",
        "producers": ["local-tool:provider-contract"],
        "action": "Inspect the provider exit/stderr/events/receipt first. Change provider/resource/strategy when warranted; do not repeat identical inputs or misclassify a schema-preflight failure as missing output.",
    },
    "invalid_json_schema": {
        "kind": "LOCAL_REMEDIATION", "evidence": "STRICT_MODEL_SCHEMA_VALID", "trust": "E2",
        "producers": ["local-tool:schema-validation"],
        "action": "Repair the canonical output schema to strict model compatibility and validate it before any provider invocation. Update release identity/fingerprints after package changes.",
    },
    "local_branch_differs_from_protected_main": {
        "kind": "LOCAL_REMEDIATION", "evidence": "ISOLATED_CLEAN_WORKTREE", "trust": "E2",
        "producers": ["local-tool:problem-isolation"],
        "action": "Create a managed detached worktree from the exact recorded protected base and transfer only task-scoped files. Preserve the user's original branch unchanged.",
    },
    "dirty_worktree": {
        "kind": "LOCAL_REMEDIATION", "evidence": "ISOLATED_CLEAN_WORKTREE", "trust": "E2",
        "producers": ["local-tool:problem-isolation"],
        "action": "Preserve the dirty user worktree untouched and continue in a managed clean worktree from the exact protected base; never ask the owner to choose mixed changes.",
    },
}

SUBJECT_KEYS = (
    "repository", "base_sha", "head_sha", "artifact_digest", "change_contract_hash", "policy_bundle_hash", "toolchain_hash",
)


def prepare_blocker_request(
    blocker: str,
    *,
    subject: dict[str, Any],
    reason: str,
    schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if blocker not in BLOCKER_CATALOG:
        raise ValueError(f"Unknown blocker: {blocker}")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason must be non-empty")
    missing = [key for key in SUBJECT_KEYS if key not in subject]
    if missing:
        raise ValueError("blocker subject is missing required keys: " + ", ".join(missing))
    normalized_subject = {key: subject.get(key) for key in SUBJECT_KEYS}
    spec = BLOCKER_CATALOG[blocker]
    material = {
        "blocker": blocker,
        "subject": normalized_subject,
        "reason": reason.strip(),
        "required_evidence_type": spec["evidence"],
        "minimum_trust": spec["trust"],
    }
    request_id = "REQ-" + sha256_bytes(canonical_json(material)).removeprefix("sha256:")[:16]
    result = {
        "schema_version": 1,
        "request_id": request_id,
        "blocker": blocker,
        "request_kind": spec["kind"],
        "required_evidence_type": spec["evidence"],
        "minimum_trust": spec["trust"],
        "expected_producer_prefixes": list(spec["producers"]),
        "subject": normalized_subject,
        "reason": reason.strip(),
        "next_protected_or_local_action": spec["action"],
        "prepared_at": utc_now(),
        "authority": "LOCAL_NON_AUTHORITATIVE",
        "can_satisfy_gate": False,
        "local_evidence_notice": LOCAL_EVIDENCE_NOTICE,
    }
    if schema is not None:
        errors = validate_instance(result, schema)
        if errors:
            raise ValueError("Generated blocker request is invalid: " + "; ".join(errors))
    return result
