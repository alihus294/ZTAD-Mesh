from __future__ import annotations

"""Immutable delivery-subject identity and fail-closed mutation handling.

The historical lifecycle format exposed one ``head_sha`` value.  That value
cannot describe a pull-request revision, a squash/rebase result, and the
revision actually used to build and deploy an artifact at the same time.  This
module keeps the old aliases for interoperability while making every material
identity component explicit.
"""

import copy
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .delivery_model import DELIVERY_MODELS
from .util import canonical_json, sha256_bytes, utc_now

SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

SUBJECT_FIELDS = (
    "repository",
    "delivery_model",
    "delivery_model_proof_digest",
    "protected_base_sha",
    "pr_head_sha",
    "reviewed_diff_hash",
    "merged_main_sha",
    "merge_method",
    "merge_provenance",
    "post_merge_ci_run_id",
    "change_contract_hash",
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
    "subject_epoch",
    "subject_version",
)

MATERIAL_SUBJECT_FIELDS = tuple(field for field in SUBJECT_FIELDS if field not in {"subject_epoch", "subject_version"})
CORE_REVIEW_FIELDS = {
    "protected_base_sha",
    "pr_head_sha",
    "reviewed_diff_hash",
    "change_contract_hash",
    "policy_bundle_hash",
    "toolchain_hash",
}
ARTIFACT_FIELDS = {
    "artifact_digest",
    "release_fingerprint",
    "sbom_digest",
    "provenance_digest",
    "attestation_digest",
    "artifact_identity",
}
PRODUCTION_FIELDS = {"production_release_id", "deployed_revision"}
POST_PRODUCTION_STATES = {"PRODUCTION_RELEASED", "POST_DEPLOY_VERIFIED", "CLOSED", "ROLLBACK_REQUIRED"}
PACKAGE_RELEASE_STATES = {"PACKAGE_RELEASED", "RELEASE_ARTIFACT_VERIFIED", "CONSUMER_VALIDATION_PASS"}
SUBJECT_TRANSITION_POLICY = {
    "delivery_model": {
        "fields": frozenset({"delivery_model", "delivery_model_proof_digest"}),
        "old_epoch_to_new_epoch": "new = old + 1",
        "evidence_survives": ("immutable_prior_ledger_history",),
        "evidence_invalidated": ("all_current_subject_bound_evidence_refs",),
        "earliest_lifecycle_state_retained": "CHANGE_PLANNED",
        "earliest_revalidation_state": "CHANGE_PLANNED",
    },
    "candidate_identity": {
        "fields": frozenset({"protected_base_sha", "pr_head_sha", "reviewed_diff_hash"}),
        "old_epoch_to_new_epoch": "new = old + 1",
        "evidence_survives": ("non_subject_problem_intake", "immutable_prior_ledger_history"),
        "evidence_invalidated": ("all_current_subject_bound_evidence_refs",),
        "earliest_lifecycle_state_retained": "CHANGE_PLANNED",
        "earliest_revalidation_state": "CHANGE_PLANNED",
    },
    "merge_identity": {
        "fields": frozenset({"merged_main_sha", "merge_method", "merge_provenance", "post_merge_ci_run_id"}),
        "old_epoch_to_new_epoch": "new = old + 1",
        "evidence_survives": ("pre_merge_review_provenance", "immutable_prior_ledger_history"),
        "evidence_invalidated": ("pre_merge_subject_bound_execution_and_release_refs",),
        "earliest_lifecycle_state_retained": "CHANGE_PLANNED",
        "earliest_revalidation_state": "CHANGE_PLANNED",
    },
    "contract_policy_toolchain": {
        "fields": frozenset({"change_contract_hash", "policy_bundle_hash", "toolchain_hash"}),
        "old_epoch_to_new_epoch": "new = old + 1",
        "evidence_survives": ("non_subject_problem_intake", "immutable_prior_ledger_history"),
        "evidence_invalidated": ("all_current_subject_bound_evidence_refs",),
        "earliest_lifecycle_state_retained": "CHANGE_PLANNED",
        "earliest_revalidation_state": "CHANGE_PLANNED",
    },
    "artifact_release": {
        "fields": frozenset({"artifact_digest", "release_fingerprint", "sbom_digest", "provenance_digest", "attestation_digest", "artifact_identity"}),
        "old_epoch_to_new_epoch": "new = old + 1",
        "evidence_survives": ("pre_artifact_subject_provenance", "immutable_prior_ledger_history"),
        "evidence_invalidated": ("artifact_and_downstream_subject_bound_evidence_refs",),
        "earliest_lifecycle_state_retained": "CI_PASS",
        "earliest_revalidation_state": "CI_PASS",
    },
    "production_identity": {
        "fields": frozenset({"production_release_id", "deployed_revision"}),
        "old_epoch_to_new_epoch": "new = old + 1",
        "evidence_survives": ("immutable_prior_ledger_history",),
        "evidence_invalidated": ("all_production_and_downstream_subject_bound_evidence_refs",),
        "earliest_lifecycle_state_retained": "ROLLBACK_REQUIRED",
        "earliest_revalidation_state": "ROLLBACK_REQUIRED",
    },
}


@dataclass(frozen=True)
class SubjectValidation:
    errors: tuple[str, ...]
    fingerprint: str


def _value(record: Mapping[str, Any], canonical: str, legacy: str | None = None) -> Any:
    value = record.get(canonical)
    if value is None and legacy is not None:
        value = record.get(legacy)
    return value


def subject_from_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical subject, retaining explicit nulls for hashing."""

    merged = record.get("merged_main_sha")
    pr_head = _value(record, "pr_head_sha")
    if pr_head is None and merged is None:
        pr_head = record.get("head_sha")
    result: dict[str, Any] = {
        "repository": _value(record, "repository"),
        "delivery_model": record.get("delivery_model"),
        "delivery_model_proof_digest": record.get("delivery_model_proof_digest"),
        "protected_base_sha": _value(record, "protected_base_sha", "base_sha"),
        "pr_head_sha": pr_head,
        "reviewed_diff_hash": _value(record, "reviewed_diff_hash", "diff_hash"),
        "merged_main_sha": merged,
        "merge_method": record.get("merge_method"),
        "merge_provenance": copy.deepcopy(record.get("merge_provenance")),
        "post_merge_ci_run_id": record.get("post_merge_ci_run_id"),
        "change_contract_hash": record.get("change_contract_hash"),
        "policy_bundle_hash": record.get("policy_bundle_hash"),
        "toolchain_hash": record.get("toolchain_hash"),
        "artifact_digest": record.get("artifact_digest"),
        "release_fingerprint": record.get("release_fingerprint"),
        "sbom_digest": record.get("sbom_digest"),
        "provenance_digest": record.get("provenance_digest"),
        "attestation_digest": record.get("attestation_digest"),
        "production_release_id": record.get("production_release_id"),
        "deployed_revision": record.get("deployed_revision"),
        "artifact_identity": record.get("artifact_identity"),
        "subject_epoch": int(record.get("subject_epoch") or 0),
        "subject_version": int(record.get("subject_version") or 1),
    }
    if result["delivery_model"] is None and result["delivery_model_proof_digest"] is None:
        result.pop("delivery_model")
        result.pop("delivery_model_proof_digest")
    return result


def active_revision(subject_or_record: Mapping[str, Any]) -> str | None:
    subject = subject_from_record(subject_or_record)
    return subject.get("merged_main_sha") or subject.get("pr_head_sha")


def subject_fingerprint(subject_or_record: Mapping[str, Any]) -> str:
    subject = subject_from_record(subject_or_record)
    return sha256_bytes(canonical_json(subject))


def validate_subject(subject_or_record: Mapping[str, Any], *, require_merge_provenance: bool = False) -> SubjectValidation:
    subject = subject_from_record(subject_or_record)
    errors: list[str] = []
    if not isinstance(subject.get("repository"), str) or not subject["repository"].strip():
        errors.append("Subject repository is required")
    if subject.get("delivery_model") is not None and subject.get("delivery_model") not in DELIVERY_MODELS:
        errors.append("Subject delivery_model is unsupported")
    if subject.get("delivery_model_proof_digest") is not None and (
        not isinstance(subject.get("delivery_model_proof_digest"), str)
        or not DIGEST_RE.fullmatch(subject["delivery_model_proof_digest"])
    ):
        errors.append("Subject delivery_model_proof_digest must be a sha256 digest")
    for field in ("protected_base_sha", "pr_head_sha", "merged_main_sha", "deployed_revision"):
        value = subject.get(field)
        if value is not None and (not isinstance(value, str) or not SHA_RE.fullmatch(value)):
            errors.append(f"Subject {field} must be a lowercase hexadecimal revision")
    for field in (
        "reviewed_diff_hash",
        "change_contract_hash",
        "policy_bundle_hash",
        "toolchain_hash",
        "artifact_digest",
        "release_fingerprint",
        "sbom_digest",
        "provenance_digest",
        "attestation_digest",
    ):
        value = subject.get(field)
        if value is not None and (not isinstance(value, str) or not DIGEST_RE.fullmatch(value)):
            errors.append(f"Subject {field} must be a sha256 digest")
    if subject.get("merge_method") is not None and subject["merge_method"] not in {"MERGE", "SQUASH", "REBASE", "FAST_FORWARD"}:
        errors.append("Subject merge_method is unsupported")
    if subject.get("merge_provenance") is not None and not isinstance(subject["merge_provenance"], dict):
        errors.append("Subject merge_provenance must be an object")
    if subject.get("artifact_identity") is not None and not str(subject["artifact_identity"]).strip():
        errors.append("Subject artifact_identity must be non-empty")
    if subject.get("subject_epoch", 0) < 0:
        errors.append("Subject subject_epoch cannot be negative")
    if subject.get("merged_main_sha") and not subject.get("pr_head_sha"):
        errors.append("Merged-main subject requires the reviewed PR head")
    active = subject.get("merged_main_sha") or subject.get("pr_head_sha")
    if subject.get("deployed_revision") and active and subject.get("deployed_revision") != active:
        errors.append("deployed_revision must equal the active merged-main or candidate revision")
    if require_merge_provenance and subject.get("merged_main_sha"):
        provenance = subject.get("merge_provenance")
        if not isinstance(provenance, dict):
            errors.append("Merged-main subject requires merge_provenance")
        else:
            for field in ("pr_head_sha", "reviewed_diff_hash", "merged_main_sha", "transformation"):
                if not provenance.get(field):
                    errors.append(f"merge_provenance.{field} is required")
            if provenance.get("pr_head_sha") != subject.get("pr_head_sha"):
                errors.append("merge_provenance.pr_head_sha mismatch")
            if provenance.get("reviewed_diff_hash") != subject.get("reviewed_diff_hash"):
                errors.append("merge_provenance.reviewed_diff_hash mismatch")
            if provenance.get("merged_main_sha") != subject.get("merged_main_sha"):
                errors.append("merge_provenance.merged_main_sha mismatch")
        if not subject.get("post_merge_ci_run_id"):
            errors.append("Merged-main subject requires post_merge_ci_run_id")
    return SubjectValidation(tuple(sorted(set(errors))), subject_fingerprint(subject))


def material_subject_changes(old: Mapping[str, Any], new: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    previous = subject_from_record(old)
    current = subject_from_record(new)
    return {
        field: {"old": previous.get(field), "new": current.get(field)}
        for field in MATERIAL_SUBJECT_FIELDS
        if previous.get(field) != current.get(field)
    }


def earliest_revalidation_state(changed_fields: set[str]) -> str:
    if changed_fields & PRODUCTION_FIELDS:
        return "ROLLBACK_REQUIRED"
    if changed_fields & ARTIFACT_FIELDS:
        return "CI_PASS"
    return "CHANGE_PLANNED"


def subject_epoch_transition_policy(changed_fields: set[str]) -> dict[str, Any]:
    """Return the strict epoch/invalidation rule for a material mutation."""

    changed = set(changed_fields)
    if not changed:
        return {"category": "NO_CHANGE", "fields": [], "increments_epoch": False, "earliest_revalidation_state": None}
    categories = [
        (name, value)
        for name, value in SUBJECT_TRANSITION_POLICY.items()
        if changed & set(value["fields"])
    ]
    if any(name == "production_identity" for name, _value in categories):
        category = "production_identity"
    elif any(name == "artifact_release" for name, _value in categories):
        category = "artifact_release"
    elif any(name == "merge_identity" for name, _value in categories):
        category = "merge_identity"
    elif any(name == "candidate_identity" for name, _value in categories):
        category = "candidate_identity"
    elif any(name == "delivery_model" for name, _value in categories):
        category = "delivery_model"
    else:
        category = "contract_policy_toolchain"
    return {
        "category": category,
        "fields": sorted(changed),
        "increments_epoch": True,
        "old_epoch_to_new_epoch": SUBJECT_TRANSITION_POLICY[category]["old_epoch_to_new_epoch"],
        "evidence_survives": list(SUBJECT_TRANSITION_POLICY[category]["evidence_survives"]),
        "evidence_invalidated": list(SUBJECT_TRANSITION_POLICY[category]["evidence_invalidated"]),
        "earliest_lifecycle_state_retained": SUBJECT_TRANSITION_POLICY[category]["earliest_lifecycle_state_retained"],
        "earliest_revalidation_state": earliest_revalidation_state(changed),
    }


def describe_subject_transition(old: Mapping[str, Any], new: Mapping[str, Any]) -> dict[str, Any]:
    """Return the complete machine-readable epoch transition decision."""

    previous = subject_from_record(old)
    current = subject_from_record(new)
    changes = material_subject_changes(previous, current)
    rule = subject_epoch_transition_policy(set(changes))
    return {
        **rule,
        "old_epoch": int(previous.get("subject_epoch") or 0),
        "new_epoch": int(current.get("subject_epoch") or 0),
        "changed_fields": sorted(changes),
    }


def validate_subject_epoch_transition(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[str]:
    previous = subject_from_record(old)
    current = subject_from_record(new)
    changes = material_subject_changes(previous, current)
    rule = subject_epoch_transition_policy(set(changes))
    old_epoch = int(previous.get("subject_epoch") or 0)
    new_epoch = int(current.get("subject_epoch") or 0)
    errors: list[str] = []
    if changes and new_epoch != old_epoch + 1:
        errors.append("Material subject change must increment subject_epoch exactly once")
    if not changes and new_epoch != old_epoch:
        errors.append("subject_epoch cannot change without a material subject mutation")
    if changes and new.get("subject_fingerprint") != subject_fingerprint(current):
        errors.append("Material subject change must recompute subject_fingerprint")
    if changes and rule["category"] == "production_identity" and str(new.get("state") or "") not in {"ROLLBACK_REQUIRED", "BLOCKED", "CHANGE_PLANNED"}:
        errors.append("Production identity changes require rollback or blocked revalidation")
    return sorted(set(errors))


def apply_subject_update(
    record: Mapping[str, Any],
    updates: Mapping[str, Any],
    *,
    reason: str,
) -> dict[str, Any]:
    """Apply a subject change and invalidate incompatible downstream claims.

    The returned JSON is an export, not the authority.  The durable lifecycle
    store records the same mutation as an append-only event.  This function is
    nevertheless fail-closed so callers cannot accidentally keep a completed
    state while only deleting evidence references.
    """

    unsupported = sorted(set(updates) - set(MATERIAL_SUBJECT_FIELDS))
    if unsupported:
        raise ValueError(
            "Subject updates may change only material subject fields: "
            + ", ".join(unsupported)
        )
    result = copy.deepcopy(dict(record))
    # Subject helpers produce a projection.  Only LifecycleStore.transition may
    # restore the authoritative marker after ledger validation and append.
    result["authoritative_lifecycle"] = False
    result["authority_store"] = None
    for field in ("store_version", "store_record_hash", "store_binding"):
        result.pop(field, None)
    before = subject_from_record(result)
    result.update(copy.deepcopy(dict(updates)))
    if "protected_base_sha" in updates:
        result["base_sha"] = updates["protected_base_sha"]
    if "pr_head_sha" in updates:
        result["head_sha"] = updates["pr_head_sha"]
        result["diff_hash"] = updates.get("reviewed_diff_hash", result.get("diff_hash"))
    if "reviewed_diff_hash" in updates:
        result["diff_hash"] = updates["reviewed_diff_hash"]
    if "merged_main_sha" in updates and updates.get("merged_main_sha"):
        result["head_sha"] = updates["merged_main_sha"]
    after = subject_from_record(result)
    subject_errors = validate_subject(
        after,
        require_merge_provenance=bool(after.get("merged_main_sha")),
    ).errors
    if subject_errors:
        raise ValueError("Invalid subject update: " + "; ".join(subject_errors))
    changes = material_subject_changes(before, after)
    if not changes:
        result["subject_fingerprint"] = subject_fingerprint(result)
        return result

    old_epoch = int(before.get("subject_epoch") or 0)
    new_epoch = old_epoch + 1
    result["subject_epoch"] = new_epoch
    result["subject_version"] = max(int(result.get("subject_version") or 1), 1)
    result["subject_fingerprint"] = subject_fingerprint(result)

    existing_refs = copy.deepcopy(result.get("evidence_refs") or {})
    historical = copy.deepcopy(result.get("historical_evidence_refs") or {})
    if existing_refs:
        for evidence_type, refs in existing_refs.items():
            historical.setdefault(evidence_type, [])
            historical[evidence_type] = sorted(set(historical[evidence_type]) | set(refs or []))
        result["evidence_refs"] = {}
    result["historical_evidence_refs"] = historical
    invalidation = {
        "subject_epoch": new_epoch,
        "occurred_at": utc_now(),
        "reason": reason,
        "changed_fields": sorted(changes),
        "old_subject_fingerprint": subject_fingerprint(before),
        "new_subject_fingerprint": result["subject_fingerprint"],
        "invalidated_evidence_ids": sorted({ref for refs in existing_refs.values() for ref in refs or []}),
    }
    history = list(result.get("subject_mutations") or [])
    history.append(invalidation)
    result["subject_mutations"] = history

    current_state = str(result.get("state") or "")
    if current_state in POST_PRODUCTION_STATES:
        result["state"] = "ROLLBACK_REQUIRED"
        result["resume_state"] = "ROLLBACK_REQUIRED"
        result["blocked_target"] = current_state
        result["blockers"] = ["Subject changed after production exposure; rollback or containment is required"]
        result["final_state"] = None
    elif current_state in PACKAGE_RELEASE_STATES:
        result["state"] = "BLOCKED"
        result["resume_state"] = "CI_PASS"
        result["blocked_target"] = current_state
        result["blockers"] = [
            "Package release subject changed after publication; revoke or replace the affected package before revalidation",
            "Changed subject fields: " + ", ".join(sorted(changes)),
        ]
        result["final_state"] = None
    elif current_state not in {"UNVERIFIED_REPORT", "SOURCE_OF_TRUTH_RESOLVED", "ISSUE_CLASSIFIED", "BUG_REPRODUCED", "ROOT_CAUSE_PROVEN", "BLAST_RADIUS_MAPPED", "CHANGE_PLANNED", "BLOCKED"}:
        reset = earliest_revalidation_state(set(changes))
        result["state"] = "BLOCKED"
        result["resume_state"] = reset
        result["blocked_target"] = current_state
        result["blockers"] = [
            "Material subject change invalidated downstream evidence; revalidation is required",
            "Changed subject fields: " + ", ".join(sorted(changes)),
        ]
        result["final_state"] = None
    return result
