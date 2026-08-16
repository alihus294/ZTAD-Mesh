from __future__ import annotations

import copy
import re
from typing import Any, Iterable

from .bug_protocol import (
    TERMINAL_EVIDENCE_PRODUCERS,
    VALID_DOMAINS,
    validate_artifact_chain,
    validate_ci_metadata,
    validate_production_release_metadata,
    validate_rollback_closure,
    validate_post_deploy_metadata,
    validate_package_release_metadata,
    validate_published_asset_metadata,
    validate_consumer_validation_metadata,
    validate_synthetic_transaction_metadata,
    validate_observation_window_metadata,
    validate_policy_safety,
)
from .evidence import TRUST_ORDER, validate_evidence_record, validate_evidence_subject
from .controller_context import LIFECYCLE_CONTROLLER_ID, LIFECYCLE_CONTROLLER_TYPE
from .lifecycle_store import (
    ALLOWED_TRANSITIONS,
    CODE_LIFECYCLE,
    GENESIS_HASH,
    PROTECTED_TRANSITION_STATES,
    TRANSITION_AUTHORIZATION_PRODUCER,
    TRANSITION_AUTHORIZATION_TYPE,
    event_commitment,
)
from .delivery_model import HOSTED_RUNTIME_SERVICE, HYBRID, PACKAGE_OR_PLUGIN, validate_delivery_model_proof
from .schema_validation import validate_instance
from .subject import (
    subject_fingerprint as canonical_subject_fingerprint,
    subject_from_record,
    validate_subject,
    validate_subject_epoch_transition,
)
from .trust import is_host_accepted_trust_roots
from .util import canonical_json, sha256_bytes

PRE_MERGE_EVIDENCE_TYPES = {
    "CANDIDATE_PATCH_CREATED",
    "REGRESSION_RED_GREEN_PROVEN",
    "TARGETED_VALIDATION_PASSED",
    "FULL_REGRESSION_VALIDATION_PASSED",
    "DIFF_FORENSICS_PASSED",
    "INDEPENDENT_REVIEW_COMPLETED",
    "PROTECTED_CI",
    "REQUIRED_CHECKS_VERIFIED",
}
POST_MERGE_EVIDENCE_TYPES = {
    "POST_MERGE_CI_PROVEN",
    "RELEASE_FINGERPRINT_VERIFIED",
    "SIGNED_RELEASE_MANIFEST",
    "SBOM_VERIFIED",
    "ARTIFACT_ATTESTATION_VERIFIED",
    "BUILD_PROVENANCE_VERIFIED",
    "STAGING_SMOKE_PASSED",
    "ORIGINAL_PROBLEM_STAGING_VERIFIED",
    "PROTECTED_SUPERVISOR_APPROVAL",
    "PROTECTED_RELEASE_AUTHORIZATION",
    "PRODUCTION_RELEASE_COMPLETED",
    "EXPECTED_DIGEST_RUNNING",
    "ORIGINAL_PROBLEM_PRODUCTION_VERIFIED",
    "PRODUCTION_HEALTH",
    "SYNTHETIC_TRANSACTION",
    "OBSERVATION_WINDOW",
    "PROTECTED_PACKAGE_RELEASE",
    "PUBLISHED_ASSET_DIGEST_VERIFIED",
    "PUBLISHED_ASSET_METADATA_VERIFIED",
    "CONSUMER_INSTALLATION_VALIDATED",
    "PACKAGED_REGRESSIONS_PASSED",
    "PACKAGE_CONTENT_SECURITY_VERIFIED",
}
ROLLBACK_EVIDENCE_TYPES = {"ROLLBACK_COMPLETED", "POST_ROLLBACK_HEALTH_VERIFIED"}


def evidence_subject_from_lifecycle(lifecycle: dict[str, Any]) -> dict[str, Any]:
    subject = subject_from_record(lifecycle)
    return {field: value for field, value in subject.items() if value is not None}


def _bundle_subject(bundle: dict[str, Any]) -> dict[str, Any]:
    return subject_from_record({
        "repository": bundle.get("repository"),
        "delivery_model": bundle.get("delivery_model"),
        "delivery_model_proof_digest": bundle.get("delivery_model_proof_digest"),
        "protected_base_sha": bundle.get("protected_base_sha") or bundle.get("base_sha"),
        "pr_head_sha": bundle.get("pr_head_sha") or bundle.get("final_sha"),
        "reviewed_diff_hash": bundle.get("reviewed_diff_hash"),
        "merged_main_sha": bundle.get("merged_main_sha"),
        "merge_method": bundle.get("merge_method"),
        "merge_provenance": bundle.get("merge_provenance"),
        "post_merge_ci_run_id": bundle.get("post_merge_ci_run_id"),
        "change_contract_hash": bundle.get("change_contract_hash"),
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
        "subject_epoch": bundle.get("subject_epoch", 0),
        "subject_version": bundle.get("subject_version", 1),
    })


def _subject_lineage_errors(record: dict[str, Any], final_subject: dict[str, Any], evidence_type: str) -> list[str]:
    record_subject = subject_from_record(record)
    errors = list(validate_evidence_subject(record_subject))
    if record.get("subject_fingerprint") is not None and record.get("subject_fingerprint") != canonical_subject_fingerprint(record_subject):
        errors.append("Evidence record subject_fingerprint does not match its subject")
    for field in (
        "repository", "delivery_model", "delivery_model_proof_digest", "protected_base_sha", "pr_head_sha",
        "reviewed_diff_hash", "change_contract_hash", "policy_bundle_hash", "toolchain_hash",
    ):
        if record_subject.get(field) != final_subject.get(field):
            errors.append(f"Evidence record lineage mismatch for {field}")
    if record_subject.get("subject_epoch") != final_subject.get("subject_epoch"):
        errors.append("Evidence record has a stale subject_epoch")
    if final_subject.get("merged_main_sha"):
        if record_subject.get("merged_main_sha") and record_subject.get("merged_main_sha") != final_subject.get("merged_main_sha"):
            errors.append("Evidence record merged-main SHA is not the final subject")
        if evidence_type not in PRE_MERGE_EVIDENCE_TYPES and not record_subject.get("merged_main_sha"):
            errors.append("Post-merge evidence must bind merged_main_sha")
    if evidence_type in POST_MERGE_EVIDENCE_TYPES:
        for field in ("artifact_digest", "release_fingerprint", "sbom_digest", "provenance_digest", "attestation_digest"):
            if final_subject.get(field) and record_subject.get(field) != final_subject.get(field):
                errors.append(f"Post-merge evidence must bind final {field}")
        if final_subject.get("subject_epoch") != record_subject.get("subject_epoch"):
            errors.append("Post-merge evidence has a stale subject_epoch")
    return sorted(set(errors))


def _validate_lifecycle_replay(
    events: list[dict[str, Any]],
    *,
    issue_id: str,
    final_subject: dict[str, Any],
    evidence_ids: set[str],
    terminal_state: str,
    closure_class: str | None = None,
    evidence_by_id: dict[str, dict[str, Any]] | None = None,
    trust_roots: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    previous_hash = GENESIS_HASH
    expected_sequence = 1
    case_events: list[dict[str, Any]] = []
    previous_epoch = 0
    case_state: str | None = None
    case_resume_state: str | None = None
    store_binding: str | None = None
    for event in events:
        if not isinstance(event, dict):
            errors.append("Lifecycle replay contains a non-object event")
            continue
        event_case_id = str(event.get("case_id") or "")
        if event_case_id != issue_id:
            errors.append(
                f"Lifecycle replay contains an event for another lifecycle case: {event_case_id or '<missing>'}"
            )
        event_binding = event.get("store_binding")
        if not isinstance(event_binding, str) or not event_binding:
            errors.append(f"Lifecycle replay event {event.get('sequence', '<unknown>')} has no store binding")
        elif store_binding is None:
            store_binding = event_binding
        elif event_binding != store_binding:
            errors.append(f"Lifecycle replay event {event.get('sequence', '<unknown>')} changes store binding")
        try:
            sequence = int(event.get("sequence", 0) or 0)
        except (TypeError, ValueError):
            errors.append("Lifecycle replay contains a non-numeric sequence")
            sequence = expected_sequence
        if sequence != expected_sequence:
            errors.append(f"Lifecycle replay sequence mismatch: expected {expected_sequence}, got {sequence}")
        if event.get("previous_hash") != previous_hash:
            errors.append(f"Lifecycle replay event {sequence} has an invalid previous hash")
        record_hash = str(event.get("record_hash") or "")
        record_mac = str(event.get("record_mac") or "")
        if not re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", record_mac):
            errors.append(f"Lifecycle replay event {sequence} has no valid record MAC envelope")
        material = dict(event)
        material.pop("record_hash", None)
        material.pop("record_mac", None)
        if not record_hash or sha256_bytes(canonical_json(material)) != record_hash:
            errors.append(f"Lifecycle replay event {sequence} has an invalid record hash")
        state = event.get("state") if isinstance(event.get("state"), dict) else {}
        if event.get("current_record_hash") != sha256_bytes(canonical_json(state)):
            errors.append(f"Lifecycle replay event {sequence} has an invalid current record hash")
        event_subject = event.get("subject") if isinstance(event.get("subject"), dict) else {}
        if event.get("subject_fingerprint") != canonical_subject_fingerprint(event_subject):
            errors.append(f"Lifecycle replay event {sequence} has an invalid subject fingerprint")
        if event.get("actor") != LIFECYCLE_CONTROLLER_ID:
            errors.append(f"Lifecycle replay event {sequence} has an unauthorized controller actor")
        controller_identity = event.get("controller_identity")
        if not isinstance(controller_identity, dict):
            errors.append(f"Lifecycle replay event {sequence} has no controller identity")
        else:
            if controller_identity.get("controller_id") != LIFECYCLE_CONTROLLER_ID:
                errors.append(f"Lifecycle replay event {sequence} has an unauthorized controller identity")
            if controller_identity.get("controller_type") != LIFECYCLE_CONTROLLER_TYPE:
                errors.append(f"Lifecycle replay event {sequence} has an unauthorized controller type")
            for field in ("identity_source", "authentication_mechanism"):
                if not str(controller_identity.get(field) or ""):
                    errors.append(f"Lifecycle replay event {sequence} has no {field}")
        if subject_from_record(state) != subject_from_record(event_subject):
            errors.append(f"Lifecycle replay event {sequence} subject does not match its state snapshot")
        if event.get("policy_hash") is not None and event.get("policy_hash") != state.get("policy_bundle_hash"):
            errors.append(f"Lifecycle replay event {sequence} policy hash does not match its state snapshot")
        if event.get("toolchain_hash") is not None and event.get("toolchain_hash") != state.get("toolchain_hash"):
            errors.append(f"Lifecycle replay event {sequence} toolchain hash does not match its state snapshot")
        try:
            event_epoch = int(event.get("subject_epoch", 0) or 0)
            subject_epoch = int(event_subject.get("subject_epoch", 0) or 0)
        except (TypeError, ValueError):
            event_epoch = previous_epoch
            subject_epoch = previous_epoch
            errors.append(f"Lifecycle replay event {sequence} has an invalid subject_epoch")
        if event_epoch != subject_epoch:
            errors.append(f"Lifecycle replay event {sequence} subject epoch mismatch")
        epoch = event_epoch
        if epoch < previous_epoch:
            errors.append("Lifecycle replay subject_epoch decreases")
        previous_epoch = max(previous_epoch, epoch)
        accepted = event.get("accepted_evidence") or []
        missing_ids = sorted(set(str(item) for item in accepted) - evidence_ids)
        if missing_ids:
            errors.append(f"Lifecycle replay references evidence absent from bundle: {', '.join(missing_ids)}")
        if evidence_by_id is not None:
            accepted_ids = {str(item) for item in accepted}
            accepted_records = [evidence_by_id[item] for item in accepted_ids if item in evidence_by_id]
            required_types = {str(item) for item in (event.get("required_evidence") or [])}
            accepted_types = {str(item.get("type") or "") for item in accepted_records}
            missing_event_types = sorted(required_types - accepted_types)
            if missing_event_types:
                errors.append(
                    f"Lifecycle replay event {sequence} does not accept its required evidence: "
                    + ", ".join(missing_event_types)
                )
            for evidence in accepted_records:
                if str(evidence.get("lifecycle_case_id") or "") != issue_id:
                    errors.append(
                        f"Lifecycle replay event {sequence} accepts evidence from another lifecycle case"
                    )
                if evidence.get("subject_epoch") != event_epoch:
                    errors.append(f"Lifecycle replay event {sequence} accepts evidence from the wrong subject_epoch")
                if evidence.get("subject_fingerprint") != event.get("subject_fingerprint"):
                    errors.append(f"Lifecycle replay event {sequence} accepts evidence from the wrong subject fingerprint")
        if str(event.get("case_id")) == issue_id:
            case_events.append(event)
            state_name = str(state.get("state") or "")
            requested_state = str(event.get("requested_state") or "")
            decision = str(event.get("decision") or "")
            prior_state = str(event.get("prior_state") or "")
            if case_state is None:
                if prior_state != "<GENESIS>" or state_name != "UNVERIFIED_REPORT" or requested_state != "UNVERIFIED_REPORT" or decision != "INITIALIZED":
                    errors.append("Lifecycle replay does not begin with an authoritative initialization")
            else:
                prior_snapshot = case_events[-2].get("state") if len(case_events) > 1 and isinstance(case_events[-2].get("state"), dict) else {}
                errors.extend(
                    f"Lifecycle replay event {sequence}: {item}"
                    for item in validate_subject_epoch_transition(prior_snapshot, state)
                )
                if prior_state != case_state:
                    errors.append(f"Lifecycle replay prior state mismatch: expected {case_state}, got {prior_state}")
                logical_state = case_resume_state if case_state == "BLOCKED" else case_state
                if decision == "PROCEED":
                    allowed = ALLOWED_TRANSITIONS.get(str(logical_state), set())
                    if state_name != requested_state or requested_state not in allowed:
                        errors.append("Lifecycle replay contains an out-of-order successful transition")
                elif decision == "BLOCKED":
                    if state_name != "BLOCKED":
                        errors.append("Lifecycle replay blocking decision does not write BLOCKED")
                elif decision == "ROLLBACK_REQUIRED":
                    if state_name != "ROLLBACK_REQUIRED":
                        errors.append("Lifecycle replay rollback decision does not write ROLLBACK_REQUIRED")
                elif decision in {"SUBJECT_BOUND", "ARTIFACT_BOUND", "SUBJECT_MUTATION_INVALIDATED_DOWNSTREAM"}:
                    if state_name not in {case_state, "BLOCKED", "ROLLBACK_REQUIRED"}:
                        errors.append("Lifecycle replay subject binding advanced the lifecycle")
                else:
                    errors.append(f"Lifecycle replay contains an unknown decision {decision!r}")
            case_state = state_name
            case_resume_state = str(state.get("resume_state") or "") or None
            if requested_state in PROTECTED_TRANSITION_STATES or state_name in PROTECTED_TRANSITION_STATES:
                authorization = event.get("transition_authorization")
                if not isinstance(authorization, dict):
                    errors.append(
                        f"Lifecycle replay event {sequence} has no signed transition authorization"
                    )
                else:
                    authorization_errors = validate_evidence_record(
                        authorization,
                        subject=event_subject,
                        minimum_trust="E6",
                        trust_roots=trust_roots,
                        require_authoritative_signature=True,
                        require_affirmative_status=True,
                    )
                    errors.extend(
                        f"Lifecycle replay event {sequence} authorization: {item}"
                        for item in authorization_errors
                    )
                    if authorization.get("type") != TRANSITION_AUTHORIZATION_TYPE:
                        errors.append(f"Lifecycle replay event {sequence} authorization type is invalid")
                    if authorization.get("producer") != TRANSITION_AUTHORIZATION_PRODUCER:
                        errors.append(f"Lifecycle replay event {sequence} authorization producer is invalid")
                    metadata = authorization.get("metadata") if isinstance(authorization.get("metadata"), dict) else {}
                    if metadata.get("event_commitment") != event_commitment(event):
                        errors.append(
                            f"Lifecycle replay event {sequence} authorization is not bound to its immutable event material"
                        )
                    if metadata.get("event_occurred_at") != event.get("occurred_at"):
                        errors.append(
                            f"Lifecycle replay event {sequence} authorization timestamp does not match the event"
                        )
                    if authorization.get("created_at") != event.get("occurred_at"):
                        errors.append(
                            f"Lifecycle replay event {sequence} authorization creation time does not match the event"
                        )
                    expected_version = len(case_events) - 1
                    expected_current_hash = case_events[-2].get("current_record_hash") if len(case_events) > 1 else None
                    expected_authorization = {
                        "case_id": issue_id,
                        "expected_version": expected_version,
                        "current_record_hash": expected_current_hash,
                        "next_record_hash": event.get("current_record_hash"),
                        "requested_state": requested_state,
                        "decision": decision,
                        "actor": event.get("actor"),
                        "idempotency_key": event.get("idempotency_key"),
                        "subject_fingerprint": event.get("subject_fingerprint"),
                        "subject_epoch": event_epoch,
                        "required_evidence": sorted(set(str(item) for item in (event.get("required_evidence") or []))),
                        "accepted_evidence": sorted(set(str(item) for item in (event.get("accepted_evidence") or []))),
                        "rejected_evidence": sorted(set(str(item) for item in (event.get("rejected_evidence") or []))),
                        "policy_hash": event.get("policy_hash"),
                        "toolchain_hash": event.get("toolchain_hash"),
                        "controller_id": LIFECYCLE_CONTROLLER_ID,
                        "controller_type": LIFECYCLE_CONTROLLER_TYPE,
                    }
                    if isinstance(controller_identity, dict):
                        expected_authorization.update(
                            {
                                "identity_source": controller_identity.get("identity_source"),
                                "authentication_mechanism": controller_identity.get("authentication_mechanism"),
                            }
                        )
                    mismatches = sorted(
                        field for field, value in expected_authorization.items()
                        if metadata.get(field) != value
                    )
                    if mismatches:
                        errors.append(
                            f"Lifecycle replay event {sequence} authorization is not bound to the exact event: "
                            + ", ".join(mismatches)
                        )
        previous_hash = record_hash or previous_hash
        expected_sequence = sequence + 1
    if not case_events:
        errors.append("Lifecycle replay has no events for the bundle issue")
        return sorted(set(errors))
    requested = [str(event.get("requested_state")) for event in case_events]
    delivery_model = str(final_subject.get("delivery_model") or HOSTED_RUNTIME_SERVICE)
    if terminal_state == "RESOLVED_NO_CODE":
        required_states = CODE_LIFECYCLE[:3]
    elif terminal_state == "ROLLBACK_REQUIRED":
        required_states = CODE_LIFECYCLE[: CODE_LIFECYCLE.index("PRODUCTION_RELEASED") + 1]
    elif terminal_state == "CLOSED" and closure_class == "PACKAGE_RELEASE":
        required_states = (
            "UNVERIFIED_REPORT", "SOURCE_OF_TRUTH_RESOLVED", "ISSUE_CLASSIFIED", "BUG_REPRODUCED",
            "ROOT_CAUSE_PROVEN", "BLAST_RADIUS_MAPPED", "CHANGE_PLANNED", "PATCH_IMPLEMENTED",
            "REGRESSION_TEST_PROVEN", "TARGETED_VALIDATION_PASS", "REGRESSION_VALIDATION_PASS",
            "DIFF_FORENSICS_PASS", "INDEPENDENT_REVIEW_PASS", "CI_PASS", "PACKAGE_RELEASED",
            "RELEASE_ARTIFACT_VERIFIED", "CONSUMER_VALIDATION_PASS", "CLOSED",
        )
    elif terminal_state == "CLOSED" and delivery_model == HYBRID and closure_class == "CODE_FIX":
        required_states = (
            "UNVERIFIED_REPORT", "SOURCE_OF_TRUTH_RESOLVED", "ISSUE_CLASSIFIED", "BUG_REPRODUCED",
            "ROOT_CAUSE_PROVEN", "BLAST_RADIUS_MAPPED", "CHANGE_PLANNED", "PATCH_IMPLEMENTED",
            "REGRESSION_TEST_PROVEN", "TARGETED_VALIDATION_PASS", "REGRESSION_VALIDATION_PASS",
            "DIFF_FORENSICS_PASS", "INDEPENDENT_REVIEW_PASS", "CI_PASS", "PACKAGE_RELEASED",
            "RELEASE_ARTIFACT_VERIFIED", "CONSUMER_VALIDATION_PASS", "STAGING_PASS",
            "READY_FOR_OWNER_RELEASE", "PRODUCTION_RELEASED", "POST_DEPLOY_VERIFIED", "CLOSED",
        )
    else:
        required_states = CODE_LIFECYCLE
    missing_states = [state for state in required_states if state not in requested]
    if missing_states:
        errors.append("Lifecycle replay is incomplete: " + ", ".join(missing_states))
    if delivery_model == PACKAGE_OR_PLUGIN:
        forbidden_runtime = {"STAGING_PASS", "READY_FOR_OWNER_RELEASE", "PRODUCTION_RELEASED", "POST_DEPLOY_VERIFIED"}
        if forbidden_runtime.intersection(requested):
            errors.append("Package-only lifecycle replay contains runtime deployment states")
    final_event = case_events[-1]
    if terminal_state == "RESOLVED_NO_CODE":
        if final_event.get("requested_state") != "RESOLVED_NO_CODE" or (final_event.get("state") or {}).get("state") != "RESOLVED_NO_CODE":
            errors.append("Lifecycle replay does not end in RESOLVED_NO_CODE")
        accepted = {str(item) for item in final_event.get("accepted_evidence") or []}
        proven_ids = {
            str(item.get("evidence_id"))
            for item in (evidence_by_id or {}).values()
            if item.get("type") == "RESOLVED_NO_CODE_PROVEN"
        }
        if not accepted & proven_ids:
            errors.append("RESOLVED_NO_CODE lifecycle must accept the proven no-code evidence")
    elif final_event.get("requested_state") not in {"CLOSED", "ROLLBACK_REQUIRED"}:
        errors.append("Lifecycle replay does not end in a legitimate terminal decision")
    if terminal_state == "CLOSED":
        if closure_class == "CODE_FIX":
            if final_event.get("prior_state") != "POST_DEPLOY_VERIFIED":
                errors.append("CODE_FIX closure must follow POST_DEPLOY_VERIFIED")
        elif closure_class == "ROLLBACK_CLOSURE":
            if final_event.get("prior_state") != "ROLLBACK_REQUIRED":
                errors.append("ROLLBACK_CLOSURE must follow ROLLBACK_REQUIRED")
            if not any(event.get("requested_state") == "ROLLBACK_REQUIRED" for event in case_events):
                errors.append("ROLLBACK_CLOSURE requires an authoritative ROLLBACK_REQUIRED event")
        elif closure_class == "PACKAGE_RELEASE":
            if delivery_model != PACKAGE_OR_PLUGIN:
                errors.append("PACKAGE_RELEASE closure requires PACKAGE_OR_PLUGIN delivery")
            if final_event.get("prior_state") != "CONSUMER_VALIDATION_PASS":
                errors.append("PACKAGE_RELEASE closure must follow CONSUMER_VALIDATION_PASS")
    if int(final_event.get("subject_epoch", 0) or 0) != int(final_subject.get("subject_epoch", 0) or 0):
        errors.append("Lifecycle replay final subject_epoch does not match the bundle")
    if final_event.get("subject_fingerprint") != canonical_subject_fingerprint(final_subject):
        errors.append("Lifecycle replay final subject fingerprint does not match the bundle")
    return sorted(set(errors))


def subject_fingerprint(lifecycle: dict[str, Any]) -> str:
    return canonical_subject_fingerprint(lifecycle)


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
    package_release = next((item for item in records if item.get("type") == "PROTECTED_PACKAGE_RELEASE"), {})
    artifact_verification = next((item for item in records if item.get("type") == "PUBLISHED_ASSET_DIGEST_VERIFIED"), {})
    consumer_validation = next((item for item in records if item.get("type") == "CONSUMER_INSTALLATION_VALIDATED"), {})
    migration = next((item for item in records if item.get("type") == "MIGRATION_LEDGER_HISTORY_GUARD_PASSED"), None)
    final_state = lifecycle.get("final_state") or lifecycle.get("state")
    delivery_model = str(lifecycle.get("delivery_model") or HOSTED_RUNTIME_SERVICE)
    change_plan = problem_case.get("change_plan") or {}
    file_reasons = change_plan.get("file_reasons") or {}
    changed_files = [
        {
            "path": str(path),
            "justification": (
                str(file_reasons.get(str(path)))
                if isinstance(file_reasons.get(str(path)), str)
                else str((file_reasons.get(str(path)) or {}).get("why") or "Recorded in the approved change plan")
            ),
        }
        for path in change_plan.get("expected_files") or []
    ]
    bundle = {
        "schema_version": 2,
        "issue_id": str(problem_case.get("case_id")),
        "original_report": problem_case.get("original_report_verbatim") or problem_case.get("report"),
        "classification": problem_case.get("classification"),
        "repository": lifecycle.get("repository"),
        "delivery_model": lifecycle.get("delivery_model"),
        "delivery_model_proof": lifecycle.get("delivery_model_proof"),
        "delivery_model_proof_digest": lifecycle.get("delivery_model_proof_digest"),
        "change_contract_hash": lifecycle.get("change_contract_hash"),
        "base_sha": lifecycle.get("base_sha"),
        "final_sha": lifecycle.get("head_sha"),
        "protected_base_sha": lifecycle.get("protected_base_sha") or lifecycle.get("base_sha"),
        "pr_head_sha": lifecycle.get("pr_head_sha") or lifecycle.get("head_sha"),
        "reviewed_diff_hash": lifecycle.get("reviewed_diff_hash") or lifecycle.get("diff_hash"),
        "merged_main_sha": lifecycle.get("merged_main_sha"),
        "merge_method": lifecycle.get("merge_method"),
        "merge_provenance": lifecycle.get("merge_provenance"),
        "post_merge_ci_run_id": lifecycle.get("post_merge_ci_run_id"),
        "policy_bundle_hash": lifecycle.get("policy_bundle_hash"),
        "toolchain_hash": lifecycle.get("toolchain_hash"),
        "authoritative_sources": problem_case.get("authoritative_sources") or [],
        "source_conflicts": problem_case.get("source_conflicts") or [],
        "unresolved_ambiguities": problem_case.get("unresolved_ambiguities") or [],
        "reproduction": problem_case.get("reproduction") or {},
        "root_cause": problem_case.get("root_cause") or {},
        "blast_radius": problem_case.get("blast_radius") or {},
        "risk": lifecycle.get("risk_class") or lifecycle.get("risk"),
        "risk_class": lifecycle.get("risk_class"),
        "domains": list(lifecycle.get("domains") or problem_case.get("domains") or []),
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
        "production_release": production.get("metadata") or (None if delivery_model == PACKAGE_OR_PLUGIN else {}),
        "staging": staging.get("metadata") if staging else None,
        "package_release": package_release.get("metadata") or (None if delivery_model not in {PACKAGE_OR_PLUGIN, HYBRID} else {}),
        "artifact_verification": artifact_verification.get("metadata") or (None if delivery_model not in {PACKAGE_OR_PLUGIN, HYBRID} else {}),
        "consumer_validation": consumer_validation.get("metadata") or (None if delivery_model not in {PACKAGE_OR_PLUGIN, HYBRID} else {}),
        "migration": migration.get("metadata") if migration else None,
        "release_fingerprint": lifecycle.get("release_fingerprint"),
        "artifact_digest": lifecycle.get("artifact_digest"),
        "sbom_digest": lifecycle.get("sbom_digest"),
        "provenance_digest": lifecycle.get("provenance_digest"),
        "attestation_digest": lifecycle.get("attestation_digest"),
        "production_release_id": lifecycle.get("production_release_id"),
        "deployed_revision": lifecycle.get("deployed_revision"),
        "artifact_identity": lifecycle.get("artifact_identity"),
        "post_deploy_verification": next((item.get("metadata") or {} for item in records if item.get("type") == "ORIGINAL_PROBLEM_PRODUCTION_VERIFIED"), None if delivery_model == PACKAGE_OR_PLUGIN else {}),
        "final_state": final_state,
        "closure_class": (
            "RESOLVED_NO_CODE" if final_state == "RESOLVED_NO_CODE"
            else "ROLLBACK_CLOSURE" if final_state == "ROLLBACK_REQUIRED" or lifecycle.get("closure_class") == "ROLLBACK_CLOSURE"
            else "PACKAGE_RELEASE" if delivery_model == PACKAGE_OR_PLUGIN and final_state == "CLOSED"
            else "CODE_FIX"
        ),
        "rollback_closure": next((item.get("metadata") or {} for item in records if item.get("type") == "ROLLBACK_COMPLETED"), {}),
        "subject_fingerprint": fingerprint,
        "subject_epoch": lifecycle.get("subject_epoch", 0),
        "subject_version": lifecycle.get("subject_version", 1),
        "lifecycle_events": copy.deepcopy(lifecycle.get("lifecycle_events") or lifecycle.get("transition_events") or []),
        "evidence_records": records,
        "claim_boundary": "A bundle is a subject-bound record. It does not create protected authority, deployment, or runtime evidence.",
    }
    return bundle


def validate_evidence_bundle(
    bundle: dict[str, Any],
    *,
    bundle_schema: dict[str, Any],
    evidence_schema: dict[str, Any],
    trust_roots: Any = None,
    policy: dict[str, Any] | None = None,
) -> list[str]:
    errors = list(validate_instance(bundle, bundle_schema))
    if policy is not None:
        errors.extend(validate_policy_safety(policy))
    records = bundle.get("evidence_records") or []
    subject = _bundle_subject(bundle)
    subject_validation = validate_subject(subject, require_merge_provenance=bool(subject.get("merged_main_sha")))
    errors.extend(subject_validation.errors)
    if bundle.get("subject_fingerprint") != subject_validation.fingerprint:
        errors.append("Evidence bundle subject_fingerprint is not bound to its complete subject")

    final_state = str(bundle.get("final_state") or "")
    closure_class = str(bundle.get("closure_class") or ("RESOLVED_NO_CODE" if final_state == "RESOLVED_NO_CODE" else "CODE_FIX"))
    delivery_model = str(bundle.get("delivery_model") or "")
    if delivery_model == PACKAGE_OR_PLUGIN and (final_state == "ROLLBACK_REQUIRED" or closure_class == "ROLLBACK_CLOSURE"):
        errors.append("Package-only delivery cannot claim runtime rollback closure; revoke or replace the release instead")
    if final_state in {"CLOSED", "ROLLBACK_REQUIRED", "RESOLVED_NO_CODE"} and not is_host_accepted_trust_roots(trust_roots):
        errors.append(
            "Terminal evidence-bundle verification requires host-accepted trust-root custody; "
            "local trust-root values are verification fixtures only"
        )
    if final_state in {"CLOSED", "ROLLBACK_REQUIRED", "RESOLVED_NO_CODE"} and policy is None:
        errors.append("Terminal evidence-bundle verification requires the authoritative policy bundle")
    if final_state == "RESOLVED_NO_CODE":
        if closure_class != "RESOLVED_NO_CODE":
            errors.append("RESOLVED_NO_CODE must declare the RESOLVED_NO_CODE closure class")
        if str(bundle.get("classification") or "") in {"CONFIRMED_BUG", "CONFIGURATION_ISSUE", "SECURITY_INCIDENT", "PERFORMANCE_REGRESSION"}:
            errors.append("RESOLVED_NO_CODE cannot use a code-fix classification")
        proven = [item for item in records if isinstance(item, dict) and item.get("type") == "RESOLVED_NO_CODE_PROVEN"]
        if not proven:
            errors.append("RESOLVED_NO_CODE requires RESOLVED_NO_CODE_PROVEN evidence")
        else:
            for item in proven:
                errors.extend(
                    validate_evidence_record(
                        item,
                        schema=evidence_schema,
                        subject=subject,
                        minimum_trust="E3",
                        trust_roots=trust_roots,
                        require_authoritative_signature=True,
                        require_affirmative_status=True,
                    )
                )
                errors.extend(_subject_lineage_errors(item, subject, "RESOLVED_NO_CODE_PROVEN"))
        lifecycle_events = bundle.get("lifecycle_events")
        if not isinstance(lifecycle_events, list) or not lifecycle_events:
            errors.append("Terminal bundle must contain the authoritative lifecycle event replay")
        else:
            errors.extend(
                _validate_lifecycle_replay(
                    lifecycle_events,
                    issue_id=str(bundle.get("issue_id")),
                    final_subject=subject,
                    evidence_ids={str(item.get("evidence_id")) for item in records if isinstance(item, dict) and item.get("evidence_id")},
                    terminal_state=final_state,
                    closure_class=closure_class,
                    trust_roots=trust_roots,
                    evidence_by_id={
                        str(item.get("evidence_id")): item
                        for item in records
                        if isinstance(item, dict) and item.get("evidence_id")
                    },
                )
            )
        return sorted(set(errors))

    if final_state not in {"CLOSED", "ROLLBACK_REQUIRED"}:
        errors.append("Evidence bundle has no legitimate terminal class")
    if final_state == "CLOSED" and closure_class not in {"CODE_FIX", "PACKAGE_RELEASE", "ROLLBACK_CLOSURE"}:
        errors.append("CLOSED bundle has an unsupported closure_class")
    if final_state == "ROLLBACK_REQUIRED" and closure_class != "ROLLBACK_CLOSURE":
        errors.append("ROLLBACK_REQUIRED bundle must declare ROLLBACK_CLOSURE")

    minimum_by_type = {
        "INDEPENDENT_REVIEW_COMPLETED": "E3",
        "PROTECTED_CI": "E3",
        "REQUIRED_CHECKS_VERIFIED": "E3",
        "POST_MERGE_CI_PROVEN": "E3",
        "RELEASE_FINGERPRINT_VERIFIED": "E4",
        "SIGNED_RELEASE_MANIFEST": "E4",
        "SBOM_VERIFIED": "E4",
        "ARTIFACT_ATTESTATION_VERIFIED": "E4",
        "BUILD_PROVENANCE_VERIFIED": "E4",
        "STAGING_SMOKE_PASSED": "E5",
        "ORIGINAL_PROBLEM_STAGING_VERIFIED": "E5",
        "PROTECTED_RELEASE_AUTHORIZATION": "E6",
        "PROTECTED_SUPERVISOR_APPROVAL": "E6",
        "PRODUCTION_RELEASE_COMPLETED": "E5",
        "EXPECTED_DIGEST_RUNNING": "E5",
        "ORIGINAL_PROBLEM_PRODUCTION_VERIFIED": "E5",
        "PRODUCTION_HEALTH": "E5",
        "SYNTHETIC_TRANSACTION": "E5",
        "OBSERVATION_WINDOW": "E5",
        "PROTECTED_PACKAGE_RELEASE": "E4",
        "PUBLISHED_ASSET_DIGEST_VERIFIED": "E4",
        "PUBLISHED_ASSET_METADATA_VERIFIED": "E4",
        "CONSUMER_INSTALLATION_VALIDATED": "E4",
        "PACKAGED_REGRESSIONS_PASSED": "E4",
        "PACKAGE_CONTENT_SECURITY_VERIFIED": "E4",
        "ROLLBACK_COMPLETED": "E5",
        "POST_ROLLBACK_HEALTH_VERIFIED": "E5",
    }
    seen_ids: set[str] = set()
    seen_receipt_ids: set[str] = set()
    duplicate_ids: set[str] = set()
    valid_types: set[str] = set()
    valid_evidence_ids: set[str] = set()

    policy_minimum_by_type: dict[str, str] = {}
    gate_names = (
        "PATCH_IMPLEMENTED",
        "REGRESSION_TEST_PROVEN",
        "TARGETED_VALIDATION_PASS",
        "REGRESSION_VALIDATION_PASS",
        "DIFF_FORENSICS_PASS",
        "INDEPENDENT_REVIEW_PASS",
        "CI_PASS",
        "PACKAGE_RELEASED",
        "RELEASE_ARTIFACT_VERIFIED",
        "CONSUMER_VALIDATION_PASS",
        "STAGING_PASS",
        "READY_FOR_OWNER_RELEASE",
        "PRODUCTION_RELEASED",
        "POST_DEPLOY_VERIFIED",
        "CLOSED",
        "ROLLBACK_CLOSURE",
    )
    risk_keys = {str(bundle.get("risk") or ""), str(bundle.get("risk_class") or "")}
    domains = {str(item).upper() for item in bundle.get("domains") or []}
    unknown_domains = sorted(domains - VALID_DOMAINS)
    if unknown_domains:
        errors.append("Evidence bundle contains unknown domains: " + ", ".join(unknown_domains))
    for gate_name in gate_names:
        gate = ((policy or {}).get("gates") or {}).get(gate_name) or {}
        gate_minimum = str(gate.get("minimum_trust", "E2"))
        gate_types = set(str(item) for item in gate.get("required_evidence", []) or [])
        for risk_key in risk_keys:
            risk_requirements = (gate.get("by_risk") or {}).get(risk_key) or []
            if isinstance(risk_requirements, dict):
                gate_minimum = max(
                    (gate_minimum, str(risk_requirements.get("minimum_trust", gate_minimum))),
                    key=lambda value: TRUST_ORDER.get(value, -1),
                )
                gate_types.update(str(item) for item in risk_requirements.get("required_evidence", []) or [])
                gate_types.update(str(item) for item in risk_requirements.get("required", []) or [])
            else:
                gate_types.update(str(item) for item in risk_requirements)
        for domain in domains:
            gate_types.update(str(item) for item in (gate.get("by_domain") or {}).get(domain, []) or [])
            profile = ((policy or {}).get("domain_profiles") or {}).get(domain) or {}
            if gate_name in {
                "TARGETED_VALIDATION_PASS",
                "REGRESSION_VALIDATION_PASS",
                "STAGING_PASS",
                "READY_FOR_OWNER_RELEASE",
                "PRODUCTION_RELEASED",
                "POST_DEPLOY_VERIFIED",
            }:
                gate_types.update(str(item) for item in profile.get("required_checks", []) or [])
                profile_minimum = str(profile.get("minimum_trust") or "")
                if TRUST_ORDER.get(profile_minimum, -1) > TRUST_ORDER.get(gate_minimum, -1):
                    gate_minimum = profile_minimum
        model_gate = (gate.get("by_delivery_model") or {}).get(delivery_model) or {}
        if isinstance(model_gate, dict):
            model_minimum = str(model_gate.get("minimum_trust", gate_minimum))
            gate_minimum = max(
                (gate_minimum, model_minimum),
                key=lambda value: TRUST_ORDER.get(value, -1),
            )
            gate_types.update(str(item) for item in model_gate.get("required_evidence", []) or [])
        for evidence_type in gate_types:
            previous_minimum = policy_minimum_by_type.get(evidence_type, "E2")
            policy_minimum_by_type[evidence_type] = max(
                (previous_minimum, gate_minimum),
                key=lambda value: TRUST_ORDER.get(value, -1),
            )
    progressive = ((policy or {}).get("progressive_exposure") or {}).get(str(bundle.get("risk_class") or "")) or {}
    if isinstance(progressive, dict):
        progressive_minimum = str(((policy or {}).get("gates") or {}).get("READY_FOR_OWNER_RELEASE", {}).get("minimum_trust", "E2"))
        for evidence_type in progressive.get("required_evidence", []) or []:
            policy_minimum_by_type[str(evidence_type)] = max(
                (policy_minimum_by_type.get(str(evidence_type), "E2"), progressive_minimum),
                key=lambda value: TRUST_ORDER.get(value, -1),
            )
    for item in records:
        if not isinstance(item, dict):
            errors.append("Evidence bundle contains a non-object evidence record")
            continue
        evidence_id = str(item.get("evidence_id") or "<missing>")
        if evidence_id in seen_ids:
            duplicate_ids.add(evidence_id)
        seen_ids.add(evidence_id)
        evidence_type = str(item.get("type") or "")
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        receipt_id = str(metadata.get("receipt_id") or "")
        if receipt_id:
            if receipt_id in seen_receipt_ids:
                errors.append(f"Duplicate machine receipt ID indicates replayed evidence: {receipt_id}")
            seen_receipt_ids.add(receipt_id)
        minimum = max(
            (minimum_by_type.get(evidence_type, "E2"), policy_minimum_by_type.get(evidence_type, "E2")),
            key=lambda value: TRUST_ORDER.get(value, -1),
        )
        record_subject = subject_from_record(item)
        record_errors = validate_evidence_record(
            item,
            schema=evidence_schema,
            subject=record_subject,
            minimum_trust=minimum,
            trust_roots=trust_roots,
            require_authoritative_signature=TRUST_ORDER.get(minimum, 0) >= TRUST_ORDER["E3"],
            require_affirmative_status=True,
        )
        record_errors.extend(_subject_lineage_errors(item, subject, evidence_type))
        errors.extend(record_errors)
        if not record_errors:
            valid_types.add(evidence_type)
            valid_evidence_ids.add(evidence_id)
    if duplicate_ids:
        errors.append("Duplicate evidence IDs are prohibited: " + ", ".join(sorted(duplicate_ids)))

    if closure_class == "ROLLBACK_CLOSURE":
        required_types = set(ROLLBACK_EVIDENCE_TYPES)
    elif closure_class == "PACKAGE_RELEASE":
        required_types = {
            "CANDIDATE_PATCH_CREATED",
            "REGRESSION_RED_GREEN_PROVEN",
            "TARGETED_VALIDATION_PASSED",
            "FULL_REGRESSION_VALIDATION_PASSED",
            "DIFF_FORENSICS_PASSED",
            "INDEPENDENT_REVIEW_COMPLETED",
            "PROTECTED_CI",
            "REQUIRED_CHECKS_VERIFIED",
            "PROTECTED_PACKAGE_RELEASE",
            "RELEASE_FINGERPRINT_VERIFIED",
            "SIGNED_RELEASE_MANIFEST",
            "SBOM_VERIFIED",
            "ARTIFACT_ATTESTATION_VERIFIED",
            "BUILD_PROVENANCE_VERIFIED",
            "PUBLISHED_ASSET_DIGEST_VERIFIED",
            "PUBLISHED_ASSET_METADATA_VERIFIED",
            "CONSUMER_INSTALLATION_VALIDATED",
            "PACKAGED_REGRESSIONS_PASSED",
            "PACKAGE_CONTENT_SECURITY_VERIFIED",
        }
        if subject.get("merged_main_sha"):
            required_types.add("POST_MERGE_CI_PROVEN")
        package_gate = (((policy or {}).get("gates") or {}).get("CLOSED") or {}).get("by_delivery_model", {}).get(PACKAGE_OR_PLUGIN, {})
        if isinstance(package_gate, dict):
            required_types.update(str(item) for item in package_gate.get("required_evidence", []) or [])
    else:
        required_types = {
            "CANDIDATE_PATCH_CREATED",
            "REGRESSION_RED_GREEN_PROVEN",
            "TARGETED_VALIDATION_PASSED",
            "FULL_REGRESSION_VALIDATION_PASSED",
            "DIFF_FORENSICS_PASSED",
            "INDEPENDENT_REVIEW_COMPLETED",
            "PROTECTED_CI",
            "REQUIRED_CHECKS_VERIFIED",
            "STAGING_SMOKE_PASSED",
            "ORIGINAL_PROBLEM_STAGING_VERIFIED",
            "RELEASE_FINGERPRINT_VERIFIED",
            "SIGNED_RELEASE_MANIFEST",
            "SBOM_VERIFIED",
            "ARTIFACT_ATTESTATION_VERIFIED",
            "BUILD_PROVENANCE_VERIFIED",
            "ROLLBACK_READY",
            "ROLLBACK_REHEARSAL_VERIFIED",
            "OBSERVABILITY_READY",
            "SYNTHETIC_TRANSACTION_DEFINED",
            "PROTECTED_SUPERVISOR_APPROVAL",
            "PROTECTED_RELEASE_AUTHORIZATION",
            "PRODUCTION_RELEASE_COMPLETED",
            "EXPECTED_DIGEST_RUNNING",
            "ORIGINAL_PROBLEM_PRODUCTION_VERIFIED",
            "PRODUCTION_HEALTH",
            "SYNTHETIC_TRANSACTION",
            "OBSERVATION_WINDOW",
        }
        if subject.get("merged_main_sha"):
            required_types.add("POST_MERGE_CI_PROVEN")
        for domain in domains:
            profile = ((policy or {}).get("domain_profiles") or {}).get(domain) or {}
            if profile.get("required_checks"):
                required_types.update(str(item) for item in profile["required_checks"])
        ready_gate = ((policy or {}).get("gates") or {}).get("READY_FOR_OWNER_RELEASE") or {}
        for risk_key in risk_keys:
            risk_requirements = (ready_gate.get("by_risk") or {}).get(risk_key) or []
            if isinstance(risk_requirements, dict):
                required_types.update(risk_requirements.get("required_evidence", []) or [])
                required_types.update(risk_requirements.get("required", []) or [])
            else:
                required_types.update(risk_requirements)
        if isinstance(progressive, dict):
            required_types.update(progressive.get("required_evidence", []) or [])
        if delivery_model == HYBRID:
            required_types.update({
                "PROTECTED_PACKAGE_RELEASE",
                "RELEASE_FINGERPRINT_VERIFIED",
                "SIGNED_RELEASE_MANIFEST",
                "SBOM_VERIFIED",
                "ARTIFACT_ATTESTATION_VERIFIED",
                "BUILD_PROVENANCE_VERIFIED",
                "PUBLISHED_ASSET_DIGEST_VERIFIED",
                "PUBLISHED_ASSET_METADATA_VERIFIED",
                "CONSUMER_INSTALLATION_VALIDATED",
                "PACKAGED_REGRESSIONS_PASSED",
                "PACKAGE_CONTENT_SECURITY_VERIFIED",
            })
    missing = sorted(required_types - valid_types)
    if missing:
        errors.append("Terminal bundle is missing independently validated gate evidence: " + ", ".join(missing))
    for item in records:
        if not isinstance(item, dict) or item.get("type") not in required_types:
            continue
        producer = str(item.get("producer") or "")
        if producer not in TERMINAL_EVIDENCE_PRODUCERS:
            errors.append(
                f"Terminal gate evidence {item.get('type')} must come from a controller or protected platform"
            )

    if closure_class == "PACKAGE_RELEASE" or (delivery_model == HYBRID and closure_class == "CODE_FIX"):
        if closure_class == "PACKAGE_RELEASE" and delivery_model != PACKAGE_OR_PLUGIN:
            errors.append("PACKAGE_RELEASE bundle must declare PACKAGE_OR_PLUGIN delivery_model")
        if not isinstance(bundle.get("delivery_model_proof"), dict) or not bundle.get("delivery_model_proof_digest"):
            errors.append("PACKAGE_RELEASE bundle requires source-derived delivery model proof")
        else:
            errors.extend(
                validate_delivery_model_proof(
                    delivery_model,
                    bundle.get("delivery_model_proof"),
                    bundle.get("delivery_model_proof_digest"),
                )
            )
        for field in (("staging", "production_release", "production_release_id", "deployed_revision", "post_deploy_verification") if closure_class == "PACKAGE_RELEASE" else ()):
            value = bundle.get(field)
            if value not in (None, {}, ""):
                errors.append(f"PACKAGE_RELEASE bundle cannot contain runtime field {field}")
        for item in records:
            if not isinstance(item, dict):
                continue
            evidence_type = str(item.get("type") or "")
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            if evidence_type in {
                "PROTECTED_PACKAGE_RELEASE", "RELEASE_FINGERPRINT_VERIFIED", "SIGNED_RELEASE_MANIFEST",
                "SBOM_VERIFIED", "ARTIFACT_ATTESTATION_VERIFIED", "BUILD_PROVENANCE_VERIFIED",
            }:
                errors.extend(
                    validate_package_release_metadata(
                        metadata,
                        head_sha=bundle.get("final_sha"),
                        artifact_digest=bundle.get("artifact_digest"),
                        merged_main_sha=bundle.get("merged_main_sha"),
                    )
                )
            elif evidence_type in {"PUBLISHED_ASSET_DIGEST_VERIFIED", "PUBLISHED_ASSET_METADATA_VERIFIED"}:
                errors.extend(
                    validate_published_asset_metadata(
                        metadata,
                        head_sha=bundle.get("final_sha"),
                        artifact_digest=bundle.get("artifact_digest"),
                        merged_main_sha=bundle.get("merged_main_sha"),
                    )
                )
            elif evidence_type in {
                "CONSUMER_INSTALLATION_VALIDATED", "PACKAGED_REGRESSIONS_PASSED", "PACKAGE_CONTENT_SECURITY_VERIFIED",
            }:
                errors.extend(
                    validate_consumer_validation_metadata(
                        metadata,
                        artifact_digest=bundle.get("artifact_digest"),
                    )
                )

    if closure_class != "ROLLBACK_CLOSURE" and bundle.get("artifact_digest"):
        errors.extend(validate_artifact_chain({
            "source_sha": bundle.get("merged_main_sha") or bundle.get("final_sha"),
            "merged_main_sha": bundle.get("merged_main_sha"),
            "artifact_digest": bundle.get("artifact_digest"),
            "release_fingerprint": bundle.get("release_fingerprint"),
            "sbom_digest": bundle.get("sbom_digest"),
            "provenance_digest": bundle.get("provenance_digest"),
            "attestation_digest": bundle.get("attestation_digest"),
            "artifact_identity": bundle.get("artifact_identity"),
        }, head_sha=bundle.get("final_sha"), merged_main_sha=bundle.get("merged_main_sha"), artifact_digest=bundle.get("artifact_digest")))
    production_metadata = bundle.get("production_release") if isinstance(bundle.get("production_release"), dict) else {}
    if closure_class not in {"ROLLBACK_CLOSURE", "PACKAGE_RELEASE"} and production_metadata:
        errors.extend(
            validate_production_release_metadata(
                production_metadata,
                head_sha=bundle.get("final_sha"),
                merged_main_sha=bundle.get("merged_main_sha"),
                pr_head_sha=bundle.get("pr_head_sha"),
                artifact_digest=bundle.get("artifact_digest"),
            )
        )
    if closure_class == "ROLLBACK_CLOSURE":
        rollback_metadata = bundle.get("rollback_closure") if isinstance(bundle.get("rollback_closure"), dict) else {}
        errors.extend(validate_rollback_closure(rollback_metadata, domains=bundle.get("domains") or [], policy=policy))
    elif closure_class == "CODE_FIX" and final_state == "CLOSED":
        for item in records:
            if not isinstance(item, dict):
                continue
            if item.get("type") in {"ORIGINAL_PROBLEM_PRODUCTION_VERIFIED", "PRODUCTION_HEALTH"}:
                errors.extend(
                    validate_post_deploy_metadata(
                        item.get("metadata"),
                        artifact_digest=bundle.get("artifact_digest"),
                        deployed_revision=bundle.get("deployed_revision"),
                    )
                )
            elif item.get("type") == "SYNTHETIC_TRANSACTION":
                errors.extend(validate_synthetic_transaction_metadata(item.get("metadata")))
            elif item.get("type") == "OBSERVATION_WINDOW":
                errors.extend(validate_observation_window_metadata(item.get("metadata")))

    lifecycle_events = bundle.get("lifecycle_events")
    if not isinstance(lifecycle_events, list) or not lifecycle_events:
        errors.append("Terminal bundle must contain the authoritative lifecycle event replay")
    else:
        errors.extend(
            _validate_lifecycle_replay(
                lifecycle_events,
                issue_id=str(bundle.get("issue_id")),
                final_subject=subject,
                evidence_ids=valid_evidence_ids,
                terminal_state=final_state,
                closure_class=closure_class,
                trust_roots=trust_roots,
                evidence_by_id={
                    str(item.get("evidence_id")): item
                    for item in records
                    if isinstance(item, dict) and str(item.get("evidence_id") or "") in valid_evidence_ids
                },
            )
        )
    return sorted(set(errors))
