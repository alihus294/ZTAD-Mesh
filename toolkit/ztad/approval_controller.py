from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from .crypto import sign_evidence
from .orchestrator import ContinuityStore
from .util import sha256_bytes, canonical_json, utc_now
from .subject import active_revision, subject_fingerprint, subject_from_record, validate_subject

APPROVAL_TYPES = {
    "PROTECTED_SUPERVISOR_APPROVAL",
    "STRONG_SUPERVISOR_MERGE_APPROVAL",
    "STRONG_SUPERVISOR_TECHNICAL_APPROVAL",
    "STRONG_SUPERVISOR_RELEASE_APPROVAL",
}


def issue_supervisor_approval_evidence(
    *,
    store: ContinuityStore,
    task_id: str,
    role: str | None = None,
    session_id: str | None = None,
    reviewer_run_id: str | None = None,
    head_sha: str,
    diff_hash: str,
    evidence_refs: list[str],
    approval_type: str,
    subject: dict[str, str],
    private_key_path: Path,
    key_id: str,
    output_path: Path | None = None,
) -> dict[str, Any]:
    """Convert a validated strong-model decision into protected E6 evidence.

    The private key belongs to this controller, never to the model session. The
    durable store validates role separation, exact SHA binding, and every
    underlying E3+ evidence identifier before this function signs anything.
    """

    if approval_type not in APPROVAL_TYPES:
        raise ValueError("Unsupported supervisor approval type")
    required_subject = {
        "repository", "change_contract_hash", "base_sha", "head_sha",
        "protected_base_sha", "pr_head_sha", "reviewed_diff_hash",
        "policy_bundle_hash", "toolchain_hash", "subject_epoch", "subject_fingerprint",
    }
    missing = sorted(required_subject - set(subject))
    if missing:
        raise ValueError("Approval subject is incomplete: " + ", ".join(missing))
    if subject["head_sha"] != head_sha:
        raise ValueError("Approval subject head SHA mismatch")
    canonical = subject_from_record(subject)
    subject_errors = validate_subject(canonical, require_merge_provenance=bool(canonical.get("merged_main_sha"))).errors
    if subject_errors:
        raise ValueError("Approval subject is invalid: " + "; ".join(subject_errors))
    if subject_fingerprint(canonical) != subject.get("subject_fingerprint"):
        raise ValueError("Approval subject fingerprint mismatch")

    if not reviewer_run_id:
        raise PermissionError(
            "A protected approval must derive role and session identity from a stored reviewer run; "
            "legacy caller-supplied role/session arguments cannot authorize approval"
        )
    approval = store.record_approval_from_run(
        reviewer_run_id=reviewer_run_id, head_sha=head_sha, diff_hash=diff_hash,
        evidence_refs=evidence_refs, decision="APPROVE",
        subject_epoch=int(subject["subject_epoch"]),
        subject_fingerprint=subject["subject_fingerprint"],
        policy_bundle_hash=subject["policy_bundle_hash"],
        toolchain_hash=subject["toolchain_hash"],
    )
    if approval["task_id"] != task_id:
        raise ValueError("Reviewer run task mismatch")
    if role is not None and role != approval["role"]:
        raise PermissionError("Caller-supplied role does not match stored reviewer-run identity")
    if session_id is not None and session_id != approval["session_id"]:
        raise PermissionError("Caller-supplied session does not match stored reviewer-run identity")
    role = approval["role"]
    session_id = approval["session_id"]
    record: dict[str, Any] = {
        "evidence_id": f"ev-supervisor-{uuid.uuid4()}",
        "type": approval_type,
        "trust_level": "E6",
        "producer": "platform:approval-controller",
        "repository": subject["repository"],
        "change_contract_hash": subject["change_contract_hash"],
        "base_sha": subject["base_sha"],
        "head_sha": subject["head_sha"],
        "protected_base_sha": subject.get("protected_base_sha") or subject["base_sha"],
        "pr_head_sha": subject.get("pr_head_sha") or subject["head_sha"],
        "reviewed_diff_hash": subject.get("reviewed_diff_hash") or diff_hash,
        "merged_main_sha": subject.get("merged_main_sha"),
        "merge_method": subject.get("merge_method"),
        "merge_provenance": subject.get("merge_provenance"),
        "post_merge_ci_run_id": subject.get("post_merge_ci_run_id"),
        "policy_bundle_hash": subject["policy_bundle_hash"],
        "toolchain_hash": subject["toolchain_hash"],
        "subject_epoch": subject["subject_epoch"],
        "subject_version": subject.get("subject_version", 1),
        "subject_fingerprint": subject["subject_fingerprint"],
        "environment": "supervisor-approval-controller",
        "command_id": None,
        "exit_code": None,
        "status": "APPROVED",
        "output_hash": diff_hash,
        "artifact_digest": subject.get("artifact_digest"),
        "created_at": utc_now(),
        "expires_at": None,
        "invalidated_by": [],
        "signature_or_attestation": None,
        "metadata": {
            "approval_id": approval["approval_id"],
            "task_id": task_id,
            "review_role": role,
            "review_session_id": session_id,
            "reviewer_run_id": reviewer_run_id,
            "diff_hash": diff_hash,
            "underlying_evidence_refs": sorted(set(evidence_refs)),
            "subject_epoch": subject["subject_epoch"],
            "subject_fingerprint": subject["subject_fingerprint"],
            "policy_bundle_hash": subject["policy_bundle_hash"],
            "toolchain_hash": subject["toolchain_hash"],
        },
    }
    signed = sign_evidence(record, private_key_path=private_key_path, key_id=key_id)
    store.register_evidence(
        evidence_id=signed["evidence_id"],
        task_id=task_id,
        head_sha=head_sha,
        evidence_type=approval_type,
        trust_level="E6",
        status="APPROVED",
        producer="platform:approval-controller",
        payload={
            "signature_hash": sha256_bytes(canonical_json(signed["signature_or_attestation"])),
            "approval_id": approval["approval_id"],
        },
    )
    if output_path is not None:
        import json
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"approval": approval, "signed_evidence": signed, "output_path": str(output_path) if output_path else None}
