from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from .crypto import sign_evidence
from .orchestrator import ContinuityStore
from .util import sha256_bytes, canonical_json, utc_now

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
        "policy_bundle_hash", "toolchain_hash",
    }
    missing = sorted(required_subject - set(subject))
    if missing:
        raise ValueError("Approval subject is incomplete: " + ", ".join(missing))
    if subject["head_sha"] != head_sha:
        raise ValueError("Approval subject head SHA mismatch")

    if reviewer_run_id:
        approval = store.record_approval_from_run(
            reviewer_run_id=reviewer_run_id, head_sha=head_sha, diff_hash=diff_hash,
            evidence_refs=evidence_refs, decision="APPROVE",
        )
        if approval["task_id"] != task_id:
            raise ValueError("Reviewer run task mismatch")
        role = approval["role"]
        session_id = approval["session_id"]
    else:
        if not role or not session_id:
            raise ValueError("reviewer_run_id is required unless legacy role and session_id are supplied")
        approval = store.record_approval(
            task_id=task_id, role=role, session_id=session_id, head_sha=head_sha,
            diff_hash=diff_hash, evidence_refs=evidence_refs, decision="APPROVE",
        )
    record: dict[str, Any] = {
        "evidence_id": f"ev-supervisor-{uuid.uuid4()}",
        "type": approval_type,
        "trust_level": "E6",
        "producer": "platform:approval-controller",
        "repository": subject["repository"],
        "change_contract_hash": subject["change_contract_hash"],
        "base_sha": subject["base_sha"],
        "head_sha": subject["head_sha"],
        "policy_bundle_hash": subject["policy_bundle_hash"],
        "toolchain_hash": subject["toolchain_hash"],
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
