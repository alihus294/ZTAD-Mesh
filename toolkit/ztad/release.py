from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from .evidence import TRUST_ORDER, validate_evidence_record
from .schema_validation import validate_instance
from .util import sha256_file

TARGET_TO_GATE = {"merge": "MERGE", "staging": "STAGING", "release": "RELEASE", "production": "PRODUCTION"}
SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
SUPERVISOR_APPROVAL_PREFIX = "STRONG_SUPERVISOR_"
ALLOWED_APPROVAL_PRODUCER_PREFIXES = ("platform:approval-controller",)


def _merge_gate_config(policy: dict[str, Any], target: str, risk: str) -> dict[str, Any]:
    gate_name = TARGET_TO_GATE[target]
    gate = dict(((policy.get("gates") or {}).get(gate_name) or {}))
    risk_gate = dict(((gate.get("by_risk") or {}).get(risk) or {}))
    return {
        "gate": gate_name,
        "minimum_trust": risk_gate.get("minimum_trust", gate.get("minimum_trust", "E3")),
        "required_evidence": sorted(set(gate.get("required_evidence", []) or []) | set(risk_gate.get("required_evidence", []) or [])),
        "required_platform_controls": sorted(set(gate.get("required_platform_controls", []) or []) | set(risk_gate.get("required_platform_controls", []) or [])),
        "required_approvals": sorted(set(gate.get("required_approvals", []) or []) | set(risk_gate.get("required_approvals", []) or [])),
    }


def platform_control_evidence_type(control: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", control).strip("_").upper()
    return f"PLATFORM_{normalized}_VERIFIED"


def evaluate_release_readiness(
    *,
    repository: str,
    contract_path: Path,
    base_sha: str,
    head_sha: str,
    toolchain_hash: str,
    policy_bundle_hash: str,
    risk: str,
    target: str,
    evidence_records: Iterable[dict[str, Any]],
    evidence_schema: dict[str, Any],
    release_policy: dict[str, Any],
    trust_roots: dict[str, Any] | None,
    release_manifest: dict[str, Any] | None = None,
    release_manifest_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if target not in TARGET_TO_GATE:
        raise ValueError(f"Unknown readiness target: {target}")
    if risk not in {"R0", "R1", "R2", "R3", "R4"}:
        raise ValueError(f"Unknown risk: {risk}")
    for label, value in (("base", base_sha), ("head", head_sha)):
        if not isinstance(value, str) or not SHA_RE.fullmatch(value):
            raise ValueError(f"{label} must be an exact lowercase 40- or 64-character hexadecimal revision")
    for label, value in (("toolchain_hash", toolchain_hash), ("policy_bundle_hash", policy_bundle_hash)):
        if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError(f"{label} must be a sha256 digest")

    contract_hash = sha256_file(contract_path)
    gate = _merge_gate_config(release_policy, target, risk)
    artifact_digest: str | None = None
    manifest_errors: list[str] = []
    artifact_target = target in {"staging", "release", "production"}
    if artifact_target:
        if release_manifest is None:
            manifest_errors.append("Release manifest is required for artifact-bearing targets")
        else:
            if release_manifest_schema is not None:
                manifest_errors.extend(validate_instance(release_manifest, release_manifest_schema))
            artifact_digest = release_manifest.get("artifact_digest")
            exact = {
                "repository": repository,
                "change_contract_hash": contract_hash,
                "merged_sha": head_sha,
                "risk": risk,
                "policy_bundle_hash": policy_bundle_hash,
                "toolchain_hash": toolchain_hash,
            }
            for key, expected in exact.items():
                if release_manifest.get(key) != expected:
                    manifest_errors.append(f"Release manifest {key} mismatch")
            if release_manifest.get("rollback_artifact_digest") == artifact_digest:
                manifest_errors.append("Rollback artifact must differ from the proposed artifact")

    subject: dict[str, str] = {
        "repository": repository,
        "change_contract_hash": contract_hash,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "policy_bundle_hash": policy_bundle_hash,
        "toolchain_hash": toolchain_hash,
    }
    if artifact_digest:
        subject["artifact_digest"] = artifact_digest

    records = list(evidence_records)
    seen_ids: set[str] = set()
    duplicate_ids: list[str] = []
    valid_by_type: dict[str, list[str]] = {}
    valid_record_by_id: dict[str, dict[str, Any]] = {}
    invalid: dict[str, list[str]] = {}
    valid_approvals: dict[str, list[str]] = {}
    minimum = str(gate["minimum_trust"])
    for record in records:
        evidence_id = str(record.get("evidence_id", "<missing>"))
        if evidence_id in seen_ids:
            duplicate_ids.append(evidence_id)
        seen_ids.add(evidence_id)
        errors = validate_evidence_record(
            record,
            schema=evidence_schema,
            subject=subject,
            minimum_trust=minimum,
            trust_roots=trust_roots,
            require_authoritative_signature=TRUST_ORDER.get(str(record.get("trust_level", "E0")), 0) >= TRUST_ORDER["E3"],
            require_affirmative_status=True,
        )
        evidence_type = str(record.get("type", ""))
        if not errors and evidence_type.startswith(SUPERVISOR_APPROVAL_PREFIX):
            producer = str(record.get("producer", ""))
            if str(record.get("trust_level", "E0")) != "E6":
                errors.append("Supervisor approval-controller evidence must have trust level E6")
            if not producer.startswith(ALLOWED_APPROVAL_PRODUCER_PREFIXES):
                errors.append("Supervisor approval-controller evidence has an unauthorized producer")
        if errors:
            invalid[evidence_id] = sorted(set(errors))
        else:
            valid_by_type.setdefault(evidence_type, []).append(evidence_id)
            valid_record_by_id[evidence_id] = record
            if evidence_type.startswith(SUPERVISOR_APPROVAL_PREFIX):
                valid_approvals.setdefault(evidence_type, []).append(evidence_id)

    required_platform_evidence = {
        control: platform_control_evidence_type(control) for control in gate["required_platform_controls"]
    }
    missing_evidence = [item for item in gate["required_evidence"] if not valid_by_type.get(item)]
    missing_platform_controls = {
        control: evidence_type
        for control, evidence_type in required_platform_evidence.items()
        if not valid_by_type.get(evidence_type)
    }
    missing_approvals = [item for item in gate["required_approvals"] if not valid_approvals.get(item)]

    if release_manifest is not None:
        refs = release_manifest.get("test_evidence_refs", []) or []
        if len(refs) != len(set(refs)):
            manifest_errors.append("Release manifest contains duplicate test_evidence_refs")
        missing_refs = sorted(set(str(item) for item in refs) - set(valid_record_by_id))
        if missing_refs:
            manifest_errors.append("Release manifest references missing or invalid evidence: " + ", ".join(missing_refs))

    blockers: list[str] = []
    if manifest_errors:
        blockers.append("RELEASE_MANIFEST_INVALID")
    if duplicate_ids:
        blockers.append("DUPLICATE_EVIDENCE_IDS")
    if missing_evidence:
        blockers.append("REQUIRED_EVIDENCE_MISSING")
    if missing_platform_controls:
        blockers.append("PLATFORM_CONTROLS_NOT_VERIFIED")
    if missing_approvals:
        blockers.append("SUPERVISOR_APPROVAL_REQUIRED")
    if target == "production" and artifact_digest is None:
        blockers.append("ARTIFACT_DIGEST_MISSING")

    if blockers:
        blocker_set = set(blockers)
        if blocker_set == {"SUPERVISOR_APPROVAL_REQUIRED"}:
            decision = "AUTO_SUPERVISOR_APPROVAL_REQUIRED"
        elif blocker_set <= {"REQUIRED_EVIDENCE_MISSING", "PLATFORM_CONTROLS_NOT_VERIFIED"}:
            decision = "AUTO_GENERATE_EVIDENCE"
        elif "RELEASE_MANIFEST_INVALID" in blocker_set or "DUPLICATE_EVIDENCE_IDS" in blocker_set:
            decision = "AUTO_REPLAN"
        else:
            decision = "QUARANTINE_AND_CONTINUE"
    else:
        decision = {
            "merge": "MERGE_ELIGIBLE",
            "staging": "STAGING_ELIGIBLE",
            "release": "RELEASE_ELIGIBLE",
            "production": "PRODUCTION_VERIFIED",
        }[target]

    return {
        "decision": decision,
        "target": target,
        "gate": gate["gate"],
        "risk": risk,
        "subject": subject,
        "minimum_trust": minimum,
        "required_evidence": gate["required_evidence"],
        "valid_evidence": valid_by_type,
        "invalid_evidence": invalid,
        "duplicate_evidence_ids": sorted(set(duplicate_ids)),
        "missing_evidence_types": missing_evidence,
        "required_platform_controls": required_platform_evidence,
        "missing_platform_controls": missing_platform_controls,
        "required_approvals": gate["required_approvals"],
        "valid_approval_evidence": valid_approvals,
        "missing_approvals": missing_approvals,
        "release_manifest_errors": sorted(set(manifest_errors)),
        "blockers": sorted(set(blockers)),
        "claim_boundary": (
            "Eligibility is not a merge or deployment action. A strong-model response is only a proposal. "
            "Supervisor approvals count only after a protected approval controller validates and signs exact-subject E6 evidence; "
            "a protected transition controller must execute the transition."
        ),
    }
