from __future__ import annotations

from typing import Any, Iterable

from .evidence import TRUST_ORDER, validate_evidence_record, validate_evidence_subject

SUPERVISOR_APPROVAL_PREFIX = "STRONG_SUPERVISOR_"
ALLOWED_APPROVAL_PRODUCER_PREFIXES = ("platform:approval-controller",)


def gate_requirements(policy: dict[str, Any], requested_state: str, risk: str) -> dict[str, Any]:
    gate = ((policy.get("gates", {}) or {}).get(requested_state, {}) or {})
    risk_gate = (gate.get("by_risk", {}) or {}).get(risk, {}) or {}
    risk_required = risk_gate.get("required_evidence", []) if isinstance(risk_gate, dict) else risk_gate
    required = set(gate.get("required_evidence", []) or []) | set(risk_required or [])
    if isinstance(risk_gate, list):
        required.update(risk_gate)
    return {
        "minimum_trust": str(risk_gate.get("minimum_trust", gate.get("minimum_trust", "E0")) if isinstance(risk_gate, dict) else gate.get("minimum_trust", "E0")),
        "required_evidence": sorted(required),
        "required_approvals": sorted(set(gate.get("required_approvals", []) or []) | set((risk_gate.get("required_approvals", []) if isinstance(risk_gate, dict) else []) or [])),
    }


def _evaluate_transition_validated(
    policy: dict[str, Any],
    *,
    current_state: str,
    requested_state: str,
    risk: str,
    evidence_types: Iterable[str] = (),
    approvals: Iterable[str] = (),
) -> dict[str, Any]:
    """Pure policy evaluation over already-validated evidence type sets.

    Callers exposed to agents must validate evidence records first; raw strings are
    not authority. The CLI uses evaluate_transition_from_records.
    """
    states = set(policy.get("states", []) or [])
    if current_state not in states or requested_state not in states:
        return {
            "allowed": False,
            "reasons": ["Unknown state"],
            "current_state": current_state,
            "requested_state": requested_state,
            "risk": risk,
            "minimum_trust": "E0",
            "missing_evidence": [],
            "missing_approvals": [],
        }
    transitions = policy.get("transitions", {}) or {}
    allowed_next = transitions.get(current_state, []) or []
    reasons: list[str] = []
    if requested_state not in allowed_next:
        reasons.append(f"Transition {current_state} -> {requested_state} is not allowed")
    requirements = gate_requirements(policy, requested_state, risk)
    missing_evidence = sorted(set(requirements["required_evidence"]) - set(evidence_types))
    missing_approvals = sorted(set(requirements["required_approvals"]) - set(approvals))
    if missing_evidence:
        reasons.append("Missing evidence: " + ", ".join(missing_evidence))
    if missing_approvals:
        reasons.append("Missing approvals: " + ", ".join(missing_approvals))
    return {
        "allowed": not reasons,
        "current_state": current_state,
        "requested_state": requested_state,
        "risk": risk,
        "minimum_trust": requirements["minimum_trust"],
        "missing_evidence": missing_evidence,
        "missing_approvals": missing_approvals,
        "reasons": reasons,
    }


def _validate_records_for_gate(
    records: Iterable[dict[str, Any]],
    *,
    subject: dict[str, str] | None,
    evidence_schema: dict[str, Any],
    minimum_trust: str,
    trust_roots: dict[str, Any] | None,
) -> dict[str, Any]:
    records_list = list(records)
    valid_types: set[str] = set()
    valid_approvals: set[str] = set()
    valid_ids: list[str] = []
    invalid: dict[str, list[str]] = {}
    seen: set[str] = set()
    duplicates: list[str] = []
    subject_errors = validate_evidence_subject(subject) if records_list else []
    if subject_errors:
        invalid["<subject>"] = subject_errors
        return {
            "valid_evidence_types": [],
            "valid_approval_types": [],
            "valid_evidence_ids": [],
            "invalid_evidence": invalid,
            "duplicate_evidence_ids": [],
        }
    for record in records_list:
        evidence_id = str(record.get("evidence_id", "<missing>"))
        if evidence_id in seen:
            duplicates.append(evidence_id)
        seen.add(evidence_id)
        errors = validate_evidence_record(
            record,
            schema=evidence_schema,
            subject=subject,
            minimum_trust=minimum_trust,
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
            continue
        valid_ids.append(evidence_id)
        valid_types.add(evidence_type)
        if evidence_type.startswith(SUPERVISOR_APPROVAL_PREFIX):
            valid_approvals.add(evidence_type)
    if duplicates:
        invalid["<duplicates>"] = ["Duplicate evidence IDs: " + ", ".join(sorted(set(duplicates)))]
    return {
        "valid_evidence_types": sorted(valid_types),
        "valid_approval_types": sorted(valid_approvals),
        "valid_evidence_ids": sorted(valid_ids),
        "invalid_evidence": invalid,
        "duplicate_evidence_ids": sorted(set(duplicates)),
    }


def evaluate_transition_from_records(
    policy: dict[str, Any],
    *,
    current_state: str,
    requested_state: str,
    risk: str,
    records: Iterable[dict[str, Any]],
    subject: dict[str, str] | None,
    evidence_schema: dict[str, Any],
    trust_roots: dict[str, Any] | None,
) -> dict[str, Any]:
    requirements = gate_requirements(policy, requested_state, risk)
    validation = _validate_records_for_gate(
        records,
        subject=subject,
        evidence_schema=evidence_schema,
        minimum_trust=requirements["minimum_trust"],
        trust_roots=trust_roots,
    )
    result = _evaluate_transition_validated(
        policy,
        current_state=current_state,
        requested_state=requested_state,
        risk=risk,
        evidence_types=validation["valid_evidence_types"],
        approvals=validation["valid_approval_types"],
    )
    if validation["duplicate_evidence_ids"]:
        result["allowed"] = False
        result["reasons"] = sorted(set(result["reasons"] + ["Duplicate evidence IDs are prohibited"]))
    result.update(validation)
    result["claim_boundary"] = "Only schema-valid, subject-bound evidence records contribute to this transition decision."
    return result


def _evaluate_next_actions_validated(
    policy: dict[str, Any],
    *,
    current_state: str,
    risk: str,
    evidence_types: Iterable[str] = (),
    approvals: Iterable[str] = (),
) -> dict[str, Any]:
    transitions = policy.get("transitions", {}) or {}
    candidates = transitions.get(current_state, []) or []
    results = [
        _evaluate_transition_validated(
            policy,
            current_state=current_state,
            requested_state=candidate,
            risk=risk,
            evidence_types=evidence_types,
            approvals=approvals,
        )
        for candidate in candidates
    ]
    permitted = [item["requested_state"] for item in results if item["allowed"]]
    blocked = {item["requested_state"]: item["reasons"] for item in results if not item["allowed"]}
    return {
        "current_state": current_state,
        "risk": risk,
        "permitted_next_states": permitted,
        "blocked_next_states": blocked,
        "decision": "PROCEED" if permitted else "CONTAIN_TASK_AND_CONTINUE_SCHEDULER",
    }


def evaluate_next_actions_from_records(
    policy: dict[str, Any],
    *,
    current_state: str,
    risk: str,
    records: Iterable[dict[str, Any]],
    subject: dict[str, str] | None,
    evidence_schema: dict[str, Any],
    trust_roots: dict[str, Any] | None,
) -> dict[str, Any]:
    candidates = ((policy.get("transitions", {}) or {}).get(current_state, []) or [])
    results = [
        evaluate_transition_from_records(
            policy,
            current_state=current_state,
            requested_state=candidate,
            risk=risk,
            records=records,
            subject=subject,
            evidence_schema=evidence_schema,
            trust_roots=trust_roots,
        )
        for candidate in candidates
    ]
    permitted = [item["requested_state"] for item in results if item["allowed"]]
    return {
        "current_state": current_state,
        "risk": risk,
        "permitted_next_states": permitted,
        "blocked_next_states": {item["requested_state"]: item["reasons"] for item in results if not item["allowed"]},
        "evaluations": results,
        "decision": "PROCEED" if permitted else "CONTAIN_TASK_AND_CONTINUE_SCHEDULER",
        "claim_boundary": "Raw agent claims are never accepted as transition evidence.",
    }
