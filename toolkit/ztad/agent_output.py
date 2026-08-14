from __future__ import annotations

import re
from typing import Any, Iterable

from .schema_validation import validate_instance

ALLOWED_RESULT_TYPES = {
    "PLAN_READY", "IMPLEMENTATION_PROPOSAL", "PROPOSED_FINDINGS",
    "NO_BLOCKING_FINDINGS_IN_REVIEWED_SCOPE", "INSUFFICIENT_CONTEXT",
    "INSUFFICIENT_EVIDENCE", "SAFE_ASSUMPTION_PLAN_READY",
    "WAITING_EXTERNAL_DEPENDENCY", "RISK_ESCALATION_REQUESTED",
    "TOOL_REQUEST", "REPAIR_PROPOSAL", "AUTO_REPLAN",
    "SUPERVISOR_TAKEOVER", "QUARANTINE_AND_CONTINUE",
    "RETROSPECTIVE_PROPOSAL",
}
FORBIDDEN_AUTHORITATIVE_PHRASES = {
    "APPROVED", "DEPLOYMENT_VERIFIED", "NO_SIDE_EFFECTS", "FULLY_SAFE",
    "MERGE APPROVED", "RELEASE APPROVED", "ALL TESTS PASSED",
}
ALLOWED_REQUESTED_ACTIONS = {
    "VALIDATE_PLAN", "VALIDATE_PATCH", "RUN_LOCAL_CHECKS", "OPEN_PR_VIA_BROKER",
    "VERIFY_FINDINGS", "REQUEST_CONTEXT_EXPANSION", "RETURN_TO_SPEC_OWNER",
    "ESCALATE_RISK", "REPAIR_CONFIRMED_FINDINGS", "CONTINUE_POLICY_EVALUATION",
    "REQUEST_STRONG_SUPERVISOR", "AUTO_REPLAN", "AUTO_GENERATE_EVIDENCE",
    "QUARANTINE_TASK", "CONTINUE_NEXT_TASK", "RECORD_RETROSPECTIVE_PROPOSAL",
}
AGENT_ROLE_ALIASES = {"test_designer": "planner", "test_oracle": "planner", "reviewer": "independent_reviewer", "worker": "implementer"}

def normalize_agent_role(value: str | None) -> str | None:
    return None if value is None else AGENT_ROLE_ALIASES.get(value, value)

SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")


def validate_agent_result(
    result: dict[str, Any],
    schema: dict[str, Any],
    *,
    expected: dict[str, str] | None = None,
    known_evidence_ids: Iterable[str] = (),
) -> list[str]:
    normalized = dict(result)
    normalized["agent_role"] = normalize_agent_role(result.get("agent_role"))
    result = normalized
    if expected and expected.get("agent_role") is not None:
        expected = dict(expected)
        expected["agent_role"] = normalize_agent_role(expected.get("agent_role"))
    errors = validate_instance(result, schema)
    if result.get("result_type") not in ALLOWED_RESULT_TYPES:
        errors.append(f"Unsupported or authoritative result_type: {result.get('result_type')}")
    if result.get("requested_action") not in ALLOWED_REQUESTED_ACTIONS:
        errors.append(f"Unsupported requested_action: {result.get('requested_action')}")
    serialized = str(result).upper()
    for phrase in FORBIDDEN_AUTHORITATIVE_PHRASES:
        if phrase in serialized:
            errors.append(f"Authoritative phrase is prohibited in agent output: {phrase}")
    if expected:
        for key in ("task_id", "agent_role", "model_registry_id", "prompt_version", "base_sha", "head_sha", "context_id"):
            value = expected.get(key)
            if value is not None and result.get(key) != value:
                errors.append(f"Agent result subject mismatch for {key}")
    evidence_ids = set(known_evidence_ids)
    for index, claim in enumerate(result.get("claims", []) or []):
        if claim.get("verification_status") == "UNVERIFIED":
            if claim.get("evidence_ref"):
                errors.append(f"claims/{index}: unverified claim must not cite authoritative evidence")
            continue
        ref = claim.get("evidence_ref")
        if not ref:
            errors.append(f"claims/{index}: verified claim lacks evidence_ref")
        elif evidence_ids and ref not in evidence_ids:
            errors.append(f"claims/{index}: unknown evidence_ref {ref}")
        source_sha = str(claim.get("source_sha", ""))
        if claim.get("claim_type") in {"REPOSITORY_FACT", "EXECUTION_FACT"} and not SHA_RE.fullmatch(source_sha):
            errors.append(f"claims/{index}: repository/execution claim requires exact source_sha")
    for index, finding in enumerate(result.get("findings", []) or []):
        if not finding.get("file") and not finding.get("symbol"):
            errors.append(f"findings/{index}: file or symbol is required")
        if not finding.get("violated_rule"):
            errors.append(f"findings/{index}: violated_rule is required")
        if finding.get("severity") in {"P0", "P1"} and not finding.get("evidence_refs"):
            errors.append(f"findings/{index}: blocking finding lacks evidence")
        if finding.get("verification_status") == "CONFIRMED" and not finding.get("reproduction"):
            errors.append(f"findings/{index}: confirmed finding requires reproduction or proof")
    if result.get("agent_role") == "implementer" and result.get("result_type") == "NO_BLOCKING_FINDINGS_IN_REVIEWED_SCOPE":
        errors.append("Implementer cannot independently clear its own change")
    return sorted(set(errors))
