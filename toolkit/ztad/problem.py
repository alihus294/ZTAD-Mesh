from __future__ import annotations

import copy
import re
import subprocess
from pathlib import Path
from typing import Any

from .schema_validation import validate_instance
from .util import canonical_json, sha256_bytes, utc_now

LOCAL_EVIDENCE_NOTICE = "LOCAL_EVIDENCE_IS_NON_AUTHORITATIVE_UNTIL_PROMOTED_BY_A_PROTECTED_CONTROLLER"
SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")

PROBLEM_STATES = (
    "UNVERIFIED_REPORT",
    "SOURCE_OF_TRUTH_RESOLVED",
    "ISSUE_CLASSIFIED",
    "BUG_REPRODUCED",
    "ROOT_CAUSE_PROVEN",
    "BLAST_RADIUS_MAPPED",
    "CHANGE_PLANNED",
    "REGRESSION_BASELINE_PROVEN",
    "HANDOFF_READY",
    "WAITING_EXTERNAL_DEPENDENCY",
    "RESOLVED_NO_CODE",
    "QUARANTINED",
)

CODE_CLASSIFICATIONS = {"CONFIRMED_BUG", "SECURITY_INCIDENT", "PERFORMANCE_REGRESSION"}
NON_CODE_CLASSIFICATIONS = {
    "EXPECTED_BEHAVIOR", "ENVIRONMENT_ISSUE", "CONFIGURATION_ISSUE", "DATA_ISSUE",
    "EXTERNAL_DEPENDENCY", "USER_WORKFLOW_ISSUE", "SPEC_CONFLICT", "INCONCLUSIVE",
}

TRANSITIONS: dict[str, set[str]] = {
    "UNVERIFIED_REPORT": {"SOURCE_OF_TRUTH_RESOLVED", "WAITING_EXTERNAL_DEPENDENCY", "QUARANTINED"},
    "SOURCE_OF_TRUTH_RESOLVED": {"ISSUE_CLASSIFIED", "WAITING_EXTERNAL_DEPENDENCY", "QUARANTINED"},
    "ISSUE_CLASSIFIED": {"BUG_REPRODUCED", "RESOLVED_NO_CODE", "WAITING_EXTERNAL_DEPENDENCY", "QUARANTINED"},
    "BUG_REPRODUCED": {"ROOT_CAUSE_PROVEN", "WAITING_EXTERNAL_DEPENDENCY", "QUARANTINED"},
    "ROOT_CAUSE_PROVEN": {"BLAST_RADIUS_MAPPED", "QUARANTINED"},
    "BLAST_RADIUS_MAPPED": {"CHANGE_PLANNED", "QUARANTINED"},
    "CHANGE_PLANNED": {"REGRESSION_BASELINE_PROVEN", "WAITING_EXTERNAL_DEPENDENCY", "QUARANTINED"},
    "REGRESSION_BASELINE_PROVEN": {"HANDOFF_READY", "WAITING_EXTERNAL_DEPENDENCY", "QUARANTINED"},
    "HANDOFF_READY": set(),
    "WAITING_EXTERNAL_DEPENDENCY": {"SOURCE_OF_TRUTH_RESOLVED", "ISSUE_CLASSIFIED", "BUG_REPRODUCED", "CHANGE_PLANNED", "REGRESSION_BASELINE_PROVEN", "QUARANTINED"},
    "RESOLVED_NO_CODE": set(),
    "QUARANTINED": set(),
}


def _git(repo: Path, *argv: str) -> tuple[int, str]:
    completed = subprocess.run(
        ["git", "-C", str(repo), *argv],
        text=True,
        capture_output=True,
        check=False,
        shell=False,
        timeout=30,
    )
    return completed.returncode, (completed.stdout or "").strip()


def _resolve_protected_sha(repo: Path, protected_ref: str) -> tuple[str | None, str | None]:
    ref = protected_ref.strip()
    if not ref:
        return None, None
    candidates = [ref] if SHA_RE.fullmatch(ref) else [
        f"refs/remotes/origin/{ref}",
        f"refs/heads/{ref}",
        ref,
    ]
    for candidate in candidates:
        code, value = _git(repo, "rev-parse", "--verify", candidate)
        if code == 0 and SHA_RE.fullmatch(value):
            return value, candidate
    return None, None


def inspect_repository_read_only(repository: Path, *, protected_ref: str = "main") -> dict[str, Any]:
    repo = repository.resolve()
    code, head = _git(repo, "rev-parse", "HEAD")
    head_sha = head if code == 0 and SHA_RE.fullmatch(head) else None
    protected_sha, resolved_ref = _resolve_protected_sha(repo, protected_ref)
    code, branch = _git(repo, "branch", "--show-current")
    current_branch = branch if code == 0 and branch else None
    code, status = _git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    dirty = None if code != 0 else bool(status)
    diverged = None if protected_sha is None or head_sha is None else protected_sha != head_sha
    return {
        "repository": str(repo),
        "protected_ref": protected_ref,
        "resolved_protected_ref": resolved_ref,
        "protected_ref_resolved": protected_sha is not None,
        "protected_base_sha": protected_sha,
        "local_head_sha": head_sha,
        "working_branch": current_branch,
        "dirty": dirty,
        "diverged_from_protected_base": diverged,
        "status_lines": status.splitlines() if code == 0 else [],
    }


def initialize_problem_case(
    repository: Path,
    *,
    report: str,
    expected_behavior: str | None = None,
    case_id: str | None = None,
    protected_ref: str = "main",
) -> dict[str, Any]:
    if not isinstance(report, str) or not report.strip():
        raise ValueError("report must be non-empty")
    inspected = inspect_repository_read_only(repository, protected_ref=protected_ref)
    base_sha = inspected["protected_base_sha"] or inspected["local_head_sha"]
    digest = sha256_bytes(canonical_json({
        "repository": inspected["repository"],
        "report": report.strip(),
        "protected_ref": protected_ref,
        "base_sha": base_sha,
        "local_head_sha": inspected["local_head_sha"],
    }))
    generated_case_id = "CASE-" + digest.removeprefix("sha256:")[:16].upper()
    environment_details: list[str] = []
    if inspected["resolved_protected_ref"]:
        environment_details.append(f"protected_ref_resolved_as={inspected['resolved_protected_ref']}")
    elif protected_ref:
        environment_details.append(f"protected_ref_unresolved={protected_ref}")
    return {
        "schema_version": 1,
        "case_id": case_id or generated_case_id,
        "state": "UNVERIFIED_REPORT",
        "repository": inspected["repository"],
        "report": report,
        "observed_at": utc_now(),
        "protected_ref": protected_ref,
        "protected_ref_resolved": inspected["protected_ref_resolved"],
        "base_sha": base_sha,
        "local_head_sha": inspected["local_head_sha"],
        "working_branch": inspected["working_branch"],
        "worktree_status": {
            "dirty": inspected["dirty"],
            "diverged_from_protected_base": inspected["diverged_from_protected_base"],
            "user_worktree_preserved": None,
            "isolated_clean_worktree": None,
            "evidence_refs": [],
        },
        "environment": {"label": "local", "details": environment_details},
        "expected_behavior": expected_behavior,
        "observed_behavior": None,
        "supplied_evidence": [],
        "authoritative_sources": [],
        "source_conflicts": [],
        "classification": None,
        "classification_evidence": [],
        "reproduction": None,
        "root_cause": None,
        "rejected_hypotheses": [],
        "blast_radius": {"direct": [], "adjacent": [], "security_boundaries": [], "data_boundaries": []},
        "invariants": [],
        "risk": None,
        "regression_baseline": None,
        "change_plan": None,
        "external_dependencies": [] if inspected["protected_ref_resolved"] else [f"protected_ref_unresolved:{protected_ref}"],
        "local_evidence_notice": LOCAL_EVIDENCE_NOTICE,
    }


def problem_case_fingerprint(case: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(case))


def _require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def semantic_errors(case: dict[str, Any], *, target_state: str | None = None) -> list[str]:
    state = target_state or str(case.get("state") or "")
    errors: list[str] = []
    if state not in PROBLEM_STATES:
        return [f"Unknown problem state: {state}"]

    index = PROBLEM_STATES.index(state) if state in PROBLEM_STATES[:9] else -1
    if index >= PROBLEM_STATES.index("SOURCE_OF_TRUTH_RESOLVED"):
        _require(case.get("protected_ref_resolved") is True, "protected/current base ref must be resolved before source-of-truth completion", errors)
        _require(bool(case.get("base_sha")), "protected/current base SHA is required", errors)
        _require(bool(case.get("authoritative_sources")), "source-of-truth resolution requires authoritative_sources", errors)
        _require(not case.get("source_conflicts"), "unresolved source conflicts must not be treated as resolved", errors)
    if index >= PROBLEM_STATES.index("ISSUE_CLASSIFIED"):
        _require(case.get("classification") is not None, "classification is required", errors)
        _require(bool(case.get("classification_evidence")), "classification evidence is required", errors)
    if state == "RESOLVED_NO_CODE":
        _require(case.get("classification") in NON_CODE_CLASSIFICATIONS, "RESOLVED_NO_CODE requires a non-code classification", errors)
        return sorted(set(errors))
    if index >= PROBLEM_STATES.index("BUG_REPRODUCED"):
        _require(case.get("classification") in CODE_CLASSIFICATIONS, "implementation path requires a code-affecting classification", errors)
        _require(isinstance(case.get("reproduction"), dict), "reproduction/proof is required", errors)
        reproduction = case.get("reproduction") or {}
        _require(bool(reproduction.get("evidence_refs")), "reproduction requires evidence_refs", errors)
    if index >= PROBLEM_STATES.index("ROOT_CAUSE_PROVEN"):
        root = case.get("root_cause")
        _require(isinstance(root, dict), "root cause is required", errors)
        if isinstance(root, dict):
            _require(bool(root.get("trigger")), "root cause trigger is required", errors)
            _require(bool(root.get("incorrect_state_or_assumption")), "root cause incorrect state/assumption is required", errors)
            _require(bool(root.get("observable_failure")), "root cause observable failure is required", errors)
            _require(bool(root.get("evidence_refs")), "root cause requires evidence_refs", errors)
    if index >= PROBLEM_STATES.index("BLAST_RADIUS_MAPPED"):
        _require(bool((case.get("blast_radius") or {}).get("direct")), "blast radius must contain direct surfaces", errors)
        _require(bool(case.get("invariants")), "at least one invariant is required", errors)
        _require(case.get("risk") in {"R0", "R1", "R2", "R3", "R4"}, "risk classification is required", errors)
    if index >= PROBLEM_STATES.index("CHANGE_PLANNED"):
        plan = case.get("change_plan")
        _require(isinstance(plan, dict), "change plan is required", errors)
        if isinstance(plan, dict):
            _require(bool(plan.get("intended_fix")), "change plan intended_fix is required", errors)
            _require(bool(plan.get("expected_files")), "change plan expected_files must be explicit", errors)
            _require(bool(plan.get("tests")), "change plan must name tests/oracles", errors)
        worktree = case.get("worktree_status") or {}
        if worktree.get("dirty") or worktree.get("diverged_from_protected_base"):
            _require(worktree.get("user_worktree_preserved") is True, "dirty/divergent user worktree must be preserved", errors)
            _require(worktree.get("isolated_clean_worktree") is True, "dirty/divergent work requires an isolated clean worktree", errors)
            _require(bool(worktree.get("evidence_refs")), "clean-isolation claim requires evidence_refs", errors)
    if index >= PROBLEM_STATES.index("REGRESSION_BASELINE_PROVEN"):
        baseline = case.get("regression_baseline")
        _require(isinstance(baseline, dict), "regression baseline is required", errors)
        if isinstance(baseline, dict):
            _require(baseline.get("bad_result") in {"FAIL", "PROVEN_BAD_WITH_EQUIVALENT_EVIDENCE"}, "known-bad baseline must fail or carry equivalent proof", errors)
            _require(bool(baseline.get("test_or_oracle")), "regression baseline requires a test/oracle", errors)
            _require(bool(baseline.get("evidence_refs")), "regression baseline requires evidence_refs", errors)
            if baseline.get("bad_result") == "FAIL":
                _require(baseline.get("same_oracle") is True, "RED→GREEN requires the same oracle", errors)
            if case.get("base_sha"):
                _require(baseline.get("base_sha") == case.get("base_sha"), "regression baseline must bind the exact protected problem base SHA", errors)
    if state == "HANDOFF_READY":
        _require(not case.get("external_dependencies"), "HANDOFF_READY cannot retain unresolved external dependencies", errors)
    return sorted(set(errors))


def validate_problem_case(case: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    return sorted(set(validate_instance(case, schema) + semantic_errors(case)))


def can_transition(case: dict[str, Any], target_state: str, schema: dict[str, Any]) -> dict[str, Any]:
    current = str(case.get("state") or "")
    reasons: list[str] = []
    if target_state not in TRANSITIONS.get(current, set()):
        reasons.append(f"Transition {current} -> {target_state} is not allowed")
    candidate = copy.deepcopy(case)
    candidate["state"] = target_state
    reasons.extend(validate_instance(candidate, schema))
    reasons.extend(semantic_errors(candidate, target_state=target_state))
    return {
        "allowed": not reasons,
        "current_state": current,
        "target_state": target_state,
        "reasons": sorted(set(reasons)),
        "problem_case_fingerprint": problem_case_fingerprint(case),
        "claim_boundary": "Local problem-case progression is E2 evidence only; it cannot grant merge, release, or production authority.",
    }


def advance_problem_case(case: dict[str, Any], target_state: str, schema: dict[str, Any]) -> dict[str, Any]:
    decision = can_transition(case, target_state, schema)
    if not decision["allowed"]:
        raise ValueError("; ".join(decision["reasons"]))
    result = copy.deepcopy(case)
    result["state"] = target_state
    return result


def problem_case_to_change_contract(case: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    errors = validate_problem_case(case, schema)
    if errors:
        raise ValueError("Invalid problem case: " + "; ".join(errors))
    if case.get("state") != "HANDOFF_READY":
        raise ValueError("Problem case is not HANDOFF_READY")
    if case.get("classification") not in CODE_CLASSIFICATIONS:
        raise ValueError("Only code-affecting classifications can produce a Change Contract")

    plan = case["change_plan"]
    baseline = case["regression_baseline"]
    expected = case.get("expected_behavior") or "The proven reported problem no longer reproduces under the recorded regression oracle."
    expected_files = list(dict.fromkeys(plan.get("expected_files") or (case.get("blast_radius") or {}).get("direct") or ["."]))
    invariants = list(dict.fromkeys(case.get("invariants") or ["No unrelated behavior changes outside the bounded change plan."]))
    seed = int(problem_case_fingerprint(case).removeprefix("sha256:")[:12], 16) % 1_000_000_000
    change_id = f"PROBLEM-{seed}"
    risk = str(case["risk"])
    criticality = "tier_0" if risk == "R4" else "tier_1" if risk == "R3" else "tier_2"
    data_classification = "C3" if risk == "R4" else "C2" if risk == "R3" else "C1"
    negative_cases = [
        "The original known-bad behavior must not recur.",
        "The candidate must not modify prohibited or unrelated scope.",
    ]
    return {
        "schema_version": 1,
        "change_id": change_id,
        "title": f"Problem fix: {case['case_id']}",
        "outcome": {"user_or_system_value": expected, "success_metric": None},
        "requirements": {
            "acceptance_criteria": [{"id": "AC-01", "statement": expected}],
            "non_goals": list(plan.get("forbidden_scope") or []),
            "invariants": [{"id": f"INV-{index:02d}", "statement": statement} for index, statement in enumerate(invariants, 1)],
            "assumptions": [],
        },
        "scope": {
            "expected_components": expected_files,
            "prohibited_components": list(plan.get("forbidden_scope") or []),
            "public_contract_change": False,
            "data_migration_expected": "migration" in str(plan.get("database_impact", "")).lower(),
            "service_criticality": criticality,
            "data_classification": data_classification,
        },
        "quality_attributes": {
            "security": "Preserve all recorded security boundaries and fail closed on uncertainty.",
            "privacy": "Do not expose new sensitive information or PII.",
            "performance": "Do not introduce an unexplained performance regression.",
            "availability": "Preserve availability except for bounded approved maintenance.",
            "accessibility": "Preserve existing accessibility behavior unless explicitly in scope.",
            "compatibility": "Preserve adjacent contracts unless explicitly planned and re-reviewed.",
        },
        "verification": {
            "test_oracles": [{"acceptance_test": str(baseline["test_or_oracle"]), "expected_evidence": "Same oracle fails on recorded protected bad base and passes on exact candidate."}],
            "observability": [{"metric": "original_problem_recurrence", "threshold": "0 during the applicable verification window"}],
            "negative_cases": negative_cases,
        },
        "release": {
            "feature_flag_required": risk in {"R3", "R4"},
            "rollback_strategy": str(plan.get("rollback_or_containment") or "Stop progression and restore the previously verified artifact by the protected path."),
            "data_reversal_required": "migration" in str(plan.get("database_impact", "")).lower(),
            "stop_conditions": ["original problem persists", "security/data invariant fails", "required evidence is missing or conflicting"],
        },
        "governance": {
            "product_owner": "repository-owner",
            "engineering_owner": "ztad-controller",
            "requested_risk": risk,
            "policy_risk": risk,
            "human_decisions": [
                {"type": "PROBLEM_CASE_FINGERPRINT", "value": problem_case_fingerprint(case)},
                {"type": "PROTECTED_BASE_SHA", "value": case["base_sha"]},
                {"type": "LOCAL_HEAD_SHA", "value": case.get("local_head_sha")},
            ],
        },
        "budget": {"max_implementation_runs": 3, "max_repair_cycles": 2, "max_review_runs": 3},
    }
