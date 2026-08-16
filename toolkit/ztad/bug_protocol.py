from __future__ import annotations

import re
from typing import Any, Iterable

from .risk import RISK_TO_CLASS, effective_risk as canonical_effective_risk
from .diff_forensics import validate_git_inventory


AUTHORITATIVE_LIFECYCLE = (
    "UNVERIFIED_REPORT",
    "SOURCE_OF_TRUTH_RESOLVED",
    "ISSUE_CLASSIFIED",
    "BUG_REPRODUCED",
    "ROOT_CAUSE_PROVEN",
    "BLAST_RADIUS_MAPPED",
    "CHANGE_PLANNED",
    "PATCH_IMPLEMENTED",
    "REGRESSION_TEST_PROVEN",
    "TARGETED_VALIDATION_PASS",
    "REGRESSION_VALIDATION_PASS",
    "DIFF_FORENSICS_PASS",
    "INDEPENDENT_REVIEW_PASS",
    "CI_PASS",
    "STAGING_PASS",
    "READY_FOR_OWNER_RELEASE",
    "PRODUCTION_RELEASED",
    "POST_DEPLOY_VERIFIED",
    "CLOSED",
)

CLASSIFICATIONS = {
    "CONFIRMED_BUG",
    "EXPECTED_BEHAVIOR",
    "ENVIRONMENT_ISSUE",
    "CONFIGURATION_ISSUE",
    "DATA_ISSUE",
    "EXTERNAL_DEPENDENCY",
    "USER_WORKFLOW_ISSUE",
    "SPEC_CONFLICT",
    "SECURITY_INCIDENT",
    "PERFORMANCE_REGRESSION",
    "INCONCLUSIVE",
}

IMPLEMENTATION_CLASSIFICATIONS = {
    "CONFIRMED_BUG",
    "CONFIGURATION_ISSUE",
    "SECURITY_INCIDENT",
    "PERFORMANCE_REGRESSION",
}

NON_CODE_CLASSIFICATIONS = CLASSIFICATIONS - IMPLEMENTATION_CLASSIFICATIONS

RISK_LEVEL_TO_CLASS = RISK_TO_CLASS
RISK_CLASS_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
HIGH_RISK_DOMAINS = {
    "DATABASE",
    "AUTH_TENANT",
    "FINANCIAL",
    "ZATCA",
    "PROVIDER",
    "CONCURRENCY",
    "SECURITY",
}
VALID_DOMAINS = frozenset({"GENERAL", *HIGH_RISK_DOMAINS})
# Domain profiles impose a minimum risk floor.  They do not, by themselves,
# turn every change into R4; deterministic destructive or irreversible signals
# are the separate critical escalation path.
CRITICAL_DOMAINS = set()
DOMAIN_MINIMUM_CLASS = {domain: "HIGH" for domain in HIGH_RISK_DOMAINS}
DOMAIN_MARKERS = {
    "DATABASE": ("database", "migration", "rls", "tenant filter", "backfill", "database schema"),
    "AUTH_TENANT": ("auth", "rbac", "authorization", "tenant", "permission", "id tampering"),
    "FINANCIAL": ("payment", "invoice", "ledger", "financial", "vat", "refund"),
    "ZATCA": ("zatca", "clearance", "reporting", "signed xml", "tax invoice"),
    "PROVIDER": ("provider", "webhook", "reconciliation", "sandbox", "external integration"),
    "CONCURRENCY": ("concurrency", "race", "parallel", "idempotency", "duplicate request", "lock"),
    "SECURITY": ("security incident", "secret", "pii", "data leak", "encryption", "kms", "fail-open"),
}

SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PHONE_RE = re.compile(r"(?<!\d)\d{8,15}(?!\d)")
ARTIFACT_CHAIN_POLICY_KEYS = ("build_once_promote_by_digest", "mutable_tag_only", "rebuild_after_validation")
HOTFIX_POLICY_KEY = "may_reduce_validation_breadth"
PROTECTED_APPROVAL_PRODUCERS = frozenset({
    "controller:release",
    "platform:approval-controller",
})
TERMINAL_EVIDENCE_PRODUCERS = frozenset({
    "controller:release",
    "controller:test-executor",
    "controller:validation",
    "platform:approval-controller",
    "platform:protected-build",
    "platform:protected-ci",
    "platform:protected-release",
    "platform:protected-staging",
    "platform:protected-validation",
    "platform:production-runtime",
})


def validate_authoritative_lifecycle_policy(policy: dict[str, Any]) -> list[str]:
    """Check that the repository policy preserves the exact authoritative order."""

    states = tuple(str(item) for item in policy.get("states", []) or [])
    errors: list[str] = []
    if states[: len(AUTHORITATIVE_LIFECYCLE)] != AUTHORITATIVE_LIFECYCLE:
        errors.append("Authoritative lifecycle order is not exact")
    transitions = policy.get("transitions") or {}
    for index, state in enumerate(AUTHORITATIVE_LIFECYCLE[:-1]):
        expected = AUTHORITATIVE_LIFECYCLE[index + 1]
        if expected not in set(transitions.get(state) or []):
            errors.append(f"Authoritative lifecycle transition {state} -> {expected} is missing")
    if set(transitions.get("CLOSED") or []):
        errors.append("CLOSED must have no outgoing authoritative lifecycle transition")
    return sorted(set(errors))


MANDATORY_POLICY_DOMAINS = frozenset(HIGH_RISK_DOMAINS)
MANDATORY_SECURITY_CHECKS = frozenset({
    "SECURITY_VALIDATION_PASSED",
    "SECRETS_SCAN_PASSED",
    "FAIL_CLOSED_BOUNDARY_PASSED",
})


def validate_policy_safety(policy: dict[str, Any] | None) -> list[str]:
    """Reject policy edits that would weaken foundational invariants."""

    if not isinstance(policy, dict):
        return ["Authoritative bug policy must be an object"]
    errors = list(validate_authoritative_lifecycle_policy(policy))
    declared_states = {str(item) for item in (policy.get("states") or [])}
    for required_state in (*AUTHORITATIVE_LIFECYCLE, "BLOCKED", "ROLLBACK_REQUIRED", "RESOLVED_NO_CODE"):
        if required_state not in declared_states:
            errors.append(f"Policy is missing mandatory lifecycle state: {required_state}")
    risk_classes = policy.get("risk_classes") if isinstance(policy.get("risk_classes"), dict) else {}
    if set(risk_classes.get("CRITICAL") or []) != {"R4"}:
        errors.append("Policy must map R4 exactly to CRITICAL")
    if set(risk_classes.get("HIGH") or []) != {"R3"}:
        errors.append("Policy must map R3 exactly to HIGH")
    domain_profiles = policy.get("domain_profiles") if isinstance(policy.get("domain_profiles"), dict) else {}
    missing_domains = sorted(MANDATORY_POLICY_DOMAINS - {str(item).upper() for item in domain_profiles})
    if missing_domains:
        errors.append("Policy is missing mandatory domain profiles: " + ", ".join(missing_domains))
    for domain in sorted(MANDATORY_POLICY_DOMAINS):
        profile = domain_profiles.get(domain) or domain_profiles.get(domain.upper()) or {}
        minimum = str(profile.get("minimum_risk_class") or "").upper()
        if minimum not in {"HIGH", "CRITICAL"}:
            errors.append(f"Policy domain {domain} must retain a HIGH or CRITICAL minimum risk class")
        if not isinstance(profile.get("required_checks"), list) or not profile.get("required_checks"):
            errors.append(f"Policy domain {domain} must retain required checks")
    security_checks = set((domain_profiles.get("SECURITY") or {}).get("required_checks") or [])
    if not MANDATORY_SECURITY_CHECKS.issubset(security_checks):
        errors.append("Policy cannot remove mandatory SECURITY domain checks")
    rollback_by_domain = set(((policy.get("gates") or {}).get("ROLLBACK_CLOSURE") or {}).get("by_domain") or {})
    if not MANDATORY_POLICY_DOMAINS.issubset({str(item).upper() for item in rollback_by_domain}):
        errors.append("Policy cannot remove mandatory rollback recovery domains")
    hotfix = policy.get("hotfix") if isinstance(policy.get("hotfix"), dict) else {}
    if hotfix.get("may_reduce_validation_breadth") is not False:
        errors.append("Policy cannot weaken hotfix validation breadth")
    if hotfix.get("may_skip_states") is not False:
        errors.append("Policy cannot enable lifecycle state skipping")
    artifact_chain = policy.get("artifact_chain") if isinstance(policy.get("artifact_chain"), dict) else {}
    if artifact_chain.get("build_once_promote_by_digest") is not True:
        errors.append("Policy must require build-once promotion by digest")
    if artifact_chain.get("mutable_tag_only") is not False or artifact_chain.get("rebuild_after_validation") is not False:
        errors.append("Policy cannot permit mutable tags or rebuild-after-validation")
    transitions = policy.get("transitions") if isinstance(policy.get("transitions"), dict) else {}
    for index, state in enumerate(AUTHORITATIVE_LIFECYCLE[:-1]):
        expected = {AUTHORITATIVE_LIFECYCLE[index + 1], "BLOCKED"}
        if state == "ISSUE_CLASSIFIED":
            expected.add("RESOLVED_NO_CODE")
        if state in {"PRODUCTION_RELEASED", "POST_DEPLOY_VERIFIED"}:
            expected.add("ROLLBACK_REQUIRED")
        actual = set(transitions.get(state) or [])
        if not actual.issubset(expected):
            errors.append(f"Policy permits a lifecycle skip from {state}")
    if "RESOLVED_NO_CODE" not in set(transitions.get("ISSUE_CLASSIFIED") or []):
        errors.append("Policy must retain ISSUE_CLASSIFIED -> RESOLVED_NO_CODE")
    if "CLOSED" not in set(transitions.get("ROLLBACK_REQUIRED") or []):
        errors.append("Policy must retain ROLLBACK_REQUIRED -> CLOSED")
    progressive = policy.get("progressive_exposure") if isinstance(policy.get("progressive_exposure"), dict) else {}
    for level in ("HIGH", "CRITICAL"):
        configured = progressive.get(level) or {}
        required = set(configured.get("required_evidence") or []) if isinstance(configured, dict) else set(configured)
        if "PROGRESSIVE_EXPOSURE_PLAN" not in required:
            errors.append(f"Policy progressive exposure for {level} is mandatory")
    critical_strategies = set((progressive.get("CRITICAL") or {}).get("strategies") or [])
    if not {"WRITE_GATE", "OWNER_STOP_CONDITION"}.issubset(critical_strategies):
        errors.append("Critical progressive exposure must retain write gate and owner stop condition")
    return sorted(set(errors))


def risk_class_for_level(level: str | None) -> str | None:
    return RISK_LEVEL_TO_CLASS.get(str(level).upper()) if level is not None else None


def derive_risk_class(
    *,
    risk: str | None,
    domains: Iterable[str] = (),
    changed_paths: Iterable[str] = (),
    operation_text: str = "",
    policy: dict[str, Any] | None = None,
) -> str:
    """Derive a monotonic protocol risk class from deterministic inputs."""

    normalized_domains = {str(item).upper() for item in domains}
    unknown_domains = sorted(normalized_domains - VALID_DOMAINS)
    if unknown_domains:
        raise ValueError("Unknown risk domain: " + ", ".join(unknown_domains))
    if risk is not None and str(risk).upper() not in RISK_LEVEL_TO_CLASS:
        raise ValueError("Unknown risk level: " + str(risk))
    paths = {str(item).replace("\\", "/").casefold() for item in changed_paths}
    text = " ".join([operation_text, *paths]).casefold()
    requested_level = str(risk or "R0").upper() if str(risk or "R0").upper() in {"R0", "R1", "R2", "R3", "R4"} else "R0"
    escalation = policy.get("deterministic_escalation", {}) if isinstance(policy, dict) else {}
    critical_markers = tuple(str(item).casefold() for item in (escalation.get("CRITICAL") or (
        "drop table", "drop column", "truncate", "payment", "ledger", "zatca", "kms", "secret", "production", "destructive"
    )))
    high_markers = tuple(str(item).casefold() for item in (escalation.get("HIGH") or (
        "auth", "authorization", "tenant_isolation", "persistent_write", "provider_side_effect", "concurrency", "infrastructure"
    )))
    operation_level = "R4" if any(marker in text for marker in critical_markers) else "R3" if any(marker in text for marker in high_markers) else "R0"
    path_level = "R3" if any(path.startswith("migrations/") or path.startswith("migration/") for path in paths) else "R0"
    domain_level = "R0"
    if normalized_domains & HIGH_RISK_DOMAINS:
        profiles = policy.get("domain_profiles", {}) if isinstance(policy, dict) else {}
        for domain in normalized_domains & HIGH_RISK_DOMAINS:
            configured = profiles.get(domain, {}) if isinstance(profiles, dict) else {}
            configured_class = str(configured.get("minimum_risk_class") or "HIGH").upper()
            configured_level = {"HIGH": "R3", "CRITICAL": "R4"}.get(configured_class, "R3")
            domain_level = canonical_effective_risk(domain_minimum=domain_level, requested=configured_level)
    level = canonical_effective_risk(
        requested=requested_level,
        path=path_level,
        operation=operation_level,
        domain_minimum=domain_level,
    )
    return RISK_LEVEL_TO_CLASS[level]


def infer_domains(case: dict[str, Any] | None, explicit_domains: Iterable[str] = ()) -> list[str]:
    """Infer only escalation domains; explicit or inferred risk can never be lowered."""

    values = [str(item).upper() for item in explicit_domains]
    unknown_explicit = sorted(set(values) - VALID_DOMAINS)
    if unknown_explicit:
        raise ValueError("Unknown risk domain: " + ", ".join(unknown_explicit))
    case = case if isinstance(case, dict) else {}
    def leaf_text(value: Any) -> list[str]:
        if isinstance(value, dict):
            result: list[str] = []
            for child in value.values():
                result.extend(leaf_text(child))
            return result
        if isinstance(value, list):
            result = []
            for child in value:
                result.extend(leaf_text(child))
            return result
        return [str(value)] if value is not None else []

    text = " ".join(leaf_text(case)).casefold()
    inferred = [domain for domain, markers in DOMAIN_MARKERS.items() if any(marker in text for marker in markers)]
    result = set(values) | set(inferred)
    if not result:
        result.add("GENERAL")
    if result - {"GENERAL"}:
        result.discard("GENERAL")
    return sorted(result)


def validate_authoritative_sources(
    sources: Iterable[dict[str, Any]],
    conflicts: Iterable[Any] = (),
    *,
    required_hierarchy: Iterable[str] = (),
    authority_order: Iterable[str] = (),
) -> list[str]:
    errors: list[str] = []
    source_list = list(sources)
    if list(conflicts):
        errors.append("BLOCKED: SOURCE_CONFLICT")
    if not source_list:
        errors.append("authoritative_sources is required")
    seen: set[str] = set()
    authority_positions = {str(value): index for index, value in enumerate(authority_order)}
    authority_aliases = {"TEST_EVIDENCE": "TEST_BEHAVIOR", "HISTORICAL_NON_AUTHORITY": "REPORT_OR_PLAN"}
    previous_position = -1
    for index, source in enumerate(source_list):
        if not isinstance(source, dict):
            errors.append(f"authoritative_sources/{index} must be an object")
            continue
        name = str(source.get("source") or "")
        authority = str(source.get("authority") or "")
        reason = str(source.get("authority_reason") or "")
        if not name:
            errors.append(f"authoritative_sources/{index} source is required")
        if name in seen:
            errors.append(f"authoritative_sources/{index} duplicates source {name}")
        seen.add(name)
        if not authority:
            errors.append(f"authoritative_sources/{index} authority is required")
        normalized_authority = authority_aliases.get(authority, authority)
        if authority_positions and normalized_authority not in authority_positions:
            errors.append(f"authoritative_sources/{index} authority is outside the declared hierarchy")
        elif authority_positions and authority_positions[normalized_authority] < previous_position:
            errors.append("Authoritative source order is weaker than the declared hierarchy")
        elif authority_positions:
            previous_position = authority_positions[normalized_authority]
        if not reason:
            errors.append(f"authoritative_sources/{index} authority_reason is required")
        if "evidence_ref" not in source:
            errors.append(f"authoritative_sources/{index} evidence_ref is required")
    hierarchy = [str(item) for item in required_hierarchy]
    if hierarchy:
        actual = [str(item.get("source")) for item in source_list if isinstance(item, dict)]
        missing = [item for item in hierarchy if item not in actual]
        if missing:
            errors.append("Canonical source hierarchy is incomplete: " + ", ".join(missing))
        positions = [actual.index(item) for item in hierarchy if item in actual]
        if positions != sorted(positions):
            errors.append("Canonical source hierarchy order is not authoritative")
    return sorted(set(errors))


def validate_classification_record(case: dict[str, Any]) -> list[str]:
    classification = case.get("classification")
    errors: list[str] = []
    if classification not in CLASSIFICATIONS:
        errors.append(f"Unsupported classification: {classification}")
    if not case.get("classification_evidence"):
        errors.append("classification evidence is required")
    record = case.get("classification_record")
    if not isinstance(record, dict):
        errors.append("classification_record is mandatory and must be an object")
    else:
        required_fields = (
            "evidence",
            "reproduction_status",
            "authoritative_expected_behavior",
            "competing_explanations_tested",
            "environment_findings",
            "unresolved_ambiguities",
            "source_conflicts",
            "implementation_justified",
        )
        for field in required_fields:
            if field not in record:
                errors.append(f"classification_record.{field} is required")
        if not isinstance(record.get("evidence"), list) or not record.get("evidence"):
            errors.append("classification_record.evidence must be a non-empty array")
        if record.get("reproduction_status") not in {"NOT_ATTEMPTED", "NOT_REPRODUCED", "REPRODUCED", "INCONCLUSIVE"}:
            errors.append("classification_record.reproduction_status is invalid")
        for field in ("competing_explanations_tested", "environment_findings", "unresolved_ambiguities", "source_conflicts"):
            if not isinstance(record.get(field), list):
                errors.append(f"classification_record.{field} must be an array")
        if not isinstance(record.get("implementation_justified"), bool):
            errors.append("classification_record.implementation_justified must be boolean")
        if classification in IMPLEMENTATION_CLASSIFICATIONS and record.get("implementation_justified") is not True:
            errors.append("implementation classification requires implementation_justified=true")
        if classification in NON_CODE_CLASSIFICATIONS and record.get("implementation_justified") is True:
            errors.append("non-code classification cannot claim implementation is justified")
    if classification in IMPLEMENTATION_CLASSIFICATIONS and not case.get("expected_behavior"):
        errors.append("implementation classification requires claimed or authoritative expected behavior")
    return sorted(set(errors))


def validate_reproduction(reproduction: dict[str, Any] | None) -> list[str]:
    if not isinstance(reproduction, dict):
        return ["BUG_REPRODUCED requires a reproduction record"]
    errors: list[str] = []
    for field in ("preconditions", "action", "expected", "actual", "environment", "evidence_refs"):
        if not reproduction.get(field):
            errors.append(f"reproduction.{field} is required")
    if reproduction.get("deterministic") is False:
        repetitions = reproduction.get("repetition_count")
        frequency = reproduction.get("observed_frequency")
        timing = reproduction.get("timing_conditions")
        if not isinstance(repetitions, int) or repetitions < 2:
            errors.append("nondeterministic reproduction requires repetition_count >= 2")
        if not frequency:
            errors.append("nondeterministic reproduction requires observed_frequency")
        if not timing:
            errors.append("nondeterministic reproduction requires timing_conditions")
    if not reproduction.get("affected_component"):
        errors.append("reproduction.affected_component is required")
    return sorted(set(errors))


def validate_root_cause(case: dict[str, Any]) -> list[str]:
    root = case.get("root_cause")
    if not isinstance(root, dict):
        return ["ROOT_CAUSE_PROVEN requires root_cause"]
    errors: list[str] = []
    for field in ("trigger", "incorrect_state_or_assumption", "propagation", "observable_failure", "affected_source", "evidence_refs"):
        if not root.get(field):
            errors.append(f"root_cause.{field} is required")
    hypotheses = case.get("hypothesis_tests")
    if hypotheses is not None:
        if not isinstance(hypotheses, list) or not hypotheses:
            errors.append("hypothesis_tests must contain tested hypotheses")
        else:
            for index, hypothesis in enumerate(hypotheses):
                if not isinstance(hypothesis, dict) or not hypothesis.get("hypothesis") or not hypothesis.get("test") or not hypothesis.get("result"):
                    errors.append(f"hypothesis_tests/{index} must contain hypothesis, test, and result")
    return sorted(set(errors))


def validate_change_plan(plan: dict[str, Any] | None) -> list[str]:
    if not isinstance(plan, dict):
        return ["CHANGE_PLANNED requires change_plan"]
    errors: list[str] = []
    for field in (
        "root_cause_summary",
        "intended_fix",
        "expected_files",
        "tests",
        "forbidden_scope",
        "database_impact",
        "external_side_effects",
        "rollback_or_containment",
    ):
        if field not in plan or (isinstance(plan.get(field), str) and not plan.get(field).strip()):
            errors.append(f"change_plan.{field} is required")
    expected_files = [str(item) for item in plan.get("expected_files") or []]
    reasons = plan.get("file_reasons")
    if not isinstance(reasons, dict):
        errors.append("change_plan.file_reasons is mandatory and must be an object")
    else:
        for path in expected_files:
            value = reasons.get(path)
            if isinstance(value, dict):
                for field in ("why", "root_cause_mechanism", "validation"):
                    if not str(value.get(field) or "").strip():
                        errors.append(f"change_plan.file_reasons.{path}.{field} is required")
            elif not isinstance(value, str) or not value.strip():
                errors.append(f"change_plan.file_reasons lacks justification for {path}")
        extra = sorted(set(str(item) for item in reasons) - set(expected_files))
        if extra:
            errors.append("change_plan.file_reasons contains paths outside expected_files: " + ", ".join(extra))
    if plan.get("scope_expansion"):
        errors.append("CHANGE_PLANNED must be regenerated after material scope expansion")
    return sorted(set(errors))


BLAST_RADIUS_COVERAGE_FIELDS = (
    "direct_components",
    "adjacent_components",
    "callers_callees",
    "api_contracts",
    "database_data_boundaries",
    "tenant_auth_boundaries",
    "financial_zatca_boundaries",
    "provider_boundaries",
    "concurrency_idempotency_boundaries",
    "deployment_infra_boundaries",
    "tests",
    "observability",
    "migration_rollback_impact",
    "invariants",
    "validation_depth",
)


def validate_blast_radius(coverage: dict[str, Any] | None, *, domains: Iterable[str] = ()) -> list[str]:
    """Require an explicit coupling map; absence is unknown impact, not no impact."""

    if not isinstance(coverage, dict):
        return ["BLAST_RADIUS_MAPPED requires structured blast_radius coverage"]
    if isinstance(coverage.get("coverage"), dict):
        coverage = coverage["coverage"]
    errors: list[str] = []
    for field in BLAST_RADIUS_COVERAGE_FIELDS:
        if field not in coverage:
            errors.append(f"blast_radius.{field} is required")
        elif not isinstance(coverage.get(field), list):
            errors.append(f"blast_radius.{field} must be an array")
    if not coverage.get("direct_components"):
        errors.append("blast_radius.direct_components must identify direct impact")
    if not coverage.get("validation_depth"):
        errors.append("blast_radius.validation_depth must describe intended validation")
    if coverage.get("unknown_material_coupling") is True and coverage.get("unknown_coupling_action") not in {"EXPAND_CONTEXT", "ESCALATE_BLOCK"}:
        errors.append("Unknown material coupling requires context expansion or escalation")
    normalized = {str(item).upper() for item in domains}
    unknown_domains = sorted(normalized - VALID_DOMAINS)
    if unknown_domains:
        errors.append("Unknown blast-radius domain: " + ", ".join(unknown_domains))
    domain_field = {
        "DATABASE": "database_data_boundaries",
        "AUTH_TENANT": "tenant_auth_boundaries",
        "FINANCIAL": "financial_zatca_boundaries",
        "ZATCA": "financial_zatca_boundaries",
        "PROVIDER": "provider_boundaries",
        "CONCURRENCY": "concurrency_idempotency_boundaries",
        "SECURITY": "tenant_auth_boundaries",
    }
    for domain in normalized & set(domain_field):
        if not coverage.get(domain_field[domain]):
            errors.append(f"blast_radius.{domain_field[domain]} is required for {domain}")
    return sorted(set(errors))


TARGETED_BASE_CASES = (
    "original_reproduction",
    "normal_case",
    "nearest_boundary",
    "invalid_input",
    "empty_null_missing_input",
    "repeated_operation",
    "retry_behavior",
    "stale_state",
    "error_path",
)
TARGETED_DOMAIN_CASES = {
    "AUTH_TENANT": ("authorization_denial", "tenant_crossing_denial", "id_tampering_denial"),
    "FINANCIAL": ("idempotency", "financial_duplicate_prevention", "ledger_consistency"),
    "ZATCA": ("legal_state_machine", "duplicate_prevention", "immutability"),
    "DATABASE": ("database_migration", "database_recovery", "compatibility_matrix"),
    "PROVIDER": ("provider_failure", "provider_reconciliation", "provider_idempotency"),
    "CONCURRENCY": ("concurrency", "idempotency", "no_duplicate_durable_side_effect"),
    "SECURITY": ("authorization_denial", "secrets_scan", "fail_closed_boundary"),
}


def validate_targeted_validation(
    metadata: dict[str, Any] | None,
    *,
    risk_class: str | None = None,
    domains: Iterable[str] = (),
    required_cases: Iterable[str] = (),
) -> list[str]:
    """Validate semantic case coverage instead of accepting a type-only receipt."""

    metadata = metadata if isinstance(metadata, dict) else {}
    cases = metadata.get("cases") or metadata.get("validation_cases") or metadata.get("semantic_case_matrix")
    if not isinstance(cases, (list, dict)) or not cases:
        return ["TARGETED_VALIDATION_PASSED requires a non-empty semantic case matrix"]
    if isinstance(cases, list):
        names = {str(item.get("case") or item.get("name")) for item in cases if isinstance(item, dict)}
        affirmative = {str(item.get("case") or item.get("name")): item for item in cases if isinstance(item, dict) and item.get("status") in {"PASS", "PASSED", "VERIFIED"}}
    else:
        names = set(str(item) for item in cases)
        affirmative = {str(key): value for key, value in cases.items() if value is True or (isinstance(value, dict) and value.get("status") in {"PASS", "PASSED", "VERIFIED"})}
    required = set(TARGETED_BASE_CASES if risk_class in {"HIGH", "CRITICAL"} or set(str(item).upper() for item in domains) - {"GENERAL"} else ("original_reproduction", "normal_case", "nearest_boundary", "error_path"))
    required.update(str(item) for item in required_cases)
    for domain in {str(item).upper() for item in domains}:
        required.update(TARGETED_DOMAIN_CASES.get(domain, ()))
    missing = sorted(required - names)
    not_affirmative = sorted(required & names - set(affirmative))
    errors = ["TARGETED_VALIDATION missing semantic cases: " + ", ".join(missing)] if missing else []
    if not_affirmative:
        errors.append("TARGETED_VALIDATION has non-affirmative cases: " + ", ".join(not_affirmative))
    if metadata.get("original_reproduction_passed") is not True:
        errors.append("TARGETED_VALIDATION must prove the original reproduction passes")
    return sorted(set(errors))


def validate_rollback_closure(
    metadata: dict[str, Any] | None,
    *,
    domains: Iterable[str] = (),
    policy: dict[str, Any] | None = None,
) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    for field in ("rollback_completed", "post_rollback_health_verified", "stable_artifact_digest", "rollback_receipt"):
        if metadata.get(field) in (None, False, ""):
            errors.append(f"ROLLBACK_CLOSURE requires {field}")
    normalized = {str(item).upper() for item in domains}
    unknown_domains = sorted(normalized - VALID_DOMAINS)
    if unknown_domains:
        errors.append("ROLLBACK_CLOSURE contains unknown domains: " + ", ".join(unknown_domains))
    rollback_gate = ((policy or {}).get("gates") or {}).get("ROLLBACK_CLOSURE") or {}
    required_by_domain = {
        str(domain).upper(): list(values or [])
        for domain, values in (rollback_gate.get("by_domain") or {}).items()
    }
    if normalized & HIGH_RISK_DOMAINS and not policy:
        errors.append("ROLLBACK_CLOSURE requires the authoritative policy for domain recovery checks")
    checks = metadata.get("domain_checks")
    if not isinstance(checks, list):
        errors.append("ROLLBACK_CLOSURE requires domain_checks")
        checks = []
    for domain in normalized & set(required_by_domain):
        expected = required_by_domain.get(domain, [])
        for required_type in expected:
            if not any(isinstance(item, dict) and item.get("type") == required_type and item.get("status") in {"PASS", "PASSED", "VERIFIED"} for item in checks):
                errors.append(f"ROLLBACK_CLOSURE missing {required_type}")
    return sorted(set(errors))


def validate_performance_evidence(metadata: dict[str, Any] | None) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    if metadata.get("applicable") is False:
        return []
    errors: list[str] = []
    for field in ("baseline_subject", "candidate_subject", "workload_id", "environment", "sample_count", "warmup", "variance", "threshold_policy", "regression_budget", "result_hash"):
        if metadata.get(field) in (None, "", []) or (field == "sample_count" and (not isinstance(metadata.get(field), int) or metadata.get(field) < 1)):
            errors.append(f"Performance evidence requires {field}")
    return sorted(set(errors))


def validate_database_release_sequence(sequence: Any) -> list[str]:
    if sequence is None:
        return []
    if not isinstance(sequence, list) or not sequence:
        return ["Database multi-release sequence must be a non-empty array"]
    required = ("expand", "compatible_deploy", "migrate_or_backfill", "verify", "contract")
    seen = [str(item.get("phase")) for item in sequence if isinstance(item, dict)]
    missing = [phase for phase in required if phase not in seen]
    errors = ["Database release sequence is missing phases: " + ", ".join(missing)] if missing else []
    positions = {phase: seen.index(phase) for phase in set(seen)}
    if all(phase in positions for phase in required) and any(positions[left] > positions[right] for left, right in zip(required, required[1:])):
        errors.append("Database release sequence is not expand-compatible-migrate-verify-contract")
    return sorted(set(errors))


def validate_work_origin(
    contract: dict[str, Any] | None,
    *,
    lifecycle_handoff: bool = False,
    authoritative_lifecycle: dict[str, Any] | None = None,
) -> list[str]:
    contract = contract if isinstance(contract, dict) else {}
    origin = str(contract.get("origin") or "").upper()
    errors: list[str] = []
    if not origin:
        errors.append("Work origin is required; missing origin cannot default to FEATURE")
    if origin not in {"FEATURE", "REPORTED_DEFECT", "INCIDENT", "MAINTENANCE", "REFACTOR", "OTHER"}:
        errors.append("Unsupported work origin")
    handoff = contract.get("authoritative_lifecycle_handoff")
    if origin != "REPORTED_DEFECT" and (
        contract.get("bug_lifecycle_case_id")
        or isinstance(handoff, dict)
    ):
        errors.append("Authoritative bug lifecycle fields require origin REPORTED_DEFECT")
    valid_handoff = isinstance(handoff, dict) and bool(
        handoff.get("case_id")
        and handoff.get("problem_case_fingerprint")
        and handoff.get("state") in {"HANDOFF_READY", "CHANGE_PLANNED"}
        and handoff.get("authority_store") == "controller-owned-sqlite"
    )
    if origin == "REPORTED_DEFECT" and not valid_handoff:
        errors.append("REPORTED_DEFECT cannot enter generic autopilot without an authoritative lifecycle handoff")
    if origin == "REPORTED_DEFECT" and valid_handoff:
        if not isinstance(authoritative_lifecycle, dict):
            errors.append("REPORTED_DEFECT handoff must be verified against the controller-owned lifecycle store")
        else:
            if authoritative_lifecycle.get("authority_store") != "controller-owned-sqlite":
                errors.append("REPORTED_DEFECT handoff is not backed by the controller-owned lifecycle store")
            if authoritative_lifecycle.get("authoritative_lifecycle") is not True:
                errors.append("REPORTED_DEFECT handoff is not authoritative")
            if authoritative_lifecycle.get("case_id") != handoff.get("case_id"):
                errors.append("REPORTED_DEFECT lifecycle store case ID mismatch")
            if authoritative_lifecycle.get("problem_case_fingerprint") != handoff.get("problem_case_fingerprint"):
                errors.append("REPORTED_DEFECT lifecycle handoff fingerprint mismatch")
            if authoritative_lifecycle.get("state") not in {"CHANGE_PLANNED", "HANDOFF_READY"}:
                errors.append("REPORTED_DEFECT lifecycle handoff is not at CHANGE_PLANNED")
        if contract.get("bug_lifecycle_case_id") != handoff.get("case_id"):
            errors.append("REPORTED_DEFECT lifecycle handoff case ID mismatch")
        scope = contract.get("scope") if isinstance(contract.get("scope"), dict) else {}
        if not isinstance(scope.get("file_reasons"), dict) or set(scope.get("file_reasons") or {}) != set(scope.get("expected_components") or {}):
            errors.append("REPORTED_DEFECT Change Contracts require per-file file_reasons")
    if origin == "INCIDENT" and not (lifecycle_handoff or contract.get("incident_id") or contract.get("containment_plan")):
        errors.append("INCIDENT work requires incident containment context before generic implementation")
    return sorted(set(errors))


def validate_red_green_evidence(
    metadata: dict[str, Any] | None,
    *,
    bad_base_sha: str | None,
    candidate_head_sha: str | None,
) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    if metadata.get("bad_base_sha") != bad_base_sha:
        errors.append("RED→GREEN bad_base_sha must equal the exact protected base SHA")
    if metadata.get("candidate_head_sha") != candidate_head_sha:
        errors.append("RED→GREEN candidate_head_sha must equal the exact candidate SHA")
    if metadata.get("bad_base_sha") and metadata.get("bad_base_sha") == metadata.get("candidate_head_sha"):
        errors.append("FLAKY_SAME_SHA: FAIL→PASS on one subject is not RED→GREEN proof")
    if metadata.get("same_oracle") is not True:
        errors.append("REGRESSION_TEST_PROVEN requires the same regression oracle")
    if metadata.get("bad_result") != "FAIL":
        errors.append("known-bad exact base must produce FAIL")
    if metadata.get("patched_result") != "PASS":
        errors.append("exact candidate must produce PASS")
    for field in ("oracle_id", "oracle_hash", "oracle_command", "bad_environment", "candidate_environment"):
        if not metadata.get(field):
            errors.append(f"RED→GREEN evidence requires {field}")
    if not isinstance(metadata.get("bad_exit_code"), int) or metadata.get("bad_exit_code") == 0:
        errors.append("RED→GREEN bad_exit_code must be a non-zero failing exit code")
    if metadata.get("candidate_exit_code") != 0:
        errors.append("RED→GREEN candidate_exit_code must be zero")
    for field in ("bad_output_hash", "candidate_output_hash"):
        if not DIGEST_RE.fullmatch(str(metadata.get(field) or "")):
            errors.append(f"RED→GREEN evidence requires {field}")
    if not metadata.get("failing_assertion"):
        errors.append("RED→GREEN evidence requires failing_assertion")
    if not metadata.get("passing_assertion"):
        errors.append("RED→GREEN evidence requires passing_assertion")
    if metadata.get("waiver") or metadata.get("equivalent_evidence") or metadata.get("manual_substitute"):
        errors.append("RED→GREEN has no waiver or equivalent-evidence substitute")
    return sorted(set(errors))


def red_green_result(metadata: dict[str, Any] | None, *, bad_base_sha: str | None, candidate_head_sha: str | None) -> str:
    metadata = metadata if isinstance(metadata, dict) else {}
    if metadata.get("bad_base_sha") and metadata.get("bad_base_sha") == metadata.get("candidate_head_sha"):
        return "FLAKY_SAME_SHA"
    return "VALID_RED_GREEN" if not validate_red_green_evidence(metadata, bad_base_sha=bad_base_sha, candidate_head_sha=candidate_head_sha) else "INVALID_REGRESSION_TEST"


def validate_test_integrity(metadata: dict[str, Any] | None) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    findings = metadata.get("findings") or metadata.get("integrity_findings") or []
    if not isinstance(findings, list):
        errors.append("test-integrity findings must be an array")
    else:
        for finding in findings:
            if not isinstance(finding, dict):
                errors.append("test-integrity finding must be an object")
                continue
            severity = str(finding.get("severity") or "").upper()
            code = str(finding.get("code") or "")
            if severity in {"BLOCK", "BLOCKED"} or code in {
                "SKIP_ADDED", "FOCUS_ADDED", "XFAIL_ADDED", "ASSERTION_REMOVED", "TEST_FILE_DELETED",
                "TEST_MOVED_OUT_OF_DISCOVERY", "TEST_CASE_COUNT_DECREASED", "CI_CONTINUE_ON_ERROR",
                "CI_STEP_DISABLED", "SHELL_FAILURE_MASKED", "TEST_DISCOVERY_CHANGED", "TEST_SCRIPT_MASKED",
                "COVERAGE_CONTROL_REMOVED", "EXCEPTION_SWALLOWED",
            }:
                errors.append(f"BLOCKED: TEST_WEAKENING:{code or 'UNSPECIFIED'}")
    for flag, message in (
        ("assertion_weakened", "assertion weakening"),
        ("mocked_failing_boundary", "failing boundary was mocked away"),
        ("blocking_test_nonblocking", "blocking test was made non-blocking"),
        ("failure_hidden", "test failure was hidden"),
        ("coverage_lowered", "coverage was lowered"),
    ):
        if metadata.get(flag) is True:
            errors.append("BLOCKED: " + message)
    if metadata.get("oracle_discriminates_bad_and_fixed") is False:
        errors.append("BLOCKED: INVALID_REGRESSION_TEST")
    if metadata.get("same_sha_fail_pass") is True:
        errors.append("BLOCKED: FLAKY_SAME_SHA")
    return sorted(set(errors))


def validate_diff_forensics(
    metadata: dict[str, Any] | None,
    *,
    planned_files: Iterable[str] = (),
    expected_diff_hash: str | None = None,
    expected_base_sha: str | None = None,
    expected_candidate_sha: str | None = None,
    actual_git_inventory: dict[str, Any] | None = None,
) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    files = metadata.get("files") or metadata.get("changed_files")
    if files is None:
        errors.append("DIFF_FORENSICS_PASS requires the complete actual changed-file list")
    else:
        if not isinstance(files, list):
            errors.append("diff forensics files must be an array")
        else:
            for index, item in enumerate(files):
                if not isinstance(item, dict) or not item.get("path") or not item.get("justification"):
                    errors.append(f"DIFF_FORENSICS_PASS requires a justification for changed file {index}")
                if isinstance(item, dict):
                    for field in ("planned", "security_impact", "data_domain_impact", "generated", "category"):
                        if field not in item:
                            errors.append(f"DIFF_FORENSICS_PASS requires {field} for {item.get('path', index)}")
                if isinstance(item, dict) and item.get("unexpected") is True:
                    errors.append(f"Unexpected changed file requires re-planning: {item.get('path')}")
    if metadata.get("complete_changed_file_list") is not True:
        errors.append("DIFF_FORENSICS_PASS requires complete_changed_file_list=true")
    if not isinstance(metadata.get("actual_changed_files"), list):
        errors.append("DIFF_FORENSICS_PASS requires actual_changed_files")
    if not isinstance(metadata.get("allowed_scope"), list):
        errors.append("DIFF_FORENSICS_PASS requires allowed_scope")
    actual_risk = str(metadata.get("actual_risk") or "").upper()
    if actual_risk not in {"R0", "R1", "R2", "R3", "R4"}:
        errors.append("DIFF_FORENSICS_PASS requires a valid actual_risk classification")
    actual_domains = metadata.get("actual_domains")
    if not isinstance(actual_domains, list) or not actual_domains:
        errors.append("DIFF_FORENSICS_PASS requires actual_domains")
    else:
        normalized_domains = {str(item).upper() for item in actual_domains}
        unknown_domains = sorted(normalized_domains - VALID_DOMAINS)
        if unknown_domains:
            errors.append("DIFF_FORENSICS_PASS contains unknown actual domains: " + ", ".join(unknown_domains))
    if not str(metadata.get("analysis_method") or "").strip():
        errors.append("DIFF_FORENSICS_PASS requires analysis_method")
    if expected_diff_hash is not None and metadata.get("reviewed_diff_hash") != expected_diff_hash:
        errors.append("DIFF_FORENSICS_PASS must bind the exact reviewed diff hash")
    strict_inventory = expected_diff_hash is not None or metadata.get("require_git_inventory") is True
    inventory = metadata.get("git_inventory")
    if strict_inventory:
        errors.extend(validate_git_inventory(inventory))
        if actual_git_inventory is not None:
            if inventory != actual_git_inventory:
                errors.append("DIFF_FORENSICS_PASS metadata does not match the actual Git inventory")
        if isinstance(inventory, dict):
            if expected_base_sha is not None and inventory.get("base_sha") != expected_base_sha:
                errors.append("DIFF_FORENSICS_PASS must bind the exact protected base SHA")
            if expected_candidate_sha is not None and inventory.get("candidate_sha") != expected_candidate_sha:
                errors.append("DIFF_FORENSICS_PASS must bind the exact candidate SHA")
            if expected_diff_hash is not None and inventory.get("diff_hash") != expected_diff_hash:
                errors.append("DIFF_FORENSICS_PASS Git inventory diff hash mismatch")
    planned = {str(item) for item in planned_files}
    changed = {str(item.get("path")) for item in files or [] if isinstance(item, dict) and item.get("path")}
    actual_declared = {str(item) for item in metadata.get("actual_changed_files") or []}
    allowed_scope = {str(item) for item in metadata.get("allowed_scope") or []}
    if actual_declared != changed:
        errors.append("DIFF_FORENSICS_PASS actual_changed_files must exactly match the per-file forensic records")
    if allowed_scope and changed - allowed_scope and metadata.get("scope_replanned") is not True:
        errors.append("DIFF_FORENSICS_PASS contains a file outside allowed_scope; replan is required")
    if planned and changed - planned and metadata.get("scope_replanned") is not True:
        errors.append("Material diff scope expansion must return to CHANGE_PLANNED")
    if strict_inventory and isinstance(inventory, dict) and isinstance(inventory.get("files"), list):
        git_changed = {
            str(item.get("path"))
            for item in inventory["files"]
            if isinstance(item, dict) and item.get("path")
        }
        if changed != git_changed:
            errors.append("DIFF_FORENSICS_PASS file records must exactly match Git's changed-file set")
        if actual_declared != git_changed:
            errors.append("DIFF_FORENSICS_PASS actual_changed_files must exactly match Git's changed-file set")
    for key in (
        "test_weakening",
        "secret_detected",
        "pii_logging",
        "fail_open",
        "tenant_scope_changed",
        "permission_changed_unplanned",
        "migration_unplanned",
        "debug_statements",
        "dependency_unplanned",
        "api_contract_changed_unplanned",
    ):
        if metadata.get(key) is True:
            errors.append(f"BLOCKED: DIFF_FORENSICS:{key}")
    return sorted(set(errors))


def validate_ci_metadata(
    metadata: dict[str, Any] | None,
    *,
    head_sha: str | None,
    diff_hash: str | None,
    pr_head_sha: str | None = None,
    merged_main_sha: str | None = None,
    require_post_merge: bool = False,
) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    expected_pr_head = pr_head_sha or head_sha
    if metadata.get("pr_head_sha") != expected_pr_head:
        errors.append("CI evidence must bind the exact final PR head SHA")
    if metadata.get("reviewed_diff_hash") != diff_hash:
        errors.append("CI evidence must bind the final reviewed diff hash")
    if not metadata.get("workflow_run_id"):
        errors.append("CI evidence requires a protected workflow run identity")
    checks = metadata.get("required_checks")
    if not isinstance(checks, list) or not checks:
        errors.append("CI evidence requires required_checks")
    if str(metadata.get("conclusion") or "").upper() != "SUCCESS":
        errors.append("CI evidence must have SUCCESS conclusion")
    if metadata.get("earlier_sha") is not None and metadata.get("earlier_sha") != (merged_main_sha or head_sha):
        errors.append("Earlier-SHA CI evidence cannot satisfy final-head CI_PASS")
    if require_post_merge or merged_main_sha is not None:
        if metadata.get("merged_main_sha") != merged_main_sha:
            errors.append("Post-merge CI must bind the exact merged-main SHA")
        if not metadata.get("post_merge_ci_run_id"):
            errors.append("Post-merge CI requires post_merge_ci_run_id")
    return sorted(set(errors))


def validate_staging_metadata(
    metadata: dict[str, Any] | None,
    *,
    head_sha: str | None,
    artifact_digest: str | None,
) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    if metadata.get("candidate_head_sha") != head_sha:
        errors.append("STAGING_PASS must bind the exact reviewed candidate SHA")
    if metadata.get("artifact_digest") != artifact_digest:
        errors.append("STAGING_PASS must bind the exact candidate artifact digest")
    if metadata.get("environment") != "staging":
        errors.append("STAGING_PASS requires a non-production staging environment")
    if metadata.get("real_customer_pii") is True or metadata.get("real_financial_side_effects") is True:
        errors.append("STAGING_PASS forbids real customer PII and financial/legal side effects")
    for field in ("original_symptom_absent", "expected_behavior_present", "health_verified", "affected_workflow_verified"):
        if metadata.get(field) is not True:
            errors.append(f"STAGING_PASS requires {field}")
    return sorted(set(errors))


def validate_full_regression_metadata(
    metadata: dict[str, Any] | None,
    *,
    base_sha: str | None,
    candidate_head_sha: str | None,
) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    if metadata.get("protected_base_sha") != base_sha:
        errors.append("Full regression evidence must bind the exact protected base SHA")
    if metadata.get("candidate_head_sha") != candidate_head_sha:
        errors.append("Full regression evidence must bind the exact candidate SHA")
    checks = metadata.get("test_layers") or metadata.get("checks")
    if not isinstance(checks, list) or not checks:
        errors.append("Full regression evidence requires test_layers")
    if str(metadata.get("conclusion") or metadata.get("result") or "").upper() not in {"PASS", "PASSED", "SUCCESS"}:
        errors.append("Full regression evidence must have a passing conclusion")
    preexisting = metadata.get("preexisting_failures")
    if preexisting:
        if not isinstance(preexisting, list):
            errors.append("preexisting_failures must be an array")
        else:
            for index, item in enumerate(preexisting):
                if not isinstance(item, dict) or item.get("base_result") != "FAIL" or item.get("candidate_result") != "FAIL" or not item.get("oracle"):
                    errors.append(f"preexisting_failures/{index} requires exact base and candidate proof")
    if metadata.get("earlier_sha") is not None and metadata.get("earlier_sha") != candidate_head_sha:
        errors.append("Earlier-SHA regression evidence cannot satisfy final-candidate validation")
    return sorted(set(errors))


def validate_progressive_exposure(metadata: dict[str, Any] | None, *, risk_class: str | None) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    if risk_class not in {"HIGH", "CRITICAL"}:
        return []
    errors: list[str] = []
    if metadata.get("strategy") not in {"FEATURE_FLAG", "BLUE_GREEN", "CANARY", "TENANT_LIMITED", "BRANCH_LIMITED", "READ_ONLY", "WRITE_GATE"}:
        errors.append("High-risk exposure requires an explicit progressive strategy")
    if metadata.get("rollback_trigger") is None or not str(metadata.get("rollback_trigger") or "").strip():
        errors.append("High-risk exposure requires a rollback trigger")
    if metadata.get("stop_conditions") is None or not metadata.get("stop_conditions"):
        errors.append("High-risk exposure requires stop conditions")
    if metadata.get("scope_limit") is None or not str(metadata.get("scope_limit") or "").strip():
        errors.append("High-risk exposure requires a bounded exposure scope")
    if risk_class == "CRITICAL":
        if metadata.get("write_gate") is not True:
            errors.append("Critical exposure requires an explicit write gate")
        if not str(metadata.get("owner_stop_condition") or "").strip():
            errors.append("Critical exposure requires an owner stop condition")
    rollback_hash = str(metadata.get("rollback_trigger_hash") or "")
    if metadata.get("rollback_trigger") and not DIGEST_RE.fullmatch(rollback_hash):
        errors.append("Progressive exposure rollback trigger requires a deterministic sha256 hash")
    return sorted(set(errors))


def validate_production_release_metadata(
    metadata: dict[str, Any] | None,
    *,
    head_sha: str | None,
    artifact_digest: str | None,
    merged_main_sha: str | None = None,
    pr_head_sha: str | None = None,
) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    expected_main = merged_main_sha or head_sha
    if merged_main_sha is not None and not pr_head_sha:
        errors.append("Production release subject is missing the reviewed PR head")
    if merged_main_sha is not None and metadata.get("pr_head_sha") != pr_head_sha:
        errors.append("Production release must retain the exact reviewed PR head provenance")
    if metadata.get("reviewed_main_sha") != expected_main or metadata.get("deployed_revision") != expected_main:
        errors.append("Production release must bind the exact merged-main revision; PR head and merged-main are not interchangeable")
    if metadata.get("artifact_digest") != artifact_digest:
        errors.append("Production release must bind the exact validated artifact digest")
    if metadata.get("environment") != "production":
        errors.append("Production release evidence requires the production environment")
    for field in ("workflow_run_id", "deployment_receipt", "occurred_at", "production_release_id"):
        if not metadata.get(field):
            errors.append(f"Production release evidence requires {field}")
    if metadata.get("protected_workflow") is not True:
        errors.append("Production release evidence requires a protected workflow")
    for field in ("release_id", "receipt_hash"):
        if field in metadata and not metadata.get(field):
            errors.append(f"Production release evidence requires {field} when declared")
    return sorted(set(errors))


def validate_post_deploy_metadata(
    metadata: dict[str, Any] | None,
    *,
    artifact_digest: str | None,
    deployed_revision: str | None = None,
) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    if metadata.get("deployed_artifact_digest") != artifact_digest:
        errors.append("POST_DEPLOY_VERIFIED must bind the exact deployed artifact digest")
    if deployed_revision is not None and metadata.get("deployed_revision") != deployed_revision:
        errors.append("POST_DEPLOY_VERIFIED must bind the exact deployed revision")
    for field in ("original_symptom_absent", "expected_behavior_present", "health_verified", "synthetic_transaction_safe", "observation_window_complete"):
        if metadata.get(field) is not True:
            errors.append(f"POST_DEPLOY_VERIFIED requires {field}")
    for field in ("error_rate", "latency", "api_errors", "queue_health", "database_health", "provider_health", "auth_health", "financial_anomalies", "zatca_anomalies"):
        if field not in metadata:
            errors.append(f"POST_DEPLOY_VERIFIED requires adjacent health field {field}")
    if metadata.get("safety_uncertain") is True or metadata.get("original_problem_persists") is True:
        errors.append("ROLLBACK_REQUIRED: production safety is not proven")
    return sorted(set(errors))


def validate_synthetic_transaction_metadata(metadata: dict[str, Any] | None) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    if metadata.get("synthetic_transaction_safe") is not True:
        errors.append("SYNTHETIC_TRANSACTION requires synthetic_transaction_safe=true")
    for field in ("transaction_id", "environment", "side_effect_policy", "result_hash"):
        if not str(metadata.get(field) or "").strip():
            errors.append(f"SYNTHETIC_TRANSACTION requires {field}")
    if metadata.get("environment") != "production":
        errors.append("SYNTHETIC_TRANSACTION must identify the production environment")
    return sorted(set(errors))


def validate_observation_window_metadata(metadata: dict[str, Any] | None) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    if metadata.get("observation_window_complete") is not True:
        errors.append("OBSERVATION_WINDOW requires observation_window_complete=true")
    for field in ("window_id", "started_at", "ended_at", "duration_seconds", "sample_count", "health_summary_hash"):
        if metadata.get(field) in (None, "", []) or (field in {"duration_seconds", "sample_count"} and (not isinstance(metadata.get(field), int) or metadata.get(field) < 1)):
            errors.append(f"OBSERVATION_WINDOW requires {field}")
    return sorted(set(errors))


def validate_artifact_chain(
    metadata: dict[str, Any] | None,
    *,
    head_sha: str | None,
    artifact_digest: str | None,
    merged_main_sha: str | None = None,
) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    expected_source = merged_main_sha or head_sha
    if metadata.get("source_sha") != expected_source:
        errors.append("Artifact chain source SHA does not match the exact active subject")
    if merged_main_sha is not None and metadata.get("merged_main_sha") != merged_main_sha:
        errors.append("Artifact chain must bind merged_main_sha, not only the PR head")
    if metadata.get("artifact_digest") != artifact_digest:
        errors.append("Artifact chain digest does not match the lifecycle artifact")
    for field in ("release_fingerprint", "sbom_digest", "provenance_digest", "attestation_digest"):
        value = metadata.get(field)
        if not DIGEST_RE.fullmatch(str(value or "")):
            errors.append(f"Artifact chain requires {field}")
    if not str(metadata.get("artifact_identity") or "").strip():
        errors.append("Artifact chain requires immutable artifact_identity")
    if metadata.get("rebuilt_after_validation") is True:
        errors.append("Validated subject cannot be rebuilt into different bytes")
    if metadata.get("mutable_tag_only") is True:
        errors.append("Mutable tag cannot be the sole artifact identity")
    return sorted(set(errors))


def continuation_decision(
    failure_class: str,
    *,
    after_production_exposure: bool = False,
    previous_attempt_fingerprint: str | None = None,
    current_attempt_fingerprint: str | None = None,
    material_change: bool = False,
) -> dict[str, Any]:
    failure = str(failure_class).upper()
    if after_production_exposure:
        return {"action": "ROLLBACK_REQUIRED", "continue_unrelated_work": True, "reason": "production safety is not proven"}
    if failure in {"MISSING_CREDENTIAL", "EXTERNAL_DEPENDENCY", "BUSINESS_DECISION_REQUIRED", "SERVICE_PERMISSION_MISSING", "ENVIRONMENT_NOT_PROVISIONED"}:
        return {"action": "WAITING_EXTERNAL_DEPENDENCY", "continue_unrelated_work": True, "reason": "external prerequisite is unavailable"}
    if failure in {"POLICY_VIOLATION", "SECRET_EXPOSURE_ATTEMPT", "DESTRUCTIVE_UNREVERSIBLE", "EVIDENCE_FABRICATION", "CONTROL_PLANE_CORRUPTION"}:
        return {"action": "QUARANTINE", "continue_unrelated_work": True, "reason": "unsafe task is isolated"}
    if previous_attempt_fingerprint and previous_attempt_fingerprint == current_attempt_fingerprint and not material_change:
        return {"action": "AUTO_REPLAN", "continue_unrelated_work": True, "reason": "identical retry strategy is prohibited"}
    if failure in {"MODEL_PROVIDER_UNAVAILABLE", "MODEL_TIMEOUT", "MODEL_RATE_LIMIT", "CI_UNAVAILABLE", "NETWORK_TRANSIENT"}:
        return {"action": "AUTO_REPAIR", "continue_unrelated_work": True, "reason": "bounded alternate execution may proceed"}
    return {"action": "AUTO_REPLAN", "continue_unrelated_work": True, "reason": "the failing strategy must change before retry"}


def validate_workshopos_message(
    recipient: str,
    *,
    profile: dict[str, Any] | None = None,
    browser_or_e2e: bool = False,
    uses_dummy_data: bool = False,
) -> list[str]:
    errors: list[str] = []
    profile = profile if isinstance(profile, dict) else {}
    destinations = profile.get("test_only_message_destinations")
    if not isinstance(destinations, list) or not destinations:
        return ["WorkshopOS profile configuration must declare test_only_message_destinations"]
    allowed = {str(item) for item in destinations}
    if str(recipient) not in allowed:
        errors.append("WorkshopOS test messages may target only the configured test-only destination")
    if PHONE_RE.search(str(recipient)) and str(recipient) not in allowed:
        errors.append("Unexpected phone destination is prohibited")
    if browser_or_e2e and not uses_dummy_data:
        errors.append("WorkshopOS browser/E2E tests must use dummy data")
    return sorted(set(errors))
