from __future__ import annotations

import re
from typing import Any, Iterable


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

RISK_LEVEL_TO_CLASS = {
    "R0": "LOW",
    "R1": "LOW",
    "R2": "MEDIUM",
    "R3": "HIGH",
    "R4": "CRITICAL",
}
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
CRITICAL_DOMAINS = {"DATABASE", "FINANCIAL", "ZATCA", "SECURITY"}
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


def risk_class_for_level(level: str | None) -> str | None:
    return RISK_LEVEL_TO_CLASS.get(str(level).upper()) if level is not None else None


def derive_risk_class(
    *,
    risk: str | None,
    domains: Iterable[str] = (),
    changed_paths: Iterable[str] = (),
    operation_text: str = "",
) -> str:
    """Derive a monotonic protocol risk class from deterministic inputs."""

    normalized_domains = {str(item).upper() for item in domains}
    paths = {str(item).replace("\\", "/").casefold() for item in changed_paths}
    text = " ".join([operation_text, *paths]).casefold()
    if normalized_domains & CRITICAL_DOMAINS or any(
        marker in text
        for marker in (
            "drop table",
            "drop column",
            "truncate",
            "payment",
            "ledger",
            "zatca",
            "kms",
            "secret",
            "production",
            "destructive",
        )
    ):
        return "CRITICAL"
    if any(path.startswith("migrations/") or path.startswith("migration/") for path in paths):
        return "HIGH"
    if normalized_domains & HIGH_RISK_DOMAINS or risk in {"R3", "R4"}:
        return "HIGH"
    if risk in {"R2"}:
        return "MEDIUM"
    return "LOW"


def infer_domains(case: dict[str, Any] | None, explicit_domains: Iterable[str] = ()) -> list[str]:
    """Infer only escalation domains; explicit or inferred risk can never be lowered."""

    values = [str(item).upper() for item in explicit_domains]
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
    if record is not None:
        if not isinstance(record, dict):
            errors.append("classification_record must be an object")
        else:
            for field in ("evidence", "reproduction_status", "authoritative_expected_behavior", "competing_explanations_tested"):
                if field not in record:
                    errors.append(f"classification_record.{field} is required")
            if record.get("reproduction_status") not in {"NOT_ATTEMPTED", "NOT_REPRODUCED", "REPRODUCED", "INCONCLUSIVE"}:
                errors.append("classification_record.reproduction_status is invalid")
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
    if reasons is not None:
        if not isinstance(reasons, dict):
            errors.append("change_plan.file_reasons must be an object")
        else:
            for path in expected_files:
                if not str(reasons.get(path) or "").strip():
                    errors.append(f"change_plan.file_reasons lacks justification for {path}")
    if plan.get("scope_expansion"):
        errors.append("CHANGE_PLANNED must be regenerated after material scope expansion")
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


def validate_diff_forensics(metadata: dict[str, Any] | None, *, planned_files: Iterable[str] = ()) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    files = metadata.get("files") or metadata.get("changed_files")
    if files is not None:
        if not isinstance(files, list):
            errors.append("diff forensics files must be an array")
        else:
            for index, item in enumerate(files):
                if not isinstance(item, dict) or not item.get("path") or not item.get("justification"):
                    errors.append(f"DIFF_FORENSICS_PASS requires a justification for changed file {index}")
                if isinstance(item, dict) and item.get("unexpected") is True:
                    errors.append(f"Unexpected changed file requires re-planning: {item.get('path')}")
    planned = {str(item) for item in planned_files}
    changed = {str(item.get("path")) for item in files or [] if isinstance(item, dict) and item.get("path")}
    if planned and changed - planned and metadata.get("scope_replanned") is not True:
        errors.append("Material diff scope expansion must return to CHANGE_PLANNED")
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


def validate_ci_metadata(metadata: dict[str, Any] | None, *, head_sha: str | None, diff_hash: str | None) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    if metadata.get("pr_head_sha") != head_sha:
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
    if metadata.get("earlier_sha") is not None and metadata.get("earlier_sha") != head_sha:
        errors.append("Earlier-SHA CI evidence cannot satisfy final-head CI_PASS")
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
    return sorted(set(errors))


def validate_production_release_metadata(
    metadata: dict[str, Any] | None,
    *,
    head_sha: str | None,
    artifact_digest: str | None,
) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    if metadata.get("reviewed_main_sha") != head_sha or metadata.get("deployed_revision") != head_sha:
        errors.append("Production release must bind the exact reviewed and deployed revision")
    if metadata.get("artifact_digest") != artifact_digest:
        errors.append("Production release must bind the exact validated artifact digest")
    if metadata.get("environment") != "production":
        errors.append("Production release evidence requires the production environment")
    for field in ("workflow_run_id", "deployment_receipt", "occurred_at", "production_release_id"):
        if not metadata.get(field):
            errors.append(f"Production release evidence requires {field}")
    if metadata.get("protected_workflow") is not True:
        errors.append("Production release evidence requires a protected workflow")
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


def validate_artifact_chain(metadata: dict[str, Any] | None, *, head_sha: str | None, artifact_digest: str | None) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    errors: list[str] = []
    if metadata.get("source_sha") != head_sha:
        errors.append("Artifact chain source SHA does not match candidate SHA")
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
