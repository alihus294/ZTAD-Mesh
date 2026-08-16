from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .repository import GitRepository
from .path_security import path_matches, filesystem_case_insensitive, normalize_repo_path
from .util import load_data

RISK_ORDER = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}
RISK_CLASS_TO_LEVEL = {"LOW": "R1", "MEDIUM": "R2", "HIGH": "R3", "CRITICAL": "R4"}
RISK_TO_CLASS = {"R0": "LOW", "R1": "LOW", "R2": "MEDIUM", "R3": "HIGH", "R4": "CRITICAL"}
SCORE_TO_RISK = ((2, "R0"), (6, "R1"), (11, "R2"), (16, "R3"), (22, "R4"))
KNOWN_DOMAINS = frozenset({
    "GENERAL",
    "DATABASE",
    "AUTH_TENANT",
    "FINANCIAL",
    "ZATCA",
    "PROVIDER",
    "CONCURRENCY",
    "SECURITY",
})


@dataclass(frozen=True)
class RiskResult:
    risk: str
    score: int
    score_risk: str
    dimensions: dict[str, int]
    hard_minimum: str
    reasons: list[str]
    blocked: bool
    blockers: list[str]
    unknowns: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk": self.risk,
            "score": self.score,
            "score_risk": self.score_risk,
            "dimensions": self.dimensions,
            "hard_minimum": self.hard_minimum,
            "reasons": self.reasons,
            "blocked": self.blocked,
            "blockers": self.blockers,
            "unknowns": self.unknowns,
            "agent_may_downgrade": False,
            "effective_risk": self.risk,
        }


def effective_risk(
    *,
    previous: str = "R0",
    requested: str = "R0",
    contract: str = "R0",
    path: str = "R0",
    operation: str = "R0",
    domain_minimum: str = "R0",
    actual_diff: str = "R0",
    runtime: str = "R0",
) -> str:
    """Canonical monotonic risk join used by all delivery decisions."""

    values = (previous, requested, contract, path, operation, domain_minimum, actual_diff, runtime)
    unknown = [value for value in values if value not in RISK_ORDER]
    if unknown:
        raise ValueError("Unknown risk level: " + ", ".join(sorted(set(unknown))))
    return max(values, key=RISK_ORDER.__getitem__)


def risk_class_to_level(value: str | None) -> str:
    normalized = str(value or "LOW").upper()
    if normalized in RISK_ORDER:
        return normalized
    if normalized in RISK_CLASS_TO_LEVEL:
        return RISK_CLASS_TO_LEVEL[normalized]
    raise ValueError("Unknown risk class: " + normalized)


def risk_level_to_class(value: str | None) -> str:
    normalized = str(value or "R0").upper()
    if normalized not in RISK_TO_CLASS:
        raise ValueError("Unknown risk level: " + normalized)
    return RISK_TO_CLASS[normalized]


def assert_monotonic_risk(previous: str, current: str) -> None:
    if previous not in RISK_ORDER or current not in RISK_ORDER:
        raise ValueError("Unknown risk level in monotonicity check")
    if RISK_ORDER[current] < RISK_ORDER[previous]:
        raise ValueError(f"Risk downgrade is prohibited: {previous} -> {current}")


def max_risk(*levels: str) -> str:
    unknown = [level for level in levels if level not in RISK_ORDER]
    if unknown:
        raise ValueError("Unknown risk level: " + ", ".join(sorted(set(unknown))))
    return max(levels, key=lambda value: RISK_ORDER[value]) if levels else "R0"


def score_to_risk(score: int) -> str:
    for maximum, risk in SCORE_TO_RISK:
        if score <= maximum:
            return risk
    return "R4"


def _contract_dimensions(contract: dict[str, Any]) -> tuple[dict[str, int], list[str], list[str], list[str]]:
    scope = contract.get("scope", {}) or {}
    governance = contract.get("governance", {}) or {}
    requirements = contract.get("requirements", {}) or {}
    release = contract.get("release", {}) or {}
    verification = contract.get("verification", {}) or {}
    quality = contract.get("quality_attributes", {}) or {}
    data_class = str(scope.get("data_classification", "UNKNOWN")).upper()
    criticality = str(scope.get("service_criticality", "UNKNOWN")).lower()
    expected_components = scope.get("expected_components") or []
    assumptions = requirements.get("assumptions") or []

    criticality_map = {"tier_0": 3, "tier0": 3, "tier_1": 2, "tier1": 2, "tier_2": 1, "tier2": 1, "tier_3": 0, "tier3": 0}
    data_map = {"C0": 0, "C1": 1, "C2": 3, "C3": 4}
    dimensions = {
        "user_service_impact": criticality_map.get(criticality, 3),
        "data_security_privacy": data_map.get(data_class, 4),
        "financial_regulatory": 0,
        "reversibility": 3 if release.get("data_reversal_required") else 1 if release.get("rollback_strategy") else 3,
        "blast_radius_coupling": 3 if len(expected_components) > 2 else 2 if len(expected_components) == 2 else 1 if len(expected_components) == 1 else 3,
        "verification_maturity": 0,
        "operational_novelty": 0,
    }
    reasons: list[str] = []
    blockers: list[str] = []
    unknowns: list[str] = []

    text = " ".join(str(value) for value in [contract.get("title", ""), quality, requirements, scope]).lower()
    if any(term in text for term in ("payment", "pricing", "tax", "invoice", "zatca", "financial", "regulatory")):
        dimensions["financial_regulatory"] = 4
        reasons.append("Financial or regulatory semantics declared in the Change Contract")
    if scope.get("public_contract_change"):
        dimensions["blast_radius_coupling"] = max(dimensions["blast_radius_coupling"], 3)
        reasons.append("Public contract change declared")
    if scope.get("data_migration_expected"):
        dimensions["reversibility"] = max(dimensions["reversibility"], 2)
        reasons.append("Persistent data migration declared")
    unverified = [item for item in assumptions if str(item.get("status", "unverified")).lower() != "verified"]
    if unverified:
        dimensions["verification_maturity"] = 3
        blockers.append("Unverified assumptions remain in the Change Contract")
        unknowns.extend(str(item.get("id", "unknown-assumption")) for item in unverified)
    if not verification.get("test_oracles"):
        dimensions["verification_maturity"] = 3
        blockers.append("No test oracle is defined")
    if not verification.get("negative_cases"):
        dimensions["verification_maturity"] = max(dimensions["verification_maturity"], 2)
        blockers.append("No negative verification case is defined")
    if not release.get("rollback_strategy"):
        blockers.append("No rollback strategy is defined")
    if not governance.get("product_owner") or not governance.get("engineering_owner"):
        blockers.append("Required accountable owners are missing")
    if criticality not in criticality_map:
        unknowns.append("service_criticality")
    if data_class not in data_map:
        unknowns.append("data_classification")
    return dimensions, reasons, blockers, unknowns


def _scan_diff_for_operations(diff_text: str, operations: dict[str, str]) -> list[str]:
    added = "\n".join(line[1:] for line in diff_text.splitlines() if line.startswith("+") and not line.startswith("+++"))
    detected = {name for name, pattern in operations.items() if re.search(pattern, added, re.IGNORECASE | re.MULTILINE)}
    # Analyze each added SQL statement independently so a WHERE in a later statement
    # cannot make an earlier unbounded UPDATE/DELETE appear safe.
    without_comments = re.sub(r"--[^\n]*|/\*[\s\S]*?\*/", " ", added)
    for statement in re.split(r";", without_comments):
        normalized = re.sub(r"\s+", " ", statement).strip().upper()
        if not normalized:
            continue
        if re.match(r'^UPDATE\s+[A-Z0-9_."`\[\]]+\s+SET\b', normalized) and not re.search(r"\bWHERE\b", normalized):
            detected.add("unbounded_update")
        if re.match(r'^DELETE\s+FROM\s+[A-Z0-9_."`\[\]]+\b', normalized) and not re.search(r"\bWHERE\b", normalized):
            detected.add("unbounded_delete")
    return sorted(detected)


def _is_control_plane_path(path: str, prefixes: tuple[str, ...], *, case_insensitive: bool = False) -> bool:
    normalized = normalize_repo_path(path, case_insensitive=case_insensitive)
    if case_insensitive:
        prefixes = tuple(item.casefold() for item in prefixes)
    literals = {"AGENTS.md", "AGENTS.override.md", "CODEOWNERS", ".github/CODEOWNERS"}
    suffixes = ("/AGENTS.md", "/AGENTS.override.md")
    if case_insensitive:
        literals = {item.casefold() for item in literals}
        suffixes = tuple(item.casefold() for item in suffixes)
    if normalized in literals:
        return True
    if normalized.endswith(suffixes):
        return True
    return any(normalized.startswith(prefix) for prefix in prefixes)


def classify_risk(
    contract: dict[str, Any],
    *,
    changed_paths: Iterable[str] = (),
    diff_text: str = "",
    policy: dict[str, Any] | None = None,
) -> RiskResult:
    policy = policy or {}
    dimensions, reasons, blockers, unknowns = _contract_dimensions(contract)
    case_insensitive = bool(policy.get("case_insensitive_paths", filesystem_case_insensitive()))
    normalized_paths: set[str] = set()
    invalid_paths: list[str] = []
    for raw_path in changed_paths:
        try:
            normalized_paths.add(normalize_repo_path(raw_path, case_insensitive=case_insensitive))
        except (TypeError, ValueError):
            invalid_paths.append(repr(raw_path))
    paths = sorted(normalized_paths)
    hard_minimum = "R0"
    if invalid_paths:
        hard_minimum = "R4"
        blockers.append("Unsafe or invalid changed paths were supplied")
        unknowns.extend(f"invalid_path:{item}" for item in invalid_paths[:20])
        reasons.append("Invalid path input was contained and classified at maximum risk")

    hard = policy.get("hard_minimums", {}) or {}
    for level in ("R3", "R4"):
        for pattern in ((hard.get(level, {}) or {}).get("paths", []) or []):
            matches = [path for path in paths if path_matches(path, pattern, case_insensitive=case_insensitive)]
            if matches:
                hard_minimum = max_risk(hard_minimum, level)
                reasons.append(f"{level} path override matched {pattern}: {', '.join(matches[:5])}")

    manifest_names = set(policy.get("dependency_manifest_names", []) or []) or {
        "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
        "pyproject.toml", "requirements.txt", "requirements.lock", "poetry.lock", "uv.lock", "pom.xml",
        "build.gradle", "build.gradle.kts", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
    }
    manifest_names_cmp = {name.casefold() if case_insensitive else name for name in manifest_names}
    if any((Path(path).name.casefold() if case_insensitive else Path(path).name) in manifest_names_cmp for path in paths):
        hard_minimum = max_risk(hard_minimum, "R3")
        dimensions["operational_novelty"] = max(dimensions["operational_novelty"], 2)
        reasons.append("Dependency or build manifest changed")

    scope = contract.get("scope", {}) or {}
    if scope.get("public_contract_change") or scope.get("data_migration_expected"):
        hard_minimum = max_risk(hard_minimum, "R3")
    requested = str(((contract.get("governance") or {}).get("requested_risk") or "R0")).upper()
    if requested in RISK_ORDER:
        hard_minimum = max_risk(hard_minimum, requested)

    operations = policy.get("operation_patterns", {}) or {}
    detected_ops = _scan_diff_for_operations(diff_text, operations)
    if detected_ops:
        hard_minimum = "R4"
        dimensions["reversibility"] = max(dimensions["reversibility"], 3)
        reasons.append("R4 destructive or privilege operation detected: " + ", ".join(sorted(detected_ops)))

    control_prefixes = tuple(policy.get("control_plane_prefixes", [".github/", ".delivery/", ".agents/", ".codex-plugin/", "AGENTS.md"]))
    application_changes = [path for path in paths if not _is_control_plane_path(path, control_prefixes, case_insensitive=case_insensitive)]
    control_changes = [path for path in paths if _is_control_plane_path(path, control_prefixes, case_insensitive=case_insensitive)]
    if application_changes and control_changes:
        hard_minimum = "R4"
        reasons.append("Application behavior and delivery control-plane files changed together")

    score = sum(dimensions.values())
    score_risk = score_to_risk(score)
    domain_minimum = "R0"
    declared_domains = {
        str(item).upper()
        for item in (
            contract.get("domains") or
            scope.get("domains") or
            ((contract.get("governance") or {}).get("domains") or [])
        )
    }
    unknown_domains = sorted(declared_domains - KNOWN_DOMAINS)
    if unknown_domains:
        blockers.append("Unknown change domains require explicit classification")
        unknowns.extend("unknown_domain:" + item for item in unknown_domains)
    domain_text = " ".join(str(value) for value in [contract.get("title", ""), contract.get("scope", {}), contract.get("requirements", {})]).casefold()
    for domain, profile in (policy.get("domain_profiles") or {}).items():
        normalized_domain = str(domain).upper()
        markers = (str(normalized_domain).casefold(),)
        if normalized_domain in declared_domains or any(marker in domain_text for marker in markers):
            minimum_class = str((profile or {}).get("minimum_risk_class") or "HIGH").upper()
            domain_minimum = max_risk(domain_minimum, RISK_CLASS_TO_LEVEL.get(minimum_class, "R3"))
    governance = contract.get("governance") or {}
    previous = str(governance.get("previous_effective_risk") or "R0").upper()
    policy_risk = str(governance.get("policy_risk") or "R0").upper()
    operation_risk = "R4" if detected_ops else "R0"
    risk = effective_risk(
        previous=previous,
        requested=requested,
        contract=max_risk(score_risk, policy_risk),
        path=hard_minimum,
        operation=operation_risk,
        domain_minimum=domain_minimum,
        actual_diff=hard_minimum,
        runtime=str(contract.get("runtime_risk") or "R0").upper(),
    )
    # Unknown metadata is a blocking condition even when a policy elects to
    # assign a conservative numerical floor.  A risk number alone is not
    # permission to proceed with an unclassified change.
    blocked = bool(blockers or unknowns)
    if (blockers or unknowns) and policy.get("unknown_value_policy", "highest_plausible") == "highest_plausible":
        risk = max_risk(risk, "R2")
    return RiskResult(
        risk=risk,
        score=score,
        score_risk=score_risk,
        dimensions=dimensions,
        hard_minimum=hard_minimum,
        reasons=sorted(set(reasons)),
        blocked=blocked,
        blockers=sorted(set(blockers)),
        unknowns=sorted(set(unknowns)),
    )


def classify_repository_change(repo: GitRepository, contract: dict[str, Any], base: str, head: str, policy_path: Path) -> RiskResult:
    paths = [entry.path for entry in repo.changed_paths(base, head)]
    diff_text = repo.diff(base, head, unified=0)
    policy = load_data(policy_path)
    return classify_risk(contract, changed_paths=paths, diff_text=diff_text, policy=policy)
