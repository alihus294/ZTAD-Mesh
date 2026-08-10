from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .util import hash_directory, load_data, sha256_file


@dataclass(frozen=True)
class PolicySpec:
    mode: str
    consumers: tuple[str, ...]
    claim: str


@dataclass(frozen=True)
class PolicyStatus:
    name: str
    path: str
    mode: str
    consumers: tuple[str, ...]
    loaded: bool
    consumer_modules_available: bool
    errors: tuple[str, ...]
    sha256: str | None
    claim: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "mode": self.mode,
            "consumers": list(self.consumers),
            "loaded": self.loaded,
            "consumer_modules_available": self.consumer_modules_available,
            "errors": list(self.errors),
            "sha256": self.sha256,
            "claim": self.claim,
        }


POLICY_SPECS: dict[str, PolicySpec] = {
    "benchmark-policy.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.model_benchmark", "ztad.mesh_store", "ztad.cli"), "Routing benchmarks are locally validated and are never delivery evidence."),
    "budget-policy.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.budget", "ztad.cli"), "Model-call and cost budgets are evaluated locally."),
    "command-policy.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.commands", "ztad.hooks", "ztad.checks"), "Argv and active-hook command boundaries are evaluated locally."),
    "context-policy.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.context", "ztad.repository_index"), "Context size and selection limits are local inputs; static context is not runtime completeness proof."),
    "diff-limits.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.diff_limits",), "Diff-size limits are locally enforced."),
    "model-catalog.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.model_router",), "Candidates are routed only after quality/tier/sandbox filtering."),
    "mesh-policy.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.mesh_store", "ztad.mesh_runtime", "ztad.loop_guard"), "DAG, scope locks, attempt fingerprints and parallel limits are locally enforced."),
    "model-routing.yaml": PolicySpec("LEGACY_COMPATIBILITY", ("ztad.models",), "Legacy three-role routing remains for compatibility; Mesh uses model-catalog.yaml."),
    "path-policy.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.control_plane", "ztad.patch_broker", "ztad.hooks"), "Protected paths and patch modes are checked locally."),
    "provider-policy.yaml": PolicySpec("DETERMINISTIC_AND_HOST_RUNTIME", ("ztad.providers", "ztad.host_acceptance", "ztad.mesh_runtime"), "Provider process boundaries are local; executable capability and authentication require target-host acceptance."),
    "risk-policy.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.risk",), "Risk floors are computed locally and cannot be downgraded by model text."),
    "release-policy.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.release", "ztad.progressive_delivery"), "Readiness and progressive decisions are local; platform execution needs a verified adapter."),
    "state-machine.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.state_machine", "ztad.scheduler", "ztad.orchestrator"), "Transitions require validated evidence when the production gate is configured."),
    "test-integrity-policy.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.test_weakening",), "Configured test-integrity findings are locally evaluated."),
    "continuity-policy.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.orchestrator", "ztad.mesh_store", "ztad.scheduler"), "Durable state, leases and task-local containment are locally implemented."),
    "host-acceptance-policy.yaml": PolicySpec("HOST_VERIFICATION_REQUIRED", ("ztad.host_acceptance",), "Local probes cannot prove remote controls or hook trust without host evidence."),
    "network-policy.yaml": PolicySpec("HOST_ENFORCEMENT_REQUIRED", ("ztad.hooks",), "Hooks provide a guardrail; the host sandbox/network configuration is the enforcement boundary."),
    "autonomy-policy.yaml": PolicySpec("REFERENCE_AND_HOST_POLICY", ("ztad.orchestrator", "ztad.mesh_runtime"), "Autonomy intent is realized only for capabilities verified by host acceptance."),
    "data-classification.yaml": PolicySpec("REFERENCE_AND_HOST_POLICY", ("ztad.context",), "Classification rules guide context exclusion; external data controls require host enforcement."),
    "database-policy.yaml": PolicySpec("REFERENCE_AND_PLATFORM_POLICY", ("ztad.risk", "ztad.release"), "Database guidance requires database-specific adapters and evidence."),
    "dependency-policy.yaml": PolicySpec("REFERENCE_AND_PLATFORM_POLICY", ("ztad.risk", "ztad.test_weakening"), "Dependency guidance requires package-manager and supply-chain evidence."),
    "evidence-policy.yaml": PolicySpec("REFERENCE_AND_CONTROLLER_POLICY", ("ztad.evidence", "ztad.state_machine", "ztad.approval_controller"), "Authoritative evidence requires protected signing/attestation controllers."),
    "feature-flag-policy.yaml": PolicySpec("REFERENCE_AND_PLATFORM_POLICY", ("ztad.release",), "Feature-flag behavior requires a platform adapter."),
    "model-governance-policy.yaml": PolicySpec("REFERENCE_AND_HOST_POLICY", ("ztad.model_router", "ztad.providers"), "Model pinning and eval gates require actual provider inventory and benchmarks."),
    "model-registry.example.yaml": PolicySpec("REFERENCE_TEMPLATE", (), "Example only; it is never treated as an active registry."),
    "waiver-policy.yaml": PolicySpec("REFERENCE_AND_CONTROLLER_POLICY", ("ztad.state_machine",), "Waivers require an external authorized controller and are not auto-issued."),
}


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def audit_policy_wiring(root: Path) -> dict[str, Any]:
    policy_dir = root / "policies"
    statuses: list[PolicyStatus] = []
    for path in sorted(policy_dir.glob("*.yaml")):
        errors: list[str] = []
        loaded = False
        try:
            value = load_data(path)
            if not isinstance(value, dict):
                errors.append("Policy must be a mapping")
            else:
                loaded = True
        except Exception as exc:
            errors.append(str(exc))
        spec = POLICY_SPECS.get(path.name)
        if spec is None:
            errors.append("Policy has no declared enforcement/claim classification")
            spec = PolicySpec("UNCLASSIFIED", (), "No claim is permitted.")
        module_state = all(_module_available(name) for name in spec.consumers)
        if spec.consumers and not module_state:
            errors.append("One or more declared consumer modules are unavailable")
        statuses.append(
            PolicyStatus(
                name=path.name, path=str(path), mode=spec.mode, consumers=spec.consumers,
                loaded=loaded, consumer_modules_available=module_state,
                errors=tuple(errors), sha256=sha256_file(path) if path.is_file() else None,
                claim=spec.claim,
            )
        )
    required = set(POLICY_SPECS)
    found = {item.name for item in statuses}
    missing = sorted(required - found)
    invalid = [item.to_dict() for item in statuses if item.errors]
    modes: dict[str, int] = {}
    for item in statuses:
        modes[item.mode] = modes.get(item.mode, 0) + 1
    return {
        "valid": not missing and not invalid,
        "policy_bundle_hash": hash_directory(policy_dir),
        "declared": len(required),
        "found": len(statuses),
        "missing": missing,
        "mode_counts": modes,
        "policies": [item.to_dict() for item in statuses],
        "errors": invalid,
        "claim_boundary": "A declared consumer proves code availability, not host activation. Non-runtime policies are explicitly classified instead of being mislabeled as enforced.",
    }
