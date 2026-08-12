from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .agent_output import validate_agent_result
from .autopilot import prepare_autopilot, submit_prepared_autopilot
from .approval_controller import issue_supervisor_approval_evidence
from .budget import evaluate_budget
from .bundle import validate_bundle
from .capabilities import detect_capabilities
from .checks import classify_check_history, run_checks
from .commands import validate_command_file
from .context import build_context_manifest
from .control_plane import detect_control_plane_changes
from .crypto import generate_ed25519_keypair, load_trust_roots, sign_evidence
from .diff_limits import evaluate_diff_limits
from .distribution import build_distributions, validate_distribution_archive, verify_checksum_file
from .errors import ZTADError
from .evidence import evaluate_required_evidence, load_evidence_records, validate_evidence_record
from .findings import validate_finding
from .host_acceptance import audit_host_acceptance
from .mesh_runtime import MeshRuntime
from .mesh_plan import build_mesh_plan, write_mesh_plan
from .mesh_store import MeshNodeSpec, MeshStore
from .model_router import AdaptiveModelRouter, TaskProfile
from .model_benchmark import ModelBenchmarkRunner, benchmark_suite_hash, load_benchmark_cases
from .providers import CodexExecProvider, GenericStructuredCommandProvider, ProviderRegistry
from .repository_index import assess_context_sufficiency, build_repository_index
from .scope_guard import ScopeEnvelope
from .injection import scan_documents
from . import installer
from .ledger import append_record, create_checkpoint, verify_ledger
from .marketplace import validate_marketplace
from .models import (
    ModelRoutingPolicy,
    build_codex_exec_argv,
    execute_role_with_fallback,
    make_run_spec,
)
from .orchestrator import ContinuityStore
from .policy_registry import audit_policy_wiring
from .patch_broker import validate_patch
from .platform import audit_github
from .release import evaluate_release_readiness
from .repository import GitRepository
from .risk import classify_repository_change, classify_risk
from .schema_validation import validate_file, validate_instance
from .state_machine import evaluate_next_actions_from_records, evaluate_transition_from_records
from .test_weakening import inspect_repository_test_integrity
from .util import dump_json, hash_directory, load_data, sha256_file, sha256_json


def _write_result(result: Any, output: str | None) -> None:
    text = dump_json(result)
    if output:
        target = Path(output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    sys.stdout.write(text)


def _root_file(relative: str) -> Path:
    return installer.distribution_root() / relative


def _data(path: str | Path) -> Any:
    return load_data(Path(path))


def _repo_path(repo: GitRepository, raw: str | Path) -> Path:
    path = Path(raw)
    return path if path.is_absolute() else repo.root / path


def _route_preview(plan, router: AdaptiveModelRouter) -> dict[str, Any]:
    deterministic_roles = {"repository_indexer", "patch_integrator", "check_runner"}
    items: list[dict[str, Any]] = []
    for node in plan.nodes:
        if node.role in deterministic_roles:
            continue
        metadata = node.metadata or {}
        profile = TaskProfile(
            task_family=node.task_family, role=node.role, risk=node.risk,
            complexity=int(metadata.get("complexity", 1)), ambiguity=int(metadata.get("ambiguity", 0)),
            required_provider_diversity=bool(metadata.get("require_provider_diversity", False)),
            preferred_provider=metadata.get("preferred_provider"),
            preferred_registry_id=metadata.get("preferred_registry_id"),
            maximum_reasoning_effort=metadata.get("maximum_reasoning_effort"),
            excluded_models=tuple(metadata.get("excluded_models", [])),
            excluded_providers=tuple(metadata.get("excluded_providers", [])),
        )
        try:
            selected = router.route(profile)
            ranking = router.ranked(profile)[:3]
            items.append({
                "node_id": node.node_id, "role": node.role, "task_family": node.task_family,
                "selected": selected.to_dict(), "top_candidates": ranking,
            })
        except LookupError as exc:
            items.append({
                "node_id": node.node_id, "role": node.role, "task_family": node.task_family,
                "selected": None, "top_candidates": [], "error": str(exc),
            })
    return {
        "model_call_count": len(items), "nodes": items,
        "claim_boundary": (
            "Catalog-prior route preview only. It performs no model call and does not prove provider availability, "
            "authentication, benchmark promotion, or target-host acceptance."
        ),
    }


def _provider_capability_fingerprint(registry: ProviderRegistry) -> str:
    probes = registry.probe_all()
    material: dict[str, Any] = {}
    for name, probe in sorted(probes.items()):
        material[name] = {
            "provider": probe.get("provider", name),
            "available": bool(probe.get("available")),
            "executable": probe.get("executable"),
            "version": probe.get("version"),
        }
    return sha256_json(material)


def _benchmark_cache_metadata(cases, registry: ProviderRegistry) -> dict[str, str]:
    suite_hash = benchmark_suite_hash(cases)
    provider_fingerprint = _provider_capability_fingerprint(registry)
    cache_hash = sha256_json({
        "benchmark_suite_hash": suite_hash,
        "provider_executable_fingerprint": provider_fingerprint,
    })
    return {
        "benchmark_suite_hash": suite_hash,
        "provider_executable_fingerprint": provider_fingerprint,
        "benchmark_cache_hash": cache_hash,
    }


def _repo_args(parser: argparse.ArgumentParser, *, revisions: bool = False) -> None:
    parser.add_argument("--repo", default=".", help="Repository path")
    if revisions:
        parser.add_argument("--base", required=True, help="Base revision")
        parser.add_argument("--head", default="HEAD", help="Head revision")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ztad", description="Deterministic Zero-Trust Agentic Delivery controls")
    parser.add_argument("--output", help="Also write the JSON result to this path")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("capabilities", help="Detect local capabilities without claiming remote enforcement")
    _repo_args(p)

    p = sub.add_parser("validate-contract", help="Validate a Change Contract")
    p.add_argument("--contract", required=True)
    p.add_argument("--schema", default=str(_root_file("schemas/change-contract.schema.json")))

    p = sub.add_parser("classify-risk", help="Classify contract-only, intended-path, or actual-diff risk")
    _repo_args(p)
    p.add_argument("--contract", required=True)
    p.add_argument("--base", help="Base revision; must be paired with --head")
    p.add_argument("--head", help="Head revision; must be paired with --base")
    p.add_argument("--changed-file", action="append", default=[])
    p.add_argument("--diff-file")
    p.add_argument("--policy", default=str(_root_file("policies/risk-policy.yaml")))

    p = sub.add_parser("context-manifest", help="Build a SHA-bound deterministic context manifest")
    _repo_args(p, revisions=True)
    p.add_argument("--risk", required=True, choices=["R0", "R1", "R2", "R3", "R4"])
    p.add_argument("--contract", required=True)
    p.add_argument("--risk-policy", default=str(_root_file("policies/risk-policy.yaml")))
    p.add_argument("--context-policy", default=str(_root_file("policies/context-policy.yaml")))

    p = sub.add_parser("detect-control-plane", help="Detect protected and mixed control-plane changes")
    _repo_args(p, revisions=True)
    p.add_argument("--policy", default=str(_root_file("policies/path-policy.yaml")))

    p = sub.add_parser("detect-test-weakening", help="Detect test and CI weakening")
    _repo_args(p, revisions=True)
    p.add_argument("--policy", default=str(_root_file("policies/test-integrity-policy.yaml")))

    p = sub.add_parser("diff-limits", help="Enforce risk-specific change-size limits")
    _repo_args(p, revisions=True)
    p.add_argument("--risk", required=True, choices=["R0", "R1", "R2", "R3", "R4"])
    p.add_argument("--policy", default=str(_root_file("policies/diff-limits.yaml")))

    p = sub.add_parser("run-checks", help="Run the reviewed batch check registry and emit local E2 evidence")
    _repo_args(p, revisions=True)
    p.add_argument("--contract", required=True)
    p.add_argument("--config", default=".delivery/ztad/config.json")
    p.add_argument("--command-policy", default=str(_root_file("policies/command-policy.yaml")))
    p.add_argument("--evidence-dir", default=".delivery/ztad/evidence/local")
    p.add_argument("--check-id", action="append", default=[])
    p.add_argument("--dry-run", action="store_true")

    p = sub.add_parser("check-history", help="Classify repeated results without converting fail-then-pass into pass")
    p.add_argument("--evidence", required=True)
    p.add_argument("--check-id", required=True)
    p.add_argument("--head", required=True)

    p = sub.add_parser("validate-agent-output", help="Validate structured agent output and evidence references")
    p.add_argument("--input", required=True)
    p.add_argument("--schema", default=str(_root_file("schemas/agent-result.schema.json")))
    p.add_argument("--expected")
    p.add_argument("--evidence")

    p = sub.add_parser("validate-finding", help="Validate a finding against an exact reviewed SHA")
    p.add_argument("--input", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--schema", default=str(_root_file("schemas/finding.schema.json")))
    p.add_argument("--evidence")

    p = sub.add_parser("validate-evidence", help="Validate evidence records against an exact subject")
    p.add_argument("--input", required=True)
    p.add_argument("--subject", required=True)
    p.add_argument("--schema", default=str(_root_file("schemas/evidence.schema.json")))
    p.add_argument("--minimum-trust", default="E3", choices=["E0", "E1", "E2", "E3", "E4", "E5", "E6"])
    p.add_argument("--required-type", action="append", default=[])
    p.add_argument("--trust-roots")

    p = sub.add_parser("sign-evidence", help="Sign authoritative evidence in a protected controller or CI context")
    p.add_argument("--input", required=True)
    p.add_argument("--private-key", required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--signed-output", required=True)
    p.add_argument("--acknowledge-protected-signing-context", action="store_true")
    p.add_argument("--schema", default=str(_root_file("schemas/evidence.schema.json")))

    p = sub.add_parser("keygen", help="Generate a protected-controller Ed25519 evidence keypair")
    p.add_argument("--private-key", required=True)
    p.add_argument("--public-key", required=True)
    p.add_argument("--acknowledge-protected-key-custody", action="store_true")

    p = sub.add_parser("validate-command", help="Validate argv against command policy; no shell parsing")
    p.add_argument("--policy", default=str(_root_file("policies/command-policy.yaml")))
    p.add_argument("--workspace-root")
    p.add_argument("argv", nargs=argparse.REMAINDER)

    p = sub.add_parser("budget", help="Enforce model-call, token, and cost budgets")
    p.add_argument("--risk", required=True, choices=["R0", "R1", "R2", "R3", "R4"])
    p.add_argument("--usage", required=True)
    p.add_argument("--policy", default=str(_root_file("policies/budget-policy.yaml")))

    p = sub.add_parser("transition", help="Evaluate a state transition from validated evidence records")
    p.add_argument("--current", required=True)
    p.add_argument("--requested", required=True)
    p.add_argument("--risk", required=True, choices=["R0", "R1", "R2", "R3", "R4"])
    p.add_argument("--evidence", help="Evidence JSON file or directory; raw evidence-type strings are not accepted")
    p.add_argument("--subject", help="Evidence subject JSON; required when --evidence is supplied")
    p.add_argument("--trust-roots", help="Trust roots required for E3-E6 evidence")
    p.add_argument("--evidence-schema", default=str(_root_file("schemas/evidence.schema.json")))
    p.add_argument("--policy", default=str(_root_file("policies/state-machine.yaml")))

    p = sub.add_parser("next-actions", help="List policy-permitted next states from validated evidence records")
    p.add_argument("--current", required=True)
    p.add_argument("--risk", required=True, choices=["R0", "R1", "R2", "R3", "R4"])
    p.add_argument("--evidence", help="Evidence JSON file or directory; raw evidence-type strings are not accepted")
    p.add_argument("--subject", help="Evidence subject JSON; required when --evidence is supplied")
    p.add_argument("--trust-roots", help="Trust roots required for E3-E6 evidence")
    p.add_argument("--evidence-schema", default=str(_root_file("schemas/evidence.schema.json")))
    p.add_argument("--policy", default=str(_root_file("policies/state-machine.yaml")))

    p = sub.add_parser("scan-injection", help="Flag prompt-injection signals while keeping content non-authoritative")
    p.add_argument("--input", required=True)
    p.add_argument("--trust-label", default="EXTERNAL_UNTRUSTED_CONTENT")

    p = sub.add_parser("validate-patch", help="Validate a patch on a clean detached base")
    p.add_argument("--repo", default=".")
    p.add_argument("--patch", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--path-policy", default=str(_root_file("policies/path-policy.yaml")))

    p = sub.add_parser("ledger-append", help="Append a hash-chained evidence-ledger record")
    p.add_argument("--ledger", required=True)
    p.add_argument("--payload", required=True)

    p = sub.add_parser("ledger-verify", help="Verify the transactional evidence ledger")
    p.add_argument("--ledger", required=True)
    p.add_argument("--checkpoint")

    p = sub.add_parser("github-audit", help="Read and conservatively assess GitHub enforcement")
    p.add_argument("--repo-slug", required=True)
    p.add_argument("--branch", default="main")

    p = sub.add_parser("release-readiness", help="Evaluate eligibility from signed, subject-bound evidence without merging or deploying")
    p.add_argument("--repo-id", required=True, help="Stable repository identifier used in evidence")
    p.add_argument("--contract", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--policy-bundle-hash", required=True)
    p.add_argument("--toolchain-hash", required=True)
    p.add_argument("--risk", required=True, choices=["R0", "R1", "R2", "R3", "R4"])
    p.add_argument("--target", required=True, choices=["merge", "staging", "release", "production"])
    p.add_argument("--evidence-dir", required=True)
    p.add_argument("--release-manifest")
    p.add_argument("--trust-roots", required=True)
    p.add_argument("--policy", default=str(_root_file("policies/release-policy.yaml")))

    p = sub.add_parser("policy-bundle-hash", help="Hash the policy bundle deterministically")
    p.add_argument("--root", default=str(_root_file("policies")))

    for name, help_text in (
        ("audit", "Audit repository and plan installation without mutation"),
        ("dry-run", "Produce the exact non-mutating installation plan"),
        ("install", "Install managed controls idempotently"),
        ("update", "Update controls while preserving local modifications"),
    ):
        p = sub.add_parser(name, help=help_text)
        _repo_args(p)
        p.add_argument("--activate-ci", action="store_true")
        p.add_argument("--no-repo-skills", action="store_true")

    p = sub.add_parser("continuity-init", help="Initialize the durable continuity database")
    p.add_argument("--database", required=True)

    p = sub.add_parser("continuity-submit", help="Submit a durable task idempotently")
    p.add_argument("--database", required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--contract", required=True)
    p.add_argument("--risk", required=True, choices=["R0", "R1", "R2", "R3", "R4"])
    p.add_argument("--priority", type=int, default=0)
    p.add_argument("--idempotency-key")

    p = sub.add_parser("continuity-claim", help="Claim the next runnable task using a lease")
    p.add_argument("--database", required=True)
    p.add_argument("--worker-id", required=True)
    p.add_argument("--lease-seconds", type=int, default=300)

    p = sub.add_parser("continuity-transition", help="Transition one durable task")
    p.add_argument("--database", required=True)
    p.add_argument("--task-id", required=True)
    p.add_argument("--state", required=True)
    p.add_argument("--actor", required=True)
    p.add_argument("--expected-version", type=int)
    p.add_argument("--release-lease", action="store_true")
    p.add_argument("--idempotency-key")

    p = sub.add_parser("continuity-failure", help="Contain a failure and schedule recovery")
    p.add_argument("--database", required=True)
    p.add_argument("--task-id", required=True)
    p.add_argument("--role", required=True, choices=["worker", "supervisor", "closure"])
    p.add_argument("--failure-class", required=True)
    p.add_argument("--error", required=True)
    p.add_argument("--actor", required=True)
    p.add_argument("--idempotency-key", required=True)

    p = sub.add_parser("continuity-status", help="Report durable scheduler status")
    p.add_argument("--database", required=True)

    p = sub.add_parser("continuity-verify", help="Verify the durable event hash chain")
    p.add_argument("--database", required=True)

    p = sub.add_parser("model-command", help="Build a role-isolated Codex exec command without executing it")
    p.add_argument("--policy", default=str(_root_file("policies/model-routing.yaml")))
    p.add_argument("--role", required=True, choices=["worker", "supervisor", "closure"])
    p.add_argument("--task-id", required=True)
    p.add_argument("--prompt", required=True)
    p.add_argument("--output-schema", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--codex-executable", default="codex")

    p = sub.add_parser("model-run", help="Execute a role-isolated Codex run with configured model fallback")
    p.add_argument("--policy", default=str(_root_file("policies/model-routing.yaml")))
    p.add_argument("--role", required=True, choices=["worker", "supervisor", "closure"])
    p.add_argument("--task-id", required=True)
    p.add_argument("--prompt", required=True)
    p.add_argument("--output-schema", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--cwd", required=True)
    p.add_argument("--codex-executable", default="codex")
    p.add_argument("--timeout-seconds", type=int, default=1800)

    p = sub.add_parser("approval-issue", help="Issue signed E6 supervisor approval through the protected controller")
    p.add_argument("--database", required=True)
    p.add_argument("--task-id", required=True)
    p.add_argument("--reviewer-run-id", help="Preferred: derive task, role and session from a stored completed model run")
    p.add_argument("--role", choices=["supervisor", "closure"], help="Legacy compatibility only")
    p.add_argument("--session-id", help="Legacy compatibility only")
    p.add_argument("--head-sha", required=True)
    p.add_argument("--diff-hash", required=True)
    p.add_argument("--evidence-ref", action="append", required=True)
    p.add_argument("--approval-type", required=True, choices=[
        "STRONG_SUPERVISOR_MERGE_APPROVAL",
        "STRONG_SUPERVISOR_TECHNICAL_APPROVAL",
        "STRONG_SUPERVISOR_RELEASE_APPROVAL",
    ])
    p.add_argument("--subject", required=True)
    p.add_argument("--private-key", required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--signed-output", required=True)

    p = sub.add_parser("policy-wiring", help="Prove which policy files have deterministic consumers")
    p.add_argument("--root", default=str(installer.distribution_root()))

    p = sub.add_parser("ledger-checkpoint", help="Write a separately protected ledger head checkpoint")
    p.add_argument("--ledger", required=True)
    p.add_argument("--checkpoint", required=True)

    p = sub.add_parser("repository-index", help="Build a deterministic static repository index")
    _repo_args(p)
    p.add_argument("--revision", default="HEAD")
    p.add_argument("--max-files", type=int, default=5000)
    p.add_argument("--max-file-bytes", type=int, default=1000000)

    p = sub.add_parser("context-sufficiency", help="Assess risk-bounded context coverage from an index")
    p.add_argument("--index", required=True)
    p.add_argument("--risk", required=True, choices=["R0", "R1", "R2", "R3", "R4"])
    p.add_argument("--changed-file", action="append", default=[])
    p.add_argument("--included-file", action="append", default=[])

    p = sub.add_parser("model-route", help="Select a model using adaptive quality/risk routing")
    p.add_argument("--catalog", default=str(_root_file("policies/model-catalog.yaml")))
    p.add_argument("--task-family", required=True)
    p.add_argument("--role", required=True)
    p.add_argument("--risk", required=True, choices=["R0", "R1", "R2", "R3", "R4"])
    p.add_argument("--complexity", type=int, default=1)
    p.add_argument("--ambiguity", type=int, default=0)
    p.add_argument("--prior-failures", type=int, default=0)
    p.add_argument("--require-provider-diversity", action="store_true")
    p.add_argument("--previous-provider")
    p.add_argument("--preferred-registry-id")
    p.add_argument("--maximum-reasoning-effort", choices=["none", "low", "medium", "high", "xhigh", "max", "ultra"])

    p = sub.add_parser("model-benchmark", help="Run explicit local task-family benchmarks for routing")
    _repo_args(p)
    p.add_argument("--catalog", default=str(_root_file("policies/model-catalog.yaml")))
    p.add_argument("--cases", default=str(_root_file("evals/model-benchmark-cases.json")))
    p.add_argument("--codex-executable", default="codex")
    p.add_argument("--provider-config", action="append", default=[])
    p.add_argument("--registry-id", action="append", default=[])
    p.add_argument("--mesh-database", help="Optionally persist measured routing history")
    p.add_argument("--timeout-seconds", type=int, default=600)

    p = sub.add_parser("provider-probe", help="Probe the configured Codex execution provider without a model call")
    p.add_argument("--codex-executable", default="codex")

    p = sub.add_parser("host-acceptance", help="Non-mutating host readiness audit")
    p.add_argument("--plugin-root", default=str(installer.distribution_root()))
    p.add_argument("--repo")
    p.add_argument("--skip-plugin-state", action="store_true")

    p = sub.add_parser("scope-verify", help="Verify immutable goal and path scope")
    p.add_argument("--task-id", required=True)
    p.add_argument("--contract", required=True)
    p.add_argument("--allowed", action="append", default=[])
    p.add_argument("--must-not-touch", action="append", default=[])
    p.add_argument("--changed-file", action="append", default=[])

    p = sub.add_parser("mesh-plan", help="Generate a bounded multi-model DAG and prompt set from a Change Contract")
    _repo_args(p)
    p.add_argument("--task-id", required=True)
    p.add_argument("--risk", required=True, choices=["R0", "R1", "R2", "R3", "R4"])
    p.add_argument("--contract", required=True)
    p.add_argument("--plan-output", default=".delivery/ztad/mesh-plan.json")
    p.add_argument("--prompt-root", default=".delivery/ztad/mesh-prompts")
    p.add_argument("--output-schema", default=str(_root_file("schemas/agent-result.schema.json")))
    p.add_argument("--check-config", default=".delivery/ztad/config.json")
    p.add_argument("--command-policy", default=str(_root_file("policies/command-policy.yaml")))
    p.add_argument("--risk-policy", default=str(_root_file("policies/risk-policy.yaml")))
    p.add_argument("--catalog", default=str(_root_file("policies/model-catalog.yaml")))
    p.add_argument("--max-parallel-writers", type=int, default=6)
    p.add_argument("--max-plan-candidates", type=int, default=4)
    p.add_argument("--dry-run", action="store_true")

    p = sub.add_parser("mesh-autopilot", help="Prepare, submit and run one idempotent local autonomous delivery mesh")
    _repo_args(p)
    p.add_argument("--contract", required=True)
    p.add_argument("--task-id")
    p.add_argument("--risk", choices=["R0", "R1", "R2", "R3", "R4"], help="Optional minimum risk; cannot downgrade deterministic risk")
    p.add_argument("--database", default=".delivery/ztad/state/mesh.db")
    p.add_argument("--continuity-database", default=".delivery/ztad/state/continuity.db")
    p.add_argument("--plan-output")
    p.add_argument("--prompt-root")
    p.add_argument("--output-schema", default=str(_root_file("schemas/agent-result.schema.json")))
    p.add_argument("--check-config", default=".delivery/ztad/config.json")
    p.add_argument("--command-policy", default=str(_root_file("policies/command-policy.yaml")))
    p.add_argument("--risk-policy", default=str(_root_file("policies/risk-policy.yaml")))
    p.add_argument("--catalog", default=str(_root_file("policies/model-catalog.yaml")))
    p.add_argument("--worker-id", default="ztad-autopilot")
    p.add_argument("--codex-executable", default="codex")
    p.add_argument("--provider-config", action="append", default=[])
    p.add_argument("--auto-benchmark", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--benchmark-cases", default=str(_root_file("evals/model-benchmark-cases.json")))
    p.add_argument("--benchmark-timeout-seconds", type=int, default=600)
    p.add_argument("--max-parallel-writers", type=int, default=6)
    p.add_argument("--max-plan-candidates", type=int, default=4)
    p.add_argument("--max-nodes", type=int, default=8)
    p.add_argument("--maximum-ticks", type=int, default=100)
    p.add_argument("--maximum-seconds", type=int, default=3600)
    p.add_argument("--priority", type=int, default=0)
    p.add_argument("--dry-run", action="store_true")

    p = sub.add_parser("mesh-init", help="Initialize the durable multi-model mesh database")
    p.add_argument("--database", required=True)

    p = sub.add_parser("mesh-submit", help="Submit a validated DAG of mesh nodes")
    p.add_argument("--database", required=True)
    p.add_argument("--nodes", required=True, help="JSON/YAML file containing a nodes array")

    p = sub.add_parser("mesh-status", help="Report durable mesh status")
    p.add_argument("--database", required=True)
    p.add_argument("--task-id")

    p = sub.add_parser("mesh-reactivate", help="Reactivate one quarantined node after a verified condition changed")
    p.add_argument("--database", required=True)
    p.add_argument("--node-id", required=True)
    p.add_argument("--change-token", required=True)
    p.add_argument("--reason", required=True)

    for mesh_command, mesh_help in (
        ("mesh-run-once", "Claim and run one bounded batch of ready mesh nodes"),
        ("mesh-run-until-idle", "Run bounded mesh batches until currently runnable work is exhausted"),
        ("mesh-service", "Continuously poll and run durable mesh work until interrupted or time-bounded"),
    ):
        p = sub.add_parser(mesh_command, help=mesh_help)
        _repo_args(p)
        p.add_argument("--database", required=True)
        p.add_argument("--continuity-database", required=True)
        p.add_argument("--catalog", default=str(_root_file("policies/model-catalog.yaml")))
        p.add_argument("--worker-id", required=True)
        p.add_argument("--codex-executable", default="codex")
        p.add_argument("--provider-config", action="append", default=[], help="Host-accepted generic structured provider YAML/JSON")
        p.add_argument("--auto-benchmark", action=argparse.BooleanOptionalAction, default=True,
                       help="Benchmark unmeasured task families before routing (default: enabled)")
        p.add_argument("--benchmark-cases", default=str(_root_file("evals/model-benchmark-cases.json")))
        p.add_argument("--benchmark-timeout-seconds", type=int, default=600)
        p.add_argument("--max-nodes", type=int, default=8)
        p.add_argument("--maximum-ticks", type=int, default=100)
        p.add_argument("--maximum-seconds", type=int, default=3600)
        p.add_argument("--poll-seconds", type=float, default=2.0)
        p.add_argument("--status-interval-seconds", type=float, default=60.0)

    p = sub.add_parser("uninstall", help="Remove only unchanged managed files and the unchanged managed AGENTS block")
    _repo_args(p)

    p = sub.add_parser("preflight", help="Run deterministic contract/risk/control/test/diff gates")
    _repo_args(p, revisions=True)
    p.add_argument("--contract", required=True)

    p = sub.add_parser("validate-bundle", help="Validate this plugin and skill-suite package")
    p.add_argument("--root", default=str(installer.distribution_root()))

    p = sub.add_parser("validate-marketplace", help="Validate a local marketplace and every bundled plugin")
    p.add_argument("--root", required=True)

    p = sub.add_parser("build-distribution", help="Build reproducible plugin and marketplace ZIP distributions")
    p.add_argument("--root", default=str(installer.distribution_root()))
    p.add_argument("--output-dir", default="dist")
    p.add_argument("--no-stable-aliases", action="store_true")

    p = sub.add_parser("validate-distribution", help="Safely extract and validate a built distribution ZIP")
    p.add_argument("--archive", required=True)
    p.add_argument("--kind", required=True, choices=["plugin", "marketplace"])

    p = sub.add_parser("verify-checksums", help="Verify a release CHECKSUMS.sha256 file without shell utilities")
    p.add_argument("--file", required=True)
    return parser


def execute(args: argparse.Namespace) -> tuple[Any, int]:
    command = args.command
    if command == "capabilities":
        return detect_capabilities(args.repo), 0
    if command == "validate-contract":
        errors = validate_file(Path(args.contract), Path(args.schema))
        return {"valid": not errors, "errors": errors}, 0 if not errors else 2
    if command == "classify-risk":
        if bool(args.base) != bool(args.head):
            raise ValueError("--base and --head must be supplied together")
        repo = GitRepository(args.repo) if args.base else None
        contract_path = _repo_path(repo, args.contract) if repo else Path(args.contract)
        contract = _data(contract_path)
        if args.base and args.head and repo:
            result = classify_repository_change(repo, contract, args.base, args.head, Path(args.policy)).to_dict()
            result["mode"] = "ACTUAL_DIFF"
        else:
            diff_text = Path(args.diff_file).read_text(encoding="utf-8", errors="replace") if args.diff_file else ""
            result = classify_risk(contract, changed_paths=args.changed_file, diff_text=diff_text, policy=_data(args.policy)).to_dict()
            if args.diff_file:
                result["mode"] = "SUPPLIED_DIFF"
            elif args.changed_file:
                result["mode"] = "INTENDED_PATHS"
            else:
                result["mode"] = "CONTRACT_ONLY"
        return result, 3 if result["blocked"] else 0
    if command == "context-manifest":
        repo = GitRepository(args.repo)
        contract_path = _repo_path(repo, args.contract)
        context_policy = _data(args.context_policy)
        max_files = context_policy.get("max_files_by_risk", {}) if isinstance(context_policy, dict) else None
        result = build_context_manifest(
            repo, args.base, args.head, args.risk,
            contract_hash=sha256_file(contract_path),
            policy_hash=sha256_file(Path(args.risk_policy)),
            max_files_by_risk=max_files,
        )
        return result, 0
    if command == "detect-control-plane":
        repo = GitRepository(args.repo)
        paths = [item.path for item in repo.changed_paths(args.base, args.head)]
        result = detect_control_plane_changes(paths, _data(args.policy))
        return result, 4 if result["blocked"] else 0
    if command == "detect-test-weakening":
        result = inspect_repository_test_integrity(
            GitRepository(args.repo), args.base, args.head, _data(args.policy)
        )
        return result, 5 if result["blocked"] else 0
    if command == "diff-limits":
        result = evaluate_diff_limits(GitRepository(args.repo), args.base, args.head, args.risk, _data(args.policy))
        return result, 6 if not result["passed"] else 0
    if command == "run-checks":
        repo = GitRepository(args.repo)
        result = run_checks(
            repo.root,
            base=args.base,
            head=args.head,
            contract_path=_repo_path(repo, args.contract),
            config_path=_repo_path(repo, args.config),
            command_policy_path=Path(args.command_policy),
            policy_bundle_hash=hash_directory(_root_file("policies")),
            output_dir=_repo_path(repo, args.evidence_dir),
            selected_ids=set(args.check_id) if args.check_id else None,
            dry_run=args.dry_run,
        )
        return result, 19 if result["blocked"] else 0
    if command == "check-history":
        return classify_check_history(load_evidence_records(Path(args.evidence)), args.check_id, args.head), 0
    if command == "validate-agent-output":
        evidence_ids = [str(item.get("evidence_id")) for item in load_evidence_records(Path(args.evidence))] if args.evidence else []
        errors = validate_agent_result(_data(args.input), _data(args.schema), expected=_data(args.expected) if args.expected else None, known_evidence_ids=evidence_ids)
        return {"valid": not errors, "errors": errors}, 0 if not errors else 7
    if command == "validate-finding":
        evidence_ids = [str(item.get("evidence_id")) for item in load_evidence_records(Path(args.evidence))] if args.evidence else []
        errors = validate_finding(_data(args.input), schema=_data(args.schema), expected_head_sha=args.head, known_evidence_ids=evidence_ids)
        return {"valid": not errors, "errors": errors}, 0 if not errors else 7
    if command == "validate-evidence":
        records = load_evidence_records(Path(args.input))
        schema = _data(args.schema)
        subject = _data(args.subject)
        trust_roots = load_trust_roots(Path(args.trust_roots)) if args.trust_roots else None
        if args.required_type:
            result = evaluate_required_evidence(records, args.required_type, subject=subject, schema=schema, minimum_trust=args.minimum_trust, trust_roots=trust_roots)
            return result, 0 if result["passed"] else 8
        results = {str(record.get("evidence_id", index)): validate_evidence_record(record, schema=schema, subject=subject, minimum_trust=args.minimum_trust, trust_roots=trust_roots) for index, record in enumerate(records)}
        valid = bool(records) and all(not errors for errors in results.values())
        return {"valid": valid, "records": results, "record_count": len(records)}, 0 if valid else 8
    if command == "sign-evidence":
        if not args.acknowledge_protected_signing_context:
            return {"signed": False, "decision": "PROTECTED_SIGNING_CONTEXT_ACKNOWLEDGEMENT_REQUIRED"}, 18
        record = _data(args.input)
        errors = validate_instance(record, _data(args.schema))
        if errors:
            return {"signed": False, "errors": errors}, 8
        if record.get("trust_level") not in {"E3", "E4", "E5", "E6"}:
            return {"signed": False, "errors": ["Only authoritative E3-E6 evidence may use this signing path"]}, 8
        signed = sign_evidence(record, private_key_path=Path(args.private_key), key_id=args.key_id)
        target = Path(args.signed_output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {"signed": True, "evidence_id": signed.get("evidence_id"), "output": str(target.resolve()), "claim_boundary": "Key secrecy and signer authorization must be enforced outside the model."}, 0
    if command == "keygen":
        if not args.acknowledge_protected_key_custody:
            return {"generated": False, "decision": "PROTECTED_KEY_CUSTODY_ACKNOWLEDGEMENT_REQUIRED"}, 18
        return {"generated": True, **generate_ed25519_keypair(Path(args.private_key), Path(args.public_key))}, 0
    if command == "validate-command":
        argv = list(args.argv)
        if argv and argv[0] == "--":
            argv = argv[1:]
        result = validate_command_file(argv, Path(args.policy), workspace_root=Path(args.workspace_root) if args.workspace_root else None)
        return result, 0 if result["allowed"] else 9
    if command == "budget":
        result = evaluate_budget(_data(args.policy), _data(args.usage), args.risk)
        return result, 0 if result["passed"] else 10
    if command in {"transition", "next-actions"}:
        if args.evidence and not args.subject:
            raise ValueError("--subject is required when --evidence is supplied")
        records = load_evidence_records(Path(args.evidence)) if args.evidence else []
        subject = _data(args.subject) if args.subject else None
        if subject is not None:
            subject_errors = validate_instance(subject, _data(_root_file("schemas/evidence-subject.schema.json")))
            if subject_errors:
                raise ValueError("Invalid evidence subject: " + "; ".join(subject_errors))
        trust_roots = load_trust_roots(Path(args.trust_roots)) if args.trust_roots else None
        common = {
            "policy": _data(args.policy),
            "current_state": args.current,
            "risk": args.risk,
            "records": records,
            "subject": subject,
            "evidence_schema": _data(args.evidence_schema),
            "trust_roots": trust_roots,
        }
        if command == "transition":
            result = evaluate_transition_from_records(requested_state=args.requested, **common)
            return result, 0 if result["allowed"] else 11
        result = evaluate_next_actions_from_records(**common)
        return result, 0 if result["permitted_next_states"] else 11
    if command == "scan-injection":
        text = Path(args.input).read_text(encoding="utf-8", errors="replace")
        signals = scan_documents([(args.input, args.trust_label, text)])
        trusted = args.trust_label in {"TRUSTED_POLICY", "TRUSTED_REQUIREMENT"}
        return {
            "instruction_authority": "DEFINED_BY_CALLER_TRUST_BOUNDARY" if trusted else "DENIED",
            "signals_detected": bool(signals),
            "signals": signals,
            "claim_boundary": "Absence of a signal never makes untrusted content authoritative.",
        }, 0 if not signals else 12
    if command == "validate-patch":
        result = validate_patch(GitRepository(args.repo), Path(args.patch), expected_base=args.base, path_policy=_data(args.path_policy))
        return result, 0 if result["valid"] else 13
    if command == "ledger-append":
        return append_record(Path(args.ledger), _data(args.payload)), 0
    if command == "ledger-verify":
        result = verify_ledger(Path(args.ledger), checkpoint_path=Path(args.checkpoint) if getattr(args, "checkpoint", None) else None)
        return result, 0 if result["valid"] else 14
    if command == "ledger-checkpoint":
        return create_checkpoint(Path(args.ledger), Path(args.checkpoint)), 0
    if command == "continuity-init":
        store = ContinuityStore(Path(args.database))
        return store.system_status(), 0
    if command == "continuity-submit":
        store = ContinuityStore(Path(args.database))
        result = store.submit_task(
            repository=args.repository, title=args.title, contract=_data(args.contract),
            risk=args.risk, priority=args.priority, idempotency_key=args.idempotency_key,
        )
        return result, 0
    if command == "continuity-claim":
        store = ContinuityStore(Path(args.database))
        result = store.claim_next(args.worker_id, lease_seconds=args.lease_seconds)
        return {"claimed": result is not None, "task": result, "status": store.system_status()}, 0
    if command == "continuity-transition":
        store = ContinuityStore(Path(args.database))
        return store.transition(
            args.task_id, args.state, actor=args.actor, expected_version=args.expected_version,
            release_lease=args.release_lease, idempotency_key=args.idempotency_key,
        ), 0
    if command == "continuity-failure":
        store = ContinuityStore(Path(args.database))
        return store.record_failure(
            args.task_id, role=args.role, failure_class=args.failure_class, error=args.error,
            actor=args.actor, idempotency_key=args.idempotency_key,
        ), 0
    if command == "continuity-status":
        return ContinuityStore(Path(args.database)).system_status(), 0
    if command == "continuity-verify":
        result = ContinuityStore(Path(args.database)).verify_event_chain()
        return result, 0 if result["valid"] else 26
    if command == "model-command":
        routing = ModelRoutingPolicy.from_file(Path(args.policy))
        role = routing.role(args.role)
        spec = make_run_spec(
            task_id=args.task_id, role=role, prompt_path=Path(args.prompt),
            output_schema=Path(args.output_schema), output_dir=Path(args.output_dir),
        )
        return {
            "run_id": spec.run_id, "role": spec.role, "model": spec.model,
            "sandbox": spec.sandbox, "argv": build_codex_exec_argv(spec, codex_executable=args.codex_executable),
            "claim_boundary": "This command only builds argv; it does not execute a model or prove host support."
        }, 0
    if command == "model-run":
        routing = ModelRoutingPolicy.from_file(Path(args.policy))
        result = execute_role_with_fallback(
            task_id=args.task_id,
            role=routing.role(args.role),
            prompt_path=Path(args.prompt),
            output_schema=Path(args.output_schema),
            output_dir=Path(args.output_dir),
            cwd=Path(args.cwd),
            codex_executable=args.codex_executable,
            timeout_seconds=args.timeout_seconds,
        )
        result["claim_boundary"] = (
            "A successful model process is a structured proposal only. Validate its schema, exact subject, and evidence references before any transition."
        )
        return result, 0 if result["success"] else 28
    if command == "approval-issue":
        result = issue_supervisor_approval_evidence(
            store=ContinuityStore(Path(args.database)),
            task_id=args.task_id,
            role=args.role,
            session_id=args.session_id,
            reviewer_run_id=args.reviewer_run_id,
            head_sha=args.head_sha,
            diff_hash=args.diff_hash,
            evidence_refs=args.evidence_ref,
            approval_type=args.approval_type,
            subject=_data(args.subject),
            private_key_path=Path(args.private_key),
            key_id=args.key_id,
            output_path=Path(args.signed_output),
        )
        return {
            "issued": True,
            "approval_id": result["approval"]["approval_id"],
            "evidence_id": result["signed_evidence"]["evidence_id"],
            "output": result["output_path"],
            "claim_boundary": "The signing key must remain available only to a protected approval-controller process, never to a model session.",
        }, 0
    if command == "policy-wiring":
        result = audit_policy_wiring(Path(args.root).resolve())
        return result, 0 if result["valid"] else 27
    if command == "repository-index":
        index = build_repository_index(
            GitRepository(args.repo), args.revision,
            max_files=args.max_files, max_file_bytes=args.max_file_bytes,
        )
        return index.to_dict(), 0
    if command == "context-sufficiency":
        raw = _data(args.index)
        if not isinstance(raw, dict):
            raise ValueError("Index must be an object")
        from .repository_index import RepositoryIndex
        index = RepositoryIndex(
            repository=str(raw["repository"]), revision=str(raw["revision"]),
            generated_at=str(raw.get("generated_at", "")), files=tuple(raw.get("files", [])),
            imports={str(k): tuple(v) for k, v in (raw.get("imports", {}) or {}).items()},
            reverse_imports={str(k): tuple(v) for k, v in (raw.get("reverse_imports", {}) or {}).items()},
            symbols={str(k): tuple(v) for k, v in (raw.get("symbols", {}) or {}).items()},
            signals={str(k): tuple(v) for k, v in (raw.get("signals", {}) or {}).items()},
            dynamic_gaps=tuple(raw.get("dynamic_gaps", [])), skipped=tuple(raw.get("skipped", [])),
            index_hash=str(raw["index_hash"]),
        )
        result = assess_context_sufficiency(
            index, changed_paths=args.changed_file, included_paths=args.included_file, risk=args.risk,
        )
        return result, 0 if result["sufficient"] else 29
    if command == "model-route":
        router = AdaptiveModelRouter.from_file(Path(args.catalog))
        profile = TaskProfile(
            task_family=args.task_family, role=args.role, risk=args.risk,
            complexity=args.complexity, ambiguity=args.ambiguity,
            prior_failures=args.prior_failures,
            required_provider_diversity=args.require_provider_diversity,
            preferred_registry_id=args.preferred_registry_id,
            maximum_reasoning_effort=args.maximum_reasoning_effort,
        )
        decision = router.route(profile, previous_provider=args.previous_provider)
        return {"selected": decision.to_dict(), "ranking": router.ranked(profile, previous_provider=args.previous_provider)}, 0
    if command == "model-benchmark":
        provider_items = [CodexExecProvider(executable=args.codex_executable)]
        for config_path in args.provider_config:
            config = _data(config_path)
            raw = config.get("providers", []) if isinstance(config, dict) else []
            if not isinstance(raw, list):
                raise ValueError("provider config must contain a providers array")
            provider_items.extend(GenericStructuredCommandProvider.from_mapping(item) for item in raw)
        router = AdaptiveModelRouter.from_file(Path(args.catalog))
        provider_registry = ProviderRegistry(provider_items)
        benchmark_cases = load_benchmark_cases(Path(args.cases))
        cache_metadata = _benchmark_cache_metadata(benchmark_cases, provider_registry)
        result = ModelBenchmarkRunner(router, provider_registry).run(
            benchmark_cases, cwd=Path(args.repo).resolve(),
            registry_ids=args.registry_id, timeout_seconds=args.timeout_seconds,
        )
        result.update(cache_metadata)
        if args.mesh_database:
            store = MeshStore(Path(args.mesh_database))
            for model in result["results"]:
                if not model.get("available"):
                    continue
                for case in model.get("cases", []):
                    store.record_model_performance(
                        registry_id=model["registry_id"], task_family=case["task_family"],
                        success=bool(case["success"]), quality=float(case["score"]),
                        latency=next(item.latency_index for item in router.candidates if item.registry_id == model["registry_id"]),
                        cost=next(item.cost_index for item in router.candidates if item.registry_id == model["registry_id"]),
                        catalog_hash=result["catalog_hash"], benchmark_suite_hash=result["benchmark_cache_hash"],
                    )
            result["persisted_to_mesh_database"] = str(Path(args.mesh_database).resolve())
        return result, 0
    if command == "provider-probe":
        result = CodexExecProvider(executable=args.codex_executable).probe()
        return result, 0 if result.get("available") else 30
    if command == "host-acceptance":
        result = audit_host_acceptance(
            plugin_root=Path(args.plugin_root),
            repository=Path(args.repo) if args.repo else None,
            inspect_codex_plugin_state=not args.skip_plugin_state,
        )
        return result, 0 if result["maximum_verified_mode"] != "ADVISORY_ONLY" else 31
    if command == "scope-verify":
        contract = _data(args.contract)
        envelope = ScopeEnvelope.from_contract(
            task_id=args.task_id, contract=contract, allowed_patterns=args.allowed,
            must_not_touch=args.must_not_touch,
        )
        path_result = envelope.verify_paths(args.changed_file)
        return {"envelope": envelope.to_dict(), "contract_errors": envelope.verify_contract(contract), "paths": path_result}, 0 if path_result["allowed"] else 32
    if command == "mesh-plan":
        repo = GitRepository(args.repo)
        contract_path = _repo_path(repo, args.contract)
        contract = _data(contract_path)
        mesh_plan = build_mesh_plan(
            task_id=args.task_id, risk=args.risk, contract=contract,
            prompt_root=args.prompt_root, output_schema=str(Path(args.output_schema).resolve()),
            check_config=args.check_config, command_policy=str(Path(args.command_policy).resolve()),
            risk_policy=str(Path(args.risk_policy).resolve()),
            maximum_parallel_writers=args.max_parallel_writers,
            maximum_plan_candidates=args.max_plan_candidates,
        )
        payload = mesh_plan.to_dict()
        if args.dry_run:
            router = AdaptiveModelRouter.from_file(Path(args.catalog))
            return {
                "dry_run": True, "repository_mutated": False, "plan": payload,
                "route_preview": _route_preview(mesh_plan, router),
            }, 0
        written = write_mesh_plan(mesh_plan, repository=repo.root, output_file=Path(args.plan_output))
        return {"dry_run": False, "repository_mutated": True, "plan": payload, "written": written}, 0
    if command == "mesh-autopilot":
        repo = GitRepository(args.repo)
        contract_path = _repo_path(repo, args.contract)
        contract = _data(contract_path)
        contract_hash = sha256_json(contract)
        default_task = f"{str(contract.get('change_id', 'change')).casefold()}-{contract_hash.removeprefix('sha256:')[:12]}"
        task_id = args.task_id or default_task
        plan_output = args.plan_output or f".delivery/ztad/tasks/{task_id}/mesh-plan.json"
        prompt_root = args.prompt_root or f".delivery/ztad/tasks/{task_id}/prompts"
        preparation = prepare_autopilot(
            repository=repo.root, contract_path=contract_path,
            contract_schema=_root_file("schemas/change-contract.schema.json"),
            risk_policy=Path(args.risk_policy), requested_risk=args.risk, task_id=task_id,
            plan_output=plan_output, prompt_root=prompt_root, output_schema=str(Path(args.output_schema).resolve()),
            check_config=args.check_config, command_policy=str(Path(args.command_policy).resolve()),
            mesh_database=args.database, continuity_database=args.continuity_database,
            maximum_parallel_writers=args.max_parallel_writers,
            maximum_plan_candidates=args.max_plan_candidates,
        )
        if args.dry_run:
            router = AdaptiveModelRouter.from_file(Path(args.catalog))
            result = preparation.to_dict(include_plan=True)
            result.update({
                "dry_run": True, "repository_mutated": False, "database_mutated": False,
                "route_preview": _route_preview(preparation.plan, router),
            })
            return result, 0
        persisted = submit_prepared_autopilot(
            preparation=preparation, contract=contract, title=str(contract.get("title") or task_id),
            priority=args.priority,
        )
        provider_items = [CodexExecProvider(executable=args.codex_executable)]
        for config_path in args.provider_config:
            config = _data(config_path)
            raw = config.get("providers", []) if isinstance(config, dict) else []
            if not isinstance(raw, list):
                raise ValueError("provider config must contain a providers array")
            for item in raw:
                if not isinstance(item, dict):
                    raise ValueError("Every provider config entry must be an object")
                provider_items.append(GenericStructuredCommandProvider.from_mapping(item))
        mesh_store = MeshStore(Path(preparation.mesh_database))
        router = AdaptiveModelRouter.from_file(Path(args.catalog))
        provider_registry = ProviderRegistry(provider_items)
        benchmark_result = None
        cases = load_benchmark_cases(Path(args.benchmark_cases))
        cache_metadata = _benchmark_cache_metadata(cases, provider_registry)
        catalog_hash = sha256_json(router.catalog)
        benchmark_cache_hash = cache_metadata["benchmark_cache_hash"]
        if args.auto_benchmark:
            active_families = {
                node["task_family"] for node in mesh_store.list_nodes(task_id=preparation.task_id)
                if node["role"] not in {"repository_indexer", "patch_integrator", "check_runner"}
                and node["state"] not in {"SUCCEEDED", "CANCELLED", "SUPERSEDED"}
            }
            missing_families = {
                family for family in active_families
                if not mesh_store.performance_overrides(
                    family, catalog_hash=catalog_hash, benchmark_suite_hash=benchmark_cache_hash,
                    minimum_runs=int(router.policy.get("minimum_observations_for_override", 1)),
                )
            }
            selected_cases = [case for case in cases if case.task_family in missing_families]
            if selected_cases:
                benchmark_result = ModelBenchmarkRunner(router, provider_registry).run(
                    selected_cases, cwd=repo.root, timeout_seconds=args.benchmark_timeout_seconds,
                )
                benchmark_result.update(cache_metadata)
                for model in benchmark_result["results"]:
                    if not model.get("available"):
                        continue
                    for case in model.get("cases", []):
                        mesh_store.record_model_performance(
                            registry_id=model["registry_id"], task_family=case["task_family"],
                            success=bool(case["success"]), quality=float(case["score"]),
                            latency=next(item.latency_index for item in router.candidates if item.registry_id == model["registry_id"]),
                            cost=next(item.cost_index for item in router.candidates if item.registry_id == model["registry_id"]),
                            catalog_hash=benchmark_result["catalog_hash"],
                            benchmark_suite_hash=benchmark_cache_hash,
                        )
        runtime = MeshRuntime(
            repository=repo.root, mesh_store=mesh_store,
            continuity_store=ContinuityStore(Path(preparation.continuity_database)),
            router=router, providers=provider_registry, worker_id=args.worker_id,
            global_parallel_cap=args.max_nodes, performance_context_hash=benchmark_cache_hash,
        )
        execution = runtime.run_until_idle(
            maximum_ticks=args.maximum_ticks, maximum_seconds=args.maximum_seconds,
        )
        result = preparation.to_dict(include_plan=False)
        result.update({
            "dry_run": False, "repository_mutated": True, "persistence": persisted,
            "execution": execution,
            "next_action": (
                "START_OR_KEEP_MESH_SERVICE_RUNNING_OR_REACTIVATE_CONTAINED_NODES"
                if any(
                    execution["mesh_status"].get(key, 0)
                    for key in ("runnable_now", "delayed_retry", "quarantined", "blocked_by_dependencies")
                )
                else "REVIEW_PLATFORM_GATES_AND_RELEASE_READINESS"
            ),
        })
        if benchmark_result is not None:
            result["automatic_model_benchmark"] = benchmark_result
        return result, 0
    if command == "mesh-init":
        return MeshStore(Path(args.database)).status(), 0
    if command == "mesh-submit":
        payload = _data(args.nodes)
        raw_nodes = payload.get("nodes", []) if isinstance(payload, dict) else payload
        if not isinstance(raw_nodes, list):
            raise ValueError("nodes file must contain an array or {nodes: [...]}")
        specs = []
        for item in raw_nodes:
            if not isinstance(item, dict):
                raise ValueError("Every mesh node must be an object")
            specs.append(MeshNodeSpec.create(
                task_id=str(item["task_id"]), title=str(item["title"]),
                task_family=str(item["task_family"]), role=str(item["role"]), risk=str(item["risk"]),
                write_access=bool(item.get("write_access", False)), scopes=item.get("scopes", []),
                prompt_path=str(item["prompt_path"]), output_schema=str(item["output_schema"]),
                priority=int(item.get("priority", 0)), metadata=item.get("metadata", {}),
                dependencies=item.get("dependencies", []), node_id=item.get("node_id"),
                idempotency_key=item.get("idempotency_key"),
            ))
        store = MeshStore(Path(args.database))
        submitted = store.submit_graph(specs)
        return {"submitted": submitted, "status": store.status()}, 0
    if command == "mesh-status":
        store = MeshStore(Path(args.database))
        return {"status": store.status(), "nodes": store.list_nodes(task_id=args.task_id)}, 0
    if command == "mesh-reactivate":
        store = MeshStore(Path(args.database))
        node = store.reactivate_quarantined(
            args.node_id, change_token=args.change_token, reason=args.reason,
        )
        return {
            "reactivated": True, "node": node, "status": store.status(),
            "claim_boundary": "Reactivation records a changed condition; it does not guarantee the next attempt will succeed.",
        }, 0
    if command in {"mesh-run-once", "mesh-run-until-idle", "mesh-service"}:
        provider_items = [CodexExecProvider(executable=args.codex_executable)]
        for config_path in args.provider_config:
            config = _data(config_path)
            raw = config.get("providers", []) if isinstance(config, dict) else []
            if not isinstance(raw, list):
                raise ValueError("provider config must contain a providers array")
            for item in raw:
                if not isinstance(item, dict):
                    raise ValueError("Every provider config entry must be an object")
                provider_items.append(GenericStructuredCommandProvider.from_mapping(item))
        mesh_store = MeshStore(Path(args.database))
        router = AdaptiveModelRouter.from_file(Path(args.catalog))
        provider_registry = ProviderRegistry(provider_items)
        benchmark_result = None
        cases = load_benchmark_cases(Path(args.benchmark_cases))
        cache_metadata = _benchmark_cache_metadata(cases, provider_registry)
        catalog_hash = sha256_json(router.catalog)
        benchmark_cache_hash = cache_metadata["benchmark_cache_hash"]
        if args.auto_benchmark:
            active_families = {
                node["task_family"] for node in mesh_store.list_nodes()
                if node["role"] not in {"patch_integrator", "check_runner"}
                and node["state"] not in {"SUCCEEDED", "CANCELLED", "SUPERSEDED"}
            }
            missing_families = {
                family for family in active_families
                if not mesh_store.performance_overrides(
                    family, catalog_hash=catalog_hash, benchmark_suite_hash=benchmark_cache_hash,
                    minimum_runs=int(router.policy.get("minimum_observations_for_override", 1)),
                )
            }
            selected_cases = [case for case in cases if case.task_family in missing_families]
            if selected_cases:
                benchmark_result = ModelBenchmarkRunner(router, provider_registry).run(
                    selected_cases, cwd=Path(args.repo).resolve(),
                    timeout_seconds=args.benchmark_timeout_seconds,
                )
                benchmark_result.update(cache_metadata)
                for model in benchmark_result["results"]:
                    if not model.get("available"):
                        continue
                    for case in model.get("cases", []):
                        mesh_store.record_model_performance(
                            registry_id=model["registry_id"], task_family=case["task_family"],
                            success=bool(case["success"]), quality=float(case["score"]),
                            latency=next(item.latency_index for item in router.candidates if item.registry_id == model["registry_id"]),
                            cost=next(item.cost_index for item in router.candidates if item.registry_id == model["registry_id"]),
                            catalog_hash=benchmark_result["catalog_hash"],
                            benchmark_suite_hash=benchmark_cache_hash,
                        )
        runtime = MeshRuntime(
            repository=Path(args.repo), mesh_store=mesh_store,
            continuity_store=ContinuityStore(Path(args.continuity_database)),
            router=router, providers=provider_registry, worker_id=args.worker_id,
            global_parallel_cap=args.max_nodes, performance_context_hash=benchmark_cache_hash,
        )
        if command == "mesh-run-once":
            result = runtime.run_once(maximum_nodes=args.max_nodes).to_dict()
        elif command == "mesh-run-until-idle":
            result = runtime.run_until_idle(maximum_ticks=args.maximum_ticks, maximum_seconds=args.maximum_seconds)
        else:
            result = runtime.serve(
                maximum_seconds=args.maximum_seconds, poll_seconds=args.poll_seconds,
                maximum_nodes=args.max_nodes, status_interval_seconds=args.status_interval_seconds,
            )
        if benchmark_result is not None:
            result["automatic_model_benchmark"] = benchmark_result
        return result, 0
    if command == "github-audit":
        result = audit_github(args.repo_slug, args.branch)
        result["claim_boundary"] = "A read-only API report proves only the returned GitHub state; cloud OIDC trust and runtime controls require separate evidence."
        return result, 0 if not result["errors"] else 21
    if command == "release-readiness":
        result = evaluate_release_readiness(
            repository=args.repo_id,
            contract_path=Path(args.contract),
            base_sha=args.base,
            head_sha=args.head,
            policy_bundle_hash=args.policy_bundle_hash,
            toolchain_hash=args.toolchain_hash,
            risk=args.risk,
            target=args.target,
            evidence_records=load_evidence_records(Path(args.evidence_dir)),
            evidence_schema=_data(_root_file("schemas/evidence.schema.json")),
            release_policy=_data(args.policy),
            trust_roots=load_trust_roots(Path(args.trust_roots)),
            release_manifest=_data(args.release_manifest) if args.release_manifest else None,
            release_manifest_schema=_data(_root_file("schemas/release-manifest.schema.json")),
        )
        return result, 0 if result["decision"] in {"MERGE_ELIGIBLE", "STAGING_ELIGIBLE", "RELEASE_ELIGIBLE", "PRODUCTION_VERIFIED"} else 22
    if command == "policy-bundle-hash":
        root = Path(args.root).resolve()
        return {"root": str(root), "sha256": hash_directory(root)}, 0
    if command in {"audit", "dry-run"}:
        result = installer.plan(args.repo, activate_ci=args.activate_ci, install_repo_skills=not args.no_repo_skills)
        result.update({"mode": command.upper().replace("-", "_"), "repository_mutated": False})
        return result, 0
    if command in {"install", "update"}:
        result = installer.apply_install(args.repo, activate_ci=args.activate_ci, install_repo_skills=not args.no_repo_skills)
        result["mode"] = command.upper()
        return result, 0 if result.get("applied") else 15
    if command == "uninstall":
        return installer.uninstall(args.repo), 0
    if command == "preflight":
        repo = GitRepository(args.repo)
        contract_path = _repo_path(repo, args.contract)
        contract_errors = validate_file(contract_path, _root_file("schemas/change-contract.schema.json"))
        if contract_errors:
            return {"passed": False, "stage": "CONTRACT", "errors": contract_errors}, 2
        risk_result = classify_repository_change(repo, _data(contract_path), args.base, args.head, _root_file("policies/risk-policy.yaml")).to_dict()
        paths = [item.path for item in repo.changed_paths(args.base, args.head)]
        control_result = detect_control_plane_changes(paths, _data(_root_file("policies/path-policy.yaml")))
        test_result = inspect_repository_test_integrity(repo, args.base, args.head)
        diff_result = evaluate_diff_limits(repo, args.base, args.head, risk_result["risk"], _data(_root_file("policies/diff-limits.yaml")))
        passed = not risk_result["blocked"] and not control_result["blocked"] and not test_result["blocked"] and diff_result["passed"]
        return {
            "passed": passed,
            "contract": {"valid": True, "hash": sha256_file(contract_path)},
            "risk": risk_result,
            "control_plane": control_result,
            "test_integrity": test_result,
            "diff_limits": diff_result,
            "policy_bundle_hash": hash_directory(_root_file("policies")),
            "next_action": "BUILD_CONTEXT_AND_RUN_CHECKS" if passed else "CONTAIN_TASK_REPLAN_OR_CONTINUE_QUEUE",
        }, 0 if passed else 16
    if command == "validate-bundle":
        result = validate_bundle(Path(args.root).resolve())
        return result, 0 if result["valid"] else 17
    if command == "validate-marketplace":
        result = validate_marketplace(Path(args.root).resolve())
        return result, 0 if result["valid"] else 23
    if command == "build-distribution":
        result = build_distributions(
            Path(args.root),
            Path(args.output_dir),
            create_stable_aliases=not args.no_stable_aliases,
        )
        return result, 0
    if command == "validate-distribution":
        result = validate_distribution_archive(Path(args.archive), args.kind)
        return result, 0 if result["valid"] else 24
    if command == "verify-checksums":
        result = verify_checksum_file(Path(args.file))
        return result, 0 if result["valid"] else 25
    raise ValueError(f"Unhandled command: {command}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result, exit_code = execute(args)
    except (ZTADError, OSError, ValueError, KeyError, TypeError) as exc:
        result = {"error": type(exc).__name__, "message": str(exc), "decision": "FAIL_CLOSED"}
        exit_code = 99
    _write_result(result, args.output)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
