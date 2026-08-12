from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one replacement, found {count}: {old[:80]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8")


def replace_count(path: str, old: str, new: str, expected: int) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != expected:
        raise SystemExit(f"{path}: expected {expected} replacements, found {count}: {old[:80]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8")


# ---- Mesh plan: proportional guarded fast paths for R0/R1/R2. ----
mesh_path = ROOT / "toolkit/ztad/mesh_plan.py"
mesh = mesh_path.read_text(encoding="utf-8")
old_to_dict = '''    def to_dict(self) -> dict[str, Any]:\n        return {\n            "schema_version": 1,\n'''
new_to_dict = '''    def to_dict(self) -> dict[str, Any]:\n        deterministic_roles = {"repository_indexer", "patch_integrator", "check_runner"}\n        model_nodes = [node for node in self.nodes if node.role not in deterministic_roles]\n        intended_usage: dict[str, int] = {}\n        for node in model_nodes:\n            registry_id = str((node.metadata or {}).get("preferred_registry_id") or "adaptive")\n            intended_usage[registry_id] = intended_usage.get(registry_id, 0) + 1\n        execution_mode = "GUARDED_FAST_PATH" if self.risk in {"R0", "R1"} else "BOUNDED_MESH" if self.risk == "R2" else "FULL_MESH"\n        return {\n            "schema_version": 1,\n            "execution_mode": execution_mode,\n            "model_call_count": len(model_nodes),\n            "intended_model_usage": dict(sorted(intended_usage.items())),\n'''
if mesh.count(old_to_dict) != 1:
    raise SystemExit("mesh_plan.py: could not locate MeshPlan.to_dict")
mesh = mesh.replace(old_to_dict, new_to_dict)
start = mesh.index("def build_mesh_plan(\n")
end = mesh.index("\ndef write_mesh_plan(", start)
new_build = r'''def build_mesh_plan(
    *,
    task_id: str,
    risk: str,
    contract: dict[str, Any],
    prompt_root: str = ".delivery/ztad/mesh-prompts",
    output_schema: str = "schemas/agent-result.schema.json",
    maximum_parallel_writers: int = 8,
    maximum_plan_candidates: int = 4,
    check_config: str = ".delivery/ztad/config.json",
    command_policy: str = "policies/command-policy.yaml",
    risk_policy: str = "policies/risk-policy.yaml",
) -> MeshPlan:
    if risk not in _RISK_RANK:
        raise ValueError(f"Unknown risk: {risk}")
    if not isinstance(contract, dict):
        raise ValueError("contract must be an object")
    scope = contract.get("scope", {}) or {}
    expected_components = scope.get("expected_components", []) or []
    if not expected_components:
        raise ValueError("Change Contract has no expected_components")
    rank = _RISK_RANK[risk]
    raw_scope_groups = _group_scopes(expected_components, max(1, maximum_parallel_writers))
    if rank <= 2:
        # Fast/medium paths deliberately use one isolated writer. Parallel writer fan-out
        # is reserved for R3/R4 where its coordination cost is justified.
        all_patterns = tuple(sorted({pattern for group in raw_scope_groups for pattern in group}))
        scope_groups = (all_patterns,)
    else:
        scope_groups = raw_scope_groups
    all_scopes = sum((list(group) for group in scope_groups), [])
    budget = contract.get("budget", {}) or {}
    max_review_runs = int(budget.get("max_review_runs", 0))
    max_repair_cycles = int(budget.get("max_repair_cycles", 0))
    if rank <= 1 and max_review_runs < 1:
        raise ValueError("R0/R1 guarded fast path requires at least one independent review run")
    if rank == 2 and max_review_runs < 1:
        raise ValueError("R2 bounded mesh requires at least one independent review run")
    scout_dimensions, review_dimensions = _dimensions(risk, contract)
    plan_candidates = min(maximum_plan_candidates, 3 if rank == 3 else 4 if rank == 4 else 1)
    prompts: dict[str, str] = {}
    nodes: list[MeshNodeSpec] = []
    contract_hash = sha256_json(contract)
    base_metadata = {
        "contract_hash": contract_hash,
        "prompt_version": "mesh-4.3",
        "max_attempts": max(1, 1 + max_repair_cycles) if rank <= 2 else 4,
    }

    def add(
        key: str, *, title: str, family: str, role: str, agent_role: str, dimension: str,
        write: bool = False, scopes: Iterable[str] = (), dependencies: Iterable[str] = (),
        priority: int = 0, metadata: dict[str, Any] | None = None,
    ) -> str:
        node_id = f"{_slug(task_id)}-{_slug(key)}"
        prompt_path = f"{prompt_root.rstrip('/')}/{node_id}.md"
        purpose = {
            "repository_index": "Build a deterministic repository index and bounded context seed before model work.",
            "context_scout": "Collect evidence-backed repository context for the assigned dimension.",
            "architecture": "Produce an independent bounded implementation plan candidate.",
            "plan_adjudication": "Compare plan candidates and select or synthesize the strongest bounded plan.",
            "test_design": "Design independent acceptance, negative, boundary and regression test oracles.",
            "implementation": "Implement the assigned independent scope in a disposable worktree.",
            "integration": "Deterministically combine independent patches; no model judgment is permitted.",
            "verification": "Apply the integrated patch to one deterministic candidate SHA and run reviewed machine checks.",
            "review": "Adversarially review the exact checked candidate in the assigned dimension.",
            "release": "Assess release strategy and evidence gaps without authorizing platform actions.",
        }.get(family, title)
        node_scopes = tuple(scopes)
        prompts[prompt_path] = _prompt(
            title=title, purpose=purpose, agent_role=agent_role, contract=contract,
            dimension=dimension, write=write, scopes=node_scopes,
        )
        node_metadata = {
            **base_metadata,
            "agent_role": agent_role,
            "dimension": dimension,
            "complexity": min(5, max(1, rank + (1 if family in {"architecture", "review", "release"} else 0))),
            "ambiguity": len([x for x in contract.get("requirements", {}).get("assumptions", []) if x.get("status") == "unverified"]),
            **(metadata or {}),
        }
        nodes.append(MeshNodeSpec.create(
            node_id=node_id, task_id=task_id, title=title, task_family=family,
            role=role, risk=risk, write_access=write, scopes=node_scopes,
            prompt_path=prompt_path, output_schema=output_schema, priority=priority,
            metadata=node_metadata, dependencies=dependencies,
            idempotency_key=sha256_json({"task": task_id, "risk": risk, "key": key, "contract": contract_hash}),
        ))
        return node_id

    indexer = add(
        "repository-index", title="Deterministic repository index", family="repository_index",
        role="repository_indexer", agent_role="planner", dimension="static-repository-index",
        scopes=all_scopes, dependencies=(), priority=110,
        metadata={"deterministic_node": True, "expected_components": list(expected_components)},
    )

    def add_integrator_and_checks(implementation_ids: list[str]) -> tuple[str, str]:
        integrator = add(
            "integrate", title="Deterministic patch integration", family="integration",
            role="patch_integrator", agent_role="implementer", dimension="patch-integration",
            scopes=all_scopes, dependencies=implementation_ids, priority=60,
            metadata={"deterministic_node": True},
        )
        checks = add(
            "machine-checks", title="Deterministic machine verification", family="verification",
            role="check_runner", agent_role="planner", dimension="configured-machine-checks",
            scopes=all_scopes, dependencies=[integrator], priority=55,
            metadata={
                "deterministic_node": True, "consume_dependency_patches": True,
                "check_config": check_config, "command_policy": command_policy, "risk_policy": risk_policy,
            },
        )
        return integrator, checks

    if rank <= 1:
        worker = add(
            "implement-1", title="Primary bounded implementation", family="implementation",
            role="worker", agent_role="implementer", dimension="bounded-change",
            write=True, scopes=scope_groups[0], dependencies=[indexer], priority=70,
            metadata={
                "preferred_registry_id": "codex-luna",
                "maximum_reasoning_effort": "high",
                "strategy_hash": sha256_json({"mode": "guarded-fast", "contract": contract_hash}),
            },
        )
        integrator, checks = add_integrator_and_checks([worker])
        add(
            "final-guard", title="Independent frontier final guard", family="review",
            role="supervisor", agent_role="independent_reviewer", dimension="final-guard",
            scopes=all_scopes, dependencies=[integrator, checks], priority=50,
            metadata={
                "consume_dependency_patches": True,
                "preferred_registry_id": "codex-sol",
                "maximum_reasoning_effort": "high",
                "mandatory_final_guard": True,
            },
        )
        return _finalize_plan(
            task_id=task_id, risk=risk, contract_hash=contract_hash, nodes=nodes, prompts=prompts,
            scope_groups=scope_groups,
            rationale=(
                "guarded fast path: deterministic index -> Luna worker -> integration -> checks/risk reclassification -> one Sol final guard",
                "no redundant scout, plan adjudicator, test-oracle, supervisor synthesis, or release-advisor calls on the normal R0/R1 path",
                "actual-diff risk escalation invalidates this topology before final review",
            ),
        )

    if rank == 2:
        scout = add(
            "scout-focused", title="Focused context scout", family="context_scout",
            role="context_scout", agent_role="planner", dimension="runtime-and-tests",
            scopes=all_scopes, dependencies=[indexer], priority=100,
            metadata={
                "require_context_sufficiency": True,
                "preferred_registry_id": "codex-terra",
                "maximum_reasoning_effort": "high",
            },
        )
        worker = add(
            "implement-1", title="Primary bounded implementation", family="implementation",
            role="worker", agent_role="implementer", dimension="bounded-change",
            write=True, scopes=scope_groups[0], dependencies=[scout], priority=70,
            metadata={
                "preferred_registry_id": "codex-luna",
                "maximum_reasoning_effort": "high",
                "strategy_hash": sha256_json({"mode": "bounded-r2", "contract": contract_hash}),
            },
        )
        integrator, checks = add_integrator_and_checks([worker])
        review_count = min(2, max_review_runs)
        dimensions = ("scope-correctness-tests", "runtime-compatibility")[:review_count]
        for index, dimension in enumerate(dimensions, 1):
            add(
                f"focused-review-{index}", title=f"Focused independent review {index}", family="review",
                role="focused_reviewer", agent_role="independent_reviewer", dimension=dimension,
                scopes=all_scopes, dependencies=[integrator, checks], priority=50,
                metadata={
                    "consume_dependency_patches": True,
                    "preferred_registry_id": "codex-terra",
                    "maximum_reasoning_effort": "high",
                },
            )
        return _finalize_plan(
            task_id=task_id, risk=risk, contract_hash=contract_hash, nodes=nodes, prompts=prompts,
            scope_groups=scope_groups,
            rationale=(
                "bounded R2 mesh: one focused Terra scout, one Luna worker, deterministic integration/checks, and at most two focused Terra reviews",
                "plan adjudication and release-advisor fan-out are reserved for R3/R4",
                "actual-diff risk escalation invalidates this topology before review",
            ),
        )

    # R3/R4 retain the full independent mesh. Cost is intentional because risk is high.
    scout_ids = [
        add(
            f"scout-{dimension}", title=f"{dimension.title()} context scout",
            family="context_scout", role="context_scout", agent_role="planner",
            dimension=dimension, scopes=all_scopes, dependencies=[indexer], priority=100,
            metadata={"require_context_sufficiency": True},
        )
        for dimension in scout_dimensions
    ]
    plan_ids = [
        add(
            f"plan-{index + 1}", title=f"Independent plan candidate {index + 1}",
            family="architecture", role="architecture_advisor", agent_role="architecture_advisor",
            dimension=f"candidate-{index + 1}", scopes=all_scopes,
            dependencies=scout_ids, priority=90,
            metadata={"require_provider_diversity": index > 0, "maximum_reasoning_effort": "high"},
        )
        for index in range(plan_candidates)
    ]
    adjudicator = add(
        "plan-adjudicator", title="Frontier plan adjudication", family="plan_adjudication",
        role="plan_adjudicator", agent_role="architecture_advisor", dimension="plan-adjudication",
        scopes=all_scopes, dependencies=plan_ids, priority=85,
        metadata={"require_provider_diversity": True, "maximum_reasoning_effort": "high"},
    )
    test_oracle = add(
        "test-oracle", title="Independent test-oracle design", family="test_design",
        role="test_designer", agent_role="planner", dimension="acceptance-and-negative-tests",
        scopes=all_scopes, dependencies=[adjudicator], priority=80,
    )
    implementation_ids: list[str] = []
    for index, group in enumerate(scope_groups, 1):
        implementation_ids.append(add(
            f"implement-{index}", title=f"Implementation shard {index}", family="implementation",
            role="worker", agent_role="implementer", dimension=f"scope-shard-{index}",
            write=True, scopes=group, dependencies=[adjudicator, test_oracle], priority=70,
            metadata={
                "preferred_registry_id": "codex-terra" if risk == "R3" else None,
                "strategy_hash": sha256_json({"plan": contract_hash, "scope": group}),
            },
        ))
    integrator, checks = add_integrator_and_checks(implementation_ids)
    review_ids = [
        add(
            f"review-{dimension}", title=f"Independent {dimension} review", family="review",
            role=("security_reviewer" if dimension == "security" else "data_reviewer" if dimension == "data" else "supervisor"),
            agent_role="independent_reviewer", dimension=dimension,
            scopes=all_scopes, dependencies=[integrator, checks], priority=50,
            metadata={
                "consume_dependency_patches": True, "require_provider_diversity": True,
                "maximum_reasoning_effort": "high",
            },
        )
        for dimension in review_dimensions
    ]
    supervisor = add(
        "supervisor", title="Frontier synthesis and technical decision", family="review",
        role="supervisor", agent_role="independent_reviewer", dimension="review-synthesis",
        scopes=all_scopes, dependencies=[integrator, checks, *review_ids], priority=40,
        metadata={
            "consume_dependency_patches": True, "require_provider_diversity": True,
            "maximum_reasoning_effort": "high",
        },
    )
    add(
        "release-advisor", title="Frontier release-readiness advice", family="release",
        role="release_advisor", agent_role="release_advisor", dimension="release-and-rollback",
        scopes=all_scopes, dependencies=[integrator, checks, supervisor], priority=30,
        metadata={
            "consume_dependency_patches": True, "require_provider_diversity": True,
            "maximum_reasoning_effort": "high",
        },
    )
    return _finalize_plan(
        task_id=task_id, risk=risk, contract_hash=contract_hash, nodes=nodes, prompts=prompts,
        scope_groups=scope_groups,
        rationale=(
            "full R3/R4 mesh retains deterministic indexing, independent scouts/plans, adjudication, test oracle, isolated writers, checks, multidimensional reviews, synthesis, and release advice",
            f"{len(scout_ids)} independent context dimensions",
            f"{plan_candidates} independent plan candidates",
            f"{len(implementation_ids)} non-overlapping implementation shards",
            f"{len(review_ids)} independent review dimensions",
        ),
    )


def _finalize_plan(
    *, task_id: str, risk: str, contract_hash: str, nodes: list[MeshNodeSpec],
    prompts: dict[str, str], scope_groups: tuple[tuple[str, ...], ...], rationale: tuple[str, ...],
) -> MeshPlan:
    material = {
        "task_id": task_id, "risk": risk, "contract_hash": contract_hash,
        "nodes": [(node.node_id, node.role, node.dependencies, node.scopes, node.metadata.get("preferred_registry_id")) for node in nodes],
    }
    return MeshPlan(
        task_id=task_id, risk=risk, plan_id=sha256_json(material), nodes=tuple(nodes),
        prompt_files=prompts, scope_groups=scope_groups, rationale=rationale,
    )
'''
mesh = mesh[:start] + new_build + mesh[end:]
mesh_path.write_text(mesh, encoding="utf-8")

# ---- Router: explicit preferred registry and hard reasoning ceiling. ----
replace_once(
    "toolkit/ztad/model_router.py",
    "    preferred_provider: str | None = None\n    excluded_models: tuple[str, ...] = ()\n",
    "    preferred_provider: str | None = None\n    preferred_registry_id: str | None = None\n    maximum_reasoning_effort: str | None = None\n    excluded_models: tuple[str, ...] = ()\n",
)
replace_once(
    "toolkit/ztad/model_router.py",
    "        if self.prior_failures < 0:\n            raise ValueError(\"prior_failures must be non-negative\")\n",
    "        if self.prior_failures < 0:\n            raise ValueError(\"prior_failures must be non-negative\")\n        if self.maximum_reasoning_effort is not None and self.maximum_reasoning_effort not in {\"none\", \"low\", \"medium\", \"high\", \"xhigh\", \"max\", \"ultra\"}:\n            raise ValueError(\"maximum_reasoning_effort is unsupported\")\n",
)
router_path = ROOT / "toolkit/ztad/model_router.py"
router = router_path.read_text(encoding="utf-8")
rstart = router.index("    def _reasoning(self, candidate: ModelCandidate, profile: TaskProfile) -> str:\n")
rend = router.index("\n    def route(\n", rstart)
new_reasoning = '''    def _reasoning(self, candidate: ModelCandidate, profile: TaskProfile) -> str:\n        target = "medium"\n        pressure = RISK_RANK[profile.risk] + profile.complexity + profile.ambiguity + min(profile.prior_failures, 3)\n        if pressure >= 11:\n            target = "max"\n        elif pressure >= 8:\n            target = "xhigh"\n        elif pressure >= 5:\n            target = "high"\n        elif pressure <= 2:\n            target = "low"\n        order = ["none", "low", "medium", "high", "xhigh", "max", "ultra"]\n        available = [item for item in order if item in candidate.reasoning_efforts]\n        if not available:\n            raise ValueError(f"Candidate {candidate.registry_id} has no supported reasoning effort")\n        caps = self.policy.get("maximum_reasoning_effort_by_registry", {}) or {}\n        cap = profile.maximum_reasoning_effort or caps.get(candidate.registry_id)\n        if cap is not None:\n            if cap not in order:\n                raise ValueError(f"Unsupported reasoning cap for {candidate.registry_id}: {cap}")\n            cap_index = order.index(cap)\n            available = [item for item in available if order.index(item) <= cap_index]\n            if not available:\n                raise ValueError(f"Candidate {candidate.registry_id} has no reasoning effort at or below cap {cap}")\n        wanted_index = order.index(target)\n        return min(available, key=lambda item: abs(order.index(item) - wanted_index))\n'''
router = router[:rstart] + new_reasoning + router[rend:]
router = router.replace(
    '            reasons = [f"quality {quality:.3f} >= floor {quality_floor:.3f}"]\n',
    '            reasons = [f"quality {quality:.3f} >= floor {quality_floor:.3f}"]\n            if profile.preferred_registry_id and candidate.registry_id == profile.preferred_registry_id:\n                reasons.append("preferred registry")\n',
    1,
)
router = router.replace(
    '        if not options:\n            raise LookupError("No available model satisfies the task quality, tier, provider, and sandbox constraints")\n        # Higher score wins; deterministic tie breakers prefer lower cost/latency and stable registry id.\n',
    '        if not options:\n            raise LookupError("No available model satisfies the task quality, tier, provider, and sandbox constraints")\n        if profile.preferred_registry_id:\n            preferred = [item for item in options if item.candidate.registry_id == profile.preferred_registry_id]\n            if preferred:\n                options = preferred\n        # Higher score wins; deterministic tie breakers prefer lower cost/latency and stable registry id.\n',
    1,
)
router_path.write_text(router, encoding="utf-8")

# ---- Runtime profile supports the planner's explicit routing intent. ----
replace_once(
    "toolkit/ztad/mesh_runtime.py",
    '    "context_scout": "planner",\n',
    '    "context_scout": "planner",\n    "focused_reviewer": "independent_reviewer",\n',
)
replace_once(
    "toolkit/ztad/mesh_runtime.py",
    "            preferred_provider=metadata.get(\"preferred_provider\"),\n            excluded_models=tuple(excluded_models),\n",
    "            preferred_provider=metadata.get(\"preferred_provider\"),\n            preferred_registry_id=metadata.get(\"preferred_registry_id\"),\n            maximum_reasoning_effort=metadata.get(\"maximum_reasoning_effort\"),\n            excluded_models=tuple(excluded_models),\n",
)

# ---- Model catalog: Luna is the explicit low/medium-risk worker; Sol has a hard HIGH ceiling. ----
catalog_path = ROOT / "policies/model-catalog.yaml"
catalog = catalog_path.read_text(encoding="utf-8")
catalog = catalog.replace(
    "  preferred_provider_bonus: 0.02\n  global_parallel_cap: 16\n",
    "  preferred_provider_bonus: 0.02\n  preferred_worker_registry_id: codex-luna\n  balanced_fallback_registry_id: codex-terra\n  frontier_consultant_registry_id: codex-sol\n  maximum_reasoning_effort_by_registry:\n    codex-sol: high\n  global_parallel_cap: 16\n",
    1,
)
catalog = catalog.replace("      default: 0.76\n      repository_navigation", "      default: 0.76\n      implementation: 0.84\n      repository_navigation", 1)
catalog = catalog.replace("    reasoning_efforts: [medium, high, xhigh, max]\n", "    reasoning_efforts: [medium, high]\n", 1)
catalog_path.write_text(catalog, encoding="utf-8")

# Budget policy now matches the mandatory low-risk guard and bounded R2 reviews.
budget_path = ROOT / "policies/budget-policy.yaml"
budget = budget_path.read_text(encoding="utf-8")
budget = budget.replace("R0:\n  implementation_runs: 1\n  independent_reviews: 0\n", "R0:\n  implementation_runs: 1\n  independent_reviews: 1\n", 1)
budget = budget.replace("R2:\n  implementation_runs: 1\n  independent_reviews: 1\n", "R2:\n  implementation_runs: 1\n  independent_reviews: 2\n", 1)
budget_path.write_text(budget, encoding="utf-8")

# ---- Benchmark refusal/insufficient-context responses cannot earn a perfect capability score. ----
bench_path = ROOT / "toolkit/ztad/model_benchmark.py"
bench = bench_path.read_text(encoding="utf-8")
bench = bench.replace(
    "def _score_output(output: dict[str, Any] | None, assertions: dict[str, Any]) -> dict[str, Any]:\n",
    "_ABSTENTION_RESULT_TYPES = {\"INSUFFICIENT_CONTEXT\", \"INSUFFICIENT_EVIDENCE\", \"WAITING_EXTERNAL_DEPENDENCY\", \"AUTO_REPLAN\", \"QUARANTINE_AND_CONTINUE\"}\n\n\ndef _score_output(output: dict[str, Any] | None, assertions: dict[str, Any]) -> dict[str, Any]:\n",
    1,
)
bench = bench.replace(
    '    passed = sum(1 for item in checks if item["passed"])\n    return {"score": passed / max(1, len(checks)), "checks": checks}\n',
    '    passed = sum(1 for item in checks if item["passed"])\n    raw_score = passed / max(1, len(checks))\n    if output.get("result_type") in _ABSTENTION_RESULT_TYPES:\n        add("capability_demonstrated", False, output.get("result_type"))\n        raw_score = min(raw_score, 0.25)\n    return {"score": raw_score, "checks": checks}\n',
    1,
)
bench_path.write_text(bench, encoding="utf-8")

# Benchmark persistence must keep latency/cost in the same normalized index units as the catalog.
cli_path = ROOT / "toolkit/ztad/cli.py"
cli = cli_path.read_text(encoding="utf-8")
old_metrics = '''                        latency=float(case["latency_seconds"]),\n                        cost=max(0.01, float((case.get("input_tokens") or 0) + (case.get("output_tokens") or 0)) / 100000.0),\n'''
new_metrics = '''                        latency=next(item.latency_index for item in router.candidates if item.registry_id == model["registry_id"]),\n                        cost=next(item.cost_index for item in router.candidates if item.registry_id == model["registry_id"]),\n'''
if cli.count(old_metrics) != 3:
    raise SystemExit(f"cli.py: expected 3 benchmark metric persistence blocks, found {cli.count(old_metrics)}")
cli = cli.replace(old_metrics, new_metrics)
cli_path.write_text(cli, encoding="utf-8")

# ---- Version metadata. ----
for path in ("VERSION",):
    (ROOT / path).write_text("4.3.0\n", encoding="utf-8")
plugin_path = ROOT / ".codex-plugin/plugin.json"
plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
plugin["version"] = "4.3.0"
plugin_path.write_text(json.dumps(plugin, indent=2, sort_keys=True) + "\n", encoding="utf-8")
replace_once("toolkit/pyproject.toml", 'version = "4.2.1"', 'version = "4.3.0"')
replace_count(
    ".github/workflows/ci.yml",
    "zero-trust-agentic-delivery-plugin-4.2.1.zip",
    "zero-trust-agentic-delivery-plugin-4.3.0.zip",
    1,
)
replace_count(
    ".github/workflows/ci.yml",
    "zero-trust-agentic-delivery-marketplace-4.2.1.zip",
    "zero-trust-agentic-delivery-marketplace-4.3.0.zip",
    1,
)
changelog = ROOT / "CHANGELOG.md"
changelog_text = changelog.read_text(encoding="utf-8")
entry = '''## 4.3.0 — 2026-08-12\n\n- Added guarded R0/R1 fast paths: deterministic index, Luna implementation, deterministic integration/checks with actual-diff risk reclassification, and exactly one Sol final guard.\n- Added bounded R2 routing with one focused Terra scout, one Luna implementation, deterministic integration/checks, and up to two focused Terra reviews.\n- Retained the full independent mesh for R3/R4.\n- Added explicit preferred-model routing and a defense-in-depth hard HIGH reasoning ceiling for every Sol invocation.\n- Prevented protocol-correct benchmark abstentions from receiving perfect capability scores and kept learned cost/latency in normalized catalog-index units.\n- Added dry-run model-call counts and intended model usage to every mesh plan.\n\n'''
if "## 4.3.0" not in changelog_text:
    changelog_text = changelog_text.replace("# Changelog\n\n", "# Changelog\n\n" + entry, 1)
changelog.write_text(changelog_text, encoding="utf-8")

# ---- New architecture/routing regressions. ----
test_path = ROOT / "tests/test_v43_guarded_fast_path.py"
test_path.write_text(r'''from __future__ import annotations

from pathlib import Path

import pytest

from conftest import valid_contract
from ztad.mesh_plan import build_mesh_plan
from ztad.model_benchmark import _score_output
from ztad.model_router import AdaptiveModelRouter, TaskProfile
from ztad.util import load_data

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "policies/model-catalog.yaml"


def _plan(risk: str):
    return build_mesh_plan(task_id=f"shape-{risk.lower()}", risk=risk, contract=valid_contract(risk=risk))


def _model_nodes(plan):
    return [node for node in plan.nodes if node.role not in {"repository_indexer", "patch_integrator", "check_runner"}]


@pytest.mark.parametrize("risk", ["R0", "R1"])
def test_low_risk_guarded_fast_path_is_exactly_two_model_calls(risk):
    plan = _plan(risk)
    payload = plan.to_dict()
    assert len(plan.nodes) == 5
    assert payload["execution_mode"] == "GUARDED_FAST_PATH"
    assert payload["model_call_count"] == 2
    assert payload["intended_model_usage"] == {"codex-luna": 1, "codex-sol": 1}
    roles = [node.role for node in plan.nodes]
    assert roles == ["repository_indexer", "worker", "patch_integrator", "check_runner", "supervisor"]
    assert not any(node.role in {"plan_adjudicator", "release_advisor", "architecture_advisor", "test_designer", "context_scout"} for node in plan.nodes)


def test_r2_is_bounded_to_seven_nodes_and_four_model_calls():
    plan = _plan("R2")
    payload = plan.to_dict()
    assert len(plan.nodes) == 7
    assert payload["execution_mode"] == "BOUNDED_MESH"
    assert payload["model_call_count"] == 4
    assert payload["intended_model_usage"] == {"codex-luna": 1, "codex-terra": 3}
    assert sum(node.role == "focused_reviewer" for node in plan.nodes) == 2
    assert not any(node.role in {"plan_adjudicator", "release_advisor", "architecture_advisor"} for node in plan.nodes)


@pytest.mark.parametrize("risk", ["R3", "R4"])
def test_high_risk_retains_full_mesh(risk):
    plan = _plan(risk)
    payload = plan.to_dict()
    roles = {node.role for node in plan.nodes}
    assert payload["execution_mode"] == "FULL_MESH"
    assert {"repository_indexer", "architecture_advisor", "plan_adjudicator", "test_designer", "worker", "patch_integrator", "check_runner", "supervisor", "release_advisor"} <= roles
    assert payload["model_call_count"] > 4


def test_luna_is_primary_r2_worker_and_terra_is_fail_safe_fallback():
    router = AdaptiveModelRouter.from_file(CATALOG)
    profile = TaskProfile(
        task_family="implementation", role="worker", risk="R2",
        complexity=2, preferred_registry_id="codex-luna", maximum_reasoning_effort="high",
    )
    first = router.route(profile)
    assert first.candidate.registry_id == "codex-luna"
    fallback = router.route(profile, unavailable_registry_ids={"codex-luna"})
    assert fallback.candidate.registry_id == "codex-terra"


@pytest.mark.parametrize("risk,complexity,ambiguity,failures", [
    ("R0", 1, 0, 0), ("R2", 5, 3, 3), ("R3", 5, 5, 3), ("R4", 5, 5, 9),
])
def test_sol_can_never_exceed_high_reasoning(risk, complexity, ambiguity, failures):
    router = AdaptiveModelRouter.from_file(CATALOG)
    decision = router.route(TaskProfile(
        task_family="review", role="supervisor", risk=risk,
        complexity=complexity, ambiguity=ambiguity, prior_failures=failures,
        preferred_registry_id="codex-sol",
    ))
    assert decision.candidate.registry_id == "codex-sol"
    assert decision.reasoning_effort in {"none", "low", "medium", "high"}
    assert decision.reasoning_effort != "xhigh"
    assert decision.reasoning_effort != "max"
    assert decision.reasoning_effort != "ultra"


def test_catalog_defense_in_depth_removes_sol_efforts_above_high():
    catalog = load_data(CATALOG)
    sol = next(item for item in catalog["models"] if item["registry_id"] == "codex-sol")
    assert set(sol["reasoning_efforts"]) <= {"none", "low", "medium", "high"}
    assert catalog["routing"]["maximum_reasoning_effort_by_registry"]["codex-sol"] == "high"


def test_benchmark_abstention_cannot_score_as_capability_success():
    output = {"result_type": "INSUFFICIENT_CONTEXT", "requested_action": "REQUEST_CONTEXT_EXPANSION", "findings": []}
    scored = _score_output(output, {
        "result_type_in": ["PLAN_READY", "INSUFFICIENT_CONTEXT"],
        "requested_action_in": ["VALIDATE_PLAN", "REQUEST_CONTEXT_EXPANSION"],
        "max_findings": 0,
    })
    assert scored["score"] <= 0.25
''', encoding="utf-8")
