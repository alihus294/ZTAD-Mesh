from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}: {old[:100]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8")


def replace_count(path: str, old: str, new: str, expected: int) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != expected:
        raise SystemExit(f"{path}: expected {expected} replacements, found {count}: {old[:100]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8")


# --- Budget and mesh caps are executable defaults, not aspirational YAML. ---
replace_once(
    "toolkit/ztad/mesh_plan.py",
    "    maximum_parallel_writers: int = 8,\n",
    "    maximum_parallel_writers: int = 6,\n",
)
replace_once(
    "toolkit/ztad/autopilot.py",
    "    maximum_parallel_writers: int = 8,\n",
    "    maximum_parallel_writers: int = 6,\n",
)
replace_count(
    "toolkit/ztad/cli.py",
    'p.add_argument("--max-parallel-writers", type=int, default=8)',
    'p.add_argument("--max-parallel-writers", type=int, default=6)',
    2,
)
replace_once(
    "toolkit/ztad/mesh_plan.py",
    '    max_review_runs = int(budget.get("max_review_runs", 0))\n    max_repair_cycles = int(budget.get("max_repair_cycles", 0))\n',
    '    max_implementation_runs = int(budget.get("max_implementation_runs", 0))\n    max_review_runs = int(budget.get("max_review_runs", 0))\n    max_repair_cycles = int(budget.get("max_repair_cycles", 0))\n    if max_implementation_runs < 1:\n        raise ValueError("Mesh execution requires at least one implementation run")\n',
)

# --- Model performance overrides require repeated evidence before influencing routing. ---
replace_once(
    "policies/model-catalog.yaml",
    "  frontier_role_quality_floor: 0.92\n",
    "  frontier_role_quality_floor: 0.92\n  minimum_observations_for_override: 2\n",
)
store_path = ROOT / "toolkit/ztad/mesh_store.py"
store = store_path.read_text(encoding="utf-8")
old_sig = '''    def performance_overrides(\n        self, task_family: str, *, catalog_hash: str | None = None, benchmark_suite_hash: str | None = None\n    ) -> dict[str, dict[str, float]]:\n'''
new_sig = '''    def performance_overrides(\n        self, task_family: str, *, catalog_hash: str | None = None, benchmark_suite_hash: str | None = None,\n        minimum_runs: int = 1,\n    ) -> dict[str, dict[str, float]]:\n        if minimum_runs < 1:\n            raise ValueError("minimum_runs must be at least 1")\n'''
if store.count(old_sig) != 1:
    raise SystemExit("mesh_store.py: performance_overrides signature not found")
store = store.replace(old_sig, new_sig, 1)
old_runs = '''                runs = max(1, int(row["runs"]))\n                result[row["registry_id"]] = {\n'''
new_runs = '''                runs = max(1, int(row["runs"]))\n                if runs < minimum_runs:\n                    continue\n                result[row["registry_id"]] = {\n'''
if store.count(old_runs) != 1:
    raise SystemExit("mesh_store.py: runs averaging block not found")
store = store.replace(old_runs, new_runs, 1)
store_path.write_text(store, encoding="utf-8")

# --- Continuity phase state follows the Mesh without granting merge/release authority. ---
runtime_path = ROOT / "toolkit/ztad/mesh_runtime.py"
runtime = runtime_path.read_text(encoding="utf-8")
old_init = '''        global_parallel_cap: int = 8,\n        trusted_control_roots: tuple[Path, ...] | None = None,\n    ):\n'''
new_init = '''        global_parallel_cap: int = 8,\n        trusted_control_roots: tuple[Path, ...] | None = None,\n        performance_context_hash: str | None = None,\n    ):\n'''
if runtime.count(old_init) != 1:
    raise SystemExit("mesh_runtime.py: init signature not found")
runtime = runtime.replace(old_init, new_init, 1)
old_attr = '''        self.providers = providers\n        self.worker_id = worker_id\n'''
new_attr = '''        self.providers = providers\n        self.worker_id = worker_id\n        self.performance_context_hash = performance_context_hash\n'''
if runtime.count(old_attr) != 1:
    raise SystemExit("mesh_runtime.py: init attrs not found")
runtime = runtime.replace(old_attr, new_attr, 1)
old_record = '''            cost=candidate.cost_index,\n            catalog_hash=sha256_json(self.router.catalog),\n        )\n'''
new_record = '''            cost=candidate.cost_index,\n            catalog_hash=sha256_json(self.router.catalog),\n            benchmark_suite_hash=self.performance_context_hash,\n        )\n'''
if runtime.count(old_record) != 1:
    raise SystemExit("mesh_runtime.py: performance record block not found")
runtime = runtime.replace(old_record, new_record, 1)

insert_anchor = '''    def _candidate(self, registry_id: str):\n        return next((item for item in self.router.candidates if item.registry_id == registry_id), None)\n\n'''
phase_methods = r'''    def _candidate(self, registry_id: str):
        return next((item for item in self.router.candidates if item.registry_id == registry_id), None)

    @staticmethod
    def _continuity_target_for_role(role: str) -> str | None:
        if role in {"repository_indexer", "context_scout", "architecture_advisor", "plan_adjudicator", "test_designer"}:
            return "PLANNING"
        if role in {"worker", "repairer", "supervisor_takeover", "patch_integrator"}:
            return "WORKER_IMPLEMENTING"
        if role == "check_runner":
            return "MACHINE_CHECKS"
        if role in {"supervisor", "focused_reviewer", "security_reviewer", "data_reviewer", "closure", "release_advisor"}:
            return "SUPERVISOR_REVIEW"
        return None

    def _sync_continuity_phase(self, node: dict[str, Any]) -> str:
        target = self._continuity_target_for_role(str(node["role"]))
        task = self.continuity_store.get_task(node["task_id"])
        if target is None:
            return str(task["state"])
        order = ["READY", "PLANNING", "WORKER_IMPLEMENTING", "MACHINE_CHECKS", "SUPERVISOR_REVIEW"]
        if task["state"] not in order or order.index(task["state"]) >= order.index(target):
            return str(task["state"])
        for _ in range(6):
            task = self.continuity_store.get_task(node["task_id"])
            current = str(task["state"])
            if current not in order or order.index(current) >= order.index(target):
                return current
            if current == "READY":
                next_state = "PLANNING" if target == "PLANNING" else "WORKER_IMPLEMENTING"
            elif current == "PLANNING":
                next_state = "WORKER_IMPLEMENTING"
            elif current == "WORKER_IMPLEMENTING":
                next_state = "MACHINE_CHECKS"
            elif current == "MACHINE_CHECKS":
                next_state = "SUPERVISOR_REVIEW"
            else:
                return current
            try:
                task = self.continuity_store.transition(
                    node["task_id"], next_state, actor="mesh-runtime",
                    expected_version=int(task["version"]),
                    payload={"mesh_node_id": node["node_id"], "mesh_role": node["role"]},
                    idempotency_key=f"mesh-phase:{node['task_id']}:{current}:{next_state}",
                )
            except RuntimeError:
                continue
        raise RuntimeError("Unable to synchronize Continuity phase after bounded optimistic retries")

    def _transition_parent_control_state(self, node: dict[str, Any], target: str, *, reason: str) -> str:
        task = self.continuity_store.get_task(node["task_id"])
        if str(task["state"]) == target:
            return target
        try:
            updated = self.continuity_store.transition(
                node["task_id"], target, actor="mesh-runtime-controller",
                expected_version=int(task["version"]),
                payload={"mesh_node_id": node["node_id"], "reason": reason},
                idempotency_key=f"mesh-control:{node['task_id']}:{node['node_id']}:{target}:{reason}",
            )
            return str(updated["state"])
        except RuntimeError:
            latest = self.continuity_store.get_task(node["task_id"])
            if str(latest["state"]) == target:
                return target
            raise

'''
if runtime.count(insert_anchor) != 1:
    raise SystemExit("mesh_runtime.py: candidate anchor not found")
runtime = runtime.replace(insert_anchor, phase_methods, 1)

# Replan now transitions the parent to the corresponding control state before child creation.
old_replan_parent = '''        parent = self.continuity_store.get_task(node["task_id"])\n        contract = copy.deepcopy(parent["contract"])\n'''
new_replan_parent = '''        parent = self.continuity_store.get_task(node["task_id"])\n        parent_control_state = "AUTO_REPAIR" if reason == "BLOCKING_FINAL_GUARD_FINDINGS" else "AUTO_REPLAN"\n        self._transition_parent_control_state(node, parent_control_state, reason=reason)\n        parent = self.continuity_store.get_task(node["task_id"])\n        contract = copy.deepcopy(parent["contract"])\n'''
if runtime.count(old_replan_parent) != 1:
    raise SystemExit("mesh_runtime.py: replan parent block not found")
runtime = runtime.replace(old_replan_parent, new_replan_parent, 1)

# High-risk full meshes contain context-expansion requests instead of spawning competing replans.
old_context = '''            target = self._next_risk(str(node["risk"]))\n            if target != str(node["risk"]):\n                replan = {\n'''
new_context = '''            target = self._next_risk(str(node["risk"]))\n            if str(node["risk"]) in {"R0", "R1", "R2"} and target != str(node["risk"]):\n                replan = {\n'''
if runtime.count(old_context) != 1:
    raise SystemExit("mesh_runtime.py: context replan block not found")
runtime = runtime.replace(old_context, new_context, 1)

# Performance overrides are shadowed until the minimum observation count is met and are context-bound.
old_overrides = '''        overrides = self.mesh_store.performance_overrides(\n            node["task_family"], catalog_hash=sha256_json(self.router.catalog)\n        )\n'''
new_overrides = '''        overrides = self.mesh_store.performance_overrides(\n            node["task_family"], catalog_hash=sha256_json(self.router.catalog),\n            benchmark_suite_hash=self.performance_context_hash,\n            minimum_runs=int(self.router.policy.get("minimum_observations_for_override", 1)),\n        )\n'''
if runtime.count(old_overrides) != 1:
    raise SystemExit("mesh_runtime.py: routing overrides block not found")
runtime = runtime.replace(old_overrides, new_overrides, 1)

# Every claimed node first synchronizes the durable Continuity phase. Failure is contained in the node.
old_execute = '''    def _execute(self, node: dict[str, Any]) -> dict[str, Any]:\n        if node["role"] == "repository_indexer":\n'''
new_execute = '''    def _execute(self, node: dict[str, Any]) -> dict[str, Any]:\n        try:\n            continuity_state = self._sync_continuity_phase(node)\n        except Exception as exc:\n            errors = [f"continuity_phase_sync_error:{type(exc).__name__}:{exc}"]\n            failure = self._finish_failure(\n                node, run_id=f"continuity-{uuid.uuid4()}", registry_id="deterministic-continuity-sync",\n                provider="local", errors=errors, force_quarantine=True,\n            )\n            return {\n                "node_id": node["node_id"], "task_id": node["task_id"], "success": False,\n                "state": failure["state"], "route": None, "validation_errors": errors,\n            }\n        if node["role"] == "repository_indexer":\n'''
if runtime.count(old_execute) != 1:
    raise SystemExit("mesh_runtime.py: execute dispatch block not found")
runtime = runtime.replace(old_execute, new_execute, 1)

# If structured output quarantines without creating a replan, Continuity must reflect containment.
old_failure_call = '''                state = self._finish_failure(\n                    node, run_id=result.run_id, registry_id=decision.candidate.registry_id,\n                    provider=decision.candidate.provider, errors=validation_errors,\n                    force_quarantine=bool(control["force_quarantine"]),\n                )\n'''
new_failure_call = '''                state = self._finish_failure(\n                    node, run_id=result.run_id, registry_id=decision.candidate.registry_id,\n                    provider=decision.candidate.provider, errors=validation_errors,\n                    force_quarantine=bool(control["force_quarantine"]),\n                )\n                if bool(control["force_quarantine"]) and replan is None:\n                    self._transition_parent_control_state(\n                        node, "QUARANTINED", reason="STRUCTURED_CONTROL_CONTAINMENT"\n                    )\n'''
if runtime.count(old_failure_call) != 1:
    raise SystemExit("mesh_runtime.py: structured failure block not found")
runtime = runtime.replace(old_failure_call, new_failure_call, 1)
runtime_path.write_text(runtime, encoding="utf-8")

# --- CLI: catalog-prior route preview + provider/suite-bound benchmark cache. ---
cli_path = ROOT / "toolkit/ztad/cli.py"
cli = cli_path.read_text(encoding="utf-8")
helper_anchor = '''def _repo_path(repo: GitRepository, raw: str | Path) -> Path:\n    path = Path(raw)\n    return path if path.is_absolute() else repo.root / path\n\n\n'''
helpers = r'''def _repo_path(repo: GitRepository, raw: str | Path) -> Path:
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


'''
if cli.count(helper_anchor) != 1:
    raise SystemExit("cli.py: helper insertion anchor not found")
cli = cli.replace(helper_anchor, helpers, 1)

# Expose explicit routing controls and catalog on mesh-plan dry-run.
cli = cli.replace(
    '    p.add_argument("--previous-provider")\n',
    '    p.add_argument("--previous-provider")\n    p.add_argument("--preferred-registry-id")\n    p.add_argument("--maximum-reasoning-effort", choices=["none", "low", "medium", "high", "xhigh", "max", "ultra"])\n',
    1,
)
cli = cli.replace(
    '    p.add_argument("--risk-policy", default=str(_root_file("policies/risk-policy.yaml")))\n    p.add_argument("--max-parallel-writers", type=int, default=6)\n',
    '    p.add_argument("--risk-policy", default=str(_root_file("policies/risk-policy.yaml")))\n    p.add_argument("--catalog", default=str(_root_file("policies/model-catalog.yaml")))\n    p.add_argument("--max-parallel-writers", type=int, default=6)\n',
    1,
)
# model-route TaskProfile includes explicit controls.
old_model_profile = '''            prior_failures=args.prior_failures,\n            required_provider_diversity=args.require_provider_diversity,\n        )\n'''
new_model_profile = '''            prior_failures=args.prior_failures,\n            required_provider_diversity=args.require_provider_diversity,\n            preferred_registry_id=args.preferred_registry_id,\n            maximum_reasoning_effort=args.maximum_reasoning_effort,\n        )\n'''
if cli.count(old_model_profile) != 1:
    raise SystemExit("cli.py: model-route profile not found")
cli = cli.replace(old_model_profile, new_model_profile, 1)

# model-benchmark cache metadata and persistence.
old_model_benchmark_registry = '''        router = AdaptiveModelRouter.from_file(Path(args.catalog))\n        result = ModelBenchmarkRunner(router, ProviderRegistry(provider_items)).run(\n            load_benchmark_cases(Path(args.cases)), cwd=Path(args.repo).resolve(),\n            registry_ids=args.registry_id, timeout_seconds=args.timeout_seconds,\n        )\n'''
new_model_benchmark_registry = '''        router = AdaptiveModelRouter.from_file(Path(args.catalog))\n        provider_registry = ProviderRegistry(provider_items)\n        benchmark_cases = load_benchmark_cases(Path(args.cases))\n        cache_metadata = _benchmark_cache_metadata(benchmark_cases, provider_registry)\n        result = ModelBenchmarkRunner(router, provider_registry).run(\n            benchmark_cases, cwd=Path(args.repo).resolve(),\n            registry_ids=args.registry_id, timeout_seconds=args.timeout_seconds,\n        )\n        result.update(cache_metadata)\n'''
if cli.count(old_model_benchmark_registry) != 1:
    raise SystemExit("cli.py: model-benchmark execution block not found")
cli = cli.replace(old_model_benchmark_registry, new_model_benchmark_registry, 1)
cli = cli.replace(
    '                        catalog_hash=result["catalog_hash"], benchmark_suite_hash=result["benchmark_suite_hash"],\n',
    '                        catalog_hash=result["catalog_hash"], benchmark_suite_hash=result["benchmark_cache_hash"],\n',
    1,
)

# mesh-plan dry-run now gives actual catalog route decisions without provider execution.
old_mesh_plan_dry = '''        payload = mesh_plan.to_dict()\n        if args.dry_run:\n            return {"dry_run": True, "repository_mutated": False, "plan": payload}, 0\n'''
new_mesh_plan_dry = '''        payload = mesh_plan.to_dict()\n        if args.dry_run:\n            router = AdaptiveModelRouter.from_file(Path(args.catalog))\n            return {\n                "dry_run": True, "repository_mutated": False, "plan": payload,\n                "route_preview": _route_preview(mesh_plan, router),\n            }, 0\n'''
if cli.count(old_mesh_plan_dry) != 1:
    raise SystemExit("cli.py: mesh-plan dry-run block not found")
cli = cli.replace(old_mesh_plan_dry, new_mesh_plan_dry, 1)

# autopilot dry-run also includes route preview.
old_auto_dry = '''        if args.dry_run:\n            result = preparation.to_dict(include_plan=True)\n            result.update({"dry_run": True, "repository_mutated": False, "database_mutated": False})\n            return result, 0\n'''
new_auto_dry = '''        if args.dry_run:\n            router = AdaptiveModelRouter.from_file(Path(args.catalog))\n            result = preparation.to_dict(include_plan=True)\n            result.update({\n                "dry_run": True, "repository_mutated": False, "database_mutated": False,\n                "route_preview": _route_preview(preparation.plan, router),\n            })\n            return result, 0\n'''
if cli.count(old_auto_dry) != 1:
    raise SystemExit("cli.py: autopilot dry-run block not found")
cli = cli.replace(old_auto_dry, new_auto_dry, 1)

# Both live execution paths use suite+provider fingerprint cache, minimum trials, and runtime context binding.
old_auto_benchmark = '''        benchmark_result = None\n        if args.auto_benchmark:\n            cases = load_benchmark_cases(Path(args.benchmark_cases))\n            catalog_hash = sha256_json(router.catalog)\n            suite_hash = benchmark_suite_hash(cases)\n'''
new_auto_benchmark = '''        benchmark_result = None\n        cases = load_benchmark_cases(Path(args.benchmark_cases))\n        cache_metadata = _benchmark_cache_metadata(cases, provider_registry)\n        catalog_hash = sha256_json(router.catalog)\n        benchmark_cache_hash = cache_metadata["benchmark_cache_hash"]\n        if args.auto_benchmark:\n'''
if cli.count(old_auto_benchmark) != 2:
    raise SystemExit(f"cli.py: expected two auto-benchmark blocks, found {cli.count(old_auto_benchmark)}")
cli = cli.replace(old_auto_benchmark, new_auto_benchmark)
cli = cli.replace(
    '''                if not mesh_store.performance_overrides(\n                    family, catalog_hash=catalog_hash, benchmark_suite_hash=suite_hash\n                )\n''',
    '''                if not mesh_store.performance_overrides(\n                    family, catalog_hash=catalog_hash, benchmark_suite_hash=benchmark_cache_hash,\n                    minimum_runs=int(router.policy.get("minimum_observations_for_override", 1)),\n                )\n''',
)
# Persist benchmark results under the full cache hash, not raw suite hash.
cli = cli.replace(
    '                            benchmark_suite_hash=benchmark_result["benchmark_suite_hash"],\n',
    '                            benchmark_suite_hash=benchmark_cache_hash,\n',
)
# Attach cache metadata to benchmark reports.
cli = cli.replace(
    '                for model in benchmark_result["results"]:\n',
    '                benchmark_result.update(cache_metadata)\n                for model in benchmark_result["results"]:\n',
    2,
)
# Runtime gets context binding in autopilot + generic mesh execution.
cli = cli.replace(
    '''            router=router, providers=provider_registry, worker_id=args.worker_id,\n            global_parallel_cap=args.max_nodes,\n        )\n''',
    '''            router=router, providers=provider_registry, worker_id=args.worker_id,\n            global_parallel_cap=args.max_nodes, performance_context_hash=benchmark_cache_hash,\n        )\n''',
    1,
)
cli = cli.replace(
    '''            router=router, providers=provider_registry, worker_id=args.worker_id,\n            global_parallel_cap=args.max_nodes,\n        )\n''',
    '''            router=router, providers=provider_registry, worker_id=args.worker_id,\n            global_parallel_cap=args.max_nodes, performance_context_hash=benchmark_cache_hash,\n        )\n''',
    1,
)
cli_path.write_text(cli, encoding="utf-8")

# --- Policy wiring claim becomes precise rather than claiming every budget YAML key drives runtime. ---
replace_once(
    "toolkit/ztad/policy_registry.py",
    '    "budget-policy.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.budget", "ztad.cli"), "Model-call and cost budgets are evaluated locally."),\n',
    '    "budget-policy.yaml": PolicySpec("DETERMINISTIC_RUNTIME", ("ztad.budget", "ztad.cli", "ztad.mesh_plan"), "Contract budgets deterministically bound low/medium implementation, repair, and review topology; standalone policy defaults are evaluated by the CLI and cannot suppress mandatory high-risk safety gates."),\n',
)

# --- Phase-3 regressions. ---
test_path = ROOT / "tests/test_v43_final_hardening.py"
test_path.write_text(r'''from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import init_git_repo, valid_contract
from ztad.cli import (
    _benchmark_cache_metadata,
    _provider_capability_fingerprint,
    build_parser,
    execute,
)
from ztad.mesh_plan import build_mesh_plan
from ztad.mesh_runtime import MeshRuntime
from ztad.mesh_store import MeshNodeSpec, MeshStore
from ztad.model_router import AdaptiveModelRouter
from ztad.orchestrator import ContinuityStore
from ztad.providers import MockProvider, ProviderRegistry

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/agent-result.schema.json"
CATALOG = ROOT / "policies/model-catalog.yaml"


def test_performance_override_is_shadowed_until_two_observations(tmp_path):
    store = MeshStore(tmp_path / "mesh.db")
    kwargs = dict(
        registry_id="codex-luna", task_family="implementation", success=True,
        quality=1.0, latency=0.35, cost=0.25, catalog_hash="sha256:catalog",
        benchmark_suite_hash="sha256:context",
    )
    store.record_model_performance(**kwargs)
    assert store.performance_overrides(
        "implementation", catalog_hash="sha256:catalog", benchmark_suite_hash="sha256:context", minimum_runs=2
    ) == {}
    store.record_model_performance(**kwargs)
    current = store.performance_overrides(
        "implementation", catalog_hash="sha256:catalog", benchmark_suite_hash="sha256:context", minimum_runs=2
    )
    assert current["codex-luna"]["runs"] == 2.0


def test_provider_fingerprint_and_benchmark_cache_are_deterministic_and_provider_bound():
    one = ProviderRegistry([MockProvider(name="mock-a")])
    two = ProviderRegistry([MockProvider(name="mock-b")])
    assert _provider_capability_fingerprint(one) == _provider_capability_fingerprint(one)
    assert _provider_capability_fingerprint(one) != _provider_capability_fingerprint(two)
    cases = []
    first = _benchmark_cache_metadata(cases, one)
    second = _benchmark_cache_metadata(cases, two)
    assert first["benchmark_suite_hash"] == second["benchmark_suite_hash"]
    assert first["provider_executable_fingerprint"] != second["provider_executable_fingerprint"]
    assert first["benchmark_cache_hash"] != second["benchmark_cache_hash"]


def test_fast_path_rejects_contract_that_forbids_all_implementation_runs():
    contract = valid_contract(risk="R0")
    contract["budget"]["max_implementation_runs"] = 0
    with pytest.raises(ValueError, match="at least one implementation run"):
        build_mesh_plan(task_id="budget-r0", risk="R0", contract=contract)


def test_default_writer_cap_does_not_exceed_mesh_policy():
    import inspect
    import yaml
    from ztad import autopilot, mesh_plan

    policy = yaml.safe_load((ROOT / "policies/mesh-policy.yaml").read_text())
    cap = int(policy["parallelism"]["write_cap"])
    assert inspect.signature(mesh_plan.build_mesh_plan).parameters["maximum_parallel_writers"].default <= cap
    assert inspect.signature(autopilot.prepare_autopilot).parameters["maximum_parallel_writers"].default <= cap
    parser = build_parser()
    args = parser.parse_args(["mesh-plan", "--task-id", "x", "--risk", "R0", "--contract", "x.json"])
    assert args.max_parallel_writers <= cap


def test_continuity_phase_tracks_mesh_without_auto_granting_merge_ready(tmp_path):
    repo, _ = init_git_repo(tmp_path / "repo")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    contract = valid_contract(risk="R0", components=["README.md"])
    continuity.submit_task(repository=str(repo), title="phase", contract=contract, risk="R0", task_id="task", idempotency_key="task")
    mesh = MeshStore(tmp_path / "mesh.db")
    runtime = MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter.from_file(CATALOG), providers=ProviderRegistry([]),
        worker_id="phase-test", output_root=tmp_path / "runs",
    )
    base = dict(task_id="task", risk="R0", metadata={})
    sequence = [
        ("index", "repository_indexer", "PLANNING"),
        ("worker", "worker", "WORKER_IMPLEMENTING"),
        ("check", "check_runner", "MACHINE_CHECKS"),
        ("guard", "supervisor", "SUPERVISOR_REVIEW"),
    ]
    for node_id, role, expected in sequence:
        node = {**base, "node_id": node_id, "role": role}
        assert runtime._sync_continuity_phase(node) == expected
        assert continuity.get_task("task")["state"] == expected
    assert continuity.get_task("task")["state"] != "MERGE_READY"


def test_mesh_plan_dry_run_shows_exact_low_risk_catalog_routes_without_mutation(tmp_path):
    repo, _ = init_git_repo(tmp_path / "repo")
    contract = valid_contract(risk="R0", components=["README.md"])
    contract_path = repo / "contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    before = sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*"))
    args = build_parser().parse_args([
        "mesh-plan", "--repo", str(repo), "--task-id", "DRY-R0", "--risk", "R0",
        "--contract", str(contract_path), "--catalog", str(CATALOG), "--dry-run",
    ])
    result, code = execute(args)
    after = sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*"))
    assert code == 0
    assert result["repository_mutated"] is False
    assert result["route_preview"]["model_call_count"] == 2
    selected = [(item["role"], item["selected"]["registry_id"], item["selected"]["reasoning_effort"]) for item in result["route_preview"]["nodes"]]
    assert selected[0][0:2] == ("worker", "codex-luna")
    assert selected[1][0:2] == ("supervisor", "codex-sol")
    assert selected[1][2] in {"medium", "high"}
    assert before == after


def test_model_catalog_requires_two_observations_before_override_and_sol_cap_is_high():
    router = AdaptiveModelRouter.from_file(CATALOG)
    assert int(router.policy["minimum_observations_for_override"]) == 2
    assert router.policy["maximum_reasoning_effort_by_registry"]["codex-sol"] == "high"
''', encoding="utf-8")
