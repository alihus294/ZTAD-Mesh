from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}: {old[:120]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8")


# Strict context binding: legacy/unbound performance rows never mix with a new catalog/cache context.
replace_once(
    "toolkit/ztad/mesh_store.py",
    '''            if existing and catalog_hash and existing["catalog_hash"] not in {None, catalog_hash}:\n                conn.execute("DELETE FROM model_performance WHERE registry_id=? AND task_family=?", (registry_id, task_family))\n                existing = None\n            if existing and benchmark_suite_hash and existing["benchmark_suite_hash"] not in {None, benchmark_suite_hash}:\n                conn.execute("DELETE FROM model_performance WHERE registry_id=? AND task_family=?", (registry_id, task_family))\n''',
    '''            if existing and catalog_hash is not None and existing["catalog_hash"] != catalog_hash:\n                conn.execute("DELETE FROM model_performance WHERE registry_id=? AND task_family=?", (registry_id, task_family))\n                existing = None\n            if existing and benchmark_suite_hash is not None and existing["benchmark_suite_hash"] != benchmark_suite_hash:\n                conn.execute("DELETE FROM model_performance WHERE registry_id=? AND task_family=?", (registry_id, task_family))\n                existing = None\n''',
)
replace_once(
    "toolkit/ztad/mesh_store.py",
    '''                if catalog_hash and row["catalog_hash"] not in {None, catalog_hash}:\n                    continue\n                if benchmark_suite_hash and row["benchmark_suite_hash"] not in {None, benchmark_suite_hash}:\n                    continue\n''',
    '''                if catalog_hash is not None and row["catalog_hash"] != catalog_hash:\n                    continue\n                if benchmark_suite_hash is not None and row["benchmark_suite_hash"] != benchmark_suite_hash:\n                    continue\n''',
)

# Exhausted repair budget contains the parent instead of transitioning to AUTO_REPAIR without a child.
runtime_path = ROOT / "toolkit/ztad/mesh_runtime.py"
runtime = runtime_path.read_text(encoding="utf-8")
old = '''        self._sync_continuity_phase(node)\n        parent = self.continuity_store.get_task(node["task_id"])\n        parent_control_state = "AUTO_REPAIR" if reason == "BLOCKING_FINAL_GUARD_FINDINGS" else "AUTO_REPLAN"\n        self._transition_parent_control_state(node, parent_control_state, reason=reason)\n        parent = self.continuity_store.get_task(node["task_id"])\n        contract = copy.deepcopy(parent["contract"])\n        budget = contract.setdefault("budget", {})\n        remaining_repairs = int(budget.get("max_repair_cycles", 0))\n        if consume_repair_cycle:\n            if remaining_repairs <= 0:\n                return None\n            budget["max_repair_cycles"] = remaining_repairs - 1\n'''
new = '''        self._sync_continuity_phase(node)\n        parent = self.continuity_store.get_task(node["task_id"])\n        contract = copy.deepcopy(parent["contract"])\n        budget = contract.setdefault("budget", {})\n        remaining_repairs = int(budget.get("max_repair_cycles", 0))\n        if consume_repair_cycle and remaining_repairs <= 0:\n            self._transition_parent_control_state(\n                node, "QUARANTINED", reason="REPAIR_BUDGET_EXHAUSTED"\n            )\n            return None\n        if consume_repair_cycle:\n            budget["max_repair_cycles"] = remaining_repairs - 1\n        parent_control_state = "AUTO_REPAIR" if reason == "BLOCKING_FINAL_GUARD_FINDINGS" else "AUTO_REPLAN"\n        self._transition_parent_control_state(node, parent_control_state, reason=reason)\n'''
if runtime.count(old) != 1:
    raise SystemExit("mesh_runtime.py: could not locate repair-budget replan block")
runtime_path.write_text(runtime.replace(old, new), encoding="utf-8")

# Final regressions: strict performance context, repair exhaustion, generic CLI shadowing guard, and real R0 E2E.
test_path = ROOT / "tests/test_v43_last_gaps.py"
test_path.write_text(r'''from __future__ import annotations

import ast
import json
import sqlite3
import subprocess
import symtable
from pathlib import Path

import pytest

from conftest import init_git_repo, valid_contract
from ztad.mesh_plan import build_mesh_plan, write_mesh_plan
from ztad.mesh_runtime import MeshRuntime
from ztad.mesh_store import MeshStore
from ztad.model_router import AdaptiveModelRouter
from ztad.orchestrator import ContinuityStore
from ztad.providers import ProviderRegistry, ProviderRunRequest, ProviderRunResult
from ztad.util import canonical_json, sha256_bytes, utc_now

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/agent-result.schema.json"
CATALOG = ROOT / "policies/model-catalog.yaml"
CLI_SOURCE = ROOT / "toolkit/ztad/cli.py"


def test_context_bound_performance_never_mixes_legacy_rows(tmp_path):
    store = MeshStore(tmp_path / "mesh.db")
    base = dict(
        registry_id="codex-luna", task_family="implementation", success=True,
        latency=0.35, cost=0.25,
    )
    store.record_model_performance(**base, quality=0.2)
    assert store.performance_overrides(
        "implementation", catalog_hash="sha256:new-catalog",
        benchmark_suite_hash="sha256:new-context",
    ) == {}
    store.record_model_performance(
        **base, quality=1.0, catalog_hash="sha256:new-catalog",
        benchmark_suite_hash="sha256:new-context",
    )
    current = store.performance_overrides(
        "implementation", catalog_hash="sha256:new-catalog",
        benchmark_suite_hash="sha256:new-context",
    )
    assert current["codex-luna"]["runs"] == 1.0
    assert current["codex-luna"]["quality"] == pytest.approx(1.0)


def test_exhausted_repair_budget_quarantines_parent_without_orphan_auto_repair(tmp_path):
    repo, _ = init_git_repo(tmp_path / "repo")
    contract = valid_contract(risk="R0", components=["README.md"])
    contract["budget"]["max_repair_cycles"] = 0
    continuity_db = tmp_path / "continuity.db"
    continuity = ContinuityStore(continuity_db)
    continuity.submit_task(
        repository=str(repo), title="exhausted", contract=contract, risk="R0",
        task_id="parent", idempotency_key="parent",
    )
    runtime = MeshRuntime(
        repository=repo, mesh_store=MeshStore(tmp_path / "mesh.db"),
        continuity_store=continuity, router=AdaptiveModelRouter.from_file(CATALOG),
        providers=ProviderRegistry([]), worker_id="test", output_root=tmp_path / "runs",
    )
    node = {
        "task_id": "parent", "node_id": "guard", "role": "supervisor", "risk": "R0",
        "output_schema": str(SCHEMA), "metadata": {"mandatory_final_guard": True},
    }
    result = runtime._submit_replan(
        node=node, target_risk="R0", reason="BLOCKING_FINAL_GUARD_FINDINGS",
        details={"finding": "P1"}, consume_repair_cycle=True,
    )
    assert result is None
    assert continuity.get_task("parent")["state"] == "QUARANTINED"
    with sqlite3.connect(continuity_db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1


def test_cli_execute_cannot_shadow_any_module_import_it_references():
    source = CLI_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            imported.update(alias.asname or alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.update(alias.asname or alias.name for alias in node.names if alias.name != "*")
    table = symtable.symtable(source, str(CLI_SOURCE), "exec")
    execute_table = next(child for child in table.get_children() if child.get_name() == "execute")
    collisions = []
    identifiers = set(execute_table.get_identifiers())
    for name in sorted(imported & identifiers):
        symbol = execute_table.lookup(name)
        if symbol.is_local() and symbol.is_referenced():
            collisions.append(name)
    assert collisions == [], f"execute() shadows referenced module imports: {collisions}"


def _structured_output(request: ProviderRunRequest) -> dict:
    envelope = ast.literal_eval(request.prompt.split("ZTAD_IMMUTABLE_ENVELOPE\n", 1)[1].splitlines()[0])
    role = envelope["agent_role"]
    if role == "implementer":
        result_type, action = "IMPLEMENTATION_PROPOSAL", "VALIDATE_PATCH"
    else:
        result_type, action = "NO_BLOCKING_FINDINGS_IN_REVIEWED_SCOPE", "CONTINUE_POLICY_EVALUATION"
    return {
        "schema_version": 1,
        "task_id": request.task_id,
        "agent_role": role,
        "model_registry_id": request.registry_id,
        "prompt_version": envelope["prompt_version"],
        "base_sha": envelope["base_sha"],
        "head_sha": envelope["head_sha"],
        "context_id": envelope["context_id"],
        "result_type": result_type,
        "claims": [], "findings": [], "files_read": [], "files_not_read": [],
        "uncertainties": [], "tested_scope": [], "untested_scope": [], "known_unknowns": [],
        "requested_action": action, "risk_escalation": None, "patch_path": None,
    }


class _FastPathProvider:
    name = "codex"

    def __init__(self):
        self.calls: list[tuple[str, str, str, str]] = []
        self.counter = 0

    def probe(self):
        return {"available": True, "provider": self.name, "executable": "fake-codex", "version": "test"}

    def run(self, request: ProviderRunRequest) -> ProviderRunResult:
        self.counter += 1
        self.calls.append((request.registry_id, request.model, request.reasoning_effort, request.role))
        if request.registry_id == "codex-luna":
            target = request.cwd / "src/component.py"
            target.write_text("VALUE = 2\n", encoding="utf-8")
        output = _structured_output(request)
        now = utc_now()
        return ProviderRunResult(
            run_id=f"fast-{self.counter}", provider=self.name, task_id=request.task_id,
            role=request.role, registry_id=request.registry_id, model=request.model,
            session_id=f"session-{self.counter}", started_at=now, completed_at=now,
            exit_code=0, success=True, output=output,
            output_hash=sha256_bytes(canonical_json(output)), stdout_hash=sha256_bytes(b""),
            stderr_hash=sha256_bytes(b""), input_tokens=10, output_tokens=10,
            errors=(), argv=("fake-codex",),
        )


def test_real_r0_fast_path_executes_only_luna_then_sol_and_stops_before_merge_ready(tmp_path):
    repo, _ = init_git_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    (repo / "src/component.py").write_text("VALUE = 1\n", encoding="utf-8")
    config = repo / ".delivery/ztad/config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({
        "schema_version": 1, "configured": True, "environment_allowlist": [],
        "checks": [{
            "id": "diff-check", "argv": ["git", "diff", "--check", "HEAD^", "HEAD"],
            "cwd": ".", "timeout_seconds": 60,
            "evidence_type": "LOCAL_DIFF_CHECK", "fail_fast": True,
        }],
    }), encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "r0-base"], cwd=repo, check=True, capture_output=True)

    contract = valid_contract(risk="R0", components=["src/component.py"])
    contract["quality_attributes"]["security"] = ""
    task_id = "r0-e2e"
    plan = build_mesh_plan(
        task_id=task_id, risk="R0", contract=contract,
        prompt_root=f".delivery/ztad/tasks/{task_id}/prompts",
        output_schema=str(SCHEMA), check_config=".delivery/ztad/config.json",
        command_policy=str(ROOT / "policies/command-policy.yaml"),
        risk_policy=str(ROOT / "policies/risk-policy.yaml"),
    )
    write_mesh_plan(plan, repository=repo, output_file=repo / f".delivery/ztad/tasks/{task_id}/mesh-plan.json")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    continuity.submit_task(
        repository=str(repo), title="R0 E2E", contract=contract, risk="R0",
        task_id=task_id, idempotency_key=task_id,
    )
    mesh = MeshStore(tmp_path / "mesh.db")
    mesh.submit_graph(plan.nodes)
    provider = _FastPathProvider()
    runtime = MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter.from_file(CATALOG), providers=ProviderRegistry([provider]),
        worker_id="r0-worker", output_root=tmp_path / "runs",
    )
    report = runtime.run_until_idle(maximum_ticks=20, maximum_seconds=60)
    nodes = mesh.list_nodes(task_id=task_id)
    assert len(nodes) == 5
    assert all(node["state"] == "SUCCEEDED" for node in nodes), [(n["node_id"], n["state"], n["last_error"]) for n in nodes]
    assert [call[0] for call in provider.calls] == ["codex-luna", "codex-sol"]
    assert provider.calls[0][3] == "worker"
    assert provider.calls[1][3] == "supervisor"
    assert provider.calls[1][2] in {"medium", "high"}
    assert provider.calls[1][2] not in {"xhigh", "max", "ultra"}
    assert continuity.get_task(task_id)["state"] == "SUPERVISOR_REVIEW"
    assert report["mesh_status"]["states"].get("SUCCEEDED") == 5
''', encoding="utf-8")
