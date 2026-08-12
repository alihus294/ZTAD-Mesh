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


# Router retry fallback must preserve explicit model preference/reasoning caps.
replace_once(
    "toolkit/ztad/mesh_runtime.py",
    "from __future__ import annotations\n\nimport concurrent.futures\n",
    "from __future__ import annotations\n\nimport concurrent.futures\nimport copy\n",
)
replace_once(
    "toolkit/ztad/mesh_runtime.py",
    "from .mesh_store import MeshStore\n",
    "from .mesh_plan import build_mesh_plan, write_mesh_plan\nfrom .mesh_store import MeshStore\n",
)
replace_once(
    "toolkit/ztad/mesh_runtime.py",
    "            required_provider_diversity=False, preferred_provider=metadata.get(\"preferred_provider\"),\n            excluded_models=tuple(metadata.get(\"excluded_models\", [])),\n",
    "            required_provider_diversity=False, preferred_provider=metadata.get(\"preferred_provider\"),\n            preferred_registry_id=metadata.get(\"preferred_registry_id\"),\n            maximum_reasoning_effort=metadata.get(\"maximum_reasoning_effort\"),\n            excluded_models=tuple(metadata.get(\"excluded_models\", [])),\n",
)

runtime_path = ROOT / "toolkit/ztad/mesh_runtime.py"
runtime = runtime_path.read_text(encoding="utf-8")
anchor = "        self.worktrees = WorktreeManager(self.repo)\n\n    def _profile(self, node: dict[str, Any]) -> TaskProfile:\n"
methods = r'''        self.worktrees = WorktreeManager(self.repo)

    @staticmethod
    def _next_risk(risk: str) -> str:
        order = ["R0", "R1", "R2", "R3", "R4"]
        index = order.index(risk)
        return order[min(len(order) - 1, index + 1)]

    def _candidate(self, registry_id: str):
        return next((item for item in self.router.candidates if item.registry_id == registry_id), None)

    def _record_performance(
        self, *, registry_id: str, task_family: str, success: bool, quality: float
    ) -> None:
        candidate = self._candidate(registry_id)
        if candidate is None:
            return
        self.mesh_store.record_model_performance(
            registry_id=registry_id,
            task_family=task_family,
            success=success,
            quality=max(0.0, min(1.0, float(quality))),
            latency=candidate.latency_index,
            cost=candidate.cost_index,
            catalog_hash=sha256_json(self.router.catalog),
        )

    @staticmethod
    def _candidate_prior_quality(decision: RouteDecision, task_family: str) -> float:
        return float(
            decision.candidate.task_quality.get(
                task_family, decision.candidate.task_quality.get("default", 0.0)
            )
        )

    @staticmethod
    def _is_capability_abstention(output: dict[str, Any]) -> bool:
        return str(output.get("result_type")) in {
            "INSUFFICIENT_CONTEXT", "INSUFFICIENT_EVIDENCE", "WAITING_EXTERNAL_DEPENDENCY",
            "AUTO_REPLAN", "QUARANTINE_AND_CONTINUE",
        }

    def _submit_replan(
        self,
        *,
        node: dict[str, Any],
        target_risk: str,
        reason: str,
        details: dict[str, Any],
        consume_repair_cycle: bool,
    ) -> dict[str, Any] | None:
        current_risk = str(node["risk"])
        if target_risk not in RISK_ORDER or RISK_ORDER[target_risk] < RISK_ORDER[current_risk]:
            raise ValueError("Replan target risk may not downgrade the current risk")
        parent = self.continuity_store.get_task(node["task_id"])
        contract = copy.deepcopy(parent["contract"])
        budget = contract.setdefault("budget", {})
        remaining_repairs = int(budget.get("max_repair_cycles", 0))
        if consume_repair_cycle:
            if remaining_repairs <= 0:
                return None
            budget["max_repair_cycles"] = remaining_repairs - 1
        governance = contract.setdefault("governance", {})
        governance["policy_risk"] = target_risk
        decisions = governance.setdefault("human_decisions", [])
        decision_record = {
            "type": "ZTAD_AUTOMATED_REPLAN",
            "source_task_id": node["task_id"],
            "source_node_id": node["node_id"],
            "reason": reason,
            "from_risk": current_risk,
            "to_risk": target_risk,
            "details": details,
        }
        decisions.append(decision_record)
        material = {
            "source_task_id": node["task_id"],
            "source_node_id": node["node_id"],
            "reason": reason,
            "target_risk": target_risk,
            "details": details,
            "remaining_repairs": budget.get("max_repair_cycles"),
        }
        digest = sha256_json(material).removeprefix("sha256:")[:16]
        child_task_id = f"replan-{target_risk.casefold()}-{digest}"
        prompt_root = f".delivery/ztad/tasks/{child_task_id}/prompts"
        plan_output = f".delivery/ztad/tasks/{child_task_id}/mesh-plan.json"
        metadata = node.get("metadata") or {}
        child_plan = build_mesh_plan(
            task_id=child_task_id,
            risk=target_risk,
            contract=contract,
            prompt_root=prompt_root,
            output_schema=node["output_schema"],
            check_config=str(metadata.get("check_config", ".delivery/ztad/config.json")),
            command_policy=str(metadata.get("command_policy", "policies/command-policy.yaml")),
            risk_policy=str(metadata.get("risk_policy", "policies/risk-policy.yaml")),
        )
        plan_written = write_mesh_plan(
            child_plan, repository=self.repo.root, output_file=Path(plan_output)
        )
        child = self.continuity_store.submit_task(
            repository=str(self.repo.root),
            title=f"Replan: {parent['title']}",
            contract=contract,
            risk=target_risk,
            priority=int(parent.get("priority", 0)),
            idempotency_key=sha256_json({"ztad_replan": material}),
            task_id=child_task_id,
        )
        submitted = self.mesh_store.submit_graph(child_plan.nodes)
        return {
            "created": not bool(child.get("idempotent_replay")),
            "child_task_id": child_task_id,
            "risk": target_risk,
            "reason": reason,
            "plan_id": child_plan.plan_id,
            "execution_mode": child_plan.to_dict()["execution_mode"],
            "model_call_count": child_plan.to_dict()["model_call_count"],
            "submitted_nodes": len(submitted),
            "plan_written": plan_written,
        }

    def _structured_control(self, node: dict[str, Any], output: dict[str, Any]) -> dict[str, Any]:
        action = str(output.get("requested_action") or "")
        result_type = str(output.get("result_type") or "")
        blocking_findings = [
            item for item in (output.get("findings") or [])
            if str(item.get("severity")) in {"P0", "P1"}
            and str(item.get("verification_status", "PROPOSED")) != "FALSIFIED"
        ]
        errors: list[str] = []
        force_quarantine = False
        replan: dict[str, Any] | None = None

        if blocking_findings or action in {"VERIFY_FINDINGS", "REPAIR_CONFIRMED_FINDINGS"}:
            errors.append("structured_control:blocking_findings_require_verification_or_repair")
            force_quarantine = True
            # Automatic low-risk repair is serialized through a child task. Higher-risk
            # multi-review meshes fail closed to avoid spawning competing repair plans.
            if str(node["risk"]) in {"R0", "R1"} and bool((node.get("metadata") or {}).get("mandatory_final_guard")):
                replan = {
                    "target_risk": str(node["risk"]),
                    "reason": "BLOCKING_FINAL_GUARD_FINDINGS",
                    "consume_repair_cycle": True,
                    "details": {
                        "requested_action": action,
                        "findings": [
                            {key: item.get(key) for key in ("finding_id", "severity", "title", "description", "verification_status")}
                            for item in blocking_findings[:20]
                        ],
                    },
                }
        elif action == "REQUEST_CONTEXT_EXPANSION" or result_type == "INSUFFICIENT_CONTEXT":
            errors.append("structured_control:context_expansion_required")
            force_quarantine = True
            target = self._next_risk(str(node["risk"]))
            if target != str(node["risk"]):
                replan = {
                    "target_risk": target,
                    "reason": "CONTEXT_EXPANSION_TO_STRONGER_TOPOLOGY",
                    "consume_repair_cycle": False,
                    "details": {"requested_action": action, "result_type": result_type},
                }
        elif action == "ESCALATE_RISK" or result_type == "RISK_ESCALATION_REQUESTED":
            errors.append("structured_control:risk_escalation_requested")
            force_quarantine = True
            proposed = str((output.get("risk_escalation") or {}).get("proposed_risk") or "")
            current = str(node["risk"])
            target = proposed if proposed in RISK_ORDER and RISK_ORDER[proposed] > RISK_ORDER[current] else self._next_risk(current)
            if target != current:
                replan = {
                    "target_risk": target,
                    "reason": "MODEL_REQUESTED_UPWARD_RISK_ESCALATION",
                    "consume_repair_cycle": False,
                    "details": {"requested_action": action, "risk_escalation": output.get("risk_escalation")},
                }
        elif action == "AUTO_REPLAN" or result_type == "AUTO_REPLAN":
            errors.append("structured_control:auto_replan_requested")
            force_quarantine = True
            replan = {
                "target_risk": str(node["risk"]),
                "reason": "MODEL_REQUESTED_BOUNDED_REPLAN",
                "consume_repair_cycle": True,
                "details": {"requested_action": action, "result_type": result_type},
            }
        elif action in {"QUARANTINE_TASK", "REQUEST_STRONG_SUPERVISOR"} or result_type == "QUARANTINE_AND_CONTINUE":
            errors.append(f"structured_control:{action or result_type}")
            force_quarantine = True
            if action == "REQUEST_STRONG_SUPERVISOR" and RISK_ORDER[str(node["risk"])] < RISK_ORDER["R3"]:
                replan = {
                    "target_risk": "R3",
                    "reason": "STRONG_SUPERVISOR_REQUESTED",
                    "consume_repair_cycle": False,
                    "details": {"requested_action": action},
                }
        elif result_type in {"INSUFFICIENT_EVIDENCE", "WAITING_EXTERNAL_DEPENDENCY"}:
            errors.append(f"structured_control:{result_type.casefold()}")
            force_quarantine = True
        return {
            "errors": errors,
            "force_quarantine": force_quarantine,
            "replan": replan,
            "blocking_findings": len(blocking_findings),
        }

    def _profile(self, node: dict[str, Any]) -> TaskProfile:
'''
if runtime.count(anchor) != 1:
    raise SystemExit("mesh_runtime.py: could not locate runtime method insertion anchor")
runtime = runtime.replace(anchor, methods, 1)

# Integrator propagates the exact writer model provenance into the combined patch.
old_integrator_start = '''        try:\n            patches = self._artifact_paths(node["node_id"])\n            if not patches:\n'''
new_integrator_start = '''        try:\n            source_artifacts = self.mesh_store.dependency_artifacts(\n                node["node_id"], artifact_types=("PATCH",), transitive=False\n            )\n            source_models = [\n                {\n                    "registry_id": item["metadata"].get("registry_id"),\n                    "provider": item["metadata"].get("provider"),\n                    "model": item["metadata"].get("model"),\n                    "task_family": item["metadata"].get("task_family", "implementation"),\n                    "node_id": item["node_id"],\n                }\n                for item in source_artifacts if item.get("metadata", {}).get("registry_id")\n            ]\n            patches = self._artifact_paths(node["node_id"])\n            if not patches:\n'''
if runtime.count(old_integrator_start) != 1:
    raise SystemExit("mesh_runtime.py: could not locate integrator start")
runtime = runtime.replace(old_integrator_start, new_integrator_start, 1)
old_integrator_error = '''            if errors:\n                result = self._finish_failure(\n                    node, run_id=run_id, registry_id="deterministic-integrator", provider="local", errors=errors,\n                )\n'''
new_integrator_error = '''            if errors:\n                for source in source_models:\n                    self._record_performance(\n                        registry_id=str(source["registry_id"]), task_family=str(source["task_family"]),\n                        success=False, quality=0.0,\n                    )\n                result = self._finish_failure(\n                    node, run_id=run_id, registry_id="deterministic-integrator", provider="local", errors=errors,\n                )\n'''
if runtime.count(old_integrator_error) != 1:
    raise SystemExit("mesh_runtime.py: could not locate integrator failure block")
runtime = runtime.replace(old_integrator_error, new_integrator_error, 1)
old_combined_meta = 'sha256=sha256_file(output_path), metadata={"source_patches": applied["applied"], "changed_paths": patch["changed_paths"]},\n'
new_combined_meta = 'sha256=sha256_file(output_path), metadata={"source_patches": applied["applied"], "changed_paths": patch["changed_paths"], "source_models": source_models},\n'
if runtime.count(old_combined_meta) != 1:
    raise SystemExit("mesh_runtime.py: could not locate combined patch metadata")
runtime = runtime.replace(old_combined_meta, new_combined_meta, 1)

# Check runner reads propagated writer provenance and records quality only from deterministic outcomes.
old_check_start = '''        try:\n            patches = self._artifact_paths(node["node_id"])\n            if not patches:\n                raise ValueError("machine_checks_have_no_integrated_patch")\n'''
new_check_start = '''        try:\n            combined_artifacts = self.mesh_store.dependency_artifacts(\n                node["node_id"], artifact_types=("COMBINED_PATCH",), transitive=False\n            )\n            source_models = []\n            for item in combined_artifacts:\n                source_models.extend(item.get("metadata", {}).get("source_models", []) or [])\n            patches = self._artifact_paths(node["node_id"])\n            if not patches:\n                raise ValueError("machine_checks_have_no_integrated_patch")\n'''
if runtime.count(old_check_start) != 1:
    raise SystemExit("mesh_runtime.py: could not locate check-runner start")
runtime = runtime.replace(old_check_start, new_check_start, 1)
old_check_artifact = '''            artifact = self.mesh_store.register_artifact(\n                node_id=node["node_id"], artifact_type="CHECK_RESULT", path=str(result_path),\n                sha256=sha256_file(result_path), metadata={"head_sha": candidate_sha, "evidence_refs": registered},\n            )\n            if report.get("blocked") or risk_escalated:\n'''
new_check_artifact = '''            artifact = self.mesh_store.register_artifact(\n                node_id=node["node_id"], artifact_type="CHECK_RESULT", path=str(result_path),\n                sha256=sha256_file(result_path), metadata={"head_sha": candidate_sha, "evidence_refs": registered},\n            )\n            if not risk_escalated:\n                checks_passed = not bool(report.get("blocked"))\n                for source in source_models:\n                    registry_id = source.get("registry_id")\n                    if registry_id:\n                        self._record_performance(\n                            registry_id=str(registry_id),\n                            task_family=str(source.get("task_family") or "implementation"),\n                            success=checks_passed, quality=1.0 if checks_passed else 0.0,\n                        )\n            replan = None\n            if risk_escalated:\n                replan = self._submit_replan(\n                    node=node, target_risk=actual_risk.risk,\n                    reason="ACTUAL_DIFF_RISK_ESCALATION",\n                    details={\n                        "planned_risk": node["risk"],\n                        "actual_risk": actual_risk.to_dict(),\n                        "candidate_sha": candidate_sha,\n                    },\n                    consume_repair_cycle=False,\n                )\n            if report.get("blocked") or risk_escalated:\n'''
if runtime.count(old_check_artifact) != 1:
    raise SystemExit("mesh_runtime.py: could not locate check artifact block")
runtime = runtime.replace(old_check_artifact, new_check_artifact, 1)
runtime = runtime.replace(
    '                    "actual_risk": actual_risk.to_dict(), "risk_escalated": risk_escalated,\n                }\n',
    '                    "actual_risk": actual_risk.to_dict(), "risk_escalated": risk_escalated, "replan": replan,\n                }\n',
    1,
)

# Route-attempt performance: deterministic provider/schema failures are negative; valid
# proposals are not promoted until semantic/deterministic downstream evidence exists.
old_perf = '''                quality = 1.0 if result.success and not errors else max(0.0, 0.5 - 0.05 * len(errors))\n                token_cost = float((result.input_tokens or 0) + (result.output_tokens or 0)) / 100_000.0\n                self.mesh_store.record_model_performance(\n                    registry_id=decision.candidate.registry_id, task_family=node["task_family"],\n                    success=result.success and not errors, quality=quality, latency=latency,\n                    cost=max(0.01, token_cost),\n                )\n'''
new_perf = '''                if not result.success or errors:\n                    self._record_performance(\n                        registry_id=decision.candidate.registry_id, task_family=node["task_family"],\n                        success=False, quality=0.0,\n                    )\n'''
if runtime.count(old_perf) != 1:
    raise SystemExit("mesh_runtime.py: could not locate premature model-performance block")
runtime = runtime.replace(old_perf, new_perf, 1)

# Apply structured controller decisions after patch/scope validation but before the node can succeed.
old_output = '''            output = result.output or {}\n            strategy_hash = str(metadata.get("strategy_hash") or sha256_json({\n'''
new_output = '''            output = result.output or {}\n            control = self._structured_control(node, output)\n            validation_errors.extend(control["errors"])\n            replan = None\n            if control["replan"] is not None:\n                replan_spec = control["replan"]\n                replan = self._submit_replan(\n                    node=node, target_risk=str(replan_spec["target_risk"]),\n                    reason=str(replan_spec["reason"]), details=dict(replan_spec["details"]),\n                    consume_repair_cycle=bool(replan_spec["consume_repair_cycle"]),\n                )\n            strategy_hash = str(metadata.get("strategy_hash") or sha256_json({\n'''
if runtime.count(old_output) != 1:
    raise SystemExit("mesh_runtime.py: could not locate structured-control insertion point")
runtime = runtime.replace(old_output, new_output, 1)

# PATCH artifacts carry writer provenance for downstream deterministic scoring.
old_patch_meta = 'metadata={"changed_paths": changed_paths, "base_sha": base_sha},\n'
new_patch_meta = 'metadata={"changed_paths": changed_paths, "base_sha": base_sha, "registry_id": decision.candidate.registry_id, "provider": decision.candidate.provider, "model": decision.candidate.model, "task_family": node["task_family"], "quality_pending": True},\n'
if runtime.count(old_patch_meta) != 1:
    raise SystemExit("mesh_runtime.py: could not locate PATCH metadata")
runtime = runtime.replace(old_patch_meta, new_patch_meta, 1)

# Final performance/update semantics and fail-closed structured outcomes.
old_success_block = '''            success = result.success and not validation_errors\n            if success:\n                model_result_artifact = self._register_model_result_artifact(node=node, result=result)\n'''
new_success_block = '''            success = result.success and not validation_errors\n            if node["write_access"]:\n                if not success:\n                    quality = 0.25 if self._is_capability_abstention(output) else 0.0\n                    self._record_performance(\n                        registry_id=decision.candidate.registry_id, task_family=node["task_family"],\n                        success=False, quality=quality,\n                    )\n            else:\n                abstained = self._is_capability_abstention(output)\n                self._record_performance(\n                    registry_id=decision.candidate.registry_id, task_family=node["task_family"],\n                    success=not abstained,\n                    quality=0.25 if abstained else self._candidate_prior_quality(decision, node["task_family"]),\n                )\n            if success:\n                model_result_artifact = self._register_model_result_artifact(node=node, result=result)\n'''
if runtime.count(old_success_block) != 1:
    raise SystemExit("mesh_runtime.py: could not locate final success block")
runtime = runtime.replace(old_success_block, new_success_block, 1)
old_finish_failure = '''                state = self._finish_failure(\n                    node, run_id=result.run_id, registry_id=decision.candidate.registry_id,\n                    provider=decision.candidate.provider, errors=validation_errors,\n                )\n'''
new_finish_failure = '''                state = self._finish_failure(\n                    node, run_id=result.run_id, registry_id=decision.candidate.registry_id,\n                    provider=decision.candidate.provider, errors=validation_errors,\n                    force_quarantine=bool(control["force_quarantine"]),\n                )\n'''
if runtime.count(old_finish_failure) != 1:
    raise SystemExit("mesh_runtime.py: could not locate model-node finish failure")
runtime = runtime.replace(old_finish_failure, new_finish_failure, 1)
old_return_tail = '''                "model_result_artifact": model_result_artifact, "attempt": attempt,\n            }\n'''
new_return_tail = '''                "model_result_artifact": model_result_artifact, "attempt": attempt,\n                "structured_control": control, "replan": replan,\n            }\n'''
if runtime.count(old_return_tail) != 1:
    raise SystemExit("mesh_runtime.py: could not locate model-node return tail")
runtime = runtime.replace(old_return_tail, new_return_tail, 1)
runtime_path.write_text(runtime, encoding="utf-8")

# Normalize the remaining automatic-benchmark persistence paths.
cli_path = ROOT / "toolkit/ztad/cli.py"
cli = cli_path.read_text(encoding="utf-8")
raw_metrics = '''                            latency=float(case["latency_seconds"]),\n                            cost=max(0.01, float((case.get("input_tokens") or 0) + (case.get("output_tokens") or 0)) / 100000.0),\n'''
normalized_metrics = '''                            latency=next(item.latency_index for item in router.candidates if item.registry_id == model["registry_id"]),\n                            cost=next(item.cost_index for item in router.candidates if item.registry_id == model["registry_id"]),\n'''
if cli.count(raw_metrics) != 2:
    raise SystemExit(f"cli.py: expected two remaining raw benchmark metric blocks, found {cli.count(raw_metrics)}")
cli = cli.replace(raw_metrics, normalized_metrics)
cli_path.write_text(cli, encoding="utf-8")

# Runtime-control regressions.
test_path = ROOT / "tests/test_v43_runtime_controls.py"
test_path.write_text(r'''from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path

import pytest

from conftest import init_git_repo, valid_contract
from ztad.mesh_runtime import MeshRuntime
from ztad.mesh_store import MeshNodeSpec, MeshStore
from ztad.model_router import AdaptiveModelRouter
from ztad.orchestrator import ContinuityStore
from ztad.providers import ProviderRegistry
from ztad.util import sha256_file

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/agent-result.schema.json"
CATALOG = ROOT / "policies/model-catalog.yaml"


def _runtime(repo: Path, mesh: MeshStore, continuity: ContinuityStore, tmp_path: Path) -> MeshRuntime:
    return MeshRuntime(
        repository=repo, mesh_store=mesh, continuity_store=continuity,
        router=AdaptiveModelRouter.from_file(CATALOG), providers=ProviderRegistry([]),
        worker_id="test-worker", output_root=tmp_path / "outputs",
    )


def _prepare_integrated_patch(tmp_path: Path, *, content: str, risk: str = "R0"):
    repo, _ = init_git_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    (repo / "src/component.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "component"], cwd=repo, check=True, capture_output=True)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    output_root = tmp_path / "outputs"
    output_root.mkdir()
    (repo / "src/component.py").write_text(content, encoding="utf-8")
    patch = output_root / "combined.patch"
    patch.write_bytes(subprocess.check_output(["git", "diff", "--binary", base, "--", "src/component.py"], cwd=repo))
    subprocess.run(["git", "reset", "--hard", base], cwd=repo, check=True, capture_output=True)
    config = repo / ".delivery/ztad/config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({
        "schema_version": 1, "configured": True, "environment_allowlist": [],
        "checks": [{
            "id": "diff-check", "argv": ["git", "diff", "--check", "HEAD^", "HEAD"],
            "cwd": ".", "timeout_seconds": 60, "evidence_type": "LOCAL_DIFF_CHECK", "fail_fast": True,
        }],
    }), encoding="utf-8")
    contract = valid_contract(risk=risk, components=["src/component.py"])
    continuity = ContinuityStore(tmp_path / "continuity.db")
    task = continuity.submit_task(repository=str(repo), title="runtime control", contract=contract, risk=risk, task_id="parent", idempotency_key="parent")
    mesh = MeshStore(tmp_path / "mesh.db")
    mesh.submit_graph([
        MeshNodeSpec.create(
            node_id="integrated", task_id=task["task_id"], title="integrated", task_family="integration",
            role="patch_integrator", risk=risk, write_access=False, scopes=("src/component.py",),
            prompt_path="unused.md", output_schema=str(SCHEMA), priority=100,
        ),
        MeshNodeSpec.create(
            node_id="check", task_id=task["task_id"], title="check", task_family="verification",
            role="check_runner", risk=risk, write_access=False, scopes=("src/component.py",),
            prompt_path="unused.md", output_schema=str(SCHEMA), priority=90, dependencies=("integrated",),
            metadata={
                "base_sha": base, "max_attempts": 1,
                "check_config": ".delivery/ztad/config.json",
                "command_policy": str(ROOT / "policies/command-policy.yaml"),
                "risk_policy": str(ROOT / "policies/risk-policy.yaml"),
            },
        ),
        MeshNodeSpec.create(
            node_id="guard", task_id=task["task_id"], title="guard", task_family="review",
            role="supervisor", risk=risk, write_access=False, scopes=("src/component.py",),
            prompt_path="unused.md", output_schema=str(SCHEMA), priority=80, dependencies=("check",),
        ),
    ])
    claimed = mesh.claim_ready("fixture", limit=1)
    assert claimed[0]["node_id"] == "integrated"
    mesh.finish_node("integrated", owner="fixture", success=True, run_id="fixture", registry_id="deterministic-integrator", provider="local")
    mesh.register_artifact(
        node_id="integrated", artifact_type="COMBINED_PATCH", path=str(patch.resolve()), sha256=sha256_file(patch),
        metadata={
            "source_models": [{
                "registry_id": "codex-luna", "provider": "codex", "model": "gpt-5.6-luna",
                "task_family": "implementation", "node_id": "worker",
            }],
        },
    )
    return repo, base, mesh, continuity


def test_machine_check_failure_scores_writer_from_downstream_evidence(tmp_path):
    repo, _, mesh, continuity = _prepare_integrated_patch(tmp_path, content="VALUE = 2   \n", risk="R0")
    runtime = _runtime(repo, mesh, continuity, tmp_path)
    tick = runtime.run_once(maximum_nodes=1)
    result = tick.results[0]
    assert result["node_id"] == "check"
    assert result["success"] is False
    assert mesh.get_node("guard")["state"] == "READY"
    perf = mesh.performance_overrides("implementation", catalog_hash=runtime.router.catalog_hash if hasattr(runtime.router, "catalog_hash") else None)
    if not perf:
        perf = mesh.performance_overrides("implementation")
    assert perf["codex-luna"]["quality"] == pytest.approx(0.0)
    assert perf["codex-luna"]["reliability"] == pytest.approx(0.0)


def test_machine_check_success_promotes_writer_only_after_checks(tmp_path):
    repo, _, mesh, continuity = _prepare_integrated_patch(tmp_path, content="VALUE = 2\n", risk="R0")
    runtime = _runtime(repo, mesh, continuity, tmp_path)
    tick = runtime.run_once(maximum_nodes=1)
    result = tick.results[0]
    assert result["node_id"] == "check"
    assert result["success"] is True
    perf = mesh.performance_overrides("implementation")
    assert perf["codex-luna"]["quality"] == pytest.approx(1.0)
    assert perf["codex-luna"]["reliability"] == pytest.approx(1.0)


def test_actual_risk_escalation_auto_submits_full_r3_replan_and_blocks_guard(tmp_path, monkeypatch):
    repo, _, mesh, continuity = _prepare_integrated_patch(tmp_path, content="VALUE = 2\n", risk="R0")

    class ForcedRisk:
        risk = "R3"
        def to_dict(self):
            return {"risk": "R3", "reasons": ["forced test escalation"]}

    monkeypatch.setattr("ztad.mesh_runtime.classify_repository_change", lambda *args, **kwargs: ForcedRisk())
    runtime = _runtime(repo, mesh, continuity, tmp_path)
    tick = runtime.run_once(maximum_nodes=1)
    result = tick.results[0]
    assert result["success"] is False
    assert result["state"] == "QUARANTINED"
    assert result["risk_escalated"] is True
    assert result["replan"]["risk"] == "R3"
    assert result["replan"]["execution_mode"] == "FULL_MESH"
    assert mesh.get_node("guard")["state"] == "READY"
    assert mesh.claim_ready("guard-attempt", limit=20) != [mesh.get_node("guard")]
    child_id = result["replan"]["child_task_id"]
    child = continuity.get_task(child_id)
    assert child["risk"] == "R3"
    child_nodes = mesh.list_nodes(task_id=child_id)
    roles = {node["role"] for node in child_nodes}
    assert {"architecture_advisor", "plan_adjudicator", "check_runner", "supervisor", "release_advisor"} <= roles
    sol_cap = runtime.router.policy["maximum_reasoning_effort_by_registry"]["codex-sol"]
    assert sol_cap == "high"


def test_structured_controller_never_allows_p0_p1_to_silently_continue(tmp_path):
    repo, _ = init_git_repo(tmp_path / "repo")
    continuity = ContinuityStore(tmp_path / "continuity.db")
    contract = valid_contract(risk="R0", components=["README.md"])
    task = continuity.submit_task(repository=str(repo), title="finding", contract=contract, risk="R0", task_id="parent", idempotency_key="parent")
    mesh = MeshStore(tmp_path / "mesh.db")
    mesh.submit_graph([MeshNodeSpec.create(
        node_id="guard", task_id=task["task_id"], title="guard", task_family="review", role="supervisor",
        risk="R0", write_access=False, scopes=("README.md",), prompt_path="unused.md", output_schema=str(SCHEMA),
        metadata={"mandatory_final_guard": True},
    )])
    runtime = _runtime(repo, mesh, continuity, tmp_path)
    node = mesh.get_node("guard")
    control = runtime._structured_control(node, {
        "result_type": "PROPOSED_FINDINGS", "requested_action": "VERIFY_FINDINGS",
        "findings": [{"finding_id": "F-001", "severity": "P1", "title": "blocking", "description": "must verify", "verification_status": "PROPOSED"}],
    })
    assert control["force_quarantine"] is True
    assert control["errors"]
    assert control["replan"]["reason"] == "BLOCKING_FINAL_GUARD_FINDINGS"
    replan = runtime._submit_replan(
        node=node, target_risk=control["replan"]["target_risk"], reason=control["replan"]["reason"],
        details=control["replan"]["details"], consume_repair_cycle=True,
    )
    assert replan is not None
    child = continuity.get_task(replan["child_task_id"])
    assert child["contract"]["budget"]["max_repair_cycles"] == contract["budget"]["max_repair_cycles"] - 1
    decisions = child["contract"]["governance"]["human_decisions"]
    assert decisions[-1]["reason"] == "BLOCKING_FINAL_GUARD_FINDINGS"


def test_runtime_source_has_no_premature_schema_valid_quality_one_learning():
    source = (ROOT / "toolkit/ztad/mesh_runtime.py").read_text(encoding="utf-8")
    assert "quality = 1.0 if result.success and not errors" not in source
    assert "latency=latency" not in source
    assert "cost=max(0.01, token_cost)" not in source


def test_all_cli_benchmark_persistence_uses_normalized_indices():
    source = (ROOT / "toolkit/ztad/cli.py").read_text(encoding="utf-8")
    assert 'latency=float(case["latency_seconds"])' not in source
    assert "100000.0" not in source[source.find('if command == "model-benchmark"'):source.find('if command == "provider-probe"')]
''', encoding="utf-8")
