from __future__ import annotations

import concurrent.futures
import copy
import json
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .agent_output import validate_agent_result
from .checks import run_checks
from .loop_guard import AttemptFingerprint, ProgressSnapshot
from .mesh_plan import build_mesh_plan, write_mesh_plan
from .mesh_store import MeshStore
from .model_router import AdaptiveModelRouter, RouteDecision, TaskProfile
from .orchestrator import ContinuityStore
from .providers import ProviderRegistry, ProviderRunRequest, ProviderRunResult
from .repository import GitRepository
from .repository_index import assess_context_sufficiency, build_repository_index
from .risk import RISK_ORDER, classify_repository_change
from .scope_guard import ScopeEnvelope
from .util import hash_directory, load_data, run_command, sha256_bytes, sha256_file, sha256_json, utc_now
from .worktrees import WorktreeManager



def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False

@dataclass(frozen=True)
class RuntimeTick:
    claimed: int
    succeeded: int
    failed: int
    quarantined: int
    results: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "claimed": self.claimed,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "quarantined": self.quarantined,
            "results": list(self.results),
        }


_ARTIFACT_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

_ROLE_TO_AGENT_ROLE = {
    "worker": "implementer",
    "repairer": "repairer",
    "supervisor_takeover": "implementer",
    "supervisor": "independent_reviewer",
    "closure": "independent_reviewer",
    "security_reviewer": "independent_reviewer",
    "data_reviewer": "independent_reviewer",
    "test_designer": "planner",
    "context_scout": "planner",
    "focused_reviewer": "independent_reviewer",
    "architecture_advisor": "architecture_advisor",
    "plan_adjudicator": "architecture_advisor",
    "release_advisor": "release_advisor",
}


class MeshRuntime:
    """Concrete durable mesh runner.

    Model output is always a proposal. This runtime connects DAG claims, adaptive
    routing, isolated worktrees, local schema/subject validation, patch artifacts,
    scope containment, loop detection and durable run registration. It does not
    bypass platform evidence gates for merge or deployment.
    """

    def __init__(
        self,
        *,
        repository: Path,
        mesh_store: MeshStore,
        continuity_store: ContinuityStore,
        router: AdaptiveModelRouter,
        providers: ProviderRegistry,
        worker_id: str,
        output_root: Path | None = None,
        global_parallel_cap: int = 8,
        trusted_control_roots: tuple[Path, ...] | None = None,
        performance_context_hash: str | None = None,
    ):
        self.repo = GitRepository(repository)
        self.mesh_store = mesh_store
        self.continuity_store = continuity_store
        self.router = router
        self.providers = providers
        self.worker_id = worker_id
        self.performance_context_hash = performance_context_hash
        self.output_root = (output_root or self.repo.root / ".delivery" / "ztad" / "mesh-runs").resolve()
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.global_parallel_cap = max(1, global_parallel_cap)
        package_root = Path(__file__).resolve().parents[2]
        roots = trusted_control_roots or (package_root,)
        self.trusted_control_roots = tuple(root.resolve() for root in roots)
        self.worktrees = WorktreeManager(self.repo)

    @staticmethod
    def _next_risk(risk: str) -> str:
        order = ["R0", "R1", "R2", "R3", "R4"]
        index = order.index(risk)
        return order[min(len(order) - 1, index + 1)]

    def _candidate(self, registry_id: str):
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
            benchmark_suite_hash=self.performance_context_hash,
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
        self._sync_continuity_phase(node)
        parent = self.continuity_store.get_task(node["task_id"])
        contract = copy.deepcopy(parent["contract"])
        budget = contract.setdefault("budget", {})
        remaining_repairs = int(budget.get("max_repair_cycles", 0))
        if consume_repair_cycle and remaining_repairs <= 0:
            self._transition_parent_control_state(
                node, "QUARANTINED", reason="REPAIR_BUDGET_EXHAUSTED"
            )
            return None
        if consume_repair_cycle:
            budget["max_repair_cycles"] = remaining_repairs - 1
        parent_control_state = "AUTO_REPAIR" if reason == "BLOCKING_FINAL_GUARD_FINDINGS" else "AUTO_REPLAN"
        self._transition_parent_control_state(node, parent_control_state, reason=reason)
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
            if str(node["risk"]) in {"R0", "R1", "R2"} and target != str(node["risk"]):
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
        metadata = node.get("metadata") or {}
        excluded_models = list(metadata.get("excluded_models", []))
        excluded_providers = list(metadata.get("excluded_providers", []))
        # A retry must change execution resource when an alternative clears the
        # quality gate. If no alternative exists, ranked routing can still fall
        # back to the prior resource after the exclusion is relaxed below.
        if int(node.get("attempts", 0)) > 0 and node.get("selected_registry_id"):
            prior_id = str(node.get("selected_registry_id"))
            prior = next((item for item in self.router.candidates if item.registry_id == prior_id), None)
            if prior is not None:
                excluded_models.append(prior.model)
        return TaskProfile(
            task_family=node["task_family"],
            role=node["role"],
            risk=node["risk"],
            complexity=int(metadata.get("complexity", 1)),
            ambiguity=int(metadata.get("ambiguity", 0)),
            prior_failures=int(node.get("attempts", 0)),
            required_provider_diversity=bool(metadata.get("require_provider_diversity", False)),
            preferred_provider=metadata.get("preferred_provider"),
            preferred_registry_id=metadata.get("preferred_registry_id"),
            maximum_reasoning_effort=metadata.get("maximum_reasoning_effort"),
            excluded_models=tuple(excluded_models),
            excluded_providers=tuple(excluded_providers),
        )

    def _ranked_routes(self, node: dict[str, Any]) -> list[RouteDecision]:
        profile = self._profile(node)
        previous_provider = node.get("selected_provider") or (node.get("metadata") or {}).get("previous_provider")
        overrides = self.mesh_store.performance_overrides(
            node["task_family"], catalog_hash=sha256_json(self.router.catalog),
            benchmark_suite_hash=self.performance_context_hash,
            minimum_runs=int(self.router.policy.get("minimum_observations_for_override", 1)),
        )
        routes: list[RouteDecision] = []
        unavailable: set[str] = set()
        for _ in range(len(self.router.candidates)):
            try:
                decision = self.router.route(
                    profile,
                    unavailable_registry_ids=unavailable,
                    previous_provider=previous_provider,
                    performance_overrides=overrides,
                )
            except LookupError:
                break
            unavailable.add(decision.candidate.registry_id)
            if self.providers.has(decision.candidate.provider):
                routes.append(decision)
        if routes:
            return routes
        # Retry exclusion can remove the only viable model. In that case permit
        # the same resource only after the alternative-resource attempt was made.
        metadata = node.get("metadata") or {}
        fallback_profile = TaskProfile(
            task_family=node["task_family"], role=node["role"], risk=node["risk"],
            complexity=int(metadata.get("complexity", 1)), ambiguity=int(metadata.get("ambiguity", 0)),
            prior_failures=int(node.get("attempts", 0)),
            required_provider_diversity=False, preferred_provider=metadata.get("preferred_provider"),
            preferred_registry_id=metadata.get("preferred_registry_id"),
            maximum_reasoning_effort=metadata.get("maximum_reasoning_effort"),
            excluded_models=tuple(metadata.get("excluded_models", [])),
            excluded_providers=tuple(metadata.get("excluded_providers", [])),
        )
        ranked = self.router.ranked(
            fallback_profile, previous_provider=previous_provider, performance_overrides=overrides
        )
        by_id = {candidate.registry_id: candidate for candidate in self.router.candidates}
        for item in ranked:
            candidate = by_id[item["registry_id"]]
            if self.providers.has(candidate.provider):
                routes.append(RouteDecision(
                    candidate=candidate,
                    reasoning_effort=str(item["reasoning_effort"]),
                    sandbox=str(item["sandbox"]),
                    quality_floor=float(item["quality_floor"]),
                    score=float(item["score"]),
                    reasons=tuple(item["reasons"]),
                ))
        return routes

    def _resolve_node_path(self, raw: str, *, control_file: bool = False) -> Path:
        path = Path(raw)
        resolved = (path if path.is_absolute() else self.repo.root / path).resolve()
        roots = (self.repo.root.resolve(), *self.trusted_control_roots) if control_file else (self.repo.root.resolve(),)
        if not any(_is_relative_to(resolved, root) for root in roots):
            raise ValueError(f"Node path escapes trusted roots: {resolved}")
        if resolved.is_symlink() or not resolved.is_file():
            raise ValueError(f"Node path must be a regular non-symlink file: {resolved}")
        return resolved

    def _managed_output_path(self, node_id: str, run_id: str, suffix: str) -> Path:
        if not _ARTIFACT_COMPONENT_RE.fullmatch(node_id) or not _ARTIFACT_COMPONENT_RE.fullmatch(run_id):
            raise ValueError("Artifact node/run identifiers must be bounded path-free components")
        path = (self.output_root / f"{node_id}-{run_id}{suffix}").resolve()
        if not _is_relative_to(path, self.output_root):
            raise ValueError("Managed output path escapes output root")
        return path

    @staticmethod
    def _provider_result_errors(
        result: ProviderRunResult, *, node: dict[str, Any], decision: RouteDecision
    ) -> list[str]:
        errors: list[str] = []
        expected = {
            "task_id": node["task_id"], "role": node["role"],
            "registry_id": decision.candidate.registry_id, "model": decision.candidate.model,
            "provider": decision.candidate.provider,
        }
        for field, value in expected.items():
            if getattr(result, field) != value:
                errors.append(f"provider_result_{field}_mismatch")
        if not _ARTIFACT_COMPONENT_RE.fullmatch(result.run_id):
            errors.append("provider_result_run_id_invalid")
        if result.session_id is not None and (len(result.session_id) > 512 or any(ord(ch) < 32 for ch in result.session_id)):
            errors.append("provider_result_session_id_invalid")
        if result.success and result.exit_code != 0:
            errors.append("provider_result_success_with_nonzero_exit")
        if result.output is not None:
            expected_hash = sha256_bytes(json.dumps(
                result.output, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode("utf-8"))
            if result.output_hash != expected_hash:
                errors.append("provider_result_output_hash_mismatch")
        elif result.output_hash is not None:
            errors.append("provider_result_hash_without_output")
        return errors

    def _artifact_paths(self, node_id: str) -> list[Path]:
        result: list[Path] = []
        for artifact in self.mesh_store.dependency_artifacts(node_id):
            path = Path(artifact["path"]).resolve()
            try:
                path.relative_to(self.output_root)
            except ValueError as exc:
                raise ValueError(f"Dependency artifact escapes managed output root: {path}") from exc
            if sha256_file(path) != artifact["sha256"]:
                raise ValueError(f"Dependency artifact hash mismatch: {path}")
            result.append(path)
        return result

    @staticmethod
    def _compact_value(value: Any, *, depth: int = 0) -> Any:
        if depth >= 5:
            return "<depth-limited>"
        if isinstance(value, str):
            return value if len(value) <= 2000 else value[:2000] + "<truncated>"
        if isinstance(value, list):
            return [MeshRuntime._compact_value(item, depth=depth + 1) for item in value[:30]]
        if isinstance(value, dict):
            return {
                str(key): MeshRuntime._compact_value(child, depth=depth + 1)
                for key, child in list(sorted(value.items(), key=lambda item: str(item[0])))[:60]
            }
        return value

    def _dependency_result_context(
        self, node_id: str, *, maximum_items: int = 32, maximum_bytes: int = 262_144
    ) -> dict[str, Any]:
        """Return a bounded, hash-verified dependency context envelope.

        Dependency results are useful model context, not authoritative evidence. The
        envelope is bounded before prompt construction so a fan-out/fan-in mesh cannot
        silently explode token use or omit context without an explicit marker.
        """
        artifacts = self.mesh_store.dependency_artifacts(
            node_id, artifact_types=("MODEL_RESULT", "CHECK_RESULT", "CONTEXT_RESULT"), transitive=False
        )
        items: list[dict[str, Any]] = []
        omitted: list[dict[str, str]] = []
        serialized_bytes = 0
        for artifact in artifacts:
            path = Path(artifact["path"]).resolve()
            try:
                path.relative_to(self.output_root)
            except ValueError as exc:
                raise ValueError(f"Dependency result escapes managed output root: {path}") from exc
            if sha256_file(path) != artifact["sha256"]:
                raise ValueError(f"Dependency result hash mismatch: {path}")
            data = load_data(path)
            if not isinstance(data, dict):
                raise ValueError(f"Dependency result is not an object: {path}")
            item = {
                "artifact_id": artifact["artifact_id"],
                "node_id": artifact["node_id"],
                "sha256": artifact["sha256"],
                "result": self._compact_value(data),
            }
            encoded = json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode("utf-8")
            if len(items) >= maximum_items or serialized_bytes + len(encoded) > maximum_bytes:
                omitted.append({
                    "artifact_id": str(artifact["artifact_id"]),
                    "node_id": str(artifact["node_id"]),
                    "sha256": str(artifact["sha256"]),
                })
                continue
            items.append(item)
            serialized_bytes += len(encoded)
        return {
            "items": items,
            "truncated": bool(omitted),
            "omitted": omitted,
            "serialized_bytes": serialized_bytes,
            "maximum_items": maximum_items,
            "maximum_bytes": maximum_bytes,
            "claim_boundary": (
                "Dependency model results are bounded context proposals, not evidence. "
                "When truncated is true the agent must request targeted context expansion "
                "instead of asserting completeness."
            ),
        }

    def _register_model_result_artifact(
        self, *, node: dict[str, Any], result: ProviderRunResult
    ) -> dict[str, Any] | None:
        if result.output is None:
            return None
        path = self._managed_output_path(node["node_id"], result.run_id, ".result.json")
        path.write_text(json.dumps(result.output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return self.mesh_store.register_artifact(
            node_id=node["node_id"], artifact_type="MODEL_RESULT", path=str(path.resolve()),
            sha256=sha256_file(path), metadata={
                "run_id": result.run_id, "registry_id": result.registry_id,
                "provider": result.provider, "role": node["role"],
            },
        )

    def _reset_worktree(self, worktree: Path, base_sha: str, patches: list[Path]) -> str:
        base = self.repo.rev_parse(base_sha)
        run_command(["git", "-c", "core.hooksPath=/dev/null", "reset", "--hard", base], cwd=worktree, timeout=120)
        run_command(["git", "-c", "core.hooksPath=/dev/null", "clean", "-fdx"], cwd=worktree, timeout=120)
        if patches:
            self.worktrees.apply_patches(worktree, patches)
            return self.worktrees.materialize_candidate(worktree, base)
        return base

    def _finish_failure(
        self, node: dict[str, Any], *, run_id: str, registry_id: str, provider: str,
        errors: list[str], retry_after: int | None = None, force_quarantine: bool = False,
    ) -> dict[str, Any]:
        attempts = int(node.get("attempts", 0))
        max_attempts = int((node.get("metadata") or {}).get("max_attempts", 4))
        quarantine = force_quarantine or attempts + 1 >= max_attempts
        delay = retry_after if retry_after is not None else min(3600, 30 * (2 ** min(attempts, 6)))
        updated = self.mesh_store.finish_node(
            node["node_id"], owner=self.worker_id, success=False, run_id=run_id,
            registry_id=registry_id, provider=provider, error=";".join(sorted(set(errors)))[:4000],
            retry_after_seconds=delay, quarantine=quarantine,
        )
        return {"state": updated["state"], "quarantined": quarantine}

    def _execute_repository_indexer(self, node: dict[str, Any]) -> dict[str, Any]:
        metadata = node.get("metadata") or {}
        base_sha = str(metadata.get("base_sha") or self.repo.current_head())
        run_id = f"index-{uuid.uuid4()}"
        try:
            index = build_repository_index(
                self.repo, base_sha,
                max_files=int(metadata.get("maximum_index_files", 5000)),
                max_file_bytes=int(metadata.get("maximum_index_file_bytes", 1_000_000)),
            )
            expected = [str(item).replace("\\", "/") for item in metadata.get("expected_components", [])]
            seeds: list[str] = []
            for raw in expected:
                prefix = raw.split("*", 1)[0].rstrip("/")
                if raw in index.files:
                    seeds.append(raw)
                elif prefix:
                    seeds.extend(path for path in index.files if path == prefix or path.startswith(prefix + "/"))
            seeds = sorted(set(seeds))[:500]
            related = index.related_files(
                seeds, depth=3 if node["risk"] in {"R3", "R4"} else 2, max_files=500
            )
            included = sorted(set(seeds) | {item["path"] for item in related})
            sufficiency = assess_context_sufficiency(
                index, changed_paths=seeds, included_paths=included, risk=node["risk"]
            )
            index_path = self._managed_output_path(node["node_id"], run_id, ".repository-index.json")
            index_path.write_text(json.dumps(index.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
            summary = {
                "task_id": node["task_id"], "node_id": node["node_id"], "base_sha": base_sha,
                "index_hash": index.index_hash, "file_count": len(index.files), "seed_files": seeds,
                "related_files": related,
                "signals": {key: list(value)[:200] for key, value in sorted(index.signals.items())},
                "dynamic_gaps": list(index.dynamic_gaps)[:200],
                "skipped_summary": {
                    reason: sum(1 for item in index.skipped if item.get("reason") == reason)
                    for reason in sorted({str(item.get("reason")) for item in index.skipped})
                },
                "context_sufficiency": sufficiency,
                "requested_action": sufficiency["requested_action"],
                "claim_boundary": (
                    "This is a deterministic static index. Scouts must investigate dynamic gaps and external systems; "
                    "the index is not proof of complete runtime coupling."
                ),
            }
            summary_path = self._managed_output_path(node["node_id"], run_id, ".context-result.json")
            summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            index_artifact = self.mesh_store.register_artifact(
                node_id=node["node_id"], artifact_type="REPOSITORY_INDEX", path=str(index_path),
                sha256=sha256_file(index_path), metadata={"base_sha": base_sha, "index_hash": index.index_hash},
            )
            context_artifact = self.mesh_store.register_artifact(
                node_id=node["node_id"], artifact_type="CONTEXT_RESULT", path=str(summary_path),
                sha256=sha256_file(summary_path), metadata={
                    "base_sha": base_sha, "index_hash": index.index_hash,
                    "sufficient": sufficiency["sufficient"],
                },
            )
            updated = self.mesh_store.finish_node(
                node["node_id"], owner=self.worker_id, success=True, run_id=run_id,
                registry_id="deterministic-repository-indexer", provider="local",
            )
            return {
                "node_id": node["node_id"], "task_id": node["task_id"], "success": True,
                "state": updated["state"], "route": None, "validation_errors": [],
                "index_artifact": index_artifact, "context_artifact": context_artifact,
                "context_sufficiency": sufficiency,
            }
        except Exception as exc:
            errors = [f"repository_index_error:{type(exc).__name__}:{exc}"]
            failure = self._finish_failure(
                node, run_id=run_id, registry_id="deterministic-repository-indexer",
                provider="local", errors=errors,
            )
            return {
                "node_id": node["node_id"], "task_id": node["task_id"], "success": False,
                "state": failure["state"], "route": None, "validation_errors": errors,
            }

    def _execute_check_runner(self, node: dict[str, Any]) -> dict[str, Any]:
        metadata = node.get("metadata") or {}
        base_sha = str(metadata.get("base_sha") or self.repo.current_head())
        run_id = f"checks-{uuid.uuid4()}"
        worktree = self.worktrees.create(node["node_id"], base_sha)
        try:
            combined_artifacts = self.mesh_store.dependency_artifacts(
                node["node_id"], artifact_types=("COMBINED_PATCH",), transitive=False
            )
            source_models = []
            for item in combined_artifacts:
                source_models.extend(item.get("metadata", {}).get("source_models", []) or [])
            patches = self._artifact_paths(node["node_id"])
            if not patches:
                raise ValueError("machine_checks_have_no_integrated_patch")
            self.worktrees.apply_patches(worktree, patches)
            candidate_sha = self.worktrees.materialize_candidate(worktree, base_sha)
            config_path = self._resolve_node_path(str(metadata.get("check_config", ".delivery/ztad/config.json")), control_file=False)
            command_policy = self._resolve_node_path(str(metadata.get("command_policy", "policies/command-policy.yaml")), control_file=True)
            contract = self.continuity_store.get_task(node["task_id"])["contract"]
            default_risk_policy = Path(__file__).resolve().parents[2] / "policies" / "risk-policy.yaml"
            risk_policy = self._resolve_node_path(
                str(metadata.get("risk_policy", default_risk_policy)), control_file=True
            )
            actual_risk = classify_repository_change(
                GitRepository(worktree), contract, base_sha, candidate_sha, risk_policy
            )
            risk_escalated = RISK_ORDER[actual_risk.risk] > RISK_ORDER[str(node["risk"])]
            contract_path = self._managed_output_path(node["node_id"], run_id, ".contract.json")
            contract_path.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            evidence_dir = (self.output_root / f"{node['node_id']}-{run_id}.evidence").resolve()
            if not _is_relative_to(evidence_dir, self.output_root):
                raise ValueError("Check evidence directory escapes output root")
            package_root = Path(__file__).resolve().parents[2]
            report = run_checks(
                worktree, base=base_sha, head=candidate_sha, contract_path=contract_path,
                config_path=config_path, command_policy_path=command_policy,
                policy_bundle_hash=hash_directory(package_root / "policies"),
                output_dir=evidence_dir, dry_run=False,
            )
            registered: list[str] = []
            for item in report.get("results", []):
                evidence_path = item.get("evidence_path")
                evidence_id = item.get("evidence_id")
                if not evidence_path or not evidence_id:
                    continue
                record = load_data(Path(evidence_path))
                raw_status = str(record.get("status"))
                status = "PASSED" if raw_status == "PASSED" else "FAILED"
                self.continuity_store.register_evidence(
                    evidence_id=str(evidence_id), task_id=node["task_id"], head_sha=candidate_sha,
                    evidence_type=str(record.get("type", "LOCAL_CHECK")), trust_level="E2",
                    status=status, producer="tool:ztad-local-check-runner",
                    payload={
                        "record_sha256": sha256_file(Path(evidence_path)),
                        "check_id": (record.get("metadata") or {}).get("check_id"),
                        "authoritative_record_validated": False,
                        "claim_boundary": "Local E2 evidence cannot satisfy merge or release gates.",
                    },
                )
                registered.append(str(evidence_id))
            result_path = self._managed_output_path(node["node_id"], run_id, ".check-result.json")
            result_payload = {
                "task_id": node["task_id"], "node_id": node["node_id"],
                "base_sha": base_sha, "head_sha": candidate_sha,
                "planned_risk": node["risk"], "actual_risk": actual_risk.to_dict(),
                "risk_escalated": risk_escalated,
                "blocked": bool(report.get("blocked")) or risk_escalated,
                "decision": "AUTO_REPLAN_REQUIRED" if risk_escalated else report.get("decision"),
                "evidence_refs": registered, "results": report.get("results", []),
                "claim_boundary": (
                    "Actual diff risk is reclassified before review. A higher risk invalidates the existing review topology "
                    "and contains this node for a stronger task-scoped replan; other queue work continues."
                    if risk_escalated else report.get("claim_boundary")
                ),
            }
            result_path.write_text(json.dumps(result_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            artifact = self.mesh_store.register_artifact(
                node_id=node["node_id"], artifact_type="CHECK_RESULT", path=str(result_path),
                sha256=sha256_file(result_path), metadata={"head_sha": candidate_sha, "evidence_refs": registered},
            )
            if not risk_escalated:
                checks_passed = not bool(report.get("blocked"))
                for source in source_models:
                    registry_id = source.get("registry_id")
                    if registry_id:
                        self._record_performance(
                            registry_id=str(registry_id),
                            task_family=str(source.get("task_family") or "implementation"),
                            success=checks_passed, quality=1.0 if checks_passed else 0.0,
                        )
            replan = None
            if risk_escalated:
                replan = self._submit_replan(
                    node=node, target_risk=actual_risk.risk,
                    reason="ACTUAL_DIFF_RISK_ESCALATION",
                    details={
                        "planned_risk": node["risk"],
                        "actual_risk": actual_risk.to_dict(),
                        "candidate_sha": candidate_sha,
                    },
                    consume_repair_cycle=False,
                )
            if report.get("blocked") or risk_escalated:
                failure_errors = ["machine_checks_blocked"] if report.get("blocked") else []
                if risk_escalated:
                    failure_errors.append(f"risk_escalation_required:{node['risk']}->{actual_risk.risk}")
                failure = self._finish_failure(
                    node, run_id=run_id, registry_id="deterministic-check-runner", provider="local",
                    errors=failure_errors, force_quarantine=risk_escalated,
                )
                return {
                    "node_id": node["node_id"], "task_id": node["task_id"], "success": False,
                    "state": failure["state"], "route": None, "validation_errors": failure_errors,
                    "candidate_sha": candidate_sha, "check_report": report, "artifact": artifact,
                    "actual_risk": actual_risk.to_dict(), "risk_escalated": risk_escalated, "replan": replan,
                }
            updated = self.mesh_store.finish_node(
                node["node_id"], owner=self.worker_id, success=True, run_id=run_id,
                registry_id="deterministic-check-runner", provider="local",
            )
            return {
                "node_id": node["node_id"], "task_id": node["task_id"], "success": True,
                "state": updated["state"], "route": None, "validation_errors": [],
                "candidate_sha": candidate_sha, "check_report": report, "artifact": artifact,
                "actual_risk": actual_risk.to_dict(), "risk_escalated": False,
            }
        except Exception as exc:
            errors = [f"machine_check_error:{type(exc).__name__}:{exc}"]
            failure = self._finish_failure(
                node, run_id=run_id, registry_id="deterministic-check-runner", provider="local", errors=errors,
            )
            return {
                "node_id": node["node_id"], "task_id": node["task_id"], "success": False,
                "state": failure["state"], "route": None, "validation_errors": errors,
            }
        finally:
            self.worktrees.remove(worktree)

    def _execute_integrator(self, node: dict[str, Any]) -> dict[str, Any]:
        metadata = node.get("metadata") or {}
        base_sha = str(metadata.get("base_sha") or self.repo.current_head())
        worktree = self.worktrees.create(node["node_id"], base_sha)
        run_id = f"integrate-{uuid.uuid4()}"
        try:
            source_artifacts = self.mesh_store.dependency_artifacts(
                node["node_id"], artifact_types=("PATCH",), transitive=False
            )
            source_models = [
                {
                    "registry_id": item["metadata"].get("registry_id"),
                    "provider": item["metadata"].get("provider"),
                    "model": item["metadata"].get("model"),
                    "task_family": item["metadata"].get("task_family", "implementation"),
                    "node_id": item["node_id"],
                }
                for item in source_artifacts if item.get("metadata", {}).get("registry_id")
            ]
            patches = self._artifact_paths(node["node_id"])
            if not patches:
                result = self._finish_failure(
                    node, run_id=run_id, registry_id="deterministic-integrator", provider="local",
                    errors=["integration_has_no_dependency_patches"], retry_after=30,
                )
                return {
                    "node_id": node["node_id"], "task_id": node["task_id"], "success": False,
                    "state": result["state"], "route": None, "validation_errors": ["integration_has_no_dependency_patches"],
                }
            applied = self.worktrees.apply_patches(worktree, patches)
            output_path = self.output_root / f"{node['node_id']}-{run_id}.patch"
            patch = self.worktrees.patch(worktree, base_sha, output_path)
            errors: list[str] = []
            if not patch["has_changes"]:
                errors.append("integration_produced_empty_patch")
            task = self.continuity_store.get_task(node["task_id"])
            envelope = ScopeEnvelope.from_contract(
                task_id=node["task_id"], contract=task["contract"], allowed_patterns=node["scopes"],
                must_not_touch=metadata.get("must_not_touch", []),
            )
            scope = envelope.verify_paths(patch["changed_paths"])
            if not scope["allowed"]:
                errors.append("integration_scope_violation:" + sha256_json(scope))
            if errors:
                for source in source_models:
                    self._record_performance(
                        registry_id=str(source["registry_id"]), task_family=str(source["task_family"]),
                        success=False, quality=0.0,
                    )
                result = self._finish_failure(
                    node, run_id=run_id, registry_id="deterministic-integrator", provider="local", errors=errors,
                )
                return {
                    "node_id": node["node_id"], "task_id": node["task_id"], "success": False,
                    "state": result["state"], "route": None, "validation_errors": errors,
                    "changed_paths": patch["changed_paths"], "patch": patch,
                }
            artifact = self.mesh_store.register_artifact(
                node_id=node["node_id"], artifact_type="COMBINED_PATCH", path=str(output_path.resolve()),
                sha256=sha256_file(output_path), metadata={"source_patches": applied["applied"], "changed_paths": patch["changed_paths"], "source_models": source_models},
            )
            updated = self.mesh_store.finish_node(
                node["node_id"], owner=self.worker_id, success=True, run_id=run_id,
                registry_id="deterministic-integrator", provider="local",
            )
            return {
                "node_id": node["node_id"], "task_id": node["task_id"], "success": True,
                "state": updated["state"], "route": None, "validation_errors": [],
                "changed_paths": patch["changed_paths"], "patch": patch, "artifact": artifact,
            }
        except Exception as exc:
            errors = [f"integration_error:{type(exc).__name__}:{exc}"]
            result = self._finish_failure(
                node, run_id=run_id, registry_id="deterministic-integrator", provider="local", errors=errors,
            )
            return {"node_id": node["node_id"], "task_id": node["task_id"], "success": False, "state": result["state"], "route": None, "validation_errors": errors}
        finally:
            self.worktrees.remove(worktree)

    def _execute(self, node: dict[str, Any]) -> dict[str, Any]:
        try:
            continuity_state = self._sync_continuity_phase(node)
        except Exception as exc:
            errors = [f"continuity_phase_sync_error:{type(exc).__name__}:{exc}"]
            failure = self._finish_failure(
                node, run_id=f"continuity-{uuid.uuid4()}", registry_id="deterministic-continuity-sync",
                provider="local", errors=errors, force_quarantine=True,
            )
            return {
                "node_id": node["node_id"], "task_id": node["task_id"], "success": False,
                "state": failure["state"], "route": None, "validation_errors": errors,
            }
        if node["role"] == "repository_indexer":
            return self._execute_repository_indexer(node)
        if node["role"] == "patch_integrator":
            return self._execute_integrator(node)
        if node["role"] == "check_runner":
            return self._execute_check_runner(node)

        metadata = node.get("metadata") or {}
        routes = self._ranked_routes(node)
        if not routes:
            result = self._finish_failure(
                node, run_id=f"route-{uuid.uuid4()}", registry_id="none", provider="none",
                errors=["no_configured_provider_clears_quality_gate"], retry_after=300,
            )
            return {"node_id": node["node_id"], "task_id": node["task_id"], "success": False, "state": result["state"], "route": None, "validation_errors": ["no_configured_provider_clears_quality_gate"]}

        prompt_path = self._resolve_node_path(node["prompt_path"], control_file=False)
        output_schema = self._resolve_node_path(node["output_schema"], control_file=True)
        prompt_base = prompt_path.read_text(encoding="utf-8")
        dependency_results = self._dependency_result_context(
            node["node_id"],
            maximum_items=int(metadata.get("maximum_dependency_result_items", 32)),
            maximum_bytes=int(metadata.get("maximum_dependency_result_bytes", 262_144)),
        )
        if dependency_results["items"] or dependency_results["truncated"]:
            prompt_base += "\n\nZTAD_DEPENDENCY_RESULTS\n" + json.dumps(
                dependency_results, sort_keys=True, separators=(",", ":")
            ) + "\n"
        task = self.continuity_store.get_task(node["task_id"])
        base_sha = str(metadata.get("base_sha") or self.repo.current_head())
        head_sha = str(metadata.get("head_sha") or base_sha)
        context_id = str(metadata.get("context_id") or sha256_json({"node": node["node_id"], "base": base_sha}))
        prompt_version = str(metadata.get("prompt_version", "mesh-v1"))
        agent_role = str(metadata.get("agent_role") or _ROLE_TO_AGENT_ROLE.get(node["role"], "planner"))
        dependency_patches = self._artifact_paths(node["node_id"]) if metadata.get("consume_dependency_patches") else []
        worktree: Path | None = None
        cwd = self.repo.root
        if node["write_access"] or dependency_patches:
            worktree = self.worktrees.create(node["node_id"], base_sha)
            cwd = worktree
            if dependency_patches:
                self.worktrees.apply_patches(worktree, dependency_patches)
                head_sha = self.worktrees.materialize_candidate(worktree, base_sha)
        max_routes = max(1, int(metadata.get("max_provider_attempts_per_run", 3)))
        route_attempts: list[dict[str, Any]] = []
        selected: tuple[RouteDecision, ProviderRunResult, str, list[str]] | None = None
        try:
            for route_index, decision in enumerate(routes[:max_routes]):
                if route_index and worktree is not None:
                    head_sha = self._reset_worktree(worktree, base_sha, dependency_patches)
                provider = self.providers.get(decision.candidate.provider)
                immutable_envelope = {
                    "task_id": node["task_id"], "mesh_node_id": node["node_id"], "risk": node["risk"],
                    "base_sha": base_sha, "head_sha": head_sha, "context_id": context_id,
                    "contract_hash": sha256_json(task["contract"]), "allowed_scopes": node["scopes"],
                    "must_not_touch": metadata.get("must_not_touch", []),
                    "agent_role": agent_role, "model_registry_id": decision.candidate.registry_id,
                    "prompt_version": prompt_version,
                    "dependency_patch_hashes": [sha256_file(path) for path in dependency_patches],
                }
                prompt = prompt_base + "\n\nZTAD_IMMUTABLE_ENVELOPE\n" + repr(immutable_envelope) + "\n"
                request = ProviderRunRequest(
                    task_id=node["task_id"], role=node["role"], registry_id=decision.candidate.registry_id,
                    model=decision.candidate.model, reasoning_effort=decision.reasoning_effort,
                    sandbox=decision.sandbox, prompt=prompt, output_schema=output_schema, cwd=cwd,
                    timeout_seconds=int(metadata.get("timeout_seconds", 1800)),
                    artifact_dir=self.output_root,
                )
                started = time.monotonic()
                try:
                    result = provider.run(request)
                except Exception as exc:
                    result = ProviderRunResult(
                        run_id=f"provider-error-{uuid.uuid4()}", provider=decision.candidate.provider,
                        task_id=node["task_id"], role=node["role"],
                        registry_id=decision.candidate.registry_id, model=decision.candidate.model,
                        session_id=None, started_at=utc_now(), completed_at=utc_now(),
                        exit_code=125, success=False, output=None, output_hash=None,
                        stdout_hash=sha256_bytes(b""), stderr_hash=sha256_bytes(str(exc).encode()),
                        input_tokens=None, output_tokens=None,
                        errors=(f"provider_adapter_exception:{type(exc).__name__}:{exc}",),
                        argv=(decision.candidate.provider,),
                    )
                latency = max(0.001, time.monotonic() - started)
                errors = list(result.errors)
                errors.extend(self._provider_result_errors(result, node=node, decision=decision))
                if result.output is not None:
                    schema = load_data(output_schema)
                    errors.extend(validate_agent_result(
                        result.output, schema,
                        expected={
                            "task_id": node["task_id"], "agent_role": agent_role,
                            "model_registry_id": decision.candidate.registry_id,
                            "prompt_version": prompt_version, "base_sha": base_sha,
                            "head_sha": head_sha, "context_id": context_id,
                        },
                    ))
                else:
                    errors.append("model_returned_no_structured_output")
                session_id = result.session_id or f"{result.provider}:{result.run_id}"
                self.continuity_store.record_model_run(
                    task_id=node["task_id"], role=node["role"], model_id=decision.candidate.model,
                    prompt_version=prompt_version, context_hash=context_id,
                    status="COMPLETED" if result.success and not errors else "FAILED", session_id=session_id,
                    reasoning_effort=decision.reasoning_effort, head_sha=head_sha,
                    input_tokens=result.input_tokens, output_tokens=result.output_tokens,
                    output_hash=result.output_hash, run_id=result.run_id,
                )
                if not result.success or errors:
                    self._record_performance(
                        registry_id=decision.candidate.registry_id, task_family=node["task_family"],
                        success=False, quality=0.0,
                    )
                route_attempts.append({"route": decision.to_dict(), "run": result.to_dict(), "validation_errors": sorted(set(errors))})
                if result.success and not errors:
                    selected = (decision, result, prompt, errors)
                    break
            if selected is None:
                last = route_attempts[-1]
                run = last["run"]
                errors = list(last["validation_errors"])
                result_state = self._finish_failure(
                    node, run_id=str(run["run_id"]), registry_id=str(run["registry_id"]),
                    provider=str(run["provider"]), errors=errors,
                )
                return {
                    "node_id": node["node_id"], "task_id": node["task_id"], "success": False,
                    "state": result_state["state"], "route": last["route"], "route_attempts": route_attempts,
                    "run": run, "validation_errors": errors,
                }

            decision, result, prompt, validation_errors = selected
            changed_paths: list[str] = []
            patch_info: dict[str, Any] | None = None
            artifact: dict[str, Any] | None = None
            model_result_artifact = None
            if node["write_access"] and worktree is not None:
                patch_path = self._managed_output_path(node["node_id"], result.run_id, ".patch")
                patch_info = self.worktrees.patch(worktree, base_sha, patch_path)
                changed_paths = list(patch_info["changed_paths"])
                envelope = ScopeEnvelope.from_contract(
                    task_id=node["task_id"], contract=task["contract"], allowed_patterns=node["scopes"],
                    must_not_touch=metadata.get("must_not_touch", []),
                )
                scope_result = envelope.verify_paths(changed_paths)
                if not scope_result["allowed"]:
                    validation_errors.append("scope_violation:" + sha256_json(scope_result))
                result_type = (result.output or {}).get("result_type")
                if not patch_info["has_changes"] and result_type not in {
                    "WAITING_EXTERNAL_DEPENDENCY", "INSUFFICIENT_CONTEXT", "AUTO_REPLAN", "QUARANTINE_AND_CONTINUE",
                }:
                    validation_errors.append("write_role_produced_no_patch")

            output = result.output or {}
            control = self._structured_control(node, output)
            validation_errors.extend(control["errors"])
            replan = None
            if control["replan"] is not None:
                replan_spec = control["replan"]
                replan = self._submit_replan(
                    node=node, target_risk=str(replan_spec["target_risk"]),
                    reason=str(replan_spec["reason"]), details=dict(replan_spec["details"]),
                    consume_repair_cycle=bool(replan_spec["consume_repair_cycle"]),
                )
            strategy_hash = str(metadata.get("strategy_hash") or sha256_json({
                "role": node["role"], "family": node["task_family"], "dimension": metadata.get("dimension"),
            }))
            fingerprint = AttemptFingerprint(
                task_id=node["task_id"], strategy_hash=strategy_hash,
                prompt_hash=sha256_bytes(prompt.encode()), context_hash=context_id, head_sha=head_sha,
                diff_hash=sha256_json(changed_paths),
                failing_evidence_hash=sha256_json({"errors": validation_errors, "findings": output.get("findings", [])}),
                provider=decision.candidate.provider, model=decision.candidate.model,
            )
            snapshot = ProgressSnapshot(
                failing_checks=int(metadata.get("failing_checks", 0 if not validation_errors else 1)),
                blocking_findings=sum(1 for item in output.get("findings", []) if item.get("severity") in {"P0", "P1"}),
                unknowns=len(output.get("known_unknowns", [])) + len(output.get("uncertainties", [])),
                evidence_count=len(metadata.get("evidence_refs", [])), strategy_hash=strategy_hash,
                context_hash=context_id, provider=decision.candidate.provider, model=decision.candidate.model,
            )
            try:
                attempt = self.mesh_store.record_attempt(node_id=node["node_id"], fingerprint=fingerprint, snapshot=snapshot)
            except ValueError as exc:
                validation_errors.append("repeated_attempt_signature")
                attempt = {"progress": False, "decision": "NO_PROGRESS_CYCLE_ESCALATE", "error": str(exc)}
            if not attempt.get("progress", False) and int(node.get("attempts", 0)) > 0:
                validation_errors.append("no_progress_cycle")
            success = result.success and not validation_errors
            if node["write_access"]:
                if not success:
                    quality = 0.25 if self._is_capability_abstention(output) else 0.0
                    self._record_performance(
                        registry_id=decision.candidate.registry_id, task_family=node["task_family"],
                        success=False, quality=quality,
                    )
            else:
                abstained = self._is_capability_abstention(output)
                self._record_performance(
                    registry_id=decision.candidate.registry_id, task_family=node["task_family"],
                    success=not abstained,
                    quality=0.25 if abstained else self._candidate_prior_quality(decision, node["task_family"]),
                )
            if success:
                model_result_artifact = self._register_model_result_artifact(node=node, result=result)
                if patch_info and patch_info["has_changes"]:
                    artifact = self.mesh_store.register_artifact(
                        node_id=node["node_id"], artifact_type="PATCH",
                        path=str(Path(patch_info["patch_path"]).resolve()),
                        sha256=sha256_file(Path(patch_info["patch_path"])),
                        metadata={"changed_paths": changed_paths, "base_sha": base_sha, "registry_id": decision.candidate.registry_id, "provider": decision.candidate.provider, "model": decision.candidate.model, "task_family": node["task_family"], "quality_pending": True},
                    )
                updated = self.mesh_store.finish_node(
                    node["node_id"], owner=self.worker_id, success=True, run_id=result.run_id,
                    registry_id=decision.candidate.registry_id, provider=decision.candidate.provider,
                )
            else:
                state = self._finish_failure(
                    node, run_id=result.run_id, registry_id=decision.candidate.registry_id,
                    provider=decision.candidate.provider, errors=validation_errors,
                    force_quarantine=bool(control["force_quarantine"]),
                )
                if bool(control["force_quarantine"]) and replan is None:
                    self._transition_parent_control_state(
                        node, "QUARANTINED", reason="STRUCTURED_CONTROL_CONTAINMENT"
                    )
                updated = {"state": state["state"]}
            return {
                "node_id": node["node_id"], "task_id": node["task_id"], "success": success,
                "state": updated["state"], "route": decision.to_dict(), "route_attempts": route_attempts,
                "run": result.to_dict(), "validation_errors": sorted(set(validation_errors)),
                "changed_paths": changed_paths, "patch": patch_info, "artifact": artifact,
                "model_result_artifact": model_result_artifact, "attempt": attempt,
                "structured_control": control, "replan": replan,
            }
        except Exception as exc:
            errors = [f"runtime_validation_error:{type(exc).__name__}:{exc}"]
            last_route = routes[0]
            state = self._finish_failure(
                node, run_id=f"runtime-{uuid.uuid4()}", registry_id=last_route.candidate.registry_id,
                provider=last_route.candidate.provider, errors=errors,
            )
            return {
                "node_id": node["node_id"], "task_id": node["task_id"], "success": False,
                "state": state["state"], "route": last_route.to_dict(), "route_attempts": route_attempts,
                "validation_errors": errors,
            }
        finally:
            if worktree is not None:
                self.worktrees.remove(worktree)

    def run_once(self, *, maximum_nodes: int | None = None, lease_seconds: int = 1800) -> RuntimeTick:
        self.mesh_store.recover_expired()
        status = self.mesh_store.status()
        desired = maximum_nodes or self.global_parallel_cap
        provider_limit = self.router.maximum_useful_parallelism(
            independent_units=max(1, status.get("runnable_now", status.get("ready", 1))), configured_cap=self.global_parallel_cap,
        )
        parallel = min(desired, self.global_parallel_cap, provider_limit, max(1, status.get("runnable_now", status.get("ready", 1))))
        nodes = self.mesh_store.claim_ready(self.worker_id, limit=parallel, lease_seconds=lease_seconds)
        if not nodes:
            return RuntimeTick(0, 0, 0, 0, ())
        results: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(nodes)) as pool:
            futures = [pool.submit(self._execute, node) for node in nodes]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        return RuntimeTick(
            claimed=len(nodes),
            succeeded=sum(bool(item["success"]) for item in results),
            failed=sum(not bool(item["success"]) and item["state"] != "QUARANTINED" for item in results),
            quarantined=sum(item["state"] == "QUARANTINED" for item in results),
            results=tuple(sorted(results, key=lambda item: item["node_id"])),
        )

    def run_until_idle(
        self,
        *,
        maximum_ticks: int = 100,
        maximum_seconds: int = 3600,
        idle_rounds: int = 2,
        sleep_seconds: float = 0.1,
    ) -> dict[str, Any]:
        started_wall = utc_now()
        started = time.monotonic()
        ticks: list[dict[str, Any]] = []
        idle = 0
        for _ in range(maximum_ticks):
            if time.monotonic() - started >= maximum_seconds:
                break
            tick = self.run_once().to_dict()
            ticks.append(tick)
            if tick["claimed"] == 0:
                idle += 1
                if idle >= idle_rounds:
                    break
                time.sleep(sleep_seconds)
            else:
                idle = 0
        return {
            "started_at": started_wall,
            "completed_at": utc_now(),
            "ticks": ticks,
            "mesh_status": self.mesh_store.status(),
            "continuity_status": self.continuity_store.system_status(),
            "claim_boundary": (
                "The runtime exhausts currently runnable local mesh work. Tasks blocked by external services remain durable "
                "and require a scheduler service or later invocation to resume."
            ),
        }

    def serve(
        self,
        *,
        maximum_seconds: int = 0,
        poll_seconds: float = 2.0,
        maximum_nodes: int | None = None,
        status_interval_seconds: float = 60.0,
    ) -> dict[str, Any]:
        """Continuously execute runnable work until interrupted or time-bounded.

        A zero maximum_seconds means no runtime deadline. The service never spins: it
        sleeps when no nodes are runnable and relies on durable leases/state for
        recovery. External process supervision is still required for automatic restart
        after host or process failure.
        """
        if maximum_seconds < 0:
            raise ValueError("maximum_seconds must be zero or positive")
        if poll_seconds <= 0 or status_interval_seconds <= 0:
            raise ValueError("poll and status intervals must be positive")
        started_wall = utc_now()
        started = time.monotonic()
        next_status = started
        totals = {"ticks": 0, "claimed": 0, "succeeded": 0, "failed": 0, "quarantined": 0}
        snapshots: list[dict[str, Any]] = []
        interrupted = False
        try:
            while maximum_seconds == 0 or time.monotonic() - started < maximum_seconds:
                tick = self.run_once(maximum_nodes=maximum_nodes).to_dict()
                totals["ticks"] += 1
                for key in ("claimed", "succeeded", "failed", "quarantined"):
                    totals[key] += int(tick[key])
                now = time.monotonic()
                if now >= next_status:
                    snapshots.append({
                        "at": utc_now(),
                        "mesh_status": self.mesh_store.status(),
                        "continuity_status": self.continuity_store.system_status(),
                    })
                    # Bound memory for long-running services. Durable details remain in SQLite.
                    snapshots = snapshots[-120:]
                    next_status = now + status_interval_seconds
                if tick["claimed"] == 0:
                    time.sleep(poll_seconds)
        except KeyboardInterrupt:
            interrupted = True
        return {
            "started_at": started_wall,
            "completed_at": utc_now(),
            "interrupted": interrupted,
            "totals": totals,
            "status_snapshots": snapshots,
            "mesh_status": self.mesh_store.status(),
            "continuity_status": self.continuity_store.system_status(),
            "claim_boundary": (
                "This service keeps local runnable work moving and preserves delayed work. "
                "A host service manager must restart it after process or host failure; platform actions remain evidence-gated."
            ),
        }
