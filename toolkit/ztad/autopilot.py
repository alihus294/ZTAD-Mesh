from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .mesh_plan import MeshPlan, build_mesh_plan, write_mesh_plan
from .mesh_store import MeshStore
from .orchestrator import ContinuityStore
from .repository import GitRepository
from .risk import RiskResult, classify_risk, max_risk
from .schema_validation import validate_file
from .util import load_data, sha256_json


@dataclass(frozen=True)
class AutopilotPreparation:
    repository: str
    task_id: str
    contract_hash: str
    effective_risk: str
    risk_result: dict[str, Any]
    plan: MeshPlan
    plan_output: str
    prompt_root: str
    mesh_database: str
    continuity_database: str

    def to_dict(self, *, include_plan: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "repository": self.repository,
            "task_id": self.task_id,
            "contract_hash": self.contract_hash,
            "effective_risk": self.effective_risk,
            "risk_result": self.risk_result,
            "plan_output": self.plan_output,
            "prompt_root": self.prompt_root,
            "mesh_database": self.mesh_database,
            "continuity_database": self.continuity_database,
            "claim_boundary": (
                "Autopilot prepares and executes the local evidence-producing mesh. "
                "It cannot prove hosted CI, merge, deployment, or production controls without platform evidence."
            ),
        }
        if include_plan:
            result["plan"] = self.plan.to_dict()
        return result


def _repo_path(repo: GitRepository, raw: str | Path) -> Path:
    path = Path(raw)
    resolved = (path if path.is_absolute() else repo.root / path).resolve()
    try:
        resolved.relative_to(repo.root)
    except ValueError as exc:
        raise ValueError(f"Autopilot path escapes repository: {resolved}") from exc
    return resolved


def _default_task_id(contract: dict[str, Any], contract_hash: str) -> str:
    change_id = str(contract.get("change_id") or "change").strip().casefold()
    safe = "".join(character if character.isalnum() or character in {"-", "_"} else "-" for character in change_id)
    safe = safe.strip("-_")[:48] or "change"
    return f"{safe}-{contract_hash.removeprefix('sha256:')[:12]}"


def prepare_autopilot(
    *,
    repository: Path,
    contract_path: Path,
    contract_schema: Path,
    risk_policy: Path,
    requested_risk: str | None = None,
    task_id: str | None = None,
    plan_output: str = ".delivery/ztad/mesh-plan.json",
    prompt_root: str = ".delivery/ztad/mesh-prompts",
    output_schema: str,
    check_config: str = ".delivery/ztad/config.json",
    command_policy: str,
    mesh_database: str = ".delivery/ztad/state/mesh.db",
    continuity_database: str = ".delivery/ztad/state/continuity.db",
    maximum_parallel_writers: int = 6,
    maximum_plan_candidates: int = 4,
) -> AutopilotPreparation:
    repo = GitRepository(repository)
    resolved_contract = _repo_path(repo, contract_path)
    schema_errors = validate_file(resolved_contract, contract_schema)
    if schema_errors:
        raise ValueError("Invalid Change Contract: " + "; ".join(schema_errors[:20]))
    contract = load_data(resolved_contract)
    if not isinstance(contract, dict):
        raise ValueError("Change Contract must be an object")
    contract_hash = sha256_json(contract)
    intended_paths = list((contract.get("scope") or {}).get("expected_components") or [])
    risk: RiskResult = classify_risk(
        contract,
        changed_paths=intended_paths,
        policy=load_data(risk_policy),
    )
    effective_risk = max_risk(risk.risk, requested_risk or "R0")
    stable_task_id = task_id or _default_task_id(contract, contract_hash)
    plan = build_mesh_plan(
        task_id=stable_task_id,
        risk=effective_risk,
        contract=contract,
        prompt_root=prompt_root,
        output_schema=str(output_schema),
        check_config=check_config,
        command_policy=str(command_policy),
        risk_policy=str(risk_policy),
        maximum_parallel_writers=maximum_parallel_writers,
        maximum_plan_candidates=maximum_plan_candidates,
    )
    return AutopilotPreparation(
        repository=str(repo.root),
        task_id=stable_task_id,
        contract_hash=contract_hash,
        effective_risk=effective_risk,
        risk_result=risk.to_dict(),
        plan=plan,
        plan_output=str(_repo_path(repo, plan_output)),
        prompt_root=str(_repo_path(repo, prompt_root)),
        mesh_database=str(_repo_path(repo, mesh_database)),
        continuity_database=str(_repo_path(repo, continuity_database)),
    )


def submit_prepared_autopilot(
    *,
    preparation: AutopilotPreparation,
    contract: dict[str, Any],
    title: str,
    priority: int = 0,
) -> dict[str, Any]:
    """Persist an already validated preparation idempotently.

    Split from prepare_autopilot so dry-run remains strictly non-mutating and
    callers can re-check the contract hash immediately before persistence.
    """
    if sha256_json(contract) != preparation.contract_hash:
        raise ValueError("Change Contract changed after autopilot preparation")
    repo = GitRepository(Path(preparation.repository))
    plan_written = write_mesh_plan(
        preparation.plan,
        repository=repo.root,
        output_file=Path(preparation.plan_output),
    )
    continuity = ContinuityStore(Path(preparation.continuity_database))
    task = continuity.submit_task(
        repository=str(repo.root),
        title=title,
        contract=contract,
        risk=preparation.effective_risk,
        priority=priority,
        idempotency_key=sha256_json({
            "repository": str(repo.root),
            "contract_hash": preparation.contract_hash,
            "task_id": preparation.task_id,
            "autopilot_schema": 1,
        }),
        task_id=preparation.task_id,
    )
    mesh = MeshStore(Path(preparation.mesh_database))
    submitted = mesh.submit_graph(preparation.plan.nodes)
    return {
        "plan_written": plan_written,
        "task": task,
        "submitted_nodes": len(submitted),
        "mesh_status": mesh.status(),
        "idempotent": bool(task.get("idempotent_replay")),
    }
