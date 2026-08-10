from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .util import sha256_json


@dataclass(frozen=True)
class AttemptFingerprint:
    task_id: str
    strategy_hash: str
    prompt_hash: str
    context_hash: str
    head_sha: str
    diff_hash: str
    failing_evidence_hash: str
    provider: str = ""
    model: str = ""

    @property
    def signature(self) -> str:
        return sha256_json({
            "task_id": self.task_id,
            "strategy_hash": self.strategy_hash,
            "prompt_hash": self.prompt_hash,
            "context_hash": self.context_hash,
            "head_sha": self.head_sha,
            "diff_hash": self.diff_hash,
            "failing_evidence_hash": self.failing_evidence_hash,
            "provider": self.provider,
            "model": self.model,
        })


@dataclass(frozen=True)
class ProgressSnapshot:
    failing_checks: int
    blocking_findings: int
    unknowns: int
    evidence_count: int
    strategy_hash: str
    context_hash: str
    provider: str
    model: str


def evaluate_progress(previous: ProgressSnapshot | None, current: ProgressSnapshot) -> dict[str, Any]:
    if previous is None:
        return {"progress": True, "reasons": ["first_attempt"], "decision": "CONTINUE"}
    reasons: list[str] = []
    if current.failing_checks < previous.failing_checks:
        reasons.append("fewer_failing_checks")
    if current.blocking_findings < previous.blocking_findings:
        reasons.append("fewer_blocking_findings")
    if current.unknowns < previous.unknowns:
        reasons.append("reduced_uncertainty")
    if current.evidence_count > previous.evidence_count:
        reasons.append("new_evidence")
    if current.strategy_hash != previous.strategy_hash:
        reasons.append("new_strategy")
    if current.context_hash != previous.context_hash:
        reasons.append("expanded_or_changed_context")
    if (current.provider, current.model) != (previous.provider, previous.model):
        reasons.append("different_execution_resource")
    return {
        "progress": bool(reasons),
        "reasons": reasons,
        "decision": "CONTINUE" if reasons else "NO_PROGRESS_CYCLE_ESCALATE",
    }
