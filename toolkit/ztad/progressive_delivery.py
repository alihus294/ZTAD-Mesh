from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class DeploymentAdapter(Protocol):
    def deploy(self, *, artifact_digest: str, environment: str, percentage: int) -> dict[str, Any]: ...
    def rollback(self, *, environment: str, stable_artifact_digest: str) -> dict[str, Any]: ...
    def metrics(self, *, environment: str, artifact_digest: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class MetricPolicy:
    maximum_error_rate: float
    maximum_latency_ratio: float
    minimum_transaction_success: float
    maximum_inconclusive_rounds: int = 1


class ProgressiveDeliveryController:
    """Platform-neutral promotion state machine; adapters perform actual deployment."""

    def __init__(self, adapter: DeploymentAdapter, policy: MetricPolicy, *, steps: tuple[int, ...] = (1, 10, 25, 50, 100)):
        if not steps or steps[-1] != 100 or any(step <= 0 or step > 100 for step in steps):
            raise ValueError("Promotion steps must be positive percentages ending at 100")
        if tuple(sorted(set(steps))) != steps:
            raise ValueError("Promotion steps must be unique and ascending")
        self.adapter = adapter
        self.policy = policy
        self.steps = steps

    def evaluate_metrics(self, metrics: dict[str, Any]) -> str:
        required = {"conclusive", "error_rate", "latency_ratio", "transaction_success"}
        if not required <= set(metrics):
            return "INCONCLUSIVE"
        if not metrics["conclusive"]:
            return "INCONCLUSIVE"
        healthy = (
            float(metrics["error_rate"]) <= self.policy.maximum_error_rate
            and float(metrics["latency_ratio"]) <= self.policy.maximum_latency_ratio
            and float(metrics["transaction_success"]) >= self.policy.minimum_transaction_success
        )
        return "HEALTHY" if healthy else "UNHEALTHY"

    def run(
        self,
        *,
        artifact_digest: str,
        stable_artifact_digest: str,
        environment: str = "production",
    ) -> dict[str, Any]:
        history: list[dict[str, Any]] = []
        inconclusive = 0
        for percentage in self.steps:
            deployed = self.adapter.deploy(artifact_digest=artifact_digest, environment=environment, percentage=percentage)
            history.append({"step": percentage, "deploy": deployed})
            if not deployed.get("success"):
                rollback = self.adapter.rollback(environment=environment, stable_artifact_digest=stable_artifact_digest)
                return {"decision": "ROLLED_BACK", "reason": "deployment_step_failed", "history": history, "rollback": rollback}
            metrics = self.adapter.metrics(environment=environment, artifact_digest=artifact_digest)
            verdict = self.evaluate_metrics(metrics)
            history[-1].update({"metrics": metrics, "verdict": verdict})
            if verdict == "HEALTHY":
                inconclusive = 0
                continue
            if verdict == "INCONCLUSIVE" and inconclusive < self.policy.maximum_inconclusive_rounds:
                inconclusive += 1
                retry_metrics = self.adapter.metrics(environment=environment, artifact_digest=artifact_digest)
                retry_verdict = self.evaluate_metrics(retry_metrics)
                history[-1]["extended_observation"] = {"metrics": retry_metrics, "verdict": retry_verdict}
                if retry_verdict == "HEALTHY":
                    continue
            rollback = self.adapter.rollback(environment=environment, stable_artifact_digest=stable_artifact_digest)
            return {"decision": "ROLLED_BACK", "reason": "unhealthy_or_inconclusive_metrics", "history": history, "rollback": rollback}
        return {"decision": "PROMOTED", "artifact_digest": artifact_digest, "history": history}
