from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .util import load_data

RISK_RANK = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}
FRONTIER_ROLES = {
    "supervisor", "closure", "architecture_advisor", "security_reviewer",
    "data_reviewer", "release_advisor", "plan_adjudicator", "supervisor_takeover",
}
WRITE_ROLES = {"worker", "repairer", "supervisor_takeover"}


@dataclass(frozen=True)
class TaskProfile:
    task_family: str
    role: str
    risk: str
    complexity: int = 1
    ambiguity: int = 0
    prior_failures: int = 0
    required_provider_diversity: bool = False
    preferred_provider: str | None = None
    excluded_models: tuple[str, ...] = ()
    excluded_providers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.risk not in RISK_RANK:
            raise ValueError(f"Unknown risk: {self.risk}")
        if not 0 <= self.complexity <= 5 or not 0 <= self.ambiguity <= 5:
            raise ValueError("complexity and ambiguity must be between 0 and 5")
        if self.prior_failures < 0:
            raise ValueError("prior_failures must be non-negative")


@dataclass(frozen=True)
class ModelCandidate:
    registry_id: str
    provider: str
    model: str
    tier: str
    enabled: bool
    reasoning_efforts: tuple[str, ...]
    sandboxes: tuple[str, ...]
    task_quality: dict[str, float]
    reliability: float
    cost_index: float
    latency_index: float
    max_parallel: int

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "ModelCandidate":
        required = {"registry_id", "provider", "model", "tier"}
        missing = sorted(required - set(value))
        if missing:
            raise ValueError("Model candidate missing: " + ", ".join(missing))
        registry_id = str(value["registry_id"])
        provider = str(value["provider"])
        model = str(value["model"])
        for name, item in (("registry_id", registry_id), ("provider", provider), ("model", model)):
            if not item or len(item) > 256 or any(ord(ch) < 32 for ch in item):
                raise ValueError(f"Model candidate {name} is invalid")
        tier = str(value["tier"]).lower()
        if tier not in {"economy", "balanced", "frontier"}:
            raise ValueError(f"Unsupported model tier: {tier}")
        efforts = tuple(str(x) for x in value.get("reasoning_efforts", ["medium"]))
        allowed_efforts = {"none", "low", "medium", "high", "xhigh", "max", "ultra"}
        if not efforts or any(item not in allowed_efforts for item in efforts):
            raise ValueError("Model candidate has unsupported reasoning efforts")
        sandboxes = tuple(str(x) for x in value.get("sandboxes", ["read-only"]))
        if not sandboxes or any(item not in {"read-only", "workspace-write"} for item in sandboxes):
            raise ValueError("Model candidate has an unsafe or unsupported sandbox")
        task_quality = {str(k): float(v) for k, v in (value.get("task_quality", {}) or {}).items()}
        if any(not 0.0 <= score <= 1.0 for score in task_quality.values()):
            raise ValueError("Model task quality values must be between 0 and 1")
        reliability = float(value.get("reliability", 0.9))
        if not 0.0 <= reliability <= 1.0:
            raise ValueError("Model reliability must be between 0 and 1")
        cost_index = float(value.get("cost_index", 1.0))
        latency_index = float(value.get("latency_index", 1.0))
        if cost_index <= 0 or latency_index <= 0:
            raise ValueError("Model cost and latency indexes must be positive")
        max_parallel = int(value.get("max_parallel", 1))
        if not 1 <= max_parallel <= 64:
            raise ValueError("Model max_parallel must be between 1 and 64")
        return cls(
            registry_id=registry_id, provider=provider, model=model, tier=tier,
            enabled=bool(value.get("enabled", True)), reasoning_efforts=efforts,
            sandboxes=sandboxes, task_quality=task_quality, reliability=reliability,
            cost_index=cost_index, latency_index=latency_index, max_parallel=max_parallel,
        )


@dataclass(frozen=True)
class RouteDecision:
    candidate: ModelCandidate
    reasoning_effort: str
    sandbox: str
    quality_floor: float
    score: float
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry_id": self.candidate.registry_id,
            "provider": self.candidate.provider,
            "model": self.candidate.model,
            "tier": self.candidate.tier,
            "reasoning_effort": self.reasoning_effort,
            "sandbox": self.sandbox,
            "quality_floor": self.quality_floor,
            "score": round(self.score, 6),
            "reasons": list(self.reasons),
        }


class AdaptiveModelRouter:
    """Select the lowest-cost candidate that clears a risk- and role-aware quality gate.

    Model output is never evidence. Routing only selects an execution resource; all
    resulting claims still pass schema, scope, evidence, and state-transition gates.
    """

    def __init__(self, catalog: dict[str, Any]):
        self.catalog = catalog
        raw = catalog.get("models", []) if isinstance(catalog, dict) else []
        self.candidates = tuple(ModelCandidate.from_mapping(item) for item in raw if isinstance(item, dict))
        if not self.candidates:
            raise ValueError("Model catalog contains no candidates")
        ids = [item.registry_id for item in self.candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate model registry_id")
        self.policy = catalog.get("routing", {}) or {}

    @classmethod
    def from_file(cls, path) -> "AdaptiveModelRouter":
        value = load_data(path)
        if not isinstance(value, dict):
            raise ValueError("Model catalog must be a mapping")
        return cls(value)

    def _quality_floor(self, profile: TaskProfile) -> float:
        by_risk = self.policy.get("minimum_quality_by_risk", {}) or {}
        floor = float(by_risk.get(profile.risk, 0.75))
        if profile.role in FRONTIER_ROLES:
            floor = max(floor, float(self.policy.get("frontier_role_quality_floor", 0.9)))
        floor += min(profile.ambiguity, 3) * 0.01
        return min(floor, 0.99)

    def _requires_frontier(self, profile: TaskProfile) -> bool:
        if profile.role in FRONTIER_ROLES:
            return True
        if profile.risk == "R4":
            return True
        if profile.risk == "R3" and profile.task_family in {
            "architecture", "security", "authorization", "database", "financial_logic", "release",
        }:
            return True
        return False

    @staticmethod
    def _sandbox(profile: TaskProfile) -> str:
        return "workspace-write" if profile.role in WRITE_ROLES else "read-only"

    def _reasoning(self, candidate: ModelCandidate, profile: TaskProfile) -> str:
        target = "medium"
        pressure = RISK_RANK[profile.risk] + profile.complexity + profile.ambiguity + min(profile.prior_failures, 3)
        if pressure >= 11:
            target = "max"
        elif pressure >= 8:
            target = "xhigh"
        elif pressure >= 5:
            target = "high"
        elif pressure <= 2:
            target = "low"
        order = ["none", "low", "medium", "high", "xhigh", "max", "ultra"]
        available = [item for item in order if item in candidate.reasoning_efforts]
        if not available:
            raise ValueError(f"Candidate {candidate.registry_id} has no supported reasoning effort")
        wanted_index = order.index(target)
        return min(available, key=lambda item: abs(order.index(item) - wanted_index))

    def route(
        self,
        profile: TaskProfile,
        *,
        unavailable_registry_ids: Iterable[str] = (),
        previous_provider: str | None = None,
        performance_overrides: dict[str, dict[str, float]] | None = None,
    ) -> RouteDecision:
        unavailable = set(unavailable_registry_ids)
        excluded_models = set(profile.excluded_models)
        excluded_providers = set(profile.excluded_providers)
        quality_floor = self._quality_floor(profile)
        frontier_required = self._requires_frontier(profile)
        sandbox = self._sandbox(profile)
        overrides = performance_overrides or {}
        options: list[RouteDecision] = []
        for candidate in self.candidates:
            if not candidate.enabled or candidate.registry_id in unavailable:
                continue
            if candidate.model in excluded_models or candidate.provider in excluded_providers:
                continue
            if frontier_required and candidate.tier != "frontier":
                continue
            if sandbox not in candidate.sandboxes:
                continue
            measured = overrides.get(candidate.registry_id, {})
            prior_quality = float(candidate.task_quality.get(profile.task_family, candidate.task_quality.get("default", 0.0)))
            measured_runs = max(0.0, float(measured.get("runs", 0.0)))
            prior_weight = max(1.0, float(self.policy.get("catalog_prior_weight", 3.0)))
            if measured_runs > 0:
                quality = (prior_quality * prior_weight + float(measured.get("quality", prior_quality)) * measured_runs) / (prior_weight + measured_runs)
                reliability = (candidate.reliability * prior_weight + float(measured.get("reliability", candidate.reliability)) * measured_runs) / (prior_weight + measured_runs)
            else:
                quality = prior_quality
                reliability = candidate.reliability
            if quality < quality_floor:
                continue
            diversity_bonus = 0.0
            preference_bonus = 0.0
            reasons = [f"quality {quality:.3f} >= floor {quality_floor:.3f}"]
            if profile.preferred_provider and candidate.provider == profile.preferred_provider:
                preference_bonus = float(self.policy.get("preferred_provider_bonus", 0.02))
                reasons.append("preferred provider bonus")
            if previous_provider and candidate.provider != previous_provider:
                diversity_bonus = 0.04 if profile.required_provider_diversity else 0.015
                reasons.append("provider diversity bonus")
            if frontier_required:
                reasons.append("frontier tier required")
            cost = max(0.01, float(measured.get("cost_index", candidate.cost_index)))
            latency = max(0.01, float(measured.get("latency_index", candidate.latency_index)))
            # Quality and reliability dominate; cost and latency decide between candidates
            # that already clear the minimum quality gate.
            score = quality * 0.55 + reliability * 0.25 + diversity_bonus + preference_bonus - cost * 0.12 - latency * 0.08
            options.append(RouteDecision(candidate, self._reasoning(candidate, profile), sandbox, quality_floor, score, tuple(reasons)))
        if not options:
            raise LookupError("No available model satisfies the task quality, tier, provider, and sandbox constraints")
        # Higher score wins; deterministic tie breakers prefer lower cost/latency and stable registry id.
        return sorted(
            options,
            key=lambda item: (-item.score, item.candidate.cost_index, item.candidate.latency_index, item.candidate.registry_id),
        )[0]

    def ranked(self, profile: TaskProfile, **kwargs: Any) -> list[dict[str, Any]]:
        decisions: list[RouteDecision] = []
        unavailable: set[str] = set(kwargs.pop("unavailable_registry_ids", ()))
        while True:
            try:
                decision = self.route(profile, unavailable_registry_ids=unavailable, **kwargs)
            except LookupError:
                break
            decisions.append(decision)
            unavailable.add(decision.candidate.registry_id)
        return [item.to_dict() for item in decisions]

    def maximum_useful_parallelism(
        self,
        *,
        independent_units: int,
        provider_limits: dict[str, int] | None = None,
        configured_cap: int | None = None,
    ) -> int:
        if independent_units <= 0:
            return 0
        limits = provider_limits or {}
        total = 0
        by_provider: dict[str, int] = {}
        for candidate in self.candidates:
            if not candidate.enabled:
                continue
            by_provider[candidate.provider] = max(by_provider.get(candidate.provider, 0), candidate.max_parallel)
        for provider, limit in by_provider.items():
            total += min(limit, max(0, int(limits.get(provider, limit))))
        cap = int(configured_cap or self.policy.get("global_parallel_cap", 16))
        return max(1, min(independent_units, total or 1, cap))
