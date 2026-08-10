from __future__ import annotations

from typing import Any


def evaluate_budget(policy: dict[str, Any], usage: dict[str, Any], risk: str) -> dict[str, Any]:
    limits = policy.get(risk, {}) or policy.get("default", {}) or {}
    exceeded: list[str] = []
    percentages: dict[str, float] = {}
    mapping = {
        "implementation_runs": "implementation_runs",
        "independent_reviews": "independent_reviews",
        "repair_cycles": "repair_cycles",
        "closure_reviews": "closure_reviews",
        "escalation_runs": "escalation_runs",
        "input_tokens": "max_input_tokens",
        "output_tokens": "max_output_tokens",
        "cost": "max_cost",
    }
    for usage_key, limit_key in mapping.items():
        limit = limits.get(limit_key)
        if limit in (None, 0):
            continue
        actual = usage.get(usage_key, 0) or 0
        percentages[usage_key] = round(float(actual) / float(limit) * 100, 2)
        if actual > limit:
            exceeded.append(f"{usage_key}: {actual} > {limit}")
    stop_percent = float(limits.get("stop_at_budget_percent", 80))
    threshold_keys = {"input_tokens", "output_tokens", "cost"}
    approaching = [key for key, value in percentages.items() if key in threshold_keys and value >= stop_percent]
    return {
        "risk": risk,
        "passed": not exceeded and not approaching,
        "hard_exceeded": exceeded,
        "circuit_breaker_triggered": bool(approaching),
        "approaching_or_at_stop_threshold": approaching,
        "percentages": percentages,
        "decision": "QUARANTINE_TASK_AND_CONTINUE_QUEUE" if exceeded or approaching else "CONTINUE",
        "global_stop": False,
    }
