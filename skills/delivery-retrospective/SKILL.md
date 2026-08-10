---
name: delivery-retrospective
description: Analyze completed machine-generated delivery evidence and metrics to improve policies, prompts, tests, and budgets. Use only for an explicit retrospective or calibration review; never weaken non-waivable controls from anecdotal results.
---


# Inputs

Evidence ledgers, incidents, platform records, model registry entries, flow metrics, and token/cost reports. Do not reconstruct metrics from agent memory.

# Procedure

1. Measure lead time, deployment frequency, recovery, change failure/rework, WIP, queue time, escaped defects, flaky tests, rollback success, finding precision, unsupported claims, unauthorized-action attempts, repair cycles, and tokens/cost per merged change.
2. Segment by risk, repository, model/prompt version, and change type.
3. Identify the largest measured bottleneck or control failure.
4. Propose one bounded experiment with owner, expected effect, rollback condition, and evaluation window.
5. Never lower secret boundaries, production authority, SHA/digest binding, hard risk floors, or control-plane protection.
6. Model upgrades require evals, repeated-run variance analysis, shadow comparison, and approval.
7. A proposal becomes active only through the high-risk control-plane change path.

# Output

Return factual metrics, coverage limitations, one prioritized experiment, and any control escalation. Do not claim causality without evidence.
