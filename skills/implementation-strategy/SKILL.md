---
name: implementation-strategy
description: Create a bounded implementation strategy for an approved Change Contract before editing behavior. Use only after deterministic risk classification; do not resolve ambiguous requirements or edit code in this skill.
---


# Authority

Read-only planning. Do not modify files, approve work, lower risk, or claim repository facts without tool evidence.

# Procedure

1. Read the validated contract, risk report, capability report, architecture/invariants, and deterministic context manifest.
2. Verify every referenced file, symbol, API, test, command, and dependency with repository tools. Mark missing items `UNVERIFIED_REFERENCE`.
3. Propose the smallest slice satisfying acceptance criteria while preserving invariants.
4. State expected and prohibited file changes, tests and negative cases, observability, rollback, and scope-reset triggers.
5. Separate repository facts, requirement facts, assumptions, proposals, and known unknowns.
6. Resolve non-destructive ambiguity with the safe-assumption policy: preserve current behavior, preserve compatibility, avoid permission expansion and deletion, prefer the smallest reversible change, and keep uncertain activation behind a disabled feature flag. If an external business fact is indispensable, route only this task to `WAITING_EXTERNAL_DEPENDENCY`.
7. Return `RISK_ESCALATION_REQUESTED` when the solution reveals higher risk.
8. Exclude unrelated refactoring.

# Output

Return an `agent-result` envelope with `PLAN_READY`, `SAFE_ASSUMPTION_PLAN_READY`, `WAITING_EXTERNAL_DEPENDENCY`, or `RISK_ESCALATION_REQUESTED`. Include evidence references and the next schedulable action. Do not return a patch.
