---
name: finding-verification-repair
description: Falsify proposed review findings, classify them, and repair only confirmed defects within bounded cycles. Use only when explicitly invoked for findings on an exact SHA; do not repair speculative concerns.
---


# Verification sequence

1. Validate the finding schema, referenced SHA, location, rule, and evidence identifiers.
2. Attempt to falsify the claim before accepting it.
3. Classify each finding as `CONFIRMED`, `FALSIFIED`, or `INCONCLUSIVE`.
4. Repair only `CONFIRMED` findings. Add a failing regression test first when feasible.
5. Apply the smallest fix. Do not include unrelated refactoring.
6. Re-run targeted and impacted deterministic checks, then protected CI as required.
7. Closure review receives only the original finding, fix diff, regression test, and new evidence.

# Circuit breakers

After two worker repair cycles, automatically change strategy and escalate to the strong supervisor. If the supervisor takes over implementation, require a fresh closure reviewer. Scope expansion, protected components, flaky oracles, stale evidence, or budget pressure route the task to `AUTO_REPLAN`, `CLEAN_RECONSTRUCTION`, `WAITING_RETRY`, or `QUARANTINE_AND_CONTINUE`; they never stop the global queue. `INCONCLUSIVE` on `R3/R4` triggers stronger protected evidence or reversible containment rather than speculative approval.

# Output

Return validated finding states, repair-cycle count, patch path if any, evidence identifiers, scope changes, and the deterministic next action.
