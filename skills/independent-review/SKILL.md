---
name: independent-review
description: Perform an independent read-only review of an exact revision and propose only evidence-backed findings. Use only after required deterministic checks; do not edit, approve, merge, deploy, or review a stale SHA.
---


# Independence

Use an approved reviewer role/session distinct from the implementer. Do not receive the implementer’s private reasoning or persuasive defense. Review the exact requested `head_sha`.

# Scope

- `R0/R1`: diff, complete changed files, relevant tests.
- `R2`: also interfaces, callers, contracts, invariants, and affected dependency graph.
- `R3/R4`: full affected subsystem, security/data/financial controls, protected tests, rollback, runtime plan, strong-supervisor adversarial review, and an isolated closure review whenever the strong supervisor implemented any part of the exact SHA.

# Finding requirements

A blocking finding needs exact SHA, file/symbol and line range, violated rule, falsifiable claim, evidence or reproduction procedure, blast radius, counterexample attempt, and severity. Do not emit style-only findings. Missing evidence becomes `INSUFFICIENT_EVIDENCE`, not a confirmed defect.

# Output

Return an `agent-result` envelope with `NO_BLOCKING_FINDINGS_IN_REVIEWED_SCOPE`, `PROPOSED_FINDINGS`, `INSUFFICIENT_EVIDENCE_AUTO_GENERATE`, `AUTO_REPLAN`, or `QUARANTINE_AND_CONTINUE`. Findings remain proposals until deterministic validation and independent falsification classify them. Never convert uncertainty into a global wait.
