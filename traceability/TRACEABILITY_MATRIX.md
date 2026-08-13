# ZTAD Mesh 4.3.2 Traceability Matrix

Active normative requirements: **96**.

This matrix maps the retained normative control catalogue to implementation and verification. Version 4.3 uses risk-proportional orchestration and model routing without weakening the 96 existing authority, scope, evidence, recovery, and platform-boundary requirements. External controls are not considered active until target-platform evidence verifies them.

## Coverage by enforcement class

| Class | Count |
|---|---:|
| CONTROL_SPECIFIC | 87 |
| DETERMINISTIC | 5 |
| DETERMINISTIC_AND_EXTERNAL | 1 |
| DETERMINISTIC_AND_PLATFORM | 2 |
| HOST_AND_DETERMINISTIC | 1 |

## Coverage by section

| Section | Requirements |
|---|---:|
| 5. Immutable change contract | 1 |
| 6. Deterministic risk | 1 |
| 12. Provider execution | 1 |
| 13. Worktrees and patch flow | 1 |
| 14. Machine-check gate | 2 |
| 15. Independent review | 1 |
| 18. Loop prevention and recovery | 1 |
| 24. Validation and release | 1 |
| 26. Normative control catalogue | 87 |

## v4.3 orchestration invariants

- R0/R1 guarded fast path preserves deterministic indexing, isolated writing, integration/checks, actual-risk classification, and independent review while removing redundant model fan-out.
- R2 bounded mesh preserves the same authority boundaries with limited focused context/review.
- R3/R4 retain the full independent mesh.
- Upward actual-diff risk invalidates a weaker topology before approval.
- The Sol reasoning ceiling is HIGH for every role.
- Performance-learning changes affect routing only; they do not create evidence or authority.

## Interpretation

- `DETERMINISTIC`: enforced by local/protected code and tests.
- `PROTECTED_CONTROLLER`: requires a protected non-model controller and private-key boundary.
- `HOST_ENFORCED` / `HOST_ACCEPTANCE`: requires verified Codex host behavior.
- `PLATFORM_REQUIRED`: requires verified source-control, CI, artifact, deployment, or runtime enforcement.
- `CAPABILITY_GATED`: autonomy is capped until the capability is independently verified.
- `OPERATIONAL` / `DOCUMENTED_*`: governed by runbook, architecture, or scenario testing.

The row-level retained normative source of truth is `requirements.csv`; v4.3 does not delete or weaken those requirements.
