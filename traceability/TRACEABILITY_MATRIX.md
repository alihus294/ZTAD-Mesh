# ZTAD Mesh 4.3.7 Traceability Matrix

Active normative requirements: **119**.

This matrix maps the retained normative control catalogue to implementation and verification. Version 4.3 uses risk-proportional orchestration and model routing without weakening the existing authority, scope, evidence, recovery, and platform-boundary requirements. External controls are not considered active until target-platform evidence verifies them.

The WorkshopOS Fail-Closed Bug-to-Production Protocol v1 is mapped state-by-state in `traceability/BUG_TO_PRODUCTION_MAPPING.md`. That mapping is an explicit composition/refinement of the existing problem-intake, test-integrity, evidence, approval, release, and production controls; it does not relabel historical requirement counts or validation artifacts.

## Coverage by enforcement class

| Class | Count |
|---|---:|
| CONTROL_SPECIFIC | 87 |
| DETERMINISTIC | 5 |
| DETERMINISTIC_AND_EXTERNAL | 1 |
| DETERMINISTIC_AND_PLATFORM | 25 |
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
| 27. Autonomous problem-to-production intake | 23 |

## Interpretation

- `DETERMINISTIC`: enforced by local/protected code and tests.
- `PROTECTED_CONTROLLER`: requires a protected non-model controller and private-key boundary.
- `HOST_ENFORCED` / `HOST_ACCEPTANCE`: requires verified Codex host behavior.
- `PLATFORM_REQUIRED`: requires verified source-control, CI, artifact, deployment, or runtime enforcement.
- `CAPABILITY_GATED`: autonomy is capped until the capability is independently verified.
- `OPERATIONAL` / `DOCUMENTED_*`: governed by runbook, architecture, or scenario testing.

The row-level source of truth is `requirements.csv`; the state-to-control composition for the WorkshopOS protocol is `BUG_TO_PRODUCTION_MAPPING.md`.
