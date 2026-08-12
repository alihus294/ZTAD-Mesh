# Validation Report — ZTAD Mesh 4.3.0

## Decision

```text
OFFLINE_DISTRIBUTION_ACCEPTED_WITH_TARGET_HOST_ACCEPTANCE_REQUIRED
```

## Dedicated v4.3 final validation

A clean candidate was validated on GitHub Actions across Ubuntu and Windows with Python 3.11 and 3.13. All four matrix jobs completed successfully.

| Gate | Result |
|---|---:|
| Unit/integration tests | 263/263 passed |
| Cross-platform matrix | Ubuntu 3.11, Ubuntu 3.13, Windows 3.11, Windows 3.13 — all passed |
| Offline deterministic/adversarial evals | 44/44 passed |
| Critical v4.3 control-path stress | 29/29 tests × 5 consecutive runs passed |
| Selected critical mutation guards | 14/14 killed; 0 survived; 0 invalid |
| External fuzz cases | 43,000; 0 reported errors |
| Transactional ledger process writes | 320 across 5×64-writer rounds |
| Branch-aware toolkit coverage | 76% total; mesh plan 90%, mesh runtime 78%, mesh store 84%, model router 88% |
| Bundle structure | valid |
| Skills | 13, explicit-only |
| Policies | 26/26 declared/found; policy wiring valid |
| Schemas | 17 |
| Traceability requirements | 96 |
| Deterministic distribution | two complete v4.3.0 builds compared byte-for-byte |
| Plugin and Marketplace archives | both validated successfully |
| Source preservation | clean after validation, fuzz, mutation, and distribution work |

The dedicated validation run was executed on the code candidate before the final documentation synchronization. A test-owned SQLite connection produced one `ResourceWarning` during the coverage pass despite all gates succeeding. The final branch closes that connection deterministically and adds a CI gate that treats `ResourceWarning` in the critical v4.3 control paths as an error.

## v4.3 behaviors explicitly covered

- R0/R1 normal execution uses Luna implementation plus exactly one independent Sol final guard.
- Sol reasoning never exceeds HIGH.
- R2 uses the bounded topology rather than the full high-risk mesh.
- R3/R4 retain the full independent mesh.
- Upward actual-diff risk invalidates the lower-risk path and submits a stronger replan.
- Blocking P0/P1 findings cannot silently pass.
- Schema-valid output does not become perfect implementation quality by itself.
- Benchmark abstention/refusal cannot receive a perfect capability score.
- Performance overrides are context-bound and require the configured minimum observation count.
- Exhausted repair budget quarantines rather than leaving an orphan repair state.
- Continuity reaches supervisor review without auto-granting `MERGE_READY`.
- CLI import-shadowing regression is guarded structurally.

## What the numbers do not prove

- The mutation score covers the 14 selected critical mutations, not every possible mutation.
- Fuzzing is bounded generated testing, not proof of absence of defects.
- Offline evals do not execute or rank hosted models.
- GitHub-hosted runners do not prove a target workstation's Codex, credentials, hooks, endpoint controls, or provider authentication.
- Passing repository CI does not prove branch protection, merge queue, deployment, canary, rollback, OIDC, or production-environment enforcement.

## Runtime dependency boundary

CI installs the exact reviewed dependency locks and runs `pip check` on every matrix job. Governed signing and all target-host capabilities remain subject to host acceptance rather than inference from source configuration.

## Release condition

Do not grant merge/deployment authority inside ZTAD itself until `docs/HOST_ACCEPTANCE.md` and target-platform gates emit exact-subject protected evidence. Repository CI proves the source/test state for its exact commit; it does not grant production authority.
