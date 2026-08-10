# Validation Report — ZTAD Mesh 4.2.0

## Decision

```text
OFFLINE_DISTRIBUTION_ACCEPTED_WITH_TARGET_HOST_ACCEPTANCE_REQUIRED
```

## Executed validation

| Gate | Result |
|---|---:|
| Unit/integration tests | 227/227 passed on Ubuntu and Windows with Python 3.11 and 3.13 |
| Offline deterministic/adversarial evals | 44/44 passed in the CI matrix |
| Selected critical mutation guards | 14/14 killed (100% for this selected set) |
| External fuzz cases | 43,000; 0 unhandled errors |
| Transactional ledger process writes | 320 across 5×64-writer rounds; 0 reported errors |
| Branch-aware total coverage | 80% including tests |
| Branch-aware toolkit coverage | 75% |
| Bundle structure | valid |
| Skills | 13, explicit-only |
| Policies | 26/26 declared and loadable with classified consumers |
| Schemas | 17 |
| Traceability requirements | 96 |
| Deterministic distribution | two complete builds compared byte-for-byte; Plugin and Marketplace archives validated |
| Source publication | exact 253-file archive and Git tree verified before publication |

## Cross-platform defects closed during publication

- A repository-wide `SOURCE_DATE_EPOCH=0` leaked into Windows dependency installation and produced an invalid pre-1980 ZIP timestamp. CI now derives the reproducible timestamp from the commit only for distribution-build steps.
- Text-mode patch transport on Windows converted Git patch framing from LF to CRLF. Patch generation, validation, and worktree application now preserve bytes and recover canonical Git framing before `git apply`.

## What the numbers do not prove

- The mutation score covers the 14 explicitly selected critical mutations, not every possible program mutation.
- Fuzzing used bounded generated inputs and is not a proof of absence of defects.
- Offline evals do not execute or rank hosted models.
- GitHub-hosted Windows runners do not prove the user's exact PowerShell, Codex, Git, credential, hook, or endpoint configuration.
- Passing repository CI does not prove branch protection, merge queue, deployment, canary, rollback, OIDC, or target-environment enforcement.

## Runtime dependency boundary

The public-source CI installs the exact reviewed locks on every matrix job: PyYAML 6.0.3, jsonschema 4.26.0, cryptography 50.0.0, pytest 9.1.1, coverage 7.15.4, pytest-cov 7.1.0, and hypothesis 6.165.2. Governed signing requires `cryptography >=50.0.0,<51`. The historical local-environment record under `validation/` remains provenance for the earlier offline run; it is not evidence that an unverified target host satisfies the current lock.

## Release condition

Do not grant merge or production authority until `docs/HOST_ACCEPTANCE.md` passes and the target platform emits exact-SHA, protected evidence for its controls.
