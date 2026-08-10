# Validation Report — ZTAD Mesh 4.2.0

## Decision

```text
OFFLINE_DISTRIBUTION_ACCEPTED_WITH_TARGET_HOST_ACCEPTANCE_REQUIRED
```

## Executed validation

| Gate | Result |
|---|---:|
| Unit/integration tests | 223/223 passed |
| Offline deterministic/adversarial evals | 44/44 passed |
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

## What the numbers do not prove

- The mutation score covers the 14 explicitly selected critical mutations, not every possible program mutation.
- Fuzzing used bounded generated inputs and is not a proof of absence of defects.
- Offline evals do not execute or rank hosted models.
- Local checks are not protected CI evidence.
- The build host did not provide Codex host execution, native Windows acceptance, GitHub rulesets, merge queue, deployment, canary or rollback.

## Runtime dependency boundary

The build host ran Python 3.13.5 with PyYAML 6.0.3, jsonschema 4.26.0 and cryptography 46.0.4. The release requires `cryptography >=48.0.1,<51` for governed signing. Network resolution prevented constructing the isolated target-version environment in this build host. Therefore evidence-signing behavior was tested functionally, but must be rerun on the target host with the required cryptography range before governed signing is enabled.

## Release condition

Do not grant merge or production authority until `docs/HOST_ACCEPTANCE.md` passes and the target platform emits exact-SHA, protected evidence for its controls.
