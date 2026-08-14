# Validation Report — ZTAD Mesh 4.3.8

## Decision

```text
CANDIDATE_REQUIRES_EXACT_COMMIT_VALIDATION_AND_TARGET_HOST_ACCEPTANCE
```

## Evidence semantics

Release identity is derived from `VERSION` and checked against every current package, runtime, release-facing, operational, and normative identity surface. Identity is not validation evidence by itself.

This source document does not self-attest the 4.3.8 release. Current-release repository evidence becomes authoritative only when protected GitHub CI succeeds on the exact final commit. Artifact/release evidence becomes authoritative only when the immutable release workflow binds the exact commit and exact archive digests. Target-host/provider/deployment/runtime claims remain external evidence classes.

Historical measurements are never silently re-attributed to 4.3.8.

| Evidence source | What it can establish |
|---|---|
| `VERSION` and identity verification | Current source/release naming consistency |
| Local deterministic tests | E2 facts for their exact checkout only |
| Historical validation artifacts | Only the exact checks/release recorded by each artifact |
| Protected GitHub Actions bound to an exact commit | Authoritative repository CI evidence for that commit |
| Immutable tag, release assets, checksums/provenance bound to an exact SHA | Release/artifact evidence for that SHA |
| Protected deployment/runtime controllers | Staging, release, rollback, health, synthetic, and observation evidence only |

## 4.3.8 protocol acceptance targets

The deterministic lifecycle introduced in v4.3.7 remains unchanged. The 4.3.8 candidate must prove that all packaged skill instructions match those deterministic gates without a softer prompt-level escape hatch:

- problem investigation and finding repair cannot replace exact protected bad-base/exact-candidate same-oracle RED→GREEN with model judgment, “equivalent evidence”, feasibility wording, or controller-reviewed exception;
- strong-model/supervisor `APPROVE` is advisory only and cannot itself satisfy `PROTECTED_SUPERVISOR_APPROVAL`, create E6, or be mechanically translated into protected merge/release/production authority;
- independent review must identify distinct implementation/review sessions and emit exact lifecycle verdict `PASS` before `INDEPENDENT_REVIEW_PASS`;
- `PRODUCTION_VERIFIED` readiness is evidence toward `POST_DEPLOY_VERIFIED` only and cannot substitute for the separate deterministic `POST_DEPLOY_VERIFIED → CLOSED` transition;
- all v4.3.7 lifecycle, high-risk domain, E6 protected approval, packaging, CI, and release controls remain intact.

The authoritative reported-defect lifecycle remains:

```text
UNVERIFIED_REPORT
→ SOURCE_OF_TRUTH_RESOLVED
→ ISSUE_CLASSIFIED
→ BUG_REPRODUCED
→ ROOT_CAUSE_PROVEN
→ BLAST_RADIUS_MAPPED
→ CHANGE_PLANNED
→ PATCH_IMPLEMENTED
→ REGRESSION_TEST_PROVEN
→ TARGETED_VALIDATION_PASS
→ REGRESSION_VALIDATION_PASS
→ DIFF_FORENSICS_PASS
→ INDEPENDENT_REVIEW_PASS
→ CI_PASS
→ STAGING_PASS
→ READY_FOR_OWNER_RELEASE
→ PRODUCTION_RELEASED
→ POST_DEPLOY_VERIFIED
→ CLOSED
```

## Historical evidence boundary

The immutable predecessor `v4.3.7` is historical evidence for its exact source SHA and published assets. Earlier v4.3.x and v4.2 validation records likewise retain only their original subjects. Their numeric test, coverage, fuzz, mutation, package, and concurrency results are not copied here as 4.3.8 claims.

The 4.3.8 candidate must pass the repository's current source identity gate, compile gate, full unit/integration suite, ResourceWarning/unraisable protections, offline evals, bundle validation, policy wiring, traceability validation, deterministic distribution builds, exact Plugin and Marketplace archive validation, and packaged regressions. Protected PR CI must run on the final PR head; post-merge CI must run on the exact merged main SHA before release publication can be treated as current evidence.

## What repository validation cannot prove

- Hosted model/provider credentials or capacity.
- Target Codex hook trust/sandbox behavior beyond host acceptance.
- GitHub rulesets or merge queue merely from source files.
- Production credentials being unavailable unless the host/platform proves that boundary.
- Staging or production deployment success from a local adapter/template.
- Production correctness merely because deployment completed.
- Restore/rollback effectiveness without the applicable rehearsal evidence.
- Production health, synthetic transaction, or observation window without exact runtime evidence.

## Runtime dependency boundary

CI installs the exact reviewed dependency locks and runs dependency consistency checks. Dependency-audit and migration-ledger failures remain blocking until repaired on the exact protected-base candidate; they cannot be dismissed by changing or weakening their guards.

## Release condition

Do not grant production authority from a model, local file, scheduler terminal state, or repository test result. For a reported defect the strongest truthful lifecycle state is capped by the exact evidence actually present. `CLOSED` requires `POST_DEPLOY_VERIFIED`, or protected evidence that a required rollback completed and restored acceptable health.
