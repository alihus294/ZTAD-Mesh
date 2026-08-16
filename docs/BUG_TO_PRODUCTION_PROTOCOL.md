# Autonomous Fail-Closed Bug-to-Production Protocol — ZTAD Mesh 4.3.10

## Purpose

This document is the normative ZTAD implementation of the WorkshopOS Fail-Closed Bug-to-Production Protocol v1. It is optimized for a solo owner who may not be a programmer. Routine technical decisions belong to the agent/controller; owner involvement is limited to irreducible business intent, legal/compliance decisions, irreversible authorization, or protected production authority the agent does not possess.

The governing rule is: **no state advances because a model is confident. Every transition requires the exact evidence defined by policy and bound to the correct subject.** Missing, conflicting, incomplete, stale, or invalid evidence fails closed.

## Subject identity and provenance

The lifecycle subject is a structured provenance tuple, never a single mutable head SHA:

```text
protected_base_sha
→ pr_head_sha
→ reviewed_diff_hash
→ merged_main_sha + merge_method + merge_provenance
→ post_merge_ci_run_id
→ change_contract_hash + policy_bundle_hash + toolchain_hash
→ artifact_digest + artifact_identity + release_fingerprint
→ sbom_digest + provenance_digest + attestation_digest
→ production_release_id + deployed_revision
```

The PR head and merged-main SHA are allowed to differ. A squash, rebase, or merge transition requires a protected transformation record containing the reviewed PR head, reviewed diff hash, merged-main SHA, and transformation method. PR review and pre-merge CI evidence proves only the reviewed PR subject. Artifact, staging, release, production, and runtime evidence must bind the exact merged-main subject and its post-merge CI. A production validator must compare the deployed revision with the validated merged-main subject and artifact chain; it must never require deployed-main to equal an obsolete PR head.

Every material subject mutation increments `subject_epoch` and changes `subject_fingerprint`. Candidate, reviewed diff, contract, policy, toolchain, merged-main, artifact, release, and deployed-revision changes invalidate incompatible evidence and approvals. The controller resets the lifecycle to the earliest state that must be reproven, or writes `ROLLBACK_REQUIRED` after production exposure. Historical evidence remains retained but cannot satisfy a current gate.

## Authoritative lifecycle ledger

The controller-owned SQLite ledger is the security authority. JSON lifecycle files are verified exports only and carry an explicit claim boundary. Each ledger event is append-only and records the actor, timestamp, prior state, requested state, decision, required and accepted evidence IDs, rejected evidence, exact subject fingerprint and epoch, policy and toolchain hashes, risk and domain snapshots, prior event hash, and current state hash. Writes use an optimistic version check inside a durable transaction. Reads verify the global sequence and hash chain; reordered, deleted, replayed, tampered, stale, or unauthorized writes fail closed.

The scheduler's `DONE`, merge completion, deployment-command success, and model output are subordinate execution facts. They cannot write `CLOSED`, `POST_DEPLOY_VERIFIED`, production authority, or a no-code resolution into the authoritative ledger.

## Risk, domains, and evidence trust

One deterministic risk engine computes the effective level as the maximum of previous effective risk, requested risk, contract risk, path risk, operation risk, domain minimum, actual-diff risk, and runtime or platform escalation. The mapping is `R0/R1 → LOW`, `R2 → MEDIUM`, `R3 → HIGH`, and `R4 → CRITICAL`; automatic downgrade is prohibited. All active domain-profile checks are unioned across every declared domain, including in hotfix mode. Progressive-exposure requirements use the effective risk, not only the submitted label.

E0 and E1 are context only. E2 is local deterministic evidence and cannot grant protected authority. E3 through E6 require the configured trust root, valid signature or attestation, affirmative status, exact subject, non-expiry, valid producer class, and non-invalidation. Machine execution evidence additionally requires a registered executor, exact command and configuration fingerprints, working directory, timestamps, exit code, output hashes, immutable receipt, toolchain hash, result artifact hash, and subject epoch. A model-authored JSON record cannot manufacture a deterministic execution result.

## Terminal classes and exceptional flows

`RESOLVED_NO_CODE` is a distinct terminal class. It requires explicit non-code classification and authoritative proof, but does not require code-fix, artifact, staging, production, or post-deploy fields. Its lifecycle still replays through intake, source resolution, and classification before the terminal decision.

Rollback closure is a separate terminal class. App health alone is insufficient: database, financial, ZATCA, auth/tenant, provider, concurrency, and security domains require their corresponding reconciliation or containment proof. A deployment receipt never proves correctness. `PRODUCTION_RELEASED`, `POST_DEPLOY_VERIFIED`, and `CLOSED` remain separate claims.

Incident intake may contain the active exposure first. The controller may contain or roll back immediately, retain the original incident subject, and then require the full root-cause and remediation lifecycle. Database work may span `expand → compatible deploy → migrate/backfill → verify → contract`; each release subject retains its own compatibility and migration evidence. Performance-regression cases require baseline and candidate subjects, workload identity, environment, sample count, warmup, variance, threshold policy, regression budget, and result hashes.

## Authority hierarchy

1. governing agent/platform instructions;
2. current executable source/configuration for implemented behavior;
3. authorized runtime observations for mutable external state;
4. tests only for behavior they actually exercise;
5. accepted architecture/specification for intent;
6. reports, audits, plans, handoffs, roadmaps, summaries, and historical notes as non-authoritative context.

A repository may define a narrower canonical deployment/migration chain. ZTAD must use that chain and must never create an alternative production path. The WorkshopOS profile requires:

```text
DEPLOYMENT.md
→ infra/docs/runbook.md
→ .github/workflows/deploy.yml
```

The executable protected workflow is the final enforcement layer.

## Mandatory state machine

`policies/bug-to-production-policy.yaml` and `schemas/bug-lifecycle.schema.json` define the authoritative case state. Internal scheduler states are implementation details and cannot close the case.

Every code-fix case follows exactly:

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

A mandatory-gate failure before production becomes `BLOCKED`. After production exposure it becomes `ROLLBACK_REQUIRED`. A report proven to require no code/configuration fix may end as `RESOLVED_NO_CODE`.

`DONE` is intentionally not a bug-lifecycle state. Merge completion, an internal scheduler terminal state, successful deployment command, or model prose cannot substitute for `POST_DEPLOY_VERIFIED → CLOSED`.

## Intake and read-only investigation

Every report begins as `UNVERIFIED_REPORT`, never as `BUG`. Preserve the report verbatim and record repository, protected base SHA, local head SHA, branch, worktree state, environment, timestamp, claimed observed/expected behavior, and supplied evidence.

Investigation is read-only by default. Before classification/reproduction, do not modify source, tests, migrations, configuration, documentation to fit an assumption, production state, or external provider state.

## Source of truth and classification

Resolve governing sources before diagnosis. If primary authorities conflict and the conflict cannot be safely resolved, keep the conflict open; do not invent business intent.

Supported classifications include confirmed bug, expected behavior, environment issue, configuration issue, data issue, external dependency, user workflow issue, specification conflict, security incident, performance regression, and inconclusive. Only a classification that requires a code/configuration change continues through the implementation path.

## Reproduction and root cause

Prefer deterministic automated reproduction, then integration, browser/E2E, API, local runtime/database, sanitized logs/state evidence, and only bounded authorized production read-only evidence when necessary.

Record exact preconditions, action, input, expected result, actual result, environment, component, determinism/frequency, and evidence references.

Root cause must establish:

```text
Trigger
→ incorrect state / logic / assumption
→ propagation path
→ observable failure
```

Material competing hypotheses must be tested. “This file looks wrong”, “changing this makes the test pass”, or model confidence alone are not root-cause proof.

## Blast radius, invariants, risk, and plan

Before implementation, inspect direct/indirect callers, routes/controllers/services, schemas/types, data tables, RLS/tenant filters, auth/RBAC, caches, jobs, invoices/payments/ZATCA state, webhooks/providers, frontend consumers, migrations, deployment, and concurrency as applicable.

Define explicit invariants and classify risk. Plan the smallest correct change with expected files, required tests, forbidden unrelated scope, database/external effects, rollback/containment, and release risk. Material scope expansion requires replanning and revalidation.

## Clean isolation

Protected refs such as `main` are not development worktrees. Dirty/divergent owner work must remain byte-for-byte preserved. ZTAD creates an isolated clean worktree from the protected/current base and transfers only an explicit task-scoped allowlist. It must not stash, reset, commit, discard, or push unrelated owner work.

## Patch and regression proof

`PATCH_IMPLEMENTED` proves only that the bounded candidate exists and is bound to an exact head SHA, diff hash, Change Contract hash, policy bundle hash, and toolchain hash.

`REGRESSION_TEST_PROVEN` is a separate mandatory state. Required proof is:

```text
exact known-bad protected base + regression oracle → FAIL
exact candidate + same regression oracle → PASS
```

The RED→GREEN evidence must name the exact bad base and candidate SHA and prove the same oracle. Same-SHA/configuration FAIL→PASS is flaky/environment-dependent and remains blocking. No model judgment, feasibility exception, controller-reviewed waiver, or “equivalent evidence” may replace this code-fix gate. If the exact RED cannot be obtained safely, the lifecycle remains `BLOCKED` until the testability or source-of-truth problem is resolved.

Never loosen assertions, delete tests, add skip/xfail/focus/retry to hide failure, reduce coverage, change discovery/exclusion, mock away the real boundary, make CI non-blocking, swallow errors, or alter a guard merely to obtain green status.

## Targeted and regression validation

`TARGETED_VALIDATION_PASS` verifies the original reproduction, normal/boundary/invalid/error paths, retries, repeat actions, stale/partial state, role/tenant differences, provider failure/recovery, and concurrency where applicable.

Domain-specific mandatory evidence is added by policy:

- Database: migration necessity, canonical migration/ledger/history guard, fresh rebuild, RLS/tenant safety, indexes/constraints, bounded deterministic backfill, compatibility sequencing, and explicit recovery.
- Auth/RBAC/tenant: unauthenticated behavior, allowed/denied roles, cross-tenant denial, identifier tampering, server-side enforcement, and non-leaking failures.
- Financial/payments/invoices/tax: totals, VAT/tax, discounts, rounding, explicit zero, duplicate requests, retries, idempotency, concurrency, ledger consistency, refunds/returns where connected, legal transitions, and final-state immutability.
- ZATCA: high/critical risk; legal state machine, accepted/warning responses, retry/duplicate rules, reporting vs clearance, signed-document persistence, certificate/EGS state, cutover gates, immutability, and no production provider mutation during tests.
- Providers: local vs provider state, transport vs application failure, sandbox/mock, bounded idempotent retries, stale-output rejection, and safe reconciliation.
- Concurrency: parallel sessions, transactions/locks/unique constraints, retries, no duplicate durable side effect, and valid final state.

`REGRESSION_VALIDATION_PASS` then runs changed-unit, affected-module, adjacent-domain, integration/full-suite, type, lint, build, security, dependency audit, migration, documentation, i18n, and E2E/browser checks as applicable.

A required failing check cannot be ignored as “pre-existing” unless failure on the exact base is proven and repository policy explicitly handles it. The candidate must not worsen it.

## Diff forensics and independent adversarial review

`DIFF_FORENSICS_PASS` requires every changed file and line to be justified by the proven root cause and plan. Unexpected dependency/lockfile/config/permission/API/migration/generated changes, PII/secrets, debug output, tenant-scope changes, fail-open handling, and test weakening block progression.

`INDEPENDENT_REVIEW_PASS` requires a review session/context different from implementation. The reviewer attempts to disprove diagnosis, root cause, regression-test validity, minimality, preservation of unrelated behavior, security/data safety, concurrency/idempotency, and deployment assumptions. The review evidence must identify both session IDs and verdict exactly `PASS`; any blocker or material missing evidence prevents the transition. A model review verdict is not E6 approval or protected release authority.

## PR and protected CI

`CI_PASS` requires required platform checks on the exact final PR head. Local green does not replace protected CI, and green on an earlier SHA does not prove a later SHA. Branch/ruleset/review/environment protections must not be bypassed.

## Staging and release-candidate validation

`STAGING_PASS` uses the exact validated candidate/artifact. Staging uses separate/synthetic data, avoids real customer PII and unintended financial/ZATCA/provider side effects, verifies health, reproduces the original scenario, proves the bug absent, runs affected and adjacent critical workflows, inspects logs/errors, and verifies invariants.

Hotfix mode does not skip lifecycle states or reduce mandatory high-risk validation breadth. Database, auth/tenant, financial, ZATCA, provider, concurrency, and security changes retain their complete profile gates.

## Ready for owner release

`READY_FOR_OWNER_RELEASE` is the maximum state the coding agent may reach without protected production authority. It requires the applicable exact-subject evidence, including:

- release fingerprint;
- protected signed release manifest;
- SBOM;
- artifact attestation/provenance;
- exact tested artifact digest;
- protected CI/review evidence;
- rollback artifact/strategy;
- rollback rehearsal;
- observability readiness;
- synthetic transaction definition;
- staged restore/recovery evidence where required by risk.

Local files/templates are not substitutes for protected evidence. A strong-model or supervisor `APPROVE` is advisory only and cannot itself satisfy `PROTECTED_SUPERVISOR_APPROVAL`, create E6, or be mechanically translated into protected authority. A protected non-model controller must independently validate the configured protected authority and exact evidence subject before emitting E6. When an external gate is unavailable, create the request/template/local preparation and mark it `LOCAL_EVIDENCE_IS_NON_AUTHORITATIVE_UNTIL_PROMOTED_BY_A_PROTECTED_CONTROLLER`.

## Protected production release

`PRODUCTION_RELEASED` is separate from post-deployment correctness. It requires protected release authorization, exact reviewed main revision, exact validated artifact digest, and protected evidence that the release completed. `PROTECTED_RELEASE_AUTHORIZATION` must reflect an authorized protected production action; it cannot be self-issued by a model or created by merely wrapping a model recommendation in a signature.

ZTAD must never use direct production SQL, direct production SSH/VPS mutation, local production migrations, ad-hoc production service-role credentials, alternate deployment paths, mutable tags, or rebuilt unverified bytes.

For high/critical risk, use supported containment such as feature flags, blue/green, canary/rings, limited tenant/branch rollout, read-only mode, provider sandbox, or write gates.

## Post-deployment proof and rollback

`POST_DEPLOY_VERIFIED` requires production-safe proof that the original symptom no longer occurs and expected behavior now occurs. Separately verify exact running digest, application health, error rate/logs/metrics, latency, queues/backlog, database/provider errors, authorization/tenant anomalies, financial anomalies, ZATCA anomalies, duplicate side effects, synthetic transaction, and observation window as applicable.

A release-readiness result such as `PRODUCTION_VERIFIED` is evidence toward the `POST_DEPLOY_VERIFIED` claim only; it is not `CLOSED` and cannot skip the deterministic closure transition.

If the original problem remains, a new regression appears, health degrades without explanation, or security/data/tenant/financial/ZATCA safety cannot be proven, transition to `ROLLBACK_REQUIRED`.

Rollback closure requires protected evidence that rollback completed and post-rollback health is acceptable. Code rollback is not assumed to reverse database/data changes; migrations require an explicit recovery strategy.

## Completion rule

A code-fix case is `CLOSED` only after `POST_DEPLOY_VERIFIED`, or after required rollback has been proven complete and healthy. The evidence record preserves issue description, classification, base/final SHA, authoritative sources, reproduction, root cause, blast radius, risk, plan, changed files, RED proof, GREEN proof, targeted/full validation, security/domain evidence, independent review, CI, staging, migration/recovery evidence, release identifier/digest, production release evidence, post-deploy verification, and final state.

If any applicable mandatory item is not proven, the case is **not closed**.

## Owner responsibilities

The owner should only need to describe the problem, clarify genuinely ambiguous business intent, authorize protected production release, and make explicit business/legal decisions that cannot be safely derived. The owner should not need to choose files, tests, providers, retries, branches, refactors, or routine implementation details.

## Technical enforcement

The prompt is not the security boundary. Use protected `main`, PR-only merge, required CI, no force-push, protected production environment, production secrets unavailable to normal coding agents, exact-commit/digest release, protected migration workflow, automated security/tenant/database tests, staging validation, rollback evidence, and deployment/runtime evidence tied to exact revisions.

The platform must prevent bypass of critical rules.
