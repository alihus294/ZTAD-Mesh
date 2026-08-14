# Autonomous Fail-Closed Bug-to-Production Protocol — ZTAD Mesh 4.3.6

## Purpose

This protocol is the generic problem-to-production front end for ZTAD. It is designed for repository owners who may not be programmers and should not need to make routine implementation decisions. The agent/controller continues all safe work autonomously and asks the owner only for irreducible business intent or protected authority it does not possess.

The governing rule is: **a claim does not advance because a model is confident; it advances only when the required evidence exists and is bound to the correct subject.** Missing or conflicting evidence fails closed for the affected transition while unrelated safe work may continue.

## Authority hierarchy

1. governing agent/platform instructions;
2. current executable source/configuration for implemented behavior;
3. authorized runtime observations for mutable external state;
4. tests only for behavior they actually exercise;
5. accepted architecture/specification for intent;
6. reports, audits, plans, handoffs, and historical notes as non-authoritative context.

A repository may define a narrower canonical deployment/migration chain. ZTAD must use that chain and must not create an alternate production path.

## Problem-investigation lifecycle

Every reported problem starts as `UNVERIFIED_REPORT` and follows the deterministic `problem-case` contract:

```text
UNVERIFIED_REPORT
→ SOURCE_OF_TRUTH_RESOLVED
→ ISSUE_CLASSIFIED
→ BUG_REPRODUCED
→ ROOT_CAUSE_PROVEN
→ BLAST_RADIUS_MAPPED
→ CHANGE_PLANNED
→ REGRESSION_BASELINE_PROVEN
→ HANDOFF_READY
```

Non-code classifications may terminate as `RESOLVED_NO_CODE`. Missing protected facts/credentials/authority route to `WAITING_EXTERNAL_DEPENDENCY`. Unsafe or logically irrecoverable cases route to `QUARANTINED`.

### Intake and source truth

Preserve the original report without reinterpretation. Capture repository, exact base SHA, branch, worktree state, environment, timestamp, expected/observed behavior, and supplied evidence. Investigation is read-only until a code-affecting classification is proven.

Resolve authoritative sources and preserve conflicts. Do not invent a business decision when primary authorities conflict.

### Classification

Supported classifications are `CONFIRMED_BUG`, `EXPECTED_BEHAVIOR`, `ENVIRONMENT_ISSUE`, `CONFIGURATION_ISSUE`, `DATA_ISSUE`, `EXTERNAL_DEPENDENCY`, `USER_WORKFLOW_ISSUE`, `SPEC_CONFLICT`, `SECURITY_INCIDENT`, `PERFORMANCE_REGRESSION`, and `INCONCLUSIVE`.

Only a classification that actually requires a code/configuration change enters implementation.

### Reproduction and root cause

Prefer deterministic regression reproduction, then integration/E2E/API/local-runtime proof, then sanitized read-only runtime evidence when authorized. Record exact preconditions, action, input, expected result, actual result, environment, determinism/frequency, and evidence refs.

Root cause must establish trigger → incorrect state/logic/assumption → propagation → observable failure and must account for material alternative hypotheses. “Changing this makes a test pass” is not root-cause proof.

### Blast radius and plan

Map direct/indirect callers, schemas/types, data, authorization/tenant boundaries, side effects, queues/jobs, providers, concurrency, frontend consumers, deployment and migration surfaces as applicable. Record invariants and deterministic risk.

Plan the smallest correct change. Material scope expansion, migrations, contract/permission/financial/deployment changes require reclassification/replanning rather than silent widening.

### Clean isolation

`main`/protected refs are not development worktrees. If the user worktree is dirty or divergent, preserve it untouched and build an isolated clean worktree from the protected/current base. Transfer only an explicit task-scoped file allowlist. Do not stash, reset, commit, discard, or push unrelated user work.

### Regression proof

Preferred proof is:

```text
known-bad exact base + regression oracle → FAIL
exact candidate + same oracle → PASS
```

A same-SHA/configuration FAIL→PASS rerun is flaky/environment-dependent, not RED→GREEN evidence. Never weaken assertions, delete coverage, mock away the failing boundary, skip a required check, or modify a guard merely to make it green.

## Governed ZTAD handoff

Only `HANDOFF_READY` problem evidence may generate a Change Contract for a code-affecting problem. The generated contract carries the problem-case fingerprint and enters the existing ZTAD risk-adaptive delivery engine:

```text
Change Contract
→ deterministic repository index
→ risk-proportional isolated model topology
→ deterministic integration/scope checks
→ machine checks
→ actual-diff risk reclassification
→ independent adversarial review
→ protected exact-SHA approval/CI
→ exact artifact + release evidence
→ staging/canary/rollback controls
→ protected production release
→ production health + synthetic transaction + observation window
→ DONE or ROLLBACK
```

R0/R1 use Luna writer + deterministic gates + one independent Sol guard. R2 remains bounded with Luna preferred writer and Terra support/fallback. R3/R4 use the full mesh. Every Sol invocation remains capped at HIGH reasoning. A model never grants merge/deploy/production authority.

## Validation layers

Run the applicable sequence without downgrading failures:

1. regression/targeted tests;
2. affected module/domain tests;
3. adjacent-domain tests;
4. integration/full suite;
5. type/lint/build;
6. dependency/security audit;
7. migration/ledger/history/fresh-rebuild checks;
8. documentation/i18n checks;
9. browser/E2E using synthetic data only;
10. concurrency tests where shared durable state is involved;
11. diff forensics;
12. independent adversarial review;
13. protected CI on the exact final PR head.

A purported pre-existing failure must be proven against the base commit and handled according to repository policy; it is never silently ignored.

## High-risk domain profiles

### Database

Prove migration necessity, canonical migration location/ledger/history guard, fresh rebuild, RLS/tenant boundaries, indexes/constraints, bounded deterministic backfill, retries, compatibility sequencing, and explicit recovery. Prefer expand → compatible deploy → migrate/backfill → verify → contract. Code rollback does not imply data rollback.

### Authentication / authorization / tenant isolation

Prove unauthenticated behavior, allowed and denied roles, Tenant A vs Tenant B isolation, identifier tampering resistance, server-side enforcement, branch restrictions where applicable, and non-leaking failure responses. UI hiding is never the security boundary.

### Payments / invoices / tax / financial state

Prove totals, VAT/tax, discounts, rounding, explicit zero semantics, duplicate requests, retry/idempotency, concurrent requests, ledger consistency, refunds/returns when connected, legal state transitions, final-state immutability, and no duplicate durable side effects.

### ZATCA / legally significant provider state

Treat as R3+ and usually critical when persistent/legal state is affected. Prove state transitions, accepted/warning responses, retry/duplicate rules, reporting vs clearance, signed-document persistence, certificate/EGS state, cutover gates, immutability, and no accidental legacy resubmission. Tests must not mutate real production provider state.

### External providers

Distinguish local from provider state and transport failures from application defects. Use sandbox/mock where possible, bound and make retries idempotent, reject stale output, reconcile safely, and never infer provider success from a local row/model statement.

### Concurrency

Reproduce with parallel sessions where possible. Verify transactions/locks/unique constraints/retries, no duplicate durable side effect, and valid deterministic final state.

## Independent review and diff forensics

Every changed line must be justified by the proven root cause/plan. Investigate unexpected lockfile/dependency/config/permission/API/migration/generated-file changes, debug output, secrets/PII, fail-open error handling, tenant-scope changes, and test weakening.

The independent reviewer must attempt to falsify diagnosis, root cause, regression-test validity, minimality, security/data invariants, concurrency/idempotency, and deployment assumptions. Same implementation session cannot approve the exact candidate. Protected approval binds task, base/head SHA, diff hash, contract, evidence IDs, policy/toolchain, artifact subject, and review identity.

## Release evidence

Before promotion, the exact candidate must have the applicable protected evidence. Local files/templates are not substitutes for protected evidence. Required release subjects include:

- deterministic release fingerprint bound to exact manifest subject;
- protected signed release manifest;
- SBOM;
- artifact provenance/attestation;
- exact tested artifact digest;
- protected CI/review evidence;
- rollback artifact/strategy;
- staged restore rehearsal for applicable high-risk work;
- rollback rehearsal;
- observability readiness and synthetic transaction definition;
- protected release authorization;
- production runtime health, synthetic transaction, and observation window after release.

If an external gate is unavailable, create the request/template/local preparation and mark it `LOCAL_EVIDENCE_IS_NON_AUTHORITATIVE_UNTIL_PROMOTED_BY_A_PROTECTED_CONTROLLER`. Never fabricate completion.

## Production boundary

Production release uses only the repository’s canonical protected workflow from the exact reviewed main revision and exact validated digest. ZTAD must not use direct production SQL, direct production SSH mutation, local production migrations, ad-hoc service-role credentials, alternate deployment routes, mutable tags, or rebuilt unverified bytes.

For high/critical risk prefer supported containment such as feature flags, blue/green, canary, tenant/branch-limited rollout, provider sandbox, read-only mode, or write gates.

After authorized deployment, prove the original symptom is gone and expected behavior occurs; separately verify adjacent health, errors, metrics, queues, DB/provider failures, authorization/tenant anomalies, financial/ZATCA anomalies, and duplicate side effects. Unresolved critical uncertainty routes to containment/rollback.

## Never-idle / owner interaction

Routine implementation choices belong to the agent/controller, not the owner. Missing local files are created as non-authoritative local evidence. Dirty worktrees are isolated, not presented to the owner for file selection. Provider/tool failures use bounded retry followed by materially different provider/resource/context/strategy or deterministic local verification. Exhausted repair budgets quarantine only the affected task while unrelated safe work continues.

Ask the owner only for contradictory/undefined business intent, unavailable protected credentials/authority, legal/compliance decisions, or explicit irreversible/destructive authorization. Prepare the evidence-bound request before asking.

## Completion rule

Repository-side work is not `DONE` merely because code/tests/CI are green. The maximum truthful state is capped by the strongest evidence actually present. Missing release fingerprint, signed manifest, SBOM/attestation, restore/rollback rehearsal, observability/synthetic evidence, runtime health, protected supervisor/release approval, migration-ledger proof, dependency-audit proof, provider structured output, clean protected-base isolation, or exact-subject evidence prevents any state that requires it.
