---
name: zero-trust-delivery
description: Run autonomous fail-closed problem-to-production delivery with read-only diagnosis, clean isolation, exact lifecycle states, regression proof, risk-proportional implementation, independent review, protected release, recovery, and post-deploy verification.
---

# Authority

Models are untrusted compute. They may investigate, plan, review, or create bounded patches. Deterministic controllers own state, scope, checks, evidence, fingerprints, approvals, and eligibility. Protected platforms own CI, merge, signing/attestation, deployment, and production truth. No model statement can become approval or authoritative evidence.

# Owner interaction contract

The owner may be a non-programmer. Continue routine technical work autonomously to the last safe practical result. Do not ask the owner to choose files, retries, providers, test commands, refactors, ordinary implementation details, or how to recover from a dirty/divergent worktree.

Ask only when a fact cannot be safely derived or an action requires authority the agent does not possess, such as contradictory business intent, missing protected credentials, irreversible/destructive authorization, protected production release approval, or a legal/compliance decision. Prepare the exact request and evidence first.

# Normative bug-to-production lifecycle

For every reported defect, `policies/bug-to-production-policy.yaml` and `schemas/bug-lifecycle.schema.json` are the authoritative case-state contract. Internal scheduler states are implementation details and can never substitute for the bug lifecycle.

Every code-fix case must progress, without skipping states, through:

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

A failed mandatory transition becomes `BLOCKED` before production exposure and `ROLLBACK_REQUIRED` after production exposure. A non-code classification may end as `RESOLVED_NO_CODE`.

`DONE` is not a valid bug-lifecycle state. A scheduler task, merge, release command, model response, or deployment command may finish while the bug case remains open. A code-fix case is closed only after `POST_DEPLOY_VERIFIED → CLOSED`.

# End-to-end sequence

1. Validate the installed bundle and policy wiring. Run host acceptance, provider probes, repository audit, and dry-run where available.
2. Invoke `$problem-investigation` for every reported defect. A report begins as `UNVERIFIED_REPORT`, never as a bug.
3. Initialize the exact bug lifecycle and bind it to the problem case. For WorkshopOS use profile `workshopos`, which requires the canonical production chain `DEPLOYMENT.md → infra/docs/runbook.md → .github/workflows/deploy.yml`.
4. Preserve the report verbatim and resolve authoritative sources read-only. Classify expected behavior, environment/configuration/data/provider issues, spec conflicts, security incidents, performance regressions, and confirmed defects separately.
5. Preserve any dirty or divergent user worktree untouched. Create a clean isolated worktree from the protected/current base and transfer only task-scoped changes by an explicit file allowlist. Never commit, discard, stash, or push unrelated user changes.
6. For a code-affecting defect, reproduce or otherwise prove it, falsify material alternative hypotheses, prove the causal root, map blast radius/invariants, classify risk/domains, and write the smallest-change plan before implementation.
7. Build/validate the Change Contract only after `CHANGE_PLANNED`. Bind the exact candidate SHA, diff hash, Change Contract hash, policy bundle hash, and toolchain hash before `PATCH_IMPLEMENTED`.
8. `PATCH_IMPLEMENTED` proves only that the bounded candidate exists. It does not prove the fix.
9. `REGRESSION_TEST_PROVEN` requires the same regression oracle to prove `FAIL` on the exact protected known-bad base and `PASS` on the exact candidate. Same-SHA/configuration FAIL→PASS is flaky/environment-dependent and remains blocking. Never weaken, skip, quarantine, xfail, mock away, or make non-blocking a required test.
10. `TARGETED_VALIDATION_PASS` runs the original reproduction, nearest edge/error/retry/concurrency cases, and all applicable domain profile checks. Database work requires migration ledger/history guard, fresh rebuild, and recovery evidence. Auth/tenant, financial, ZATCA, provider, and concurrency work require their dedicated evidence.
11. `REGRESSION_VALIDATION_PASS` runs affected-module, adjacent-domain, integration/full-suite, type/lint/build/security/migration/docs/i18n/E2E checks as applicable. A purported pre-existing failure must be proven against the base and cannot be silently downgraded.
12. `DIFF_FORENSICS_PASS` requires every changed line to be justified. Unexpected dependencies, lockfiles, configuration, permissions, API contracts, tenant scope, migrations, PII/secrets, fail-open handling, debug output, generated noise, or test weakening must be removed or replanned.
13. `INDEPENDENT_REVIEW_PASS` requires a different review session/context from implementation and verdict `PASS`. The reviewer attempts to falsify diagnosis, root cause, test validity, minimality, security/data invariants, concurrency/idempotency, and deployment assumptions.
14. `CI_PASS` requires protected CI and required checks on the exact final PR head. Local green and earlier-commit green do not satisfy this state.
15. Build once and promote by exact digest. `STAGING_PASS` uses the exact candidate/artifact, proves the original problem scenario, adjacent critical workflows, health, logs/errors, and invariants using synthetic/non-customer data and provider sandboxes where possible.
16. `READY_FOR_OWNER_RELEASE` requires release fingerprint, protected signed manifest, SBOM, attestation/provenance, rollback readiness/rehearsal, observability readiness, and synthetic transaction definition. R3/R4 additionally require restore/recovery evidence defined by policy.
17. The agent continues all local and non-protected work autonomously until `READY_FOR_OWNER_RELEASE`. It asks the owner only for the protected production authority that cannot be derived or self-issued.
18. `PRODUCTION_RELEASED` requires protected release authorization, exact reviewed main revision, exact validated digest, and protected evidence that the production release completed. No direct production SQL, SSH mutation, local production migration, alternate deploy path, mutable tag, or rebuilt unverified bytes.
19. `POST_DEPLOY_VERIFIED` is a separate claim from deployment. It requires production-safe proof that the original symptom is gone and expected behavior occurs, plus runtime health, synthetic transaction, observation window, and adjacent safety checks.
20. `CLOSED` is allowed only from `POST_DEPLOY_VERIFIED`, or after a required rollback has itself been proven complete and healthy. Any unresolved security/data/auth/financial/ZATCA/production uncertainty routes to rollback/containment.

# Minimal owner entry

The owner only describes what happened and, if known, what was expected. The agent/controller performs the routine technical decisions.

```text
python3 <PLUGIN_ROOT>/scripts/ztad.py problem-init --repo <REPOSITORY> --protected-ref main --report "<what happened>" --expected "<expected behavior>"
python3 <PLUGIN_ROOT>/scripts/ztad.py problem-isolate --case <CASE.json>
python3 <PLUGIN_ROOT>/scripts/ztad_bug_lifecycle.py init --problem-case <CASE.json> --output <LIFECYCLE.json> --profile workshopos --remote-repository alihus294/WorkshopOS
```

After each proven gate, the controller advances the lifecycle with exact evidence:

```text
python3 <PLUGIN_ROOT>/scripts/ztad_bug_lifecycle.py advance --lifecycle <LIFECYCLE.json> --target <NEXT_STATE> --problem-case <CASE.json> --evidence <EVIDENCE_DIR> --trust-roots <TRUST_ROOTS.json>
```

# Never-idle recovery

- Missing local file/report/template: create it and label it `LOCAL_EVIDENCE_IS_NON_AUTHORITATIVE_UNTIL_PROMOTED_BY_A_PROTECTED_CONTROLLER`.
- Missing external/protected prerequisite: block only the affected lifecycle transition and continue unrelated safe work.
- Transient provider/tool failure: bounded backoff, then materially change provider/resource/context/strategy or use deterministic local verification. Never repeat an identical no-progress attempt.
- Repeated implementation failure: targeted repair → replan → independent takeover → clean reconstruction → quarantine when budget is exhausted.
- Failed mandatory evidence remains failed; model consensus or an unrelated approval cannot convert it into success.
- Hotfix mode may reduce validation breadth but cannot skip lifecycle states. Database, auth/tenant, financial, ZATCA, and security work retain full high-risk gates.

# High-risk mandatory profiles

- Auth/RBAC/tenant: allowed/denied roles, cross-tenant denial, ID tampering, server-side enforcement, no protected-data leakage.
- Payments/invoices/tax: exact totals, VAT/tax, rounding, explicit zero values, retries, concurrency, idempotency, duplicate prevention, ledger invariants, refunds/returns where connected, and legal/final-state immutability.
- ZATCA: high/critical risk; prove legal state transitions, accepted/warning responses, retry/duplicate rules, reporting vs clearance, signed-document persistence, certificate/EGS state, cutover gates, immutability, and no real production provider mutation in tests.
- Database: migration necessity, canonical ledger/history guard, fresh rebuild, RLS/tenant safety, expand→migrate→contract where possible, deterministic/bounded backfill, compatibility sequencing, and explicit recovery/restore strategy.
- External providers: distinguish local/provider state and transport/application failure, bounded idempotent retry, sandbox/mock, stale-output rejection, no inferred provider success.
- Concurrency: parallel reproduction, transaction/lock/constraint proof, retries, no duplicate durable effect, valid final state.

# Mandatory blocker closure model

The following conditions can never be silently downgraded. Resolve them or return the named external/local blocker with exact next action:

- `missing_release_fingerprint`
- `missing_signed_release_manifest`
- `missing_artifact_attestation_and_sbom`
- `missing_staged_restore_rehearsal`
- `missing_rollback_rehearsal`
- `missing_observation_and_synthetic_transaction`
- `missing_production_runtime_health`
- `missing_protected_supervisor_approval`
- `migration_ledger_history_guard_failure`
- `remote_main_dependency_fix_not_applied`
- `provider_output_missing`
- `invalid_json_schema`
- `local_branch_differs_from_protected_main`
- `dirty_worktree`

# Protected evidence request preparation

When a mandatory blocker remains, prepare a precise subject-bound request rather than asking the owner a generic technical question or claiming success:

```text
python3 <PLUGIN_ROOT>/scripts/ztad.py prepare-blocker-request --blocker <BLOCKER> --subject <SUBJECT.json> --reason "<observed missing evidence>"
```

The request itself is local/non-authoritative and cannot satisfy the gate it requests.

# Output

Report exact lifecycle state, problem classification, authoritative sources, reproduction/root-cause/blast-radius evidence, protected base and candidate SHA/diff, isolated-worktree status, regression RED/GREEN evidence, targeted/full validation, diff forensics, dependency/migration/domain status, actual risk, independent review, protected CI, artifact fingerprint/digest, manifest/SBOM/attestation/provenance, staging/restore/rollback/observability evidence, protected release authorization, production release evidence, post-deploy proof, contained blockers, next protected action, and final state. Never report `CLOSED` when an applicable mandatory gate lacks objective evidence.
