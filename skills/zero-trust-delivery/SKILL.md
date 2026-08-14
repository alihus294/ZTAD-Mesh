---
name: zero-trust-delivery
description: Run autonomous fail-closed problem-to-production delivery with read-only diagnosis, clean isolation, regression proof, risk-proportional implementation, exact-evidence gates, independent review, protected release, recovery, and post-deploy verification.
---

# Authority

Models are untrusted compute. They may investigate, plan, review, or create bounded patches. Deterministic controllers own state, scope, checks, evidence, fingerprints, approvals, and eligibility. Protected platforms own CI, merge, signing/attestation, deployment, and production truth. No model statement can become approval or authoritative evidence.

# Owner interaction contract

The owner may be a non-programmer. Continue routine technical work autonomously to the last safe practical result. Do not ask the owner to choose files, retries, providers, test commands, refactors, or ordinary implementation details.

Ask only when a fact cannot be safely derived or an action requires authority the agent does not possess, such as contradictory business intent, missing protected credentials, irreversible/destructive authorization, protected release approval, or a legal/compliance decision. Prepare the exact request and evidence first.

# End-to-end sequence

1. Validate the installed bundle and policy wiring. Run host acceptance, provider probes, repository audit, and dry-run where available.
2. Invoke `$problem-investigation` for every reported defect. A report begins as `UNVERIFIED_REPORT`, never as a bug.
3. Preserve the report verbatim and resolve authoritative sources read-only. Classify expected behavior, environment/configuration/data/provider issues, spec conflicts, security incidents, performance regressions, and confirmed defects separately.
4. Preserve any dirty or divergent user worktree untouched. Create a clean isolated worktree from the protected/current base and transfer only task-scoped changes by an explicit file allowlist. Never commit, discard, stash, or push unrelated user changes.
5. For a code-affecting defect, reproduce or otherwise prove it, falsify material alternative hypotheses, prove the causal root, map blast radius/invariants, classify risk, and write the smallest-change plan before implementation.
6. Establish regression evidence. Preferred proof is the same oracle failing on the exact known-bad base and passing on the candidate. Same-SHA/config FAIL→PASS is flaky or environment-dependent and is not RED→GREEN proof. Never weaken, skip, quarantine, or mock away a required test.
7. Build/validate the Change Contract only after diagnosis. Index the repository deterministically before model work. Unknowns may raise risk; a model cannot lower deterministic risk.
8. Execute risk-proportional topology:
   - R0/R1: Luna writer in isolated worktree → deterministic integration/checks → actual-diff risk → exactly one independent Sol final guard.
   - R2: focused Terra context → Luna preferred writer with qualified fallback → deterministic integration/checks → bounded independent Terra review.
   - R3/R4: full independent mesh with planning/test/review dimensions and stronger protected gates.
   - Every Sol invocation is capped at HIGH reasoning or below.
9. Reclassify risk from the actual diff. Upward risk invalidates the weaker downstream topology and creates the stronger child plan before approval can continue.
10. Run targeted validation, adjacent-domain regressions, full configured checks, type/lint/build/security/documentation/i18n/E2E as applicable, dependency audit, migration/history/ledger guards, fresh DB rebuild where applicable, and concurrency tests when shared state is involved.
11. Perform diff forensics on every changed file. Any unexplained line, unexpected dependency/lockfile/config/permission/API/migration change, PII leak, fail-open path, debug output, secret, or scope expansion must be removed or replanned.
12. Require a single candidate SHA, exact diff hash, machine evidence, and independent adversarial review. An implementing session cannot approve its own candidate. Takeover requires a fresh closure session.
13. Use the protected controller for approval. Bind task, exact base/head SHA, diff hash, contract, policy/toolchain hashes, artifact digest where applicable, evidence IDs, risk, reviewer run/session, and open blocking findings. Model prose is never approval.
14. Use PR and exact-head protected CI. A local green run cannot replace CI. A green earlier commit cannot prove a later commit. Never bypass branch/ruleset/review/environment protection.
15. Build once and promote by exact digest. Before artifact promotion require a release fingerprint, signed release manifest from the protected path, SBOM, artifact attestation/provenance, exact test evidence, and rollback artifact/strategy. Never invent or locally self-sign protected evidence.
16. Validate the exact candidate in staging when required. Require health/smoke, the original problem scenario, adjacent critical workflows, observability, synthetic transaction strategy, and risk-appropriate restore/rollback rehearsal. Use synthetic/non-customer data and provider sandboxes where possible.
17. Continue all local work until `READY_FOR_OWNER_RELEASE`. If protected production authorization is the only missing requirement, stop only that transition, prepare the approval request, and continue unrelated safe tasks.
18. Production release must use only the repository's canonical protected workflow, exact reviewed main revision, exact validated digest, protected environment, and reviewed migration plan. No direct production SQL, SSH mutation, local production migration, alternate deploy path, or mutable/unverified artifact.
19. After authorized release, verify the exact running digest, original symptom, expected behavior, health, errors, metrics, synthetic transaction, observation window, and adjacent invariants. Any unresolved safety/data/auth/financial/ZATCA uncertainty routes to containment or rollback.
20. Close only when exact production evidence proves the issue fixed without material regression. Preserve the compact evidence record and release fingerprint.

# Minimal owner entry

For a reported problem, the owner only needs to describe what happened and, if known, what was expected. ZTAD initializes the case against the protected ref, isolates dirty/divergent work automatically, proves the problem before patching, and carries the resulting Change Contract through governed delivery.

```text
python3 <PLUGIN_ROOT>/scripts/ztad.py problem-init --repo <REPOSITORY> --protected-ref main --report "<what happened>" --expected "<expected behavior>"
python3 <PLUGIN_ROOT>/scripts/ztad.py problem-isolate --case <CASE.json>
```

# Never-idle recovery

- Missing local file/report/template: create it and label it `LOCAL_EVIDENCE_IS_NON_AUTHORITATIVE_UNTIL_PROMOTED_BY_A_PROTECTED_CONTROLLER`.
- Missing external/protected prerequisite: place only the affected node in `WAITING_EXTERNAL_DEPENDENCY`; continue other safe runnable work.
- Transient provider/tool failure: bounded backoff, then materially change provider/resource/context/strategy or use deterministic local verification. Never repeat an identical no-progress attempt.
- Repeated implementation failure: targeted repair → replan → independent takeover → clean reconstruction → quarantine when budget is exhausted.
- Failed mandatory evidence remains failed; model consensus or E6 approval cannot convert it into success.

# High-risk mandatory profiles

- Auth/RBAC/tenant: allowed/denied roles, cross-tenant denial, ID tampering, server-side enforcement, no protected-data leakage.
- Payments/invoices/tax/ZATCA: exact totals/rounding/zero values, retries, concurrency, idempotency, duplicate prevention, legal state transitions, signed-document persistence, no real production provider mutation in tests.
- Database: migration necessity, canonical ledger/history guard, fresh rebuild, RLS/tenant safety, expand→migrate→contract where possible, deterministic/bounded backfill, explicit recovery/restore strategy.
- External providers: distinguish local/provider state, bounded idempotent retry, sandbox/mock, stale-output rejection, no inferred provider success.
- Concurrency: parallel reproduction, transaction/lock/constraint proof, no duplicate durable effect.

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

Report exact problem-case state, classification, authoritative sources, reproduction/root-cause/blast-radius evidence, protected base and candidate SHA/diff, isolated-worktree status, regression RED/GREEN evidence, checks, dependency/migration status, actual risk, independent review, CI, artifact fingerprint/digest, manifest/SBOM/attestation/provenance, staging/restore/rollback/observability evidence, protected approvals, runtime evidence, contained blockers, next protected action, and final mode. Never say DONE when an applicable mandatory gate lacks objective evidence.
