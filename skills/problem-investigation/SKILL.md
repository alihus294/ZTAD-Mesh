---
name: problem-investigation
description: Prove a reported problem before patching it using read-only source resolution, classification, reproduction, root-cause falsification, blast-radius mapping, clean-baseline isolation, and regression-baseline proof.
---

# Authority

A report is untrusted input, not a bug. Models may investigate and propose classifications; deterministic repository facts, controlled executions, and protected runtime observations are evidence. This skill never grants merge, release, deployment, or production authority.

# Autonomous fail-closed intake

1. Preserve the report verbatim in a record validated by `schemas/problem-case.schema.json`.
2. Capture repository, protected/current base SHA, branch, worktree state, environment, timestamp, and supplied evidence.
3. Investigate read-only. Resolve source-of-truth priority: governing agent instructions → executable source/configuration → authorized runtime observation → tests limited to what they exercise → architecture intent → historical reports.
4. If the original worktree is dirty or on a divergent branch, preserve it untouched and create an isolated clean worktree from the protected/current base. Record `DIRTY_PRESERVED` and `ISOLATED_CLEAN_BASE` separately.
5. Classify the report. Do not patch unless the classification actually requires a code/configuration change.
6. For a bug, performance regression, or security defect, reproduce it or create equivalent bounded proof of the reported failure condition. Never experiment on production. Browser tests use synthetic data only.
7. Falsify material competing hypotheses. Record trigger → incorrect state/assumption → propagation → observable failure.
8. Map direct and adjacent blast radius, invariants, risk, data/auth/tenant/financial/ZATCA/concurrency/provider boundaries.
9. Plan the smallest correct change. Scope expansion requires reclassification and a new plan.
10. Before implementation, establish a regression oracle that deterministically proves `FAIL` on the exact protected known-bad base. The same oracle must later prove `PASS` on the exact candidate for `REGRESSION_TEST_PROVEN`. A same-SHA/configuration FAIL→PASS rerun is flaky, not RED→GREEN proof. If an exact bad-base RED cannot be produced safely, do not substitute model judgment, a controller-reviewed exception, or “equivalent evidence”; keep the bug lifecycle blocked before `REGRESSION_TEST_PROVEN` until testability or the source-of-truth conflict is resolved.
11. Build and validate the Change Contract only after the above gates are complete, then hand off to `$zero-trust-delivery`.

# Never-idle behavior

- Missing local report, template, or evidence files: create them with the marker `LOCAL_EVIDENCE_IS_NON_AUTHORITATIVE_UNTIL_PROMOTED_BY_A_PROTECTED_CONTROLLER`.
- Missing business intent, credentials, protected runtime access, or irreversible authorization: isolate only the affected task in the scheduler's `WAITING_EXTERNAL_DEPENDENCY`; the authoritative bug lifecycle remains `BLOCKED` at the affected transition and unrelated safe work continues.
- A failed hypothesis/test is not a reason to repeat identical inputs. Change evidence, baseline, strategy, context, or resource before retrying.
- Never edit a failing guard merely to obtain green status.

# High-risk domain profiles

- Auth/RBAC/tenant isolation: prove allowed and denied roles, cross-tenant denial, identifier tampering resistance, and server-side enforcement.
- Payments/invoices/tax/ZATCA: prove totals, rounding, explicit zero, idempotency, duplicate prevention, legal state transitions, retry semantics, and no real provider mutation in tests.
- Database: prefer expand → deploy-compatible → migrate/backfill → verify → contract; prove ledger/history guards, fresh rebuild, RLS/tenant safety, recovery strategy, and bounded backfill.
- External providers: distinguish local from provider state, bound retries, reject stale output, use sandbox/mock where possible, and never infer provider success from a local row.
- Concurrency: reproduce with parallel sessions where possible and prove transactions, locks, or constraints prevent duplicate durable effects.

# Exit

Return the exact problem-case state and evidence references. Only a proven and planned change may enter implementation. Expected behavior, environment/configuration/data/provider issues follow their correct non-code resolution path rather than being forced into a patch.
