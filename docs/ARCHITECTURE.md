# Architecture — ZTAD Mesh 4.3.8

## Design rule

Models are untrusted compute resources. They may analyze or write bounded patches; they do not own workflow state, evidence validity, approval, merge, deployment, production truth, or bug closure. Orchestration cost must be proportional to verified risk: low-risk work stays small, while actual-diff escalation reconstructs the stronger topology before approval can continue.

## Planes

1. **Skill plane** — explicit-only Codex skills containing narrow operating procedures.
2. **Hook plane** — lifecycle interception for session, tool, permission, subagent, and stop events. Hooks are defense in depth, not the sole security boundary.
3. **Repository/context plane** — deterministic index, dependency/context artifacts, context-sufficiency checks, and targeted expansion.
4. **Problem lifecycle plane** — authoritative reported-defect state from `UNVERIFIED_REPORT` through `CLOSED`, exact evidence transitions, domain gates, and `BLOCKED`/`ROLLBACK_REQUIRED` containment. Generic scheduler states are subordinate implementation detail for bug cases.
5. **Model plane** — provider adapters, host probes, bounded task-family benchmarks, adaptive routing, provider fallback, model preference, reasoning ceilings, and run identity.
6. **Mesh plane** — risk-proportional dependency-aware DAG, leases, idempotency, scope locks, bounded parallelism, durable artifacts, retry, quarantine, replan, and reactivation.
7. **Code plane** — dedicated Git worktrees, patch artifacts, deterministic integration, one candidate commit, and scope validation.
8. **Quality/evidence plane** — machine checks, RED→GREEN proof, targeted/full validation, diff forensics, actual-diff risk reclassification, test-integrity checks, evidence binding, exact-subject validation, independent review, and approval controller.
9. **Platform plane** — Git host audit, PR/CI, immutable artifact promotion, staging, protected production release, progressive exposure, post-deploy proof, and rollback. These become authoritative only after target-host acceptance.

## Authoritative bug-to-production path

For reported code defects the outer lifecycle is fixed:

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

`DONE` in the generic scheduler cannot close this outer lifecycle. Before production a failed mandatory transition is `BLOCKED`; after production exposure it is `ROLLBACK_REQUIRED`.

## Risk-proportional execution paths

### R0 / R1 — Guarded Fast Path

```text
Change Contract
→ deterministic validation/risk
→ deterministic repository index
→ GPT-5.6 Luna primary worker in isolated worktree
→ deterministic patch integration and scope validation
→ machine checks
→ actual-diff risk reclassification
→ one independent GPT-5.6 Sol final guard (HIGH maximum)
→ evidence/approval controller
```

Normal R0/R1 execution intentionally has no redundant context-scout fan-out, plan candidate/adjudicator, independent test-oracle call, review fan-out, supervisor synthesis, or release-advisor call. If actual risk rises, the fast topology is invalidated before the final guard can run and a stronger child plan is submitted. For a reported defect, these internal steps still must satisfy each outer lifecycle state.

### R2 — Bounded Mesh

```text
Change Contract
→ deterministic validation/risk
→ deterministic repository index
→ one focused Terra context scout
→ Luna primary worker
→ deterministic integration
→ machine checks + actual-diff risk reclassification
→ up to two focused Terra reviews
→ evidence/approval controller
```

Luna is eligible as the R2 worker only because its explicit implementation prior clears the R2 quality floor. If Luna is unavailable or becomes ineligible, Terra is the configured balanced fallback. The quality floor itself is not lowered.

### R3 / R4 — Full Mesh

```text
Change Contract
→ deterministic contract/risk validation
→ repository index
→ parallel context scouts
→ independent plan candidates
→ frontier plan adjudication
→ independent test-oracle design
→ non-overlapping implementation shards in worktrees
→ deterministic patch integration
→ one candidate commit
→ machine checks
→ actual-diff risk reclassification
→ independent review dimensions
→ frontier supervisor
→ release advice / closure controls where required
→ approval controller
→ protected platform action
→ runtime evidence
```

## Model routing

Catalog values are priors. Routing combines task family/role, risk/complexity/ambiguity/failures, minimum quality floor, preferred registry after eligibility, host/provider availability, catalog and benchmark/provider fingerprints, repeated measured observations, normalized reliability/cost/latency, diversity preference, parallel caps, and reasoning ceilings.

Default intent is Luna as primary low/medium-risk worker, Terra as balanced fallback/focused R2 support, and Sol as frontier consultant/reviewer. **Every Sol invocation is hard-capped at HIGH reasoning**, including planning, review, diagnosis, takeover, closure, and release consultation. A benchmark never grants authority.

Model performance is not promoted merely because output is schema-valid. Writer quality is updated from downstream deterministic integration/check outcomes; protocol-correct abstentions are capped and cannot receive a perfect capability score.

## Structured control and continuity

Structured results such as P0/P1 findings, context expansion, risk escalation, replan, repair, quarantine, and strong-supervisor requests are controller inputs rather than decorative model text. Blocking findings cannot silently mark a review successful. Actual-diff upward risk creates a stronger child topology and blocks lower-risk downstream review.

SQLite stores task/node state, leases, artifacts, attempts, performance, and events transactionally on one host. Mesh execution synchronizes durable Continuity phases through planning, implementation, machine checks, and supervisor review, but it never auto-grants `MERGE_READY` or closes an outer bug lifecycle. The scheduler continues unrelated runnable nodes when one node retries, delays, or quarantines. A process manager is required for restart after host/process failure.

## Deployment boundary

Local ZTAD can prove only local facts. GitHub rulesets, protected CI, merge queue, environment controls, OIDC, artifact provenance, protected production authorization, deployment, canary health, rollback, original-problem production verification, synthetic transactions, and observation windows require platform/runtime evidence from the target environment.
