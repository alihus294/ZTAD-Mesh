# Architecture — ZTAD Mesh 4.2.0

## Design rule

Models are untrusted compute resources. They may analyze or write bounded patches; they do not own workflow state, evidence validity, approval, merge, deployment, or production truth.

## Planes

1. **Skill plane** — thirteen explicit-only Codex skills containing narrow operating procedures.
2. **Hook plane** — lifecycle interception for session, tool, permission, subagent, and stop events. Hooks are defense in depth, not the sole security boundary.
3. **Repository/context plane** — deterministic index, dependency/context artifacts, context-sufficiency checks, and targeted expansion.
4. **Model plane** — provider adapters, host probes, bounded task-family benchmarks, adaptive routing, provider fallback, and run identity.
5. **Mesh plane** — dependency-aware DAG, leases, idempotency, scope locks, bounded parallelism, durable artifacts, retry, quarantine, and reactivation.
6. **Code plane** — dedicated Git worktrees, patch artifacts, deterministic integration, one candidate commit, and scope validation.
7. **Quality/evidence plane** — machine checks, risk reclassification, test-integrity checks, signed evidence, exact-subject validation, and approval controller.
8. **Platform plane** — Git host audit, PR/merge readiness, immutable artifact promotion, staged release, canary analysis, and rollback. These become authoritative only after target-host acceptance.

## Required execution path

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
→ fresh closure review after takeover
→ approval controller
→ protected platform action
→ runtime evidence
```

## Model routing

Catalog values are priors. Routing combines:

- task family and role;
- risk, complexity, ambiguity, and prior failures;
- minimum quality floor;
- host/provider availability;
- benchmark suite and catalog hashes;
- measured reliability/latency/token use;
- cost and latency indices;
- provider diversity preference;
- per-model and global parallel caps.

Economy models handle qualified navigation and mechanical work. Balanced models handle normal implementation and repair. Frontier models handle plan adjudication, sensitive review, takeover, closure, and release advice. A benchmark never grants authority.

## Continuity

SQLite stores task/node state, leases, artifacts, attempts, performance, and events transactionally on one host. The scheduler continues other runnable nodes when one node retries, delays, or quarantines. A process manager is required for restart after host/process failure.

## Deployment boundary

Local ZTAD can prove only local facts. GitHub rulesets, protected CI, merge queue, environment controls, OIDC, artifact provenance, deployment, canary health, and rollback require platform evidence from the target environment.
