# Operating Guide — ZTAD Mesh 4.3.5

## Modes

- `AUDIT`: inspect package, repository, and host without mutation.
- `DRY_RUN`: generate the exact risk-proportional mesh plan, route preview, scopes, and intended controls without code mutation.
- `RESTRICTED_OPERATE`: execute local bounded worktrees and machine checks without merge/deploy authority.
- `GOVERNED_DELIVERY`: permitted only after target Git/CI/artifact/deployment/runtime controls are independently verified.

## First-time sequence

1. Run `validate-bundle` and `policy-wiring`.
2. Run `host-acceptance` for the installed plugin and target repository.
3. Run `provider-probe` for every configured provider.
4. Run `model-benchmark` using the current catalog and benchmark cases; treat results as routing data only.
5. Run repository `audit` and `dry-run`.
6. Validate the Change Contract and deterministic risk.
7. Run `mesh-autopilot --dry-run`.
8. Inspect execution mode, model-call count, route preview, write scopes, dependencies, machine checks, and risk policy.
9. Start bounded operation only when the plan is consistent with the risk and host acceptance.
10. Use `mesh-service` only under an external process manager if continuous operation is required.

## Normal autonomous flow

### R0 / R1 — Guarded Fast Path

```text
deterministic index
→ Luna worker in isolated worktree
→ deterministic patch integration and scope verification
→ machine checks
→ actual-diff risk reclassification
→ one independent Sol final guard, reasoning <= HIGH
→ approval/evidence controller
```

This normal path uses exactly two model calls. Any upward actual-risk result invalidates the fast path before the Sol guard and submits the stronger required topology.

### R2 — Bounded Mesh

```text
deterministic index
→ one focused Terra scout
→ Luna worker
→ deterministic integration
→ machine checks and actual-diff risk reclassification
→ one or two focused Terra reviews according to contract budget
→ approval/evidence controller
```

Luna remains the preferred worker only while it clears the R2 worker quality gate. Terra is the balanced fallback. The quality floor is not lowered to preserve a preferred model.

### R3 / R4 — Full Mesh

Use the full independent topology: deterministic index, risk-appropriate scouts, plan candidates/adjudication, independent test oracle, isolated implementation shards, deterministic integration, machine checks, actual-diff risk reclassification, independent review dimensions, frontier supervision, and release/closure controls where required.

Every Sol invocation is capped at HIGH reasoning even on the full mesh.

## Structured control

Model output is a proposal to the controller. P0/P1 findings, context-expansion requests, risk escalation, repair, replan, quarantine, and strong-supervisor requests are parsed as explicit control inputs. Blocking findings cannot silently become success.

If actual risk rises, the current lower-risk node is contained and a child plan at the stronger risk is created. If a bounded repair cycle is exhausted, the parent is quarantined rather than left in an orphan `AUTO_REPAIR` state.

## Retry and escalation

A retry must change at least one material input: strategy, context, model/provider, evidence, failure set, or clean baseline. Otherwise the attempt is a no-progress cycle. The recovery ladder is:

1. targeted repair;
2. fresh worker with diagnosis;
3. qualified alternative model/provider;
4. alternative plan;
5. stronger-risk re-plan where evidence requires it;
6. frontier takeover where policy requires it;
7. fresh independent closure after takeover;
8. clean reconstruction;
9. task-local quarantine;
10. scheduled reactivation only after a verified condition changes.

The scheduler continues unrelated safe runnable work throughout containment.

## Model-performance discipline

Catalog values are priors. Measured overrides are accepted only when bound to the current catalog and benchmark/provider capability context and when the configured minimum observation count is satisfied. Schema-valid output alone does not earn perfect quality. Writer quality is updated from deterministic downstream outcomes.

## Scope and authority

Every writer receives an immutable parent goal, acceptance criteria, allowed scope, and must-not-touch scope. Material work outside scope becomes a child task. One checked candidate SHA must exist before independent review.

Mesh execution may synchronize Continuity through planning, implementation, machine checks, and supervisor review. It does **not** auto-grant `MERGE_READY`; merge/deployment transitions require the protected approval/platform evidence path.

## Persistent service

`mesh-service` polls durable state and runs bounded batches. Use finite time/tick limits during acceptance. For continuous unattended operation, run it under a trusted OS service manager with restricted account permissions, explicit environment, restart/backoff policy, log rotation, and no production secrets in the model process.
