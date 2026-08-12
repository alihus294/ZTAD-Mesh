---
name: zero-trust-delivery
description: Run risk-proportional zero-trust software delivery with deterministic repository context, isolated writers, machine-check gates, actual-risk escalation, independent review, durable recovery, and evidence-gated release. Invoke explicitly for governed repository work only.
---

# Authority

Models analyze or create bounded patches. Deterministic controllers own task state, scope, checks, evidence, approvals, and platform eligibility. No model can turn its own statement into test, CI, merge, deployment, or production evidence.

# Objective

Deliver the accepted goal with orchestration proportional to verified risk. Preserve useful concurrency only where it adds independent value. Never preserve motion by bypassing failed checks, expanding scope, repeating the same strategy, or treating uncertainty as success.

# Required sequence

1. Validate the installed bundle and policy wiring.
2. Run host acceptance for the plugin and repository.
3. Probe configured providers and benchmark available models by task family; treat catalog/benchmark values as routing data only.
4. Run repository `audit` and `dry-run`.
5. Validate the Change Contract and deterministic risk.
6. Run `$multi-model-mesh` in dry-run mode and inspect execution mode, model-call count, route preview, scopes, prompts, checks, and risk policy.
7. Build the deterministic repository index before model work.
8. Execute the risk-proportional topology:
   - R0/R1: Luna writer → deterministic integration/checks/actual risk → exactly one independent Sol guard.
   - R2: focused Terra context → Luna writer → deterministic integration/checks/actual risk → bounded Terra review.
   - R3/R4: full independent mesh.
9. Keep every writer in a dedicated bounded worktree; serialize overlapping scopes.
10. Require one deterministic candidate SHA and successful machine checks before independent review.
11. Reclassify risk from the actual candidate diff. If risk rises, invalidate the lower-risk downstream path and create the stronger child plan.
12. Treat P0/P1 findings and requests for context, repair, replan, risk escalation, quarantine, or stronger supervision as controller inputs.
13. Keep every Sol invocation at HIGH reasoning or below.
14. Convert a review/supervisor recommendation into approval only through the protected controller using stored run identity, exact SHA/diff, contract, and real evidence.
15. Use bounded recovery on failure; if repair budget is exhausted, quarantine rather than creating an orphan repair state.
16. Never auto-grant `MERGE_READY` from successful model/mesh execution.
17. Treat merge, deployment, canary, rollback, and production status as external platform actions requiring verified evidence.

# Safe start

```text
python3 <PLUGIN_ROOT>/scripts/ztad.py validate-bundle --root <PLUGIN_ROOT>
python3 <PLUGIN_ROOT>/scripts/ztad.py policy-wiring --root <PLUGIN_ROOT>
python3 <PLUGIN_ROOT>/scripts/ztad.py host-acceptance --plugin-root <PLUGIN_ROOT> --repo <REPOSITORY>
python3 <PLUGIN_ROOT>/scripts/ztad.py provider-probe --codex-executable codex
python3 <PLUGIN_ROOT>/scripts/ztad.py model-benchmark --repo <REPOSITORY>
python3 <PLUGIN_ROOT>/scripts/ztad.py audit --repo <REPOSITORY>
python3 <PLUGIN_ROOT>/scripts/ztad.py dry-run --repo <REPOSITORY>
python3 <PLUGIN_ROOT>/scripts/ztad.py mesh-autopilot --repo <REPOSITORY> --contract <CONTRACT.json> --dry-run
```

# Autonomous operation

```text
python3 <PLUGIN_ROOT>/scripts/ztad.py mesh-autopilot --repo <REPOSITORY> --contract <CONTRACT.json>
```

Use `mesh-service` under an external process manager for continuous operation. Durable SQLite coordination does not provide multi-host HA and cannot restart the process or host by itself.

# Non-negotiable boundaries

- No fabricated, stale, or subject-mismatched evidence.
- No same-run implementation and independent approval.
- No overlapping writers.
- No provider output artifact in a code worktree.
- No review before one checked candidate SHA exists.
- No deterministic-risk downgrade.
- No continuation of a lower-risk topology after actual-risk escalation.
- No test/control weakening.
- No identical no-progress retry.
- No Sol reasoning above HIGH.
- No schema-valid-only perfect quality promotion.
- No unbounded repair loop.
- No automatic `MERGE_READY` from model success.
- No model merge/deploy/production credentials.
- No claim of full governed delivery until target-host acceptance verifies external gates.

# Output

Report exact task/node state, execution mode, route, model run ID, candidate SHA/diff, machine evidence, actual risk, findings, contained blockers, replan/repair state, next action, and queue status. Distinguish runnable-now, delayed, quarantined, dependency-blocked, and terminal work.
