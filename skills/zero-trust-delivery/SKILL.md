---
name: zero-trust-delivery
description: Run the complete bounded multi-model delivery mesh with deterministic repository context, adaptive routing, isolated writers, machine-check gates, independent frontier review, durable recovery, and evidence-gated release. Invoke explicitly for governed repository work only.
---

# Authority

Models analyze or create bounded patches. Deterministic controllers own task state, scope, checks, evidence, approvals, and platform eligibility. No model can turn its own statement into test, CI, merge, deployment, or production evidence.

# Objective

Deliver the accepted goal with maximum useful parallelism and no global idle state while safe runnable work exists. Never preserve motion by bypassing failed checks, expanding scope, repeating the same strategy, or treating uncertainty as success.

# Required sequence

1. Validate the installed bundle and policy wiring.
2. Run host acceptance for the plugin and repository.
3. Probe configured providers and benchmark available models by task family. Catalog scores are priors only.
4. Run repository `audit` and `dry-run`.
5. Validate the Change Contract and deterministic risk.
6. Run `$multi-model-mesh` in dry-run mode to inspect the exact DAG, routes, write scopes, prompts, check configuration, and risk policy.
7. Start the mesh only when every writer has a dedicated non-overlapping worktree scope.
8. Require deterministic repository indexing before model work and targeted context expansion rather than guessing.
9. Integrate accepted patches into one candidate commit and run machine checks before independent review.
10. Reclassify risk from the actual candidate diff. Regenerate the review plan if risk rises.
11. Use qualified frontier sessions for adjudication, sensitive review, takeover, closure, and release advice.
12. Convert a supervisor recommendation into approval only through the controller using stored run identity, exact SHA/diff, contract, and real evidence.
13. Use the recovery ladder on failure; quarantine only the blocked node/task and continue the queue.
14. Treat merge, deployment, canary, rollback, and production status as external platform actions requiring verified evidence.

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

Use `mesh-service` under an external process manager for continuous operation. The service stores durable state but cannot restart itself after process or host failure.

# Non-negotiable boundaries

- No fabricated or stale evidence.
- No same-run implementation and independent approval.
- No overlapping writers.
- No provider output artifact in a code worktree.
- No review before one checked candidate SHA exists.
- No deterministic-risk downgrade.
- No test/control weakening.
- No identical no-progress retry.
- No model merge/deploy/production credentials.
- No claim of full governed delivery until target-host acceptance verifies external gates.

# Output

Report exact task/node state, route, model run ID, candidate SHA/diff, machine evidence, actual risk, findings, contained blockers, next action, and queue status. Distinguish runnable-now, delayed, quarantined, dependency-blocked, and terminal work.
