---
name: multi-model-mesh
description: Build and operate the bounded multi-model delivery DAG, benchmark available models by task family, allocate maximum useful parallelism, isolate writers, transfer structured artifacts, and escalate to frontier review. Invoke explicitly for automated multi-model execution.
---

# Objective

Use the largest **useful and independent** set of model runs, not the largest raw count. Parallelize repository indexing, context scouts, plan candidates, test-oracle design, non-overlapping implementation shards, and independent review dimensions. Serialize overlapping writes and all evidence-gated platform transitions.

# Required order

1. Run `host-acceptance` and `provider-probe`; do not infer provider availability from configuration alone.
2. Run `model-benchmark` against the current catalog and benchmark-suite hash. Treat catalog quality values as priors only.
3. Validate the Change Contract, compute deterministic risk, and build the repository index before any model call.
4. Generate a `mesh-plan`; verify that every write scope is bounded and non-overlapping.
5. Start with `mesh-autopilot --dry-run`. Review the DAG, routing, prompts, machine-check configuration, and actual-diff risk policy.
6. Run `mesh-autopilot` or `mesh-service` only after dry-run passes.
7. Transfer dependency results only through bounded, hash-addressed result artifacts. Truncation must be explicit; missing context produces a targeted context-expansion node, never a guess.
8. Require one deterministic candidate commit and successful machine checks before any independent reviewer runs.
9. Reclassify risk from the actual candidate diff. If risk increases, quarantine only the affected node, regenerate the required review plan, and continue unrelated runnable work.
10. Bind supervisor and closure decisions to stored model-run identity, exact candidate SHA, diff hash, contract hash, and registered evidence.

# Routing policy

- Economy models: navigation, context scouting, documentation, mechanical work after benchmark qualification.
- Balanced models: normal implementation, repair, test design, and moderate complexity.
- Frontier models: plan adjudication, security/data/authorization review, high-risk diagnosis, takeover, closure, and release advice.
- A preferred provider is a soft preference. Provider or model failure triggers a qualified fallback.
- Model consensus is never proof. Deterministic evidence and the approval controller remain authoritative.

# Continuity and loop control

Every attempt has a strategy/context/SHA/diff/evidence/provider/model fingerprint. A retry must add evidence, change strategy or execution resource, reduce failures/uncertainty, or rebuild from a clean baseline. Otherwise classify `NO_PROGRESS_CYCLE`, escalate, or quarantine the task and continue the queue.

# Commands

```text
python3 <PLUGIN_ROOT>/scripts/ztad.py host-acceptance --plugin-root <PLUGIN_ROOT> --repo <REPOSITORY>
python3 <PLUGIN_ROOT>/scripts/ztad.py provider-probe --codex-executable codex
python3 <PLUGIN_ROOT>/scripts/ztad.py model-benchmark --repo <REPOSITORY> --catalog <CATALOG> --cases <CASES>
python3 <PLUGIN_ROOT>/scripts/ztad.py mesh-plan --contract <CONTRACT> --risk <R0-R4> --task-id <TASK>
python3 <PLUGIN_ROOT>/scripts/ztad.py mesh-autopilot --repo <REPOSITORY> --contract <CONTRACT> --risk <R0-R4> --task-id <TASK> --dry-run
python3 <PLUGIN_ROOT>/scripts/ztad.py mesh-service --repo <REPOSITORY> --database <DATABASE>
```

# Claim boundary

This skill coordinates local model work. It does not prove GitHub enforcement, CI success, merge eligibility, artifact provenance, deployment, canary health, or production success. Those require target-platform evidence.
