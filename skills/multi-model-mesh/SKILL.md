---
name: multi-model-mesh
description: Build and operate the risk-proportional ZTAD delivery DAG with deterministic gates, bounded model use, isolated writers, structured recovery, and independent review. Invoke explicitly for automated multi-model execution.
---

# Objective

Use the **smallest safe independent topology** for the verified risk. Do not maximize raw model count. R0/R1 stay on a guarded fast path, R2 uses a bounded mesh, and only R3/R4 use the full analysis/planning/review fan-out.

# Required order

1. Run `host-acceptance` and `provider-probe`; do not infer provider availability from configuration.
2. Run `model-benchmark` against the current catalog and benchmark/provider-capability context. Catalog values and measurements are routing data only.
3. Validate the Change Contract and deterministic risk.
4. Build the deterministic repository index before any model call.
5. Generate `mesh-plan` and run `mesh-autopilot --dry-run`; inspect execution mode, model-call count, route preview, scopes, checks, and risk policy.
6. Execute only after the selected topology matches risk and every writer scope is bounded.
7. Require deterministic integration, one candidate SHA, machine checks, and actual-diff risk reclassification before independent downstream review.
8. If actual risk increases, invalidate the lower-risk downstream path and submit the stronger child topology.
9. Treat structured blocking findings, context expansion, repair, replan, risk escalation, quarantine, and strong-supervisor requests as controller actions, not narrative text.
10. Bind any approval proposal to stored model-run identity, exact candidate SHA/diff, contract, and registered evidence.

# Risk topology

## R0 / R1

```text
deterministic repository index
→ Luna worker
→ deterministic integration
→ machine checks + actual-diff risk
→ exactly one independent Sol final guard (<= HIGH)
```

Do not add normal-path scouts, plan candidates/adjudication, model test-oracle calls, review fan-out, supervisor synthesis, or release advice.

## R2

```text
deterministic repository index
→ one focused Terra scout
→ Luna worker
→ deterministic integration
→ machine checks + actual-diff risk
→ one or two focused Terra reviews within contract budget
```

Luna remains preferred only while eligible. Terra is the balanced fallback/support resource.

## R3 / R4

Use the full independent mesh: risk-appropriate context scouts, plan candidates/adjudication, independent test design, non-overlapping implementation shards, deterministic integration/checks, independent review dimensions, frontier supervision, and release/closure controls as required.

# Routing policy

- `codex-luna`: preferred low/medium-risk writer when it clears the role/risk floor.
- `codex-terra`: balanced fallback and focused R2 context/review support.
- `codex-sol`: frontier consultation/review for gates that require it.
- **All Sol invocations are hard-capped at HIGH reasoning.** Never request `xhigh`, `max`, `ultra`, or an equivalent stronger effort for Sol.
- A preferred registry never bypasses quality, tier, sandbox, provider, independence, or actual-risk gates.
- Model consensus is never proof.

# Performance learning

Use measured routing overrides only when they match the current catalog and benchmark/provider capability context and meet the configured minimum observation count. Do not treat one successful sample, schema validity, or a protocol-correct abstention as perfect model capability. Writer quality comes from downstream deterministic outcomes.

# Continuity and loop control

Every attempt has a strategy/context/SHA/diff/evidence/provider/model fingerprint. A retry must add evidence, change strategy or execution resource, reduce failures/uncertainty, or rebuild from a clean baseline. Otherwise classify a no-progress cycle and escalate or quarantine.

Repair cycles are bounded. If repair budget is exhausted, quarantine the affected parent. Do not leave it in `AUTO_REPAIR` without a child task. Mesh execution may advance Continuity through supervisor review but never grants `MERGE_READY` by model success alone.

# Commands

```text
python3 <PLUGIN_ROOT>/scripts/ztad.py host-acceptance --plugin-root <PLUGIN_ROOT> --repo <REPOSITORY>
python3 <PLUGIN_ROOT>/scripts/ztad.py provider-probe --codex-executable codex
python3 <PLUGIN_ROOT>/scripts/ztad.py model-benchmark --repo <REPOSITORY> --catalog <CATALOG> --cases <CASES>
python3 <PLUGIN_ROOT>/scripts/ztad.py mesh-plan --contract <CONTRACT> --risk <R0-R4> --task-id <TASK> --dry-run
python3 <PLUGIN_ROOT>/scripts/ztad.py mesh-autopilot --repo <REPOSITORY> --contract <CONTRACT> --risk <R0-R4> --task-id <TASK> --dry-run
python3 <PLUGIN_ROOT>/scripts/ztad.py mesh-service --repo <REPOSITORY> --database <DATABASE>
```

# Claim boundary

This skill coordinates bounded local model work. It does not prove hosted-model quality, GitHub enforcement, protected CI, merge eligibility, artifact provenance, deployment, canary health, or production success. Those require target-platform evidence.
