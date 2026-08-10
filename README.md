# Zero-Trust Agentic Delivery Mesh 4.2.0

ZTAD Mesh is a Codex plugin and deterministic control toolkit for bounded, multi-model software delivery. It selects qualified models by task family, builds a dependency-aware DAG, runs independent read-only analysis in parallel, isolates every writer in a dedicated Git worktree, creates one checked candidate commit, and permits review or release recommendations only when they bind to real model runs and machine-generated evidence.

## Operating objective

ZTAD targets **never idle while safe runnable work exists**, not the impossible promise that every task always succeeds. A blocked task is repaired, re-planned, re-routed, reconstructed, delayed, or quarantined while unrelated ready work continues. State is durable on one host and can be resumed after process interruption.

## What 4.2.0 actually implements

- deterministic repository indexing before model calls;
- adaptive model routing from catalog priors, host probes, bounded task-family benchmarks, and measured reliability;
- maximum useful parallelism, not blind fan-out;
- parallel context scouts, plan candidates, test-oracle design, implementation shards, and review dimensions;
- dedicated worktrees and non-overlapping scope locks for writers;
- bounded, hash-addressed dependency-result artifacts;
- provider output isolation outside code worktrees and stale-output replay rejection;
- deterministic patch integration into one candidate commit;
- machine-check gate before model review;
- risk reclassification from the actual candidate diff;
- exact run/session/SHA/diff/evidence binding for approvals;
- loop fingerprints and measurable progress requirements;
- durable DAG state, leases, retries, quarantine, and explicit reactivation;
- Codex lifecycle hooks as defense in depth;
- conservative host-acceptance and platform-readiness reporting.

## Thirteen explicit-only skills

- `$zero-trust-delivery`
- `$multi-model-mesh`
- `$delivery-bootstrap`
- `$change-intake-risk`
- `$implementation-strategy`
- `$code-change-verification`
- `$independent-review`
- `$finding-verification-repair`
- `$release-readiness`
- `$delivery-retrospective`
- `$autonomous-continuity`
- `$supervisor-governance`
- `$recovery-and-takeover`

## Authority model

```text
Models propose or write bounded patches
→ deterministic tools create facts
→ one candidate SHA is built and checked
→ independent frontier review proposes a decision
→ approval controller validates exact run/SHA/diff/evidence identity
→ protected platform controllers merge or deploy
→ runtime evidence promotes or rolls back
```

A model response is never CI evidence, approval evidence, deployment evidence, or proof of production health.

## Safe first run

```bash
python -B scripts/ztad.py validate-bundle --root .
python -B scripts/ztad.py policy-wiring --root .
python -B scripts/ztad.py host-acceptance --plugin-root . --repo /path/to/repository
python -B scripts/ztad.py provider-probe
python -B scripts/ztad.py model-benchmark --repo /path/to/repository
```

After plugin installation, start a new Codex session and explicitly invoke:

```text
$zero-trust-delivery
```

Begin with `AUDIT`, `DRY_RUN`, and `mesh-autopilot --dry-run`. Do not enable governed merge or production transitions until the target Git host, CI, artifact, deployment, canary, and rollback controls produce verified evidence.

## Claim boundary

The bundled SQLite stores provide durable single-host coordination, not multi-host high availability. Local tests cannot prove hosted Codex discovery, provider credentials, GitHub rulesets, protected CI, merge queue, deployment, canary health, or rollback on your infrastructure. These remain mandatory target-host acceptance gates.

## Operational references

- `docs/MODEL_SELECTION.md` — adaptive routing and useful parallelism.
- `docs/HOST_ACCEPTANCE.md` — mandatory target-host gates.
- `docs/VALIDATION_REPORT.md` — executed evidence and claim boundaries.
