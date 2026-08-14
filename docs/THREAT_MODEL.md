# Threat Model — ZTAD Mesh 4.3.6

## Assets

Source code, tests, repository history, model credentials, signing keys, evidence, task state, CI configuration, artifacts, deployment authority, production data, and user trust.

## Untrusted inputs

Model output, repository text, issues/comments, logs, external documentation, package metadata, generated summaries, benchmark outputs, and unsigned evidence.

## Primary threats and controls

- **Prompt injection:** repository/external text remains data; command/network authority is external to prompts.
- **Excessive agency:** role-specific sandboxes, no model merge/deploy authority, scope locks, worktrees, and platform gates.
- **Fabricated evidence:** evidence registry, exact subjects, trust levels, signatures, and controller validation.
- **Stale/replayed model output:** unique run IDs and exclusive result artifact creation.
- **Scope drift:** immutable goal/scope, actual diff inspection, child-task split.
- **Infinite loops:** attempt fingerprints, progress invariants, bounded escalation, quarantine.
- **Parallel write collision:** non-overlap analysis, durable locks, dedicated worktrees, deterministic integration.
- **Test weakening:** semantic heuristics, collection/count checks, protected paths, CI gate.
- **Path escape:** normalized Windows/POSIX containment, drive/UNC/traversal/symlink checks.
- **Supply-chain/package tampering:** checksums, manifests, safe ZIP validation, reproducible builds.
- **Ledger/state corruption:** SQLite transactions, constraints, event hashes, checkpoints.
- **Provider compromise/unavailability:** qualified fallback, environment allowlist, no shell interpolation, task-local containment.
- **False hosted-control claims:** conservative host acceptance and evidence-required platform transitions.

## Residual risk

Static analysis can miss runtime coupling; multiple models can share correlated blind spots; host sandboxes and remote platform APIs can change; deployment metrics can be inconclusive. Target acceptance and operational monitoring remain mandatory.
