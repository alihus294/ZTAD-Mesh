# Threat Model — ZTAD Mesh 4.3.10

## Assets

Source code, tests, repository history, model credentials, signing keys, evidence, bug-lifecycle state, task state, CI configuration, artifacts, deployment authority, production data, and user trust.

## Untrusted inputs

Model output, repository text, issues/comments, initial bug reports, logs, external documentation, package metadata, generated summaries, benchmark outputs, and unsigned evidence.

## Primary threats and controls

- **Premature bug assumption:** every report begins `UNVERIFIED_REPORT`; read-only source-truth resolution, classification, reproduction, and root-cause proof precede patching.
- **False completion:** authoritative bug lifecycle excludes scheduler `DONE`; a code-fix case closes only after protected release and `POST_DEPLOY_VERIFIED` evidence.
- **Deployment/fix conflation:** `PRODUCTION_RELEASED` and `POST_DEPLOY_VERIFIED` are distinct mandatory states; readiness output cannot substitute for closure.
- **Fake RED→GREEN:** exact bad-base SHA, exact candidate SHA, same oracle, FAIL then PASS semantics are required, with no skill-level equivalent-evidence exception.
- **Model self-authorization:** supervisor/model `APPROVE` is advisory only; it cannot itself become E6 or be mechanically translated into protected merge/release/production authority.
- **False independent review:** `INDEPENDENT_REVIEW_PASS` requires distinct implementation/review sessions and exact reviewer verdict `PASS`.
- **Prompt injection:** repository/external text remains data; command/network authority is external to prompts.
- **Excessive agency:** role-specific sandboxes, no model merge/deploy authority, scope locks, worktrees, owner-work preservation, and platform gates.
- **Fabricated evidence:** evidence registry, exact subjects, trust levels, signatures, and controller validation.
- **Stale/replayed model output:** unique run IDs and exclusive result artifact creation.
- **Scope drift:** immutable goal/scope, actual diff inspection, child-task split, and diff forensics.
- **Infinite loops:** attempt fingerprints, progress invariants, bounded escalation, quarantine, and no identical no-progress retry.
- **Parallel write collision:** non-overlap analysis, durable locks, dedicated worktrees, deterministic integration.
- **Test weakening:** semantic heuristics, collection/count checks, protected paths, CI gate, and explicit regression-test proof state.
- **Path escape:** normalized Windows/POSIX containment, drive/UNC/traversal/symlink checks.
- **Supply-chain/package tampering:** checksums, manifests, safe ZIP validation, reproducible builds, SBOM and protected provenance/attestation gates.
- **Ledger/state corruption:** SQLite transactions, constraints, event hashes, checkpoints.
- **Provider compromise/unavailability:** strict schemas, qualified fallback, environment allowlist, no shell interpolation, task-local containment.
- **Unsafe production access:** normal coding commands/network policy prohibit direct production database/deployment mutation; protected platform paths own production authority.
- **False hosted-control claims:** conservative host acceptance and evidence-required platform transitions.
- **Post-release uncertainty:** missing or unhealthy post-deploy evidence routes to `ROLLBACK_REQUIRED` instead of optimistic closure.

## Residual risk

Static analysis can miss runtime coupling; multiple models can share correlated blind spots; host sandboxes and remote platform APIs can change; deployment metrics can be inconclusive. Target acceptance, protected authority, operational monitoring, production-safe verification, and rollback remain mandatory.
