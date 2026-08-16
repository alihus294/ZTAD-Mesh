# Control Coverage — ZTAD Mesh 4.3.10

## Deterministically enforced locally

- exact bug-to-production lifecycle ordering from `UNVERIFIED_REPORT` through `CLOSED`, with `BLOCKED` before production and `ROLLBACK_REQUIRED` after production exposure;
- internal scheduler `DONE` cannot close a bug case;
- fail-closed problem intake, source-of-truth/classification/root-cause/blast-radius gates before Change Contract creation;
- protected-base resolution and autonomous clean-worktree isolation without mutating dirty/divergent user work;
- separate `PATCH_IMPLEMENTED` and `REGRESSION_TEST_PROVEN` states;
- RED→GREEN exact-base/exact-candidate same-oracle semantics distinct from same-SHA flakiness;
- skill-prompt regressions that prohibit RED→GREEN exceptions, model-to-E6 conversion, missing independent-review `PASS`, and production-verification-as-closure shortcuts;
- targeted/full-regression/diff-forensics/independent-review/CI/staging/release/post-deploy state separation;
- domain evidence requirements for database, auth/tenant, financial, ZATCA, provider, and concurrency changes;
- strict provider-schema preflight, request fingerprints, stderr/event/receipt preservation, and boundary-only role normalization;
- deterministic non-authoritative release fingerprints and exact blocker evidence/remediation requests;
- strict structured input and schema validation;
- safe archive inspection/extraction and reproducible distribution;
- protected-path and mixed control-plane detection;
- command argv policy without shell interpolation;
- provider result artifact isolation and stale-file rejection;
- immutable task goal/scope hashes;
- risk-proportional DAG generation: guarded R0/R1, bounded R2, full R3/R4;
- Luna preferred-model routing without lowering quality floors;
- hard HIGH maximum reasoning effort for every Sol route;
- dry-run route/model-call preview without provider execution;
- worktree isolation and write-scope locks;
- patch validation and deterministic integration;
- machine checks before independent review;
- actual-diff risk escalation with stronger automatic replan;
- blocking-finding structured control for P0/P1;
- writer-quality feedback from downstream deterministic outcomes;
- benchmark abstention/refusal score caps and context-bound promotion;
- test/CI weakening detection;
- model run/session registration;
- approval subject and role-separation checks;
- evidence signature/subject validation;
- transactional task/mesh state, leases, events, and artifacts;
- Continuity phase synchronization without automatic `MERGE_READY`;
- no-progress attempt fingerprints;
- bounded repair budgets and non-replayable quarantine reactivation;
- policy-consumer wiring report;
- deterministic Plugin/Marketplace packaging, internal manifests, and release checksums.
- deterministic release SBOM, provenance, release fingerprint, subject checksums, and fail-closed evidence verification;
- protected release and SBOM attestations are requested for the exact published archive subjects by the release workflow.

## Advisory until target-host evidence exists

- GitHub branch rulesets, review enforcement, and merge queue;
- remote protected CI as an enforced merge prerequisite;
- OIDC and environment protection;
- protected release authorization;
- target-platform provenance and attestation authority beyond repository-local evidence validation;
- deployment, canary, metric analysis, and rollback;
- production health, original-problem verification, synthetic transaction, and observation window;
- provider account quotas, hosted model quality, and model availability.

## Human/owner decisions that cannot be inferred safely

- contradictory business requirements;
- legal/compliance policy choices not encoded in the contract;
- creation or disclosure of missing credentials;
- acceptance of irreversible destructive operations;
- protected production release authorization when the platform requires the owner;
- waivers of non-waivable controls.
