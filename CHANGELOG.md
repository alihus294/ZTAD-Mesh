# Changelog

## 4.3.0 — 2026-08-12

- Added guarded R0/R1 fast paths: deterministic index, Luna implementation, deterministic integration/checks with actual-diff risk reclassification, and exactly one Sol final guard.
- Added bounded R2 routing with one focused Terra scout, one Luna implementation, deterministic integration/checks, and up to two focused Terra reviews.
- Retained the full independent mesh for R3/R4.
- Added explicit preferred-model routing and a defense-in-depth hard HIGH reasoning ceiling for every Sol invocation.
- Prevented protocol-correct benchmark abstentions from receiving perfect capability scores and kept learned cost/latency in normalized catalog-index units.
- Added dry-run model-call counts and intended model usage to every mesh plan.

## 4.2.1 — 2026-08-12

- Fixed `audit` and installer `dry-run` CLI dispatch crashing before planning because the imported `plan` symbol was shadowed by the Mesh planner local variable.
- Changed CLI installer calls to a module-qualified `installer.*` namespace and renamed the Mesh local to `mesh_plan`, eliminating this class of command-local shadowing.
- Added direct dispatch, real subprocess entry-point, repository non-mutation, namespace-invariant, and Mesh dry-run regression coverage.
- Made release-version consistency derive from `VERSION` rather than hard-coding a specific patch version in the test suite.
- Revalidated unit/integration, offline eval, external fuzz/concurrency, selected mutation, bundle/policy, coverage, and deterministic distribution gates.

## 4.2.0 — 2026-08-10

- Rebuilt the real source as a bounded multi-model delivery mesh; prior unreleased 4.0/4.1 claims are not treated as distributed releases.
- Added deterministic repository indexing before model execution and bounded context-sufficiency analysis.
- Added adaptive task/risk/failure-aware routing with catalog priors, host probes, task-family benchmark hashes, measured reliability, and qualified provider fallback.
- Added maximum useful parallelism with dependency-aware DAGs, scope locks, dedicated Git worktrees, and serialized overlapping writes.
- Added bounded hash-addressed result-artifact transfer between scouts, planners, implementers, checks, and reviewers.
- Added provider artifact isolation outside worktrees, stale/replayed output rejection, and temporary benchmark-artifact cleanup.
- Added deterministic patch integration, one candidate commit, machine-check gating, and actual-diff risk reclassification before review.
- Bound approvals to stored model runs, independent sessions, exact candidate SHA/diff, contract, and registered evidence.
- Added no-progress fingerprints, clean reconstruction, task-local quarantine, delayed retry, and explicit non-replayable reactivation.
- Added `multi-model-mesh` as the thirteenth explicit-only skill.
- Added structural tests that reject duplicate module functions, class methods, and literal dictionary keys.
- Isolated every selected mutation in a temporary repository copy so interruption cannot leave production source mutated; added a source-preservation regression test.
- Corrected GitHub PR handling, hook stop behavior, benchmark freshness, provider fallback, catalog validation, and truthful host-capability reporting.
- Rewrote the operating, architecture, security, capability, validation, and limitation documentation to match implemented behavior.
- Added a clean public-source profile with pinned GitHub Actions CI, cross-platform test jobs, Dependabot configuration, CODEOWNERS, and generated-artifact exclusions.
- Added `SOURCE_DATE_EPOCH`-aware release metadata and CI byte-comparison of complete distribution trees built from the same commit.
- Removed the legacy installer version fallback; installation now fails closed when VERSION is missing, symlinked, or malformed.
- Pinned the public-source CI test environment, moved generated CI evidence outside the source tree, and pinned GitHub Actions to reviewed full commit SHAs.
- Added deterministic complete-release metadata through `SOURCE_DATE_EPOCH` and regression coverage for full release-tree reproducibility.
- Increased the verified test inventory to 227 after adding release-reproducibility regression tests.
- Published the exact 253-file source tree after validating the Base64 transport, compressed archive, extracted byte count, required paths, and final Git tree.
- Fixed Windows patch transport by preserving Git patches as bytes and canonically recovering LF framing after text-mode CRLF conversion; patch validation and worktree application now use the same binary-safe path.
- Scoped `SOURCE_DATE_EPOCH` to deterministic distribution builds so Windows dependency installation no longer receives a pre-1980 ZIP timestamp.
- Pinned governed signing to `cryptography 50.0.0` to include the CVE-2026-69247 PKCS#7 oracle fix, raised the accepted signing floor to `>=50.0.0,<51`, and updated the reviewed build/test locks to setuptools 83.0.0, coverage 7.15.4, and hypothesis 6.165.2.
- Added repository issue forms, editor configuration, expanded CODEOWNERS, stronger pull-request evidence fields, and deterministic archive validation in CI.

## 2.0.0 — 2026-08-09

- Introduced durable continuity, evidence-gated approval, hooks, single-host SQLite coordination, and fail-contained recovery.

## 1.0.1 — 2026-07-31

- Hardened structured inputs, packaging, extraction, checksums, and reproducibility.

## 1.0.0 — 2026-07-31

- Initial security-first skill suite and deterministic toolkit.
