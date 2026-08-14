# Changelog

## 4.3.6 — 2026-08-14

- Added deterministic fail-closed problem investigation before Change Contract creation: source-of-truth resolution, classification, reproduction/proof, root cause, blast radius, minimal plan, clean isolation, and regression baseline.
- Added autonomous owner-interaction rules so routine technical decisions remain agent/controller work while protected authority and irreducible business decisions remain external.
- Added strict model-output schema preflight and provider request/receipt binding so invalid schemas fail before model execution and are not misreported as missing structured output.
- Added deterministic local release fingerprints and strengthened protected gates for signed manifests, SBOM/attestation/provenance, restore/rollback rehearsal, observability, protected release authorization, runtime health, synthetic transactions, and observation windows.
- Made dependency-audit, migration-ledger, dirty/divergent worktree, provider-output, schema, and external-evidence failures explicit fail-closed workflow concerns.
- Preserved v4.3.5 and all earlier releases/validation artifacts as immutable historical evidence.

## 4.3.5 — 2026-08-13

- Synchronized the current source, package, release-facing, operational, and normative identity surfaces to `4.3.5`.
- Hardened the version-identity verifier so it fails closed across package metadata, runtime metadata, current release documentation, current operational headings, and source-only issue metadata while preserving the source/distribution profile boundary.
- Added a visible CI release-identity gate before compilation and test execution.
- Clarified that historical validation measurements remain historical unless rerun on the exact `v4.3.5` commit; protected CI, immutable release assets, and target-host acceptance provide separate evidence classes.
- Documented the historical status of retained validation and critical-review snapshots without deleting their findings.
- Enforced the Sol `HIGH` reasoning ceiling in adaptive routing, legacy command construction, and benchmark execution, including defense against permissive caller profiles and catalogs.
- Rejected non-finite or malformed model-catalog and learned-performance values, and made benchmark suite hashes depend on schema content rather than checkout-specific paths.
- Moved default mesh and provider artifacts outside application worktrees and rejected symlinked or stale managed artifact paths.
- Added Windows command-shim handling for provider probes, host acceptance, and model execution without enabling general shell interpolation.
- Added a compressed archive size bound alongside existing archive traversal, collision, and compression-ratio checks.
- Added regression coverage for release identity, Sol reasoning caps, malformed numeric metadata, external artifacts, symlink handling, deterministic benchmark hashes, and oversized archives.
- Preserved `v4.3.4` and all older releases as immutable historical records; no prior release or tag is rewritten.

## 4.3.4 — 2026-08-13

- Fixed the remaining Windows packaged-check failure by binding policy-approved `python` and `python3` commands to the exact active Python interpreter before process creation instead of relying on Windows executable search order.
- Kept command-policy validation against the original logical argv while recording deterministic active-interpreter execution binding in check evidence.
- Changed the isolated Windows packaged-regression CI gate to launch the exact Marketplace runner under Python isolated mode, matching the clean-install reproduction that exposed the v4.3.3 gap.
- Revalidated the existing sanitization and persistent-repository-mutation checks through that exact isolated venv boundary.
- Preserved source/distribution identity separation, deterministic archive validation, full packaged regressions, post-publication verification, v4.3 routing and approval invariants, and the Sol `HIGH` reasoning ceiling.
- Preserved v4.3.3 and all prior releases as immutable historical records.

## 4.3.3 — 2026-08-13

- Fixed the Windows packaged regression helper so it preserves the active virtual-environment interpreter directory instead of resolving the venv launcher to the base Python runtime.
- Added a regression that simulates a distinct active-venv launcher path and proves the helper prepends that exact environment directory to `PATH` without dereferencing it.
- Closed the failure where nested `python -m pytest` checks could run under the base runtime and fail with `No module named pytest` even though the active test environment contained pytest.
- Kept the v4.3.2 source/distribution version-identity split and exact packaged regression gates unchanged.
- Preserved all v4.3 routing, approval, actual-risk escalation, and hard Sol `HIGH` reasoning-ceiling invariants.
- Preserved `v4.3.2`, `v4.3.1`, `v4.3.0`, and older releases as immutable historical records; no prior release is rewritten.

## 4.3.2 — 2026-08-13

- Fixed the published Marketplace regression suite so release-identity verification distinguishes packaged runtime/install surfaces from repository-only `.github` metadata.
- Added explicit `source` and `distribution` profiles to the canonical version-identity verifier; repository CI remains strict while extracted release packages no longer require files intentionally excluded from distributions.
- Removed Windows PATH dependence from checks-runtime regressions by resolving an approved launcher from the active test interpreter environment rather than assuming `python3` exists.
- Added an exact packaged-regression runner that validates and safely extracts Plugin/Marketplace archives before running installation-critical or full tests from the packaged tree.
- Extended cross-platform CI to execute installation-critical regressions from the built Marketplace archive on Ubuntu/Windows with Python 3.11/3.13.
- Hardened the release pipeline to run the full packaged regression suite from both exact archives before tag creation/publication and to re-run install-critical regressions against the re-downloaded published Marketplace asset.
- Preserved all v4.3 routing, approval, actual-risk escalation, and hard Sol `HIGH` reasoning-ceiling invariants.
- Preserved `v4.3.1`, `v4.3.0`, and older releases as immutable historical records; no prior release is rewritten.

## 4.3.1 — 2026-08-13

- Fixed the toolkit runtime identity that still reported `4.2.0` even though the canonical release metadata was `4.3.0`.
- Changed traceability generation to derive its release identity from the canonical `VERSION` file instead of embedding a stale patch version.
- Added a canonical release-identity verifier covering `VERSION`, plugin metadata, Python package metadata, runtime `__version__`, generated traceability, current installation documentation, and the issue-template version hint.
- Extended regression coverage so a runtime/manifests/version mismatch fails repository CI before a release can be published.
- Made CI distribution archive validation derive filenames from `VERSION` rather than hard-coding the previous release filename.
- Updated current installation and release-facing documentation for the clean `4.3.1` patch release without changing the v4.3 risk-proportional routing or authority model.
- Preserved `v4.3.0` and older validation/provenance artifacts as historical records; they are not rewritten.

## 4.3.0 — 2026-08-12

- Added guarded R0/R1 fast paths: deterministic index, Luna implementation, deterministic integration/checks with actual-diff risk reclassification, and exactly one Sol final guard.
- Added bounded R2 routing with one focused Terra scout, one Luna implementation, deterministic integration/checks, and up to two focused Terra reviews.
- Retained the full independent mesh for R3/R4.
- Added explicit preferred-model routing and a defense-in-depth hard HIGH reasoning ceiling for every Sol invocation.
- Prevented protocol-correct benchmark abstentions from receiving perfect capability scores and kept learned cost/latency in normalized catalog-index units.
- Added dry-run model-call counts and intended model usage to every mesh plan.
- Added controller handling for blocking findings, context expansion, risk escalation, bounded repair/replan, and task-local quarantine.
- Bound learned routing performance to catalog/provider capability context and required repeated observations before override.
- Synchronized Continuity phases without auto-granting `MERGE_READY`; exhausted repair budgets now quarantine cleanly.
- Added a structural CLI shadowing guard and a ResourceWarning-as-error CI gate for critical v4.3 controls.
- Synchronized architecture, operating guides, model-selection guidance, skills, validation, traceability, quick-start, installation, capability, control-coverage, evaluation, and limitations documentation with the implemented v4.3 topology.
- Added a CI-gated deterministic release workflow that refuses stale-main publication, validates exact version identity, rebuilds twice, verifies checksums, publishes exact commit-bound assets without overwrite, and re-downloads the public release for post-publication verification.

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
