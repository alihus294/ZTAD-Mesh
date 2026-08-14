# Security Controls — ZTAD Mesh 4.3.7

## Model distrust

Every model result starts as untrusted. Models cannot create authoritative test, CI, approval, build, deployment, runtime, or bug-closure evidence.

## Reported-defect lifecycle

A reported defect begins as `UNVERIFIED_REPORT`. The authoritative bug lifecycle requires explicit source-truth, classification, reproduction, root-cause, blast-radius, plan, patch, RED→GREEN, validation, diff-forensics, independent-review, CI, staging, release, production, and post-deploy gates. Generic scheduler `DONE` is not a valid bug closure. Missing mandatory evidence fails closed; after production exposure it requires rollback/containment.

## Model/provider execution

Provider adapters use argument arrays with `shell=False`, an allowlisted environment, unique run IDs, explicit output schemas, strict local schema validation, output artifacts outside worktrees, and stale-file rejection. Generic provider commands require separate host acceptance. Invalid output schemas fail before provider execution and cannot be relabeled as missing structured output.

## Repository and scope

A deterministic index precedes model work. Writers run in dedicated Git worktrees under durable non-overlapping scope locks. Dirty/divergent owner work is preserved while problem work is isolated at the protected base. Patches are validated, combined deterministically, committed once, and checked before review.

## Test integrity

`PATCH_IMPLEMENTED` and `REGRESSION_TEST_PROVEN` are separate. RED→GREEN must bind the same oracle to the exact known-bad base and exact candidate. The detector covers skip/xfail/only/todo/retry/no-tests, CI bypass, failure masking, discovery changes, assertion loss, test deletion/move, collection reduction, snapshot changes, and unconditional-success scripts. Protected control-plane changes require separate review.

## Approval and independence

The supervisor emits a proposal. The Approval Controller looks up the stored model run, validates independent identity, exact task/contract/SHA/diff/risk/evidence bindings, and signs only after all predicates pass. Independent bug review must identify a review context distinct from the implementation context and return `PASS`. Takeover requires a fresh Closure Reviewer.

## Evidence/state

SQLite transactions, constraints, leases, idempotency, hash chains, and external checkpoints protect local concurrent state. Authoritative evidence must be exact-subject and sufficiently trusted/signed. Local evidence cannot satisfy protected CI, artifact, release, or runtime gates. Multi-host use requires a shared transactional backend.

## Production boundary

Production release is separate from post-deploy correctness. `PRODUCTION_RELEASED` requires protected authority and exact revision/digest evidence; `POST_DEPLOY_VERIFIED` separately requires original-problem proof plus runtime health, synthetic transaction, and observation window. Unresolved critical uncertainty routes to `ROLLBACK_REQUIRED`.

## Secret/network boundary

Models must not receive production credentials, signing keys, authentication files, or browser data. Network is denied by default and allowed only through explicit host policy and role need. Direct production SQL, SSH mutation, local production migrations, and alternate production deployment paths are prohibited for normal coding agents.
